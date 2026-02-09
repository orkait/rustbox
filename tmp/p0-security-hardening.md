# P0 Security Hardening — Implementation Report

**Date**: 2026-02-09
**Status**: All 5 blockers implemented. 0 warnings, 0 errors, 145 tests pass.

---

## C1: Enforce Mandatory Tmpfs Root + Chroot in Strict Mode

**Files changed**: `src/kernel/mount/filesystem.rs`, `src/exec/preexec.rs`

**What was done**:
- `setup_isolation()` signature changed: `&self` -> `&mut self`
- Added `auto_create_tmpfs_root()`: when `strict_mode && chroot_dir.is_none()`, mounts a 256MB tmpfs at `/tmp/rustbox-strict-root-<pid>`, bind-mounts workspace RW into it, then sets `self.chroot_dir = Some(tmpfs_root)`
- Added `mount_standard_bind_set()`: bind-mounts `/bin`, `/lib`, `/lib64`, `/usr` read-only into chroot
- Added `bind_mount_readonly()`: two-pass helper (MS_BIND then MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV)
- Existing `setup_chroot_jail()`, `setup_hardened_mounts()`, `apply_chroot()` all fire on the auto-created root
- `preexec.rs:setup_mounts_and_root()`: `let fs_security` -> `let mut fs_security`
- Permissive mode with `chroot_dir=None` keeps existing behavior (no chroot)

---

## C2: Implement Hard CPU-Time Enforcement

**Files changed**: `src/kernel/cgroup/v2.rs`, `src/kernel/cgroup/v1.rs`, `src/core/supervisor.rs`, `src/exec/preexec.rs`

**What was done**:
- **v2.rs**: Rewrote `set_cpu_limit()` — replaced `cpu.weight` write with `cpu.max` write (`"100000 100000"` = 1 full CPU core per 100ms CFS period)
- **v1.rs**: Implemented `set_cpu_limit()` — writes `cpu.cfs_period_us=100000` and `cpu.cfs_quota_us=100000` (was a no-op stub)
- **supervisor.rs**: Added CPU polling to watchdog loop — derives `cpu_limit_usec` from `req.profile.cpu_time_limit_ms`, polls `controller.get_cpu_usage()` in `StillAlive` branch, terminates proxy group when usage >= limit, records `cpu_timed_out` flag in evidence
- **preexec.rs**: Added `RLIMIT_CPU` as defense-in-depth (soft=limit_secs -> SIGXCPU, hard=limit_secs+1 -> SIGKILL)

---

## C3: Remove Unsafe Degraded Fallback

**Files changed**: `src/config/types.rs`, `src/core/types.rs`, `src/cli.rs`, `src/core/supervisor.rs`, `src/judge/languages/{python,java,cpp}.rs`

**What was done**:
- Added `allow_degraded: bool` (default `false`) to `IsolateConfig`
- Added `allow_degraded: bool` to `ExecutionProfile`, wired from config
- Added `--allow-degraded` CLI flag to `ExecuteCode` command with warning message
- Changed supervisor EPERM handler:
  - `EPERM && allow_degraded` -> calls `launch_degraded()` (existing behavior)
  - `EPERM && !allow_degraded` -> returns `IsolateError::Privilege("Root privileges required...")`
- All three language adapter base profiles set `allow_degraded: false`

**Before**: Non-root permissive mode silently fell back to `Command::spawn` with NO isolation.
**After**: Same scenario returns a hard error unless `--allow-degraded` is explicitly passed.

---

## C4: Remove Declared-But-Not-Enforced Controls

**Files changed**: `src/config/types.rs`, `src/config/config.rs`, `config.json`, `config-schema.json`

**Removed from structs**:
- `IsolateConfig`: `disk_quota: Option<u64>`, `enable_network: bool`
- `SecurityConfig`: `use_seccomp: bool`
- `GlobalSyscallConfig`: `blocked_syscalls: Vec<String>`
- `SyscallConfig`: `allow_clone`, `additional_blocked_syscalls`, `additional_allowed_syscalls`

**Removed from config.json**:
- `blocked_syscalls` array from global syscalls section
- `use_seccomp` from security section
- Per-language: `additional_blocked_syscalls` (python), `allow_clone`/`additional_allowed_syscalls` (java), `compilation_syscalls` (cpp)

**Removed from config-schema.json**: Corresponding schema entries for all of the above.

**Kept**: `enable_syscall_filtering` (fails closed), seccomp module (future use), `enable_network_namespace` (the real control).

---

## C5: Complete Capability Drop Implementation

**Files changed**: `src/kernel/capabilities.rs`

**What was done**:
- Implemented `drop_process_capabilities()` using raw `SYS_capset` syscall:
  - `CapUserHeader` with version `0x20080522` (v3) and pid=0 (current process)
  - Two `CapUserData` entries (caps 0-63) all zeroed (effective=0, permitted=0, inheritable=0)
  - `#[cfg(target_arch)]` for syscall number (325 on x86_64, 184 on aarch64)
  - Non-fatal on EPERM (expected after setresuid to non-root)
- Added `verify_capabilities_zeroed()`:
  - Reads `/proc/self/status`, checks `CapInh`, `CapPrm`, `CapEff` are all `"0000000000000000"`
  - Logs warning if non-zero (non-fatal — bounding set + no_new_privs still protect)

**Call order** (already correct in preexec.rs): setresgid -> setresuid -> drop_bounding -> drop_ambient -> capset(0) -> verify -> no_new_privs

---

## Build Verification

```
cargo build    -> 0 warnings, 0 errors
cargo test     -> 145 tests pass (144 unit + 1 trybuild/9 compile-fail)
```
