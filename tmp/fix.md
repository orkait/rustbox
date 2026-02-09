# Rustbox Security Hardening Status (Current)

**Date**: 2026-02-09  
**Scope**: Re-validated against current `src/` after recent fix wave  
**Verdict**: **Closer, but still not a full drop-in Isolate replacement** for hostile multi-tenant untrusted code; usable with constraints.

---

## Executive Summary

The previous report is now partially stale. Major P0 items were fixed (strict tmpfs-root boundary, hard CPU-time enforcement path, capability-drop implementation, and removal of seccomp dead surface). This pass also fixed loopback bring-up, command lifecycle cleanup parity, backend-aware cgroup diagnostics, explicit workdir `chdir` before payload exec, guaranteed executor cgroup cleanup on early-error paths, and corrected default process-limit headroom for proxy+payload launches.

---

## Re-Validation of Prior P0 Claims

### C1. Mandatory filesystem boundary in strict mode
**Status**: **FIXED**

What exists now:
- Strict mode auto-creates tmpfs sandbox root when `chroot_dir` is absent.
- Standard bind set is mounted into that root.
- `chroot` is applied in pre-exec chain.

Evidence:
- `src/kernel/mount/filesystem.rs:33` (`setup_isolation`)
- `src/kernel/mount/filesystem.rs:38` (`auto_create_tmpfs_root` call)
- `src/kernel/mount/filesystem.rs:302` (`mount_standard_bind_set`)
- `src/kernel/mount/filesystem.rs:744` (`apply_chroot`)
- `src/exec/preexec.rs:516` + `src/exec/preexec.rs:530`

### C2. Hard CPU-time enforcement
**Status**: **FIXED**

What exists now:
- cgroup v2 uses `cpu.max` (quota/period) instead of weight-only behavior.
- cgroup v1 writes CFS quota (`cpu.cfs_quota_us` / period).
- Supervisor watchdog also kills when cgroup CPU usage exceeds limit.

Evidence:
- `src/kernel/cgroup/v2.rs:244`
- `src/kernel/cgroup/v1.rs:650`
- `src/core/supervisor.rs:363`
- `src/core/supervisor.rs:421`

### C3. Unsafe degraded fallback
**Status**: **PARTIALLY FIXED / INTENTIONAL DEVGATE**

Current behavior:
- Strict mode is fail-closed.
- Degraded fallback only triggers in non-strict mode **and** when `allow_degraded` is explicitly set.

Evidence:
- `src/core/supervisor.rs:290`
- `src/core/supervisor.rs:300`
- `src/core/supervisor.rs:473`
- `src/cli.rs:843`

Risk note:
- Still a dangerous mode if used in production by mistake.

### C4. Declared-but-not-wired controls (seccomp, etc.)
**Status**: **MOSTLY RESOLVED BY REMOVAL**

What changed:
- Seccomp/syscall-filtering surface removed from active code paths.
- No active `seccomp`/`enable_syscall_filtering` flags in `src/`.

Validation:
- Repo search across `src/`, `README.md`, tests for `seccomp` and syscall-filter flags returned no active hits.

Open part:
- Quota controls (disk/inode) are still not implemented.

### C5. Capability drop implementation
**Status**: **FIXED (WITH CAVEATS)**

What exists now:
- Bounding + ambient drop path.
- `capset`-based drop for effective/permitted/inheritable sets.
- Verification by reading `/proc/self/status` capability fields.

Evidence:
- `src/kernel/capabilities.rs:31`
- `src/kernel/capabilities.rs:67`
- `src/kernel/capabilities.rs:131`

Caveat:
- Error handling tolerates some post-drop failure modes (warn/log behavior).

---

## Remaining High-Risk Gaps

### H1. No explicit loopback bring-up in netns
**Status**: **FIXED**

Current behavior:
- After namespace unshare, loopback is brought up via `SIOCGIFFLAGS`/`SIOCSIFFLAGS`.

Evidence:
- `src/kernel/namespace.rs:93`
- `src/kernel/namespace.rs:141`
- `src/kernel/namespace.rs:170`

Impact:
- Programs expecting localhost networking can fail unexpectedly.

### H2. No disk/inode quota enforcement
**Status**: **FIXED (STRICT-MODE PATH)**

Current behavior:
- Strict mode always uses an auto-created tmpfs root.
- Tmpfs root has explicit `size=` and `nr_inodes=` mount options.
- Workspace is copied into tmpfs root (instead of bind-mounting host workdir), so writes/inodes in strict mode are bounded by tmpfs limits.
- Strict mode now rejects read-write host directory bindings to avoid bypassing tmpfs limits.

Impact:
- Writable surfaces in strict mode are constrained to quota-bounded tmpfs.

### H3. Lifecycle semantics differ by command path
**Status**: **FIXED**

Current behavior:
- `run` path performs automatic cleanup after execution in multiple branches.
- `execute-code` now also performs automatic cleanup after execution.

Evidence:
- Auto cleanup in run path: `src/cli.rs:425`, `src/cli.rs:583`, `src/cli.rs:654`, `src/cli.rs:716`
- Execute-code cleanup: `src/cli.rs:899`

Impact:
- Operator confusion, inconsistent persistence semantics.

### H4. Security check messaging is backend-stale
**Status**: **FIXED**

Current behavior:
- `perform_security_checks()` now reports actual detected backend (`v2` preferred / `v1` fallback).

Evidence:
- `src/cli.rs:1068`

Impact:
- Misleading diagnostics during incident response and ops triage.

### H5. Signal teardown in CLI fast-exit path
**Status**: **FIXED**

Current behavior:
- CLI signal handler no longer uses `_exit`; it records signal atomically.
- Signal state is propagated into runtime supervision loops.
- Supervisor/degraded loops terminate child process groups immediately on signal.
- Mainline performs sandbox cleanup before final exit.

Evidence:
- `src/cli.rs:203`
- `src/cli.rs:211`
- `src/cli.rs:222`
- `src/cli.rs:240`
- `src/core/supervisor.rs` signal-aware monitor loops
- `src/kernel/signal.rs` shared shutdown signaling helpers

Impact:
- Signal interruption now stops long-running payloads promptly and preserves cleanup semantics.

---

## Moderate Gaps

### M1. No explicit `chdir(workdir)` before payload exec
**Status**: **FIXED**

Current behavior:
- After chroot, runtime switches cwd to `/`.
- Runtime now explicitly transitions to configured sandbox workdir before exec.

Evidence:
- `src/kernel/mount/filesystem.rs:760` (`set_current_dir("/")`)
- `src/exec/preexec.rs:655`

Impact:
- Relative-path behavior may not match expected sandbox workdir contract.

---

## Structural Updates Already Landed

- Module naming cleanup applied:
  - `src/legacy/` renamed to `src/runtime/`
  - Active runtime imports updated accordingly.
- Seccomp historical surface removed.

---

## Current Production Recommendation

**Ship with constraints**, not as a full Isolate replacement for hostile untrusted workloads.

Constraints required:
1. Run strict mode only for untrusted code.
2. Disallow `allow_degraded` in production policy.
3. Add explicit disk/inode quota strategy before multi-tenant exposure.
4. Keep strict tmpfs size/inode limits tuned for language workloads.
5. Keep signal-aware interruption behavior under regression tests.

---

## Verification Snapshot

- Re-check completed against current `src/`.
- Test suite status: `cargo test -q` passed (`141` tests + trybuild compile-fail suite).

---

## Follow-up Fixes Applied After Re-check

### F1. Executor cleanup leak on early errors
**Status**: **FIXED**

What changed:
- Added a `Drop` safety-net in `ProcessExecutor` so cgroup cleanup still runs when execution exits early before explicit cleanup logic.
- Added a unit test that validates `remove()` is called on drop after an early execution error.

Evidence:
- `src/exec/executor.rs:234`
- `src/exec/executor.rs:337`

### F2. Supervisor early-error fd/process cleanup
**Status**: **FIXED**

What changed:
- Added parent-fd close coverage on clone failure paths.
- On strict attach/write failures, supervisor now terminates and reaps proxy before returning.
- Added status-fd close on waitpid errors.

Evidence:
- `src/core/supervisor.rs:312`
- `src/core/supervisor.rs:327`
- `src/core/supervisor.rs:349`
- `src/core/supervisor.rs:421`

### F3. Process-limit default too low for proxy+payload model
**Status**: **FIXED**

What changed:
- Updated `IsolateConfig` default `process_limit` from `1` to `10` to avoid `fork(payload): EAGAIN` in strict proxy architecture.

Evidence:
- `src/config/types.rs:247`
