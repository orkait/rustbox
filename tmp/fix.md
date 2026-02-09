# Rustbox Security Hardening Plan

**Date**: 2026-02-09  
**Based on**: Deep analysis vs IOI Isolate baseline  
**Verdict**: Not production-ready for untrusted code execution  

---

## Executive Summary

Rustbox has strong architectural foundations (type-state chain, dual cgroup backends, structured evidence) but **critical security gaps** prevent it from replacing IOI Isolate:

**P0 Blockers**:
1. No mandatory tmpfs-root filesystem boundary (host root visible)
2. No hard CPU-time enforcement (wall-time only, not CPU quota)
3. Unsafe degraded fallback (can run without namespaces/cgroups)
4. Declared-but-not-wired security controls (seccomp, disk quotas)
5. Incomplete capability drop implementation

**Rustbox Strengths**: Type-state safety, explicit cap/NNP, PDEATHSIG, cgroup.kill, evidence provenance, memory safety  
**Isolate Strengths**: Tmpfs root, mount rule engine, capability-isolated mounting, disk quotas, 20+ years battle-testing

---

## Critical Findings (P0)

### C1. No Mandatory Filesystem Boundary

**Gap**: `chroot_dir` defaults to `None`. Strict mode does not enforce tmpfs-root + chroot.

**Isolate baseline**: Always creates tmpfs root, applies controlled bind mounts, then `chroot("root")`.

**Impact**: Payload can access host filesystem paths outside bind mount coverage.

**Fix**: 
```rust
// In strict mode, enforce:
1. Create tmpfs root
2. Apply controlled bind set (workspace, /bin, /lib, /usr, /dev, /proc)
3. Mandatory chroot/pivot_root
4. Fail closed if any step fails
```

**Files**: `src/kernel/mount/filesystem.rs`, `src/config/types.rs`

---

### C2. No Hard CPU-Time Enforcement

**Gap**: Uses `cpu.weight` (share), not `cpu.max` (quota). Watchdog is wall-time only.

**Isolate baseline**: Keeper enforces CPU runtime via periodic checks + kill on CPU limit.

**Impact**: CPU-bound abuse (tight loop) can saturate host CPU until wall timeout.

**Fix**:
```rust
// Option 1: cgroup v2 cpu.max
write("cpu.max", format!("{} 100000", cpu_limit_us));

// Option 2: Watchdog CPU runtime check
loop {
    let cpu_used = read_cpu_stat();
    if cpu_used > cpu_limit { kill_process_group(); }
}
```

**Files**: `src/kernel/cgroup/v2.rs`, `src/core/supervisor.rs`

---

### C3. Unsafe Degraded Fallback

**Gap**: Permissive mode + non-root + `clone()` EPERM → `Command::spawn` without isolation.

**Isolate baseline**: No "run unisolated" path. Root required always.

**Impact**: Untrusted payload can run with host namespace/cgroup/filesystem visibility.

**Fix**:
```rust
// Remove automatic fallback for untrusted mode
if config.strict_mode && clone_result.is_err() {
    return Err(IsolateError::InsufficientPrivileges);
}

// Require explicit --dev-unsafe flag for degraded mode
if config.allow_degraded && clone_result.is_err() {
    log::error!("UNSAFE: Running without isolation");
    launch_degraded()?;
}
```

**Files**: `src/core/supervisor.rs`

---

### C4. Declared-But-Not-Wired Controls

**Gap**: Config fields exist but have no runtime enforcement:
- `disk_quota` (no `quotactl_fd` calls)
- `use_seccomp` (returns error, not installed)
- `enable_network` (not used by launch profile)
- Judge adapter registry (not called by CLI)

**Impact**: False confidence. Users assume controls are active.

**Fix**: Either implement or remove from production config.

**Files**: `src/config/types.rs`, `src/kernel/seccomp.rs`, `src/judge/registry.rs`

---

### C5. Incomplete Capability Drop

**Gap**: `drop_process_capabilities()` is a no-op placeholder.

**Current**: Drops bounding + ambient, relies on `setresuid()` for effective/permitted.

**Fix**:
```rust
fn drop_process_capabilities() -> Result<()> {
    // Drop effective/permitted/inheritable
    for cap in 0..40 {
        caps::drop(None, CapSet::Effective, cap)?;
        caps::drop(None, CapSet::Permitted, cap)?;
        caps::drop(None, CapSet::Inheritable, cap)?;
    }
    // Verify all sets are empty
    verify_no_capabilities()?;
}
```

**Files**: `src/kernel/capabilities.rs`

---

## High-Risk Findings (P1)

### H1. No Loopback Network Setup

**Gap**: Network namespace created but loopback not brought up.

**Isolate**: `ioctl(SIOCSIFFLAGS, IFF_UP)` on `lo`.

**Impact**: Programs expecting `127.0.0.1` fail.

**Fix**:
```rust
// In network namespace setup
let sock = socket(AF_INET, SOCK_DGRAM, 0)?;
let mut ifr = ifreq { ifr_name: "lo", ... };
ioctl(sock, SIOCSIFFLAGS, IFF_UP)?;
```

**Files**: `src/kernel/namespace.rs`

---

### H2. No Disk/Inode Quotas

**Gap**: `disk_quota` field unused. No `quotactl_fd()` enforcement.

**Isolate**: Native block+inode quota via `--quota`.

**Impact**: Disk exhaustion attacks (write large files, spray inodes).

**Fix**: Implement project quotas or use size-limited tmpfs workspace.

**Files**: `src/kernel/mount/filesystem.rs`

---

### H3. Inconsistent Lifecycle Semantics

**Gap**: 
- `run` command auto-cleans after execution
- `execute-code` does not call `isolate.cleanup()`, leaves state

**Isolate**: Explicit `--init` / `--run` / `--cleanup` lifecycle.

**Impact**: State leakage, forensic confusion.

**Fix**: Unify to either explicit cleanup everywhere or guaranteed ephemeral cleanup.

**Files**: `src/cli.rs`, `src/legacy/isolate.rs`

---

### H4. No Capability-Isolated Mounting

**Gap**: Mounts performed as full root.

**Isolate**: Drops to caller UID + CAP_SYS_ADMIN only during mount.

**Impact**: Broader attack surface during mount operations.

**Fix**:
```rust
// Before mount
setresuid(orig_uid, orig_uid, 0)?;
set_cap_sys_admin_only()?;
mount(source, target, ...)?;
// After mount
setresuid(orig_uid, 0, orig_uid)?;
```

**Files**: `src/kernel/mount/filesystem.rs`

---

### H5. User Namespace Incomplete

**Gap**: `enable_user_namespace` flag exists but mapping workflow deferred.

**Impact**: Rootless strict mode is not production-ready.

**Fix**: Either complete `uid_map`/`gid_map`/`setgroups` workflow or hard-disable.

**Files**: `src/config/policy/userns.rs`

---

## Moderate Findings (P2)

### M1. No Workdir chdir() in Preexec

**Gap**: Workdir created but no explicit `chdir(workdir)` in active path.

**Impact**: Relative-path behavior fragile.

**Fix**: Add `std::env::set_current_dir(workdir)` in type-state chain.

---

### M2. Misleading Security Check Messages

**Gap**: `perform_security_checks()` reports cgroup-v1 messaging even when v2 active.

**Fix**: Report actual backend selection.

---

### M3. No Signal-Aware Teardown

**Gap**: CLI signal handler uses `_exit`, skips cleanup logic.

**Isolate**: Keeper signal handler runs cleanup before exit.

**Fix**: Run cleanup path in signal handler before exit.

---

## Rustbox Advantages (Keep These)

| Feature | Benefit |
|---------|---------|
| Type-state pre-exec chain | Compile-time ordering enforcement (9 trybuild tests) |
| Explicit capability drop | Bounding + ambient + NNP |
| PDEATHSIG | Kernel-guaranteed cleanup on parent death |
| close_range syscall | Atomic FD closure (Linux 5.9+) |
| cgroup.kill cleanup | Kernel-level process tree kill |
| Dual v1/v2 cgroup backend | Broader compatibility |
| Evidence-backed verdicts | Pure function over immutable evidence |
| Structured JSON output | Capability report + provenance |
| Memory safety | Rust automatic bounds checking |
| Post-drop verification | `verify_transition()` confirms UID/GID change |

---

## Production Hardening Checklist

### Phase 0: Remove Dead Weight (DONE)
- ✅ Deleted ~2200 LOC dead scaffolding
- ✅ Removed ~100 fake tests
- ✅ Simplified lock manager (removed heartbeat)

### Phase 1: P0 Blockers (MUST-HAVE)
- [ ] **C1**: Enforce tmpfs-root + mandatory chroot in strict mode
- [ ] **C2**: Implement hard CPU enforcement (`cpu.max` or watchdog)
- [ ] **C3**: Remove degraded fallback for untrusted mode
- [ ] **C4**: Wire or remove declared controls (disk_quota, seccomp)
- [ ] **C5**: Complete capability drop implementation

### Phase 2: P1 High-Risk (SHOULD-HAVE)
- [ ] **H1**: Bring up loopback in network namespace
- [ ] **H2**: Implement disk/inode quotas
- [ ] **H3**: Unify lifecycle semantics
- [ ] **H4**: Capability-isolated mounting
- [ ] **H5**: Complete or disable user namespace

### Phase 3: P2 Moderate (NICE-TO-HAVE)
- [ ] **M1**: Explicit workdir chdir()
- [ ] **M2**: Fix security check messaging
- [ ] **M3**: Signal-aware teardown

---

## Adversarial Test Plan

| Attack | Expected Defense | Verification |
|--------|------------------|--------------|
| Fork bomb | `pids.max` cap | No host PID growth |
| Memory bomb | `memory.max` + OOM kill | `memory.events` shows OOM |
| CPU spin | Hard CPU quota kill | CPU runtime crosses limit → kill |
| Disk fill | Disk quota or RLIMIT_FSIZE | EDQUOT/EFBIG, no host fill |
| Inode spray | Inode quota | Quota enforcement signal |
| FD leak | `close_range` + `/proc/self/fd` | Only 0/1/2 visible |
| Ptrace attempt | Namespace isolation | EPERM |
| Mount attempt | Dropped capabilities | EPERM |
| Network egress | Network namespace | Connection failure |
| Parent death | PDEATHSIG + cgroup.kill | No orphans |

---

## Comparison Matrix

| Control | Isolate | Rustbox | Winner |
|---------|---------|---------|--------|
| Tmpfs root | ✅ Always | ❌ Optional | **Isolate** |
| Hard CPU enforcement | ✅ Keeper checks | ❌ Wall-time only | **Isolate** |
| Disk quotas | ✅ quotactl_fd | ❌ Not implemented | **Isolate** |
| Mount rule engine | ✅ 8 flag types | ⚠️ Config-driven | **Isolate** |
| Capability-isolated mount | ✅ CAP_SYS_ADMIN only | ❌ Full root | **Isolate** |
| Loopback setup | ✅ Explicit | ❌ Not implemented | **Isolate** |
| Type-state safety | ❌ Convention | ✅ Compile-time | **Rustbox** |
| Explicit cap drop | ❌ Implicit | ✅ Bounding+ambient | **Rustbox** |
| no_new_privs | ❌ Not set | ✅ Set+verified | **Rustbox** |
| PDEATHSIG | ❌ Not set | ✅ Kernel-guaranteed | **Rustbox** |
| close_range | ❌ /proc iteration | ✅ Atomic syscall | **Rustbox** |
| cgroup.kill | ❌ Not used | ✅ Kernel tree kill | **Rustbox** |
| Dual cgroup backend | ❌ v2 only | ✅ v1/v2 auto-detect | **Rustbox** |
| Evidence provenance | ❌ Simple meta | ✅ Structured JSON | **Rustbox** |
| Memory safety | ❌ Manual C | ✅ Automatic Rust | **Rustbox** |
| Battle-testing | ✅ 20+ years IOI | ❌ New | **Isolate** |

---

## Recommendation

**DO NOT ship as Isolate replacement** until P0 blockers are fixed.

**Rustbox can be stronger than Isolate** if it:
1. Enforces mandatory tmpfs-root boundary (C1)
2. Implements hard CPU enforcement (C2)
3. Removes unsafe degraded fallback (C3)
4. Wires or removes declared controls (C4)
5. Completes capability drop (C5)

**Then Rustbox wins on**:
- Defense-in-depth (type-state, explicit caps, NNP, PDEATHSIG)
- Observability (evidence provenance, capability report)
- Memory safety (Rust)
- Cgroup compatibility (v1/v2 dual backend)

**Isolate still wins on**:
- Filesystem isolation sophistication
- Operational maturity (20+ years production)

---

## Files Requiring Changes

### P0 Critical
- `src/kernel/mount/filesystem.rs` — tmpfs root + mandatory chroot
- `src/kernel/cgroup/v2.rs` — cpu.max hard quota
- `src/core/supervisor.rs` — remove degraded fallback, add CPU watchdog
- `src/kernel/capabilities.rs` — complete cap drop
- `src/config/types.rs` — remove unwired fields

### P1 High-Risk
- `src/kernel/namespace.rs` — loopback setup
- `src/kernel/mount/filesystem.rs` — disk quotas, cap-isolated mounting
- `src/cli.rs` — unify lifecycle
- `src/config/policy/userns.rs` — complete or disable

### P2 Moderate
- `src/exec/preexec.rs` — explicit workdir chdir
- `src/legacy/isolate.rs` — fix security check messaging
- `src/kernel/signal.rs` — signal-aware teardown

---

**Next Steps**: Fix P0 blockers in order (C1 → C2 → C3 → C4 → C5), then re-evaluate against Isolate baseline.
