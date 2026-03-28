# Post-Fix Improvements - Design Spec

**Date:** 2026-03-28
**Branch:** `refactor/drop-cgroup-v1`
**Scope:** 7 items (B-tier), defers IsolateConfig split and root-required tests

## Context

After resolving 9 behaviour analysis findings (C1, H1-H4, M1-M4), the remaining score deductions come from dead code left by the degraded removal, a duplicated workdir setup, a 660-line supervisor mixing launch + evidence logic, an untested timer interaction, and a PID-recyclable watchdog thread.

## Batches

### Batch 1: Trivial cleanups

**#2 - Non-root CLI hard error**
- File: `src/cli.rs`
- Replace warning at lines 243-245 with error + `exit(1)`
- Message: `"Error: rustbox requires root privileges for sandbox isolation"`
- Place after the existing strict-mode root check (lines 229-232)

**#3 - Remove dead compile relaxation**
- File: `src/runtime/isolate.rs`
- Delete `if !is_root { config.strict_mode = false; }` block in `apply_compile_limits` (lines 376-378)
- Rationale: non-root never reaches compilation post-degraded-removal

**#4 - Remove empty validator stub**
- File: `src/config/validator.rs`
- Delete `fn validate_mode_compatibility` (line 214)
- Remove its call from `validate_config` (line 46)

### Batch 2: Deduplicate ensure_workdir

- File: `src/runtime/isolate.rs`
- Delete `fn ensure_workdir()` (lines 76-94)
- Remove `self.ensure_workdir()?` calls in `execute_with_overrides` and `execute_interpreted_from_config` and `compile_and_execute_from_config`
- Workdir is already created and configured in `Isolate::new()` (lines 155-169)
- `wipe_workdir()` clears contents but preserves the directory, so re-creation is unnecessary

### Batch 3: Split supervisor.rs → supervisor + evidence

- New file: `src/sandbox/evidence.rs`
- Update: `src/sandbox/mod.rs` to add `pub mod evidence;`

**Move to evidence.rs:**
- `struct LaunchEvidenceParams` (make `pub(crate)`)
- `fn build_launch_evidence()` (make `pub(crate)`)
- `fn build_configured_controls()` (keep private to evidence module)
- `fn detect_pidfd_mode()` (keep private to evidence module)

**Move tests to evidence.rs:**
- `strict_mode_does_not_claim_setup_controls_on_proxy_failure`
- `strict_mode_claims_setup_controls_when_proxy_succeeds`
- Helper functions: `test_request`, `proxy_status`, `strict_evidence`, `SETUP_CONTROLS`

**supervisor.rs changes:**
- Add `use crate::sandbox::evidence::{build_launch_evidence, LaunchEvidenceParams};`
- Remove moved functions and structs
- Remove moved tests

### Batch 4: Test proxy vs supervisor timer

- New test in `src/sandbox/supervisor.rs` tests module (unit test, no root required)
- Test 1: `supervisor_safety_timeout_produces_ie_not_tle` - Construct a `ProxyStatus` with `timed_out=false` and verify that supervisor safety timeout logic sets status to `InternalError`, not `TimeLimit`
- Test 2: `proxy_reported_timeout_produces_tle` - Construct a `ProxyStatus` with `timed_out=true` and verify status is `TimeLimit`
- These test the classification logic at supervisor.rs lines 484-505 without needing actual process spawning

### Batch 5: Replace proxy watchdog with pidfd

- File: `src/sandbox/proxy.rs`
- Replace detached watchdog thread (lines 173-185) with pidfd-based timeout:
  1. After `fork()`, call `pidfd_open(payload_pid, 0)` via syscall
  2. Use `libc::poll()` on the pidfd with wall_limit_ms as timeout
  3. If poll returns 0 (timeout), SIGKILL via `pidfd_send_signal()` or fallback to `kill()`
  4. If `pidfd_open` fails (ENOSYS on kernel < 5.3), fall back to current thread approach
- Keep `timer_fired` atomic for status reporting (unchanged)
- The pidfd approach is race-free: the fd refers to the exact process, not a recyclable PID

## Sequencing

```
Batch 1 (trivials) → Batch 2 (dedup) → Batch 3 (split) → Batch 4 (tests)
                                                         → Batch 5 (pidfd)
```

Batches 4 and 5 are independent but both depend on Batch 3 (final file structure).

## Out of scope

- `IsolateConfig` struct split (needs own design pass, touches every file)
- Integration tests requiring root (`cgroup_v2` probe, command_validation)
- `sandbox/types.rs` restructuring
- Any changes to `kernel/` module internals

## Validation

After all batches: `cargo fmt && cargo clippy --workspace && cargo test --lib` must pass with zero new warnings and zero failures.
