# Rustbox Verification Report (WSL)

Date: 2026-02-09
Workspace: `/mnt/c/codingFiles/orkait/rustbox`
Verification mode: Read-only audit (no implementation fixes applied)

## 1) Scope and Method

This audit was executed in WSL only, as requested.

I verified:
- MCP availability (`rustbox-mcp`)
- build/test status
- runtime wiring vs `plan.md` / `tasklist.md`
- consistency vs prior analysis files: `.tmp/fix.md` and `.tmp/diff.md`

MCP check:
- `tools/rustbox-mcp`: `RUSTBOX_ROOT=/mnt/c/codingFiles/orkait/rustbox npm run smoke` passed.
- Tool index status: `fileCount=115`, `chunkCount=631`, `symbolCount=1058`, git head `bc6d3b16943243e7eb231931c2fda5d377a0b6c2`.

## 2) Build and Test Verdict

### Result: **FAIL (does not compile)**

Commands run:
- `cargo build` -> exit `101`
- `cargo test --all -- --nocapture` -> exit `101`

Blocking compiler errors:
- `src/safety/lock_manager.rs:381` uses `Sender<()>` without import (`E0412`).
- `src/safety/lock_manager.rs:383` references missing field `self.heartbeat_interval` (`E0609`).

Root cause:
- `RustboxLockManager` claims heartbeat was removed (`src/safety/lock_manager.rs:2`, `src/safety/lock_manager.rs:33`), but a dead heartbeat function remains (`src/safety/lock_manager.rs:377`) and references removed state.

This alone invalidates any claim that the current tree is working.

## 3) Plan/Tasklist Conformance (Key Invariants)

`tasklist.md` status check:
- All task records are still open: `88` entries with `Status: [ ]`.

High-priority plan invariants vs implementation:

- Strict fail-closed and truthful claims: **PARTIAL / BROKEN**
  - `cleanup_verified` is hardcoded `true` in launch evidence (`src/core/supervisor.rs:163`) without baseline proof.
  - Static fallback capability report still exists (`src/utils/json_schema.rs:16`) and is used when launch evidence is absent (`src/cli.rs:953`-`src/cli.rs:958`).

- Whole-tree lifecycle control: **PARTIAL**
  - Process-group kill exists in active runtime (`src/core/supervisor.rs:171`, `src/core/supervisor.rs:185`).
  - No `cgroup.kill` path for v2 enforced termination.

- Cgroup v1/v2 semantics and backend selection: **FAIL/PARTIAL**
  - Active executor is hard-wired to v1 type (`src/exec/executor.rs:2`, `src/exec/executor.rs:55`).
  - Backend factory exists but is test-only (`src/kernel/cgroup/backend.rs:88`; callers only tests).
  - `--cgroup-v1` flag not present in CLI commands (no runtime flag wiring).
  - v2 trait reads are placeholders (`src/kernel/cgroup/v2.rs:185`, `src/kernel/cgroup/v2.rs:191`, `src/kernel/cgroup/v2.rs:197`, `src/kernel/cgroup/v2.rs:203`, `src/kernel/cgroup/v2.rs:209`, `src/kernel/cgroup/v2.rs:239`).

- Locked pre-exec step 7 (rlimits + FD close + env hygiene): **FAIL**
  - No runtime `setrlimit`/`RLIMIT_*` calls found in `src/`.
  - FD closure helper exists but uncalled (`src/utils/fd_closure.rs:17`; only test caller).
  - Env hygiene helper exists but uncalled (`src/utils/env_hygiene.rs:67`; no runtime callers).

- Filesystem hardening and cleanup safety: **FAIL/PARTIAL**
  - Multiple `remove_dir_all` usages in runtime/cleanup paths (`src/cli.rs:395`, `src/safety/cleanup.rs:230`, `src/safety/workspace.rs:145`).
  - No symlink-safe `openat/fstatat/unlinkat` cleanup walker integrated.
  - `/proc` hidepid policy exists only in unused policy module (`src/config/policy/proc_sys.rs:103`-`src/config/policy/proc_sys.rs:111`), while active mount path omits `hidepid=2` (`src/kernel/mount/filesystem.rs:472`-`src/kernel/mount/filesystem.rs:507`).

- Failure-path baseline equivalence and escalation: **FAIL/PARTIAL**
  - Cleanup manager/baseline checker are not wired into runtime flows (`src/safety/cleanup.rs` definitions only; no execution-path callers).
  - Ledger consumption bug: successful entries are not removed (`src/safety/cleanup.rs:133`-`src/safety/cleanup.rs:136`).

- Deterministic evidence-backed verdict (`verdict = f(evidence_bundle)`): **FAIL**
  - `VerdictClassifier::classify` is only called from tests (`src/verdict/verdict.rs:320`, `src/verdict/verdict.rs:353`, `src/verdict/verdict.rs:397`).
  - Runtime JSON path synthesizes evidence heuristically (`src/utils/json_schema.rs:343`-`src/utils/json_schema.rs:351`) and hardcodes problematic mappings (e.g. `FileSizeLimit -> NormalExit` at `src/utils/json_schema.rs:459`).

## 4) Additional Correctness Findings

### F1. Runtime architecture changed since prior reports

Older claim "supervisor defined but never instantiated" is stale.
- Active path uses supervisor launch (`src/exec/executor.rs:216` -> `src/core/supervisor.rs:202`).

### F2. Deferred modules were removed, but plan-critical replacements are incomplete

Removed now (stale in old reports):
- `src/observability/health.rs` (missing)
- `src/observability/ops.rs` (missing)
- `src/verdict/abuse.rs` (missing)
- `src/verdict/envelope.rs` (missing)
- `src/verdict/timeout.rs` (missing)

But required enforcement parity is still incomplete (items above).

### F3. Dead/unwired code remains

- `src/exec/typestate.rs` execution wrapper appears uncalled from runtime.
- `src/core/ledger.rs` and `src/kernel/mount/ledger.rs` are largely unintegrated in runtime.
- `src/exec/executor.rs:229` (`wait_with_timeout`) appears unused in active path.

### F4. Test quality and release confidence

Current tree cannot compile, so suite cannot be trusted for release gating.
Even aside from compilation, some tests are structural placeholders:
- `src/exec/preexec.rs:879` and `src/exec/preexec.rs:919` use `assert!(true)` placeholder patterns.
- `src/exec/typestate.rs:158` uses `assert!(result.is_ok() || result.is_err())` (non-informative).
- `src/testing/race_proof.rs:149`-`src/testing/race_proof.rs:159` explicitly says real race proof is not implemented.
- `src/testing/mount_invariance.rs:154`-`src/testing/mount_invariance.rs:156` explicitly says mount operations are simulated.

## 5) Reconciliation Against `.tmp/fix.md` and `.tmp/diff.md`

### Still valid from prior docs
- Missing rlimit hardening and FD closure enforcement.
- Missing symlink-safe cleanup walker.
- Missing `hidepid=2` in active proc mount path.
- v2 metric/evidence gaps and backend-selection wiring gaps.

### No longer valid / stale in prior docs
- Claim that supervisor is never instantiated: stale (active in `core::supervisor`).
- Claims about existing `health.rs`, `ops.rs`, `abuse.rs`, `envelope.rs`: stale (removed).

## 6) Tasklist Snapshot (Selected P0/P1)

- `P0-REMOVE-001`: **PARTIAL** (major dead modules removed; additional cleanup still pending).
- `P0-PGKILL-001`: **PARTIAL/YES** (process-group kill present; no v2 `cgroup.kill`).
- `P0-CLOSEFD-001`: **NO** (helper exists, not enforced in runtime pre-exec).
- `P0-RLIMITS-001`: **NO** (no runtime rlimit application beyond documentation comments).
- `P0-REP-001`: **PARTIAL** (runtime launch evidence path enforced; broader truthful-enforcement reporting still incomplete).
- `P0-RESULT-001` + `P0-PROV-001`: **NO/PARTIAL** (runtime bypasses `VerdictClassifier`; heuristic JSON mappings).
- `P0-CLEAN-001`: **PARTIAL** (cleanup code exists, not fully integrated).
- `P0-CLEAN-002`: **NO** (failure matrix mostly simulated).
- `P0-CLEAN-003`: **NO** (no enforced IE escalation/quarantine path wired).
- `P1-CGROUPSEL-001`: **NO** (`--cgroup-v1` not wired).
- `P1-CGROUP2-001`: **NO** (v2 read-side placeholders).
- `P1-FS-003` / mount invariance proof: **NO** (simulation placeholders, not runtime proof).

## 7) Final Verification Decision

Current implementation is still **not correct** against the full plan/tasklist contract, but status changed after cleanup:
1. It now compiles and tests pass in WSL.
2. Dead/wrong scaffolding was removed (see Section 8).
3. Core stop-ship enforcement gaps remain (rlimits/FD/env step-7, cgroup backend/runtime integration, cleanup safety guarantees, deterministic verdict pipeline).

## 8) Phase-0 Cleanup Applied (2026-02-09)

Dead/wrong code removal completed before enforcement fixes:

Removed files/modules:
- `src/exec/typestate.rs`
- `src/core/ledger.rs`
- `src/kernel/mount/ledger.rs`

Module wiring cleaned:
- `src/exec/mod.rs` (removed `typestate` module export)
- `src/core/mod.rs` (removed `ledger` module export)
- `src/kernel/mount/mod.rs` (removed `ledger` module export/re-export)

Wrong/dead runtime code removed:
- `src/safety/lock_manager.rs` removed stale heartbeat thread function that caused compile break.
- `src/exec/executor.rs` removed unused legacy wait/kill path (`wait_with_timeout`, `terminate_process`, `get_resource_usage`) and dead struct field.
- `src/exec/preexec.rs` removed unused duplicate privilege transition helpers.
- `src/utils/json_schema.rs` removed static capability report generator (configured-vs-applied misreporting path).
- `src/cli.rs` now refuses to emit capability claims without runtime launch evidence.

Validation in WSL after cleanup:
- `cargo build` -> PASS
- `cargo test --all -- --nocapture` -> PASS (including trybuild compile-fail suite)

Current status after cleanup:
- Compilation blockers are resolved.
- Dead scaffolding surface is reduced.
- Next phase should focus on enforcement gaps (rlimits/fd/env step-7, cgroup backend runtime integration, cleanup safety, deterministic verdict pipeline).

## 9) Phase-1 Stop-Ship Applied (2026-02-09)

Phase 1 implementation was completed in incremental commits:

1. `c22d519` - `phase1: remove remaining heartbeat lock path`
- Removed leftover heartbeat-path plumbing from `src/safety/lock_manager.rs` so locking is strictly flock-based.

2. `68ae4f4` - `phase1: wire runtime to cgroup backend abstraction`
- `src/exec/executor.rs` no longer hardcodes `v1::Cgroup`.
- Runtime now constructs backend via `create_cgroup_backend(...)` and uses `dyn CgroupBackend` in production path.
- `src/core/supervisor.rs` now consumes backend trait object instead of v1 concrete type.
- `src/kernel/cgroup/backend.rs` now takes `instance_id` during backend construction.

3. `0f005a4` - `phase1: add cgroup v1 CLI override and config plumbing`
- Added `--cgroup-v1` to `run` and `execute-code` CLI commands.
- Added `force_cgroup_v1` to `IsolateConfig` and plumbed it into executor backend selection.
- Added mutable config accessor on isolate for runtime override wiring.

4. `2bf6e71` - `phase1: implement real cgroup v2 runtime reads`
- Replaced v2 placeholder reads with real parsing of:
  - `memory.current`
  - `memory.peak` (fallback to `memory.current`)
  - `cpu.stat` (`usage_usec`)
  - `pids.current` (fallback `cgroup.procs` counting)
  - `memory.events` (`oom`, `oom_kill`)
  - `memory.max` / `pids.max` evidence extraction
- Fixed v2 backend construction semantics to bind explicit `instance_id` + default base path.

WSL gate results after Phase 1 commits:
- `cargo build -q` -> PASS
- `cargo test --all -q` -> PASS

Phase-1 status:
- Compile unblock: complete
- Runtime cgroup backend wiring: complete
- CLI/config v1 override: complete
- v2 read placeholders removed: complete
