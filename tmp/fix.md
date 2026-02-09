# Rustbox Verification + Remaining Fixes

Date: 2026-02-09 (WSL)
Repo: /mnt/c/codingFiles/orkait/rustbox

## What Was Verified In WSL

- `cargo test --all` passes (144 unit tests + trybuild).
- Root-required containment smoke passes:
  - `scripts/smoke/phase2_containment_smoke.sh`
  - timeout and descendant cases both return `PASS`.
- Runtime timeout verdict now reports truthful judge provenance (`TLE` + `tle_wall_judge`) for wrapper exit code `143`.

## Commits Applied In This Pass

1. `dc2145f` phase3: prioritize judge kill evidence over wrapper exit codes
2. `0127588` phase0: remove dead warning paths and harden smoke status match
3. `e286067` phase3: make cgroup capability evidence runtime-truthful

## Remaining Gaps Against plan/tasklist

### 1) Mount/Root Transition Step Is Still Not Enforced In Active Runtime Path

Severity: High

Evidence:
- Active pre-exec chain in `src/core/proxy.rs` executes:
  - `setup_namespaces` -> `harden_mount_propagation` -> `attach_to_cgroup` -> hygiene/creds/privs -> `exec`
  - There is no mount/bind/root transition step in this chain (`src/core/proxy.rs:60` onward).
- `src/exec/preexec.rs` documents Step 5 (mount/bind + root transition), but no typestate transition currently performs it in the active path (`src/exec/preexec.rs:12` and chain implementation).
- `FilesystemSecurity` setup is currently done from executor construction in parent process (`src/exec/executor.rs:85` onward), not in child pre-exec path.

Impact:
- Contract in plan Section 6 Step 5 is not fully met in the runtime execution path.
- Filesystem hardening behavior is split and may not match the strict pre-exec ordering contract.

### 2) Output Integrity In Judge JSON Is Still Heuristic

Severity: Medium

Evidence:
- `JudgeResultV1::from_execution_result` sets output integrity by simple length check (`src/utils/json_schema.rs:177`-`src/utils/json_schema.rs:181`).
- `OutputCollector` has richer integrity states but is not wired into the active runtime result pipeline (`src/utils/output.rs`, no active call path from `src/core/proxy.rs`/`src/cli.rs`).

Impact:
- `output_integrity` can overstate certainty and does not consistently reflect truncation/crash/program-close/write-error semantics.

### 3) Namespace Control Reporting Still Assumes Success In Permissive Paths

Severity: Medium

Evidence:
- `build_launch_evidence` marks most non-cgroup configured controls as applied by default (`src/core/supervisor.rs:86`-`src/core/supervisor.rs:101`).
- For permissive mode namespace failures, pre-exec can log and continue without producing explicit per-control failure evidence.

Impact:
- Capability report can still over-claim applied namespace controls in permissive mode when enforcement is not proven.

## Suggested Next Implementation Order

1. Add a real Step-5 typestate transition for mount/bind/root transition and invoke it in `src/core/proxy.rs` before hygiene.
2. Move/limit filesystem setup so parent-side pre-launch mount work is removed from `src/exec/executor.rs`.
3. Wire output capture through `OutputCollector` (or equivalent) and pass computed integrity into `JudgeResultV1`.
4. Track per-control enforcement outcomes in pre-exec and feed those into `build_launch_evidence` to avoid permissive over-claims.
