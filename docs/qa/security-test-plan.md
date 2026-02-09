# Security Test Plan (QA-SEC-001)

**Purpose**: Continuously challenge security guarantees with adversarial payloads.  
**Invariant**: Escape/resource-evasion classes are continuously tested.

## Test Coverage

### 1. Path Traversal and Symlink Attacks

**Tests**:
- `path_traversal_basic`: Attempt to access `/etc/passwd`
- `path_traversal_dotdot`: Attempt `../../etc/passwd`
- `path_traversal_absolute`: Attempt absolute path `/etc/passwd`
- `symlink_escape`: Create symlink to `/etc/passwd`
- `symlink_race`: TOCTOU symlink race condition

**Expected**: All attempts rejected, no host file access

**Evidence**: Tests in `tests/adversarial_security_test.rs`

### 2. Fork Bomb and Process Tree Evasion

**Tests**:
- `fork_bomb_basic`: Rapid fork() until process limit
- `fork_bomb_with_exec`: Fork+exec bomb
- `containment_double_fork`: Double-fork daemonization
- `containment_exec_churn`: Repeated fork+exec churn

**Expected**: All processes contained, process limit enforced, no orphans

**Evidence**: 
- Tests in `tests/process_containment_test.rs`
- Payloads in `tests/adversarial/contain_*.c`

### 3. Timeout Evasion

**Tests**:
- `timeout_busy_loop`: CPU-intensive busy loop
- `timeout_sleep`: Long sleep to evade CPU timeout
- `timeout_fork_storm`: Fork storm to distribute CPU time

**Expected**: All terminated by appropriate timeout (CPU or wall)

**Evidence**: Tests in `tests/adversarial_security_test.rs`

### 4. Spawn-to-Cgroup Race

**Tests**:
- `spawn_race_fork`: Immediate fork after spawn
- `spawn_race_memory`: Immediate memory allocation

**Expected**: All processes attached to cgroup before execution, all resources charged to sandbox cgroup

**Evidence**: Tests in `tests/race_proof_test.rs` (P1-RACE-001)

### 5. Process Containment Violations

**Tests**:
- `containment_double_fork`: Double-fork daemonization attempt
- `containment_exec_churn`: Exec churn to escape tracking
- `containment_signal_ignore`: SIGTERM ignore to evade kill

**Expected**: No orphan processes, no transient out-of-cgroup PIDs, no zombies, full reap

**Evidence**: 
- Tests in `tests/process_containment_test.rs` (P1-CONTAIN-001)
- Adversarial payloads in `tests/adversarial/`

### 6. Filesystem Mount Invariance

**Tests**:
- `mount_invariance_success`: Host mount table unchanged after success
- `mount_invariance_failure`: Host mount table unchanged after failure/panic/kill

**Expected**: Empty normalized host mountinfo diff across all paths

**Evidence**: Tests in `tests/filesystem_mountinfo_diff_test.rs` (P1-FS-003)

### 7. Syscall Filter Bypass (when enabled)

**Tests**:
- Attempt forbidden syscalls when filtering enabled
- Verify filtering metadata in capability report
- Verify failure attribution to filter, not judge

**Expected**: Forbidden syscalls blocked, failures attributed to filter

**Evidence**: Tests in `tests/seccomp_metadata_test.rs` (P15-SECCOMP-003)

**Note**: Syscall filtering is disabled by default and requires explicit `--enable-syscall-filtering` flag

### 8. Privilege Escalation Attempts

**Tests**:
- Attempt to gain capabilities after drop
- Attempt setuid/setgid after transition
- Attempt to bypass no_new_privs

**Expected**: All attempts fail, no privilege gain possible

**Evidence**: Tests in `tests/uid_gid_transition_test.rs` (P15-PRIV-003)

### 9. Appeal Safety (Evidence Integrity)

**Tests**:
- `appeal_safety_missing_evidence`: Missing required evidence → IE
- `appeal_safety_contradictory`: Contradictory evidence → IE

**Expected**: Never guess verdict, always IE when evidence insufficient

**Evidence**: Tests in `tests/adversarial_security_test.rs`

## Test Execution

### Run Full Suite

```bash
# Run all security tests
cargo test --test adversarial_security_test
cargo test --test process_containment_test
cargo test --test filesystem_mountinfo_diff_test
cargo test --test race_proof_test
cargo test --test uid_gid_transition_test
cargo test --test seccomp_metadata_test

# Run with verbose output
cargo test --test adversarial_security_test -- --nocapture
```

### CI Integration

Security tests run on every commit:

```yaml
# .github/workflows/security.yml
name: Security Tests
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run adversarial security suite
        run: cargo test --test adversarial_security_test
      - name: Run containment proof
        run: cargo test --test process_containment_test
      - name: Run mount invariance proof
        run: cargo test --test filesystem_mountinfo_diff_test
```

## Pass Criteria

All tests must pass with:
- ✅ No security boundary breaches
- ✅ No orphan processes
- ✅ No host contamination
- ✅ No resource leaks
- ✅ No false verdicts (IE when evidence missing)

## Failure Response

If any security test fails:
1. **STOP**: Do not merge, do not deploy
2. **Investigate**: Root cause analysis required
3. **Fix**: Address security vulnerability
4. **Verify**: Re-run full suite
5. **Document**: Update security advisory if needed

## Continuous Testing

Security tests run:
- On every commit (CI)
- Before every release (RC testing)
- Weekly in production (canary testing)
- After any security-related code change

## Related Documentation

- Plan.md Section 15: Verification Matrix
- Plan.md Section 3: Threat Model
- Plan.md Section 7.1: Process Containment Proof Contract
- Plan.md Section 9.1: Host Mount Invariance Proof Contract
- Tests: `tests/adversarial_security_test.rs`
- Tests: `tests/process_containment_test.rs`
- Tests: `tests/filesystem_mountinfo_diff_test.rs`
