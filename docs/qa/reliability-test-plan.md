# Stress and Crash Reliability Test Plan (QA-REL-001)

**Purpose**: Validate stability under load and cleanup integrity under crash.  
**Invariant**: No leaked processes/mounts/cgroups/state after stress.

## Test Coverage

### 1. Long-Run Stress Test

**Test**: Execute 10,000+ submissions continuously

**Scenarios**:
- Mix of OK, TLE, MLE, RE outcomes
- Random timeout values
- Random memory limits
- Random process limits
- Mix of languages (C++, Java, Python)

**Assertions**:
- No resource leaks (processes, mounts, cgroups, FDs, temp dirs)
- No worker quarantines
- No cleanup failures
- Consistent performance (no degradation)
- All verdicts correct

**Duration**: 1 hour minimum

**Evidence**: Stress test script in `tests/scripts/stress_test.sh`

### 2. Concurrent Execution Stress

**Test**: Run 100+ concurrent executions

**Scenarios**:
- High concurrency (100+ active executions)
- Rapid submission rate (1000+ submissions/minute)
- Resource contention (memory, CPU, FDs)

**Assertions**:
- No deadlocks
- No race conditions
- No resource exhaustion
- All executions complete correctly
- Queue depth remains bounded

**Duration**: 30 minutes minimum

**Evidence**: Concurrent stress test in `tests/scripts/concurrent_stress.sh`

### 3. Crash Recovery Test

**Test**: Kill supervisor at various execution phases

**Scenarios**:
- Kill during setup
- Kill during execution
- Kill during timeout
- Kill during cleanup
- Kill during verdict computation

**Assertions**:
- No orphan processes
- No leftover mounts
- No leftover cgroups
- No corrupted state files
- Worker recovers to healthy state

**Evidence**: Tests in `tests/failure_matrix_test.rs` (P0-CLEAN-002)

### 4. Cleanup Failure Injection

**Test**: Inject failures at each cleanup step

**Scenarios**:
- Mount unmount failure
- Cgroup removal failure
- Process reap failure
- FD close failure
- Temp directory removal failure

**Assertions**:
- Baseline equivalence maintained
- Worker quarantined on failure
- No silent leaks
- Recovery possible

**Evidence**: Tests in `tests/failure_matrix_test.rs`

### 5. Resource Exhaustion Test

**Test**: Execute under resource pressure

**Scenarios**:
- Disk full condition
- FD limit reached
- Memory pressure (host)
- CPU saturation (host)

**Assertions**:
- Graceful degradation
- No crashes
- Clear error messages
- Recovery after resources available

**Evidence**: Resource exhaustion tests in `tests/scripts/resource_exhaustion.sh`

### 6. Leak Detection Test

**Test**: Verify zero leaks after 1000+ executions

**Scenarios**:
- Normal completion
- Timeout termination
- Crash termination
- Forced kill termination

**Assertions**:
- Zero leaked processes
- Zero leaked mounts
- Zero leaked cgroups
- Zero leaked FDs
- Zero leaked temp directories
- Zero zombies

**Evidence**: Tests in `tests/leak_check_test.rs` (P1-LEAK-001)

### 7. Lock Integrity Test

**Test**: Concurrent access to same box

**Scenarios**:
- Multiple processes attempt to lock same box
- Lock holder crashes
- Lock file corruption
- Stale lock detection

**Assertions**:
- No split-brain
- No concurrent execution in same box
- Stale locks detected and recovered
- Lock corruption handled gracefully

**Evidence**: Lock tests in `src/lock_manager.rs`

### 8. State Corruption Recovery

**Test**: Corrupt state files and verify recovery

**Scenarios**:
- Corrupted JSON
- Partial writes
- Missing files
- Invalid data

**Assertions**:
- Corruption detected
- State quarantined
- Service continues
- Clear audit trail

**Evidence**: Tests in `src/isolate.rs` (P0-LCK-003)

## Test Execution

### Run Stress Tests

```bash
# Long-run stress test (1 hour)
./tests/scripts/stress_test.sh --duration 3600 --submissions 10000

# Concurrent stress test (30 minutes)
./tests/scripts/concurrent_stress.sh --duration 1800 --concurrency 100

# Resource exhaustion test
./tests/scripts/resource_exhaustion.sh

# Leak check stress
./tests/scripts/leak_check_stress.sh --iterations 1000
```

### Run Crash Recovery Tests

```bash
# Failure matrix test
cargo test --test failure_matrix_test

# Leak check test
cargo test --test leak_check_test
```

### CI Integration

Reliability tests run:
- On every release candidate
- Weekly in staging environment
- Before production deployment

```yaml
# .github/workflows/reliability.yml
name: Reliability Tests
on:
  schedule:
    - cron: '0 2 * * 0'  # Weekly
jobs:
  stress:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run stress test
        run: ./tests/scripts/stress_test.sh --duration 3600
      - name: Check for leaks
        run: ./tests/scripts/leak_check_stress.sh --iterations 1000
```

## Pass Criteria

All tests must pass with:
- ✅ Zero resource leaks
- ✅ Zero worker quarantines (except intentional)
- ✅ Zero cleanup failures
- ✅ Zero crashes
- ✅ Zero deadlocks
- ✅ Consistent performance (no degradation >10%)

## Metrics to Monitor

During stress testing, monitor:

```promql
# Cleanup success rate
rate(rustbox_cleanup_total{outcome="success"}[5m]) / 
rate(rustbox_cleanup_total[5m])

# Worker health
rustbox_worker_health{status="healthy"}

# Execution rate
rate(rustbox_executions_total[5m])

# Error rate
rate(rustbox_executions_by_status{status="IE"}[5m]) /
rate(rustbox_executions_total[5m])

# Latency
histogram_quantile(0.95, 
  rate(rustbox_execution_duration_seconds_bucket[5m])
)
```

## Failure Response

If any reliability test fails:
1. **Investigate**: Identify root cause
2. **Reproduce**: Minimal reproduction case
3. **Fix**: Address reliability issue
4. **Verify**: Re-run full suite
5. **Document**: Update known issues

## Soak Testing

Before v1 release, run soak test:
- Duration: 7 days continuous
- Load: 1000 submissions/hour
- Mix: 70% OK, 20% TLE, 5% MLE, 5% RE
- Monitoring: 24/7 with alerts

**Pass criteria**:
- Zero high-severity incidents
- Zero resource leaks
- Zero worker quarantines
- <0.01% IE rate
- <1% performance degradation

## Related Documentation

- Plan.md Section 15: Verification Matrix
- Plan.md Section 5.1: Failure-Path Discipline Contract
- Plan.md Section 0: Cleanup Safety (P0-CLEAN-001, P0-CLEAN-002, P0-CLEAN-003)
- Plan.md Section 1: Zero-Leak Cleanup Guarantee (P1-LEAK-001)
- Tests: `tests/failure_matrix_test.rs`
- Tests: `tests/leak_check_test.rs`
- Scripts: `tests/scripts/stress_test.sh`
- Scripts: `tests/scripts/leak_check_stress.sh`
