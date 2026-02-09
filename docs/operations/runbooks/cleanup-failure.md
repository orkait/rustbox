# Runbook: Cleanup Failure Recovery

**Severity**: Critical  
**Impact**: Resource leaks, worker quarantine, reduced capacity  
**Detection**: Cleanup failure metrics, worker health checks, IE verdicts

## Symptoms

- Worker marked as quarantined
- Verdict status: `IE` (Internal Error)
- Alert: `rustbox_cleanup_failure_rate > 0.01%`
- Leftover mounts, cgroups, or processes after execution
- Cleanup duration exceeds timeout

## Root Causes

1. **Mount unmount failure**: Mount point busy or permission denied
2. **Cgroup removal failure**: Cgroup not empty or in use
3. **Process reap failure**: Processes not fully terminated
4. **Filesystem errors**: Disk full, I/O errors, permission issues
5. **Kernel bugs**: Cgroup or namespace kernel bugs
6. **Resource exhaustion**: FD limit, memory pressure, CPU starvation

## Investigation Steps

### 1. Check Cleanup Metrics

```bash
# Check cleanup failure rate
curl http://localhost:9090/metrics | grep rustbox_cleanup_total

# Expected: outcome="success" >> outcome="failure"
# Problem: outcome="failure" > 0 or outcome="partial" > 0
```

### 2. Review Cleanup Logs

```bash
# Check for cleanup failures
journalctl -u rustbox | grep "cleanup_failure"

# Look for:
# - "mount_unmount_failed"
# - "cgroup_removal_failed"
# - "process_reap_failed"
# - "cleanup_timeout"
# - "baseline_equivalence_failed"
```

### 3. Check Worker Health

```bash
# Check worker health status
rustbox health

# Look for:
# - status="quarantined"
# - quarantine_reason="cleanup_failure"
# - failed_cleanup_count > 0
```

### 4. Inspect Leftover Resources

```bash
# Check for leftover mounts
mount | grep rustbox

# Check for leftover cgroups
find /sys/fs/cgroup -name "rustbox-*" -type d

# Check for leftover processes
ps aux | grep rustbox

# Check for leftover temp directories
find /tmp -name "rustbox-*" -type d
```

### 5. Check Baseline Equivalence

```bash
# Capture current state
/usr/local/bin/rustbox-capture-baseline.sh > current-state.txt

# Compare with expected baseline
diff baseline-state.txt current-state.txt

# Look for:
# - Additional mounts
# - Additional cgroups
# - Additional processes
# - Additional temp directories
```

## Recovery Procedures

### Procedure 1: Automatic Recovery (Preferred)

```bash
# Trigger automatic cleanup recovery
rustbox health --recover --cleanup

# This will:
# 1. Detect leftover resources
# 2. Attempt cleanup in reverse order
# 3. Mark worker healthy if successful
# 4. Keep quarantined if cleanup fails
```

### Procedure 2: Manual Mount Cleanup

```bash
# 1. List rustbox mounts
mount | grep rustbox | tee rustbox-mounts.txt

# 2. Unmount in reverse order (deepest first)
# Sort by depth (count slashes)
cat rustbox-mounts.txt | awk '{print $3}' | \
  awk '{print gsub(/\//, "/"), $0}' | sort -rn | \
  awk '{print $2}' | while read mount; do
    echo "Unmounting: $mount"
    umount "$mount" || echo "Failed: $mount"
done

# 3. Check for busy mounts
mount | grep rustbox

# 4. If busy, find processes
lsof | grep rustbox

# 5. Kill processes and retry
kill -9 PID
umount /path/to/mount

# 6. Last resort: lazy unmount
umount -l /path/to/mount
```

### Procedure 3: Manual Cgroup Cleanup

```bash
# 1. List rustbox cgroups
find /sys/fs/cgroup -name "rustbox-*" -type d | tee rustbox-cgroups.txt

# 2. For each cgroup, check if empty
for cgroup in $(cat rustbox-cgroups.txt); do
    echo "Checking: $cgroup"
    cat "$cgroup/cgroup.procs"
done

# 3. Kill processes in non-empty cgroups
for cgroup in $(cat rustbox-cgroups.txt); do
    if [ -s "$cgroup/cgroup.procs" ]; then
        echo "Killing processes in: $cgroup"
        cat "$cgroup/cgroup.procs" | xargs kill -9
    fi
done

# 4. Wait for termination
sleep 2

# 5. Remove cgroups (deepest first)
cat rustbox-cgroups.txt | sort -r | while read cgroup; do
    echo "Removing: $cgroup"
    rmdir "$cgroup" || echo "Failed: $cgroup"
done
```

### Procedure 4: Manual Process Cleanup

```bash
# 1. List all rustbox processes
ps aux | grep rustbox | tee rustbox-processes.txt

# 2. Kill all rustbox processes
ps aux | grep rustbox | awk '{print $2}' | xargs kill -9

# 3. Wait for termination
sleep 2

# 4. Check for zombies
ps aux | grep Z | grep rustbox

# 5. If zombies exist, signal parent
ps aux | grep Z | grep rustbox | awk '{print $2}' | while read pid; do
    ppid=$(ps -o ppid= -p $pid)
    kill -CHLD $ppid
done
```

### Procedure 5: Filesystem Cleanup

```bash
# 1. Remove temp directories
find /tmp -name "rustbox-*" -type d -mtime +1 -exec rm -rf {} \;

# 2. Check disk space
df -h /tmp /var/lib/rustbox

# 3. If disk full, clean up old artifacts
find /var/lib/rustbox -type f -mtime +7 -delete
```

### Procedure 6: Worker Unquarantine

**Only after successful cleanup and verification:**

```bash
# 1. Verify clean state
rustbox health --verify-clean

# 2. If clean, unquarantine
rustbox health --unquarantine

# 3. Verify worker is healthy
rustbox health

# 4. Monitor for recurrence
watch -n 5 'rustbox health'
```

## Prevention

### 1. Enable Cleanup Monitoring

```promql
# Alert on cleanup failures
rate(rustbox_cleanup_total{outcome="failure"}[5m]) > 0

# Alert on partial cleanups
rate(rustbox_cleanup_total{outcome="partial"}[5m]) > 0

# Alert on cleanup duration
histogram_quantile(0.95, 
  rate(rustbox_cleanup_duration_seconds_bucket[5m])
) > 5
```

### 2. Enable Automatic Quarantine

Rustbox automatically quarantines workers after cleanup failures:

```rust
// Configured in health.rs
const MAX_CLEANUP_FAILURES: usize = 3;
```

### 3. Regular Cleanup Audits

```bash
# Run daily cleanup audit
0 3 * * * /usr/local/bin/rustbox-audit-cleanup.sh
```

### 4. Resource Monitoring

```bash
# Monitor disk space
df -h /tmp /var/lib/rustbox

# Monitor FD usage
lsof | wc -l

# Monitor memory pressure
free -h
```

## Root Cause Analysis

### Mount Unmount Failures

Common causes:
- Processes still using mount point
- Nested mounts not unmounted first
- Permission issues
- Filesystem corruption

Investigation:
```bash
# Find processes using mount
lsof | grep /path/to/mount

# Check mount options
mount | grep /path/to/mount

# Check filesystem errors
dmesg | grep -i error | grep -i mount
```

### Cgroup Removal Failures

Common causes:
- Processes still in cgroup
- Nested cgroups not removed first
- Kernel holding reference
- Cgroup v1/v2 compatibility issues

Investigation:
```bash
# Check cgroup contents
cat /sys/fs/cgroup/rustbox-*/cgroup.procs

# Check for nested cgroups
find /sys/fs/cgroup/rustbox-* -type d

# Check kernel version
uname -r
```

### Process Reap Failures

Common causes:
- Processes in uninterruptible sleep (D state)
- Zombie processes with dead parent
- PID namespace issues
- Signal delivery failures

Investigation:
```bash
# Check process state
ps aux | grep rustbox

# Check for D state processes
ps aux | grep D | grep rustbox

# Check for zombies
ps aux | grep Z | grep rustbox
```

## Escalation

Escalate to engineering if:
- Cleanup failures recur frequently (>1/hour)
- Manual cleanup procedures fail
- Evidence of kernel bugs
- Filesystem corruption detected
- Worker cannot be unquarantined
- Baseline equivalence cannot be restored

## Post-Incident

### 1. Document Incident

- Timestamp of detection
- Root cause (if identified)
- Resources that failed to clean up
- Recovery procedure used
- Time to recovery
- Impact (number of affected executions)

### 2. Update Cleanup Logic

If root cause identified:
- Update cleanup order
- Add retry logic
- Enhance error handling
- Update cleanup tests

### 3. Run Failure Matrix Tests

```bash
# Re-run failure injection matrix
cargo test --test failure_matrix_test

# Verify all scenarios pass
```

### 4. Update Monitoring

- Add new metrics for identified failure mode
- Update alert thresholds
- Add new dashboard panels

## Related Runbooks

- [Stale State Recovery](stale-state.md)
- [Worker Quarantine](worker-quarantine.md)
- [Orphan Process](orphan-process.md)

## References

- Plan.md Section 5.1: Failure-Path Discipline Contract
- Plan.md Section 0: Cleanup Safety (P0-CLEAN-001, P0-CLEAN-002, P0-CLEAN-003)
- Plan.md Section 1: Zero-Leak Cleanup Guarantee (P1-LEAK-001)
- Tests: `tests/failure_matrix_test.rs`
- Tests: `tests/leak_check_test.rs`
- Metrics: `rustbox_cleanup_total`, `rustbox_cleanup_duration_seconds`
