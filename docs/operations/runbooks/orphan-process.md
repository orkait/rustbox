# Runbook: Orphan Process Detection and Cleanup

**Severity**: Critical  
**Impact**: Security boundary breach, resource leaks, potential host contamination  
**Detection**: Process containment proof failures, manual inspection

## Symptoms

- Processes running outside sandbox cgroup
- Processes with rustbox-attributable ancestry but no cgroup membership
- Zombie processes after cleanup
- Processes surviving timeout/kill
- Alert: `rustbox_containment_violation`

## Root Causes

1. **Spawn-to-cgroup race**: Process created before cgroup attachment (should be impossible with attach-before-exec)
2. **Cgroup migration failure**: Process failed to attach to sandbox cgroup
3. **Double-fork escape**: Payload attempted daemonization to escape process tree
4. **PID namespace escape**: Namespace setup failure allowing host PID visibility
5. **Supervisor crash**: Kill/reap path interrupted before completion

## Investigation Steps

### 1. Detect Orphan Processes

```bash
# List all rustbox-attributable processes
ps aux | grep rustbox

# Check process cgroup membership
cat /proc/PID/cgroup

# Expected: All processes should be in rustbox-* cgroup
# Violation: Process in root cgroup or non-rustbox cgroup
```

### 2. Check Process Ancestry

```bash
# Get process tree
pstree -p PID

# Check parent process
ps -o ppid= -p PID

# Verify parent is rustbox supervisor or sandbox-init
ps -p PPID
```

### 3. Check Cgroup State

```bash
# List all rustbox cgroups
find /sys/fs/cgroup -name "rustbox-*" -type d

# Check cgroup membership
cat /sys/fs/cgroup/rustbox-*/cgroup.procs

# Verify all PIDs are accounted for
```

### 4. Review Containment Proof Logs

```bash
# Check for containment violations
journalctl -u rustbox | grep "containment_violation"

# Look for:
# - "orphan_detected"
# - "transient_escape"
# - "post_cleanup_leak"
# - "zombie_detected"
```

### 5. Check Namespace State

```bash
# Check if process is in correct PID namespace
ls -l /proc/PID/ns/pid

# Compare with supervisor namespace
ls -l /proc/SUPERVISOR_PID/ns/pid

# They should be different (sandbox has its own PID namespace)
```

## Recovery Procedures

### Procedure 1: Immediate Containment

**CRITICAL**: Orphan processes represent a security boundary breach.

```bash
# 1. Identify orphan PID
ORPHAN_PID=<detected_pid>

# 2. Verify it's truly orphaned (not in rustbox cgroup)
cat /proc/$ORPHAN_PID/cgroup | grep rustbox || echo "ORPHAN CONFIRMED"

# 3. Immediate kill (do not wait)
kill -9 $ORPHAN_PID

# 4. Verify termination
ps -p $ORPHAN_PID || echo "Process terminated"

# 5. Check for child processes
pgrep -P $ORPHAN_PID

# 6. Kill any children
pkill -9 -P $ORPHAN_PID
```

### Procedure 2: Cgroup-Based Cleanup

```bash
# 1. Find all processes in rustbox cgroups
for cgroup in /sys/fs/cgroup/rustbox-*/cgroup.procs; do
    echo "Cgroup: $cgroup"
    cat $cgroup
done

# 2. Kill all processes in sandbox cgroup
cat /sys/fs/cgroup/rustbox-BOX_ID/cgroup.procs | xargs kill -9

# 3. Wait for termination
sleep 1

# 4. Verify cgroup is empty
cat /sys/fs/cgroup/rustbox-BOX_ID/cgroup.procs

# 5. Remove cgroup
rmdir /sys/fs/cgroup/rustbox-BOX_ID
```

### Procedure 3: Zombie Cleanup

```bash
# 1. List zombie processes
ps aux | grep Z | grep rustbox

# 2. Find parent process
ps -o ppid= -p ZOMBIE_PID

# 3. Signal parent to reap zombie
kill -CHLD PARENT_PID

# 4. If parent is dead, zombie will be reparented to init
# Wait for init to reap
sleep 2

# 5. Verify zombie is gone
ps -p ZOMBIE_PID || echo "Zombie reaped"
```

### Procedure 4: Worker Quarantine

If orphan processes are detected, the worker MUST be quarantined:

```bash
# 1. Mark worker as quarantined
rustbox health --quarantine --reason "orphan_process_detected"

# 2. Stop accepting new submissions
systemctl stop rustbox

# 3. Clean up all active executions
/usr/local/bin/rustbox-cleanup-all.sh

# 4. Verify no rustbox processes remain
ps aux | grep rustbox

# 5. Verify no rustbox cgroups remain
find /sys/fs/cgroup -name "rustbox-*"

# 6. Manual review required before unquarantine
```

## Prevention

### 1. Enable Process Containment Proof

Rustbox includes adversarial containment tests that must pass:

```bash
# Run containment proof suite
cargo test --test process_containment_test

# Expected: All tests pass
# Failure: Indicates containment vulnerability
```

### 2. Monitor Containment Metrics

```promql
# Alert on any containment violations
rustbox_containment_violations_total > 0

# Alert on orphan process detection
rate(rustbox_orphan_processes_detected[5m]) > 0
```

### 3. Enable Strict Mode

Ensure strict mode is enabled (default):

```json
{
  "strict_mode": true,
  "pid_namespace": true,
  "mount_namespace": true
}
```

### 4. Regular Containment Audits

```bash
# Run hourly containment audit
0 * * * * /usr/local/bin/rustbox-audit-containment.sh
```

## Root Cause Analysis

### Spawn-to-Cgroup Race

If orphan is detected during execution:

1. Check if attach-before-exec is properly implemented
2. Review executor.rs spawn logic
3. Verify cgroup attachment happens before any user code runs
4. Check for timing-dependent failures

### Double-Fork Escape

If orphan is a grandchild process:

1. Review payload for daemonization attempts
2. Check if PID namespace isolation is working
3. Verify prctl(PR_SET_PDEATHSIG) is set
4. Check if cgroup.procs includes all descendants

### Namespace Escape

If orphan is in host PID namespace:

1. Check namespace setup in executor
2. Verify unshare() succeeded
3. Check for CLONE_NEWPID flag
4. Review kernel version for namespace bugs

## Escalation

**IMMEDIATE ESCALATION** required if:
- Orphan process detected in production
- Containment proof tests fail
- Orphan processes recur (>1 occurrence)
- Evidence of namespace escape
- Payload can see host processes

This is a **CRITICAL SECURITY INCIDENT**.

## Post-Incident

### 1. Security Review

- Full code review of spawn/attach logic
- Review of all containment proof tests
- Kernel version compatibility check
- Adversarial testing with double-fork payloads

### 2. Incident Report

Document:
- Timestamp of detection
- Orphan PID and ancestry
- Cgroup state at detection
- Namespace state at detection
- Payload characteristics
- Recovery actions taken
- Root cause (if identified)

### 3. Containment Proof Re-validation

```bash
# Re-run full containment proof suite
cargo test --test process_containment_test -- --nocapture

# Run adversarial payloads
./tests/adversarial/contain_double_fork
./tests/adversarial/contain_exec_churn
./tests/adversarial/contain_sigterm_ignore
```

### 4. Update Defenses

If root cause identified:
- Update spawn-to-cgroup logic
- Add additional containment checks
- Enhance monitoring
- Update containment proof tests

## Related Runbooks

- [Stale State Recovery](stale-state.md)
- [Cleanup Failure](cleanup-failure.md)
- [Worker Quarantine](worker-quarantine.md)

## References

- Plan.md Section 7.1: Process Containment Proof Contract
- Plan.md Section 1: Isolation Core (P1-CONTAIN-001)
- Plan.md Section 1: Spawn-to-Cgroup Race Elimination (P1-RACE-001)
- Tests: `tests/process_containment_test.rs`
- Tests: `tests/adversarial/contain_*.c`
