# Runbook: Stale State Recovery

**Severity**: Warning  
**Impact**: Worker capacity reduced, potential resource leaks  
**Detection**: Worker health checks, manual inspection

## Symptoms

- Worker marked as unhealthy or quarantined
- Stale lock files in `/var/lib/rustbox/boxes/*/lock`
- Orphaned cgroup directories
- Leftover mount points
- Zombie processes attributable to rustbox

## Root Causes

1. **Supervisor crash**: Rustbox supervisor process killed unexpectedly
2. **System crash**: Host system crash or power loss during execution
3. **Cleanup failure**: Cleanup path failed to complete successfully
4. **Lock corruption**: Lock file corrupted or inaccessible

## Investigation Steps

### 1. Check Worker Health Status

```bash
# Check worker health
rustbox health

# Expected output shows worker status
# Look for: status="unhealthy" or status="quarantined"
```

### 2. Inspect Lock Files

```bash
# List all lock files
find /var/lib/rustbox/boxes -name "lock" -type f

# Check lock file contents
cat /var/lib/rustbox/boxes/*/lock

# Look for:
# - Stale PIDs (process no longer exists)
# - Corrupted JSON
# - Very old timestamps
```

### 3. Check for Orphaned Resources

```bash
# Check for orphaned cgroups
find /sys/fs/cgroup -name "rustbox-*" -type d

# Check for orphaned mounts
mount | grep rustbox

# Check for zombie processes
ps aux | grep rustbox | grep Z

# Check for leftover temp directories
find /tmp -name "rustbox-*" -type d
```

### 4. Review Logs

```bash
# Check rustbox logs for cleanup failures
journalctl -u rustbox -n 1000 | grep -i "cleanup\|failure\|error"

# Look for:
# - "cleanup_failure" events
# - "worker_quarantined" events
# - Panic messages
# - OOM killer messages
```

## Recovery Procedures

### Procedure 1: Automatic Recovery (Preferred)

```bash
# Trigger health check and auto-recovery
rustbox health --recover

# This will:
# 1. Detect stale state
# 2. Clean up orphaned resources
# 3. Mark worker healthy if successful
```

### Procedure 2: Manual Lock Cleanup

**WARNING**: Only perform if automatic recovery fails and you've verified the process is truly dead.

```bash
# 1. Verify process is dead
PID=$(cat /var/lib/rustbox/boxes/BOX_ID/lock | jq -r '.pid')
ps -p $PID || echo "Process is dead"

# 2. Backup lock file
cp /var/lib/rustbox/boxes/BOX_ID/lock /var/lib/rustbox/boxes/BOX_ID/lock.backup

# 3. Remove stale lock
rm /var/lib/rustbox/boxes/BOX_ID/lock

# 4. Verify worker health
rustbox health
```

### Procedure 3: Manual Cgroup Cleanup

```bash
# 1. List rustbox cgroups
find /sys/fs/cgroup -name "rustbox-*" -type d

# 2. Check if cgroup is empty
cat /sys/fs/cgroup/CGROUP_PATH/cgroup.procs

# 3. If empty, remove cgroup
rmdir /sys/fs/cgroup/CGROUP_PATH

# 4. If not empty, kill processes first
cat /sys/fs/cgroup/CGROUP_PATH/cgroup.procs | xargs kill -9
sleep 1
rmdir /sys/fs/cgroup/CGROUP_PATH
```

### Procedure 4: Manual Mount Cleanup

```bash
# 1. List rustbox mounts
mount | grep rustbox

# 2. Unmount in reverse order (deepest first)
umount /path/to/mount/point

# 3. If busy, find processes using mount
lsof | grep /path/to/mount/point

# 4. Kill processes and retry unmount
kill -9 PID
umount /path/to/mount/point

# 5. If still stuck, use lazy unmount (last resort)
umount -l /path/to/mount/point
```

### Procedure 5: Full Worker Reset

**WARNING**: This will terminate all active executions on the worker.

```bash
# 1. Stop rustbox service
systemctl stop rustbox

# 2. Kill all rustbox processes
pkill -9 rustbox

# 3. Clean up all resources
/usr/local/bin/rustbox-cleanup-all.sh

# 4. Verify clean state
rustbox health --verify-clean

# 5. Restart service
systemctl start rustbox

# 6. Verify worker is healthy
rustbox health
```

## Prevention

### 1. Enable Automatic Health Checks

```bash
# Add to systemd timer or cron
*/5 * * * * /usr/local/bin/rustbox health --recover
```

### 2. Monitor Worker Health Metrics

```promql
# Alert on unhealthy workers
rustbox_worker_health{status="unhealthy"} > 0

# Alert on quarantined workers
rustbox_worker_health{status="quarantined"} > 0
```

### 3. Enable Cleanup Failure Alerts

```promql
# Alert on cleanup failures
rate(rustbox_cleanup_total{outcome="failure"}[5m]) > 0
```

### 4. Regular State Audits

```bash
# Run daily state audit
0 2 * * * /usr/local/bin/rustbox-audit-state.sh
```

## Escalation

Escalate to engineering if:
- Automatic recovery fails repeatedly (>3 times)
- Manual cleanup procedures fail
- Stale state recurs frequently (>1/day)
- Evidence of kernel bugs or OOM killer activity
- Corruption in lock files or metadata

## Post-Incident

### 1. Document Incident

- Timestamp of detection
- Root cause (if identified)
- Recovery procedure used
- Time to recovery
- Impact (number of affected executions)

### 2. Review Logs

```bash
# Extract relevant logs for analysis
journalctl -u rustbox --since "1 hour ago" > incident-logs.txt
```

### 3. Update Metrics

- Record incident in incident tracking system
- Update MTTR (Mean Time To Recovery) metrics
- Review SLO impact

### 4. Root Cause Analysis

If stale state is recurring:
- Review recent code changes
- Check for kernel version issues
- Analyze resource pressure patterns
- Review cleanup path logic

## Related Runbooks

- [Cleanup Failure](cleanup-failure.md)
- [Worker Quarantine](worker-quarantine.md)
- [Orphan Process](orphan-process.md)

## References

- Plan.md Section 5.1: Failure-Path Discipline Contract
- Plan.md Section 0: Cleanup Safety (P0-CLEAN-001, P0-CLEAN-002, P0-CLEAN-003)
- Metrics: `rustbox_worker_health`, `rustbox_cleanup_total`
