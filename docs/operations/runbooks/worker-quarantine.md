# Runbook: Worker Quarantine and Recovery

**Severity**: Critical  
**Impact**: Worker offline, reduced capacity, potential data loss  
**Detection**: Worker health metrics, health check failures

## Symptoms

- Worker status: `quarantined`
- Alert: `rustbox_worker_health{status="quarantined"} > 0`
- Worker not accepting new submissions
- Health check failures
- Repeated cleanup failures or containment violations

## Root Causes

1. **Cleanup failures**: Repeated cleanup failures (>3 in sequence)
2. **Containment violations**: Orphan process detected
3. **Baseline equivalence failure**: Cannot restore clean state
4. **Resource exhaustion**: Disk full, FD exhaustion, memory pressure
5. **Kernel issues**: Kernel bugs, OOM killer, filesystem corruption

## Investigation Steps

### 1. Check Worker Health

```bash
# Check worker health status
rustbox health

# Expected output:
# {
#   "status": "quarantined",
#   "quarantine_reason": "cleanup_failure",
#   "quarantine_timestamp": "2026-02-08T12:34:56Z",
#   "failed_cleanup_count": 3,
#   "last_cleanup_error": "mount_unmount_failed: /tmp/rustbox-123/root"
# }
```

### 2. Check Quarantine Reason

```bash
# Get detailed quarantine reason
rustbox health | jq '.quarantine_reason'

# Common reasons:
# - "cleanup_failure": Cleanup failed multiple times
# - "orphan_process_detected": Process containment violation
# - "baseline_equivalence_failed": Cannot restore clean state
# - "resource_exhaustion": Disk/FD/memory exhausted
# - "manual_quarantine": Operator-initiated quarantine
```

### 3. Check Resource State

```bash
# Check disk space
df -h /tmp /var/lib/rustbox

# Check FD usage
lsof | wc -l
cat /proc/sys/fs/file-nr

# Check memory
free -h
cat /proc/meminfo

# Check for OOM killer activity
dmesg | grep -i "out of memory"
journalctl | grep -i "oom"
```

### 4. Check for Leftover Resources

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

### 5. Review Quarantine History

```bash
# Check quarantine history
cat /var/lib/rustbox/health/quarantine-history.json

# Look for:
# - Frequency of quarantines
# - Common quarantine reasons
# - Time to recovery
# - Recurring patterns
```

## Recovery Procedures

### Procedure 1: Automatic Recovery (Preferred)

```bash
# Attempt automatic recovery
rustbox health --recover

# This will:
# 1. Clean up leftover resources
# 2. Verify baseline equivalence
# 3. Unquarantine if successful
# 4. Keep quarantined if recovery fails

# Check result
rustbox health
```

### Procedure 2: Manual Resource Cleanup

If automatic recovery fails:

```bash
# 1. Stop rustbox service
systemctl stop rustbox

# 2. Kill all rustbox processes
pkill -9 rustbox

# 3. Clean up mounts (see cleanup-failure.md)
/usr/local/bin/rustbox-cleanup-mounts.sh

# 4. Clean up cgroups (see cleanup-failure.md)
/usr/local/bin/rustbox-cleanup-cgroups.sh

# 5. Clean up temp directories
find /tmp -name "rustbox-*" -type d -exec rm -rf {} \;

# 6. Verify clean state
rustbox health --verify-clean

# 7. If clean, unquarantine
rustbox health --unquarantine

# 8. Restart service
systemctl start rustbox

# 9. Verify worker is healthy
rustbox health
```

### Procedure 3: Resource Exhaustion Recovery

If quarantine due to resource exhaustion:

```bash
# 1. Free disk space
df -h
find /tmp -type f -mtime +1 -delete
find /var/lib/rustbox -type f -mtime +7 -delete

# 2. Close leaked FDs
lsof | grep rustbox | awk '{print $2}' | sort -u | \
  xargs -I {} sh -c 'ls -l /proc/{}/fd | wc -l'

# If high FD count, restart service
systemctl restart rustbox

# 3. Free memory
# Check for memory leaks
ps aux --sort=-%mem | head -20

# If rustbox is leaking, restart
systemctl restart rustbox

# 4. Verify resources available
df -h
free -h
lsof | wc -l

# 5. Unquarantine
rustbox health --unquarantine
```

### Procedure 4: Kernel Issue Recovery

If quarantine due to kernel issues:

```bash
# 1. Check kernel logs
dmesg | tail -100
journalctl -k | tail -100

# Look for:
# - OOM killer messages
# - Filesystem errors
# - Cgroup errors
# - Namespace errors

# 2. If OOM killer active, increase memory limits
# Edit config.json:
{
  "memory_limit": "2G"  # Increase from 1G
}

# 3. If filesystem errors, check filesystem
fsck /dev/sda1  # Or appropriate device

# 4. If kernel bugs suspected, check kernel version
uname -r

# Consider kernel upgrade if known bugs exist

# 5. Reboot if necessary
sudo reboot

# 6. After reboot, verify worker health
rustbox health
```

### Procedure 5: Manual Unquarantine

**WARNING**: Only unquarantine after verifying clean state.

```bash
# 1. Verify clean state
rustbox health --verify-clean

# Expected output:
# {
#   "clean": true,
#   "mounts": 0,
#   "cgroups": 0,
#   "processes": 0,
#   "temp_dirs": 0
# }

# 2. If clean, unquarantine
rustbox health --unquarantine --reason "manual_recovery"

# 3. Verify worker is healthy
rustbox health

# Expected:
# {
#   "status": "healthy",
#   "can_accept_submissions": true
# }

# 4. Monitor for recurrence
watch -n 5 'rustbox health'
```

## Prevention

### 1. Monitor Worker Health

```promql
# Alert on quarantined workers
rustbox_worker_health{status="quarantined"} > 0

# Alert on unhealthy workers
rustbox_worker_health{status="unhealthy"} > 0

# Alert on quarantine rate
rate(rustbox_worker_quarantined_total[1h]) > 0.1
```

### 2. Enable Automatic Recovery

```bash
# Add to systemd timer or cron
*/10 * * * * /usr/local/bin/rustbox health --recover
```

### 3. Resource Monitoring

```promql
# Alert on disk space
node_filesystem_avail_bytes{mountpoint="/tmp"} < 1e9

# Alert on FD usage
process_open_fds / process_max_fds > 0.8

# Alert on memory pressure
node_memory_MemAvailable_bytes < 1e9
```

### 4. Regular Health Checks

```bash
# Run health check every 5 minutes
*/5 * * * * /usr/local/bin/rustbox health --check
```

## Quarantine Policy

### Automatic Quarantine Triggers

1. **Cleanup failures**: 3 consecutive failures
2. **Containment violations**: Any orphan process detected
3. **Baseline equivalence failure**: Cannot restore clean state
4. **Resource exhaustion**: Disk/FD/memory critically low

### Unquarantine Requirements

1. **Clean state verified**: No leftover resources
2. **Root cause identified**: Known why quarantine occurred
3. **Root cause resolved**: Issue fixed or mitigated
4. **Monitoring in place**: Alerts configured for recurrence

### Manual Quarantine

Operators can manually quarantine workers:

```bash
# Manual quarantine
rustbox health --quarantine --reason "maintenance"

# Manual unquarantine
rustbox health --unquarantine --reason "maintenance_complete"
```

## Escalation

Escalate to engineering if:
- Automatic recovery fails repeatedly (>3 times)
- Manual recovery procedures fail
- Quarantine recurs frequently (>1/day)
- Root cause cannot be identified
- Evidence of kernel bugs or corruption
- Worker cannot be unquarantined

## Post-Incident

### 1. Document Incident

- Timestamp of quarantine
- Quarantine reason
- Root cause (if identified)
- Recovery procedure used
- Time to recovery
- Impact (number of affected executions)

### 2. Root Cause Analysis

If quarantine is recurring:
- Review recent code changes
- Check for kernel version issues
- Analyze resource usage patterns
- Review cleanup path logic
- Check for memory leaks

### 3. Update Monitoring

- Add new metrics for identified failure mode
- Update alert thresholds
- Add new dashboard panels
- Document new failure patterns

### 4. Update Procedures

If new recovery procedure discovered:
- Document in this runbook
- Add to automation scripts
- Update training materials

## Related Runbooks

- [Stale State Recovery](stale-state.md)
- [Cleanup Failure](cleanup-failure.md)
- [Orphan Process](orphan-process.md)
- [Backend Mismatch](backend-mismatch.md)

## References

- Plan.md Section 5.1: Failure-Path Discipline Contract
- Plan.md Section 0: Cleanup Failure Escalation (P0-CLEAN-003)
- Code: `src/health.rs` - Worker health tracking
- Metrics: `rustbox_worker_health`, `rustbox_worker_quarantined_total`
