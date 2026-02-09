# Runbook: Backend Mismatch and Degradation

**Severity**: Warning  
**Impact**: Reduced functionality, potential strict mode violations  
**Detection**: Backend selection metrics, capability reports, control degradation alerts

## Symptoms

- Alert: `rustbox_control_degraded > 0`
- Capability report shows `missing_controls`
- Backend selection differs from expected
- Cgroup v2 expected but v1 selected
- Pidfd expected but fallback used
- Strict mode execution rejected

## Root Causes

1. **Kernel version mismatch**: Kernel doesn't support expected features
2. **Cgroup configuration**: Cgroup v2 not mounted or not enabled
3. **Permission issues**: Insufficient permissions for cgroup operations
4. **System configuration**: Systemd or init system configuration issues
5. **Kernel module missing**: Required kernel modules not loaded

## Investigation Steps

### 1. Check Backend Selection

```bash
# Check current backend selection
rustbox health | jq '.backend_selection'

# Expected output:
# {
#   "cgroup_backend": "v2",
#   "pidfd_mode": "native",
#   "namespace_support": "full"
# }
```

### 2. Check Capability Report

```bash
# Run dry-run to see capability report
rustbox --dry-run run --code "echo test"

# Look for:
# - configured_controls vs applied_controls
# - missing_controls (should be empty in strict mode)
# - mode_decision_reason
# - unsafe_execution_reason
```

### 3. Check Cgroup Version

```bash
# Check if cgroup v2 is mounted
mount | grep cgroup2

# Expected: cgroup2 on /sys/fs/cgroup type cgroup2
# Problem: No cgroup2 mount or cgroup v1 only

# Check cgroup controllers
cat /sys/fs/cgroup/cgroup.controllers

# Expected: cpu memory pids
# Problem: Missing controllers
```

### 4. Check Kernel Version

```bash
# Check kernel version
uname -r

# Check for required features
# - Cgroup v2: kernel >= 4.5
# - Pidfd: kernel >= 5.3
# - PID namespace: kernel >= 2.6.24
# - Mount namespace: kernel >= 2.4.19

# Check kernel config
zcat /proc/config.gz | grep -E 'CGROUP|PIDFD|NAMESPACE'
```

### 5. Check Permissions

```bash
# Check cgroup permissions
ls -la /sys/fs/cgroup

# Check if user can create cgroups
mkdir /sys/fs/cgroup/rustbox-test
rmdir /sys/fs/cgroup/rustbox-test

# Check capabilities
capsh --print | grep cap_sys_admin
```

## Recovery Procedures

### Procedure 1: Enable Cgroup v2

**For systemd-based systems:**

```bash
# 1. Check current cgroup mode
stat -fc %T /sys/fs/cgroup

# Expected: cgroup2fs
# Problem: tmpfs (cgroup v1 mode)

# 2. Enable cgroup v2 unified hierarchy
# Add to kernel command line:
# systemd.unified_cgroup_hierarchy=1

# Edit grub config
sudo vim /etc/default/grub
# Add: GRUB_CMDLINE_LINUX="systemd.unified_cgroup_hierarchy=1"

# 3. Update grub
sudo update-grub  # Debian/Ubuntu
sudo grub2-mkconfig -o /boot/grub2/grub.cfg  # RHEL/CentOS

# 4. Reboot
sudo reboot

# 5. Verify after reboot
stat -fc %T /sys/fs/cgroup
```

### Procedure 2: Enable Cgroup Controllers

```bash
# 1. Check available controllers
cat /sys/fs/cgroup/cgroup.controllers

# 2. Enable controllers in root cgroup
echo "+cpu +memory +pids" > /sys/fs/cgroup/cgroup.subtree_control

# 3. Verify controllers enabled
cat /sys/fs/cgroup/cgroup.subtree_control

# 4. Make persistent (systemd)
sudo mkdir -p /etc/systemd/system/user@.service.d
sudo tee /etc/systemd/system/user@.service.d/delegate.conf <<EOF
[Service]
Delegate=cpu memory pids
EOF

sudo systemctl daemon-reload
```

### Procedure 3: Fallback to Cgroup v1

If cgroup v2 cannot be enabled:

```bash
# 1. Configure rustbox to use v1
# Edit config.json:
{
  "cgroup_backend": "v1",
  "strict_mode": true
}

# 2. Verify v1 is available
ls /sys/fs/cgroup/cpu
ls /sys/fs/cgroup/memory
ls /sys/fs/cgroup/pids

# 3. Test execution
rustbox run --code "echo test"

# 4. Verify backend selection
rustbox health | jq '.backend_selection.cgroup_backend'
# Expected: "v1"
```

### Procedure 4: Pidfd Fallback

If pidfd is not available:

```bash
# 1. Check kernel version
uname -r

# If < 5.3, pidfd not available

# 2. Rustbox will automatically fall back to process group signaling

# 3. Verify fallback is working
rustbox health | jq '.backend_selection.pidfd_mode'
# Expected: "fallback"

# 4. Monitor for PID reuse issues (rare)
# Watch for mis-signaled processes in logs
```

### Procedure 5: Namespace Troubleshooting

```bash
# 1. Check namespace support
unshare --pid --mount --fork echo "Namespaces work"

# If error, check kernel config
zcat /proc/config.gz | grep CONFIG_PID_NS
zcat /proc/config.gz | grep CONFIG_MNT_NS

# 2. Check user namespace support
unshare --user echo "User namespace works"

# If error, check if disabled
cat /proc/sys/kernel/unprivileged_userns_clone

# 3. Enable user namespaces (if needed)
sudo sysctl -w kernel.unprivileged_userns_clone=1

# Make persistent
echo "kernel.unprivileged_userns_clone=1" | \
  sudo tee -a /etc/sysctl.conf
```

## Prevention

### 1. System Requirements Check

Run before deployment:

```bash
# Check all requirements
/usr/local/bin/rustbox-check-requirements.sh

# Expected output:
# ✓ Kernel version: 5.10.0 (>= 5.3 required)
# ✓ Cgroup v2: enabled
# ✓ Cgroup controllers: cpu, memory, pids
# ✓ Pidfd support: available
# ✓ Namespaces: PID, mount, network
# ✓ Permissions: sufficient
```

### 2. Monitor Backend Selection

```promql
# Alert on unexpected backend selection
rustbox_backend_cgroup_v1 > 0 and on() expected_backend == "v2"

# Alert on pidfd fallback
rustbox_backend_pidfd_fallback > 0 and on() expected_pidfd == "native"

# Alert on control degradation
rustbox_control_degraded_total > 0
```

### 3. Regular Capability Audits

```bash
# Run daily capability audit
0 4 * * * /usr/local/bin/rustbox-audit-capabilities.sh
```

### 4. Document System Configuration

Maintain documentation of:
- Kernel version and required features
- Cgroup configuration (v1 vs v2)
- Expected backend selection
- Known limitations

## Backend Compatibility Matrix

| Feature | Kernel Version | Cgroup v1 | Cgroup v2 | Notes |
|---------|---------------|-----------|-----------|-------|
| Basic isolation | >= 2.6.24 | ✓ | ✓ | PID/mount namespaces |
| Memory limits | >= 2.6.25 | ✓ | ✓ | memory.limit_in_bytes vs memory.max |
| CPU limits | >= 2.6.24 | ✓ | ✓ | cpu.shares vs cpu.weight |
| PID limits | >= 4.3 | ✓ | ✓ | pids.max |
| OOM detection | >= 4.13 | Partial | ✓ | memory.events on v2 |
| Peak memory | >= 5.19 | ✗ | ✓ | memory.peak on v2 |
| Pidfd | >= 5.3 | ✓ | ✓ | Race-free signaling |
| memory.oom.group | >= 5.0 | ✗ | ✓ | Whole-tree OOM |

## Escalation

Escalate to engineering if:
- Required kernel features unavailable
- Cgroup v2 cannot be enabled on production systems
- Control degradation affects strict mode execution
- Backend mismatch causes verdict inconsistencies
- System configuration cannot meet requirements

## Post-Incident

### 1. Document Configuration

- Kernel version and features
- Cgroup configuration
- Backend selection rationale
- Known limitations

### 2. Update Deployment Docs

- Add system requirements
- Document configuration steps
- Add troubleshooting guide

### 3. Update Monitoring

- Add backend selection dashboards
- Update alert thresholds
- Add capability report tracking

## Related Runbooks

- [Stale State Recovery](stale-state.md)
- [Worker Quarantine](worker-quarantine.md)

## References

- Plan.md Section 8.1: Backend Selection
- Plan.md Section 8: Resource Governance and Cgroup Policy
- Plan.md Section 1: Cgroup Backend Abstraction (P1-CGROUP-001)
- Plan.md Section 1: v1/v2 Outcome Parity (P1-CGROUPPAR-001)
- Tests: `tests/cgroup_parity_test.rs`
- Metrics: `rustbox_backend_cgroup_*`, `rustbox_backend_pidfd_*`, `rustbox_control_degraded_*`
