# Rustbox Operational Runbooks

This directory contains incident response and recovery runbooks for Rustbox operations.

## Purpose

These runbooks provide step-by-step procedures for:
- Detecting and diagnosing operational issues
- Recovering from failures
- Preventing recurrence
- Escalating to engineering when needed

## Runbook Index

### Critical Incidents

1. **[Orphan Process Detection](orphan-process.md)** - CRITICAL
   - Security boundary breach
   - Process containment violation
   - Immediate containment required

2. **[Cleanup Failure](cleanup-failure.md)** - CRITICAL
   - Resource leaks
   - Worker quarantine
   - Baseline equivalence failures

3. **[Worker Quarantine](worker-quarantine.md)** - CRITICAL
   - Worker offline
   - Capacity reduction
   - Recovery procedures

### Warning-Level Incidents

4. **[Stale State Recovery](stale-state.md)** - WARNING
   - Stale lock files
   - Orphaned resources
   - Worker health issues

5. **[Backend Mismatch](backend-mismatch.md)** - WARNING
   - Cgroup v1/v2 issues
   - Pidfd fallback
   - Control degradation

## Quick Reference

### Severity Levels

- **CRITICAL**: Security breach, data loss, or service outage
  - Response time: Immediate
  - Escalation: Automatic to on-call engineer
  - Examples: Orphan process, cleanup failure, worker quarantine

- **WARNING**: Degraded functionality or potential issues
  - Response time: Within 1 hour
  - Escalation: If unresolved after 4 hours
  - Examples: Stale state, backend mismatch

- **INFO**: Informational alerts, no immediate action required
  - Response time: Next business day
  - Escalation: If pattern emerges
  - Examples: Abuse pattern detection, high queue depth

### Common Commands

```bash
# Check worker health
rustbox health

# Attempt automatic recovery
rustbox health --recover

# Verify clean state
rustbox health --verify-clean

# Manual quarantine
rustbox health --quarantine --reason "reason"

# Manual unquarantine
rustbox health --unquarantine --reason "reason"

# Dry-run to see capability report
rustbox --dry-run run --code "echo test"
```

### Common Metrics

```promql
# Worker health
rustbox_worker_health{status="healthy|unhealthy|quarantined"}

# Cleanup outcomes
rustbox_cleanup_total{outcome="success|failure|partial"}

# Execution outcomes
rustbox_executions_by_status{status="OK|TLE|MLE|RE|IE|..."}

# Control degradation
rustbox_control_degraded_total{control="namespace|cgroup|capability"}
```

## Incident Response Workflow

### 1. Detection

- Alert fires (Prometheus/Alertmanager)
- Metric threshold exceeded
- Manual observation
- User report

### 2. Triage

- Check severity level
- Review symptoms
- Check related metrics
- Review recent logs

### 3. Investigation

- Follow runbook investigation steps
- Gather evidence
- Identify root cause
- Document findings

### 4. Recovery

- Follow runbook recovery procedures
- Verify recovery successful
- Monitor for recurrence
- Document actions taken

### 5. Post-Incident

- Document incident
- Root cause analysis
- Update monitoring
- Update runbooks if needed
- Escalate if necessary

## Escalation Criteria

Escalate to engineering if:

1. **Immediate escalation** (CRITICAL):
   - Orphan process detected
   - Containment violation
   - Security boundary breach
   - Data loss or corruption

2. **Escalate within 1 hour**:
   - Automatic recovery fails repeatedly (>3 times)
   - Manual recovery procedures fail
   - Unknown root cause
   - Evidence of kernel bugs

3. **Escalate within 4 hours**:
   - Issue recurs frequently
   - Workaround not sustainable
   - Pattern of related issues
   - Resource exhaustion trends

## On-Call Procedures

### Initial Response

1. Acknowledge alert
2. Check severity level
3. Open relevant runbook
4. Begin investigation

### During Incident

1. Follow runbook procedures
2. Document actions in incident ticket
3. Update incident status
4. Communicate with stakeholders

### After Resolution

1. Verify recovery
2. Monitor for recurrence
3. Complete incident report
4. Schedule post-mortem if needed

## Game-Day Exercises

Regular game-day exercises should be conducted to:
- Validate runbook procedures
- Train on-call engineers
- Identify gaps in procedures
- Update runbooks based on learnings

### Recommended Exercises

1. **Cleanup Failure Simulation**
   - Inject mount unmount failure
   - Follow cleanup-failure runbook
   - Verify recovery procedures

2. **Worker Quarantine Drill**
   - Manually quarantine worker
   - Follow recovery procedures
   - Verify unquarantine process

3. **Resource Exhaustion**
   - Simulate disk full condition
   - Follow recovery procedures
   - Verify monitoring alerts

4. **Backend Mismatch**
   - Test cgroup v1 fallback
   - Verify capability reporting
   - Test control degradation alerts

## Runbook Maintenance

### Review Schedule

- **Monthly**: Review all runbooks for accuracy
- **Quarterly**: Update based on incidents
- **After incidents**: Update relevant runbooks
- **After code changes**: Update affected procedures

### Update Process

1. Identify need for update
2. Draft changes
3. Review with team
4. Test procedures
5. Merge updates
6. Communicate changes

## Related Documentation

- [Metrics Documentation](../metrics.md)
- [Health Check Documentation](../../src/health.rs)
- [Plan.md](../../../plan.md) - Architecture and requirements
- [SYSTEM_READY.md](../../../SYSTEM_READY.md) - System readiness report

## Contact Information

- **On-Call Engineer**: [PagerDuty rotation]
- **Engineering Lead**: [Contact info]
- **Security Team**: [Contact info]
- **Incident Channel**: #rustbox-incidents

## Feedback

If you find issues with these runbooks or have suggestions for improvement:
- Open an issue in the repository
- Contact the on-call engineer
- Discuss in team meetings
- Update during post-mortems
