# Rustbox Metrics and SLO Signals

**Purpose**: Ongoing health and risk telemetry for operations.  
**Invariant**: Limits, contention, and cleanup outcomes are measurable.

## Metrics Endpoint

Metrics are exported in Prometheus text format at `/metrics` endpoint (when HTTP server is enabled).

Access via:
```bash
curl http://localhost:9090/metrics
```

## Core Metrics

### Execution Outcomes

**rustbox_executions_total** (counter)
- Total number of executions
- Use for: Overall throughput tracking

**rustbox_executions_by_status{status}** (counter)
- Executions by status (OK, TLE, MLE, RE, IE, SIG, SV, ABUSE, PLE, FSE)
- Labels: `status` (OK, TLE, MLE, RE, IE, SIG, SV, ABUSE, PLE, FSE)
- Use for: Outcome distribution, error rate tracking

### Verdict Attribution

**rustbox_verdict_actor{actor}** (counter)
- Verdicts by actor (judge, kernel, runtime)
- Labels: `actor` (judge, kernel, runtime)
- Use for: Attribution analysis, kernel vs judge issue separation

**rustbox_verdict_cause{cause}** (counter)
- Verdicts by specific cause (tle_cpu_judge, tle_cpu_kernel, tle_wall_judge, etc.)
- Labels: `cause` (tle_cpu_judge, tle_cpu_kernel, tle_wall_judge, ...)
- Use for: Fine-grained timeout classification

### Resource Limit Violations

**rustbox_limit_violations{resource}** (counter)
- Limit violations by resource type
- Labels: `resource` (memory, cpu, wall, process, output)
- Use for: Capacity planning, limit tuning

### Cleanup Outcomes

**rustbox_cleanup_total{outcome}** (counter)
- Cleanup outcomes (success, failure, partial)
- Labels: `outcome` (success, failure, partial)
- Use for: Cleanup reliability tracking, leak detection

### Worker Health

**rustbox_worker_health{status}** (gauge)
- Worker health status counts
- Labels: `status` (healthy, unhealthy, quarantined)
- Use for: Worker availability, quarantine monitoring

### Contention and Queueing

**rustbox_active_executions** (gauge)
- Currently active executions
- Use for: Load monitoring, capacity planning

**rustbox_queued_executions** (gauge)
- Queued executions waiting for worker
- Use for: Queue depth monitoring, backpressure detection

### Backend Selection

**rustbox_backend_cgroup{version}** (counter)
- Cgroup backend selection (v1, v2)
- Labels: `version` (v1, v2)
- Use for: Backend distribution tracking

**rustbox_backend_pidfd{mode}** (counter)
- Pidfd backend selection (native, fallback)
- Labels: `mode` (native, fallback)
- Use for: Kernel capability tracking

### Control Degradation

**rustbox_control_degraded{control}** (counter)
- Control degradation events
- Labels: `control` (namespace, cgroup, capability)
- Use for: Security posture monitoring, strict mode violations

### Latency Histograms

**rustbox_cold_start_latency_seconds** (histogram)
- Cold start latency distribution
- Buckets: 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s
- Use for: Performance monitoring, SLO tracking

**rustbox_execution_duration_seconds** (histogram)
- Execution duration distribution
- Buckets: 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s
- Use for: Workload characterization, timeout tuning

**rustbox_cleanup_duration_seconds** (histogram)
- Cleanup duration distribution
- Buckets: 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s
- Use for: Cleanup performance monitoring, leak investigation

### Abuse Patterns

**rustbox_abuse_pattern{pattern}** (counter)
- Abuse pattern detections
- Labels: `pattern` (fork_bomb, fd_exhaustion, signal_storm, exec_churn)
- Use for: Abuse monitoring, rate limiting decisions

## Service Level Objectives (SLOs)

### Availability SLO

**Target**: 99.9% of executions complete without IE (Infrastructure Error)

**Query**:
```promql
(
  sum(rate(rustbox_executions_by_status{status!="IE"}[5m]))
  /
  sum(rate(rustbox_executions_total[5m]))
) * 100
```

**Alert**: Availability < 99.9% over 5 minutes

### Latency SLO

**Target**: 95% of cold starts complete within budget
- C++: < 100ms (p50), < 200ms (p95)
- Python: < 150ms (p50), < 300ms (p95)
- Java: < 250ms (p50), < 500ms (p95)

**Query**:
```promql
histogram_quantile(0.95, 
  rate(rustbox_cold_start_latency_seconds_bucket[5m])
)
```

**Alert**: p95 latency exceeds budget for 5 minutes

### Cleanup Reliability SLO

**Target**: 99.99% of cleanups succeed (no failures or partial)

**Query**:
```promql
(
  sum(rate(rustbox_cleanup_total{outcome="success"}[5m]))
  /
  sum(rate(rustbox_cleanup_total[5m]))
) * 100
```

**Alert**: Cleanup success rate < 99.99% over 5 minutes

### Worker Health SLO

**Target**: < 1% of workers quarantined at any time

**Query**:
```promql
(
  rustbox_worker_health{status="quarantined"}
  /
  (
    rustbox_worker_health{status="healthy"} +
    rustbox_worker_health{status="unhealthy"} +
    rustbox_worker_health{status="quarantined"}
  )
) * 100
```

**Alert**: Quarantined workers > 1%

## Alert Rules

### Critical Alerts

**InfrastructureErrorRate**
- Severity: critical
- Condition: IE rate > 1% over 5 minutes
- Impact: Judge reliability compromised
- Action: Check logs, investigate worker health, review recent changes

**CleanupFailureRate**
- Severity: critical
- Condition: Cleanup failure rate > 0.01% over 5 minutes
- Impact: Resource leaks, worker quarantine
- Action: Check cleanup logs, investigate leaked resources, restart workers

**WorkerQuarantineRate**
- Severity: critical
- Condition: Quarantined workers > 1%
- Impact: Reduced capacity, potential cascading failures
- Action: Check worker health, investigate cleanup failures, manual recovery

### Warning Alerts

**HighErrorRate**
- Severity: warning
- Condition: Non-OK rate > 10% over 5 minutes
- Impact: Potential submission issues or limit misconfiguration
- Action: Review error distribution, check limit configuration

**HighLatency**
- Severity: warning
- Condition: p95 cold start latency > budget for 5 minutes
- Impact: Degraded user experience, queue buildup
- Action: Check system load, investigate performance regression

**HighQueueDepth**
- Severity: warning
- Condition: Queued executions > 100 for 5 minutes
- Impact: Increased latency, potential timeout
- Action: Scale workers, investigate slow executions

**ControlDegradation**
- Severity: warning
- Condition: Control degradation events > 0 over 5 minutes
- Impact: Security posture weakened
- Action: Check system capabilities, review strict mode configuration

### Info Alerts

**AbusePatternDetected**
- Severity: info
- Condition: Abuse pattern rate > 1% over 5 minutes
- Impact: Potential resource abuse, rate limiting needed
- Action: Review abuse patterns, consider rate limiting

## Grafana Dashboard

### Overview Panel
- Executions per second (by status)
- Error rate (non-OK %)
- Active executions gauge
- Worker health distribution

### Latency Panel
- Cold start latency histogram (p50, p95, p99)
- Execution duration histogram
- Cleanup duration histogram

### Reliability Panel
- Cleanup success rate
- IE rate
- Worker quarantine rate
- Control degradation events

### Resource Panel
- Limit violations by resource
- Backend selection distribution
- Abuse pattern detections

## Example Queries

### Error Rate by Status
```promql
sum by (status) (
  rate(rustbox_executions_by_status[5m])
)
```

### Cleanup Failure Rate
```promql
(
  rate(rustbox_cleanup_total{outcome="failure"}[5m])
  /
  rate(rustbox_cleanup_total[5m])
) * 100
```

### Cold Start Latency p95
```promql
histogram_quantile(0.95,
  rate(rustbox_cold_start_latency_seconds_bucket[5m])
)
```

### Active Executions
```promql
rustbox_active_executions
```

### Worker Health Distribution
```promql
rustbox_worker_health
```

## Integration

### Prometheus Configuration

```yaml
scrape_configs:
  - job_name: 'rustbox'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 15s
    scrape_timeout: 10s
```

### Alertmanager Configuration

```yaml
route:
  group_by: ['alertname', 'severity']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  receiver: 'rustbox-alerts'

receivers:
  - name: 'rustbox-alerts'
    pagerduty_configs:
      - service_key: '<your-pagerduty-key>'
        severity: '{{ .GroupLabels.severity }}'
```

## Operational Runbooks

See:
- `docs/operations/runbooks/high-error-rate.md`
- `docs/operations/runbooks/cleanup-failure.md`
- `docs/operations/runbooks/worker-quarantine.md`
- `docs/operations/runbooks/control-degradation.md`

## Metric Retention

- Raw metrics: 15 days
- 5-minute aggregates: 90 days
- 1-hour aggregates: 1 year

## Performance Impact

Metrics collection overhead:
- Counter increment: ~10ns
- Gauge update: ~10ns
- Histogram observation: ~50ns
- Prometheus scrape: ~1ms per 1000 metrics

Total overhead: < 0.1% of execution time

## Security Considerations

- Metrics endpoint should be internal-only (not exposed to internet)
- No PII or sensitive data in metric labels
- Rate limiting on metrics endpoint to prevent DoS
- Authentication required for production deployments

## Future Enhancements

- Per-language execution metrics
- Per-user/submission metrics (with privacy controls)
- Cgroup resource usage histograms
- Syscall filtering metrics (when enabled)
- Network usage metrics (when network enabled)
