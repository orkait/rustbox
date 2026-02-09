// Metrics and SLO Signals (P2-METRIC-001)
//
// Purpose: Provide ongoing health and risk telemetry for operations.
// Invariant: Limits, contention, and cleanup outcomes are measurable.
//
// This module provides counters, gauges, and histograms for:
// - Execution outcomes (OK, TLE, MLE, RE, IE, SIG, SV, ABUSE, PLE, FSE)
// - Resource limit violations (memory, CPU, wall time, process, output)
// - Cleanup outcomes (success, failure, partial)
// - Contention and queueing metrics
// - Cold-start latency tracking
// - Backend selection and degradation tracking

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::config::types::{ExecutionStatus, VerdictActor, VerdictCause};

/// Metric types for different measurement needs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
}

/// Counter metric (monotonically increasing)
#[derive(Debug)]
pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(&self, delta: u64) {
        self.value.fetch_add(delta, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    pub fn reset(&self) {
        self.value.store(0, Ordering::Relaxed);
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

/// Gauge metric (can go up or down)
#[derive(Debug)]
pub struct Gauge {
    value: AtomicU64,
}

impl Gauge {
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    pub fn set(&self, value: u64) {
        self.value.store(value, Ordering::Relaxed);
    }

    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn add(&self, delta: u64) {
        self.value.fetch_add(delta, Ordering::Relaxed);
    }

    pub fn sub(&self, delta: u64) {
        self.value.fetch_sub(delta, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

impl Default for Gauge {
    fn default() -> Self {
        Self::new()
    }
}

/// Histogram bucket for latency tracking
#[derive(Debug)]
pub struct HistogramBucket {
    pub le: f64, // less than or equal to (upper bound in seconds)
    pub count: AtomicU64,
}

/// Histogram metric for latency/duration tracking
#[derive(Debug)]
pub struct Histogram {
    buckets: Vec<HistogramBucket>,
    sum: AtomicU64, // sum in microseconds
    count: AtomicU64,
}

impl Histogram {
    /// Create histogram with standard latency buckets (in seconds)
    pub fn new_latency() -> Self {
        let bucket_bounds = vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ];

        let buckets = bucket_bounds
            .into_iter()
            .map(|le| HistogramBucket {
                le,
                count: AtomicU64::new(0),
            })
            .collect();

        Self {
            buckets,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    pub fn observe(&self, value: Duration) {
        let seconds = value.as_secs_f64();
        let micros = value.as_micros() as u64;

        // Update sum and count
        self.sum.fetch_add(micros, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        // Update buckets
        for bucket in &self.buckets {
            if seconds <= bucket.le {
                bucket.count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn get_count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn get_sum_micros(&self) -> u64 {
        self.sum.load(Ordering::Relaxed)
    }

    pub fn get_bucket_count(&self, le: f64) -> u64 {
        self.buckets
            .iter()
            .find(|b| (b.le - le).abs() < 0.0001)
            .map(|b| b.count.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn reset(&self) {
        self.sum.store(0, Ordering::Relaxed);
        self.count.store(0, Ordering::Relaxed);
        for bucket in &self.buckets {
            bucket.count.store(0, Ordering::Relaxed);
        }
    }
}

/// Global metrics registry
#[derive(Debug)]
pub struct MetricsRegistry {
    // Execution outcome counters
    pub executions_total: Counter,
    pub executions_ok: Counter,
    pub executions_tle: Counter,
    pub executions_mle: Counter,
    pub executions_re: Counter,
    pub executions_ie: Counter,
    pub executions_sig: Counter,
    pub executions_sv: Counter,
    pub executions_abuse: Counter,
    pub executions_ple: Counter,
    pub executions_fse: Counter,

    // Verdict actor counters
    pub verdict_actor_judge: Counter,
    pub verdict_actor_kernel: Counter,
    pub verdict_actor_runtime: Counter,

    // Verdict cause counters (TLE variants)
    pub verdict_cause_tle_cpu_judge: Counter,
    pub verdict_cause_tle_cpu_kernel: Counter,
    pub verdict_cause_tle_wall_judge: Counter,

    // Resource limit violation counters
    pub limit_violations_memory: Counter,
    pub limit_violations_cpu: Counter,
    pub limit_violations_wall: Counter,
    pub limit_violations_process: Counter,
    pub limit_violations_output: Counter,

    // Cleanup outcome counters
    pub cleanup_success: Counter,
    pub cleanup_failure: Counter,
    pub cleanup_partial: Counter,

    // Worker health counters
    pub worker_healthy: Gauge,
    pub worker_unhealthy: Gauge,
    pub worker_quarantined: Gauge,

    // Contention and queueing gauges
    pub active_executions: Gauge,
    pub queued_executions: Gauge,

    // Backend selection counters
    pub backend_cgroup_v1: Counter,
    pub backend_cgroup_v2: Counter,
    pub backend_pidfd_native: Counter,
    pub backend_pidfd_fallback: Counter,

    // Control degradation counters
    pub control_degraded_namespace: Counter,
    pub control_degraded_cgroup: Counter,
    pub control_degraded_capability: Counter,

    // Latency histograms
    pub cold_start_latency: Histogram,
    pub execution_duration: Histogram,
    pub cleanup_duration: Histogram,

    // Abuse pattern counters
    pub abuse_fork_bomb: Counter,
    pub abuse_fd_exhaustion: Counter,
    pub abuse_signal_storm: Counter,
    pub abuse_exec_churn: Counter,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            // Execution outcomes
            executions_total: Counter::new(),
            executions_ok: Counter::new(),
            executions_tle: Counter::new(),
            executions_mle: Counter::new(),
            executions_re: Counter::new(),
            executions_ie: Counter::new(),
            executions_sig: Counter::new(),
            executions_sv: Counter::new(),
            executions_abuse: Counter::new(),
            executions_ple: Counter::new(),
            executions_fse: Counter::new(),

            // Verdict actors
            verdict_actor_judge: Counter::new(),
            verdict_actor_kernel: Counter::new(),
            verdict_actor_runtime: Counter::new(),

            // Verdict causes
            verdict_cause_tle_cpu_judge: Counter::new(),
            verdict_cause_tle_cpu_kernel: Counter::new(),
            verdict_cause_tle_wall_judge: Counter::new(),

            // Limit violations
            limit_violations_memory: Counter::new(),
            limit_violations_cpu: Counter::new(),
            limit_violations_wall: Counter::new(),
            limit_violations_process: Counter::new(),
            limit_violations_output: Counter::new(),

            // Cleanup outcomes
            cleanup_success: Counter::new(),
            cleanup_failure: Counter::new(),
            cleanup_partial: Counter::new(),

            // Worker health
            worker_healthy: Gauge::new(),
            worker_unhealthy: Gauge::new(),
            worker_quarantined: Gauge::new(),

            // Contention
            active_executions: Gauge::new(),
            queued_executions: Gauge::new(),

            // Backend selection
            backend_cgroup_v1: Counter::new(),
            backend_cgroup_v2: Counter::new(),
            backend_pidfd_native: Counter::new(),
            backend_pidfd_fallback: Counter::new(),

            // Control degradation
            control_degraded_namespace: Counter::new(),
            control_degraded_cgroup: Counter::new(),
            control_degraded_capability: Counter::new(),

            // Latency histograms
            cold_start_latency: Histogram::new_latency(),
            execution_duration: Histogram::new_latency(),
            cleanup_duration: Histogram::new_latency(),

            // Abuse patterns
            abuse_fork_bomb: Counter::new(),
            abuse_fd_exhaustion: Counter::new(),
            abuse_signal_storm: Counter::new(),
            abuse_exec_churn: Counter::new(),
        }
    }

    /// Record execution outcome
    pub fn record_execution(&self, status: ExecutionStatus) {
        self.executions_total.inc();

        match status {
            ExecutionStatus::Ok => self.executions_ok.inc(),
            ExecutionStatus::TimeLimit => self.executions_tle.inc(),
            ExecutionStatus::MemoryLimit => self.executions_mle.inc(),
            ExecutionStatus::RuntimeError => self.executions_re.inc(),
            ExecutionStatus::InternalError => self.executions_ie.inc(),
            ExecutionStatus::Signaled => self.executions_sig.inc(),
            ExecutionStatus::SecurityViolation => self.executions_sv.inc(),
            ExecutionStatus::Abuse => self.executions_abuse.inc(),
            ExecutionStatus::ProcessLimit => self.executions_ple.inc(),
            ExecutionStatus::FileSizeLimit => self.executions_fse.inc(),
        }
    }

    /// Record verdict actor
    pub fn record_verdict_actor(&self, actor: VerdictActor) {
        match actor {
            VerdictActor::Judge => self.verdict_actor_judge.inc(),
            VerdictActor::Kernel => self.verdict_actor_kernel.inc(),
            VerdictActor::Runtime => self.verdict_actor_runtime.inc(),
        }
    }

    /// Record verdict cause
    pub fn record_verdict_cause(&self, cause: VerdictCause) {
        match cause {
            VerdictCause::TleCpuJudge => self.verdict_cause_tle_cpu_judge.inc(),
            VerdictCause::TleCpuKernel => self.verdict_cause_tle_cpu_kernel.inc(),
            VerdictCause::TleWallJudge => self.verdict_cause_tle_wall_judge.inc(),
            _ => {} // Other causes tracked via status counters
        }
    }

    /// Record cleanup outcome
    pub fn record_cleanup(&self, success: bool, partial: bool) {
        if success {
            self.cleanup_success.inc();
        } else if partial {
            self.cleanup_partial.inc();
        } else {
            self.cleanup_failure.inc();
        }
    }

    /// Record backend selection
    pub fn record_backend_selection(&self, cgroup_v2: bool, pidfd_native: bool) {
        if cgroup_v2 {
            self.backend_cgroup_v2.inc();
        } else {
            self.backend_cgroup_v1.inc();
        }

        if pidfd_native {
            self.backend_pidfd_native.inc();
        } else {
            self.backend_pidfd_fallback.inc();
        }
    }

    /// Export metrics in Prometheus text format
    pub fn export_prometheus(&self) -> String {
        let mut output = String::new();

        // Execution outcomes
        output.push_str("# HELP rustbox_executions_total Total number of executions\n");
        output.push_str("# TYPE rustbox_executions_total counter\n");
        output.push_str(&format!(
            "rustbox_executions_total {}\n",
            self.executions_total.get()
        ));

        output.push_str("# HELP rustbox_executions_by_status Executions by status\n");
        output.push_str("# TYPE rustbox_executions_by_status counter\n");
        output.push_str(&format!(
            "rustbox_executions_by_status{{status=\"OK\"}} {}\n",
            self.executions_ok.get()
        ));
        output.push_str(&format!(
            "rustbox_executions_by_status{{status=\"TLE\"}} {}\n",
            self.executions_tle.get()
        ));
        output.push_str(&format!(
            "rustbox_executions_by_status{{status=\"MLE\"}} {}\n",
            self.executions_mle.get()
        ));
        output.push_str(&format!(
            "rustbox_executions_by_status{{status=\"RE\"}} {}\n",
            self.executions_re.get()
        ));
        output.push_str(&format!(
            "rustbox_executions_by_status{{status=\"IE\"}} {}\n",
            self.executions_ie.get()
        ));

        // Cleanup outcomes
        output.push_str("# HELP rustbox_cleanup_total Cleanup outcomes\n");
        output.push_str("# TYPE rustbox_cleanup_total counter\n");
        output.push_str(&format!(
            "rustbox_cleanup_total{{outcome=\"success\"}} {}\n",
            self.cleanup_success.get()
        ));
        output.push_str(&format!(
            "rustbox_cleanup_total{{outcome=\"failure\"}} {}\n",
            self.cleanup_failure.get()
        ));
        output.push_str(&format!(
            "rustbox_cleanup_total{{outcome=\"partial\"}} {}\n",
            self.cleanup_partial.get()
        ));

        // Worker health
        output.push_str("# HELP rustbox_worker_health Worker health status\n");
        output.push_str("# TYPE rustbox_worker_health gauge\n");
        output.push_str(&format!(
            "rustbox_worker_health{{status=\"healthy\"}} {}\n",
            self.worker_healthy.get()
        ));
        output.push_str(&format!(
            "rustbox_worker_health{{status=\"unhealthy\"}} {}\n",
            self.worker_unhealthy.get()
        ));
        output.push_str(&format!(
            "rustbox_worker_health{{status=\"quarantined\"}} {}\n",
            self.worker_quarantined.get()
        ));

        // Active executions
        output.push_str("# HELP rustbox_active_executions Currently active executions\n");
        output.push_str("# TYPE rustbox_active_executions gauge\n");
        output.push_str(&format!(
            "rustbox_active_executions {}\n",
            self.active_executions.get()
        ));

        // Cold start latency histogram
        output.push_str("# HELP rustbox_cold_start_latency_seconds Cold start latency\n");
        output.push_str("# TYPE rustbox_cold_start_latency_seconds histogram\n");
        for bucket in &self.cold_start_latency.buckets {
            output.push_str(&format!(
                "rustbox_cold_start_latency_seconds_bucket{{le=\"{}\"}} {}\n",
                bucket.le,
                bucket.count.load(Ordering::Relaxed)
            ));
        }
        output.push_str(&format!(
            "rustbox_cold_start_latency_seconds_sum {}\n",
            self.cold_start_latency.get_sum_micros() as f64 / 1_000_000.0
        ));
        output.push_str(&format!(
            "rustbox_cold_start_latency_seconds_count {}\n",
            self.cold_start_latency.get_count()
        ));

        output
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Global metrics instance
static METRICS: once_cell::sync::Lazy<Arc<MetricsRegistry>> =
    once_cell::sync::Lazy::new(|| Arc::new(MetricsRegistry::new()));

/// Get global metrics registry
pub fn get_metrics() -> Arc<MetricsRegistry> {
    Arc::clone(&METRICS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter() {
        let counter = Counter::new();
        assert_eq!(counter.get(), 0);

        counter.inc();
        assert_eq!(counter.get(), 1);

        counter.add(5);
        assert_eq!(counter.get(), 6);

        counter.reset();
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn test_gauge() {
        let gauge = Gauge::new();
        assert_eq!(gauge.get(), 0);

        gauge.set(10);
        assert_eq!(gauge.get(), 10);

        gauge.inc();
        assert_eq!(gauge.get(), 11);

        gauge.dec();
        assert_eq!(gauge.get(), 10);

        gauge.add(5);
        assert_eq!(gauge.get(), 15);

        gauge.sub(3);
        assert_eq!(gauge.get(), 12);
    }

    #[test]
    fn test_histogram() {
        let histogram = Histogram::new_latency();

        histogram.observe(Duration::from_millis(50));
        histogram.observe(Duration::from_millis(150));
        histogram.observe(Duration::from_millis(500));

        assert_eq!(histogram.get_count(), 3);

        // Check bucket counts (cumulative)
        assert_eq!(histogram.get_bucket_count(0.1), 1); // 50ms <= 100ms
        assert_eq!(histogram.get_bucket_count(0.25), 2); // 50ms, 150ms <= 250ms
        assert_eq!(histogram.get_bucket_count(0.5), 3); // 50ms, 150ms, 500ms <= 500ms
        assert_eq!(histogram.get_bucket_count(1.0), 3); // all <= 1s

        histogram.reset();
        assert_eq!(histogram.get_count(), 0);
    }

    #[test]
    fn test_metrics_registry_execution() {
        let metrics = MetricsRegistry::new();

        metrics.record_execution(ExecutionStatus::Ok);
        metrics.record_execution(ExecutionStatus::TimeLimit);
        metrics.record_execution(ExecutionStatus::MemoryLimit);

        assert_eq!(metrics.executions_total.get(), 3);
        assert_eq!(metrics.executions_ok.get(), 1);
        assert_eq!(metrics.executions_tle.get(), 1);
        assert_eq!(metrics.executions_mle.get(), 1);
    }

    #[test]
    fn test_metrics_registry_verdict_actor() {
        let metrics = MetricsRegistry::new();

        metrics.record_verdict_actor(VerdictActor::Judge);
        metrics.record_verdict_actor(VerdictActor::Kernel);
        metrics.record_verdict_actor(VerdictActor::Judge);

        assert_eq!(metrics.verdict_actor_judge.get(), 2);
        assert_eq!(metrics.verdict_actor_kernel.get(), 1);
        assert_eq!(metrics.verdict_actor_runtime.get(), 0);
    }

    #[test]
    fn test_metrics_registry_cleanup() {
        let metrics = MetricsRegistry::new();

        metrics.record_cleanup(true, false);
        metrics.record_cleanup(true, false);
        metrics.record_cleanup(false, true);
        metrics.record_cleanup(false, false);

        assert_eq!(metrics.cleanup_success.get(), 2);
        assert_eq!(metrics.cleanup_partial.get(), 1);
        assert_eq!(metrics.cleanup_failure.get(), 1);
    }

    #[test]
    fn test_metrics_registry_backend() {
        let metrics = MetricsRegistry::new();

        metrics.record_backend_selection(true, true);
        metrics.record_backend_selection(false, false);

        assert_eq!(metrics.backend_cgroup_v2.get(), 1);
        assert_eq!(metrics.backend_cgroup_v1.get(), 1);
        assert_eq!(metrics.backend_pidfd_native.get(), 1);
        assert_eq!(metrics.backend_pidfd_fallback.get(), 1);
    }

    #[test]
    fn test_prometheus_export() {
        let metrics = MetricsRegistry::new();

        metrics.record_execution(ExecutionStatus::Ok);
        metrics.record_execution(ExecutionStatus::TimeLimit);
        metrics.record_cleanup(true, false);

        let output = metrics.export_prometheus();

        assert!(output.contains("rustbox_executions_total 2"));
        assert!(output.contains("rustbox_executions_by_status{status=\"OK\"} 1"));
        assert!(output.contains("rustbox_executions_by_status{status=\"TLE\"} 1"));
        assert!(output.contains("rustbox_cleanup_total{outcome=\"success\"} 1"));
    }

    #[test]
    fn test_global_metrics() {
        let metrics1 = get_metrics();
        let metrics2 = get_metrics();

        // Should be the same instance
        assert!(Arc::ptr_eq(&metrics1, &metrics2));

        metrics1.executions_total.inc();
        assert_eq!(metrics2.executions_total.get(), 1);
    }
}
