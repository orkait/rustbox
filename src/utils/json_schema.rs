/// Stable JSON result schema for judge integration
/// Implements P0-JSON-001: Stable Judge JSON Result Schema
/// Per plan.md Section 14: Judge-v1 output contract
use crate::config::types::*;
use serde::{Deserialize, Serialize};

/// Build capability report from runtime launch evidence.
pub fn create_capability_report_from_evidence(
    evidence: &crate::core::types::LaunchEvidence,
) -> CapabilityReport {
    evidence.to_capability_report()
}

/// Stable JSON result schema for judge consumers (v1)
/// This schema is frozen and backward compatible
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JudgeResultV1 {
    /// Schema version (always "1.0" for v1)
    pub schema_version: String,

    /// Execution status (stable taxonomy)
    pub status: ExecutionStatus,

    /// Exit code (if normal exit)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,

    /// Standard output
    pub stdout: String,

    /// Standard error
    pub stderr: String,

    /// Output integrity classification
    pub output_integrity: OutputIntegrity,

    /// CPU time used (seconds)
    pub cpu_time: f64,

    /// Wall time used (seconds)
    pub wall_time: f64,

    /// Peak memory usage (bytes)
    pub memory_peak: u64,

    /// Verdict provenance (for non-OK verdicts)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict_provenance: Option<VerdictProvenance>,

    /// Capability report
    pub capability_report: CapabilityReport,

    /// Execution envelope ID (SHA256 hash)
    pub execution_envelope_id: String,

    /// Evidence bundle (immutable)
    pub evidence_bundle: EvidenceBundle,

    /// Language runtime envelope (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language_runtime_envelope: Option<String>,

    /// Timestamp of execution start
    pub execution_start: String,

    /// Timestamp of execution end
    pub execution_end: String,
}

impl JudgeResultV1 {
    /// Create new judge result
    pub fn new(
        status: ExecutionStatus,
        exit_code: Option<i32>,
        stdout: String,
        stderr: String,
        output_integrity: OutputIntegrity,
        cpu_time: f64,
        wall_time: f64,
        memory_peak: u64,
        verdict_provenance: Option<VerdictProvenance>,
        capability_report: CapabilityReport,
        execution_envelope_id: String,
        evidence_bundle: EvidenceBundle,
        language_runtime_envelope: Option<String>,
        execution_start: String,
        execution_end: String,
    ) -> Self {
        Self {
            schema_version: "1.0".to_string(),
            status,
            exit_code,
            stdout,
            stderr,
            output_integrity,
            cpu_time,
            wall_time,
            memory_peak,
            verdict_provenance,
            capability_report,
            execution_envelope_id,
            evidence_bundle,
            language_runtime_envelope,
            execution_start,
            execution_end,
        }
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| IsolateError::Config(format!("Failed to serialize result to JSON: {}", e)))
    }

    /// Serialize to JSON bytes
    pub fn to_json_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(|e| {
            IsolateError::Config(format!("Failed to serialize result to JSON bytes: {}", e))
        })
    }

    /// Deserialize from JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| {
            IsolateError::Config(format!("Failed to deserialize result from JSON: {}", e))
        })
    }

    /// Validate schema version
    pub fn validate_schema_version(&self) -> Result<()> {
        if self.schema_version != "1.0" {
            return Err(IsolateError::Config(format!(
                "Unsupported schema version: {}",
                self.schema_version
            )));
        }
        Ok(())
    }
}

/// Minimal result for quick status checks
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MinimalResult {
    pub status: ExecutionStatus,
    pub cpu_time: f64,
    pub wall_time: f64,
    pub memory_peak: u64,
    pub exit_code: Option<i32>,
}

impl From<&JudgeResultV1> for MinimalResult {
    fn from(result: &JudgeResultV1) -> Self {
        Self {
            status: result.status.clone(),
            cpu_time: result.cpu_time,
            wall_time: result.wall_time,
            memory_peak: result.memory_peak,
            exit_code: result.exit_code,
        }
    }
}

/// Convert ExecutionResult to JudgeResultV1 with full provenance
impl JudgeResultV1 {
    /// Create from ExecutionResult with capability report and envelope
    pub fn from_execution_result(
        result: &ExecutionResult,
        config: &IsolateConfig,
        launch_evidence: &crate::core::types::LaunchEvidence,
        capability_report: CapabilityReport,
        execution_envelope_id: String,
        language_runtime_envelope: Option<String>,
    ) -> Self {
        let now = chrono::Utc::now().to_rfc3339();

        // Determine output integrity
        let output_integrity = if result.stdout.len() + result.stderr.len() > 1024 * 1024 {
            OutputIntegrity::TruncatedByJudgeLimit
        } else {
            OutputIntegrity::Complete
        };

        // Build immutable evidence bundle from runtime artifacts.
        let wait_outcome = WaitOutcome {
            exit_code: result.exit_code,
            terminating_signal: result.signal,
            stopped: false,
            continued: false,
        };

        let wall_elapsed_ms = (result.wall_time.max(0.0) * 1000.0) as u64;
        let cpu_time_ms = (result.cpu_time.max(0.0) * 1000.0) as u64;
        let timing_evidence = TimingEvidence {
            wall_elapsed_ms,
            cpu_time_ms,
            cpu_wall_ratio: if result.wall_time > 0.0 {
                result.cpu_time / result.wall_time
            } else {
                0.0
            },
            divergence_class: Some(
                crate::verdict::verdict::VerdictClassifier::classify_divergence(
                    cpu_time_ms,
                    wall_elapsed_ms,
                ),
            ),
        };

        let mut evidence_collection_errors = launch_evidence.evidence_collection_errors.clone();
        if launch_evidence.cgroup_evidence.is_none()
            && (config.memory_limit.is_some() || config.process_limit.is_some())
        {
            evidence_collection_errors.push("missing cgroup evidence snapshot".to_string());
        }

        let evidence_bundle = EvidenceBundle {
            wait_outcome,
            judge_actions: launch_evidence.judge_actions.clone(),
            cgroup_evidence: launch_evidence.cgroup_evidence.clone(),
            timing_evidence,
            process_lifecycle: launch_evidence.process_lifecycle.clone(),
            evidence_collection_errors,
        };

        let limit_snapshot = LimitSnapshot {
            cpu_limit_ms: config.cpu_time_limit.map(|d| d.as_millis() as u64),
            wall_limit_ms: config.wall_time_limit.map(|d| d.as_millis() as u64),
            memory_limit_bytes: config.memory_limit,
            process_limit: config.process_limit,
            output_limit_bytes: config.file_size_limit,
        };

        let (status, provenance) =
            crate::verdict::verdict::VerdictClassifier::classify(&evidence_bundle, &limit_snapshot);
        let verdict_provenance = if status == ExecutionStatus::Ok {
            None
        } else {
            Some(provenance)
        };
        let memory_peak = evidence_bundle
            .cgroup_evidence
            .as_ref()
            .and_then(|e| e.memory_peak)
            .unwrap_or(result.memory_peak);

        Self::new(
            status,
            result.exit_code,
            result.stdout.clone(),
            result.stderr.clone(),
            output_integrity,
            result.cpu_time,
            result.wall_time,
            memory_peak,
            verdict_provenance,
            capability_report,
            execution_envelope_id,
            evidence_bundle,
            language_runtime_envelope,
            now.clone(),
            now,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_test_result() -> JudgeResultV1 {
        let capability_report = CapabilityReport {
            configured_controls: vec!["pid_namespace".to_string(), "mount_namespace".to_string()],
            applied_controls: vec!["pid_namespace".to_string(), "mount_namespace".to_string()],
            missing_controls: vec![],
            mode: SecurityMode::Strict,
            mode_decision_reason: "All controls available".to_string(),
            unsafe_execution_reason: None,
            cgroup_backend_selected: Some("cgroup-v1".to_string()),
            pidfd_mode: PidfdMode::Native,
            proc_policy_applied: "hardened".to_string(),
            sys_policy_applied: "disabled".to_string(),
            syscall_filtering_enabled: false,
            syscall_filtering_source: SyscallFilterSource::None,
            syscall_filtering_profile_id: None,
        };

        let evidence_bundle = EvidenceBundle {
            wait_outcome: WaitOutcome {
                exit_code: Some(0),
                terminating_signal: None,
                stopped: false,
                continued: false,
            },
            judge_actions: vec![],
            cgroup_evidence: Some(CgroupEvidence {
                memory_peak: Some(1024 * 1024),
                memory_limit: Some(128 * 1024 * 1024),
                oom_events: 0,
                oom_kill_events: 0,
                cpu_usage_usec: Some(500000),
                process_count: Some(1),
                process_limit: Some(1),
            }),
            timing_evidence: TimingEvidence {
                wall_elapsed_ms: 1000,
                cpu_time_ms: 500,
                cpu_wall_ratio: 0.5,
                divergence_class: Some(DivergenceClass::CpuBound),
            },
            process_lifecycle: ProcessLifecycleEvidence {
                reap_summary: "clean".to_string(),
                descendant_containment: "ok".to_string(),
                zombie_count: 0,
            },
            evidence_collection_errors: vec![],
        };

        JudgeResultV1::new(
            ExecutionStatus::Ok,
            Some(0),
            "Hello, World!".to_string(),
            "".to_string(),
            OutputIntegrity::Complete,
            0.5,
            1.0,
            1024 * 1024,
            None,
            capability_report,
            "abc123def456".to_string(),
            evidence_bundle,
            Some("cpp17-v1".to_string()),
            "2026-02-08T10:00:00Z".to_string(),
            "2026-02-08T10:00:01Z".to_string(),
        )
    }

    #[test]
    fn test_json_serialization() {
        let result = create_test_result();
        let json = result.to_json().unwrap();

        // Verify it's valid JSON
        assert!(json.contains("\"schema_version\""));
        assert!(json.contains("\"1.0\""));
        assert!(json.contains("\"status\""));
        assert!(json.contains("\"OK\""));
    }

    #[test]
    fn test_json_deserialization() {
        let result = create_test_result();
        let json = result.to_json().unwrap();

        let deserialized = JudgeResultV1::from_json(&json).unwrap();
        assert_eq!(deserialized.schema_version, "1.0");
        assert_eq!(deserialized.status, ExecutionStatus::Ok);
        assert_eq!(deserialized.cpu_time, 0.5);
    }

    #[test]
    fn test_schema_version_validation() {
        let result = create_test_result();
        assert!(result.validate_schema_version().is_ok());
    }

    #[test]
    fn test_minimal_result_conversion() {
        let result = create_test_result();
        let minimal = MinimalResult::from(&result);

        assert_eq!(minimal.status, ExecutionStatus::Ok);
        assert_eq!(minimal.cpu_time, 0.5);
        assert_eq!(minimal.wall_time, 1.0);
        assert_eq!(minimal.memory_peak, 1024 * 1024);
    }

    #[test]
    fn test_json_schema_stability() {
        // This test ensures the JSON schema remains stable
        let result = create_test_result();
        let json = result.to_json().unwrap();

        // Required fields must be present
        assert!(json.contains("\"schema_version\""));
        assert!(json.contains("\"status\""));
        assert!(json.contains("\"stdout\""));
        assert!(json.contains("\"stderr\""));
        assert!(json.contains("\"output_integrity\""));
        assert!(json.contains("\"cpu_time\""));
        assert!(json.contains("\"wall_time\""));
        assert!(json.contains("\"memory_peak\""));
        assert!(json.contains("\"capability_report\""));
        assert!(json.contains("\"execution_envelope_id\""));
        assert!(json.contains("\"evidence_bundle\""));
    }
}
