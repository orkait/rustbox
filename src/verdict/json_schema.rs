use crate::config::types::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JudgeResultV1 {
    pub schema_version: String,

    pub status: ExecutionStatus,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,

    pub stdout: String,

    pub stderr: String,

    pub output_integrity: OutputIntegrity,

    pub cpu_time: f64,

    pub wall_time: f64,

    pub memory_peak: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict_provenance: Option<VerdictProvenance>,

    pub capability_report: CapabilityReport,

    pub execution_envelope_id: String,

    pub evidence_bundle: EvidenceBundle,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub language_runtime_envelope: Option<String>,

    pub execution_start: String,

    pub execution_end: String,
}

impl JudgeResultV1 {
    #[allow(clippy::too_many_arguments)]
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

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| IsolateError::Config(format!("Failed to serialize result to JSON: {}", e)))
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(|e| {
            IsolateError::Config(format!("Failed to serialize result to JSON bytes: {}", e))
        })
    }

    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| {
            IsolateError::Config(format!("Failed to deserialize result from JSON: {}", e))
        })
    }

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

impl JudgeResultV1 {
    pub fn from_execution_result(
        result: &ExecutionResult,
        config: &IsolateConfig,
        launch_evidence: &crate::sandbox::types::LaunchEvidence,
        capability_report: CapabilityReport,
        execution_envelope_id: String,
        language_runtime_envelope: Option<String>,
    ) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        let output_integrity = result.output_integrity.clone();

        let wait_outcome = WaitOutcome {
            exit_code: result.exit_code,
            terminating_signal: result.signal,
            stopped: false,
            continued: false,
        };

        let wall_elapsed_ms =
            (result.wall_time.max(0.0) * crate::config::constants::MS_PER_SEC_F64) as u64;
        let cpu_time_ms =
            (result.cpu_time.max(0.0) * crate::config::constants::MS_PER_SEC_F64) as u64;
        let timing_evidence = TimingEvidence {
            wall_elapsed_ms,
            cpu_time_ms,
            cpu_wall_ratio: if result.wall_time > 0.0 {
                result.cpu_time / result.wall_time
            } else {
                0.0
            },
            divergence_class: Some(
                crate::verdict::classifier::VerdictClassifier::classify_divergence(
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

        let (status, provenance) = crate::verdict::classifier::VerdictClassifier::classify(
            &evidence_bundle,
            &limit_snapshot,
        );
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
    use crate::config::constants;

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
            profile: Some("judge".to_string()),
            network_policy: None,
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
                memory_peak: Some(constants::MB),
                memory_limit: Some(constants::DEFAULT_MEMORY_LIMIT),
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
            constants::MB,
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
    fn test_json_schema_stability() {
        let result = create_test_result();
        let json = result.to_json().unwrap();

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
