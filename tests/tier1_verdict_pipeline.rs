mod common;

use rustbox::config::constants;
use rustbox::config::types::*;
use rustbox::verdict::classifier::VerdictClassifier;
use rustbox::verdict::json_schema::JudgeResultV1;
use std::time::SystemTime;

fn test_limits() -> LimitSnapshot {
    LimitSnapshot {
        cpu_limit_ms: Some(10_000),
        wall_limit_ms: Some(20_000),
        memory_limit_bytes: Some(constants::DEFAULT_MEMORY_LIMIT),
        process_limit: Some(10),
        output_limit_bytes: Some(constants::DEFAULT_FILE_SIZE_LIMIT),
    }
}

fn base_evidence(exit_code: Option<i32>, signal: Option<i32>) -> EvidenceBundle {
    EvidenceBundle {
        wait_outcome: WaitOutcome {
            exit_code,
            terminating_signal: signal,
            stopped: false,
            continued: false,
        },
        judge_actions: vec![],
        cgroup_evidence: None,
        timing_evidence: TimingEvidence {
            wall_elapsed_ms: 1000,
            cpu_time_ms: 900,
            cpu_wall_ratio: 0.9,
            divergence_class: Some(DivergenceClass::CpuBound),
        },
        process_lifecycle: ProcessLifecycleEvidence {
            reap_summary: "clean".to_string(),
            descendant_containment: "ok".to_string(),
            zombie_count: 0,
        },
        evidence_collection_errors: vec![],
    }
}

#[test]
fn clean_exit_zero_yields_ok() {
    let (status, prov) = VerdictClassifier::classify(&base_evidence(Some(0), None), &test_limits());
    assert_eq!(status, ExecutionStatus::Ok);
    assert_eq!(prov.verdict_actor, VerdictActor::Runtime);
    assert_eq!(prov.verdict_cause, VerdictCause::NormalExit);
}

#[test]
fn nonzero_exit_yields_runtime_error() {
    let (status, prov) = VerdictClassifier::classify(&base_evidence(Some(1), None), &test_limits());
    assert_eq!(status, ExecutionStatus::RuntimeError);
    assert_eq!(prov.verdict_cause, VerdictCause::ReNonzeroExit);
    assert_eq!(prov.verdict_actor, VerdictActor::Runtime);
}

#[test]
fn oom_with_exit_code_yields_memory_limit() {
    let mut evidence = base_evidence(Some(137), None);
    evidence.cgroup_evidence = Some(CgroupEvidence {
        memory_peak: Some(constants::DEFAULT_MEMORY_LIMIT),
        memory_limit: Some(constants::DEFAULT_MEMORY_LIMIT),
        oom_events: 1,
        oom_kill_events: 1,
        cpu_usage_usec: Some(500_000),
        process_count: Some(1),
        process_limit: Some(10),
    });

    let (status, prov) = VerdictClassifier::classify(&evidence, &test_limits());
    assert_eq!(status, ExecutionStatus::MemoryLimit);
    assert_eq!(prov.verdict_cause, VerdictCause::MleKernelOom);
    assert_eq!(prov.verdict_actor, VerdictActor::Kernel);
}

#[test]
fn judge_kill_cpu_timeout_yields_tle() {
    let mut evidence = base_evidence(None, Some(9));
    evidence.timing_evidence = TimingEvidence {
        wall_elapsed_ms: 15_000,
        cpu_time_ms: 10_000,
        cpu_wall_ratio: 0.67,
        divergence_class: Some(DivergenceClass::CpuBound),
    };
    evidence.judge_actions = vec![
        JudgeAction {
            timestamp: SystemTime::now(),
            action_type: JudgeActionType::TimerExpiry,
            details: "CPU timeout".into(),
        },
        JudgeAction {
            timestamp: SystemTime::now(),
            action_type: JudgeActionType::ForcedKill,
            details: "SIGKILL".into(),
        },
    ];

    let (status, prov) = VerdictClassifier::classify(&evidence, &test_limits());
    assert_eq!(status, ExecutionStatus::TimeLimit);
    assert_eq!(prov.verdict_cause, VerdictCause::TleCpuJudge);
    assert_eq!(prov.verdict_actor, VerdictActor::Judge);
}

#[test]
fn judge_kill_wall_timeout_yields_tle() {
    let mut evidence = base_evidence(Some(143), None);
    evidence.timing_evidence = TimingEvidence {
        wall_elapsed_ms: 21_000,
        cpu_time_ms: 2_000,
        cpu_wall_ratio: 0.1,
        divergence_class: Some(DivergenceClass::SleepOrBlockBound),
    };
    evidence.judge_actions = vec![
        JudgeAction {
            timestamp: SystemTime::now(),
            action_type: JudgeActionType::TimerExpiry,
            details: "wall timeout".into(),
        },
        JudgeAction {
            timestamp: SystemTime::now(),
            action_type: JudgeActionType::ForcedKill,
            details: "SIGKILL".into(),
        },
    ];

    let (status, prov) = VerdictClassifier::classify(&evidence, &test_limits());
    assert_eq!(status, ExecutionStatus::TimeLimit);
    assert_eq!(prov.verdict_cause, VerdictCause::TleWallJudge);
}

#[test]
fn sigxcpu_yields_tle_kernel() {
    let evidence = base_evidence(None, Some(libc::SIGXCPU));
    let (status, prov) = VerdictClassifier::classify(&evidence, &test_limits());
    assert_eq!(status, ExecutionStatus::TimeLimit);
    assert_eq!(prov.verdict_cause, VerdictCause::TleCpuKernel);
    assert_eq!(prov.verdict_actor, VerdictActor::Kernel);
    assert_eq!(prov.termination_signal, Some(libc::SIGXCPU));
}

#[test]
fn sigxfsz_yields_file_size_limit() {
    let evidence = base_evidence(None, Some(libc::SIGXFSZ));
    let (status, prov) = VerdictClassifier::classify(&evidence, &test_limits());
    assert_eq!(status, ExecutionStatus::FileSizeLimit);
    assert_eq!(prov.verdict_cause, VerdictCause::FseLimitExceeded);
    assert_eq!(prov.termination_signal, Some(libc::SIGXFSZ));
}

#[test]
fn process_limit_hit_yields_ple() {
    let mut evidence = base_evidence(Some(1), None);
    evidence.cgroup_evidence = Some(CgroupEvidence {
        memory_peak: Some(constants::KB),
        memory_limit: Some(constants::DEFAULT_MEMORY_LIMIT),
        oom_events: 0,
        oom_kill_events: 0,
        cpu_usage_usec: Some(1_000),
        process_count: Some(10),
        process_limit: Some(10),
    });

    let (status, prov) = VerdictClassifier::classify(&evidence, &test_limits());
    assert_eq!(status, ExecutionStatus::ProcessLimit);
    assert_eq!(prov.verdict_cause, VerdictCause::PleCgroupPids);
}

#[test]
fn cleanup_failure_yields_internal_error() {
    let mut evidence = base_evidence(Some(0), None);
    evidence.process_lifecycle.descendant_containment = "baseline_verification_failed".into();

    let (status, prov) = VerdictClassifier::classify(&evidence, &test_limits());
    assert_eq!(status, ExecutionStatus::InternalError);
    assert_eq!(prov.verdict_cause, VerdictCause::IeCleanupFailure);
}

#[test]
fn fatal_evidence_error_yields_internal_error() {
    let mut evidence = base_evidence(Some(0), None);
    evidence
        .evidence_collection_errors
        .push("unexpected fatal failure".to_string());

    let (status, prov) = VerdictClassifier::classify(&evidence, &test_limits());
    assert_eq!(status, ExecutionStatus::InternalError);
    assert_eq!(prov.verdict_cause, VerdictCause::IeMissingEvidence);
}

#[test]
fn divergence_classification_thresholds() {
    assert_eq!(
        VerdictClassifier::classify_divergence(900, 1000),
        DivergenceClass::CpuBound
    );
    assert_eq!(
        VerdictClassifier::classify_divergence(100, 1000),
        DivergenceClass::SleepOrBlockBound
    );
    assert_eq!(
        VerdictClassifier::classify_divergence(500, 1000),
        DivergenceClass::HostInterferenceSuspected
    );
    assert_eq!(
        VerdictClassifier::classify_divergence(800, 1000),
        DivergenceClass::CpuBound
    );
    assert_eq!(
        VerdictClassifier::classify_divergence(200, 1000),
        DivergenceClass::SleepOrBlockBound
    );
    assert_eq!(
        VerdictClassifier::classify_divergence(0, 0),
        DivergenceClass::CpuBound
    );
}

#[test]
fn judge_result_v1_json_roundtrip() {
    let capability_report = CapabilityReport {
        configured_controls: vec!["pid_namespace".to_string(), "mount_namespace".to_string()],
        applied_controls: vec!["pid_namespace".to_string(), "mount_namespace".to_string()],
        missing_controls: vec![],
        mode: SecurityMode::Strict,
        mode_decision_reason: "All controls available".to_string(),
        unsafe_execution_reason: None,
        cgroup_backend_selected: Some("cgroup-v2".to_string()),
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
            cpu_usage_usec: Some(500_000),
            process_count: Some(1),
            process_limit: Some(10),
        }),
        timing_evidence: TimingEvidence {
            wall_elapsed_ms: 1_500,
            cpu_time_ms: 800,
            cpu_wall_ratio: 0.533,
            divergence_class: Some(DivergenceClass::HostInterferenceSuspected),
        },
        process_lifecycle: ProcessLifecycleEvidence {
            reap_summary: "clean".to_string(),
            descendant_containment: "ok".to_string(),
            zombie_count: 0,
        },
        evidence_collection_errors: vec![],
    };

    let original = JudgeResultV1::new(
        ExecutionStatus::Ok,
        Some(0),
        "hello world\n".to_string(),
        "".to_string(),
        OutputIntegrity::Complete,
        0.8,
        1.5,
        constants::MB,
        None,
        capability_report,
        "envelope-abc-123".to_string(),
        evidence_bundle,
        Some("python3-v1".to_string()),
        "2026-03-28T10:00:00Z".to_string(),
        "2026-03-28T10:00:01Z".to_string(),
    );

    let json = original.to_json().expect("serialization must succeed");
    let deserialized = JudgeResultV1::from_json(&json).expect("deserialization must succeed");

    assert_eq!(deserialized.schema_version, "1.0");
    assert_eq!(deserialized.status, original.status);
    assert_eq!(deserialized.exit_code, original.exit_code);
    assert_eq!(deserialized.stdout, original.stdout);
    assert_eq!(deserialized.stderr, original.stderr);
    assert_eq!(deserialized.output_integrity, original.output_integrity);
    assert!((deserialized.cpu_time - original.cpu_time).abs() < f64::EPSILON);
    assert!((deserialized.wall_time - original.wall_time).abs() < f64::EPSILON);
    assert_eq!(deserialized.memory_peak, original.memory_peak);
    assert_eq!(
        deserialized.execution_envelope_id,
        original.execution_envelope_id
    );
    assert_eq!(
        deserialized.language_runtime_envelope,
        original.language_runtime_envelope
    );
    assert_eq!(deserialized.execution_start, original.execution_start);
    assert_eq!(deserialized.execution_end, original.execution_end);
    assert!(deserialized.validate_schema_version().is_ok());
}
