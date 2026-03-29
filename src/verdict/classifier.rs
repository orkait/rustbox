use crate::config::types::*;

const MEMORY_PEAK_THRESHOLD_RATIO: f64 = 0.9;
const CPU_BOUND_THRESHOLD: f64 = 0.8;
const SLEEP_BLOCK_THRESHOLD: f64 = 0.2;

pub struct VerdictClassifier;

impl VerdictClassifier {
    pub fn classify(
        evidence: &EvidenceBundle,
        limits: &LimitSnapshot,
    ) -> (ExecutionStatus, VerdictProvenance) {
        if evidence.process_lifecycle.descendant_containment != "ok" {
            return Self::classify_cleanup_failure(evidence, limits);
        }

        let has_fatal_evidence_errors = evidence
            .evidence_collection_errors
            .iter()
            .any(|e| !e.starts_with("degraded_launch:") && !e.starts_with("missing cgroup"));
        if has_fatal_evidence_errors {
            return Self::classify_internal_error(evidence, limits);
        }

        if Self::has_judge_kill(&evidence.judge_actions) {
            return Self::classify_judge_termination(evidence, limits);
        }

        if let Some(exit_code) = evidence.wait_outcome.exit_code {
            if Self::has_kernel_limit_event(evidence) {
                if let Some(cg) = &evidence.cgroup_evidence {
                    if cg.oom_events > 0 || cg.oom_kill_events > 0 {
                        let mut prov = Self::provenance(
                            evidence,
                            limits,
                            VerdictActor::Kernel,
                            VerdictCause::MleKernelOom,
                            vec![
                                "wait_outcome".into(),
                                "cgroup_evidence".into(),
                                "oom_events".into(),
                            ],
                            None,
                        );
                        prov.memory_peak = cg.memory_peak.unwrap_or(0);
                        return (ExecutionStatus::MemoryLimit, prov);
                    }
                }
            }

            if exit_code != 0 {
                if let Some(cg) = &evidence.cgroup_evidence {
                    if let (Some(count), Some(limit)) = (cg.process_count, cg.process_limit) {
                        if count >= limit {
                            return (
                                ExecutionStatus::ProcessLimit,
                                Self::provenance(
                                    evidence,
                                    limits,
                                    VerdictActor::Kernel,
                                    VerdictCause::PleCgroupPids,
                                    vec![
                                        "wait_outcome".into(),
                                        "cgroup_evidence".into(),
                                        "pids_limit".into(),
                                    ],
                                    None,
                                ),
                            );
                        }
                    }
                }
            }

            if exit_code == 0 {
                return (
                    ExecutionStatus::Ok,
                    Self::provenance(
                        evidence,
                        limits,
                        VerdictActor::Runtime,
                        VerdictCause::NormalExit,
                        vec!["wait_outcome".into()],
                        None,
                    ),
                );
            } else {
                return (
                    ExecutionStatus::RuntimeError,
                    Self::provenance(
                        evidence,
                        limits,
                        VerdictActor::Runtime,
                        VerdictCause::ReNonzeroExit,
                        vec!["wait_outcome".into(), "exit_code".into()],
                        None,
                    ),
                );
            }
        }

        if let Some(signal) = evidence.wait_outcome.terminating_signal {
            return Self::classify_signal_termination(evidence, limits, signal);
        }

        Self::classify_internal_error(evidence, limits)
    }

    fn provenance(
        evidence: &EvidenceBundle,
        limits: &LimitSnapshot,
        actor: VerdictActor,
        cause: VerdictCause,
        sources: Vec<String>,
        signal: Option<i32>,
    ) -> VerdictProvenance {
        VerdictProvenance {
            verdict_actor: actor,
            verdict_cause: cause,
            verdict_evidence_sources: sources,
            termination_signal: signal,
            cpu_time_used: evidence.timing_evidence.cpu_time_ms as f64
                / crate::config::constants::MS_PER_SEC_F64,
            wall_time_used: evidence.timing_evidence.wall_elapsed_ms as f64
                / crate::config::constants::MS_PER_SEC_F64,
            memory_peak: evidence
                .cgroup_evidence
                .as_ref()
                .and_then(|e| e.memory_peak)
                .unwrap_or(0),
            limit_snapshot: limits.clone(),
            evidence_collection_errors: evidence.evidence_collection_errors.clone(),
        }
    }

    fn classify_judge_termination(
        evidence: &EvidenceBundle,
        limits: &LimitSnapshot,
    ) -> (ExecutionStatus, VerdictProvenance) {
        let cpu_time_ms = evidence.timing_evidence.cpu_time_ms;
        let wall_time_ms = evidence.timing_evidence.wall_elapsed_ms;
        let cpu_limit_ms = limits.cpu_limit_ms.unwrap_or(u64::MAX);
        let wall_limit_ms = limits.wall_limit_ms.unwrap_or(u64::MAX);

        if cpu_time_ms >= cpu_limit_ms {
            return (
                ExecutionStatus::TimeLimit,
                Self::provenance(
                    evidence,
                    limits,
                    VerdictActor::Judge,
                    VerdictCause::TleCpuJudge,
                    vec![
                        "judge_actions".into(),
                        "timing_evidence".into(),
                        "cpu_time".into(),
                    ],
                    Some(9),
                ),
            );
        }

        if wall_time_ms >= wall_limit_ms {
            return (
                ExecutionStatus::TimeLimit,
                Self::provenance(
                    evidence,
                    limits,
                    VerdictActor::Judge,
                    VerdictCause::TleWallJudge,
                    vec![
                        "judge_actions".into(),
                        "timing_evidence".into(),
                        "wall_time".into(),
                    ],
                    Some(9),
                ),
            );
        }

        if let Some(cg) = &evidence.cgroup_evidence {
            if cg.oom_events > 0 || cg.oom_kill_events > 0 {
                let mut prov = Self::provenance(
                    evidence,
                    limits,
                    VerdictActor::Kernel,
                    VerdictCause::MleKernelOom,
                    vec!["cgroup_evidence".into(), "oom_events".into()],
                    Some(9),
                );
                prov.memory_peak = cg.memory_peak.unwrap_or(0);
                return (ExecutionStatus::MemoryLimit, prov);
            }
        }

        Self::classify_internal_error(evidence, limits)
    }

    fn classify_signal_termination(
        evidence: &EvidenceBundle,
        limits: &LimitSnapshot,
        signal: i32,
    ) -> (ExecutionStatus, VerdictProvenance) {
        if signal == libc::SIGKILL {
            if let Some(cg) = &evidence.cgroup_evidence {
                let has_oom = cg.oom_events > 0 || cg.oom_kill_events > 0;
                let memory_at_limit = match (cg.memory_peak, cg.memory_limit) {
                    (Some(peak), Some(limit)) if limit > 0 => {
                        peak as f64 / limit as f64 >= MEMORY_PEAK_THRESHOLD_RATIO
                    }
                    _ => false,
                };
                if has_oom || memory_at_limit {
                    let sources = if has_oom {
                        vec![
                            "wait_outcome".into(),
                            "cgroup_evidence".into(),
                            "oom_events".into(),
                        ]
                    } else {
                        vec![
                            "wait_outcome".into(),
                            "cgroup_evidence".into(),
                            "memory_at_limit".into(),
                        ]
                    };
                    let cause = if has_oom {
                        VerdictCause::MleKernelOom
                    } else {
                        VerdictCause::MleLimitBreach
                    };
                    let mut prov = Self::provenance(
                        evidence,
                        limits,
                        VerdictActor::Kernel,
                        cause,
                        sources,
                        Some(signal),
                    );
                    prov.memory_peak = cg.memory_peak.unwrap_or(0);
                    return (ExecutionStatus::MemoryLimit, prov);
                }
            }

            let wall_ms = evidence.timing_evidence.wall_elapsed_ms;
            let wall_limit_ms = limits.wall_limit_ms.unwrap_or(u64::MAX);
            if wall_ms >= wall_limit_ms {
                return (
                    ExecutionStatus::TimeLimit,
                    Self::provenance(
                        evidence,
                        limits,
                        VerdictActor::Judge,
                        VerdictCause::TleWallJudge,
                        vec![
                            "wait_outcome".into(),
                            "timing_evidence".into(),
                            "wall_at_limit".into(),
                        ],
                        Some(signal),
                    ),
                );
            }
        }

        if signal == libc::SIGXCPU {
            return (
                ExecutionStatus::TimeLimit,
                Self::provenance(
                    evidence,
                    limits,
                    VerdictActor::Kernel,
                    VerdictCause::TleCpuKernel,
                    vec!["wait_outcome".into(), "signal_xcpu".into()],
                    Some(signal),
                ),
            );
        }

        if signal == libc::SIGXFSZ {
            return (
                ExecutionStatus::FileSizeLimit,
                Self::provenance(
                    evidence,
                    limits,
                    VerdictActor::Kernel,
                    VerdictCause::FseLimitExceeded,
                    vec!["wait_outcome".into(), "signal_xfsz".into()],
                    Some(signal),
                ),
            );
        }

        (
            ExecutionStatus::Signaled,
            Self::provenance(
                evidence,
                limits,
                VerdictActor::Runtime,
                VerdictCause::ReFatalSignal,
                vec!["wait_outcome".into(), "signal".into()],
                Some(signal),
            ),
        )
    }

    fn classify_internal_error(
        evidence: &EvidenceBundle,
        limits: &LimitSnapshot,
    ) -> (ExecutionStatus, VerdictProvenance) {
        let (cause, sources) = if !evidence.evidence_collection_errors.is_empty() {
            (
                VerdictCause::IeMissingEvidence,
                vec!["internal_error".into(), "evidence_collection_errors".into()],
            )
        } else {
            (
                VerdictCause::IeSupervisorFailure,
                vec!["internal_error".into()],
            )
        };

        (
            ExecutionStatus::InternalError,
            Self::provenance(
                evidence,
                limits,
                VerdictActor::Judge,
                cause,
                sources,
                evidence.wait_outcome.terminating_signal,
            ),
        )
    }

    fn classify_cleanup_failure(
        evidence: &EvidenceBundle,
        limits: &LimitSnapshot,
    ) -> (ExecutionStatus, VerdictProvenance) {
        let mut prov = Self::provenance(
            evidence,
            limits,
            VerdictActor::Judge,
            VerdictCause::IeCleanupFailure,
            vec!["process_lifecycle".into(), "cleanup_verification".into()],
            evidence.wait_outcome.terminating_signal,
        );
        prov.evidence_collection_errors.push(format!(
            "cleanup verification failed: {}",
            evidence.process_lifecycle.descendant_containment
        ));

        (ExecutionStatus::InternalError, prov)
    }

    fn has_judge_kill(actions: &[JudgeAction]) -> bool {
        actions.iter().any(|a| {
            matches!(
                a.action_type,
                JudgeActionType::ForcedKill | JudgeActionType::Escalation
            )
        })
    }

    fn has_kernel_limit_event(evidence: &EvidenceBundle) -> bool {
        evidence
            .cgroup_evidence
            .as_ref()
            .map(|e| e.oom_events > 0 || e.oom_kill_events > 0)
            .unwrap_or(false)
    }

    pub fn classify_divergence(cpu_time_ms: u64, wall_time_ms: u64) -> DivergenceClass {
        if wall_time_ms == 0 {
            return DivergenceClass::CpuBound;
        }
        let ratio = cpu_time_ms as f64 / wall_time_ms as f64;
        if ratio >= CPU_BOUND_THRESHOLD {
            DivergenceClass::CpuBound
        } else if ratio <= SLEEP_BLOCK_THRESHOLD {
            DivergenceClass::SleepOrBlockBound
        } else {
            DivergenceClass::HostInterferenceSuspected
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::constants;
    use std::time::SystemTime;

    fn test_limits() -> LimitSnapshot {
        LimitSnapshot {
            cpu_limit_ms: Some(10000),
            wall_limit_ms: Some(20000),
            memory_limit_bytes: Some(constants::DEFAULT_MEMORY_LIMIT),
            process_limit: Some(1),
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
    fn test_classify_ok() {
        let (status, prov) =
            VerdictClassifier::classify(&base_evidence(Some(0), None), &test_limits());
        assert_eq!(status, ExecutionStatus::Ok);
        assert_eq!(prov.verdict_actor, VerdictActor::Runtime);
        assert_eq!(prov.verdict_cause, VerdictCause::NormalExit);
    }

    #[test]
    fn test_classify_runtime_error() {
        let (status, prov) =
            VerdictClassifier::classify(&base_evidence(Some(1), None), &test_limits());
        assert_eq!(status, ExecutionStatus::RuntimeError);
        assert_eq!(prov.verdict_cause, VerdictCause::ReNonzeroExit);
    }

    #[test]
    fn test_classify_cpu_timeout() {
        let mut evidence = base_evidence(None, Some(9));
        evidence.timing_evidence = TimingEvidence {
            wall_elapsed_ms: 15000,
            cpu_time_ms: 10000,
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
        evidence.process_lifecycle.reap_summary = "forced".into();

        let (status, prov) = VerdictClassifier::classify(&evidence, &test_limits());
        assert_eq!(status, ExecutionStatus::TimeLimit);
        assert_eq!(prov.verdict_cause, VerdictCause::TleCpuJudge);
    }

    #[test]
    fn test_judge_kill_precedes_nonzero_exit_code() {
        let mut evidence = base_evidence(Some(143), None);
        evidence.timing_evidence = TimingEvidence {
            wall_elapsed_ms: 21000,
            cpu_time_ms: 2000,
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
        evidence.process_lifecycle.reap_summary = "forced".into();

        let (status, prov) = VerdictClassifier::classify(&evidence, &test_limits());
        assert_eq!(status, ExecutionStatus::TimeLimit);
        assert_eq!(prov.verdict_cause, VerdictCause::TleWallJudge);
    }

    #[test]
    fn test_ok_path_rejects_kernel_limit_events() {
        let mut evidence = base_evidence(Some(0), None);
        evidence.cgroup_evidence = Some(CgroupEvidence {
            memory_peak: Some(10),
            memory_limit: Some(100),
            oom_events: 1,
            oom_kill_events: 1,
            cpu_usage_usec: Some(1000),
            process_count: Some(1),
            process_limit: Some(1),
        });
        evidence.timing_evidence.cpu_time_ms = 500;
        evidence.timing_evidence.cpu_wall_ratio = 0.5;

        let (status, prov) = VerdictClassifier::classify(&evidence, &test_limits());
        assert_eq!(status, ExecutionStatus::MemoryLimit);
        assert_eq!(prov.verdict_cause, VerdictCause::MleKernelOom);
    }

    #[test]
    fn test_sigxcpu_classified_as_tle() {
        let evidence = base_evidence(None, Some(libc::SIGXCPU));
        let (status, prov) = VerdictClassifier::classify(&evidence, &test_limits());
        assert_eq!(status, ExecutionStatus::TimeLimit);
        assert_eq!(prov.verdict_cause, VerdictCause::TleCpuKernel);
    }

    #[test]
    fn test_sigxfsz_classified_as_fse() {
        let evidence = base_evidence(None, Some(libc::SIGXFSZ));
        let (status, prov) = VerdictClassifier::classify(&evidence, &test_limits());
        assert_eq!(status, ExecutionStatus::FileSizeLimit);
        assert_eq!(prov.verdict_cause, VerdictCause::FseLimitExceeded);
    }

    #[test]
    fn test_classify_process_limit() {
        let mut evidence = base_evidence(Some(1), None);
        evidence.cgroup_evidence = Some(CgroupEvidence {
            memory_peak: Some(constants::KB),
            memory_limit: Some(constants::DEFAULT_MEMORY_LIMIT),
            oom_events: 0,
            oom_kill_events: 0,
            cpu_usage_usec: Some(1000),
            process_count: Some(10),
            process_limit: Some(10),
        });

        let (status, prov) = VerdictClassifier::classify(&evidence, &test_limits());
        assert_eq!(status, ExecutionStatus::ProcessLimit);
        assert_eq!(prov.verdict_cause, VerdictCause::PleCgroupPids);
    }

    #[test]
    fn test_process_limit_not_triggered_on_exit_zero() {
        let mut evidence = base_evidence(Some(0), None);
        evidence.cgroup_evidence = Some(CgroupEvidence {
            memory_peak: Some(constants::KB),
            memory_limit: Some(constants::DEFAULT_MEMORY_LIMIT),
            oom_events: 0,
            oom_kill_events: 0,
            cpu_usage_usec: Some(1000),
            process_count: Some(10),
            process_limit: Some(10),
        });

        let (status, _) = VerdictClassifier::classify(&evidence, &test_limits());
        assert_eq!(status, ExecutionStatus::Ok);
    }

    #[test]
    fn test_cleanup_failure_escalates_to_ie() {
        let mut evidence = base_evidence(Some(0), None);
        evidence.process_lifecycle.reap_summary = "reaped_2_descendants".into();
        evidence.process_lifecycle.descendant_containment = "baseline_verification_failed".into();
        evidence.timing_evidence.cpu_time_ms = 500;
        evidence.timing_evidence.cpu_wall_ratio = 0.5;

        let (status, prov) = VerdictClassifier::classify(&evidence, &test_limits());
        assert_eq!(status, ExecutionStatus::InternalError);
        assert_eq!(prov.verdict_cause, VerdictCause::IeCleanupFailure);
    }

    #[test]
    fn test_classify_divergence() {
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
    }
}
