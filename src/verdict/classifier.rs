/// Verdict classification and provenance
/// Implements P0-RESULT-001: Honest Judge Failure Classification
/// Implements P0-PROV-001: Verdict Provenance Contract
/// Per plan.md Section 8.4, 8.5: Deterministic verdict derivation
use crate::config::types::*;

/// Verdict classifier - pure function over evidence bundle
/// Per plan.md Section 8.5: verdict = f(evidence_bundle)
pub struct VerdictClassifier;

impl VerdictClassifier {
    /// Classify execution outcome based on evidence
    /// This is a pure, deterministic function
    pub fn classify(
        evidence: &EvidenceBundle,
        limits: &LimitSnapshot,
    ) -> (ExecutionStatus, VerdictProvenance) {
        if evidence.process_lifecycle.descendant_containment != "ok" {
            return Self::classify_cleanup_failure(evidence, limits);
        }

        // Evidence collection errors are fatal only when they affect the verdict.
        // In degraded/dev mode, missing cgroup evidence is expected and should not
        // override a clean exit code. Only escalate to IE for errors that indicate
        // actual judge infrastructure failures (not merely missing instrumentation).
        let has_fatal_evidence_errors = evidence
            .evidence_collection_errors
            .iter()
            .any(|e| !e.starts_with("degraded_launch:") && !e.starts_with("missing cgroup"));
        if has_fatal_evidence_errors {
            return Self::classify_internal_error(evidence, limits, "Evidence collection failed");
        }

        // Judge actions take precedence over derived exit code because
        // forced kills may surface as non-zero exits (e.g., 143) in wrappers.
        if Self::has_judge_kill(&evidence.judge_actions) {
            return Self::classify_judge_termination(evidence, limits);
        }

        // Check for normal/runtime exit
        if let Some(exit_code) = evidence.wait_outcome.exit_code {
            if exit_code == 0 && !Self::has_kernel_limit_event(evidence) {
                // Normal successful exit
                return Self::classify_ok(evidence, limits);
            } else if exit_code != 0 {
                // Non-zero exit is runtime error
                return Self::classify_runtime_error(evidence, limits, exit_code);
            }
        }

        // Check for signal termination
        if let Some(signal) = evidence.wait_outcome.terminating_signal {
            return Self::classify_signal_termination(evidence, limits, signal);
        }

        // If we get here, something unexpected happened
        Self::classify_internal_error(evidence, limits, "Unexpected termination state")
    }

    /// Classify OK verdict
    fn classify_ok(
        evidence: &EvidenceBundle,
        limits: &LimitSnapshot,
    ) -> (ExecutionStatus, VerdictProvenance) {
        let provenance = VerdictProvenance {
            verdict_actor: VerdictActor::Runtime,
            verdict_cause: VerdictCause::NormalExit,
            verdict_evidence_sources: vec!["wait_outcome".to_string()],
            termination_signal: None,
            cpu_time_used: evidence.timing_evidence.cpu_time_ms as f64 / 1000.0,
            wall_time_used: evidence.timing_evidence.wall_elapsed_ms as f64 / 1000.0,
            memory_peak: evidence
                .cgroup_evidence
                .as_ref()
                .and_then(|e| e.memory_peak)
                .unwrap_or(0),
            limit_snapshot: limits.clone(),
            evidence_collection_errors: evidence.evidence_collection_errors.clone(),
        };

        (ExecutionStatus::Ok, provenance)
    }

    /// Classify runtime error
    fn classify_runtime_error(
        evidence: &EvidenceBundle,
        limits: &LimitSnapshot,
        _exit_code: i32,
    ) -> (ExecutionStatus, VerdictProvenance) {
        let provenance = VerdictProvenance {
            verdict_actor: VerdictActor::Runtime,
            verdict_cause: VerdictCause::ReNonzeroExit,
            verdict_evidence_sources: vec!["wait_outcome".to_string(), "exit_code".to_string()],
            termination_signal: None,
            cpu_time_used: evidence.timing_evidence.cpu_time_ms as f64 / 1000.0,
            wall_time_used: evidence.timing_evidence.wall_elapsed_ms as f64 / 1000.0,
            memory_peak: evidence
                .cgroup_evidence
                .as_ref()
                .and_then(|e| e.memory_peak)
                .unwrap_or(0),
            limit_snapshot: limits.clone(),
            evidence_collection_errors: evidence.evidence_collection_errors.clone(),
        };

        (ExecutionStatus::RuntimeError, provenance)
    }

    /// Classify judge-initiated termination
    fn classify_judge_termination(
        evidence: &EvidenceBundle,
        limits: &LimitSnapshot,
    ) -> (ExecutionStatus, VerdictProvenance) {
        // Determine if it was CPU or wall timeout
        let cpu_time_ms = evidence.timing_evidence.cpu_time_ms;
        let wall_time_ms = evidence.timing_evidence.wall_elapsed_ms;

        let cpu_limit_ms = limits.cpu_limit_ms.unwrap_or(u64::MAX);
        let wall_limit_ms = limits.wall_limit_ms.unwrap_or(u64::MAX);

        // Check for CPU timeout
        if cpu_time_ms >= cpu_limit_ms {
            let provenance = VerdictProvenance {
                verdict_actor: VerdictActor::Judge,
                verdict_cause: VerdictCause::TleCpuJudge,
                verdict_evidence_sources: vec![
                    "judge_actions".to_string(),
                    "timing_evidence".to_string(),
                    "cpu_time".to_string(),
                ],
                termination_signal: Some(9), // SIGKILL
                cpu_time_used: cpu_time_ms as f64 / 1000.0,
                wall_time_used: wall_time_ms as f64 / 1000.0,
                memory_peak: evidence
                    .cgroup_evidence
                    .as_ref()
                    .and_then(|e| e.memory_peak)
                    .unwrap_or(0),
                limit_snapshot: limits.clone(),
                evidence_collection_errors: evidence.evidence_collection_errors.clone(),
            };
            return (ExecutionStatus::TimeLimit, provenance);
        }

        // Check for wall timeout
        if wall_time_ms >= wall_limit_ms {
            let provenance = VerdictProvenance {
                verdict_actor: VerdictActor::Judge,
                verdict_cause: VerdictCause::TleWallJudge,
                verdict_evidence_sources: vec![
                    "judge_actions".to_string(),
                    "timing_evidence".to_string(),
                    "wall_time".to_string(),
                ],
                termination_signal: Some(9), // SIGKILL
                cpu_time_used: cpu_time_ms as f64 / 1000.0,
                wall_time_used: wall_time_ms as f64 / 1000.0,
                memory_peak: evidence
                    .cgroup_evidence
                    .as_ref()
                    .and_then(|e| e.memory_peak)
                    .unwrap_or(0),
                limit_snapshot: limits.clone(),
                evidence_collection_errors: evidence.evidence_collection_errors.clone(),
            };
            return (ExecutionStatus::TimeLimit, provenance);
        }

        // Check for memory limit (OOM)
        if let Some(cgroup_evidence) = &evidence.cgroup_evidence {
            if cgroup_evidence.oom_events > 0 || cgroup_evidence.oom_kill_events > 0 {
                let provenance = VerdictProvenance {
                    verdict_actor: VerdictActor::Kernel,
                    verdict_cause: VerdictCause::MleKernelOom,
                    verdict_evidence_sources: vec![
                        "cgroup_evidence".to_string(),
                        "oom_events".to_string(),
                    ],
                    termination_signal: Some(9), // SIGKILL from OOM killer
                    cpu_time_used: cpu_time_ms as f64 / 1000.0,
                    wall_time_used: wall_time_ms as f64 / 1000.0,
                    memory_peak: cgroup_evidence.memory_peak.unwrap_or(0),
                    limit_snapshot: limits.clone(),
                    evidence_collection_errors: evidence.evidence_collection_errors.clone(),
                };
                return (ExecutionStatus::MemoryLimit, provenance);
            }
        }

        // Judge killed but reason unclear - IE
        Self::classify_internal_error(evidence, limits, "Judge kill without clear cause")
    }

    /// Classify signal termination
    fn classify_signal_termination(
        evidence: &EvidenceBundle,
        limits: &LimitSnapshot,
        signal: i32,
    ) -> (ExecutionStatus, VerdictProvenance) {
        // Check if this was an OOM kill (SIGKILL with OOM evidence)
        if signal == 9 {
            if let Some(cgroup_evidence) = &evidence.cgroup_evidence {
                if cgroup_evidence.oom_events > 0 || cgroup_evidence.oom_kill_events > 0 {
                    let provenance = VerdictProvenance {
                        verdict_actor: VerdictActor::Kernel,
                        verdict_cause: VerdictCause::MleKernelOom,
                        verdict_evidence_sources: vec![
                            "wait_outcome".to_string(),
                            "cgroup_evidence".to_string(),
                            "oom_events".to_string(),
                        ],
                        termination_signal: Some(signal),
                        cpu_time_used: evidence.timing_evidence.cpu_time_ms as f64 / 1000.0,
                        wall_time_used: evidence.timing_evidence.wall_elapsed_ms as f64 / 1000.0,
                        memory_peak: cgroup_evidence.memory_peak.unwrap_or(0),
                        limit_snapshot: limits.clone(),
                        evidence_collection_errors: evidence.evidence_collection_errors.clone(),
                    };
                    return (ExecutionStatus::MemoryLimit, provenance);
                }
            }
        }

        // Fatal signal not attributable to judge or kernel limit
        let provenance = VerdictProvenance {
            verdict_actor: VerdictActor::Runtime,
            verdict_cause: VerdictCause::ReFatalSignal,
            verdict_evidence_sources: vec!["wait_outcome".to_string(), "signal".to_string()],
            termination_signal: Some(signal),
            cpu_time_used: evidence.timing_evidence.cpu_time_ms as f64 / 1000.0,
            wall_time_used: evidence.timing_evidence.wall_elapsed_ms as f64 / 1000.0,
            memory_peak: evidence
                .cgroup_evidence
                .as_ref()
                .and_then(|e| e.memory_peak)
                .unwrap_or(0),
            limit_snapshot: limits.clone(),
            evidence_collection_errors: evidence.evidence_collection_errors.clone(),
        };

        (ExecutionStatus::Signaled, provenance)
    }

    /// Classify internal error
    fn classify_internal_error(
        evidence: &EvidenceBundle,
        limits: &LimitSnapshot,
        _reason: &str,
    ) -> (ExecutionStatus, VerdictProvenance) {
        let mut evidence_sources = vec!["internal_error".to_string()];
        let cause = if !evidence.evidence_collection_errors.is_empty() {
            evidence_sources.push("evidence_collection_errors".to_string());
            VerdictCause::IeMissingEvidence
        } else {
            VerdictCause::IeSupervisorFailure
        };

        let provenance = VerdictProvenance {
            verdict_actor: VerdictActor::Judge,
            verdict_cause: cause,
            verdict_evidence_sources: evidence_sources,
            termination_signal: evidence.wait_outcome.terminating_signal,
            cpu_time_used: evidence.timing_evidence.cpu_time_ms as f64 / 1000.0,
            wall_time_used: evidence.timing_evidence.wall_elapsed_ms as f64 / 1000.0,
            memory_peak: evidence
                .cgroup_evidence
                .as_ref()
                .and_then(|e| e.memory_peak)
                .unwrap_or(0),
            limit_snapshot: limits.clone(),
            evidence_collection_errors: evidence.evidence_collection_errors.clone(),
        };

        (ExecutionStatus::InternalError, provenance)
    }

    /// Check if judge initiated kill
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

    fn classify_cleanup_failure(
        evidence: &EvidenceBundle,
        limits: &LimitSnapshot,
    ) -> (ExecutionStatus, VerdictProvenance) {
        let mut errors = evidence.evidence_collection_errors.clone();
        errors.push(format!(
            "cleanup verification failed: {}",
            evidence.process_lifecycle.descendant_containment
        ));

        let provenance = VerdictProvenance {
            verdict_actor: VerdictActor::Judge,
            verdict_cause: VerdictCause::IeCleanupFailure,
            verdict_evidence_sources: vec![
                "process_lifecycle".to_string(),
                "cleanup_verification".to_string(),
            ],
            termination_signal: evidence.wait_outcome.terminating_signal,
            cpu_time_used: evidence.timing_evidence.cpu_time_ms as f64 / 1000.0,
            wall_time_used: evidence.timing_evidence.wall_elapsed_ms as f64 / 1000.0,
            memory_peak: evidence
                .cgroup_evidence
                .as_ref()
                .and_then(|e| e.memory_peak)
                .unwrap_or(0),
            limit_snapshot: limits.clone(),
            evidence_collection_errors: errors,
        };

        (ExecutionStatus::InternalError, provenance)
    }

    /// Compute CPU vs wall divergence classification
    pub fn classify_divergence(cpu_time_ms: u64, wall_time_ms: u64) -> DivergenceClass {
        if wall_time_ms == 0 {
            return DivergenceClass::CpuBound;
        }

        let ratio = cpu_time_ms as f64 / wall_time_ms as f64;

        if ratio >= 0.8 {
            // CPU time is 80%+ of wall time - CPU bound
            DivergenceClass::CpuBound
        } else if ratio <= 0.2 {
            // CPU time is 20% or less of wall time - mostly sleeping/blocking
            DivergenceClass::SleepOrBlockBound
        } else {
            // Moderate divergence - could be host interference
            DivergenceClass::HostInterferenceSuspected
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn create_test_limits() -> LimitSnapshot {
        LimitSnapshot {
            cpu_limit_ms: Some(10000),
            wall_limit_ms: Some(20000),
            memory_limit_bytes: Some(128 * 1024 * 1024),
            process_limit: Some(1),
            output_limit_bytes: Some(64 * 1024 * 1024),
        }
    }

    #[test]
    fn test_classify_ok() {
        let evidence = EvidenceBundle {
            wait_outcome: WaitOutcome {
                exit_code: Some(0),
                terminating_signal: None,
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
        };

        let limits = create_test_limits();
        let (status, provenance) = VerdictClassifier::classify(&evidence, &limits);

        assert_eq!(status, ExecutionStatus::Ok);
        assert_eq!(provenance.verdict_actor, VerdictActor::Runtime);
        assert_eq!(provenance.verdict_cause, VerdictCause::NormalExit);
    }

    #[test]
    fn test_classify_runtime_error() {
        let evidence = EvidenceBundle {
            wait_outcome: WaitOutcome {
                exit_code: Some(1),
                terminating_signal: None,
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
        };

        let limits = create_test_limits();
        let (status, provenance) = VerdictClassifier::classify(&evidence, &limits);

        assert_eq!(status, ExecutionStatus::RuntimeError);
        assert_eq!(provenance.verdict_actor, VerdictActor::Runtime);
        assert_eq!(provenance.verdict_cause, VerdictCause::ReNonzeroExit);
    }

    #[test]
    fn test_classify_cpu_timeout() {
        let evidence = EvidenceBundle {
            wait_outcome: WaitOutcome {
                exit_code: None,
                terminating_signal: Some(9),
                stopped: false,
                continued: false,
            },
            judge_actions: vec![
                JudgeAction {
                    timestamp: SystemTime::now(),
                    action_type: JudgeActionType::TimerExpiry,
                    details: "CPU timeout".to_string(),
                },
                JudgeAction {
                    timestamp: SystemTime::now(),
                    action_type: JudgeActionType::ForcedKill,
                    details: "SIGKILL".to_string(),
                },
            ],
            cgroup_evidence: None,
            timing_evidence: TimingEvidence {
                wall_elapsed_ms: 15000,
                cpu_time_ms: 10000, // At limit
                cpu_wall_ratio: 0.67,
                divergence_class: Some(DivergenceClass::CpuBound),
            },
            process_lifecycle: ProcessLifecycleEvidence {
                reap_summary: "forced".to_string(),
                descendant_containment: "ok".to_string(),
                zombie_count: 0,
            },
            evidence_collection_errors: vec![],
        };

        let limits = create_test_limits();
        let (status, provenance) = VerdictClassifier::classify(&evidence, &limits);

        assert_eq!(status, ExecutionStatus::TimeLimit);
        assert_eq!(provenance.verdict_actor, VerdictActor::Judge);
        assert_eq!(provenance.verdict_cause, VerdictCause::TleCpuJudge);
    }

    #[test]
    fn test_judge_kill_precedes_nonzero_exit_code() {
        let evidence = EvidenceBundle {
            wait_outcome: WaitOutcome {
                exit_code: Some(143),
                terminating_signal: None,
                stopped: false,
                continued: false,
            },
            judge_actions: vec![
                JudgeAction {
                    timestamp: SystemTime::now(),
                    action_type: JudgeActionType::TimerExpiry,
                    details: "wall timeout".to_string(),
                },
                JudgeAction {
                    timestamp: SystemTime::now(),
                    action_type: JudgeActionType::ForcedKill,
                    details: "SIGKILL".to_string(),
                },
            ],
            cgroup_evidence: None,
            timing_evidence: TimingEvidence {
                wall_elapsed_ms: 21000,
                cpu_time_ms: 2000,
                cpu_wall_ratio: 0.1,
                divergence_class: Some(DivergenceClass::SleepOrBlockBound),
            },
            process_lifecycle: ProcessLifecycleEvidence {
                reap_summary: "forced".to_string(),
                descendant_containment: "ok".to_string(),
                zombie_count: 0,
            },
            evidence_collection_errors: vec![],
        };

        let limits = create_test_limits();
        let (status, provenance) = VerdictClassifier::classify(&evidence, &limits);

        assert_eq!(status, ExecutionStatus::TimeLimit);
        assert_eq!(provenance.verdict_actor, VerdictActor::Judge);
        assert_eq!(provenance.verdict_cause, VerdictCause::TleWallJudge);
    }

    #[test]
    fn test_ok_path_rejects_kernel_limit_events() {
        let evidence = EvidenceBundle {
            wait_outcome: WaitOutcome {
                exit_code: Some(0),
                terminating_signal: None,
                stopped: false,
                continued: false,
            },
            judge_actions: vec![],
            cgroup_evidence: Some(CgroupEvidence {
                memory_peak: Some(10),
                memory_limit: Some(100),
                oom_events: 1,
                oom_kill_events: 1,
                cpu_usage_usec: Some(1000),
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

        let limits = create_test_limits();
        let (status, provenance) = VerdictClassifier::classify(&evidence, &limits);
        assert_eq!(status, ExecutionStatus::InternalError);
        assert_eq!(provenance.verdict_cause, VerdictCause::IeSupervisorFailure);
    }

    #[test]
    fn test_cleanup_failure_escalates_to_ie() {
        let evidence = EvidenceBundle {
            wait_outcome: WaitOutcome {
                exit_code: Some(0),
                terminating_signal: None,
                stopped: false,
                continued: false,
            },
            judge_actions: vec![],
            cgroup_evidence: None,
            timing_evidence: TimingEvidence {
                wall_elapsed_ms: 1000,
                cpu_time_ms: 500,
                cpu_wall_ratio: 0.5,
                divergence_class: Some(DivergenceClass::CpuBound),
            },
            process_lifecycle: ProcessLifecycleEvidence {
                reap_summary: "reaped_2_descendants".to_string(),
                descendant_containment: "baseline_verification_failed".to_string(),
                zombie_count: 0,
            },
            evidence_collection_errors: vec![],
        };

        let limits = create_test_limits();
        let (status, provenance) = VerdictClassifier::classify(&evidence, &limits);
        assert_eq!(status, ExecutionStatus::InternalError);
        assert_eq!(provenance.verdict_cause, VerdictCause::IeCleanupFailure);
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
