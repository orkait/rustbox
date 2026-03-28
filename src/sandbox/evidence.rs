use crate::config::types::{
    CgroupEvidence, JudgeAction, JudgeActionType, PidfdMode, ProcessLifecycleEvidence,
};
use crate::sandbox::types::{KillReport, LaunchEvidence, ProxyStatus, SandboxLaunchRequest};
use std::time::SystemTime;

pub(crate) struct LaunchEvidenceParams<'a> {
    pub running_as_root: bool,
    pub cgroup_backend_selected: Option<String>,
    pub cgroup_enforced: bool,
    pub timed_out: bool,
    pub kill_report: Option<&'a KillReport>,
    pub proxy_status: &'a ProxyStatus,
    pub cgroup_evidence: Option<CgroupEvidence>,
    pub evidence_collection_errors: Vec<String>,
    pub cleanup_verified: bool,
}

fn detect_pidfd_mode() -> PidfdMode {
    #[cfg(target_os = "linux")]
    {
        const SYS_PIDFD_OPEN: libc::c_long = 434;
        let self_pid = std::process::id() as i32;
        let pidfd = unsafe { libc::syscall(SYS_PIDFD_OPEN, self_pid, 0) as i32 };

        if pidfd >= 0 {
            unsafe {
                libc::close(pidfd);
            }
            PidfdMode::Native
        } else {
            PidfdMode::Fallback
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        PidfdMode::Fallback
    }
}

fn build_configured_controls(req: &SandboxLaunchRequest) -> Vec<String> {
    let mut controls = Vec::with_capacity(8);
    if req.profile.enable_pid_namespace {
        controls.push("pid_namespace".into());
    }
    if req.profile.enable_mount_namespace {
        controls.push("mount_namespace".into());
    }
    if req.profile.enable_network_namespace {
        controls.push("network_namespace".into());
    }
    if req.profile.enable_user_namespace {
        controls.push("user_namespace".into());
    }
    if req.profile.memory_limit.is_some() {
        controls.push("memory_limit".into());
    }
    if req.profile.process_limit.is_some() {
        controls.push("process_limit".into());
    }
    controls.push("no_new_privileges".into());
    controls
}

pub(crate) fn build_launch_evidence(
    req: &SandboxLaunchRequest,
    params: LaunchEvidenceParams<'_>,
) -> LaunchEvidence {
    let LaunchEvidenceParams {
        running_as_root,
        cgroup_backend_selected,
        cgroup_enforced,
        timed_out,
        kill_report,
        proxy_status,
        cgroup_evidence,
        evidence_collection_errors,
        cleanup_verified,
    } = params;
    let configured = build_configured_controls(req);
    let mut applied = Vec::with_capacity(configured.len());
    let mut missing = Vec::new();
    let setup_controls_applied = req.profile.strict_mode && proxy_status.internal_error.is_none();

    for control in &configured {
        let dest = match control.as_str() {
            "memory_limit" | "process_limit" => {
                if cgroup_enforced {
                    &mut applied
                } else {
                    &mut missing
                }
            }
            "pid_namespace" | "mount_namespace" | "network_namespace" | "user_namespace"
            | "no_new_privileges" => {
                if setup_controls_applied {
                    &mut applied
                } else {
                    &mut missing
                }
            }
            _ => &mut applied,
        };
        dest.push(control.clone());
    }

    if timed_out && !applied.iter().any(|c| c == "process_lifecycle") {
        applied.push("process_lifecycle".into());
    }

    let reaped = proxy_status.reaped_descendants;
    let process_lifecycle = ProcessLifecycleEvidence {
        reap_summary: if reaped == 0 {
            "clean".into()
        } else {
            format!("reaped_{reaped}_descendants")
        },
        descendant_containment: if cleanup_verified {
            "ok".into()
        } else {
            "baseline_verification_failed".into()
        },
        zombie_count: 0,
    };

    let mode_decision_reason = match (missing.is_empty(), req.profile.strict_mode) {
        (true, _) => "All configured controls applied".to_string(),
        (false, true) => format!(
            "Strict mode requested but mandatory controls missing: {}",
            missing.join(", ")
        ),
        (false, false) => format!(
            "Execution degraded; missing controls: {}",
            missing.join(", ")
        ),
    };

    let unsafe_execution_reason = (!missing.is_empty()).then(|| mode_decision_reason.clone());

    let push_action = |actions: &mut Vec<JudgeAction>, atype, details: &str| {
        actions.push(JudgeAction {
            timestamp: SystemTime::now(),
            action_type: atype,
            details: details.to_string(),
        });
    };
    let mut judge_actions = Vec::new();
    if let Some(report) = kill_report {
        if report.term_sent {
            push_action(
                &mut judge_actions,
                JudgeActionType::SignalSent,
                "SIGTERM sent to proxy group",
            );
        }
        if report.kill_sent {
            push_action(
                &mut judge_actions,
                JudgeActionType::ForcedKill,
                "SIGKILL sent to proxy group",
            );
        }
    }
    if timed_out && kill_report.is_none() {
        push_action(
            &mut judge_actions,
            JudgeActionType::ForcedKill,
            "SIGKILL sent to child process",
        );
    }

    LaunchEvidence {
        strict_requested: req.profile.strict_mode,
        running_as_root,
        configured_controls: configured,
        applied_controls: applied,
        missing_controls: missing,
        mode_decision_reason,
        unsafe_execution_reason,
        cgroup_backend_selected,
        pidfd_mode: detect_pidfd_mode(),
        proc_policy_applied: if req.profile.enable_mount_namespace {
            "hardened"
        } else {
            "default"
        }
        .into(),
        sys_policy_applied: "disabled".to_string(),
        judge_actions,
        cgroup_evidence,
        process_lifecycle,
        evidence_collection_errors,
        cleanup_verified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::constants;
    use crate::config::types::{IsolateConfig, OutputIntegrity};

    fn test_request(strict_mode: bool) -> SandboxLaunchRequest {
        let config = IsolateConfig {
            instance_id: "evidence-test".to_string(),
            strict_mode,
            enable_pid_namespace: true,
            enable_mount_namespace: true,
            enable_network_namespace: true,
            enable_user_namespace: false,
            memory_limit: Some(constants::DEFAULT_MEMORY_LIMIT),
            process_limit: Some(2),
            ..IsolateConfig::default()
        };

        SandboxLaunchRequest::from_config(&config, &[String::from("/bin/true")], None, None)
    }

    fn proxy_status(internal_error: Option<&str>) -> ProxyStatus {
        ProxyStatus {
            payload_pid: Some(1234),
            exit_code: Some(0),
            term_signal: None,
            timed_out: false,
            wall_time_ms: 1,
            stdout: String::new(),
            stderr: String::new(),
            output_integrity: OutputIntegrity::Complete,
            internal_error: internal_error.map(str::to_string),
            reaped_descendants: 0,
        }
    }

    const SETUP_CONTROLS: [&str; 4] = [
        "pid_namespace",
        "mount_namespace",
        "network_namespace",
        "no_new_privileges",
    ];

    fn strict_evidence(internal_error: Option<&str>) -> LaunchEvidence {
        let req = test_request(true);
        let status = proxy_status(internal_error);
        build_launch_evidence(
            &req,
            LaunchEvidenceParams {
                running_as_root: true,
                cgroup_backend_selected: Some("cgroup-v1".to_string()),
                cgroup_enforced: true,
                timed_out: false,
                kill_report: None,
                proxy_status: &status,
                cgroup_evidence: None,
                evidence_collection_errors: Vec::new(),
                cleanup_verified: true,
            },
        )
    }

    #[test]
    fn strict_mode_does_not_claim_setup_controls_on_proxy_failure() {
        let evidence = strict_evidence(Some("pre-exec failed"));
        for control in SETUP_CONTROLS {
            assert!(
                !evidence.applied_controls.iter().any(|c| c == control),
                "control should not be reported as applied on proxy failure: {control}",
            );
            assert!(
                evidence.missing_controls.iter().any(|c| c == control),
                "control should be reported missing on proxy failure: {control}",
            );
        }
    }

    #[test]
    fn strict_mode_claims_setup_controls_when_proxy_succeeds() {
        let evidence = strict_evidence(None);
        for control in SETUP_CONTROLS {
            assert!(
                evidence.applied_controls.iter().any(|c| c == control),
                "control should be reported as applied on successful proxy setup: {control}",
            );
            assert!(
                !evidence.missing_controls.iter().any(|c| c == control),
                "control should not be reported missing on successful proxy setup: {control}",
            );
        }
    }
}
