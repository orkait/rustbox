use crate::config::types::{
    CgroupEvidence, ExecutionStatus, IsolateError, JudgeAction, JudgeActionType,
    ProcessLifecycleEvidence, Result,
};
use crate::core::proxy::{read_proxy_status_from_fd, run_proxy_main_from_fds, write_request_to_fd};
use crate::core::types::{
    KillReport, LaunchEvidence, ProxyStatus, SandboxLaunchOutcome, SandboxLaunchRequest,
};
use crate::kernel::cgroup::backend::CgroupBackend;
use nix::sched::{clone, CloneFlags};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{close, pipe, Pid};
use std::time::{Duration, Instant, SystemTime};

fn to_process_error(prefix: &str, err: impl std::fmt::Display) -> IsolateError {
    IsolateError::Process(format!("{prefix}: {err}"))
}

fn detect_pidfd_mode() -> crate::config::types::PidfdMode {
    // Simplified pidfd detection (no supervisor module)
    #[cfg(target_os = "linux")]
    {
        // Try to open pidfd for our own process
        const SYS_PIDFD_OPEN: libc::c_long = 434;
        let self_pid = std::process::id() as i32;
        let pidfd = unsafe { libc::syscall(SYS_PIDFD_OPEN, self_pid, 0) as i32 };

        if pidfd >= 0 {
            unsafe {
                libc::close(pidfd);
            }
            crate::config::types::PidfdMode::Native
        } else {
            crate::config::types::PidfdMode::Fallback
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        crate::config::types::PidfdMode::Fallback
    }
}

fn build_configured_controls(req: &SandboxLaunchRequest) -> Vec<String> {
    let mut controls = Vec::new();
    if req.profile.enable_pid_namespace {
        controls.push("pid_namespace".to_string());
    }
    if req.profile.enable_mount_namespace {
        controls.push("mount_namespace".to_string());
    }
    if req.profile.enable_network_namespace {
        controls.push("network_namespace".to_string());
    }
    if req.profile.enable_user_namespace {
        controls.push("user_namespace".to_string());
    }
    if req.profile.memory_limit.is_some() {
        controls.push("memory_limit".to_string());
    }
    if req.profile.process_limit.is_some() {
        controls.push("process_limit".to_string());
    }
    controls.push("no_new_privileges".to_string());
    controls
}

fn build_launch_evidence(
    req: &SandboxLaunchRequest,
    running_as_root: bool,
    cgroup_backend_selected: Option<String>,
    cgroup_enforced: bool,
    timed_out: bool,
    kill_report: Option<&KillReport>,
    proxy_status: &ProxyStatus,
    cgroup_evidence: Option<CgroupEvidence>,
    evidence_collection_errors: Vec<String>,
    cleanup_verified: bool,
) -> LaunchEvidence {
    let configured = build_configured_controls(req);
    let mut applied = Vec::new();
    let mut missing = Vec::new();
    // Namespace/no_new_privs setup is performed in proxy pre-exec.
    // Do not claim these controls when proxy reports setup failure.
    let setup_controls_applied = req.profile.strict_mode && proxy_status.internal_error.is_none();

    for control in &configured {
        match control.as_str() {
            "memory_limit" | "process_limit" => {
                if cgroup_enforced {
                    applied.push(control.clone());
                } else {
                    missing.push(control.clone());
                }
            }
            "pid_namespace" | "mount_namespace" | "network_namespace" | "user_namespace"
            | "no_new_privileges" => {
                if setup_controls_applied {
                    applied.push(control.clone());
                } else {
                    // In permissive mode these controls may log-and-continue on failure.
                    // Do not over-claim enforcement when runtime verification is absent.
                    missing.push(control.clone());
                }
            }
            _ => applied.push(control.clone()),
        }
    }

    if timed_out && !applied.contains(&"process_lifecycle".to_string()) {
        applied.push("process_lifecycle".to_string());
    }

    let process_lifecycle = ProcessLifecycleEvidence {
        reap_summary: if proxy_status.reaped_descendants == 0 {
            "clean".to_string()
        } else {
            format!("reaped_{}_descendants", proxy_status.reaped_descendants)
        },
        descendant_containment: if cleanup_verified {
            "ok".to_string()
        } else {
            "baseline_verification_failed".to_string()
        },
        zombie_count: 0,
    };

    let mode_decision_reason = if req.profile.strict_mode && !missing.is_empty() {
        format!(
            "Strict mode requested but mandatory controls missing: {}",
            missing.join(", ")
        )
    } else if missing.is_empty() {
        "All configured controls applied".to_string()
    } else {
        format!(
            "Execution degraded; missing controls: {}",
            missing.join(", ")
        )
    };

    let unsafe_execution_reason = if missing.is_empty() {
        None
    } else {
        Some(mode_decision_reason.clone())
    };

    let mut judge_actions = Vec::new();
    if let Some(report) = kill_report {
        if report.term_sent {
            judge_actions.push(JudgeAction {
                timestamp: SystemTime::now(),
                action_type: JudgeActionType::SignalSent,
                details: "SIGTERM sent to proxy group".to_string(),
            });
        }
        if report.kill_sent {
            judge_actions.push(JudgeAction {
                timestamp: SystemTime::now(),
                action_type: JudgeActionType::ForcedKill,
                details: "SIGKILL sent to proxy group".to_string(),
            });
        }
    }
    if timed_out && kill_report.is_none() {
        // Degraded launch timeout path kills the direct child via Command::kill()
        // and has no KillReport. Emit a forced-kill action so verdict logic
        // classifies this as judge-enforced timeout instead of internal error.
        judge_actions.push(JudgeAction {
            timestamp: SystemTime::now(),
            action_type: JudgeActionType::ForcedKill,
            details: "SIGKILL sent to child process (degraded mode)".to_string(),
        });
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
            "hardened".to_string()
        } else {
            "default".to_string()
        },
        sys_policy_applied: "disabled".to_string(),
        judge_actions,
        cgroup_evidence,
        process_lifecycle,
        evidence_collection_errors,
        cleanup_verified,
    }
}

fn terminate_proxy_group(proxy_pid: Pid) -> KillReport {
    let mut report = KillReport::default();
    let start = Instant::now();

    let term_rc = unsafe { libc::kill(-proxy_pid.as_raw(), libc::SIGTERM) };
    if term_rc == 0 {
        report.term_sent = true;
    } else {
        let _ = unsafe { libc::kill(proxy_pid.as_raw(), libc::SIGTERM) };
        report.term_sent = true;
        report.notes.push(format!(
            "group SIGTERM fallback used: {}",
            std::io::Error::last_os_error()
        ));
    }

    std::thread::sleep(Duration::from_millis(200));

    let kill_rc = unsafe { libc::kill(-proxy_pid.as_raw(), libc::SIGKILL) };
    if kill_rc == 0 {
        report.kill_sent = true;
    } else {
        let _ = unsafe { libc::kill(proxy_pid.as_raw(), libc::SIGKILL) };
        report.kill_sent = true;
        report.notes.push(format!(
            "group SIGKILL fallback used: {}",
            std::io::Error::last_os_error()
        ));
    }

    report.waited_ms = start.elapsed().as_millis() as u64;
    report
}

/// Launch request using supervisor -> proxy -> payload model.
pub fn launch_with_supervisor(
    req: SandboxLaunchRequest,
    cgroup: Option<&dyn CgroupBackend>,
) -> Result<SandboxLaunchOutcome> {
    if req.profile.command.is_empty() {
        return Err(IsolateError::Config("empty command".to_string()));
    }

    if req.profile.strict_mode
        && req.profile.enable_pid_namespace
        && unsafe { libc::geteuid() } != 0
    {
        return Err(IsolateError::Privilege(
            "strict pid namespace launch requires root".to_string(),
        ));
    }

    let mut evidence_collection_errors = Vec::new();
    let cgroup_backend_selected = cgroup.map(|controller| controller.backend_name().to_string());
    let mut cgroup_enforced = false;

    let (launch_read, launch_write) = pipe().map_err(|e| to_process_error("pipe(launch)", e))?;
    let (status_read, status_write) = pipe().map_err(|e| to_process_error("pipe(status)", e))?;

    // CLONE_NEWPID gives us proxy PID 1 in sandbox namespace.
    let mut clone_flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWIPC;
    if req.profile.enable_mount_namespace {
        clone_flags |= CloneFlags::CLONE_NEWNS;
    }
    if req.profile.enable_network_namespace {
        clone_flags |= CloneFlags::CLONE_NEWNET;
    }
    if req.profile.enable_user_namespace {
        clone_flags |= CloneFlags::CLONE_NEWUSER;
    }

    let child_launch_read = launch_read;
    let child_launch_write = launch_write;
    let child_status_read = status_read;
    let child_status_write = status_write;
    let mut child_stack = vec![0u8; 2 * 1024 * 1024];
    let child_cb: Box<dyn FnMut() -> isize> = Box::new(move || {
        // Close inherited pipe ends that belong to the parent.
        // Without this, the child holds launch_write open and
        // read_to_end() on launch_read never sees EOF.
        let _ = close(child_launch_write);
        let _ = close(child_status_read);
        run_proxy_main_from_fds(child_launch_read, child_status_write)
    });

    let clone_result =
        unsafe { clone(child_cb, &mut child_stack, clone_flags, Some(libc::SIGCHLD)) };

    let proxy_pid = match clone_result {
        Ok(pid) => pid,
        Err(nix::errno::Errno::EPERM) if !req.profile.strict_mode && req.profile.allow_degraded => {
            // C3: clone() requires root for namespace flags. Only fall back to
            // degraded mode when explicitly opted in via --allow-degraded.
            let _ = close(launch_read);
            let _ = close(launch_write);
            let _ = close(status_read);
            let _ = close(status_write);
            log::warn!("Falling back to degraded launch (--allow-degraded enabled)");
            return launch_degraded(req, cgroup);
        }
        Err(nix::errno::Errno::EPERM) if !req.profile.strict_mode => {
            // C3: EPERM without --allow-degraded is a hard error.
            let _ = close(launch_read);
            let _ = close(launch_write);
            let _ = close(status_read);
            let _ = close(status_write);
            return Err(IsolateError::Privilege(
                "Root privileges required for namespace isolation. \
                 Use --allow-degraded for development without isolation (unsafe for untrusted code)."
                    .to_string(),
            ));
        }
        Err(e) => return Err(to_process_error("clone(proxy)", e)),
    };

    let _ = close(launch_read);
    let _ = close(status_write);

    if let Some(controller) = cgroup {
        if let Err(e) = controller.attach_process(&req.instance_id, proxy_pid.as_raw() as u32) {
            let _ = terminate_proxy_group(proxy_pid);
            evidence_collection_errors.push(format!("cgroup_attach: {}", e));
            if req.profile.strict_mode {
                return Err(e);
            }
        } else {
            cgroup_enforced = true;
        }
    } else if req.profile.strict_mode
        && (req.profile.memory_limit.is_some() || req.profile.process_limit.is_some())
    {
        let _ = terminate_proxy_group(proxy_pid);
        return Err(IsolateError::Cgroup(
            "strict mode requires cgroup limits for configured memory/process controls".to_string(),
        ));
    }

    write_request_to_fd(launch_write, &req)?;

    let wall_limit = req
        .profile
        .wall_time_limit_ms
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_secs(30));
    let started = Instant::now();

    let mut timed_out = false;
    let mut cpu_timed_out = false;
    let mut kill_report: Option<KillReport> = None;
    let mut proxy_exit_code = None;
    let mut proxy_signal = None;

    // C2: Derive CPU limit in microseconds for watchdog polling.
    let cpu_limit_usec: Option<u64> = req.profile.cpu_time_limit_ms.map(|ms| ms * 1000);

    loop {
        match waitpid(proxy_pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                if started.elapsed() > wall_limit {
                    timed_out = true;
                    kill_report = Some(terminate_proxy_group(proxy_pid));
                } else if let (Some(limit_usec), Some(controller)) = (cpu_limit_usec, cgroup) {
                    // C2: Poll cgroup CPU usage and enforce hard CPU-time limit.
                    if let Ok(usage_usec) = controller.get_cpu_usage() {
                        if usage_usec >= limit_usec {
                            cpu_timed_out = true;
                            timed_out = true;
                            kill_report = Some(terminate_proxy_group(proxy_pid));
                            log::info!(
                                "CPU time limit exceeded: {}us >= {}us limit",
                                usage_usec,
                                limit_usec
                            );
                        }
                    }
                    if !timed_out {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            Ok(WaitStatus::Exited(_, code)) => {
                proxy_exit_code = Some(code);
                break;
            }
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                proxy_signal = Some(sig as i32);
                break;
            }
            Ok(_) => continue,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(to_process_error("waitpid(proxy)", e)),
        }
    }

    let mut status = read_proxy_status_from_fd(status_read).unwrap_or_else(|e| ProxyStatus {
        exit_code: proxy_exit_code,
        term_signal: proxy_signal,
        timed_out,
        wall_time_ms: started.elapsed().as_millis() as u64,
        stdout: String::new(),
        stderr: String::new(),
        output_integrity: crate::config::types::OutputIntegrity::WriteError,
        internal_error: Some(e.to_string()),
        payload_pid: None,
        reaped_descendants: 0,
    });
    if timed_out {
        status.timed_out = true;
    }

    let mut result = status.to_execution_result();
    if timed_out {
        result.status = ExecutionStatus::TimeLimit;
        result.success = false;
    }

    // C2: Record CPU-triggered timeout in evidence for verdict provenance.
    if cpu_timed_out {
        evidence_collection_errors.push(
            "cpu_time_limit_exceeded: judge watchdog killed process after cgroup CPU usage exceeded limit".to_string(),
        );
    }

    let mut cgroup_evidence = None;
    if cgroup_enforced {
        if let Some(controller) = cgroup {
            if let Ok(cpu_usec) = controller.get_cpu_usage() {
                result.cpu_time = cpu_usec as f64 / 1_000_000.0;
            }
            if let Ok(mem_peak) = controller.get_memory_peak() {
                result.memory_peak = mem_peak;
            }
            match controller.collect_evidence(&req.instance_id) {
                Ok(evidence) => cgroup_evidence = Some(evidence),
                Err(err) => evidence_collection_errors.push(format!("cgroup_evidence: {}", err)),
            }
        }
    } else if (req.profile.memory_limit.is_some() || req.profile.process_limit.is_some())
        && cgroup_backend_selected.is_some()
    {
        evidence_collection_errors.push(
            "cgroup_limits_unenforced: process was not attached to selected backend".to_string(),
        );
    }

    let running_as_root = unsafe { libc::geteuid() } == 0;
    let evidence = build_launch_evidence(
        &req,
        running_as_root,
        cgroup_backend_selected,
        cgroup_enforced,
        timed_out,
        kill_report.as_ref(),
        &status,
        cgroup_evidence,
        evidence_collection_errors,
        true,
    );

    Ok(SandboxLaunchOutcome {
        proxy_host_pid: proxy_pid.as_raw(),
        payload_host_pid: status.payload_pid,
        result,
        evidence,
        kill_report,
        proxy_status: status,
    })
}

/// Degraded launch path for permissive non-root execution.
/// Uses Command::spawn instead of clone() — no namespace isolation.
fn launch_degraded(
    req: SandboxLaunchRequest,
    cgroup: Option<&dyn CgroupBackend>,
) -> Result<SandboxLaunchOutcome> {
    use std::process::{Command, Stdio};

    log::warn!(
        "Falling back to degraded launch (no namespace isolation) for '{}'",
        req.profile.command.first().unwrap_or(&String::new())
    );

    let cgroup_backend_selected = cgroup.map(|c| c.backend_name().to_string());
    let started = Instant::now();

    let wall_limit = req
        .profile
        .wall_time_limit_ms
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_secs(30));

    let mut cmd = Command::new(&req.profile.command[0]);
    if req.profile.command.len() > 1 {
        cmd.args(&req.profile.command[1..]);
    }
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if req.profile.stdin_data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });

    for (key, value) in &req.profile.environment {
        cmd.env(key, value);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| IsolateError::Process(format!("spawn(degraded): {}", e)))?;

    let child_pid = child.id() as i32;

    if let (Some(data), Some(mut stdin)) = (&req.profile.stdin_data, child.stdin.take()) {
        use std::io::Write;
        let _ = stdin.write_all(data.as_bytes());
    }

    // Monitor with wall-time limit.
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if started.elapsed() > wall_limit {
                    timed_out = true;
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(IsolateError::Process(format!("wait(degraded): {}", e))),
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|e| IsolateError::Process(format!("output(degraded): {}", e)));

    let (exit_code, stdout, stderr) = match output {
        Ok(out) => (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        ),
        Err(_) => (None, String::new(), String::new()),
    };

    let status = ProxyStatus {
        payload_pid: Some(child_pid),
        exit_code,
        term_signal: None,
        timed_out,
        wall_time_ms: started.elapsed().as_millis() as u64,
        stdout,
        stderr,
        output_integrity: crate::config::types::OutputIntegrity::Complete,
        internal_error: None,
        reaped_descendants: 0,
    };

    let mut result = status.to_execution_result();
    if timed_out {
        result.status = ExecutionStatus::TimeLimit;
        result.success = false;
    }

    let evidence_collection_errors =
        vec!["degraded_launch: no namespace isolation (non-root)".to_string()];

    let evidence = build_launch_evidence(
        &req,
        false,
        cgroup_backend_selected,
        false,
        timed_out,
        None,
        &status,
        None,
        evidence_collection_errors,
        true,
    );

    Ok(SandboxLaunchOutcome {
        proxy_host_pid: child_pid,
        payload_host_pid: Some(child_pid),
        result,
        evidence,
        kill_report: None,
        proxy_status: status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{IsolateConfig, OutputIntegrity};

    fn test_request(strict_mode: bool) -> SandboxLaunchRequest {
        let mut config = IsolateConfig::default();
        config.instance_id = "evidence-test".to_string();
        config.strict_mode = strict_mode;
        config.enable_pid_namespace = true;
        config.enable_mount_namespace = true;
        config.enable_network_namespace = true;
        config.enable_user_namespace = false;
        config.memory_limit = Some(128 * 1024 * 1024);
        config.process_limit = Some(2);

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

    #[test]
    fn strict_mode_does_not_claim_setup_controls_on_proxy_failure() {
        let req = test_request(true);
        let status = proxy_status(Some("pre-exec failed"));
        let evidence = build_launch_evidence(
            &req,
            true,
            Some("cgroup-v1".to_string()),
            true,
            false,
            None,
            &status,
            None,
            Vec::new(),
            true,
        );

        for control in [
            "pid_namespace",
            "mount_namespace",
            "network_namespace",
            "no_new_privileges",
        ] {
            assert!(
                !evidence.applied_controls.iter().any(|c| c == control),
                "control should not be reported as applied on proxy failure: {}",
                control
            );
            assert!(
                evidence.missing_controls.iter().any(|c| c == control),
                "control should be reported missing on proxy failure: {}",
                control
            );
        }
    }

    #[test]
    fn strict_mode_claims_setup_controls_when_proxy_succeeds() {
        let req = test_request(true);
        let status = proxy_status(None);
        let evidence = build_launch_evidence(
            &req,
            true,
            Some("cgroup-v1".to_string()),
            true,
            false,
            None,
            &status,
            None,
            Vec::new(),
            true,
        );

        for control in [
            "pid_namespace",
            "mount_namespace",
            "network_namespace",
            "no_new_privileges",
        ] {
            assert!(
                evidence.applied_controls.iter().any(|c| c == control),
                "control should be reported as applied on successful proxy setup: {}",
                control
            );
            assert!(
                !evidence.missing_controls.iter().any(|c| c == control),
                "control should not be reported missing on successful proxy setup: {}",
                control
            );
        }
    }
}
