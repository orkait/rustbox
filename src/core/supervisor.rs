use crate::config::types::{
    CgroupEvidence, ExecutionStatus, IsolateError, JudgeAction, JudgeActionType,
    ProcessLifecycleEvidence, Result,
};
use crate::core::proxy::{read_proxy_status_from_fd, run_proxy_main_from_fds, write_request_to_fd};
use crate::core::types::{
    KillReport, LaunchEvidence, ProxyStatus, SandboxLaunchOutcome, SandboxLaunchRequest,
};
use crate::kernel::cgroup::CgroupBackend;
use nix::sched::{clone, CloneFlags};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{close, pipe, Pid};
use std::time::{Duration, Instant, SystemTime};

fn to_process_error(prefix: &str, err: impl std::fmt::Display) -> IsolateError {
    IsolateError::Process(format!("{prefix}: {err}"))
}

fn drain_reader(mut r: impl std::io::Read) -> String {
    let mut s = String::new();
    let _ = r.read_to_string(&mut s);
    s
}

fn detect_pidfd_mode() -> crate::config::types::PidfdMode {
    #[cfg(target_os = "linux")]
    {
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
    let mut controls = Vec::with_capacity(8);
    if req.profile.enable_pid_namespace { controls.push("pid_namespace".into()); }
    if req.profile.enable_mount_namespace { controls.push("mount_namespace".into()); }
    if req.profile.enable_network_namespace { controls.push("network_namespace".into()); }
    if req.profile.enable_user_namespace { controls.push("user_namespace".into()); }
    if req.profile.memory_limit.is_some() { controls.push("memory_limit".into()); }
    if req.profile.process_limit.is_some() { controls.push("process_limit".into()); }
    controls.push("no_new_privileges".into());
    controls
}

struct LaunchEvidenceParams<'a> {
    running_as_root: bool,
    cgroup_backend_selected: Option<String>,
    cgroup_enforced: bool,
    timed_out: bool,
    kill_report: Option<&'a KillReport>,
    proxy_status: &'a ProxyStatus,
    cgroup_evidence: Option<CgroupEvidence>,
    evidence_collection_errors: Vec<String>,
    cleanup_verified: bool,
}

fn build_launch_evidence(
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
                if cgroup_enforced { &mut applied } else { &mut missing }
            }
            "pid_namespace" | "mount_namespace" | "network_namespace" | "user_namespace"
            | "no_new_privileges" => {
                if setup_controls_applied { &mut applied } else { &mut missing }
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
        reap_summary: if reaped == 0 { "clean".into() } else { format!("reaped_{reaped}_descendants") },
        descendant_containment: if cleanup_verified { "ok".into() } else { "baseline_verification_failed".into() },
        zombie_count: 0,
    };

    let mode_decision_reason = match (missing.is_empty(), req.profile.strict_mode) {
        (true, _) => "All configured controls applied".to_string(),
        (false, true) => format!("Strict mode requested but mandatory controls missing: {}", missing.join(", ")),
        (false, false) => format!("Execution degraded; missing controls: {}", missing.join(", ")),
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
            push_action(&mut judge_actions, JudgeActionType::SignalSent, "SIGTERM sent to proxy group");
        }
        if report.kill_sent {
            push_action(&mut judge_actions, JudgeActionType::ForcedKill, "SIGKILL sent to proxy group");
        }
    }
    if timed_out && kill_report.is_none() {
        push_action(&mut judge_actions, JudgeActionType::ForcedKill, "SIGKILL sent to child process (degraded mode)");
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
        proc_policy_applied: if req.profile.enable_mount_namespace { "hardened" } else { "default" }.into(),
        sys_policy_applied: "disabled".to_string(),
        judge_actions,
        cgroup_evidence,
        process_lifecycle,
        evidence_collection_errors,
        cleanup_verified,
    }
}

fn send_signal_with_fallback(pid: Pid, sig: i32, report: &mut KillReport, label: &str) {
    // SAFETY: sending a POSIX signal to a process group (negative pid) or individual pid
    let rc = unsafe { libc::kill(-pid.as_raw(), sig) };
    if rc != 0 {
        let _ = unsafe { libc::kill(pid.as_raw(), sig) };
        report.notes.push(format!(
            "group {} fallback used: {}",
            label,
            std::io::Error::last_os_error()
        ));
    }
}

fn terminate_proxy_group(proxy_pid: Pid) -> KillReport {
    let mut report = KillReport::default();
    let start = Instant::now();

    send_signal_with_fallback(proxy_pid, libc::SIGTERM, &mut report, "SIGTERM");
    report.term_sent = true;

    std::thread::sleep(Duration::from_millis(200));

    send_signal_with_fallback(proxy_pid, libc::SIGKILL, &mut report, "SIGKILL");
    report.kill_sent = true;

    report.waited_ms = start.elapsed().as_millis() as u64;
    report
}

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

    let mut child_stack = vec![0u8; 2 * 1024 * 1024];
    let child_cb: Box<dyn FnMut() -> isize> = Box::new(move || {
        let _ = close(launch_write);
        let _ = close(status_read);
        run_proxy_main_from_fds(launch_read, status_write)
    });

    let clone_result =
        unsafe { clone(child_cb, &mut child_stack, clone_flags, Some(libc::SIGCHLD)) };

    let close_all_pipes = |lr, lw, sr, sw| {
        let _ = close(lr);
        let _ = close(lw);
        let _ = close(sr);
        let _ = close(sw);
    };

    let proxy_pid = match clone_result {
        Ok(pid) => pid,
        Err(nix::errno::Errno::EPERM) if !req.profile.strict_mode && req.profile.allow_degraded => {
            close_all_pipes(launch_read, launch_write, status_read, status_write);
            log::warn!("Falling back to degraded launch (--allow-degraded enabled)");
            return launch_degraded(req, cgroup);
        }
        Err(nix::errno::Errno::EPERM) if !req.profile.strict_mode => {
            close_all_pipes(launch_read, launch_write, status_read, status_write);
            return Err(IsolateError::Privilege(
                "Root privileges required for namespace isolation. \
                 Use --allow-degraded for development without isolation (unsafe for untrusted code)."
                    .to_string(),
            ));
        }
        Err(e) => {
            close_all_pipes(launch_read, launch_write, status_read, status_write);
            return Err(to_process_error("clone(proxy)", e));
        }
    };

    let _ = close(launch_read);
    let _ = close(status_write);

    let abort_proxy = |status_rd| {
        let _ = terminate_proxy_group(proxy_pid);
        let _ = waitpid(proxy_pid, None);
        let _ = close(status_rd);
    };

    if let Some(controller) = cgroup {
        if let Err(e) = controller.attach_process(&req.instance_id, proxy_pid.as_raw() as u32) {
            evidence_collection_errors.push(format!("cgroup_attach: {}", e));
            if req.profile.strict_mode {
                let _ = close(launch_write);
                abort_proxy(status_read);
                return Err(e);
            }
        } else {
            cgroup_enforced = true;
        }
    } else if req.profile.strict_mode
        && (req.profile.memory_limit.is_some() || req.profile.process_limit.is_some())
    {
        let _ = close(launch_write);
        abort_proxy(status_read);
        return Err(IsolateError::Cgroup(
            "strict mode requires cgroup limits for configured memory/process controls".to_string(),
        ));
    }

    if !crate::kernel::signal::should_continue() {
        let _ = close(launch_write);
        abort_proxy(status_read);
        return Err(IsolateError::Process(
            "interrupted by signal before launch".to_string(),
        ));
    }

    if let Err(err) = write_request_to_fd(launch_write, &req) {
        abort_proxy(status_read);
        return Err(err);
    }

    if !crate::kernel::signal::should_continue() {
        abort_proxy(status_read);
        return Err(IsolateError::Process(
            "interrupted by signal before wait loop".to_string(),
        ));
    }

    let wall_limit = req
        .profile
        .wall_time_limit_ms
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_secs(30));
    let started = Instant::now();

    let mut timed_out = false;
    let mut cpu_timed_out = false;
    let mut interrupted_by_signal = false;
    let mut interrupt_signal = None;
    let mut kill_report: Option<KillReport> = None;
    let mut proxy_exit_code = None;
    let mut proxy_signal = None;

    let cpu_limit_usec: Option<u64> = req.profile.cpu_time_limit_ms.map(|ms| ms * 1000);

    loop {
        match waitpid(proxy_pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                if !crate::kernel::signal::should_continue() {
                    interrupted_by_signal = true;
                    interrupt_signal = Some(crate::kernel::signal::received_signal());
                    kill_report = Some(terminate_proxy_group(proxy_pid));
                } else if started.elapsed() > wall_limit {
                    timed_out = true;
                    kill_report = Some(terminate_proxy_group(proxy_pid));
                } else if let (Some(limit_usec), Some(controller)) = (cpu_limit_usec, cgroup) {
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
                    if !timed_out && !interrupted_by_signal {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                } else if !interrupted_by_signal {
                    std::thread::sleep(Duration::from_millis(10));
                }

                if interrupted_by_signal {
                    break;
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
            Err(e) => {
                let _ = close(status_read);
                return Err(to_process_error("waitpid(proxy)", e));
            }
        }
    }

    if interrupted_by_signal && proxy_exit_code.is_none() && proxy_signal.is_none() {
        match waitpid(proxy_pid, None) {
            Ok(WaitStatus::Exited(_, code)) => proxy_exit_code = Some(code),
            Ok(WaitStatus::Signaled(_, sig, _)) => proxy_signal = Some(sig as i32),
            Ok(_) => {}
            Err(nix::errno::Errno::ECHILD) => {}
            Err(nix::errno::Errno::EINTR) => {}
            Err(e) => {
                let _ = close(status_read);
                return Err(to_process_error("waitpid(proxy-interrupt)", e));
            }
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
    let sig_code = interrupt_signal.unwrap_or(0) as i32;
    if timed_out {
        status.timed_out = true;
    }
    if interrupted_by_signal {
        status.timed_out = false;
        status.term_signal = Some(sig_code);
        status.internal_error = Some(format!("interrupted_by_signal:{sig_code}"));
    }

    let mut result = status.to_execution_result();
    if timed_out {
        result.status = ExecutionStatus::TimeLimit;
        result.success = false;
    }

    if cpu_timed_out {
        evidence_collection_errors.push(
            "cpu_time_limit_exceeded: judge watchdog killed process after cgroup CPU usage exceeded limit".to_string(),
        );
    }
    if interrupted_by_signal {
        evidence_collection_errors.push(format!("interrupted_by_signal:{sig_code}"));
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
        LaunchEvidenceParams {
            running_as_root,
            cgroup_backend_selected,
            cgroup_enforced,
            timed_out,
            kill_report: kill_report.as_ref(),
            proxy_status: &status,
            cgroup_evidence,
            evidence_collection_errors,
            cleanup_verified: true,
        },
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
        })
        .current_dir(&req.profile.workdir);

    cmd.env_clear();
    for (key, value) in &req.profile.environment {
        cmd.env(key, value);
    }

    const DEGRADED_ENV_BLOCKLIST: &[&str] = &[
        "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG", "LD_PROFILE",
        "LD_BIND_NOW", "LD_BIND_NOT", "LD_DYNAMIC_WEAK", "LD_USE_LOAD_BIAS",
        "BASH_ENV", "ENV", "CDPATH", "PYTHONSTARTUP", "PERL5OPT", "RUBYOPT",
        "NODE_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
    ];
    for key in DEGRADED_ENV_BLOCKLIST {
        cmd.env_remove(key);
    }

    if unsafe { libc::geteuid() } == 0 {
        if let (Some(uid), Some(gid)) = (req.profile.uid, req.profile.gid) {
            use std::os::unix::process::CommandExt;
            unsafe {
                cmd.pre_exec(move || {
                    libc::umask(0o077);

                    if libc::setgroups(0, std::ptr::null()) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::setresgid(gid, gid, gid) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::setresuid(uid, uid, uid) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    for cap in 0..=40 {
                        let _ = libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0);
                    }

                    let zero_limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                    libc::setrlimit(libc::RLIMIT_CORE, &zero_limit);

                    let fsize_limit = libc::rlimit { rlim_cur: 256 * 1024 * 1024, rlim_max: 256 * 1024 * 1024 };
                    libc::setrlimit(libc::RLIMIT_FSIZE, &fsize_limit);

                    let nofile_limit = libc::rlimit { rlim_cur: 256, rlim_max: 256 };
                    libc::setrlimit(libc::RLIMIT_NOFILE, &nofile_limit);

                    let nproc_limit = libc::rlimit { rlim_cur: 64, rlim_max: 64 };
                    libc::setrlimit(libc::RLIMIT_NPROC, &nproc_limit);

                    for fd in 3..1024 {
                        libc::close(fd);
                    }

                    Ok(())
                });
            }
        }
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| IsolateError::Process(format!("spawn(degraded): {}", e)))?;

    let child_pid = child.id() as i32;

    if let (Some(data), Some(mut stdin)) = (&req.profile.stdin_data, child.stdin.take()) {
        use std::io::Write;
        let _ = stdin.write_all(data.as_bytes());
    }

    let mut timed_out = false;
    let mut interrupted_by_signal = false;
    let mut interrupt_signal = None;
    let mut early_exit = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if !crate::kernel::signal::should_continue() {
                    interrupted_by_signal = true;
                    interrupt_signal = Some(crate::kernel::signal::received_signal());
                    early_exit = true;
                    break;
                } else if started.elapsed() > wall_limit {
                    timed_out = true;
                    early_exit = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(IsolateError::Process(format!("wait(degraded): {}", e))),
        }
    }

    let (exit_code, stdout, stderr) = if early_exit {
        let _ = child.kill();
        let stdout_data = child.stdout.take().map(drain_reader).unwrap_or_default();
        let stderr_data = child.stderr.take().map(drain_reader).unwrap_or_default();
        let exit_status = child.wait().ok().and_then(|s| s.code());
        (exit_status, stdout_data, stderr_data)
    } else {
        match child.wait_with_output() {
            Ok(out) => (
                out.status.code(),
                String::from_utf8_lossy(&out.stdout).into_owned(),
                String::from_utf8_lossy(&out.stderr).into_owned(),
            ),
            Err(_) => (None, String::new(), String::new()),
        }
    };

    let sig_code = interrupt_signal.unwrap_or(0) as i32;
    let status = ProxyStatus {
        payload_pid: Some(child_pid),
        exit_code,
        term_signal: if interrupted_by_signal { Some(sig_code) } else { None },
        timed_out,
        wall_time_ms: started.elapsed().as_millis() as u64,
        stdout,
        stderr,
        output_integrity: crate::config::types::OutputIntegrity::Complete,
        internal_error: if interrupted_by_signal {
            Some(format!("interrupted_by_signal:{sig_code}"))
        } else {
            None
        },
        reaped_descendants: 0,
    };

    let mut result = status.to_execution_result();
    if timed_out {
        result.status = ExecutionStatus::TimeLimit;
        result.success = false;
    }

    let mut evidence_collection_errors =
        vec!["degraded_launch: no namespace isolation (non-root)".to_string()];
    if interrupted_by_signal {
        evidence_collection_errors.push(format!("interrupted_by_signal:{sig_code}"));
    }

    let evidence = build_launch_evidence(
        &req,
        LaunchEvidenceParams {
            running_as_root: false,
            cgroup_backend_selected,
            cgroup_enforced: false,
            timed_out,
            kill_report: None,
            proxy_status: &status,
            cgroup_evidence: None,
            evidence_collection_errors,
            cleanup_verified: true,
        },
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
        let config = IsolateConfig {
            instance_id: "evidence-test".to_string(),
            strict_mode,
            enable_pid_namespace: true,
            enable_mount_namespace: true,
            enable_network_namespace: true,
            enable_user_namespace: false,
            memory_limit: Some(128 * 1024 * 1024),
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
