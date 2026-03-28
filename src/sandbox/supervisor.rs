use crate::config::constants;
use crate::config::types::{ExecutionStatus, IsolateError, Result};
use crate::kernel::cgroup::CgroupBackend;
use crate::sandbox::evidence::{build_launch_evidence, LaunchEvidenceParams};
use crate::sandbox::proxy::{
    read_proxy_status_from_fd, run_proxy_main_from_fds, write_request_to_fd,
};
use crate::sandbox::types::{KillReport, ProxyStatus, SandboxLaunchOutcome, SandboxLaunchRequest};
use nix::sched::{clone, CloneFlags};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{close, pipe, Pid};
use std::time::{Duration, Instant};

fn send_signal_with_fallback(pid: Pid, sig: i32, report: &mut KillReport, label: &str) {
    // SAFETY: kill(2) with negative pid sends signal to the process group. Falls back to
    // individual pid if group signal fails (e.g., process not a group leader).
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

    std::thread::sleep(constants::runtime_tuning().sigterm_grace);

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

    let (launch_read, launch_write) =
        pipe().map_err(|e| IsolateError::process("pipe(launch)", e))?;
    let (status_read, status_write) =
        pipe().map_err(|e| IsolateError::process("pipe(status)", e))?;

    let pipe_buf = req
        .profile
        .pipe_buffer_size
        .unwrap_or(constants::DEFAULT_PIPE_BUFFER_SIZE)
        .min(libc::c_int::MAX as u64) as libc::c_int;
    for fd in [launch_write, status_write] {
        unsafe {
            libc::fcntl(fd, libc::F_SETPIPE_SZ, pipe_buf);
        }
    }

    let mut clone_flags = CloneFlags::empty();
    if req.profile.enable_pid_namespace {
        clone_flags |= CloneFlags::CLONE_NEWPID;
    }
    clone_flags |= CloneFlags::CLONE_NEWIPC | CloneFlags::CLONE_NEWUTS;
    if req.profile.enable_mount_namespace {
        clone_flags |= CloneFlags::CLONE_NEWNS;
    }
    if req.profile.enable_network_namespace {
        clone_flags |= CloneFlags::CLONE_NEWNET;
    }
    if req.profile.enable_user_namespace {
        clone_flags |= CloneFlags::CLONE_NEWUSER;
    }

    let mut child_stack = vec![0u8; constants::CLONE_STACK_SIZE];
    let child_cb: Box<dyn FnMut() -> isize> = Box::new(move || {
        let _ = close(launch_write);
        let _ = close(status_read);
        run_proxy_main_from_fds(launch_read, status_write)
    });

    // SAFETY: clone(2) with namespace flags creates a child process in new namespaces.
    // - child_cb is a boxed closure moved into the child's COW address space (no CLONE_VM).
    // - child_stack is a 2MB heap buffer whose top is passed as the child's initial stack pointer.
    // - SIGCHLD ensures the parent receives notification when the child exits.
    // - The parent retains no references into child_cb or child_stack after clone returns;
    //   the child operates on its own COW copy.
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
        Err(e) => {
            close_all_pipes(launch_read, launch_write, status_read, status_write);
            return Err(IsolateError::Privilege(format!(
                "Root privileges required for namespace isolation: {}",
                e
            )));
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

    // The supervisor's kill timeout includes a setup budget on top of the wall limit.
    // Proxy setup (namespaces, mounts, chroot, creds, caps, seccomp) takes time that
    // should NOT count against the user's wall time. The proxy reports its own wall
    // time starting from after fork(), so the reported time is accurate regardless.
    let wall_limit = req
        .profile
        .wall_time_limit_ms
        .map(Duration::from_millis)
        .unwrap_or(constants::DEFAULT_SUPERVISOR_WALL_FALLBACK);
    let kill_timeout = wall_limit + constants::SUPERVISOR_SETUP_BUDGET;
    let started = Instant::now();

    let mut timed_out = false;
    let mut cpu_timed_out = false;
    let mut interrupted_by_signal = false;
    let mut interrupt_signal = None;
    let mut kill_report: Option<KillReport> = None;
    let mut proxy_exit_code = None;
    let mut proxy_signal = None;

    let cpu_limit_usec: Option<u64> = req
        .profile
        .cpu_time_limit_ms
        .map(|ms| ms * constants::USEC_PER_MS);

    let status_reader = std::thread::spawn(move || read_proxy_status_from_fd(status_read));

    loop {
        match waitpid(proxy_pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                if !crate::kernel::signal::should_continue() {
                    interrupted_by_signal = true;
                    interrupt_signal = Some(crate::kernel::signal::received_signal());
                    kill_report = Some(terminate_proxy_group(proxy_pid));
                } else if started.elapsed() > kill_timeout {
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
                        std::thread::sleep(constants::SUPERVISOR_POLL_INTERVAL);
                    }
                } else if !interrupted_by_signal {
                    std::thread::sleep(constants::SUPERVISOR_POLL_INTERVAL);
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
                return Err(IsolateError::process("waitpid(proxy)", e));
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
                return Err(IsolateError::process("waitpid(proxy-interrupt)", e));
            }
        }
    }

    let status_result = status_reader.join().unwrap_or_else(|_| {
        Err(IsolateError::Process(
            "status reader thread panicked".into(),
        ))
    });
    let mut status = status_result.unwrap_or_else(|e| ProxyStatus {
        exit_code: proxy_exit_code,
        term_signal: proxy_signal,
        timed_out: false,
        wall_time_ms: started.elapsed().as_millis() as u64,
        stdout: String::new(),
        stderr: String::new(),
        output_integrity: crate::config::types::OutputIntegrity::WriteError,
        internal_error: Some(e.to_string()),
        payload_pid: None,
        reaped_descendants: 0,
    });
    let sig_code = interrupt_signal.unwrap_or(0) as i32;
    // Proxy has its own wall timer (starts after fork, kills payload on timeout).
    // If proxy reports timed_out=true, it's a real TLE.
    // If supervisor's kill_timeout fires but proxy didn't report timeout,
    // sandbox setup hung - report as InternalError, not TLE.
    let proxy_reported_timeout = status.timed_out;
    let supervisor_safety_timeout = timed_out && !proxy_reported_timeout && !cpu_timed_out;

    if supervisor_safety_timeout {
        status.timed_out = false;
        status.internal_error =
            Some("sandbox setup exceeded safety timeout (proxy did not respond)".to_string());
    }
    if interrupted_by_signal {
        status.timed_out = false;
        status.term_signal = Some(sig_code);
        status.internal_error = Some(format!("interrupted_by_signal:{sig_code}"));
    }

    let mut result = status.to_execution_result();
    if proxy_reported_timeout || cpu_timed_out {
        result.status = ExecutionStatus::TimeLimit;
        result.success = false;
    } else if supervisor_safety_timeout {
        result.status = ExecutionStatus::InternalError;
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
                result.cpu_time = cpu_usec as f64 / constants::USEC_PER_SEC;
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

#[cfg(test)]
mod tests {
    use crate::config::types::{ExecutionStatus, OutputIntegrity};
    use crate::sandbox::types::ProxyStatus;

    #[test]
    fn proxy_reported_timeout_produces_tle() {
        let status = ProxyStatus {
            timed_out: true,
            exit_code: None,
            term_signal: Some(9),
            wall_time_ms: 10500,
            internal_error: None,
            ..ProxyStatus::default()
        };
        let result = status.to_execution_result();
        assert_eq!(result.status, ExecutionStatus::TimeLimit);
    }

    #[test]
    fn supervisor_safety_timeout_without_proxy_timeout_is_not_tle() {
        let status = ProxyStatus {
            timed_out: false,
            exit_code: None,
            term_signal: None,
            wall_time_ms: 13000,
            internal_error: Some(
                "sandbox setup exceeded safety timeout (proxy did not respond)".to_string(),
            ),
            ..ProxyStatus::default()
        };
        let result = status.to_execution_result();
        assert_eq!(
            result.status,
            ExecutionStatus::InternalError,
            "safety timeout without proxy-reported timeout must be IE, not TLE"
        );
    }

    #[test]
    fn signal_interrupt_produces_signaled_status() {
        let status = ProxyStatus {
            timed_out: false,
            exit_code: None,
            term_signal: Some(15),
            wall_time_ms: 500,
            internal_error: Some("interrupted_by_signal:15".to_string()),
            ..ProxyStatus::default()
        };
        let result = status.to_execution_result();
        assert_eq!(result.status, ExecutionStatus::Signaled);
        assert_eq!(result.signal, Some(15));
    }

    #[test]
    fn clean_exit_zero_is_ok() {
        let status = ProxyStatus {
            exit_code: Some(0),
            wall_time_ms: 100,
            output_integrity: OutputIntegrity::Complete,
            ..ProxyStatus::default()
        };
        let result = status.to_execution_result();
        assert_eq!(result.status, ExecutionStatus::Ok);
        assert!(result.success);
    }
}
