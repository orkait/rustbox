use crate::config::constants;
use crate::config::types::{ExecutionStatus, IsolateError, OutputIntegrity, Result};
use crate::kernel::cgroup::CgroupBackend;
use crate::sandbox::evidence::{build_launch_evidence, LaunchEvidenceParams};
use crate::sandbox::types::{KillReport, ProxyStatus, SandboxLaunchOutcome, SandboxLaunchRequest};
use std::io::{Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

pub fn launch_with_supervisor(
    req: SandboxLaunchRequest,
    cgroup: Option<&dyn CgroupBackend>,
) -> Result<SandboxLaunchOutcome> {
    // Phase 1: Validate
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

    // Phase 2: Spawn proxy
    let mut clone_flags: libc::c_int = libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;
    if req.profile.enable_pid_namespace {
        clone_flags |= libc::CLONE_NEWPID;
    }
    if req.profile.enable_mount_namespace {
        clone_flags |= libc::CLONE_NEWNS;
    }
    if req.profile.enable_network_namespace {
        clone_flags |= libc::CLONE_NEWNET;
    }
    if req.profile.enable_user_namespace {
        clone_flags |= libc::CLONE_NEWUSER;
    }

    let exe =
        std::env::current_exe().map_err(|e| IsolateError::Process(format!("current_exe: {e}")))?;

    let mut child = unsafe {
        Command::new(&exe)
            .arg(format!(
                "{}={}",
                constants::INTERNAL_ROLE_ARG,
                constants::INTERNAL_ROLE_PROXY
            ))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .pre_exec(move || {
                if libc::unshare(clone_flags) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            })
            .spawn()
            .map_err(|e| IsolateError::Process(format!("spawn proxy: {e}")))?
    };

    let proxy_pid = child.id() as i32;

    // Phase 3: Cgroup
    let cgroup_backend_selected = cgroup.map(|c| c.backend_name().to_string());
    let mut cgroup_enforced = false;
    let mut evidence_collection_errors = Vec::new();

    if let Some(controller) = cgroup {
        match controller.attach_process(&req.instance_id, proxy_pid as u32) {
            Ok(()) => cgroup_enforced = true,
            Err(e) => try_cgroup_op(
                Err(e),
                req.profile.strict_mode,
                &mut child,
                &mut evidence_collection_errors,
                "cgroup_attach",
            )?,
        }

        if let Some(limit) = req.profile.memory_limit {
            try_cgroup_op(
                controller.set_memory_limit(&req.instance_id, limit),
                req.profile.strict_mode,
                &mut child,
                &mut evidence_collection_errors,
                "cgroup_memory",
            )?;
        }
        if let Some(limit) = req.profile.process_limit {
            try_cgroup_op(
                controller.set_process_limit(&req.instance_id, limit),
                req.profile.strict_mode,
                &mut child,
                &mut evidence_collection_errors,
                "cgroup_pids",
            )?;
        }
        if let Some(limit_ms) = req.profile.cpu_time_limit_ms {
            let usec = (limit_ms as u64) * constants::USEC_PER_MS;
            try_cgroup_op(
                controller.set_cpu_limit(&req.instance_id, usec),
                req.profile.strict_mode,
                &mut child,
                &mut evidence_collection_errors,
                "cgroup_cpu",
            )?;
        }
    }

    // Phase 4: Send request
    let json_req = serde_json::to_vec(&req)
        .map_err(|e| IsolateError::Process(format!("encode request: {e}")))?;

    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| IsolateError::Process("child stdin not available".to_string()))?;
        if let Err(e) = stdin.write_all(&json_req) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(IsolateError::Process(format!("write proxy stdin: {e}")));
        }
    }

    // Phase 5: Capture output (2 reader threads)
    let output_limit = req
        .profile
        .output_limit
        .unwrap_or(constants::DEFAULT_OUTPUT_COMBINED_LIMIT as u64) as usize;

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let stdout_thread = std::thread::spawn(move || read_stream(stdout_pipe, output_limit));
    let stderr_thread = std::thread::spawn(move || read_stream(stderr_pipe, output_limit));

    // Phase 6: Wait with wall timeout
    let start = Instant::now();
    let wall_limit = req
        .profile
        .wall_time_limit_ms
        .map(|ms| Duration::from_millis(ms as u64))
        .unwrap_or(constants::DEFAULT_SUPERVISOR_WALL_FALLBACK);

    let (exit_status, timed_out) = wait_with_wall_timeout(&mut child, proxy_pid, wall_limit);

    let wall_time_ms = start.elapsed().as_millis() as u64;

    // Phase 7: Collect (post-mortem)
    let (stdout_bytes, stdout_integrity) = stdout_thread
        .join()
        .unwrap_or_else(|_| (Vec::new(), OutputIntegrity::WriteError));
    let (stderr_bytes, stderr_integrity) = stderr_thread
        .join()
        .unwrap_or_else(|_| (Vec::new(), OutputIntegrity::WriteError));

    let mut cgroup_evidence = None;
    if cgroup_enforced {
        if let Some(controller) = cgroup {
            match controller.collect_evidence(&req.instance_id) {
                Ok(ev) => cgroup_evidence = Some(ev),
                Err(e) => evidence_collection_errors.push(format!("cgroup_evidence: {e}")),
            }
        }
    }

    // Phase 8: Build outcome
    let (exit_code, term_signal) = match &exit_status {
        Some(s) => (s.code(), s.signal()),
        None => (None, None),
    };

    let output_integrity = OutputIntegrity::resolve_combined(&stdout_integrity, &stderr_integrity);

    let kill_report = if timed_out {
        Some(KillReport {
            term_sent: false,
            kill_sent: true,
            waited_ms: wall_time_ms,
            notes: vec!["wall_time_limit_exceeded".to_string()],
        })
    } else {
        None
    };

    let proxy_status = ProxyStatus {
        payload_pid: None,
        exit_code,
        term_signal,
        timed_out,
        wall_time_ms,
        stdout: vec_to_string_lossy(stdout_bytes),
        stderr: vec_to_string_lossy(stderr_bytes),
        output_integrity,
        internal_error: None,
        reaped_descendants: 0,
    };

    let mut result = proxy_status.to_execution_result();

    if cgroup_enforced {
        if let Some(controller) = cgroup {
            if let Ok(cpu_usec) = controller.get_cpu_usage() {
                result.cpu_time = cpu_usec as f64 / constants::USEC_PER_SEC;
            }
            if let Ok(mem_peak) = controller.get_memory_peak() {
                result.memory_peak = mem_peak;
            }
            if let Ok(true) = controller.check_oom() {
                result.status = ExecutionStatus::MemoryLimit;
                result.success = false;
            }
        }
    }

    if timed_out {
        result.status = ExecutionStatus::TimeLimit;
        result.success = false;
    }

    let evidence = build_launch_evidence(
        &req,
        LaunchEvidenceParams {
            running_as_root: unsafe { libc::geteuid() } == 0,
            cgroup_backend_selected,
            cgroup_enforced,
            timed_out,
            kill_report: kill_report.as_ref(),
            proxy_status: &proxy_status,
            cgroup_evidence,
            evidence_collection_errors,
            cleanup_verified: true,
        },
    );

    Ok(SandboxLaunchOutcome {
        proxy_host_pid: proxy_pid,
        payload_host_pid: proxy_status.payload_pid,
        result,
        evidence,
        kill_report,
        proxy_status,
    })
}

fn try_cgroup_op(
    result: Result<()>,
    strict: bool,
    child: &mut Child,
    errors: &mut Vec<String>,
    label: &str,
) -> Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(e) if strict => {
            let _ = child.kill();
            let _ = child.wait();
            Err(e)
        }
        Err(e) => {
            errors.push(format!("{label}: {e}"));
            Ok(())
        }
    }
}

fn wait_with_wall_timeout(
    child: &mut Child,
    proxy_pid: i32,
    wall_limit: Duration,
) -> (Option<ExitStatus>, bool) {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return (Some(status), false),
            Ok(None) => {
                if start.elapsed() >= wall_limit {
                    unsafe { libc::kill(-proxy_pid, libc::SIGKILL) };
                    let _ = child.kill();
                    let status = child.wait().ok();
                    return (status, true);
                }
                std::thread::sleep(constants::SUPERVISOR_POLL_INTERVAL);
            }
            Err(_) => return (None, false),
        }
    }
}

fn read_stream(pipe: Option<impl Read>, limit: usize) -> (Vec<u8>, OutputIntegrity) {
    let Some(mut reader) = pipe else {
        return (Vec::new(), OutputIntegrity::WriteError);
    };
    let mut buf = Vec::with_capacity(constants::DEFAULT_IO_BUFFER_SIZE);
    let mut tmp = [0u8; constants::READ_BUFFER_SIZE];
    let mut integrity = OutputIntegrity::Complete;

    loop {
        match reader.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() + n > limit {
                    let remaining = limit.saturating_sub(buf.len());
                    if remaining > 0 {
                        buf.extend_from_slice(&tmp[..remaining]);
                    }
                    integrity = OutputIntegrity::TruncatedByJudgeLimit;
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            Err(e) => {
                integrity = if e.kind() == std::io::ErrorKind::BrokenPipe {
                    OutputIntegrity::TruncatedByProgramClose
                } else {
                    OutputIntegrity::WriteError
                };
                break;
            }
        }
    }
    (buf, integrity)
}

fn vec_to_string_lossy(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

#[cfg(test)]
mod tests {
    use crate::config::types::{ExecutionStatus, OutputIntegrity};
    use crate::sandbox::types::ProxyStatus;

    #[test]
    fn proxy_timeout_produces_tle() {
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

    #[test]
    fn signal_produces_signaled_status() {
        let status = ProxyStatus {
            exit_code: None,
            term_signal: Some(11),
            wall_time_ms: 50,
            ..ProxyStatus::default()
        };
        let result = status.to_execution_result();
        assert_eq!(result.status, ExecutionStatus::Signaled);
        assert_eq!(result.signal, Some(11));
    }
}
