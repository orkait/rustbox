use crate::config::types::{IsolateError, OutputIntegrity, Result};
use crate::core::types::{ProxyStatus, SandboxLaunchRequest};
use crate::exec::preexec::{FreshChild, Sandbox};
use nix::errno::Errno;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{close, dup2, execvp, fork, setpgid, ForkResult, Pid};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::io::RawFd;
use std::thread;
use std::time::Instant;

fn to_isolate_error(prefix: &str, err: impl std::fmt::Display) -> IsolateError {
    IsolateError::Process(format!("{prefix}: {err}"))
}

fn read_json_from_fd<T: DeserializeOwned>(fd: RawFd) -> Result<T> {
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    serde_json::from_slice(&data)
        .map_err(|e| IsolateError::Process(format!("failed to decode json on fd {fd}: {e}")))
}

fn write_json_to_fd<T: Serialize>(fd: RawFd, value: &T) -> Result<()> {
    let mut file = unsafe { File::from_raw_fd(fd) };
    let payload = serde_json::to_vec(value)
        .map_err(|e| IsolateError::Process(format!("failed to encode json for fd {fd}: {e}")))?;
    file.write_all(&payload)?;
    file.flush()?;
    Ok(())
}

pub fn write_request_to_fd(fd: RawFd, req: &SandboxLaunchRequest) -> Result<()> {
    write_json_to_fd(fd, req)
}

pub fn read_proxy_status_from_fd(fd: RawFd) -> Result<ProxyStatus> {
    read_json_from_fd(fd)
}

fn write_proxy_status(fd: RawFd, status: &ProxyStatus) -> Result<()> {
    write_json_to_fd(fd, status)
}

fn read_fd_async(fd: RawFd, limit: usize) -> thread::JoinHandle<(Vec<u8>, OutputIntegrity)> {
    thread::spawn(move || {
        let mut file = unsafe { File::from_raw_fd(fd) };
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        let mut integrity = OutputIntegrity::Complete;

        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if out.len() + n > limit {
                        let remaining = limit.saturating_sub(out.len());
                        if remaining > 0 {
                            out.extend_from_slice(&buf[..remaining]);
                        }
                        integrity = OutputIntegrity::TruncatedByJudgeLimit;
                        break;
                    }
                    out.extend_from_slice(&buf[..n]);
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

        (out, integrity)
    })
}

fn exec_payload_with_typestate(req: &SandboxLaunchRequest) -> Result<()> {
    let sandbox = Sandbox::<FreshChild>::new(req.instance_id.clone(), req.profile.strict_mode);
    let sandbox = sandbox.setup_namespaces(
        false, // proxy is already PID 1 in sandbox pid namespace
        req.profile.enable_mount_namespace,
        req.profile.enable_network_namespace,
        req.profile.enable_user_namespace,
    )?;
    let sandbox = sandbox.harden_mount_propagation()?;
    let sandbox = sandbox.setup_mounts_and_root(&req.profile)?;
    let cgroup_attach = req.cgroup_attach_path.as_ref().and_then(|p| p.to_str());
    let sandbox = sandbox.attach_to_cgroup(cgroup_attach)?;
    let sandbox = sandbox.apply_runtime_hygiene(&req.profile)?;
    let sandbox = sandbox.drop_credentials(req.profile.uid, req.profile.gid)?;
    let sandbox = sandbox.lock_privileges()?;
    let sandbox = if req.profile.enable_syscall_filtering {
        let seccomp_config = crate::kernel::seccomp::SyscallFilterConfig::reference_catalog(
            std::env::consts::ARCH.to_string(),
            "minimal".to_string(),
            format!("ref-{}-minimal-v1", std::env::consts::ARCH),
        );
        sandbox.enable_seccomp(&seccomp_config)?
    } else {
        sandbox.without_seccomp()
    };
    sandbox.exec_payload(&req.profile.command)
}

fn wait_for_payload_and_reap(payload_pid: Pid) -> Result<(Option<i32>, Option<i32>, u32)> {
    let mut payload_exit: Option<i32> = None;
    let mut payload_signal: Option<i32> = None;
    let mut reaped_descendants: u32 = 0;

    loop {
        match waitpid(payload_pid, None) {
            Ok(WaitStatus::Exited(_, code)) => {
                payload_exit = Some(code);
                break;
            }
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                payload_signal = Some(sig as i32);
                break;
            }
            Ok(_) => continue,
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(to_isolate_error("waitpid(payload)", e)),
        }
    }

    loop {
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => break,
            Ok(WaitStatus::Exited(_, _))
            | Ok(WaitStatus::Signaled(_, _, _))
            | Ok(WaitStatus::Stopped(_, _))
            | Ok(WaitStatus::Continued(_))
            | Ok(WaitStatus::PtraceEvent(_, _, _))
            | Ok(WaitStatus::PtraceSyscall(_)) => {
                reaped_descendants += 1;
            }
            Err(Errno::ECHILD) => break,
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(to_isolate_error("waitpid(reap)", e)),
        }
    }

    Ok((payload_exit, payload_signal, reaped_descendants))
}

fn run_proxy(req: SandboxLaunchRequest) -> Result<ProxyStatus> {
    let start = Instant::now();

    let _ = setpgid(Pid::from_raw(0), Pid::from_raw(0));
    crate::exec::preexec::setup_parent_death_signal()?;

    let (stdout_read, stdout_write) = nix::unistd::pipe().map_err(|e| to_isolate_error("pipe(stdout)", e))?;
    let (stderr_read, stderr_write) = nix::unistd::pipe().map_err(|e| to_isolate_error("pipe(stderr)", e))?;
    let (stdin_read, stdin_write) = nix::unistd::pipe().map_err(|e| to_isolate_error("pipe(stdin)", e))?;

    let payload_pid = match unsafe { fork() }.map_err(|e| to_isolate_error("fork(payload)", e))? {
        ForkResult::Child => {
            let _ = close(stdout_read);
            let _ = close(stderr_read);
            let _ = close(stdin_write);

            dup2(stdin_read, libc::STDIN_FILENO).map_err(|e| to_isolate_error("dup2(stdin)", e))?;
            dup2(stdout_write, libc::STDOUT_FILENO).map_err(|e| to_isolate_error("dup2(stdout)", e))?;
            dup2(stderr_write, libc::STDERR_FILENO).map_err(|e| to_isolate_error("dup2(stderr)", e))?;

            let _ = close(stdin_read);
            let _ = close(stdout_write);
            let _ = close(stderr_write);

            if let Err(err) = exec_payload_with_typestate(&req) {
                let _ = writeln!(std::io::stderr(), "proxy payload setup failed: {err}");
                std::process::exit(127);
            }
            std::process::exit(127);
        }
        ForkResult::Parent { child } => child,
    };

    let _ = close(stdin_read);
    let _ = close(stdout_write);
    let _ = close(stderr_write);

    if let Some(data) = &req.profile.stdin_data {
        let mut stdin_writer = unsafe { File::from_raw_fd(stdin_write) };
        let _ = stdin_writer.write_all(data.as_bytes());
        let _ = stdin_writer.flush();
    } else {
        let _ = close(stdin_write);
    }

    let stream_limit = req.profile.file_size_limit.unwrap_or(64 * 1024 * 1024) as usize;
    let stdout_handle = read_fd_async(stdout_read, stream_limit);
    let stderr_handle = read_fd_async(stderr_read, stream_limit);
    let (exit_code, term_signal, reaped_descendants) = wait_for_payload_and_reap(payload_pid)?;
    let (stdout_bytes, stdout_integrity) = stdout_handle
        .join()
        .unwrap_or_else(|_| (Vec::new(), OutputIntegrity::WriteError));
    let (stderr_bytes, stderr_integrity) = stderr_handle
        .join()
        .unwrap_or_else(|_| (Vec::new(), OutputIntegrity::WriteError));

    let output_integrity = if matches!(stdout_integrity, OutputIntegrity::WriteError)
        || matches!(stderr_integrity, OutputIntegrity::WriteError)
    {
        OutputIntegrity::WriteError
    } else if matches!(stdout_integrity, OutputIntegrity::CrashMidWrite)
        || matches!(stderr_integrity, OutputIntegrity::CrashMidWrite)
    {
        OutputIntegrity::CrashMidWrite
    } else if matches!(stdout_integrity, OutputIntegrity::TruncatedByJudgeLimit)
        || matches!(stderr_integrity, OutputIntegrity::TruncatedByJudgeLimit)
    {
        OutputIntegrity::TruncatedByJudgeLimit
    } else if matches!(stdout_integrity, OutputIntegrity::TruncatedByProgramClose)
        || matches!(stderr_integrity, OutputIntegrity::TruncatedByProgramClose)
    {
        OutputIntegrity::TruncatedByProgramClose
    } else {
        OutputIntegrity::Complete
    };

    let stdout = String::from_utf8_lossy(&stdout_bytes).to_string();
    let stderr = String::from_utf8_lossy(&stderr_bytes).to_string();

    Ok(ProxyStatus {
        payload_pid: Some(payload_pid.as_raw()),
        exit_code,
        term_signal,
        timed_out: false,
        wall_time_ms: start.elapsed().as_millis() as u64,
        stdout,
        stderr,
        output_integrity,
        internal_error: None,
        reaped_descendants,
    })
}

/// Child entrypoint executed by clone()-created proxy process.
pub fn run_proxy_main_from_fds(launch_fd: RawFd, status_fd: RawFd) -> ! {
    let outcome = match read_json_from_fd::<SandboxLaunchRequest>(launch_fd).and_then(run_proxy) {
        Ok(status) => status,
        Err(err) => ProxyStatus {
            internal_error: Some(err.to_string()),
            stderr: err.to_string(),
            exit_code: None,
            term_signal: None,
            ..ProxyStatus::default()
        },
    };

    let _ = write_proxy_status(status_fd, &outcome);
    let code = outcome.exit_code.unwrap_or_else(|| if outcome.internal_error.is_some() { 126 } else { 0 });
    std::process::exit(code);
}

/// Optional CLI path: run proxy role by explicit fds.
pub fn run_proxy_role(launch_fd: i32, status_fd: i32) -> Result<()> {
    run_proxy_main_from_fds(launch_fd, status_fd)
}

/// Execute a command using execvp from an argv vector.
pub fn exec_argv(argv: &[String]) -> Result<()> {
    if argv.is_empty() {
        return Err(IsolateError::Config("empty argv for exec".to_string()));
    }
    let mut cargv = Vec::with_capacity(argv.len());
    for arg in argv {
        let c = CString::new(arg.as_str())
            .map_err(|_| IsolateError::Config("command contains NUL byte".to_string()))?;
        cargv.push(c);
    }
    let refs: Vec<&std::ffi::CStr> = cargv.iter().map(|s| s.as_c_str()).collect();
    execvp(cargv[0].as_c_str(), &refs).map_err(|e| to_isolate_error("execvp", e))?;
    Ok(())
}
