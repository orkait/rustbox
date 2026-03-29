use crate::config::constants;
use crate::config::types::{IsolateError, Result};
use crate::sandbox::types::SandboxLaunchRequest;
use nix::errno::Errno;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{close, dup2, fork, ForkResult, Pid};
use serde::de::DeserializeOwned;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::io::RawFd;
use std::thread;

fn read_json_from_fd<T: DeserializeOwned>(fd: RawFd) -> Result<T> {
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    serde_json::from_slice(&data)
        .map_err(|e| IsolateError::Process(format!("failed to decode json on fd {fd}: {e}")))
}

fn exec_payload_with_typestate(req: &SandboxLaunchRequest) -> Result<()> {
    crate::exec::pipeline::exec_payload(req)
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
            Err(e) => return Err(IsolateError::process("waitpid(payload)", e)),
        }
    }

    loop {
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => break,
            Ok(
                WaitStatus::Exited(_, _)
                | WaitStatus::Signaled(_, _, _)
                | WaitStatus::Stopped(_, _)
                | WaitStatus::Continued(_)
                | WaitStatus::PtraceEvent(_, _, _)
                | WaitStatus::PtraceSyscall(_),
            ) => {
                reaped_descendants += 1;
            }
            Err(Errno::ECHILD) => break,
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(IsolateError::process("waitpid(reap)", e)),
        }
    }

    Ok((payload_exit, payload_signal, reaped_descendants))
}

fn run_proxy(req: &SandboxLaunchRequest) -> Result<i32> {
    let _ = nix::unistd::setpgid(Pid::from_raw(0), Pid::from_raw(0));
    crate::exec::preexec::setup_parent_death_signal()?;

    let (stdin_read, stdin_write) =
        nix::unistd::pipe().map_err(|e| IsolateError::process("pipe(stdin)", e))?;

    let payload_pid =
        match unsafe { fork() }.map_err(|e| IsolateError::process("fork(payload)", e))? {
            ForkResult::Child => {
                let _ = close(stdin_write);
                dup2(stdin_read, libc::STDIN_FILENO)
                    .map_err(|e| IsolateError::process("dup2(stdin)", e))?;
                let _ = close(stdin_read);

                if let Err(err) = exec_payload_with_typestate(req) {
                    let _ = writeln!(std::io::stderr(), "proxy payload setup failed: {err}");
                    std::process::exit(constants::EXIT_EXEC_FAILURE);
                }
                std::process::exit(constants::EXIT_EXEC_FAILURE);
            }
            ForkResult::Parent { child } => child,
        };

    let _ = close(stdin_read);

    let stdin_handle = if let Some(data) = req.profile.stdin_data.clone() {
        Some(thread::spawn(move || {
            let mut writer = unsafe { File::from_raw_fd(stdin_write) };
            let _ = writer.write_all(data.as_bytes());
        }))
    } else {
        let _ = close(stdin_write);
        None
    };

    // Stdout and stderr flow through pipes to the supervisor's reader threads.
    let (exit_code, term_signal, _) = wait_for_payload_and_reap(payload_pid)?;
    if let Some(h) = stdin_handle {
        let _ = h.join();
    }

    if let Some(sig) = term_signal {
        Ok(128 + sig)
    } else {
        Ok(exit_code.unwrap_or(constants::EXIT_EXEC_FAILURE))
    }
}

pub fn run_proxy_role() -> Result<()> {
    let outcome = match read_json_from_fd::<SandboxLaunchRequest>(0).and_then(|req| run_proxy(&req))
    {
        Ok(code) => code,
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "proxy setup failed: {err}");
            126
        }
    };
    std::process::exit(outcome);
}
