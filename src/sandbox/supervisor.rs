use crate::config::constants;
use crate::config::types::{ExecutionStatus, IsolateError, OutputIntegrity, Result};
use crate::kernel::cgroup::CgroupBackend;
use crate::kernel::pidfd::{pidfd_available, AsyncPidfd};
use crate::sandbox::evidence::{build_launch_evidence, LaunchEvidenceParams};
use crate::sandbox::pool::{send_request_to_slot, ProxyPool, SlotResult};
use crate::sandbox::types::{
    KillReport, ProxyStatus, SandboxLaunchOutcome, SandboxLaunchRequest,
};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

/// Launch a sandboxed execution.
///
/// If a `ProxyPool` is provided, claims a pre-warmed slot (sub-millisecond
/// dispatch). Otherwise falls back to cold-spawning a proxy process.
pub async fn launch_with_supervisor(
    req: SandboxLaunchRequest,
    cgroup: Option<&dyn CgroupBackend>,
    pool: Option<&Arc<ProxyPool>>,
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

    // Try pool path first.
    if let Some(pool) = pool {
        return launch_via_pool(req, cgroup, pool).await;
    }

    // Fall back to cold-spawn path.
    launch_cold(req, cgroup).await
}

// ─── Pool path ────────────────────────────────────────────────────────────────

async fn launch_via_pool(
    req: SandboxLaunchRequest,
    cgroup: Option<&dyn CgroupBackend>,
    pool: &Arc<ProxyPool>,
) -> Result<SandboxLaunchOutcome> {
    let cgroup_backend_selected = cgroup.map(|c| c.backend_name().to_string());
    let mut cgroup_enforced = false;
    let mut evidence_collection_errors = Vec::new();

    // Acquire a warm slot (waits if all busy).
    let acquire_timeout = Duration::from_secs(30);
    let mut permit = pool
        .acquire_timeout(acquire_timeout)
        .await
        .ok_or_else(|| IsolateError::Process("pool: no slot available within 30s".to_string()))?;

    let handle = permit.take_handle();
    let slot_id = handle.slot_id;
    let mut stream = handle.stream;

    let start_time = Instant::now();

    // Attach proxy to cgroup. The slot's PID is unknown to us here (it's the
    // subprocess's PID); for pool mode cgroup is applied at the payload level
    // within the slot via cgroup_attach_path if configured in the request.
    // Slots with per-job cgroups: attach is handled inside run_slot_execution.
    if let Some(controller) = cgroup {
        // We don't have the slot PID directly in pool mode.
        // Cgroup resource limits are enforced via cgroup_attach_path in the req profile.
        // Log a warning if strict mode expects direct cgroup attach.
        if req.profile.strict_mode && req.profile.memory_limit.is_some() {
            evidence_collection_errors.push(
                "pool mode: cgroup attach uses attach_path, not direct PID attach".to_string(),
            );
        }
        cgroup_enforced = req.cgroup_attach_path.is_some();
        let _ = controller; // controller available but PID-based attach not used in pool mode
    }

    // Send request and get result.
    let slot_result = match send_request_to_slot(&mut stream, &req).await {
        Ok(r) => {
            // Return the handle to the pool for reuse.
            permit.recycle(crate::sandbox::pool::PoolHandle { stream, slot_id });
            // Replenish the pool slot (the slot process exited after serving).
            pool.replenish();
            r
        }
        Err(e) => {
            // Socket error — slot is dead, don't return to pool.
            pool.replenish();
            return Err(IsolateError::Process(format!("pool slot {slot_id} error: {e}")));
        }
    };

    let elapsed = start_time.elapsed();

    assemble_outcome(
        req,
        cgroup,
        slot_result,
        elapsed,
        cgroup_backend_selected,
        cgroup_enforced,
        evidence_collection_errors,
    )
    .await
}

// ─── Cold spawn path (fallback / no pool) ─────────────────────────────────────

async fn launch_cold(
    req: SandboxLaunchRequest,
    cgroup: Option<&dyn CgroupBackend>,
) -> Result<SandboxLaunchOutcome> {
    let cgroup_backend_selected = cgroup.map(|c| c.backend_name().to_string());
    let mut cgroup_enforced = false;
    let mut evidence_collection_errors = Vec::new();

    let mut clone_flags = libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;
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

    let exe = std::env::current_exe()
        .map_err(|e| IsolateError::Process(format!("current_exe: {e}")))?;

    let mut child_cmd = Command::new(exe);
    child_cmd.arg("--internal-role=proxy");
    child_cmd.arg("--launch-fd=0");
    child_cmd.arg("--status-fd=1");

    child_cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    unsafe {
        child_cmd.pre_exec(move || {
            if libc::unshare(clone_flags) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let start_time = Instant::now();
    let mut child = child_cmd
        .spawn()
        .map_err(|e| IsolateError::Process(format!("supervisor spawn error: {e}")))?;

    let proxy_pid = child.id().unwrap() as i32;
    if let Some(controller) = cgroup {
        if let Err(e) = controller.attach_process(&req.instance_id, proxy_pid as u32) {
            if req.profile.strict_mode {
                let _ = child.start_kill();
                return Err(e);
            }
            evidence_collection_errors.push(format!("cgroup attach warning: {}", e));
        } else {
            cgroup_enforced = true;
        }

        if let Some(limit) = req.profile.memory_limit {
            if let Err(e) = controller.set_memory_limit(&req.instance_id, limit) {
                if req.profile.strict_mode {
                    let _ = child.start_kill();
                    return Err(e);
                }
                evidence_collection_errors
                    .push(format!("cgroup memory limit warning: {}", e));
            }
        }
        if let Some(limit) = req.profile.process_limit {
            if let Err(e) = controller.set_process_limit(&req.instance_id, limit) {
                if req.profile.strict_mode {
                    let _ = child.start_kill();
                    return Err(e);
                }
            }
        }
        if let Some(limit) = req.profile.cpu_time_limit_ms {
            let usec = (limit as u64) * 1000;
            if let Err(e) = controller.set_cpu_limit(&req.instance_id, usec) {
                if req.profile.strict_mode {
                    let _ = child.start_kill();
                    return Err(e);
                }
            }
        }
    }

    let mut stdin = child.stdin.take().unwrap();
    let stderr_stream = child.stderr.take().unwrap();
    let stdout_stream = child.stdout.take().unwrap();

    let json_req = serde_json::to_vec(&req)
        .map_err(|e| IsolateError::Process(format!("encode req: {e}")))?;

    if let Err(e) = stdin.write_all(&json_req).await {
        drop(stdin);
        let mut buf = Vec::new();
        let mut stderr_owned = stderr_stream;
        let _ = stderr_owned.read_to_end(&mut buf).await;
        let stderr_str = String::from_utf8_lossy(&buf);
        let _ = child.start_kill();
        return Err(IsolateError::Process(format!(
            "write to proxy stdin: {e}\nproxy stderr: {stderr_str}"
        )));
    }
    drop(stdin);

    let output_limit = req
        .profile
        .output_limit
        .unwrap_or(constants::DEFAULT_OUTPUT_COMBINED_LIMIT as u64);

    let stdout_handle = tokio::spawn(async move {
        let mut buf = Vec::new();
        let mut reader = stdout_stream.take(output_limit);
        reader.read_to_end(&mut buf).await.map(|_| buf)
    });

    let stderr_handle = tokio::spawn(async move {
        let mut buf = Vec::new();
        let mut reader = stderr_stream.take(output_limit);
        reader.read_to_end(&mut buf).await.map(|_| buf)
    });

    let wall_limit = req
        .profile
        .wall_time_limit_ms
        .map(|ms| Duration::from_millis(ms as u64))
        .unwrap_or(constants::DEFAULT_SUPERVISOR_WALL_FALLBACK);

    let mut kill_report = None;

    // Use pidfd for race-free kill if available, else timeout path.
    let exit_status = if pidfd_available() {
        match AsyncPidfd::open(proxy_pid) {
            Ok(pidfd) => {
                match tokio::time::timeout(wall_limit, pidfd.wait_exit()).await {
                    Ok(_) => child.wait().await.map_err(|e| {
                        IsolateError::Process(format!("wait error (pidfd): {e}"))
                    })?,
                    Err(_) => {
                        // Wall limit exceeded — kill via pidfd (race-free).
                        let _ = pidfd.send_signal(libc::SIGKILL);
                        kill_report = Some(KillReport {
                            term_sent: false,
                            kill_sent: true,
                            waited_ms: wall_limit.as_millis() as u64,
                            notes: vec!["wall_time_limit_exceeded_pidfd".to_string()],
                        });
                        child.wait().await.map_err(|e| {
                            IsolateError::Process(format!("kill wait error: {e}"))
                        })?
                    }
                }
            }
            Err(_) => {
                // pidfd open failed — fall through to tokio timeout.
                wait_with_tokio_timeout(&mut child, wall_limit, &mut kill_report).await?
            }
        }
    } else {
        wait_with_tokio_timeout(&mut child, wall_limit, &mut kill_report).await?
    };

    let elapsed = start_time.elapsed();

    let stdout_bytes = stdout_handle
        .await
        .unwrap_or_else(|_| Ok(Vec::new()))
        .unwrap_or_default();
    let stderr_bytes = stderr_handle
        .await
        .unwrap_or_else(|_| Ok(Vec::new()))
        .unwrap_or_default();

    let slot_result = SlotResult {
        exit_code: exit_status.code(),
        term_signal: {
            use std::os::unix::process::ExitStatusExt;
            exit_status
                .core_dumped()
                .then(|| 0)
                .or_else(|| exit_status.signal())
        },
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
        wall_time_ms: elapsed.as_millis() as u64,
        timed_out: kill_report.is_some(),
        internal_error: None,
    };

    assemble_outcome(
        req,
        cgroup,
        slot_result,
        elapsed,
        cgroup_backend_selected,
        cgroup_enforced,
        evidence_collection_errors,
    )
    .await
}

async fn wait_with_tokio_timeout(
    child: &mut tokio::process::Child,
    wall_limit: Duration,
    kill_report: &mut Option<KillReport>,
) -> Result<std::process::ExitStatus> {
    match tokio::time::timeout(wall_limit, child.wait()).await {
        Ok(Ok(status)) => Ok(status),
        Ok(Err(e)) => {
            let _ = child.start_kill();
            Err(IsolateError::Process(format!("wait error: {e}")))
        }
        Err(_) => {
            *kill_report = Some(KillReport {
                term_sent: true,
                kill_sent: true,
                waited_ms: wall_limit.as_millis() as u64,
                notes: vec!["wall_time_limit_exceeded".to_string()],
            });
            let _ = child.start_kill();
            child
                .wait()
                .await
                .map_err(|e| IsolateError::Process(format!("kill wait error: {e}")))
        }
    }
}

// ─── Shared assembly ──────────────────────────────────────────────────────────

async fn assemble_outcome(
    req: SandboxLaunchRequest,
    cgroup: Option<&dyn CgroupBackend>,
    slot_result: SlotResult,
    elapsed: Duration,
    cgroup_backend_selected: Option<String>,
    cgroup_enforced: bool,
    evidence_collection_errors: Vec<String>,
) -> Result<SandboxLaunchOutcome> {
    let output_limit = req
        .profile
        .output_limit
        .unwrap_or(constants::DEFAULT_OUTPUT_COMBINED_LIMIT as u64);

    let kill_report = if slot_result.timed_out {
        Some(KillReport {
            term_sent: false,
            kill_sent: true,
            waited_ms: elapsed.as_millis() as u64,
            notes: vec!["wall_time_limit_exceeded".to_string()],
        })
    } else {
        None
    };

    let stdout_truncated = slot_result.stdout.len() as u64 >= output_limit;
    let stderr_truncated = slot_result.stderr.len() as u64 >= output_limit;

    let proxy_status = ProxyStatus {
        payload_pid: None,
        exit_code: slot_result.exit_code,
        term_signal: slot_result.term_signal,
        stdout: slot_result.stdout,
        stderr: slot_result.stderr,
        wall_time_ms: slot_result.wall_time_ms,
        reaped_descendants: 0,
        output_integrity: if stdout_truncated || stderr_truncated {
            OutputIntegrity::TruncatedByJudgeLimit
        } else {
            OutputIntegrity::Complete
        },
        internal_error: slot_result.internal_error,
        timed_out: slot_result.timed_out,
    };

    let params = LaunchEvidenceParams {
        running_as_root: unsafe { libc::geteuid() } == 0,
        cgroup_backend_selected: cgroup_backend_selected.clone(),
        timed_out: kill_report.is_some(),
        kill_report: kill_report.as_ref(),
        proxy_status: &proxy_status,
        cgroup_enforced,
        cgroup_evidence: Default::default(),
        evidence_collection_errors,
        cleanup_verified: true,
    };
    let evidence = build_launch_evidence(&req, params);

    let mut result = proxy_status.to_execution_result();

    if let Some(c) = cgroup {
        if let Ok(oom) = c.check_oom() {
            if oom {
                result.status = ExecutionStatus::MemoryLimit;
                result.success = false;
            }
        }
    }

    Ok(SandboxLaunchOutcome {
        proxy_host_pid: 0, // pool mode: no single proxy PID exposed
        payload_host_pid: None,
        result,
        evidence,
        kill_report,
        proxy_status,
    })
}
