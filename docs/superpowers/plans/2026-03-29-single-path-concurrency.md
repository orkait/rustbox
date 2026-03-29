# Single-Path Bounded-Worker Concurrency Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the dual-path (pool + cold) async supervisor with a single sync supervisor using `std::process::Command`, remove Tokio from the core `rustbox` crate, and restore full cgroup enforcement + evidence collection.

**Architecture:** One sync `launch_with_supervisor` function called by both CLI (directly) and judge-service (via `spawn_blocking`). Wall time enforced by `try_wait` poll loop. All limits delegated to kernel (cgroup, rlimits). Evidence collected post-mortem after child exits.

**Tech Stack:** Rust std library, nix, libc, serde_json. No Tokio in rustbox crate. Tokio stays in judge-service only.

---

### Task 1: Delete pool and memfd modules

**Files:**
- Delete: `src/sandbox/pool.rs`
- Delete: `src/kernel/memfd.rs`
- Modify: `src/sandbox/mod.rs`
- Modify: `src/kernel/mod.rs`

- [ ] **Step 1: Remove pool export from sandbox/mod.rs**

Replace the contents of `src/sandbox/mod.rs` with:

```rust
pub mod evidence;
pub mod proxy;
pub mod supervisor;
pub mod types;
```

- [ ] **Step 2: Remove memfd export from kernel/mod.rs**

Replace the contents of `src/kernel/mod.rs` with:

```rust
pub mod capabilities;
pub mod cgroup;
pub mod cgroup_v2;
pub mod contract;
pub mod credentials;
pub mod mount;
pub mod namespace;
pub mod pidfd;
pub mod pipeline;
pub mod seccomp;
pub mod signal;

pub use contract::{
    EnforcementMode, KernelDomain, KernelRequirement, RequirementLevel, KERNEL_REQUIREMENTS,
    REQUIRED_STAGE_ORDER,
};
pub use pipeline::{KernelPipeline, KernelRunReport, KernelStage};
```

- [ ] **Step 3: Delete the files**

```bash
rm src/sandbox/pool.rs src/kernel/memfd.rs
```

- [ ] **Step 4: Verify it compiles (expect errors in supervisor, isolate, worker, main, cli - that's fine)**

```bash
cargo check 2>&1 | head -5
```

Expected: Errors referencing `pool`, `ProxyPool`, `SlotResult`, etc. in other files. This confirms the deletion propagated. These will be fixed in subsequent tasks.

- [ ] **Step 5: Commit**

```bash
git add -A src/sandbox/pool.rs src/kernel/memfd.rs src/sandbox/mod.rs src/kernel/mod.rs
git commit -m "refactor: delete pool and memfd modules"
```

---

### Task 2: Remove Tokio from rustbox Cargo.toml

**Files:**
- Modify: `Cargo.toml` (workspace root, rustbox package)

- [ ] **Step 1: Remove the tokio dependency line**

In `Cargo.toml`, remove this line from `[dependencies]`:
```toml
tokio = { version = "1.0", features = ["full", "tracing"] }
```

The `[dependencies]` section should end with:
```toml
libc = "0.2"
sha2 = "0.10"
seccompiler = "0.4"
```

- [ ] **Step 2: Commit**

```bash
git add Cargo.toml
git commit -m "refactor: remove tokio from rustbox core crate"
```

---

### Task 3: Revert isolate.rs to sync (remove pool)

**Files:**
- Modify: `src/runtime/isolate.rs`

- [ ] **Step 1: Remove pool imports and field**

Remove these lines from the top:
```rust
use crate::sandbox::pool::ProxyPool;
```
```rust
use std::sync::Arc;
```

In the `Isolate` struct (line 52-60), remove:
```rust
    pool: Option<Arc<ProxyPool>>,
```

- [ ] **Step 2: Remove set_pool method and pool field initialization**

Remove the `set_pool` method (lines 166-169):
```rust
    /// Set a pre-warmed proxy pool to use instead of cold-spawning.
    pub fn set_pool(&mut self, pool: Option<Arc<ProxyPool>>) {
        self.pool = pool;
    }
```

In `Isolate::new()`, in the `Ok(Self { ... })` block (around line 155-163), remove:
```rust
            pool: None,
```

- [ ] **Step 3: Revert execute and execute_with_overrides to sync**

Replace the `execute` method (lines 171-183) with:
```rust
    pub fn execute(
        &mut self,
        command: &[String],
        stdin_data: Option<&str>,
    ) -> Result<ExecutionResult> {
        self.execute_with_overrides(
            command,
            &ExecutionOverrides {
                stdin_data: stdin_data.map(str::to_string),
                ..Default::default()
            },
        )
    }
```

Replace `execute_with_overrides` (lines 186-227) with:
```rust
    /// Pure execution. No allocation, no deallocation.
    pub fn execute_with_overrides(
        &mut self,
        command: &[String],
        overrides: &ExecutionOverrides,
    ) -> Result<ExecutionResult> {
        let config = apply_overrides_to_config(&self.config, overrides);

        if command.is_empty() {
            return Err(IsolateError::Config("Empty command".to_string()));
        }

        let validated = match command_validation::validate_and_resolve_command(&command[0]) {
            Ok(path) => path,
            Err(e) => {
                events::command_injection_attempt(&command[0], None);
                return Err(e);
            }
        };
        let mut argv = vec![validated.to_string_lossy().to_string()];
        argv.extend(command.iter().skip(1).cloned());

        if self.cgroup.is_none() && config.strict_mode {
            return Err(IsolateError::Cgroup(
                "No cgroup backend for strict mode".to_string(),
            ));
        }

        let request = SandboxLaunchRequest::from_config(
            &config,
            &argv,
            overrides.stdin_data.as_deref(),
            self.cgroup
                .as_ref()
                .map(|cg| cg.get_cgroup_path(&config.instance_id)),
        );

        let outcome =
            crate::sandbox::supervisor::launch_with_supervisor(request, self.cgroup.as_deref())?;

        self.last_launch_evidence = Some(outcome.evidence);
        Ok(outcome.result)
    }
```

- [ ] **Step 4: Commit**

```bash
git add src/runtime/isolate.rs
git commit -m "refactor: revert isolate to sync, remove pool field"
```

---

### Task 4: Revert executor.rs to sync

**Files:**
- Modify: `src/runtime/executor.rs`

- [ ] **Step 1: Remove async from all methods**

Replace `pub async fn execute_code_string(` (line 15) with:
```rust
    pub fn execute_code_string(
```

Replace `async fn execute_interpreted(` (line 40) with:
```rust
    fn execute_interpreted(
```

Replace `async fn compile_and_execute(` (line 66) with:
```rust
    fn compile_and_execute(
```

- [ ] **Step 2: Remove .await from all call sites**

In `execute_code_string` (around line 34), replace:
```rust
            self.compile_and_execute(code, &lang_key, &lang_cfg, comp, overrides).await
        } else {
            self.execute_interpreted(code, &lang_cfg, overrides).await
```
with:
```rust
            self.compile_and_execute(code, &lang_key, &lang_cfg, comp, overrides)
        } else {
            self.execute_interpreted(code, &lang_cfg, overrides)
```

In `execute_interpreted` (around line 61), replace:
```rust
        let result = self.execute_with_overrides(&command, overrides).await;
```
with:
```rust
        let result = self.execute_with_overrides(&command, overrides);
```

In `compile_and_execute` (around line 113), replace:
```rust
        let compile_result = match self.execute(&compile_cmd, None).await {
```
with:
```rust
        let compile_result = match self.execute(&compile_cmd, None) {
```

Around line 138, replace:
```rust
        let result = self.execute_with_overrides(&run_cmd, overrides).await;
```
with:
```rust
        let result = self.execute_with_overrides(&run_cmd, overrides);
```

- [ ] **Step 3: Commit**

```bash
git add src/runtime/executor.rs
git commit -m "refactor: revert executor methods to sync"
```

---

### Task 5: Rewrite supervisor.rs (the core change)

**Files:**
- Rewrite: `src/sandbox/supervisor.rs`

- [ ] **Step 1: Write the complete new supervisor**

Replace the entire contents of `src/sandbox/supervisor.rs` with:

```rust
use crate::config::constants;
use crate::config::types::{ExecutionStatus, IsolateError, OutputIntegrity, Result};
use crate::kernel::cgroup::CgroupBackend;
use crate::sandbox::evidence::{build_launch_evidence, LaunchEvidenceParams};
use crate::sandbox::types::{KillReport, ProxyStatus, SandboxLaunchOutcome, SandboxLaunchRequest};
use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

pub fn launch_with_supervisor(
    req: SandboxLaunchRequest,
    cgroup: Option<&dyn CgroupBackend>,
) -> Result<SandboxLaunchOutcome> {
    // ── Phase 1: Validate ──────────────────────────────────────────────────
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

    // ── Phase 2: Spawn proxy ───────────────────────────────────────────────
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

    let exe = std::env::current_exe()
        .map_err(|e| IsolateError::Process(format!("current_exe: {e}")))?;

    let mut child = unsafe {
        Command::new(&exe)
            .arg("--internal-role=proxy")
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

    // ── Phase 3: Cgroup ────────────────────────────────────────────────────
    let cgroup_backend_selected = cgroup.map(|c| c.backend_name().to_string());
    let mut cgroup_enforced = false;
    let mut evidence_collection_errors = Vec::new();

    if let Some(controller) = cgroup {
        if let Err(e) = controller.attach_process(&req.instance_id, proxy_pid as u32) {
            if req.profile.strict_mode {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
            evidence_collection_errors.push(format!("cgroup_attach: {e}"));
        } else {
            cgroup_enforced = true;
        }

        if let Some(limit) = req.profile.memory_limit {
            if let Err(e) = controller.set_memory_limit(&req.instance_id, limit) {
                if req.profile.strict_mode {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(e);
                }
                evidence_collection_errors.push(format!("cgroup_memory: {e}"));
            }
        }
        if let Some(limit) = req.profile.process_limit {
            if let Err(e) = controller.set_process_limit(&req.instance_id, limit) {
                if req.profile.strict_mode {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(e);
                }
                evidence_collection_errors.push(format!("cgroup_pids: {e}"));
            }
        }
        if let Some(limit_ms) = req.profile.cpu_time_limit_ms {
            let usec = (limit_ms as u64) * constants::USEC_PER_MS;
            if let Err(e) = controller.set_cpu_limit(&req.instance_id, usec) {
                if req.profile.strict_mode {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(e);
                }
                evidence_collection_errors.push(format!("cgroup_cpu: {e}"));
            }
        }
    }

    // ── Phase 4: Send request ──────────────────────────────────────────────
    let json_req = serde_json::to_vec(&req)
        .map_err(|e| IsolateError::Process(format!("encode request: {e}")))?;

    {
        let mut stdin = child.stdin.take().ok_or_else(|| {
            IsolateError::Process("child stdin not available".to_string())
        })?;
        if let Err(e) = stdin.write_all(&json_req) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(IsolateError::Process(format!("write proxy stdin: {e}")));
        }
        // stdin drops here, closing the pipe
    }

    // ── Phase 5: Capture output (2 reader threads) ─────────────────────────
    let output_limit = req
        .profile
        .output_limit
        .unwrap_or(constants::DEFAULT_OUTPUT_COMBINED_LIMIT as u64) as usize;

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let stdout_thread = std::thread::spawn(move || read_stream(stdout_pipe, output_limit));
    let stderr_thread = std::thread::spawn(move || read_stream(stderr_pipe, output_limit));

    // ── Phase 6: Wait with wall timeout ────────────────────────────────────
    let start = Instant::now();
    let wall_limit = req
        .profile
        .wall_time_limit_ms
        .map(|ms| Duration::from_millis(ms as u64))
        .unwrap_or(constants::DEFAULT_SUPERVISOR_WALL_FALLBACK);

    let (exit_status, timed_out) = wait_with_wall_timeout(&mut child, proxy_pid, wall_limit);

    let wall_time_ms = start.elapsed().as_millis() as u64;

    // ── Phase 7: Collect (post-mortem) ─────────────────────────────────────
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

    // ── Phase 8: Build outcome ─────────────────────────────────────────────
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
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
        output_integrity,
        internal_error: None,
        reaped_descendants: 0,
    };

    let mut result = proxy_status.to_execution_result();

    // Post-mortem cgroup metrics
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

/// Wait for child exit using non-blocking poll with wall timeout.
/// Returns (ExitStatus, timed_out).
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
                    // Kill the process group (negative PID).
                    unsafe { libc::kill(-proxy_pid, libc::SIGKILL) };
                    // Also kill by PID in case it's not a group leader yet.
                    let _ = child.kill();
                    // Reap.
                    let status = child.wait().ok();
                    return (status, true);
                }
                std::thread::sleep(constants::SUPERVISOR_POLL_INTERVAL);
            }
            Err(_) => {
                // waitpid error - child may already be dead
                return (None, false);
            }
        }
    }
}

/// Read from an optional pipe up to `limit` bytes. Returns bytes and integrity.
fn read_stream(
    pipe: Option<impl Read>,
    limit: usize,
) -> (Vec<u8>, OutputIntegrity) {
    let Some(mut reader) = pipe else {
        return (Vec::new(), OutputIntegrity::WriteError);
    };
    let mut buf = Vec::new();
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
```

- [ ] **Step 2: Verify the supervisor compiles in isolation**

```bash
cargo check -p rustbox 2>&1 | grep "^error" | head -10
```

Expected: Errors only from cli.rs (still references pool, async). Supervisor itself should be clean.

- [ ] **Step 3: Commit**

```bash
git add src/sandbox/supervisor.rs
git commit -m "refactor: rewrite supervisor as single sync path with full evidence"
```

---

### Task 6: Fix cli.rs (remove pool, remove block_on)

**Files:**
- Modify: `src/cli.rs`

- [ ] **Step 1: Remove pool-socket arg from Cli struct**

Remove these two lines (around line 52-53):
```rust
    #[arg(long, hide = true)]
    pool_socket: Option<String>,
```

- [ ] **Step 2: Remove pool-slot role handling**

Remove the pool-slot block (lines 182-187):
```rust
        if role == "pool-slot" {
            let socket_path = cli.pool_socket.ok_or_else(|| {
                anyhow::anyhow!("--pool-socket is required for --internal-role=pool-slot")
            })?;
            return crate::sandbox::pool::run_pool_slot_role(&socket_path).map_err(Into::into);
        }
```

- [ ] **Step 3: Remove block_on wrapper from execute_code_string call**

Replace lines 268-276:
```rust
            let execution_outcome: anyhow::Result<crate::config::types::ExecutionStatus> =
                match tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
                        .block_on(isolate.execute_code_string(&language, &code, &overrides))
                {
                    Ok(result) => {
                        emit_execution_result(&mut isolate, &result, Some(&language), &overrides)
                    }
                    Err(err) => Err(err.into()),
                };
```

with:
```rust
            let execution_outcome: anyhow::Result<crate::config::types::ExecutionStatus> =
                match isolate.execute_code_string(&language, &code, &overrides) {
                    Ok(result) => {
                        emit_execution_result(&mut isolate, &result, Some(&language), &overrides)
                    }
                    Err(err) => Err(err.into()),
                };
```

- [ ] **Step 4: Verify rustbox crate compiles clean**

```bash
cargo check -p rustbox 2>&1 | grep "^error" | head -10
```

Expected: No errors from rustbox crate. Errors may remain in judge-service (fixed in next task).

- [ ] **Step 5: Commit**

```bash
git add src/cli.rs
git commit -m "refactor: remove pool-slot role and block_on from CLI"
```

---

### Task 7: Fix judge-service worker.rs (spawn_blocking, remove pool)

**Files:**
- Modify: `judge-service/src/worker.rs`

- [ ] **Step 1: Remove ProxyPool import and pool parameters**

Remove line 8:
```rust
use rustbox::sandbox::pool::ProxyPool;
```

In `spawn_channel_workers` signature (line 17-24), remove the `pool` parameter:
```rust
pub fn spawn_channel_workers(
    count: usize,
    db: Arc<dyn Database>,
    queue: Arc<JobQueue>,
    node_id: String,
    webhook_timeout_secs: u64,
) -> Vec<tokio::task::JoinHandle<()>> {
```

Remove `let pool = pool.clone();` (line 30).

In the worker loop, change the `process_job` call (line 42) from:
```rust
                    process_job(db.as_ref(), job_id, &node_id, webhook_timeout_secs, pool.as_ref()).await;
```
to:
```rust
                    process_job(db.as_ref(), job_id, &node_id, webhook_timeout_secs).await;
```

- [ ] **Step 2: Remove pool from process_job and pg workers**

Change `process_job` signature (line 157) from:
```rust
async fn process_job(db: &dyn Database, job_id: Uuid, node_id: &str, webhook_timeout_secs: u64, pool: Option<&Arc<ProxyPool>>) {
```
to:
```rust
async fn process_job(db: &dyn Database, job_id: Uuid, node_id: &str, webhook_timeout_secs: u64) {
```

Change the `execute_in_sandbox` call (line 195) from:
```rust
    let result = execute_in_sandbox(&language, &code, &stdin, pool).await;
```
to:
```rust
    let span = tracing::Span::current();
    let result = tokio::task::spawn_blocking(move || {
        let _guard = span.enter();
        execute_in_sandbox(&language, &code, &stdin)
    })
    .await
    .unwrap_or_else(|e| Err(format!("worker task panicked: {e}")));
```

In `drain_pending` (line 140), change:
```rust
                    process_job(db.as_ref(), sub.id, &node_id, webhook_timeout_secs, None).await;
```
to:
```rust
                    process_job(db.as_ref(), sub.id, &node_id, webhook_timeout_secs).await;
```

In `spawn_pg_workers` (line 98-101), change:
```rust
                                        process_job(
                                            db.as_ref(),
                                            sub.id,
                                            &node_id,
                                            webhook_timeout_secs,
                                            None,
                                        )
                                        .await;
```
to:
```rust
                                        process_job(
                                            db.as_ref(),
                                            sub.id,
                                            &node_id,
                                            webhook_timeout_secs,
                                        )
                                        .await;
```

- [ ] **Step 3: Revert execute_in_sandbox to sync**

Change `execute_in_sandbox` signature (line 328) from:
```rust
async fn execute_in_sandbox(language: &str, code: &str, stdin: &str, pool: Option<&Arc<ProxyPool>>) -> Result<ExecutionOutput, String> {
```
to:
```rust
fn execute_in_sandbox(language: &str, code: &str, stdin: &str) -> Result<ExecutionOutput, String> {
```

Remove the `set_pool` call (line 356):
```rust
    // Set the pool on the isolate so the supervisor uses warm slots.
    isolate.set_pool(pool.cloned());
```

Change the execute call (lines 358-361) from:
```rust
    let result = isolate
        .execute_code_string(language, code, &overrides)
        .await
        .map_err(|e| format!("execution error: {e}"))?;
```
to:
```rust
    let result = isolate
        .execute_code_string(language, code, &overrides)
        .map_err(|e| format!("execution error: {e}"))?;
```

- [ ] **Step 4: Commit**

```bash
git add judge-service/src/worker.rs
git commit -m "refactor: sync execute_in_sandbox with spawn_blocking bridge"
```

---

### Task 8: Fix judge-service main.rs (remove pool init)

**Files:**
- Modify: `judge-service/src/main.rs`

- [ ] **Step 1: Remove pool-slot role handling**

Remove lines 25-34 (the pool-slot block):
```rust
        if role == "pool-slot" {
            let socket_path = args
                .iter()
                .find(|a| a.starts_with("--pool-socket="))
                .and_then(|a| a.split('=').nth(1))
                .ok_or_else(|| anyhow::anyhow!("--pool-socket required for pool-slot role"))?
                .to_string();
            return rustbox::sandbox::pool::run_pool_slot_role(&socket_path)
                .map_err(|e| anyhow::anyhow!("pool-slot role failed: {e}"));
        }
```

- [ ] **Step 2: Remove pool initialization in async_main**

Remove lines 60-63:
```rust
    // Initialize the pre-warmed proxy pool.
    let pool_size = rustbox::sandbox::pool::ProxyPool::default_size();
    let proxy_pool = rustbox::sandbox::pool::ProxyPool::new(pool_size);
    info!(pool_size, "proxy pool started");
```

- [ ] **Step 3: Remove pool from spawn_channel_workers call**

Change lines 88-95 from:
```rust
        let handles = judge_service::worker::spawn_channel_workers(
            cfg.workers,
            db.clone(),
            queue.clone(),
            cfg.node_id.clone(),
            cfg.webhook_timeout_secs,
            Some(proxy_pool.clone()),
        );
```
to:
```rust
        let handles = judge_service::worker::spawn_channel_workers(
            cfg.workers,
            db.clone(),
            queue.clone(),
            cfg.node_id.clone(),
            cfg.webhook_timeout_secs,
        );
```

- [ ] **Step 4: Verify full workspace compiles**

```bash
cargo check --workspace 2>&1 | grep "^error" | head -20
```

Expected: Zero errors.

- [ ] **Step 5: Commit**

```bash
git add judge-service/src/main.rs
git commit -m "refactor: remove pool initialization from judge-service"
```

---

### Task 9: Update proxy.rs comment

**Files:**
- Modify: `src/sandbox/proxy.rs`

- [ ] **Step 1: Fix stale comment about Tokio I/O**

In `src/sandbox/proxy.rs`, replace line 95:
```rust
    // Note: Stdout and Stderr are directly inherited and streamed by the Supervisor via Tokio async I/O.
```
with:
```rust
    // Stdout and stderr flow through pipes to the supervisor's reader threads.
```

- [ ] **Step 2: Commit**

```bash
git add src/sandbox/proxy.rs
git commit -m "fix: update stale proxy comment"
```

---

### Task 10: Run full test suite

**Files:** None (verification only)

- [ ] **Step 1: Format**

```bash
cargo fmt --all
```

- [ ] **Step 2: Clippy**

```bash
cargo clippy --workspace -- -D warnings 2>&1 | tail -20
```

Expected: No errors or warnings.

- [ ] **Step 3: Tests**

```bash
cargo test --workspace 2>&1 | tail -30
```

Expected: All tests pass. The 3 new supervisor tests (proxy_timeout_produces_tle, clean_exit_zero_is_ok, signal_produces_signaled_status) should appear.

- [ ] **Step 4: Fix any issues, commit**

```bash
cargo fmt --all
git add -A
git commit -m "chore: fmt + clippy fixes"
```

---

### Task 11: Clean up scratch files and move configs

**Files:**
- Delete: `concurrency_rewrite_summary.md`
- Delete: `summary.md`
- Delete: `walkthrough.md`
- Move: `config-executor.json` -> `docker/stress/config-executor.json`
- Move: `config-judge.json` -> `docker/stress/config-judge.json`

- [ ] **Step 1: Delete and move**

```bash
rm -f concurrency_rewrite_summary.md summary.md walkthrough.md
mv config-executor.json docker/stress/config-executor.json
mv config-judge.json docker/stress/config-judge.json
```

- [ ] **Step 2: Update docker/stress/Dockerfile.custom to use local config paths**

In `docker/stress/Dockerfile.custom`, change lines 57-58 from:
```dockerfile
COPY config-judge.json    /etc/rustbox/config-judge.json
COPY config-executor.json /etc/rustbox/config-executor.json
```
to:
```dockerfile
COPY docker/stress/config-judge.json    /etc/rustbox/config-judge.json
COPY docker/stress/config-executor.json /etc/rustbox/config-executor.json
```

- [ ] **Step 3: Restore Dockerfile language defaults**

In `Dockerfile`, change lines 5-8 from:
```dockerfile
ARG LANG_C_CPP=false
ARG LANG_JAVA=false
ARG LANG_JAVASCRIPT=false
ARG LANG_TYPESCRIPT=false
```
to:
```dockerfile
ARG LANG_C_CPP=true
ARG LANG_JAVA=true
ARG LANG_JAVASCRIPT=true
ARG LANG_TYPESCRIPT=true
```

Remove the CACHEBUST lines (lines 29-30):
```dockerfile
ARG CACHEBUST=1
RUN echo "Cache bust: $CACHEBUST" && cargo build --release -p rustbox && cargo build --release -p judge-service
```
Replace with:
```dockerfile
RUN cargo build --release -p rustbox && cargo build --release -p judge-service
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore: clean up scratch files, restore Dockerfile defaults"
```

---

### Task 12: Delete plan.md from root

**Files:**
- Delete: `plan.md` (superseded by this plan)

- [ ] **Step 1: Delete**

```bash
rm plan.md
```

- [ ] **Step 2: Final commit**

```bash
git add -A
git commit -m "chore: remove superseded plan.md"
```
