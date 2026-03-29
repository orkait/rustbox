# Concurrency Redesign: Single-Path Bounded Workers

## Why

The `feat/async-sandbox-concurrency` branch introduced two execution paths (pool and cold) to solve Tokio + `clone(2)` deadlocks. The fix for the deadlock was correct (replace `clone(2)` with `Command::new` + `pre_exec(unshare)`), but the implementation diverged into two paths with different behaviour:

| Problem | Pool Path | Cold Path |
|---|---|---|
| Cgroup enforcement | NOT DONE | Done |
| stdin delivery | SILENTLY DROPPED | Done |
| Namespace isolation | IPC+UTS only | All 6 namespaces |
| CPU time polling | Not done (blocking poll in slot) | Not done (regressed) |
| Evidence collection | Hardcoded defaults | OOM check only (regressed) |
| Dead handle recycling | Yes (bug) | N/A |
| Wall timer | `std::thread::sleep(10ms)` loop | `tokio::time::timeout` |
| pidfd kill | Closed fd before use (bug) | Correct |

This violates the project's own principle from #31: **one exec path**. Two paths means every security fix applied twice, and they already diverged.

The root cause analysis is simple: **concurrency doesn't require two execution paths**. It requires a queue and bounded workers.

---

## Architecture

```
                    15,000 requests / second
                              |
                              v
               +--------------------------+
               |    HTTP Server (Tokio)    |
               |                          |
               |  validate -> DB insert   |
               |        -> enqueue        |
               |                          |
               |  GET /result -> DB read  |
               +-----------+--------------+
                           |
                           v
               +--------------------------+
               |        Job Queue         |
               |                          |
               |  15,000 jobs buffered    |
               |  (mpsc channel or DB)    |
               |                          |
               |  backpressure: bounded   |
               |  channel or DB row count |
               +-----------+--------------+
                           |
             +-------------+-------------+-------------+
             |             |             |             |
             v             v             v             v
         Worker 0      Worker 1      Worker 2      Worker 3
         (tokio task)  (tokio task)  (tokio task)  (tokio task)
```

### Worker Loop

Each worker is a Tokio task. N workers = N CPUs. The worker count IS the concurrency bound.

```
Worker N:
    loop {
        job = queue.recv().await             <-- blocks until job available
        db.mark_running(job.id).await

        +-----------------------------------------------------+
        |  WALL TIMER STARTS HERE                              |
        |                                                      |
        |  child = Command::new(rustbox --internal-role=proxy) |
        |      .pre_exec(unshare(IPC|UTS|PID|MNT|NET))        |
        |      .stdin(piped)                                   |
        |      .stdout(piped)                                  |
        |      .stderr(piped)                                  |
        |      .spawn()                                        |
        |                                                      |
        |  cgroup.attach(child.pid)                            |
        |  cgroup.set_memory_limit()                           |
        |  cgroup.set_process_limit()                          |
        |  cgroup.set_cpu_limit()                              |
        |                                                      |
        |  stdin.write(request_json).await                     |
        |  drop(stdin)                                         |
        |                                                      |
        |  +--------------- parallel -----------------+        |
        |  | tokio::spawn: read stdout (async, capped) |       |
        |  | tokio::spawn: read stderr (async, capped) |       |
        |  | wait child exit (tokio::time::timeout)    |       |
        |  | poll cgroup cpu.stat (10ms interval)      |       |
        |  +-------------------------------------------+       |
        |                                                      |
        |  if wall timeout   -> child.kill(), verdict=TLE      |
        |  if cpu exceeded   -> child.kill(), verdict=TLE      |
        |  if OOM killed     -> detect via cgroup, verdict=MLE |
        |                                                      |
        |  collect evidence:                                   |
        |    cpu_time  = cgroup.get_cpu_usage()                |
        |    mem_peak  = cgroup.get_memory_peak()              |
        |    cgroup_ev = cgroup.collect_evidence()             |
        |                                                      |
        |  WALL TIMER ENDS HERE                                |
        +-----------------------------------------------------+

        db.mark_completed(job.id, result).await
    }
```

### Inside the Proxy Child (unchanged from v1)

```
rustbox --internal-role=proxy
        |
   read request JSON from stdin
        |
   fork(payload)
        |
      CHILD:
        typestate chain (11 stages, compile-time enforced):
          namespace setup (skip - already unshared by supervisor)
          mount hardening
          cgroup attach
          mount + root transition
          runtime hygiene
          drop credentials
          lock capabilities
          verify parent death signal
          verify session leadership
          verify capability sets
          install seccomp filter
          -> execvp()
        |
        (runs user code, stdout/stderr to pipes)
        |
      PARENT (proxy):
        waitpid(payload)
        reap descendants
        exit(code)
```

### Why It Scales

```
Layer           Handles                              Bottleneck?
-----           -------                              -----------
HTTP accept     15K req/s intake                     No. Tokio does 100K+.
DB insert       15K rows/s                           No. Batched writes.
Queue           15K buffered jobs                    No. Bounded channel.
Workers         4 concurrent executions              YES. This IS the limit.
Drain rate      4 / avg_execution_time per second    Physics. Can't beat CPU count.
```

With avg 500ms exec: 4 / 0.5 = 8 req/s. 15K drains in ~31 min.
With avg 100ms exec: 4 / 0.1 = 40 req/s. 15K drains in ~6 min.

You can't architecture your way past CPU count. You can only add more CPUs.

---

## Implementation Steps

### Step 1: Restore supervisor.rs to single path

Delete `launch_via_pool`, `launch_cold`, `assemble_outcome`, `wait_with_tokio_timeout`.

Write one `launch_with_supervisor` function:
- Signature: `pub async fn launch_with_supervisor(req: SandboxLaunchRequest, cgroup: Option<&dyn CgroupBackend>) -> Result<SandboxLaunchOutcome>`
- No pool parameter
- Uses `tokio::process::Command` with `pre_exec(unshare(...))`
- stdin piped: write request JSON, close
- stdout/stderr piped: async read with `take(output_limit)`
- cgroup: attach by PID, set all limits (memory, process, cpu)
- Wall timer: `tokio::time::timeout(wall_limit, child.wait())`
- CPU polling: `tokio::time::interval(10ms)` checking `cgroup.get_cpu_usage()`
- On timeout or CPU exceed: `child.start_kill()`, mark timed_out
- Evidence collection: restore `get_cpu_usage()`, `get_memory_peak()`, `collect_evidence()`
- Build `LaunchEvidence` with full params (not hardcoded defaults)
- Build `SandboxLaunchOutcome` with populated result

### Step 2: Remove pool from Isolate

In `src/runtime/isolate.rs`:
- Remove `pool: Option<Arc<ProxyPool>>` field
- Remove `set_pool()` method
- Remove `ProxyPool` import
- Update `launch_with_supervisor` call: drop pool parameter

In `src/runtime/executor.rs`:
- No changes needed (already async, calls execute_with_overrides)

### Step 3: Simplify worker.rs

In `judge-service/src/worker.rs`:
- Remove `pool` parameter from `spawn_channel_workers` and `process_job`
- Remove `ProxyPool` import
- Remove `isolate.set_pool()` call
- `execute_in_sandbox` stays async (calls isolate which calls supervisor)
- Keep `spawn_blocking` removal (async all the way)

Worker count is already set by `cfg.workers` (defaults to `nproc`). This IS the concurrency bound. Each worker task loops on queue.recv(), so exactly N jobs execute concurrently.

### Step 4: Simplify judge-service main.rs

In `judge-service/src/main.rs`:
- Remove `ProxyPool` creation and `pool_size` logic
- Remove `Some(proxy_pool.clone())` from spawn_channel_workers call
- Keep the pre-Tokio `--internal-role=proxy` intercept (still needed)
- Remove `--internal-role=pool-slot` intercept
- Keep manual `tokio::runtime::Builder` (still needed for proxy intercept)

### Step 5: Delete pool module and memfd

Delete files:
- `src/sandbox/pool.rs`
- `src/kernel/memfd.rs`

Update `src/sandbox/mod.rs`:
- Remove `pub mod pool;`

Update `src/kernel/mod.rs`:
- Remove `pub mod memfd;`

### Step 6: Clean up cli.rs

In `src/cli.rs`:
- Remove `--pool-socket` arg
- Remove `pool-slot` role handling
- Keep `tokio::runtime::Builder::new_current_thread()` for CLI execute path

### Step 7: Restore proxy.rs functions needed by supervisor

The current branch stripped proxy.rs of functions the supervisor used to call.
With the new single-path design, the proxy child:
- Reads request JSON from stdin (already works)
- Forks payload, runs typestate chain (already works)
- Stdout/stderr flow through pipes to supervisor (already works - pipes inherited)
- Exits with payload's exit code (already works)

The proxy is now thin: read stdin, fork, exec_payload, waitpid, exit. No output capture (supervisor does that via piped stdout/stderr). No wall timer (supervisor does that via tokio::time::timeout). This is correct.

### Step 8: Keep pidfd.rs as utility

`src/kernel/pidfd.rs` stays. It's clean, tested, and useful for race-free process targeting. The supervisor doesn't strictly need it (tokio::process::Child handles PID lifecycle), but it's a good kernel primitive to have available.

### Step 9: Clean up Cargo.toml

Tokio dependency: keep in rustbox crate but minimize features.
Current: `tokio = { version = "1.0", features = ["full", "tracing"] }`
Change to: `tokio = { version = "1.0", features = ["process", "io-util", "time", "rt", "macros"] }`

Only what supervisor.rs actually uses: async process, async I/O, timeouts, runtime.

### Step 10: Delete scratch files

Delete from repo root:
- `concurrency_rewrite_summary.md`
- `summary.md`
- `walkthrough.md`
- `config-executor.json` (move to docker/stress/ if needed there)
- `config-judge.json` (move to docker/stress/ if needed there)

### Step 11: Restore Dockerfile defaults

In `Dockerfile`:
- Restore language defaults: `LANG_C_CPP=true`, `LANG_JAVA=true`, `LANG_JAVASCRIPT=true`, `LANG_TYPESCRIPT=true`
- Remove `CACHEBUST` arg
- Restore 4-space indent (cosmetic, but avoids noise in diff)

### Step 12: Verify

- `cargo fmt`
- `cargo clippy`
- `cargo test`
- Build docker stress image, run tiers 1/10/50/100

---

## What Does NOT Change

- `exec/pipeline.rs` - typestate chain untouched
- `kernel/` - cgroup, seccomp, capabilities, credentials, mount, namespace all untouched
- `safety/` - uid_pool, cleanup untouched
- `config/` - constants, types, loader, validator untouched
- `judge-service/` - API routes, DB layer, job queue untouched
- `docker/stress/` - stress test infrastructure kept (useful)
- Security posture: single path, full namespace isolation, full cgroup enforcement, full evidence

## Files Changed (Summary)

| Action | File |
|---|---|
| REWRITE | `src/sandbox/supervisor.rs` |
| MODIFY | `src/runtime/isolate.rs` (remove pool field) |
| MODIFY | `judge-service/src/worker.rs` (remove pool param) |
| MODIFY | `judge-service/src/main.rs` (remove pool init) |
| MODIFY | `src/sandbox/mod.rs` (remove pool export) |
| MODIFY | `src/kernel/mod.rs` (remove memfd export) |
| MODIFY | `src/cli.rs` (remove pool-socket arg) |
| MODIFY | `src/sandbox/proxy.rs` (keep thin, verify correct) |
| MODIFY | `Cargo.toml` (minimize tokio features) |
| MODIFY | `Dockerfile` (restore defaults) |
| DELETE | `src/sandbox/pool.rs` |
| DELETE | `src/kernel/memfd.rs` |
| DELETE | `concurrency_rewrite_summary.md` |
| DELETE | `summary.md` |
| DELETE | `walkthrough.md` |
| KEEP | `src/kernel/pidfd.rs` |
| KEEP | `docker/stress/*` |
| MOVE | `config-executor.json` -> `docker/stress/` |
| MOVE | `config-judge.json` -> `docker/stress/` |
