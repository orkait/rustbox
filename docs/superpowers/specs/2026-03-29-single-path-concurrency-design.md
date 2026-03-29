# Single-Path Bounded-Worker Concurrency Design

**Date**: 2026-03-29
**Status**: Draft - pending review
**Branch**: `feat/async-sandbox-concurrency`

---

## Problem Statement

The current branch introduced two execution paths (pool and cold) to solve Tokio + `clone(2)` heap mutex deadlocks at high concurrency. The deadlock fix was correct (replace `clone(2)` with `Command::new` + `pre_exec(unshare)`), but the implementation diverged into two paths with different behaviour:

- **Pool path**: No cgroup enforcement, stdin silently dropped, only IPC+UTS namespaces, dead handle recycling bug, pidfd use-after-close bug
- **Cold path**: Full namespaces but no CPU time polling (regressed), evidence collection gutted (only OOM check), no cpu_time/memory_peak reported

This violates the project principle established in PR #31: **one exec path**. Two paths means security fixes applied twice, and they already diverged on 6 dimensions.

## Root Cause

Concurrency doesn't require two execution paths. It requires a queue and bounded workers. The deadlock was caused by `clone(2)` (shares parent address space), not by the concurrency model. `Command::new()` (fork+exec, clean address space) eliminates the deadlock from either sync or async code.

## Design

### Principle

```
Queue absorbs burst.
Workers bound concurrency.
One execution path.
Timer starts at execution, not arrival.
```

### Architecture Overview

```
                    N requests / second
                           |
                           v
            +--------------------------+
            |    HTTP Server (Tokio)    |
            |                          |
            |  POST /submit            |
            |    validate              |
            |    DB insert (pending)   |
            |    enqueue job ID        |
            |    return 200 + job ID   |
            |                          |
            |  GET /result/:id         |
            |    DB lookup             |
            |    return status/result  |
            +-----------+--------------+
                        |
                        v
            +--------------------------+
            |        Job Queue         |
            |    (mpsc channel)        |
            |                          |
            |  buffered, bounded       |
            +-----------+--------------+
                        |
          +-------------+-------------+-------------+
          |             |             |             |
          v             v             v             v
      Worker 0      Worker 1      Worker 2      Worker 3
     (tokio task)  (tokio task)  (tokio task)  (tokio task)
          |             |             |             |
    spawn_blocking spawn_blocking spawn_blocking spawn_blocking
          |             |             |             |
    execute()     execute()     execute()     execute()
    (sync)        (sync)        (sync)        (sync)
```

Worker count = CPU count. This IS the concurrency bound. No semaphore needed.

### Worker Loop (judge-service)

Each worker is a Tokio task that bridges async (HTTP/DB) to sync (sandbox execution).

```
Worker N (tokio::spawn):
    loop {
        job_id = queue.recv().await           // async: wait for next job
        submission = db.get(job_id).await      // async: read job details
        db.mark_running(job_id).await          // async: update status

        let span = tracing::Span::current();  // capture async span
        result = spawn_blocking(move || {      // bridge: async -> sync
            let _guard = span.enter();         // propagate span into blocking thread
            execute_in_sandbox(language, code, stdin)
        }).await

        db.mark_completed(job_id, result).await  // async: store result
    }
```

**Note on job queue**: The existing `JobQueue` already uses `async_channel::bounded` (MPMC).
The `Receiver` is `Clone + Sync` - each worker clones it directly. No `Arc<Mutex<>>` needed.

`spawn_blocking` is safe because:
- Old deadlock: `spawn_blocking` + `clone(2)` = child shares parent heap = Tokio mutex deadlock
- New code: `spawn_blocking` + `Command::new` = child does fork+exec = clean address space
- With N workers, exactly N blocking threads. Not unbounded.
- Tokio's blocking pool is shared (default max 512), but N=4 sandbox workers is negligible.

**Telemetry**: `tracing::Span::current()` is captured before `spawn_blocking` and entered inside
the closure via `span.enter()`. All `tracing` macros inside `execute_in_sandbox` and
`launch_with_supervisor` attach to the worker's span automatically. This is the standard
pattern for propagating structured logging across async-sync boundaries.

### CLI Path (no Tokio)

```
rustbox run --language python --code "print(1)"
    Isolate::new()
    isolate.execute_code_string()        // sync, direct call
        launch_with_supervisor()         // sync
            Command::new().spawn()       // fork+exec
            wait loop                    // blocks
    print result
```

No Tokio. No `block_on()`. No async. The core `rustbox` crate has zero Tokio dependency.

### Execution Flow (single path)

This is the complete flow for every sandbox execution, whether from CLI or judge-service.

```
execute_in_sandbox(language, code, stdin)
    |
    v
Isolate::new(config)
    allocate UID from pool (atomic)
    create cgroup
    create workdir
    |
    v
isolate.execute_code_string(language, code, overrides)
    |
    +-- compiled language? --> compile_and_execute()
    |       execute(compile_cmd)          // launch_with_supervisor
    |       if compile fails: return CE
    |       execute_with_overrides(run_cmd)  // launch_with_supervisor
    |
    +-- interpreted? --> execute_interpreted()
            write source file
            execute_with_overrides(run_cmd)  // launch_with_supervisor
    |
    v
launch_with_supervisor(request, cgroup)     // THE SINGLE PATH
```

### launch_with_supervisor - Complete Flow

```
launch_with_supervisor(req: SandboxLaunchRequest, cgroup: Option<&dyn CgroupBackend>)
    -> Result<SandboxLaunchOutcome>

PHASE 1: VALIDATE
    if req.command is empty: return Err
    if req.command[0] binary doesn't exist: return Err

PHASE 2: SPAWN PROXY
    child = std::process::Command::new(current_exe())
        .arg("--internal-role=proxy")
        .stdin(Stdio::piped)
        .stdout(Stdio::piped)
        .stderr(Stdio::piped)
        .pre_exec(move || {
            unshare(clone_flags)     // IPC|UTS|PID|MNT|NET|USER per request profile
        })
        .spawn()

    proxy_pid = child.id()

PHASE 3: CGROUP
    if cgroup is Some:
        cgroup.attach_process(proxy_pid)
        cgroup.set_memory_limit()        // kernel enforces: OOM kill
        cgroup.set_process_limit()       // kernel enforces: EAGAIN on fork
        cgroup.set_cpu_limit()           // kernel enforces: throttle via cpu.max
        if strict_mode and any fails: child.kill(), return Err

PHASE 4: SEND REQUEST
    stdin = child.stdin.take()
    stdin.write_all(serde_json::to_vec(&req))
    drop(stdin)                          // close stdin, proxy reads EOF

PHASE 5: CAPTURE OUTPUT (2 reader threads)
    stdout_thread = thread::spawn(|| {
        read child.stdout up to output_limit bytes
        return (bytes, integrity)
    })
    stderr_thread = thread::spawn(|| {
        read child.stderr up to output_limit bytes
        return (bytes, integrity)
    })

PHASE 6: WAIT WITH WALL TIMEOUT (main thread, no watchdog)
    start = Instant::now()
    wall_limit = req.wall_time_limit (or DEFAULT_SUPERVISOR_WALL_FALLBACK)
    timed_out = false

    status = loop {
        match child.try_wait():
            Some(exit_status):
                break exit_status        // child exited naturally

            None if start.elapsed() >= wall_limit:
                kill(-proxy_pid, SIGKILL) // kill process group
                timed_out = true
                break child.wait()       // reap the killed child

            None:
                thread::sleep(SUPERVISOR_POLL_INTERVAL)  // 10ms
    }

PHASE 7: COLLECT (post-mortem, after child is dead)
    stdout = stdout_thread.join()
    stderr = stderr_thread.join()

    if cgroup is Some:
        cpu_time_usec = cgroup.get_cpu_usage()
        memory_peak   = cgroup.get_memory_peak()
        oom_killed    = cgroup.check_oom()
        cgroup_evidence = cgroup.collect_evidence()

PHASE 8: BUILD OUTCOME
    proxy_status = ProxyStatus {
        exit_code:    status.code(),
        term_signal:  status.signal(),
        timed_out:    timed_out,
        wall_time_ms: start.elapsed().as_millis(),
        stdout:       String::from_utf8_lossy(stdout),
        stderr:       String::from_utf8_lossy(stderr),
        ...
    }

    result = proxy_status.to_execution_result()
    result.cpu_time    = cpu_time_usec / 1_000_000
    result.memory_peak = memory_peak

    if oom_killed:
        result.status = MemoryLimit
    else if timed_out:
        result.status = TimeLimit

    evidence = build_launch_evidence(req, params)

    return SandboxLaunchOutcome { result, evidence, proxy_status, ... }
```

### Inside the Proxy Child (unchanged from v1)

```
rustbox --internal-role=proxy
    |
    read SandboxLaunchRequest JSON from stdin
    |
    setpgid(0, 0)                    // become process group leader
    setup_parent_death_signal()       // die if supervisor dies
    |
    pipe(stdin_read, stdin_write)     // for payload's stdin
    |
    fork(payload)
    |
    CHILD (payload):
        dup2(stdin_read -> STDIN)
        close(stdin_write)
        |
        exec_payload(req)              // the typestate chain
            Sandbox::<FreshChild>::new()
            .setup_namespaces()        // skip (already unshared by supervisor)
            .harden_mount_propagation()
            .attach_to_cgroup()
            .setup_mounts_and_root()
            .apply_runtime_hygiene()
            .drop_credentials()
            .lock_privileges()
            verify parent_death_signal
            verify session_leadership
            verify capability_sets
            install seccomp_filter
            .ready_for_exec()
            .exec_payload(command)     // execvp(), never returns
        |
        (runs user code)
        stdout -> pipe to supervisor
        stderr -> pipe to supervisor
        |
        exit(code)

    PARENT (proxy):
        close(stdin_read)
        write stdin_data to stdin_write (if any)
        close(stdin_write)
        waitpid(payload_pid)
        reap stray descendants
        exit(payload_exit_code)
```

### Verdict Logic

After `launch_with_supervisor` returns, the caller (or the function itself) determines the verdict:

```
if oom_killed:
    verdict = MLE (Memory Limit Exceeded)
else if timed_out:
    verdict = TLE (Time Limit Exceeded)
else if internal_error:
    verdict = IE (Internal Error)
else if term_signal is Some:
    verdict = Signaled (RE)
else if exit_code != 0:
    verdict = RE (Runtime Error)
else:
    verdict = AC (Accepted) -- caller compares output to expected
```

CPU time is **reported** in the result (e.g., "cpu_time: 3.2s") but is **not a kill trigger**. The kernel's `cpu.max` throttles the process, which naturally pushes it toward the wall time limit. If operators want tight CPU enforcement, they set `wall_time = cpu_time + small_grace`.

### Resource Lifecycle

```
Isolate::new()
    +-- allocate UID (atomic from pool)
    +-- create cgroup directory
    +-- create workdir

    execute_code_string()
        +-- write source file
        +-- launch_with_supervisor()
            +-- spawn child (fork+exec)
            +-- attach to cgroup
            +-- set limits
            +-- wait / kill / collect
            +-- child is dead, output collected

    drop(Isolate)
        +-- wipe workdir
        +-- destroy cgroup
        +-- release UID back to pool
```

Every resource acquired in `new()` is released in `drop()`. The supervisor doesn't own any resources - it borrows the cgroup reference and returns a result.

### Thread Budget Per Execution

```
Thread          What it does                   Lifetime
------          ------------                   --------
Main            try_wait loop + wall enforce   spawn -> child exit
Reader A        read stdout from pipe          spawn -> pipe EOF
Reader B        read stderr from pipe          spawn -> pipe EOF
```

3 threads per execution. With 4 workers = 12 threads max. No watchdog. No timer thread. No polling thread.

### What the Kernel Enforces (not the supervisor)

| Limit | Kernel mechanism | What happens |
|---|---|---|
| Memory | `memory.max` in cgroup | OOM killer sends SIGKILL |
| Process count | `pids.max` in cgroup | `fork()` returns EAGAIN |
| CPU rate | `cpu.max` in cgroup | Kernel throttles (doesn't kill) |
| File size | `RLIMIT_FSIZE` via setrlimit | Write returns EFBIG, SIGXFSZ sent |
| Open files | `RLIMIT_NOFILE` via setrlimit | `open()` returns EMFILE |
| Stack size | `RLIMIT_STACK` via setrlimit | SIGSEGV on overflow |

The supervisor only enforces **wall time** (kill after deadline). Everything else is delegated to kernel mechanisms that cannot be bypassed from userspace.

### What Changes From Current Code

| Action | File | What |
|---|---|---|
| **REWRITE** | `src/sandbox/supervisor.rs` | Single `launch_with_supervisor` fn, sync, no pool param |
| **MODIFY** | `src/runtime/isolate.rs` | Remove pool field, methods back to sync |
| **MODIFY** | `src/runtime/executor.rs` | Methods back to sync |
| **MODIFY** | `judge-service/src/worker.rs` | Remove pool param, use `spawn_blocking` |
| **MODIFY** | `judge-service/src/main.rs` | Remove pool init, keep pre-Tokio proxy intercept |
| **MODIFY** | `src/sandbox/mod.rs` | Remove pool export |
| **MODIFY** | `src/sandbox/proxy.rs` | Verify thin proxy is correct (read stdin, fork, exec, wait, exit) |
| **MODIFY** | `src/kernel/mod.rs` | Remove memfd export |
| **MODIFY** | `src/cli.rs` | Remove pool-socket arg, remove block_on wrapper |
| **MODIFY** | `Cargo.toml` | Remove tokio from rustbox crate |
| **MODIFY** | `Dockerfile` | Restore language defaults, remove CACHEBUST |
| **DELETE** | `src/sandbox/pool.rs` | Pool module |
| **DELETE** | `src/kernel/memfd.rs` | Memfd module (only used by pool) |
| **DELETE** | `concurrency_rewrite_summary.md` | Stale docs |
| **DELETE** | `summary.md` | Stale docs |
| **DELETE** | `walkthrough.md` | Stale docs |
| **KEEP** | `src/kernel/pidfd.rs` | Clean utility, not on hot path |
| **KEEP** | `docker/stress/*` | Test infrastructure |
| **MOVE** | `config-executor.json` | -> `docker/stress/` |
| **MOVE** | `config-judge.json` | -> `docker/stress/` |

### What Does NOT Change

- `exec/pipeline.rs` -- typestate chain (11 stages, compile-time enforced)
- `kernel/` -- cgroup, cgroup_v2, seccomp, capabilities, credentials, mount, namespace, signal
- `safety/` -- uid_pool, cleanup, safe_cleanup
- `config/` -- constants, types, loader, validator, presets
- `observability/` -- audit logging
- `verdict/` -- classifier, json_schema
- `judge-service/` -- API routes, DB layer (sqlite/postgres), job queue, rate limiter
- `tests/` -- typestate compile-fail tests, integration tests, kernel tests

### Scaling Properties

```
Layer           Handles                              Bottleneck?
-----           -------                              -----------
HTTP accept     Unbounded req/s intake               No (Tokio handles 100K+)
DB insert       Unbounded rows/s                     No (batched, async)
Queue           Buffered jobs                        No (bounded channel)
Workers         N concurrent executions (N = nproc)  YES -- this is the real limit
Drain rate      N / avg_execution_time per second    Physics -- can't beat CPU count
```

**With 4 CPUs and avg 500ms execution**: 4 / 0.5 = 8 req/s. 15K requests drain in ~31 minutes.

You scale by adding CPUs (vertical) or machines (horizontal). Not by adding architecture.
