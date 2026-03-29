---
title: Execution Lifecycle
description: The journey of a code submission from arrival to verdict
---

## Overview

```
┌───────────┐     ┌───────────┐     ┌──────────────────────────────┐     ┌─────────────┐     ┌─────────┐     ┌──────────────┐
│   new()   │ --> │  compile  │ --> │Supervisor --> Proxy --> Code │ --> │  evidence   │ --> │ verdict │ --> │  cleanup()   │
│ alloc UID │     │ if needed │     │     typestate --> exec()     │     │ cgroup+wait │     │ pure fn │     │ wipe+release │
└───────────┘     └───────────┘     └──────────────────────────────┘     └─────────────┘     └─────────┘     └──────────────┘
```

## Phase 1: Setup

`Isolate::new(config)` allocates a UID from the atomic bitset pool (60000-60999), creates a cgroup, and sets up the workspace directory.

## Phase 2: Execution

`execute_code_string()` is language-aware:

- **Python:** Writes source to a temp file, runs `python3 <file>`
- **C++:** Compiles with `g++ -O2 -std=c++17`, runs the binary
- **Java:** Compiles with `javac`, runs with `java Main`

:::note[Design Note]
C++ compilation runs outside the sandbox. `g++` links against system libraries, reads headers from system paths, and spawns `cc1plus`, `as`, and `ld`. Putting all of this inside a chroot requires mounting the entire toolchain - fragile and host-dependent. The compiled binary is a single executable that runs fine in isolation.
:::

## Phase 3: Supervision

The Supervisor is one sync function, 250 lines. Here's what happens step by step:

1. **Spawn proxy** - `Command::new(rustbox --proxy)` with `pre_exec(unshare)` creates a child in new namespaces
2. **Attach cgroup** - memory, process, and CPU limits set on the child's PID
3. **Send request** - write JSON to child's stdin, close the pipe
4. **Read output** - two threads read stdout and stderr (capped at output limit)
5. **Wait** - poll `try_wait()` every 10ms until child exits or wall time expires
6. **Kill if needed** - `SIGKILL` to process group on timeout, no grace period
7. **Collect evidence** - read cgroup counters (cpu_time, memory_peak, OOM)
8. **Build verdict** - pure function over the evidence

Meanwhile inside the proxy child: read the request from stdin, fork a payload child, run the 9-stage typestate chain, execvp the user code, waitpid, exit.

3 threads total per execution. No watchdog, no timer thread, no async.

:::note[Design Note]
The two-process design exists because `pre_exec` runs between fork and exec - it can only do async-signal-safe operations like `unshare()`. The full typestate chain (mounts, chroot, rlimits, seccomp) needs to run in a clean process after exec. So the proxy is born via fork+exec with namespaces pre-applied, then it does the rest.
:::

## Phase 4: Evidence collection

After the child exits, the Supervisor reads cgroup counters post-mortem:

- `cpu.stat usage_usec` → `result.cpu_time`
- `memory.peak` → `result.memory_peak`
- `memory.events oom_kill` → verdict override to MLE
- `collect_evidence()` → full cgroup evidence for audit trail

These are reads, not polls. The process is already dead. The numbers are final.

## Phase 5: Cleanup

1. Wipe the workspace (fd-safe, no symlink following)
2. Remove the cgroup hierarchy
3. Remove the base path
4. Release the UID back to the pool (flock + atomic bitmap)

:::note[Design Note]
Cleanup is hygiene, not safety. The sandbox is already destroyed by this point. The PID namespace kills all descendants when the proxy exits, and cgroup removal is deterministic via `Isolate::drop`.
:::
