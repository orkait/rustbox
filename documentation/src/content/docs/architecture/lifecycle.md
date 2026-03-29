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

The Supervisor (`launch_with_supervisor`) is one sync function, 250 lines, 8 sequential phases:

```
Supervisor (main thread)              Proxy child
│                                     │
│  Command::new(rustbox --proxy)      │
│    .pre_exec(unshare(IPC|UTS|PID|   │
│     MNT|NET))                       │
│    .stdin(piped)                    │
│    .stdout(piped)                   │
│    .stderr(piped)                   │
│    .spawn() ──────────────────────► │ born in new namespaces
│                                     │
│  cgroup.attach(child_pid)           │ reads request JSON from stdin
│  cgroup.set_memory_limit()          │ setpgid(0,0) + parent death signal
│  cgroup.set_process_limit()         │ fork() payload child
│  cgroup.set_cpu_limit()             │   └── typestate chain (9 stages)
│                                     │       └── execvp(user code)
│  stdin.write(request_json)          │
│  drop(stdin)                        │ waitpid(payload)
│                                     │ reap descendants
│  thread A: read stdout (capped)     │ exit(code)
│  thread B: read stderr (capped)     │
│                                     │
│  loop {                             │
│    child.try_wait()                 │
│    if exited → break                │
│    if elapsed >= wall_limit →       │
│      kill(-pgid, SIGKILL)           │
│      break                          │
│    sleep(10ms)                      │
│  }                                  │
│                                     │
│  join readers                       │
│  collect cgroup evidence            │
│  build verdict                      │
```

3 threads per execution: main (wait loop + wall enforcement), reader A (stdout), reader B (stderr). No watchdog, no timer thread, no async.

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
