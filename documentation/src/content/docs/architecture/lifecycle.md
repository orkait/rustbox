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

The Supervisor spawns a proxy child via `std::process::Command` with namespace unsharing in the `pre_exec` hook. The Proxy then `fork()`s the actual payload:

```
Supervisor (host)
  └── Proxy (fork+exec with pre_exec(unshare))
        └── Payload (namespaced + chrooted + cgroup + seccomp)
```

If wall time expires, the Supervisor sends `SIGKILL` to the process group immediately. No SIGTERM, no grace period. CPU time is enforced by the kernel via `cpu.max` throttling, not by the supervisor.

:::note[Design Note]
The two-process design exists because the Proxy needs to run the typestate chain after exec. `pre_exec` unshares namespaces before the process image is replaced, and the typestate chain runs inside the proxy child after exec.
:::

## Phase 4: Evidence collection

After the payload exits, the Supervisor collects wait status, cgroup evidence, timing, and process lifecycle data. This evidence bundle is immutable once collected.

## Phase 5: Cleanup

1. Wipe the workspace (fd-safe, no symlink following)
2. Remove the cgroup hierarchy
3. Remove the base path
4. Release the UID back to the pool (flock + atomic bitmap)

:::note[Design Note]
Cleanup is hygiene, not safety. The sandbox is already destroyed by this point. The PID namespace kills all descendants when the proxy exits, and cgroup removal is deterministic via `Isolate::drop`.
:::
