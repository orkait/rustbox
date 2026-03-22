---
title: Execution Lifecycle
description: The journey of a code submission from arrival to verdict
---

## Overview

<div style="max-width: 360px; margin: 0 auto;">

![Execution lifecycle flow](../../../assets/lifecycle.svg)

</div>

## Phase 1: Setup

`Isolate::new(config)` allocates a UID from the atomic bitset pool (60000-60999), creates a cgroup, and captures a baseline snapshot of the workspace.

## Phase 2: Execution

`execute_code_string()` is language-aware:

- **Python:** Writes source to a temp file, runs `python3 <file>`
- **C++:** Compiles with `g++ -O2 -std=c++17`, runs the binary
- **Java:** Compiles with `javac`, runs with `java Main`

:::note[Design Note]
C++ compilation runs outside the sandbox. `g++` links against system libraries, reads headers from system paths, and spawns `cc1plus`, `as`, and `ld`. Putting all of this inside a chroot requires mounting the entire toolchain - fragile and host-dependent. The compiled binary is a single executable that runs fine in isolation.
:::

## Phase 3: Supervision

The Supervisor `clone()`s into new namespaces. The Proxy `fork()`s the actual payload:

```
Supervisor (host)
  └── Proxy (namespaced)
        └── Payload (namespaced + chrooted + cgroup + seccomp)
```

If CPU or wall time expires, the Supervisor kills with `SIGKILL` immediately. Untrusted code doesn't get a graceful shutdown.

:::note[Design Note]
The two-process design exists because the Proxy needs to run the typestate chain before exec'ing the payload. `exec()` replaces the process image, so all setup must complete first.
:::

## Phase 4: Evidence collection

After the payload exits, the Supervisor collects wait status, cgroup evidence, timing, and process lifecycle data. This evidence bundle is immutable once collected.

## Phase 5: Cleanup

1. Kill remaining processes in the cgroup
2. Verify the baseline (workspace state matches snapshot)
3. Remove the cgroup hierarchy
4. Wipe the workspace (fd-safe, no symlink following)
5. Release the UID back to the pool

:::note[Design Note]
Cleanup is hygiene, not safety. The sandbox is already destroyed by this point. But baseline verification catches bugs in the sandbox itself: if the workspace changed unexpectedly, something in our setup is wrong.
:::
