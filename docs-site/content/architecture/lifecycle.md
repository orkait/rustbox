+++
title = "Execution Lifecycle"
weight = 4
insert_anchor_links = "right"
+++

# Execution Lifecycle

The journey of a code submission from arrival to verdict.

## Overview

```
Isolate::new()          Allocate UID, create cgroup, capture baseline
       │
execute_code_string()   Write source, compile if needed, build command
       │
  Supervisor            clone() into new namespaces
       │
    Proxy               fork() payload through typestate chain
       │
  ┌────┴────┐
  │ Payload │           User code runs here (isolated)
  └────┬────┘
       │
  Evidence collection   Read cgroup stats, wait status, timing
       │
  Verdict classification Pure function over evidence bundle
       │
  Isolate::cleanup()    Verify baseline, remove cgroup, wipe workdir, release UID
```

## Phase 1: Setup

`Isolate::new(config)` does three things:

1. **Allocates a UID** from the atomic bitset pool (range 60000-60999). Each sandbox gets a unique UID so concurrent executions can't interfere with each other's files.
2. **Creates a cgroup** for resource enforcement. The cgroup path includes the instance ID for cleanup targeting.
3. **Captures a baseline** snapshot of the workspace for post-execution verification.

## Phase 2: Execution

`execute_code_string()` is language-aware:

- **Python:** Writes source to a temp file, runs `python3 <file>`
- **C++:** Writes source, compiles with `g++ -O2 -std=c++17`, runs the binary. Compilation happens outside the sandbox for toolchain stability. Only the compiled binary runs isolated.
- **Java:** Writes source as `Main.java`, compiles with `javac`, runs with `java Main`. JVM gets higher process limits (1024 vs 10) because it's... the JVM.

> **Design Note:** C++ compilation outside the sandbox is a deliberate choice. `g++` links against system libraries, reads headers from system paths, and spawns `cc1plus`, `as`, and `ld`. Putting all of this inside a chroot requires mounting the entire toolchain into the sandbox, which is fragile and host-dependent. The compiled binary is a single static executable that runs fine in isolation.

## Phase 3: Supervision

The Supervisor `clone()`s a child process into new namespaces. Inside, the Proxy `fork()`s the actual payload:

```
Supervisor (host)
  └── Proxy (namespaced)
        └── Payload (namespaced + chrooted + cgroup + seccomp)
```

The Supervisor watches from outside with two timers:

- **CPU time** - polled from `cgroup.stat` or `cpuacct.usage`
- **Wall time** - monotonic clock

If either expires, the Supervisor kills the process group with `SIGKILL`. Escalation is immediate - we don't send `SIGTERM` first. Untrusted code doesn't get a graceful shutdown period.

> **Design Note:** The two-process design (Proxy + Payload) exists because the Proxy needs to set up the sandbox environment (typestate chain) before exec'ing the payload. A single process can't do both: `exec()` replaces the process image, so all setup must complete before exec. The Proxy runs the typestate chain, then `exec()`s the payload into the same isolated environment.

## Phase 4: Evidence collection

After the payload exits (or is killed), the Supervisor collects:

- **Wait status** from `waitpid()` - exit code, signal
- **Cgroup evidence** - memory peak, OOM events, CPU usage
- **Timing** - wall clock elapsed, CPU time consumed
- **Process lifecycle** - were all descendants reaped? Any zombies?

This evidence bundle is immutable once collected. The verdict classifier gets a read-only view.

## Phase 5: Cleanup

`Isolate::cleanup()` is where trust is verified:

1. **Kill any remaining processes** in the cgroup (defence against orphaned descendants)
2. **Verify the baseline** - compare current workspace state against the snapshot from Phase 1. If they don't match, something unexpected happened.
3. **Remove the cgroup** hierarchy
4. **Wipe the workspace** using fd-safe recursive deletion (no symlink following)
5. **Release the UID** back to the atomic pool

> **Design Note:** Cleanup is not safety-critical - it's hygiene. The sandbox is already destroyed by this point (the namespace is gone, the cgroup is empty). But baseline verification catches bugs in the sandbox itself: if the workspace changed in ways we didn't expect, something in our setup is wrong. This is how we test the sandbox, not how we protect against users.
