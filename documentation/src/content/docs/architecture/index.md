---
title: Architecture Overview
description: How rustbox composes Linux primitives into a sandbox
---

rustbox is a Linux-native process sandbox. No containers, no VMs, no abstraction layers between your code and the kernel primitives that actually enforce isolation.

## The core idea

Every sandbox is a bet: "I can run your code without it affecting anything else on this machine." Most systems make that bet with thick abstraction layers (Docker, gVisor, Firecracker). rustbox makes it with direct kernel primitives, composed in a fixed order that's enforced at compile time.

The result is a 3MB sandbox binary (+ 10MB judge-service) that provides 8 layers of isolation, evidence-backed verdicts, and 260+ req/s throughput with full kernel enforcement.

## How it fits together

Two binaries, one codebase. The HTTP service wraps the sandbox core. The sandbox core is sync - no async, no Tokio.

```
judge-service (async, Tokio)
│
│  HTTP request arrives
│  DB insert (r2d2 SQLite pool or Postgres)
│  Queue dispatch
│  spawn_blocking ──────────────────────────────────┐
│                                                    │
│                              rustbox core (sync)   │
│                              ┌─────────────────────┤
│                              │                     │
│                              │  runtime/isolate    │  Allocates UID, creates cgroup,
│                              │       │             │  creates workspace
│                              │       ▼             │
│                              │  runtime/executor   │  Language dispatch:
│                              │       │             │  interpreted or compile+run
│                              │       ▼             │
│                              │  sandbox/supervisor │  THE SINGLE PATH
│                              │       │             │  Command::new + pre_exec(unshare)
│                              │       │             │  stdin pipe, stdout/stderr readers
│                              │       │             │  try_wait poll loop (wall timeout)
│                              │       │             │  post-mortem cgroup evidence
│                              │       ▼             │
│                              │  sandbox/proxy      │  Reads request from stdin
│                              │       │             │  fork() payload child
│                              │       ▼             │
│                              │  exec/pipeline      │  11-stage typestate chain:
│                              │       │             │  namespaces → mounts → cgroup
│                              │       │             │  → chroot → rlimits → creds
│                              │       │             │  → caps → seccomp → execvp
│                              │       ▼             │
│                              │  kernel/*           │  All unsafe syscall wrappers:
│                              │                     │  cgroup_v2, seccomp, capabilities,
│                              │                     │  credentials, mount, namespace
│                              │                     │
│                              │  verdict/           │  Pure functions, zero unsafe.
│                              │                     │  Evidence bundle → verdict
│                              │                     │
│                              │  safety/            │  UID pool (atomic + flock),
│                              │                     │  secure cleanup
│                              └─────────────────────┘
│                                                    │
│  Result back ◄────────────────────────────────────┘
│  DB update
│  Webhook delivery (if configured)
│  HTTP response
```

**The rules:**
- `kernel/` is the only place that touches `unsafe` syscalls. Everything above it calls safe Rust APIs.
- `verdict/` has zero `unsafe` blocks. It takes an evidence bundle and returns a classification. Pure function.
- `sandbox/supervisor.rs` is the single execution path. One function, sync, 250 lines. No pool, no async, no dual paths.
- Tokio lives in `judge-service/` only. The core `rustbox` crate has zero async dependencies.
