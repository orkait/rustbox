---
title: Architecture Overview
description: How rustbox composes Linux primitives into a sandbox
---

rustbox is a Linux-native process sandbox. No containers, no VMs, no abstraction layers between your code and the kernel primitives that actually enforce isolation.

## The core idea

Every sandbox is a bet: "I can run your code without it affecting anything else on this machine." Most systems make that bet with thick abstraction layers (Docker, gVisor, Firecracker). rustbox makes it with direct kernel primitives, composed in a fixed order that's enforced at compile time.

The result is a 3MB sandbox binary (+ 10MB judge-service) that provides 8 layers of isolation, evidence-backed verdicts, and 260+ req/s throughput with full kernel enforcement.

## How a request flows

Two binaries. `judge-service` handles HTTP (async, Tokio). `rustbox` runs sandboxes (sync, no Tokio).

1. HTTP request arrives at `judge-service`
2. Validated, inserted into DB, queued
3. Worker picks it up, calls `spawn_blocking` to bridge into sync code
4. `Isolate::new()` allocates UID, creates cgroup, sets up workspace
5. `executor` dispatches by language (interpreted or compile+run)
6. `supervisor` spawns proxy via `Command::new` with `pre_exec(unshare)`
7. Supervisor attaches cgroup, pipes stdin, reads stdout/stderr, enforces wall time
8. Inside the proxy: typestate chain (9 stages) → `execvp` → user code runs
9. Child exits. Supervisor reads cgroup evidence post-mortem
10. `verdict` classifies the result from evidence (pure function)
11. Result stored in DB, webhook fired if configured, HTTP response sent

One execution path. No branching, no fallbacks, no dual modes.

## Modules

| Module | What it does | Unsafe? |
|---|---|---|
| `judge-service/` | HTTP API (axum), SQLite/Postgres, queue, webhooks | No (Tokio async) |
| `runtime/isolate` | Allocates UID + cgroup + workspace per execution | No |
| `runtime/executor` | Language dispatch: interpreted vs compile+run | No |
| `sandbox/supervisor` | Spawns proxy, pipes I/O, wall timeout, evidence collection | No (calls kernel/) |
| `sandbox/proxy` | Reads request, forks payload, runs typestate chain | No (calls exec/) |
| `exec/pipeline` | 9-stage typestate chain ending in execvp | No (calls kernel/) |
| `kernel/` | cgroups, seccomp, capabilities, mount, namespace, credentials | **Yes** - all unsafe lives here |
| `verdict/` | Evidence bundle → verdict classification | **No** - zero unsafe, pure functions |
| `safety/` | UID pool (atomic + flock), secure file cleanup | No |
| `config/` | JSON config loader, validation, constants | No |

**The boundary:** `kernel/` wraps every unsafe syscall. Nothing outside it touches libc. `verdict/` has zero unsafe blocks - it takes immutable evidence and returns a classification.
