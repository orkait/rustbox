---
title: Architecture Overview
description: How rustbox composes Linux primitives into a sandbox
---

rustbox is a Linux-native process sandbox. No containers, no VMs, no abstraction layers between your code and the kernel primitives that actually enforce isolation.

## The core idea

Every sandbox is a bet: "I can run your code without it affecting anything else on this machine." Most systems make that bet with thick abstraction layers (Docker, gVisor, Firecracker). rustbox makes it with direct kernel primitives, composed in a fixed order that's enforced at compile time.

The result is a 3MB sandbox binary (+ 10MB judge-service) that provides 8 layers of isolation, evidence-backed verdicts, and 260+ req/s throughput with full kernel enforcement.

## Module map

```
┌────────────────┐     ┌──────────┐     ┌─────────────────────┐     ┌─────────────────┐     ┌───────────────┐
│ CLI / HTTP API │ --> │ runtime/ │ --> │  sandbox/ + exec/   │ --> │     kernel/     │ --> │    safety/    │
│ (judge-service)│     │ isolate  │     │ supervisor+typestate │     │ cgroups,seccomp │     │ uid pool      │
└────────────────┘     └──────────┘     └─────────────────────┘     │ caps,mount,ns   │     │ safe cleanup  │
                                                                    └─────────────────┘     └───────────────┘
                       ┌──────────┐     ┌─────────────────────┐
                       │ verdict/ │     │      config/        │
                       │ pure fns │     │ types,loader,valid  │
                       └──────────┘     └─────────────────────┘
```

**Key boundaries:**
- `verdict/` is pure logic - zero unsafe blocks, zero syscalls. Takes evidence in, returns classification.
- `kernel/` wraps every unsafe syscall. Nothing outside this module touches libc directly.
- `sandbox/supervisor.rs` is the single execution path - one function, sync, 250 lines.
- `judge-service/` is the async HTTP layer. It calls `spawn_blocking` to bridge into the sync sandbox core. Tokio lives here and nowhere else.
