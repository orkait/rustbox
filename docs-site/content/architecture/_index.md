+++
title = "Architecture"
weight = 3
sort_by = "weight"
insert_anchor_links = "right"
+++

# Architecture

rustbox is a Linux-native process sandbox. No containers, no VMs, no abstraction layers between your code and the kernel primitives that actually enforce isolation.

## The core idea

Every sandbox is a bet: "I can run your code without it affecting anything else on this machine." Most systems make that bet with thick abstraction layers (Docker, gVisor, Firecracker). rustbox makes it with direct kernel primitives, composed in a fixed order that's enforced at compile time.

The result is a 2.8MB binary that provides 8 layers of isolation, evidence-backed verdicts, and deterministic resource enforcement.

## Module map

```
┌─────────────────────────────────────────────┐
│                   CLI / API                  │
├─────────────────────────────────────────────┤
│              runtime/isolate.rs              │  Lifecycle: new → execute → cleanup
├──────────┬──────────┬───────────────────────┤
│ verdict/ │ config/  │     observability/     │  Pure logic, no syscalls
├──────────┴──────────┴───────────────────────┤
│           core/supervisor + proxy            │  Process management: clone, waitpid
├─────────────────────────────────────────────┤
│          exec/preexec (typestate chain)      │  Compile-time ordered setup
├─────────────────────────────────────────────┤
│                  kernel/                     │  Thin unsafe wrappers over Linux
│  namespaces │ cgroups │ seccomp │ mount │ …  │  primitives. All unsafe lives here.
├─────────────────────────────────────────────┤
│             safety/ + utils/                 │  Cleanup, UID pool, fd hygiene
└─────────────────────────────────────────────┘
```

Each layer only talks to the layer directly below it. `verdict/` never touches the kernel. `kernel/` never makes policy decisions. This isn't just good architecture - it's the reason the unsafe audit passes: `verdict/` has zero unsafe blocks because it never needs to touch a syscall.

## What to read next

- [Isolation Model](/architecture/isolation/) - the 8 security layers and what each one does
- [Typestate Chain](/architecture/typestate/) - how compile-time enforcement works
- [Verdict System](/architecture/verdict/) - evidence-based classification
- [Execution Lifecycle](/architecture/lifecycle/) - from `Isolate::new()` to cleanup
