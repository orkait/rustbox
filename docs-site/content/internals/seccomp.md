+++
title = "Seccomp"
weight = 1
insert_anchor_links = "right"
+++

# Seccomp Internals

## Why deny-list, not allowlist

This is the most common question about our seccomp design, and the answer is practical:

**Allowlist** (nsjail-style for simple binaries): You enumerate every syscall the process is allowed to make. Everything else is blocked. This is the most secure approach - if you know exactly what syscalls your program needs.

**Deny-list** (our approach): You block the specific syscalls that enable sandbox escape. Everything else is allowed.

We chose deny-list because:

1. **Python** calls 100+ different syscalls during `import sys`. The allowlist would be enormous and break on Python 3.12 → 3.13 upgrades.
2. **Java** spawns threads, uses futex, mmap, clone - the JVM's syscall profile changes between minor versions.
3. **C++ standard library** probes for features (io_uring, statx) at startup. Blocking probes kills innocent programs.

nsjail uses allowlists for simple, controlled workloads (a single static binary). They use deny-lists for complex runtimes. We only run complex runtimes, so deny-list is the right default.

**Users can supply their own policy** via `--seccomp-policy` if they need tighter control for a specific use case.

## Implementation

We use the `seccompiler` crate (from AWS Firecracker). It builds BPF programs from Rust data structures. No raw BPF assembly.

```rust
const BUILTIN_DENY_LIST: &[SyscallRule] = &[
    SyscallRule { name: "io_uring_setup",  action: Errno(ENOSYS) },  // probe-safe
    SyscallRule { name: "ptrace",          action: KillProcess },
    SyscallRule { name: "process_vm_readv", action: KillProcess },
    // ... 15 more
];
```

Two actions are used:

- **`Errno(ENOSYS)`** for probe syscalls (io_uring). The process gets "not supported" and continues.
- **`KillProcess`** for exploit syscalls (ptrace, bpf, mount). The process is terminated immediately.

Because seccompiler doesn't support mixed actions in a single filter, we install two BPF programs stacked:

1. First filter: ENOSYS rules (DEFAULT ALLOW, specific syscalls return ENOSYS)
2. Second filter: KILL rules (DEFAULT ALLOW, specific syscalls kill)

BPF filters compose with AND semantics - both must allow the syscall for it to proceed.

## Custom policies

Users can provide a JSON policy file:

```json
{
  "rules": [
    { "name": "socket", "action": "kill" },
    { "name": "connect", "action": "kill" }
  ]
}
```

Custom policies replace the built-in deny-list entirely. If you supply a custom policy, you own the security posture.
