---
title: Seccomp
description: Deny-list design, custom policies, the seccompiler crate
---

## Why deny-list, not allowlist

This is the most common question about our seccomp design.

**Allowlist** (nsjail-style for simple binaries): enumerate every allowed syscall. Everything else is blocked. Most secure if you know exactly what your program needs.

**Deny-list** (our approach): block the specific syscalls that enable sandbox escape. Everything else is allowed.

We chose deny-list because:

1. **Python** calls 100+ different syscalls during `import sys`. An allowlist would be enormous and break on version upgrades.
2. **Java** spawns threads, uses futex, mmap, clone - the JVM's syscall profile changes between minor versions.
3. **C++ standard library** probes for features (io_uring, statx) at startup. Blocking probes kills innocent programs.

nsjail uses allowlists for simple, controlled workloads. They use deny-lists for complex runtimes. We only run complex runtimes.

## Implementation

We use the `seccompiler` crate (from AWS Firecracker). It builds BPF programs from Rust data structures:

```rust
const BUILTIN_DENY_LIST: &[SyscallRule] = &[
    SyscallRule { name: "io_uring_setup",   action: Errno(ENOSYS) },
    SyscallRule { name: "ptrace",           action: KillProcess },
    SyscallRule { name: "process_vm_readv",  action: KillProcess },
    // ... 15 more
];
```

Two actions:
- **`Errno(ENOSYS)`** for probe syscalls (io_uring) - process gets "not supported" and continues
- **`KillProcess`** for exploit syscalls (ptrace, bpf, mount) - immediate termination

Two BPF programs are stacked (seccompiler doesn't support mixed actions in one filter). Both must allow the syscall for it to proceed.

## Custom policies

```bash
judge execute-code --seccomp-policy /path/to/policy.json --language python --code '...'
```

Custom policies replace the built-in deny-list entirely. You own the security posture.
