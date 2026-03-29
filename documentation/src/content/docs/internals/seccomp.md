---
title: Seccomp
description: Deny-list design, custom policies, the seccompiler crate
---

## Why deny-list, not allowlist

**Allowlist** (nsjail-style for simple binaries): enumerate every allowed syscall. Everything else is blocked. Most secure if you know exactly what your program needs.

**Deny-list** (our approach): block the specific syscalls that enable sandbox escape. Everything else is allowed.

We chose deny-list because:

1. **Python** calls 100+ different syscalls during `import sys`. An allowlist would be enormous and break on version upgrades.
2. **Java** spawns threads, uses futex, mmap, clone - the JVM's syscall profile changes between minor versions.
3. **C++ standard library** probes for features (io_uring, statx) at startup. Blocking probes kills innocent programs.

nsjail uses allowlists for simple, controlled workloads. They use deny-lists for complex runtimes. We only run complex runtimes.

## The 52-syscall deny-list

| Family | Syscalls | Action | Why |
|--------|----------|--------|-----|
| io_uring | `io_uring_setup`, `io_uring_enter`, `io_uring_register` | ERRNO(ENOSYS) | Kernel LPE history (CVE-2021-41073, CVE-2023-2598) |
| Tracing | `ptrace`, `process_vm_readv`, `process_vm_writev` | KILL | Cross-process inspection |
| Kernel subsystems | `bpf`, `userfaultfd`, `perf_event_open` | KILL | eBPF loading, page fault interception, perf abuse |
| Module loading | `kexec_load`, `kexec_file_load`, `init_module`, `finit_module`, `delete_module` | KILL | Kernel module/boot manipulation |
| Mount/swap | `mount`, `umount2`, `pivot_root`, `swapon`, `swapoff` | KILL | Filesystem manipulation |
| New mount API | `fsopen`, `fsmount`, `fsconfig`, `fspick`, `move_mount`, `open_tree`, `mount_setattr` | KILL | Linux 5.2+ mount manipulation |
| Namespace escape | `unshare`, `chroot`, `setns` | KILL | Nested namespace creation, chroot escape |
| DAC bypass | `name_to_handle_at`, `open_by_handle_at` | KILL | File handle manipulation (CVE-2014-0038) |
| System clock | `reboot`, `settimeofday`, `clock_settime`, `acct` | KILL | System state manipulation |
| Kernel keyring | `add_key`, `keyctl`, `request_key` | KILL | Not namespaced (CVE-2016-0728) |
| NUMA | `mbind`, `set_mempolicy`, `move_pages` | KILL | Memory policy manipulation |
| Execution domain | `personality` | ERRNO(EPERM) | Blocks READ_IMPLIES_EXEC |

Two actions:
- **`Errno(ENOSYS)`** for probe syscalls (io_uring, personality) - process gets "not supported" and continues
- **`KillProcess`** for exploit syscalls (ptrace, bpf, mount) - immediate termination

## Implementation

We use the `seccompiler` crate (from AWS Firecracker). It builds BPF programs from Rust data structures.

Two BPF programs are stacked because seccompiler only supports one match-action per filter. Both must allow the syscall for it to proceed. The kernel uses the most restrictive result.

## Custom policies

```bash
rustbox execute-code --seccomp-policy /path/to/policy.json --language python --code '...'
```

Policy format:

```json
{
  "default_action": "allow",
  "rules": [
    {
      "action": "kill_process",
      "syscalls": ["ptrace", "bpf", "mount"]
    },
    {
      "action": "errno_enosys",
      "syscalls": ["io_uring_setup", "io_uring_enter"]
    }
  ]
}
```

Supported actions: `kill_process`, `errno_enosys`, `errno_eperm`, `trap`, `allow`.

Custom policies replace the built-in deny-list entirely. You own the security posture.
