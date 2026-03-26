---
title: Isolation Model
description: The 8-layer security model and what each layer defends against
---

Each layer defends against a different class of attack. No single layer is sufficient. Together, they make sandbox escape require simultaneously defeating all eight.

```
╔════════════════════════════════════════════════════════════════════════════╗
║ 8. NO_NEW_PRIVS                                    can't regain privileges ║
║ ╔════════════════════════════════════════════════════════════════════════╗ ║
║ ║ 7. Credential Drop                                 UID 60000, not root ║ ║
║ ║ ╔════════════════════════════════════════════════════════════════════╗ ║ ║
║ ║ ║ 6. Capabilities Zeroed                     no privilege escalation ║ ║ ║
║ ║ ║ ╔════════════════════════════════════════════════════════════════╗ ║ ║ ║
║ ║ ║ ║ 5. Seccomp-BPF                             42 syscalls blocked ║ ║ ║ ║
║ ║ ║ ║ ╔════════════════════════════════════════════════════════════╗ ║ ║ ║ ║
║ ║ ║ ║ ║ 4. Cgroups                             memory + CPU + PIDs ║ ║ ║ ║ ║
║ ║ ║ ║ ║ ╔════════════════════════════════════════════════════════╗ ║ ║ ║ ║ ║
║ ║ ║ ║ ║ ║ 3. Network NS                       no sockets, no DNS ║ ║ ║ ║ ║ ║
║ ║ ║ ║ ║ ║ ╔════════════════════════════════════════════════════╗ ║ ║ ║ ║ ║ ║
║ ║ ║ ║ ║ ║ ║ 2. Mount NS + Chroot           isolated filesystem ║ ║ ║ ║ ║ ║ ║
║ ║ ║ ║ ║ ║ ║ ╔════════════════════════════════════════════════╗ ║ ║ ║ ║ ║ ║ ║
║ ║ ║ ║ ║ ║ ║ ║ 1. PID NS                       can't see host ║ ║ ║ ║ ║ ║ ║ ║
║ ║ ║ ║ ║ ║ ║ ║                                                ║ ║ ║ ║ ║ ║ ║ ║
║ ║ ║ ║ ║ ║ ║ ║                 ┌───────────┐                  ║ ║ ║ ║ ║ ║ ║ ║
║ ║ ║ ║ ║ ║ ║ ║                 │ User Code │                  ║ ║ ║ ║ ║ ║ ║ ║
║ ║ ║ ║ ║ ║ ║ ║                 └───────────┘                  ║ ║ ║ ║ ║ ║ ║ ║
║ ║ ║ ║ ║ ║ ║ ║                                                ║ ║ ║ ║ ║ ║ ║ ║
║ ║ ║ ║ ║ ║ ║ ╚════════════════════════════════════════════════╝ ║ ║ ║ ║ ║ ║ ║
║ ║ ║ ║ ║ ║ ╚════════════════════════════════════════════════════╝ ║ ║ ║ ║ ║ ║
║ ║ ║ ║ ║ ╚════════════════════════════════════════════════════════╝ ║ ║ ║ ║ ║
║ ║ ║ ║ ╚════════════════════════════════════════════════════════════╝ ║ ║ ║ ║
║ ║ ║ ╚════════════════════════════════════════════════════════════════╝ ║ ║ ║
║ ║ ╚════════════════════════════════════════════════════════════════════╝ ║ ║
║ ╚════════════════════════════════════════════════════════════════════════╝ ║
╚════════════════════════════════════════════════════════════════════════════╝
```

| Layer | Kernel primitive | What it prevents |
|-------|-----------------|-----------------|
| 1. PID namespace | `CLONE_NEWPID` | Seeing or signalling host processes |
| 2. Mount namespace | `CLONE_NEWNS` + chroot | Accessing host filesystem |
| 3. Network namespace | `CLONE_NEWNET` | Network access (no sockets, no DNS) |
| 4. Cgroups | cgroup v2 (v1 fallback) | Memory bombs, fork bombs, CPU hogging |
| 5. Seccomp-BPF | `prctl` + BPF | Dangerous syscalls (ptrace, mount, bpf) |
| 6. Capabilities | `capset` + bounding set | Privilege escalation |
| 7. Credential drop | `setresuid`/`setresgid` | Running as root |
| 8. NO_NEW_PRIVS | `prctl(PR_SET_NO_NEW_PRIVS)` | Regaining privileges via setuid binaries |

## Namespaces (layers 1-3)

Namespaces give the sandbox its own view of the world. The sandboxed process sees PID 1 as itself, an empty network, and a minimal filesystem via chroot.

:::note[Design Note]
We use IPC namespace isolation too, but we don't use user namespaces by default. User namespaces have a long history of privilege escalation CVEs, and they're unnecessary when you have real root to set up the sandbox. We'd rather use a well-understood privilege model than add attack surface.
:::

## Cgroups (layer 4)

The enforcer for resource limits. Cgroups are the only mechanism that can actually kill a process for using too much memory - rlimits can only limit virtual memory, not resident memory.

:::note[Design Note]
We don't use cgroup v2 exclusively because Docker on older hosts often mounts a hybrid v1/v2 setup. Auto-detection with logged selection means you don't need to think about it.
:::

## Seccomp-BPF (layer 5)

A BPF program loaded into the kernel that intercepts every syscall. `io_uring` gets special treatment - it returns `ENOSYS` instead of killing the process, because some standard libraries probe for it on startup.

## Privilege stripping (layers 6-8)

After the sandbox environment is set up, we strip everything:

1. **Drop all capabilities** from bounding, ambient, effective, permitted, and inheritable sets
2. **Drop to unprivileged UID/GID** from the UID pool (range 60000-60999)
3. **Set NO_NEW_PRIVS** - even setuid binaries won't grant privileges

The order matters. You must drop capabilities before dropping UID. You must set NO_NEW_PRIVS last.

:::note[Design Note]
This ordering is enforced by the [typestate chain](/architecture/typestate/), not by convention. If you try to call `exec_payload()` before credentials are dropped, it's a compile error. We don't trust developers (including ourselves) to remember the right order.
:::
