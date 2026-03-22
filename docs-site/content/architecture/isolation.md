+++
title = "Isolation Model"
weight = 1
insert_anchor_links = "right"
+++

# The 8-Layer Security Model

Each layer defends against a different class of attack. No single layer is sufficient. Together, they make sandbox escape require simultaneously defeating all eight.

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

## Layer 1-3: Namespaces

Namespaces give the sandbox its own view of the world. The sandboxed process sees:

- **PID 1** as itself (can't see or signal host processes)
- **Empty network** (no interfaces, no sockets)
- **Minimal filesystem** via chroot (only `/bin`, `/lib`, `/usr` read-only, plus a tmpfs workspace)

> **Design Note:** We use IPC namespace isolation too (`CLONE_NEWIPC`), but we don't use user namespaces by default. User namespaces have a long history of privilege escalation CVEs, and they're unnecessary when you have real root to set up the sandbox. We'd rather use a well-understood privilege model than add attack surface.

## Layer 4: Cgroups

Cgroups are the enforcer for resource limits. They're the only mechanism that can actually kill a process for using too much memory - rlimits can only limit virtual memory, not resident memory.

- **Memory limit** - hard cap, OOM kills if exceeded
- **CPU quota** - enforced by the kernel scheduler
- **Process limit** - caps fork bombs (pids.max)

We auto-detect cgroup v2 and fall back to v1. The selection is logged so you always know which backend is active.

> **Design Note:** We don't use cgroup v2 exclusively because Docker on older hosts often mounts a hybrid v1/v2 setup. Auto-detection with logged selection means you don't need to think about it, but you can always see what happened.

## Layer 5: Seccomp-BPF

A BPF program loaded into the kernel that intercepts every syscall. Our default deny-list blocks 18 syscalls that enable sandbox escape (io_uring, ptrace, bpf, mount, etc.).

`io_uring` gets special treatment: it returns `ENOSYS` instead of killing the process. This is because some standard library probes check for io_uring support on startup - killing the process for a probe would break innocent programs.

> **Design Note:** See the [Seccomp internals](/internals/seccomp/) page for why we chose a deny-list over an allowlist, and how custom policies work.

## Layer 6-8: Privilege stripping

After the sandbox environment is set up, we strip everything the process doesn't need:

1. **Drop all capabilities** from the bounding, ambient, effective, permitted, and inheritable sets. The process can't `CAP_SYS_ADMIN` its way out.
2. **Drop to unprivileged UID/GID** (from the UID pool, range 60000-60999). The process is nobody.
3. **Set NO_NEW_PRIVS.** Even if there's a setuid binary in the chroot (there isn't), executing it won't grant privileges.

These three happen in order, and the order matters. You must drop capabilities before dropping UID (otherwise you lose the ability to drop capabilities). You must set NO_NEW_PRIVS last (it's irreversible, and you want everything else done first).

> **Design Note:** This ordering is enforced by the [typestate chain](/architecture/typestate/), not by convention or documentation. If you try to call `exec_payload()` before credentials are dropped, it's a compile error. We don't trust developers (including ourselves) to remember the right order.
