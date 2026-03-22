---
title: Typestate Chain
description: Compile-time enforcement of sandbox setup ordering
---

The single most important safety mechanism in rustbox. It makes misordered sandbox setup a compile error, not a runtime bug.

## The problem

Setting up a Linux sandbox requires doing things in a specific order. Namespaces before mounts. Mounts before cgroups. Cgroups before credential drop. Get the order wrong and you either break the sandbox or leave a security gap.

Every other sandbox enforces this through documentation, code review, or runtime checks. All of these can be bypassed by a tired developer at 2am.

## The solution

Rust's type system enforces the order at compile time:

```
FreshChild → NamespacesReady → MountsPrivate → CgroupAttached
→ CredsDropped → PrivsLocked → ExecReady
```

Only `Sandbox<ExecReady>` has an `exec_payload()` method. You literally cannot call it on any other state.

```rust
// This compiles:
let s = Sandbox::new(config);          // FreshChild
let s = s.configure_namespaces()?;     // NamespacesReady
let s = s.setup_mounts()?;            // MountsPrivate
let s = s.attach_cgroup()?;           // CgroupAttached
let s = s.drop_credentials()?;        // CredsDropped
let s = s.lock_privileges()?;         // PrivsLocked
s.exec_payload(cmd)?;                 // ExecReady ✓

// This doesn't compile:
let s = Sandbox::new(config);
s.exec_payload(cmd)?;                 // ✗ no method on Sandbox<FreshChild>
```

## Why this matters

- **Can't skip steps.** Every transition is a required function call.
- **Can't reorder.** `drop_credentials()` only exists on `Sandbox<CgroupAttached>`.
- **Can't go backwards.** Each transition consumes `self` by value.
- **Verified by CI.** Compile-fail tests confirm that wrong ordering produces the expected compiler error.

:::note[Design Note]
We considered runtime state machines (enum with match) and capability-based designs. Both push errors to runtime. Typestates push them to compile time - caught by `cargo build`, not by a user in production. The cost is verbosity in setup code. We think that's a good trade.
:::

## Stages

| State | What happens | Kernel primitive |
|-------|-------------|-----------------|
| `FreshChild` | Process just cloned | `clone(2)` |
| `NamespacesReady` | PID/mount/net/IPC configured | `unshare(2)` |
| `MountsPrivate` | Chroot, tmpfs, devices created | `mount(2)`, `chroot(2)`, `mknod(2)` |
| `CgroupAttached` | Memory/CPU/PID limits active | cgroup filesystem writes |
| `CredsDropped` | UID/GID unprivileged, groups cleared | `setresuid(2)`, `setresgid(2)` |
| `PrivsLocked` | All capabilities zeroed, NO_NEW_PRIVS | `capset(2)`, `prctl(2)` |
| `ExecReady` | Seccomp filter installed | `seccomp(2)` |

Seccomp is installed last because the BPF filter would block syscalls needed for earlier stages (like `mount` and `capset`).
