+++
title = "Typestate Chain"
weight = 2
insert_anchor_links = "right"
+++

# Typestate Chain

The single most important safety mechanism in rustbox. It makes misordered sandbox setup a compile error, not a runtime bug.

## The problem

Setting up a Linux sandbox requires doing things in a specific order. Namespaces before mounts. Mounts before cgroups. Cgroups before credential drop. Credential drop before exec. Get the order wrong and you either break the sandbox or leave a security gap.

Every other sandbox we've looked at enforces this ordering through documentation, code review, or runtime checks. All of these can be bypassed by a tired developer at 2am.

## The solution

Rust's type system enforces the order at compile time. The sandbox progresses through a fixed sequence of states, and each transition consumes the previous state:

```
FreshChild → NamespacesReady → MountsPrivate → CgroupAttached
→ CredsDropped → PrivsLocked → ExecReady
```

Only `Sandbox<ExecReady>` has an `exec_payload()` method. You literally cannot call it on any other state.

```rust
// This compiles:
let s = Sandbox::new(config);          // FreshChild
let s = s.configure_namespaces()?;      // NamespacesReady
let s = s.setup_mounts()?;             // MountsPrivate
let s = s.attach_cgroup()?;            // CgroupAttached
let s = s.drop_credentials()?;         // CredsDropped
let s = s.lock_privileges()?;          // PrivsLocked
s.exec_payload(cmd)?;                  // ExecReady - this works

// This doesn't compile:
let s = Sandbox::new(config);
s.exec_payload(cmd)?;                  // ERROR: no method `exec_payload`
                                       //        on Sandbox<FreshChild>
```

## Why this matters

- **Can't skip steps.** Every transition is a required function call that produces the next type.
- **Can't reorder.** `drop_credentials()` only exists on `Sandbox<CgroupAttached>`, not on `FreshChild`.
- **Can't go backwards.** Each transition consumes `self` by value. The previous state is gone.
- **Verified by CI.** Compile-fail tests in `tests/typestate_compile_fail/` confirm that skipping or reordering steps produces the expected compiler error.

> **Design Note:** We considered runtime state machines (enum with match) and capability-based designs. Both push errors to runtime. Typestates push them to compile time, which means the error is caught by `cargo build`, not by a user in production. The cost is verbosity in the setup code - we think that's a good trade.

## Stages

Each stage wraps a real kernel operation:

| State | What happens | Kernel primitive |
|-------|-------------|-----------------|
| `FreshChild` | Process just cloned | `clone(2)` |
| `NamespacesReady` | PID/mount/net/IPC namespaces configured | `unshare(2)` |
| `MountsPrivate` | Chroot set up, tmpfs mounted, devices created | `mount(2)`, `chroot(2)`, `mknod(2)` |
| `CgroupAttached` | Memory/CPU/PID limits active | cgroup filesystem writes |
| `CredsDropped` | UID/GID set to unprivileged, groups cleared | `setresuid(2)`, `setresgid(2)` |
| `PrivsLocked` | All capabilities zeroed, NO_NEW_PRIVS set | `capset(2)`, `prctl(2)` |
| `ExecReady` | Seccomp filter installed, ready to exec | `seccomp(2)` |

Seccomp is installed last because the BPF filter would block the syscalls needed for the earlier stages (like `mount` and `capset`).
