+++
title = "Cgroups"
weight = 2
insert_anchor_links = "right"
+++

# Cgroups Internals

## v1 vs v2

Linux has two cgroup implementations. v2 is the modern one (unified hierarchy, better resource accounting). v1 is the legacy one (per-controller hierarchies, widely deployed).

rustbox supports both and auto-detects which one to use:

1. Check if `/sys/fs/cgroup/cgroup.controllers` exists → v2
2. Check if `/sys/fs/cgroup/memory` exists → v1
3. Neither → no cgroup support (permissive mode only)

The detection is logged, so you always know which backend is active.

> **Design Note:** We don't force v2 because Docker on older hosts (Ubuntu 20.04, CentOS 7/8) often runs a hybrid v1/v2 setup where v2 is mounted but controllers aren't delegated. Rather than fail mysteriously, we probe for writable controllers and fall back gracefully.

## Docker compatibility

Inside Docker, cgroup access is restricted. We handle this:

- **Probe before use.** We don't assume a cgroup path is writable. We test it.
- **Permissive fallback.** If we can't create a cgroup (container doesn't have the right mounts), we warn and continue without memory/CPU enforcement. Seccomp and namespaces still work.
- **Strict mode fails.** If you ask for strict mode and cgroups aren't available, we reject the execution. No partial security.

## Resource enforcement

| Resource | v2 mechanism | v1 mechanism |
|----------|-------------|-------------|
| Memory | `memory.max` | `memory.limit_in_bytes` |
| CPU | `cpu.max` (quota/period) | `cpu.cfs_quota_us` + `cpu.cfs_period_us` |
| Processes | `pids.max` | `pids.max` |
| OOM detection | `memory.events` (oom, oom_kill) | `memory.oom_control` |
| CPU usage | `cpu.stat` (usage_usec) | `cpuacct.usage` |
| Memory peak | `memory.peak` or `memory.max_usage_in_bytes` | `memory.max_usage_in_bytes` |

## Instance isolation

Each sandbox gets its own cgroup with a sanitised instance ID:

```
/sys/fs/cgroup/rustbox/instance-abc123/
```

The instance ID is checked for path traversal characters. `../` in an instance ID is rejected.

On cleanup, we kill all processes in the cgroup before removing it. This prevents resource leaks from orphaned descendants.
