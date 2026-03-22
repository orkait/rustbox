---
title: Cgroups
description: v1/v2 dual support, Docker compatibility, auto-detection
---

## v1 vs v2

Linux has two cgroup implementations. rustbox supports both and auto-detects:

1. `/sys/fs/cgroup/cgroup.controllers` exists → v2
2. `/sys/fs/cgroup/memory` exists → v1
3. Neither → no cgroup support (permissive mode only)

The selection is logged so you always know which backend is active.

:::note[Design Note]
We don't force v2 because Docker on older hosts (Ubuntu 20.04, CentOS 7/8) often runs a hybrid v1/v2 setup where v2 is mounted but controllers aren't delegated. Rather than fail mysteriously, we probe for writable controllers and fall back gracefully.
:::

## Docker compatibility

Inside Docker, cgroup access is restricted:

- **Probe before use.** We test writability, never assume.
- **Permissive fallback.** Can't create a cgroup? Warn and continue. Seccomp and namespaces still work.
- **Strict mode fails.** No cgroups + strict mode = rejected execution.

## Resource enforcement

| Resource | v2 | v1 |
|----------|----|----|
| Memory | `memory.max` | `memory.limit_in_bytes` |
| CPU | `cpu.max` (quota/period) | `cpu.cfs_quota_us` |
| Processes | `pids.max` | `pids.max` |
| OOM detection | `memory.events` | `memory.oom_control` |
| CPU usage | `cpu.stat` (usage_usec) | `cpuacct.usage` |
| Memory peak | `memory.peak` | `memory.max_usage_in_bytes` |

## Instance isolation

Each sandbox gets its own cgroup with a sanitised instance ID. Path traversal characters in instance IDs are rejected. On cleanup, all processes in the cgroup are killed before removal.
