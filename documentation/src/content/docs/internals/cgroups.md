---
title: Cgroups
description: Cgroup v2 resource enforcement and evidence collection
---

## Cgroup v2 only

rustbox requires cgroup v2. Cgroup v1 support was removed. The supervisor detects v2 by checking for `/sys/fs/cgroup/cgroup.controllers`.

If your host uses a hybrid v1/v2 setup, ensure the v2 hierarchy is available with `memory`, `pids`, and `cpu` controllers delegated.

## Resource enforcement

The supervisor sets cgroup limits after spawning the proxy child:

| Resource | Cgroup file | What happens on limit |
|---|---|---|
| Memory | `memory.max` | Kernel OOM kills the process (SIGKILL) |
| Processes | `pids.max` | `fork()` returns EAGAIN |
| CPU rate | `cpu.max` (quota/period) | Kernel throttles (doesn't kill) |

Wall time is enforced by the supervisor's `try_wait` poll loop, not by cgroups. CPU time is throttled by `cpu.max` but not used as a kill trigger - the wall timer catches everything.

## Post-mortem evidence

After the child exits, the supervisor reads cgroup counters:

| Metric | Cgroup file | Used for |
|---|---|---|
| CPU usage | `cpu.stat` (usage_usec) | `result.cpu_time` |
| Memory peak | `memory.peak` | `result.memory_peak` |
| OOM killed | `memory.events` (oom_kill) | Verdict = MLE |
| Full evidence | All of the above | `cgroup_evidence` in launch evidence |

## Docker compatibility

Inside Docker, cgroup access requires `--cap-add SYS_ADMIN` and `--cgroupns=host`. The supervisor:

1. Probes for writable controllers before use
2. Falls back gracefully in permissive mode (warns, continues without limits)
3. Fails closed in strict mode (rejects execution if cgroup setup fails)

## Instance isolation

Each sandbox gets a unique cgroup at `/sys/fs/cgroup/rustbox/sb-{uid}`. The instance ID is derived from the UID pool allocation (60000-60999). Path traversal in instance IDs is rejected. On cleanup, `Isolate::drop` removes the cgroup directory.

## Per-job reaper

The reaper polls every 5 seconds and checks each running job against its `wall_time_limit_secs + 10s` grace period. Jobs without a wall time limit fall back to 120s. This catches orphaned jobs from crashed nodes without interfering with legitimately long executor workloads.
