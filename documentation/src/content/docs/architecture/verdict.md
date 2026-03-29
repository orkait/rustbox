---
title: Verdict System
description: How rustbox classifies execution outcomes from kernel evidence
---

Every verdict is derived from kernel evidence. No guessing, no heuristics based on exit codes alone.

## The problem with exit code heuristics

Most online judges do this:

```python
if exit_code != 0:     return "RE"
if wall_time > limit:  return "TLE"
if memory > limit:     return "MLE"
return "AC"
```

This breaks in real scenarios:
- Process OOM-killed → exit code 137. Is that RE or MLE?
- Process hit CPU limit AND crashed. Which verdict wins?
- Judge killed the process for wall timeout, but the process also received SIGXCPU. TLE from which source?

## How rustbox decides

Two stages. First the proxy status is classified, then the supervisor applies post-mortem cgroup evidence.

### Stage 1: Proxy status classification

Priority order (first match wins):

| # | Condition | Verdict |
|---|---|---|
| 1 | `timed_out == true` OR `signal == SIGXCPU` | **TLE** |
| 2 | Signal present (any other) | **SIG** (Signaled) |
| 3 | `internal_error` present | **IE** (Internal Error) |
| 4 | `exit_code == 0` | **AC** (Accepted) |
| 5 | Anything else | **RE** (Runtime Error) |

### Stage 2: Supervisor post-mortem overrides

After the child exits, the supervisor reads cgroup counters:

| Check | Override | Source |
|---|---|---|
| `cgroup.check_oom() == true` | Verdict → **MLE** | `memory.events` oom_kill counter |
| `timed_out == true` | Verdict → **TLE** | Supervisor wall timer |

**TLE always wins.** If the wall timer killed the process AND it was OOM, the verdict is TLE because the timer fired first. OOM during a timeout is a secondary symptom.

### Final evidence enrichment

```
result.cpu_time    = cgroup.get_cpu_usage()     // post-mortem read
result.memory_peak = cgroup.get_memory_peak()   // post-mortem read
```

These are informational - they don't change the verdict, but they tell you exactly how much the process used.

## Divergence detection

CPU time vs wall time ratio reveals what the process was doing:

| CPU/Wall ratio | Classification | Meaning |
|---|---|---|
| >= 0.8 | CPU-bound | Computing the whole time |
| <= 0.2 | Sleep/block-bound | Waiting on I/O or sleep |
| 0.2 - 0.8 | Host interference | System load affected results |

For competitive programming: a TLE with CPU ratio 0.95 is a genuine algorithm problem. A TLE with ratio 0.1 might be a stuck network call or bad test case.

## What makes this different

The verdict classifier in `verdict/classifier.rs` has zero `unsafe` blocks. It takes an immutable evidence bundle and returns a classification. Pure function - no syscalls, no I/O, no mutation.

If a verdict is disputed, you can replay the exact same evidence bundle and get the same result every time. The evidence includes:

- Wait outcome (exit code, signal, stop/continue)
- Cgroup evidence (memory peak, OOM events, CPU usage)
- Wall time and CPU time
- Whether the judge killed the process and why
- Process lifecycle (descendant count)
