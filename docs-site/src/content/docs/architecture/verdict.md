---
title: Verdict System
description: Evidence-based classification - every verdict is a pure function over kernel evidence
---

Every verdict in rustbox is a pure function over kernel evidence. We never guess.

## The problem with most judges

Most online judges classify verdicts like this:

```python
if exit_code != 0:     return "Runtime Error"
if wall_time > limit:  return "Time Limit"
if memory > limit:     return "Memory Limit"
return "Accepted"
```

This is wrong in subtle ways. What if the process was OOM-killed with exit code 137? Is that RE or MLE? What if the process hit a CPU time limit but the wall clock hasn't expired? What if the judge killed the process for timeout but the process also crashed independently?

## Evidence bundles

rustbox collects evidence from multiple kernel sources before making a verdict:

- **Wait outcome** - exit code, terminating signal, stop/continue status
- **Judge actions** - what the judge did (timer kills, escalations)
- **Cgroup evidence** - memory peak, OOM events, CPU usage
- **Timing evidence** - wall time, CPU time, divergence classification
- **Process lifecycle** - descendant containment, zombie count
- **Collection errors** - what we failed to collect

The verdict classifier takes this bundle and applies a decision tree:

1. **Cleanup failure?** → Internal Error (evidence integrity compromised)
2. **Evidence collection errors?** → Internal Error
3. **Judge killed the process?** → Check why (timeout → TLE, OOM → MLE)
4. **OOM events in cgroup?** → Memory Limit Exceeded
5. **Exit code 0?** → Accepted
6. **Non-zero exit?** → Runtime Error
7. **Signal without attribution?** → Signaled

:::note[Design Note]
The verdict classifier lives in `verdict/` which has zero `unsafe` blocks - enforced by CI. Verdict logic is pure: immutable evidence in, classification out. No syscalls, no I/O, no mutation. If a verdict is wrong, you can reproduce it with the same evidence bundle.
:::

## Divergence detection

CPU time and wall time don't always agree. The ratio tells you something:

| CPU/Wall ratio | Classification | What it means |
|---------------|----------------|---------------|
| > 0.8 | CPU-bound | Process was computing the whole time |
| < 0.3 | Sleep/block-bound | Process was waiting (sleep, I/O) |
| Intermediate | Host interference suspected | System load may have affected results |

This matters for competitive programming: a TLE where the process was CPU-bound is a genuine algorithm problem. A TLE where the process was sleeping might be a broken test case.

## Verdict provenance

Every verdict includes an audit trail:

```json
{
  "verdict_actor": "kernel",
  "verdict_cause": "mle_kernel_oom",
  "verdict_evidence_sources": ["wait_outcome", "cgroup_evidence", "oom_events"],
  "memory_peak": 134217728
}
```

If a contestant disputes a verdict, you can show exactly which kernel evidence led to the classification.
