+++
title = "Verdict System"
weight = 3
insert_anchor_links = "right"
+++

# Verdict System

Every verdict in rustbox is a pure function over kernel evidence. We never guess.

## The problem with most judges

Most online judges classify verdicts like this:

```
if exit_code != 0 → Runtime Error
if wall_time > limit → Time Limit Exceeded
if memory > limit → Memory Limit Exceeded
else → Accepted
```

This is wrong in subtle ways. What if the process was OOM-killed with exit code 137? Is that RE or MLE? What if the process hit a CPU time limit but the wall clock hasn't expired yet? What if the judge killed the process for timeout but the process also crashed independently?

## Evidence bundles

rustbox collects evidence from multiple kernel sources before making a verdict:

```rust
EvidenceBundle {
    wait_outcome,        // exit code, terminating signal, stop/continue status
    judge_actions,       // what the judge did (timer kills, escalations)
    cgroup_evidence,     // memory peak, OOM events, CPU usage from cgroup
    timing_evidence,     // wall time, CPU time, divergence classification
    process_lifecycle,   // descendant containment, zombie count
    evidence_errors,     // what we failed to collect
}
```

The verdict classifier takes this bundle and a snapshot of the configured limits, then applies a decision tree:

1. **Cleanup failure?** → Internal Error (evidence integrity compromised)
2. **Evidence collection errors?** → Internal Error (can't trust what we have)
3. **Judge killed the process?** → Check why (timeout → TLE, OOM → MLE)
4. **OOM events in cgroup?** → Memory Limit Exceeded
5. **Exit code 0?** → Accepted
6. **Non-zero exit?** → Runtime Error
7. **Signal without attribution?** → Signaled

Each verdict carries provenance: which actor caused it (judge, kernel, or runtime), which evidence sources were consulted, and what the limits were at the time.

> **Design Note:** The verdict classifier lives in `verdict/` which has zero `unsafe` blocks. This is enforced by CI. Verdict logic is pure - it takes an immutable evidence bundle and returns a classification. No syscalls, no I/O, no mutation. If a verdict is wrong, you can reproduce it with the same evidence bundle. This makes verdict bugs debuggable and testable.

## Divergence detection

CPU time and wall time don't always agree. The ratio tells you something:

| CPU/Wall ratio | Classification | What it means |
|---------------|----------------|---------------|
| > 0.8 | CPU-bound | Process was computing the whole time |
| < 0.3 | Sleep/block-bound | Process was waiting (sleep, I/O, network) |
| Intermediate | Host interference suspected | System load may have affected results |

This matters for competitive programming: a TLE where the process was CPU-bound is a genuine algorithm problem. A TLE where the process was sleeping might be a broken test case or system issue.

## Verdict provenance

Every verdict includes:

```json
{
  "verdict_actor": "kernel",
  "verdict_cause": "mle_kernel_oom",
  "verdict_evidence_sources": ["wait_outcome", "cgroup_evidence", "oom_events"],
  "cpu_time_used": 1.234,
  "wall_time_used": 1.567,
  "memory_peak": 134217728
}
```

This is the audit trail. If a contestant disputes a verdict, you can show exactly which kernel evidence led to the classification.
