+++
title = "Result"
weight = 2
insert_anchor_links = "right"
+++

# GET /api/result/{id}

Retrieve the execution result for a submission.

## Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "verdict": "AC",
  "exit_code": 0,
  "stdout": "hello world\n",
  "stderr": "",
  "cpu_time": 0.015,
  "wall_time": 0.052,
  "memory_peak": 8400000
}
```

## Status lifecycle

```
pending → running → completed
                  → error
```

| Status | Meaning |
|--------|---------|
| `pending` | Queued, waiting for a worker |
| `running` | Executing in a sandbox |
| `completed` | Finished (check `verdict` for the outcome) |
| `error` | Internal failure (sandbox setup, timeout, etc.) |

## Verdicts

| Code | Name | What happened |
|------|------|--------------|
| `AC` | Accepted | Clean exit, code 0 |
| `RE` | Runtime Error | Non-zero exit or crash |
| `TLE` | Time Limit | CPU or wall time exceeded |
| `MLE` | Memory Limit | OOM killed by cgroup |
| `SIG` | Signaled | Killed by signal (not attributed to judge) |
| `IE` | Internal Error | Sandbox infrastructure failed |
| `SV` | Security Violation | Sandbox escape attempt detected |

> **Design Note:** We separate `SIG` from `RE` because a signal kill isn't always a runtime error - it could be the judge's timeout mechanism, an OOM kill, or the process hitting a seccomp rule. Collapsing these into one verdict loses information. The verdict provenance (available in CLI output) tells you exactly which kernel subsystem caused the termination and what evidence backs the classification.

## Not found

```
HTTP 404
```

```json
{
  "error": "submission not found"
}
```
