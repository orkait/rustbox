---
title: Health & Languages
description: Service health check, readiness probe, and language list
---

## GET /api/health

Liveness check. Always returns 200 if the process is running.

```json
{
  "status": "ok",
  "enforcement_mode": "strict",
  "cgroup_backend": "cgroup_v2",
  "namespace_support": true,
  "workers": 4,
  "queue_depth": 2,
  "node_id": "rustbox-01"
}
```

| Field | What it tells you |
|---|---|
| `enforcement_mode` | `strict` (full isolation), `degraded` (partial), or `none` |
| `cgroup_backend` | `cgroup_v2` or `null` if unavailable |
| `namespace_support` | Whether PID/mount/network namespaces work |
| `queue_depth` | Pending submissions - use for client-side backoff |

## GET /api/health/ready

Readiness probe. Returns 200 when the service can enforce isolation. Returns 503 when enforcement mode is `none` (missing capabilities or cgroup access). Use this for Kubernetes readiness probes and load balancer health checks.

## GET /api/languages

```json
["python", "c", "cpp", "java", "javascript", "typescript", "go", "rust"]
```

Detected at startup by checking which runtime binaries exist on the system. Use for validating input before submitting.
