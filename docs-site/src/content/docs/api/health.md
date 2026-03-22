---
title: Health & Languages
description: Service health check and language list
---

## GET /api/health

```json
{
  "status": "ok",
  "workers": 4,
  "queue_depth": 2,
  "node_id": "rustbox-01"
}
```

Use `queue_depth` to implement client-side backoff. If it's approaching the queue capacity, slow down submissions.

## GET /api/languages

```json
["python", "cpp", "java"]
```

Static list. Useful for building UI dropdowns or validating input before submitting.
