+++
title = "Health & Languages"
weight = 4
insert_anchor_links = "right"
+++

# GET /api/health

Service health check with queue status.

```json
{
  "status": "ok",
  "workers": 4,
  "queue_depth": 2,
  "node_id": "rustbox-01"
}
```

Use `queue_depth` to implement client-side backoff. If it's approaching the queue capacity, slow down submissions.

# GET /api/languages

Returns the supported language list.

```json
["python", "cpp", "java"]
```

This is a static list. Useful for building UI dropdowns or validating input before submitting.
