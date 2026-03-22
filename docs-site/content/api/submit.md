+++
title = "Submit"
weight = 1
insert_anchor_links = "right"
+++

# POST /api/submit

Submit source code for sandboxed execution.

## Request

```json
{
  "language": "python",
  "code": "print(2 + 2)",
  "stdin": "",
  "webhook_url": "https://your-app.com/hooks/judge",
  "webhook_secret": "your-hmac-secret"
}
```

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `language` | string | yes | `python`, `py`, `cpp`, `c++`, `cxx`, `java` |
| `code` | string | yes | Source code (max 64KB) |
| `stdin` | string | no | Input data (max 64KB) |
| `webhook_url` | string | no | HTTPS URL for result delivery |
| `webhook_secret` | string | conditional | Required if `webhook_url` is set (max 256 bytes) |

## Async response (default)

```
HTTP 202 Accepted
```

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000"
}
```

Poll `GET /api/result/{id}` for the result.

## Sync response (`?wait=true`)

```
POST /api/submit?wait=true
```

Holds the connection until execution completes (max 30s). Returns the full result directly:

```
HTTP 200 OK
```

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "verdict": "AC",
  "exit_code": 0,
  "stdout": "4\n",
  "stderr": "",
  "cpu_time": 0.012,
  "wall_time": 0.045,
  "memory_peak": 8192000
}
```

If execution doesn't finish in time:

```
HTTP 408 Request Timeout
```

```json
{
  "id": "550e8400-...",
  "error": "execution did not complete within 30s, poll GET /api/result/{id}"
}
```

## Idempotency

Send an `Idempotency-Key` header (UUID) to avoid duplicate submissions. If a submission with that key already exists, the existing record is returned with `202`.

```
Idempotency-Key: 550e8400-e29b-41d4-a716-446655440000
```

> **Design Note:** Idempotency keys are essential for judge systems. Network retries shouldn't re-execute the same code. We use UUIDs because they're universally understood and don't require server-side generation. If you don't send a key, we generate one for you - but then retries create new submissions.

## Queue full

```
HTTP 503 Service Unavailable
```

```json
{
  "error": "queue full, try again later"
}
```

The queue has a bounded capacity. This is deliberate - we'd rather reject requests cleanly than accept work we can't execute in time.

## Errors

| Status | Meaning |
|--------|---------|
| 400 | Invalid language, code too large, missing webhook_secret |
| 401 | Bad or missing API key |
| 503 | Queue full |
