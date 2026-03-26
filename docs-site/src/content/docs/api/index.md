---
title: API Overview
description: REST API for the judge-service
---

The judge-service exposes a REST API for submitting code, polling results, and receiving webhook notifications.

## Base URL

```
http://localhost:4096/api
```

## Authentication

If `RUSTBOX_API_KEY` is set, every request must include it:

```
x-api-key: your-secret-key
```

Constant-time comparison is used. Missing or wrong keys return `401`.

## Endpoints

| Method | Path | What it does |
|--------|------|-------------|
| `POST` | `/api/submit` | Submit code for execution |
| `GET` | `/api/result/{id}` | Poll execution result |
| `GET` | `/api/languages` | List supported languages |
| `GET` | `/api/health` | Service health + queue depth |

## Three ways to get results

**Async (default):** Submit, get back an ID, poll `/api/result/{id}` until it's done.

**Sync:** Add `?wait=true` to the submit request. The server holds the connection open and returns the result directly when execution completes (or times out after 30s).

**Webhooks:** Include `webhook_url` and `webhook_secret` in your submission. We'll POST the result to your URL with an HMAC-SHA256 signature when it's ready. Fire and forget.

:::note[Design Note]
We support all three patterns because each has a legitimate use case. Polling is simplest to implement on the client side. Sync mode is perfect for interactive playgrounds where latency matters. Webhooks are the right answer for batch processing where you submit hundreds of solutions and don't want to hold connections open. Judge0 only supports polling - we think that's leaving value on the table.
:::
