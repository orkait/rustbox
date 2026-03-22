+++
title = "Webhooks"
weight = 3
insert_anchor_links = "right"
+++

# Webhooks

Opt-in push notifications for execution results. Submit with a `webhook_url` and `webhook_secret`, and we'll POST the result to your endpoint when it's ready.

## How it works

1. You submit code with `webhook_url` and `webhook_secret`
2. Your code executes in the sandbox
3. We POST the result to your URL with HMAC-SHA256 signature headers
4. You verify the signature and process the result

No polling needed. Fire and forget.

## Signature verification

We follow the [Standard Webhooks](https://www.standardwebhooks.com/) specification - the same pattern used by OpenAI, Stripe, and Svix.

### Headers

| Header | Value |
|--------|-------|
| `webhook-id` | Unique message ID (the submission UUID) |
| `webhook-timestamp` | Unix timestamp (seconds) |
| `webhook-signature` | `v1,<base64-encoded-hmac>` |

### Signed content

The HMAC-SHA256 is computed over:

```
{webhook-id}.{webhook-timestamp}.{body}
```

### Verification example (Python)

```python
import hmac, hashlib, base64

def verify_webhook(body: bytes, headers: dict, secret: str) -> bool:
    msg_id = headers["webhook-id"]
    timestamp = headers["webhook-timestamp"]
    signature = headers["webhook-signature"]

    signed_content = f"{msg_id}.{timestamp}.".encode() + body
    expected = hmac.new(
        secret.encode(), signed_content, hashlib.sha256
    ).digest()
    expected_b64 = "v1," + base64.b64encode(expected).decode()

    return hmac.compare_digest(signature, expected_b64)
```

## Webhook payload

Same shape as the result endpoint:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "verdict": "AC",
  "exit_code": 0,
  "stdout": "42\n",
  "stderr": "",
  "cpu_time": 0.011,
  "wall_time": 0.038,
  "memory_peak": 7800000
}
```

## Important behaviour

- **Webhooks are opt-in.** No URL, no webhook. Simple.
- **Secret is mandatory** when URL is provided. We don't deliver unsigned webhooks.
- **HTTPS required** in production. Set `RUSTBOX_ALLOW_LOCALHOST_WEBHOOKS=true` for local development with `http://`.
- **Non-blocking delivery.** Webhook failures don't affect the submission result. If your endpoint is down, the result is still available via polling.
- **No retries.** We attempt delivery once with a 5-second timeout. Your endpoint should be reliable, or you should poll as fallback.

> **Design Note:** We chose Standard Webhooks over custom signing because it's an industry standard with existing verification libraries in every language. We chose per-submission secrets (sent by the client) over server-side global secrets because it lets each integration use its own secret without server configuration. We chose no retries because exponential backoff adds queue complexity, and the polling fallback already exists. Keep it simple.

## SSRF protection

Webhook URLs are validated:

- Must use HTTPS (unless localhost mode is enabled)
- Private IPs blocked: `10.x`, `172.16-31.x`, `192.168.x`, `169.254.x`
- Loopback blocked: `127.0.0.1`, `::1`, `localhost`
- These restrictions are lifted when `RUSTBOX_ALLOW_LOCALHOST_WEBHOOKS=true`
