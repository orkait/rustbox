---
title: Webhooks
description: Push notifications for execution results with HMAC signing
---

Opt-in push notifications. Submit with a `webhook_url` and `webhook_secret`, and we'll POST the result to your endpoint when it's ready. No polling needed.

## How it works

1. You submit code with `webhook_url` and `webhook_secret`
2. Your code executes in the sandbox
3. We POST the result to your URL with HMAC-SHA256 signature headers
4. You verify the signature and process the result

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

## Important behaviour

- **Webhooks are opt-in.** No URL, no webhook.
- **Secret is mandatory** when URL is provided. We don't deliver unsigned webhooks.
- **HTTPS required** in production. Set `RUSTBOX_ALLOW_LOCALHOST_WEBHOOKS=true` for local dev.
- **Non-blocking delivery.** Webhook failures don't affect the submission result.
- **3 attempts.** Immediate, then 1s delay, then 5s delay. Server errors (5xx) trigger retry; client errors (4xx) do not. Poll as fallback if all attempts fail.

:::note[Design Note]
We chose Standard Webhooks over custom signing because it's an industry standard with verification libraries in every language. Per-submission secrets (sent by the client) rather than server-side global secrets let each integration use its own secret without server configuration. Simple retry (3 attempts, fixed delays) because exponential backoff adds queue complexity. The polling fallback covers persistent delivery failures.
:::

## SSRF protection

Webhook URLs are validated:

- Must use HTTPS (unless localhost mode is enabled)
- Private IPs blocked: `10.x`, `172.16-31.x`, `192.168.x`, `169.254.x`
- Loopback blocked: `127.0.0.1`, `::1`, `localhost`
