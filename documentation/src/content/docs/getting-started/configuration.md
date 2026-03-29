---
title: Configuration
description: Tune limits, add languages, customize behavior
---

rustbox uses a layered configuration system. Defaults come from config files, CLI flags override them, and the judge-service reads environment variables on top.

Two config files at the repo root control resource limits per language:

| File | Profile | Memory | Wall time | CPU time | Processes |
|---|---|---|---|---|---|
| `config.json` | Judge | 256 MB | 7s | 4s | 10 |
| `config-executor.json` | Executor | 2 GB | 60s | 30s | 64 |

The judge profile is for competitive programming - tight limits, no network. The executor profile is for LLM agents - relaxed limits, filtered network. Same Docker image, different config file mounted at `/etc/rustbox/config.json`.

## config.json

Lives at the project root (or `/etc/rustbox/config.json` in Docker). Defines per-language resource limits, environment variables, and compilation settings.

```json
{
  "sandbox": {
    "tmpfs_size_mb": 256
  },
  "languages": {
    "python": {
      "limits": {
        "memory_mb": 256,
        "cpu_time_sec": 4,
        "wall_time_sec": 7,
        "max_processes": 10,
        "max_file_size_kb": 512,
        "max_open_files": 32
      },
      "runtime": {
        "command": ["/usr/bin/python3", "-u"],
        "source_file": "solution.py"
      },
      "environment": {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1"
      }
    },
    "cpp": {
      "limits": {
        "memory_mb": 512,
        "cpu_time_sec": 8,
        "wall_time_sec": 10,
        "max_processes": 8
      },
      "compilation": {
        "command": ["/usr/bin/g++", "-B/usr/bin", "-pipe", "-o", "solution", "{source}", "-std=c++17", "-O2"],
        "source_file": "solution.cpp",
        "limits": {
          "memory_mb": 256,
          "max_processes": 120,
          "cpu_time_sec": 15,
          "wall_time_sec": 30
        }
      },
      "runtime": {
        "command": ["./solution"],
        "source_file": null
      }
    }
  }
}
```

:::note[Design Note]
Limits are per-language, not global. A Python solution with 256MB is generous. A Java solution with 256MB is tight - the JVM alone needs ~100MB to start. We set sensible defaults so users don't have to think about this.
:::

## CLI overrides

CLI flags take precedence over `config.json`:

```bash
rustbox execute-code --permissive \
  --language python \
  --code 'while True: pass' \
  --cpu 1 \
  --wall-time 3 \
  --mem 64
```

## Judge-service environment variables

The HTTP service reads these at startup. All have sensible defaults.

| Variable | Default | What it does |
|----------|---------|-------------|
| `RUSTBOX_PORT` | `4096` | Listen port |
| `RUSTBOX_WORKERS` | `2` | Concurrent sandbox workers |
| `RUSTBOX_QUEUE_SIZE` | `100` | Max pending submissions |
| `RUSTBOX_DATABASE_URL` | `sqlite:rustbox.db` | SQLite or PostgreSQL connection string |
| `RUSTBOX_API_KEY` | _(none)_ | Require this key in `x-api-key` header |
| `RUSTBOX_NODE_ID` | _(auto UUID)_ | Node identifier for multi-node setups |
| `RUSTBOX_MAX_CODE_BYTES` | `65536` | Maximum source code size |
| `RUSTBOX_MAX_STDIN_BYTES` | `262144` | Maximum stdin payload (256KB) |
| `RUSTBOX_SYNC_WAIT_TIMEOUT_SECS` | `30` | Seconds before `?wait=true` times out |
| `RUSTBOX_WEBHOOK_TIMEOUT_SECS` | `10` | Seconds for webhook HTTP delivery |
| `RUSTBOX_ALLOW_LOCALHOST_WEBHOOKS` | `false` | Allow `http://localhost` webhook URLs (dev mode) |
| `RUSTBOX_REAPER_INTERVAL_SECS` | `5` | How often the reaper checks for stuck jobs |
| `RUSTBOX_RATE_LIMIT` | `0` (off) | Requests per minute per IP |
| `RUSTBOX_TRUST_PROXY_HEADERS` | `false` | Use X-Forwarded-For for rate limiting IP |
| `RUSTBOX_DRAIN_TIMEOUT_SECS` | `35` | Graceful shutdown drain timeout |
| `RUSTBOX_CORS_ORIGIN` | `http://localhost:3000` | Allowed CORS origin |

## Rate limiting

Set `RUSTBOX_RATE_LIMIT=60` to allow 60 requests per minute per IP. Token bucket with automatic cleanup of stale buckets. Disabled by default (`0`).

Behind a reverse proxy, set `RUSTBOX_TRUST_PROXY_HEADERS=true` to use `X-Forwarded-For` for the client IP instead of the direct connection IP.

Returns `429 Too Many Requests` when the limit is hit.

## Seccomp configuration

Seccomp filtering is on by default. The built-in deny-list blocks 52 dangerous syscalls across 12 families.

```bash
# Disable seccomp (not recommended)
rustbox execute-code --no-seccomp --language python --code '...'

# Use a custom policy file
rustbox execute-code --seccomp-policy /path/to/policy.json --language python --code '...'
```

See [Seccomp internals](/internals/seccomp) for the full deny-list and custom policy format.

:::note[Design Note]
We use a deny-list (block known-dangerous, allow everything else) rather than an allowlist (block everything, allow known-safe). Complex runtimes like Python, Java, and the JVM make hundreds of different syscalls. Maintaining an allowlist for each runtime is fragile and breaks with every minor version update. The deny-list approach blocks the specific syscalls that enable sandbox escape while letting runtimes work naturally.
:::
