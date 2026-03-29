---
title: Docker Deployment
description: Ship rustbox in production without --privileged
---

Three commands. Pick your profile.

```bash
docker compose up judge       # competitive programming (256MB, 7s)
docker compose up executor    # LLM agents (2GB, 60s)
docker compose up judge-pg    # judge + Postgres (multi-node)
```

That's it. Capabilities, cgroups, health checks, graceful shutdown - all preconfigured.

---

## Build your own image

Two Dockerfiles at the repo root:

```bash
# Judge profile (default) - tight limits, all languages
docker build -t rustbox .

# Executor profile - relaxed limits, network tools included
docker build -t rustbox-executor -f Dockerfile.executor .
```

Run it:

```bash
docker run -p 4096:4096 \
  --cap-add SYS_ADMIN --cap-add SETUID --cap-add SETGID \
  --cap-add NET_ADMIN --cap-add MKNOD --cap-add DAC_OVERRIDE \
  --security-opt seccomp=unconfined \
  --stop-timeout 45 \
  rustbox
```

One-off execution without the HTTP service:

```bash
docker run --rm \
  --cap-add SYS_ADMIN --cap-add SETUID --cap-add SETGID \
  --cap-add NET_ADMIN --cap-add MKNOD --cap-add DAC_OVERRIDE \
  --security-opt seccomp=unconfined \
  rustbox rustbox execute-code --language python --code 'print(42)'
```

## Why not --privileged

`--privileged` gives full host access. If someone escapes rustbox's sandbox inside a privileged container, they own the host. That defeats the purpose of 8 isolation layers.

Instead, we use 6 specific capabilities:

| Capability | Why |
|---|---|
| `SYS_ADMIN` | `unshare` for namespaces, `mount`, `chroot` |
| `SETUID` / `SETGID` | Drop to sandbox UID (60000-60999) |
| `NET_ADMIN` | Network namespace loopback |
| `MKNOD` | `/dev/null`, `/dev/urandom` in chroot |
| `DAC_OVERRIDE` | Write to cgroup filesystem |

`seccomp=unconfined` disables Docker's seccomp so our own 52-rule filter handles it. Docker's default blocks `unshare` and `mount` which we need during setup - but rustbox's seccomp blocks them before untrusted code runs.

## Health checks

```bash
# Is it alive?
curl http://localhost:4096/api/health

# Can it enforce isolation?
curl http://localhost:4096/api/health/ready
```

`/health` always returns 200 if the process runs. `/health/ready` returns 503 if isolation isn't available (missing capabilities or cgroups). Use `/health/ready` for load balancer checks.

The response tells you what mode you're in:

| `enforcement_mode` | What it means |
|---|---|
| `strict` | Full isolation. Production-ready. |
| `degraded` | Partial. Usually means not running as root. |
| `none` | Nothing enforced. Missing capabilities. Don't route traffic here. |

## Graceful shutdown

When Docker sends SIGTERM:

1. Stops accepting HTTP connections
2. Workers finish in-flight sandboxes (up to 35s drain timeout)
3. Anything still running gets marked as error in the DB
4. Process exits

Set `--stop-timeout 45` (or `stop_grace_period: 45s` in Compose). Docker's default 10s will SIGKILL running sandboxes. 45s covers the max wall time (30s) plus cleanup.

## Multi-node with Postgres

```bash
docker compose up judge-pg
```

Postgres starts automatically. Multiple `judge-pg` instances can share one Postgres - job dispatch uses `FOR UPDATE SKIP LOCKED` so each node grabs unique jobs without conflicts.

Set a unique `RUSTBOX_NODE_ID` per instance so the reaper knows which node owns which jobs.

## Environment variables you'll actually change

| Variable | Default | What |
|---|---|---|
| `RUSTBOX_API_KEY` | _(none)_ | Set this in production. Blocks unauthenticated requests. |
| `RUSTBOX_WORKERS` | `4` | Match to CPU count. Each worker holds one sandbox. |
| `RUSTBOX_DATABASE_URL` | `sqlite:///tmp/rustbox.db` | `postgresql://user:pass@host/db` for multi-node |
| `RUSTBOX_PORT` | `4096` | Must match your port mapping |
| `RUST_LOG` | `info` | `error` for production, `debug` for troubleshooting |

Full list in [Configuration](/getting-started/configuration/).

## When things go wrong

**"enforcement_mode: none"** - You forgot the capabilities. Add all 6 `--cap-add` flags and `--security-opt seccomp=unconfined`.

**"enforcement_mode: degraded"** - Container isn't running as root. Don't add `USER` to your Dockerfile. rustbox needs root to set up namespaces, then drops to UID 60000+ before running untrusted code.

**Jobs stuck as "running"** - The reaper checks every 5 seconds. Each job is reaped after its wall time limit + 10s grace. A 7-second judge job gets reaped at 17 seconds. A 60-second executor job at 70 seconds. No manual intervention needed.
