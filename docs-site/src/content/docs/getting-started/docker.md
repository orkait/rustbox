---
title: Docker Deployment
description: Running rustbox in containers with minimal capabilities
---

rustbox is designed to run inside Docker containers without `--privileged`. This page covers the minimal capability set, Docker Compose setup, health probes, and graceful shutdown.

## Quick start

```bash
# SQLite mode (single node, no external deps)
docker compose -f docker-compose.judge.yml up judge

# PostgreSQL mode (multi-node ready)
docker compose -f docker-compose.judge.yml --profile postgres up
```

## Why not --privileged

`--privileged` gives the container full host capabilities, disables Docker's seccomp profile, and grants access to all host devices. An escape from rustbox's sandbox inside a `--privileged` container gives full host access - defeating the purpose of 8 isolation layers.

The minimal capability set gives rustbox exactly what it needs for strict mode:

| Capability | Used for |
|------------|----------|
| `SYS_ADMIN` | `clone` with namespace flags, `mount`, `chroot` |
| `SETUID` / `SETGID` | Credential drop to sandbox UID (60000-60999) |
| `NET_ADMIN` | Network namespace loopback setup |
| `MKNOD` | Device nodes (`/dev/null`, `/dev/urandom`) in chroot |
| `DAC_OVERRIDE` | Cgroup filesystem writes |

`seccomp=unconfined` is required because Docker's default seccomp profile blocks `clone` with namespace flags, `mount`, and `pivot_root`. These syscalls are needed during sandbox setup but are blocked by rustbox's own seccomp filter before executing untrusted code.

## docker run

```bash
docker run -p 4096:4096 \
  --cap-add SYS_ADMIN --cap-add SETUID --cap-add SETGID \
  --cap-add NET_ADMIN --cap-add MKNOD --cap-add DAC_OVERRIDE \
  --security-opt seccomp=unconfined \
  --stop-timeout 45 \
  rustbox judge-service
```

For single executions:

```bash
docker run \
  --cap-add SYS_ADMIN --cap-add SETUID --cap-add SETGID \
  --cap-add NET_ADMIN --cap-add MKNOD --cap-add DAC_OVERRIDE \
  --security-opt seccomp=unconfined \
  rustbox judge execute-code --strict --language python --code 'print(42)'
```

## Docker Compose

The project includes `docker-compose.judge.yml` with two service profiles:

**SQLite (default)** - single node, zero external dependencies:

```bash
docker compose -f docker-compose.judge.yml up judge
```

**PostgreSQL** - multi-node ready, LISTEN/NOTIFY job dispatch:

```bash
docker compose -f docker-compose.judge.yml --profile postgres up
```

All capabilities, security options, health checks, and stop grace periods are preconfigured.

## Health probes

Two endpoints for container orchestration:

| Endpoint | Purpose | Failure means |
|----------|---------|---------------|
| `GET /api/health` | Liveness | Process crashed, restart the container |
| `GET /api/health/ready` | Readiness | Cgroups/namespaces unavailable, don't route traffic |

### Liveness response (always 200)

```json
{
  "status": "ok",
  "enforcement_mode": "strict",
  "cgroup_backend": "cgroup_v2",
  "namespace_support": true,
  "workers": 2,
  "queue_depth": 0,
  "node_id": "rustbox-01"
}
```

### Readiness response

Returns `200` when enforcement is available (`strict` or `degraded`). Returns `503` when enforcement mode is `none` - meaning the container is missing required capabilities or cgroup access.

```json
{
  "status": "not_ready",
  "enforcement_mode": "none",
  "error": "no cgroup or namespace support available"
}
```

### Enforcement modes

| Mode | Meaning | When it happens |
|------|---------|-----------------|
| `strict` | Full isolation: cgroups + namespaces + root | Correct capabilities, running as root |
| `degraded` | Partial isolation: some controls missing | Has cgroups but not root, or has root but no cgroups |
| `none` | No kernel enforcement available | Missing capabilities, no cgroup access |

### Docker Compose healthcheck

Already configured in `docker-compose.judge.yml`:

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:4096/api/health/ready"]
  interval: 10s
  timeout: 5s
  retries: 3
  start_period: 5s
```

### Kubernetes probes

```yaml
livenessProbe:
  httpGet:
    path: /api/health
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
readinessProbe:
  httpGet:
    path: /api/health/ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
```

## Graceful shutdown

When Docker sends `SIGTERM` (on `docker stop` or rolling update):

1. Server stops accepting new HTTP connections
2. Job queue closes - workers finish in-flight executions
3. Workers drain with a 35s timeout (covers max wall time of 30s + buffer)
4. If drain times out, in-flight submissions are marked as error in the database
5. Process exits cleanly

Set `stop_grace_period` (Compose) or `--stop-timeout` (docker run) to at least 45s to give workers time to finish. The default Docker timeout of 10s will SIGKILL in-flight sandbox executions.

:::note[Design Note]
The 45s grace period comes from: max wall time (30s default) + SIGTERM-to-SIGKILL escalation (200ms) + cgroup cleanup + evidence collection + DB write buffer. If you increase `RUSTBOX_SYNC_WAIT_TIMEOUT_SECS` beyond 30s, increase the grace period to match.
:::

## Environment variables

Full list in [Configuration](/getting-started/configuration/). The most relevant for Docker:

| Variable | Default | Docker notes |
|----------|---------|-------------|
| `RUSTBOX_PORT` | `4096` | Must match the port mapping |
| `RUSTBOX_WORKERS` | `2` | Scale to CPU count, each worker holds one sandbox |
| `RUSTBOX_DATABASE_URL` | `sqlite:rustbox.db` | Use `postgresql://...` for multi-node |
| `RUSTBOX_STALE_TIMEOUT_SECS` | `300` | Reaper catches submissions orphaned by crashes |
| `RUSTBOX_ALLOW_LOCALHOST_WEBHOOKS` | `false` | Set `true` if webhook target is another container |

## Troubleshooting

**"Cgroup unavailable inside container"** - You're missing capabilities. Add the 6 `--cap-add` flags listed above and `--security-opt seccomp=unconfined`.

**Health endpoint shows `enforcement_mode: "degraded"`** - Usually means cgroups are accessible but the container isn't running as root. Check your Dockerfile doesn't have a `USER` directive, or add `user: root` to your Compose service.

**Health endpoint shows `enforcement_mode: "none"`** - Neither cgroups nor namespaces are available. Verify all 6 capabilities are granted and seccomp is unconfined.

**Submissions stuck as "running" after restart** - The reaper (runs every 60s by default) will mark them as error after `RUSTBOX_STALE_TIMEOUT_SECS` (default 300s). To speed this up, lower the stale timeout.

**Volume-mounted config.json ignored** - Check the container logs for "Loading world-writable config file" warnings. Docker volume mounts sometimes get 0777 permissions. The config is still loaded (with a warning), but if you don't see the warning, verify the mount path matches where rustbox looks for config (`./config.json` relative to the binary, or `/etc/rustbox/config.json`).
