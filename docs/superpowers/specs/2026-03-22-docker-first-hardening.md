# Docker-First Deployment Hardening

**Date:** 2026-03-22
**Scope:** 5 surgical changes to make rustbox production-ready in Docker containers
**Target:** Docker Compose now, Kubernetes later. Strict mode required.

---

## 1. Container-aware config loading

**File:** `src/config/config.rs`
**Lines:** 99-115 (world-writable check in `load_default()`)

**Current behavior:** When running as root, world-writable config files are silently skipped (with `log::warn` + `continue`). Exception: paths under `/mnt/` (WSL).

**Problem:** Docker volume mounts often get 0777 permissions. Container runs as root. Config at `/app/config.json` is skipped silently. Per-language limits, environment variables, compilation settings all lost. Fallback to hardcoded defaults.

**Change:** Remove the `continue` statement. Keep the warning. Config is always loaded regardless of permissions. The threat model (attacker planting a config next to the binary) doesn't apply in containers where the config is operator-mounted.

**Before:**
```rust
if unsafe { libc::geteuid() } == 0
    && (meta.mode() & 0o002) != 0
    && !is_wsl_mount
{
    log::warn!("Skipping world-writable config file: {}", candidate.display());
    continue;  // <-- this silently skips the config
}
```

**After:**
```rust
if unsafe { libc::geteuid() } == 0
    && (meta.mode() & 0o002) != 0
    && !is_wsl_mount
{
    log::warn!(
        "Loading world-writable config file: {} (consider chmod 644)",
        candidate.display()
    );
}
```

---

## 2. Enforcement-aware health endpoint

**Files:** `judge-service/src/api.rs`, `judge-service/src/main.rs`, `judge-service/src/lib.rs`, `judge-service/src/types.rs`

**Current behavior:** `/api/health` always returns `{"status": "ok"}` with worker count and queue depth.

**Problem:** Orchestrators think the service is healthy when cgroups/namespaces are unavailable. Submissions execute without resource enforcement.

**Change:**

### 2a. Add enforcement info to AppState

In `judge-service/src/lib.rs`, add to `AppState`:
```rust
pub cgroup_backend: Option<String>,   // "cgroup_v2", "cgroup_v1", or None
pub namespace_support: bool,
pub enforcement_mode: String,          // "strict", "degraded", "none"
```

### 2b. Probe at startup

In `judge-service/src/main.rs`, before building AppState, probe:
```rust
let cgroup_backend = rustbox::kernel::cgroup::detect_cgroup_backend()
    .map(rustbox::kernel::cgroup::backend_type_name)
    .map(str::to_string);
let namespace_support = rustbox::kernel::namespace::NamespaceIsolation::is_supported();
let is_root = unsafe { libc::geteuid() } == 0;
let enforcement_mode = match (&cgroup_backend, namespace_support, is_root) {
    (Some(_), true, true) => "strict",
    (Some(_), _, _) | (_, true, _) => "degraded",
    _ => "none",
}.to_string();
```

### 2c. Update HealthResponse

In `judge-service/src/types.rs`, add fields to `HealthResponse`:
```rust
pub cgroup_backend: Option<String>,
pub namespace_support: bool,
pub enforcement_mode: String,
```

### 2d. Add readiness endpoint

In `judge-service/src/api.rs`, add `/api/health/ready`:
```rust
.route("/api/health/ready", get(readiness))
```

- `/api/health` (liveness): always 200, includes enforcement info
- `/api/health/ready` (readiness): 200 if enforcement_mode != "none", else 503

This maps to K8s `livenessProbe` / `readinessProbe` and Docker HEALTHCHECK.

---

## 3. Docker-specific cgroup error messages

**Files:** `src/kernel/cgroup.rs`, new utility `src/utils/container.rs`

**Current behavior:** Cgroup errors say "No cgroup backend available on this host" or generic creation failures.

**Problem:** Inside Docker, the host HAS cgroups but the container can't access them. The error sends operators on a wrong diagnosis path.

**Change:**

### 3a. Add container detection utility

Create `src/utils/container.rs`:
```rust
pub fn is_container() -> bool {
    std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists()
}
```

Register in `src/utils/mod.rs`.

### 3b. Append Docker hints to cgroup errors

In `src/kernel/cgroup.rs`, in `select_cgroup_backend()` when returning the "No cgroup backend available" error, check `is_container()` and append:

```
Cgroup unavailable inside container. Run with:
  --cap-add SYS_ADMIN --cap-add SETUID --cap-add SETGID \
  --cap-add NET_ADMIN --cap-add MKNOD --cap-add DAC_OVERRIDE \
  --security-opt seccomp=unconfined --cgroupns=host
```

Same pattern for `isolate.rs` when cgroup creation fails in strict mode.

---

## 4. Graceful shutdown with worker drain

**Files:** `judge-service/src/main.rs`, `judge-service/src/worker.rs`

**Current behavior:** No SIGTERM handling. Docker kills after 10s. In-flight submissions stuck as "running" until reaper (5 min default).

**Change:**

### 4a. Shutdown signal in main.rs

Replace the bare `axum::serve(listener, app).await?` with:

```rust
let shutdown = async {
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler")
        .recv()
        .await;
    info!("SIGTERM received, draining workers...");
};

axum::serve(listener, app)
    .with_graceful_shutdown(shutdown)
    .await?;
```

### 4b. Worker drain on shutdown

After the server stops, drain in-flight work:
- Close the job queue channel (senders dropped → receivers get None → workers exit loop)
- For PG mode: drop the listener handle
- `tokio::time::timeout(Duration::from_secs(35), join_all(worker_handles))` - wait up to 35s for in-flight executions
- If timeout hits: mark remaining in-flight submissions as error via `db.reap_stale(Duration::ZERO)`

### 4c. docker-compose.yml stop_grace_period

Set `stop_grace_period: 45s` to give workers time to finish (max wall time 30s + 15s buffer).

---

## 5. Docker documentation

**Files:** `docker-compose.yml` (new at project root), README.md update

### 5a. docker-compose.yml

```yaml
services:
  judge:
    build: .
    command: judge-service
    ports:
      - "8080:8080"
    environment:
      RUSTBOX_DATABASE_URL: "sqlite:rustbox.db"
      RUSTBOX_WORKERS: "2"
    cap_add:
      - SYS_ADMIN
      - SETUID
      - SETGID
      - NET_ADMIN
      - MKNOD
      - DAC_OVERRIDE
    security_opt:
      - seccomp=unconfined
    stop_grace_period: 45s
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/api/health/ready"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 5s
```

### 5b. Dockerfile HEALTHCHECK

Add to existing Dockerfile:
```dockerfile
HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=5s \
  CMD curl -f http://localhost:8080/api/health/ready || exit 1
```

### 5c. README update

Replace the current Docker section with minimal capabilities documentation. Remove `--privileged` from examples. Show `docker compose up` as the primary path.

---

## Dependency order

```
1. Container detection utility (utils/container.rs)  — no dependencies
2. Config loading fix (config/config.rs)              — no dependencies
3. Cgroup error messages (kernel/cgroup.rs)            — depends on 1
4. Health endpoint (judge-service)                     — no dependencies
5. Graceful shutdown (judge-service)                   — no dependencies
6. Docker documentation (compose + README)             — depends on 3, 4, 5
```

Tasks 1-2 and 4-5 are independent and can be done in parallel.
Task 3 depends on 1. Task 6 depends on 3, 4, 5.
