# Test Strategy for rustbox v0.2

**Date:** 2026-03-23
**Goal:** Cover the full HTTP path (submit → queue → worker → sandbox → verdict → response) that existing tests skip entirely.

---

## Tier 1: End-to-end API tests

**File:** `judge-service/tests/e2e.rs`

Spawns the actual `judge-service` binary on a random port, hits it with `reqwest`, verifies verdicts. `TestServer` struct handles lifecycle.

### TestServer infrastructure

```rust
struct TestServer {
    child: std::process::Child,
    port: u16,
    base_url: String,
    client: reqwest::Client,
}
```

- Picks random free port via `TcpListener::bind("127.0.0.1:0")`
- Sets `RUSTBOX_PORT`, `RUSTBOX_DATABASE_URL=sqlite::memory:`
- Spawns `judge-service` binary
- Polls `/api/health` until ready (max 5s)
- `Drop` kills child process

### Tests

| Test | Language | Code | Expected | Proves |
|---|---|---|---|---|
| python_ac | python | `print(42)` | AC, stdout=42 | Full path |
| python_re | python | `raise ValueError()` | RE | Runtime error classification |
| python_tle | python | `while True: pass` | TLE | Timeout kill + classification |
| c_ac | c | `printf("42\n")` | AC, stdout=42 | C compile + execute |
| cpp_ac | cpp | `cout<<42<<endl` | AC, stdout=42 | C++ compile + PCH |
| cpp_ce | cpp | `invalid` | RE, stderr has "Compilation" | Compile error through API |
| java_ac | java | `System.out.println(42)` | AC, stdout=42 | javac + JVM flags |
| js_ac | javascript | `console.log(42)` | AC, stdout=42 | Bun JS |
| ts_ac | typescript | `console.log(42)` | AC, stdout=42 | Bun TS |
| stdin_passthrough | python | reads stdin, prints | AC, stdout=input | Stdin delivery |
| unsupported_lang | brainfuck | anything | 400, lists available | Validation + dynamic langs |
| health_liveness | - | GET /api/health | 200, has enforcement_mode | Health probe |
| health_readiness | - | GET /api/health/ready | 200 or 503 | Readiness probe |
| languages_endpoint | - | GET /api/languages | array of installed langs | Dynamic detection |
| no_auth_warning | - | GET /api/health (no key) | X-Rustbox-Warning header | Warning mechanism |
| auth_reject | - | submit without key (key set) | 401 | Auth enforcement |
| auth_accept | - | submit with correct key | 202 | Auth passes |

### Not in Tier 1

- Go, Rust (opt-in, not installed in test env)
- Rate limiting (isolated unit tests in Tier 2)
- Graceful shutdown (needs signal handling, future work)

---

## Tier 2: Rate limiter unit tests

**File:** `judge-service/src/rate_limit.rs` (add `#[cfg(test)]` module)

| Test | Proves |
|---|---|
| allows_up_to_limit | Token bucket grants N tokens |
| blocks_over_limit | Request N+1 rejected |
| refills_after_window | Tokens regenerate over time |
| independent_per_ip | Different IPs have separate buckets |
| cleanup_stale | Old entries removed |

---

## Tier 3: Existing (unchanged)

- 110 unit tests (sandbox internals)
- 7 trybuild (typestate invariants)
- 19 integration (Isolate::new direct)
- Docker matrix CI (per-language image builds)

---

## Dependency order

1. Rate limiter unit tests (no dependencies)
2. TestServer infrastructure
3. E2E tests (depend on TestServer)
