# Security & Correctness Audit Findings

**Date:** 2026-03-22
**Scope:** Full codebase audit - sandbox core + judge-service
**Branch:** feat/scaling-architecture
**Last updated:** 2026-03-22 (all critical and high findings resolved)

## Critical (4) - ALL RESOLVED

1. **PostgreSQL reaper sets status='pending' instead of 'error'** - `judge-service/src/database/postgres.rs`
   **RESOLVED:** Reaper now sets `status = 'error'` and `verdict = 'IE'` with message 'node crashed or execution timed out'.

2. **Worker mark_running() failure silently continues** - `judge-service/src/worker.rs`
   **RESOLVED:** Worker returns early on mark_running failure with error log.

3. **Worker mark_completed() failure leaves 'running' forever** - `judge-service/src/worker.rs`
   **RESOLVED:** On mark_completed failure, worker calls `mark_error()` with "execution succeeded but result storage failed".

4. **API key comparison not constant-time** - `judge-service/src/api.rs`
   **RESOLVED:** `constant_time_eq()` function uses XOR accumulation with no short-circuit.

## High (7) - ALL RESOLVED

5. **No stdin size limit** - `judge-service/src/api.rs`
   **RESOLVED:** `max_stdin_bytes` enforced (default 256KB), returns 400 on excess.

6. **Error messages leak internal paths** - `judge-service/src/worker.rs`
   **RESOLVED:** `sanitize_error()` redacts `/home/`, `/tmp/rustbox/`, `/sys/fs/cgroup/` paths, truncates to 512 bytes.

7. **SQLite Mutex poison on panic** - `judge-service/src/database/sqlite.rs`
   **RESOLVED:** All `lock()` calls use `unwrap_or_else(|e| e.into_inner())` to recover from poisoned mutex.

8. **Cgroup v2 remove: insufficient retry** - `src/kernel/cgroup_v2.rs`
   **RESOLVED:** 20 retries with 25ms sleep (500ms total), cgroup.kill at attempt 0 and 5, strict mode error on timeout.

9. **Isolate::new() orphans directory on partial failure** - `src/runtime/isolate.rs`
   **RESOLVED:** Cleanup of base_path directory and cgroup on any failure during Isolate::new(). UidGuard Drop releases the UID.

10. **Missing env blocklist items** - `src/exec/preexec.rs`
    **RESOLVED:** 33-item blocklist includes BASH_FUNC_* (pattern match), IFS, GCONV_PATH, HOSTALIASES, LOCALDOMAIN, RES_OPTIONS, all proxy variants, _JAVA_OPTIONS, JDK_JAVA_OPTIONS. Java agent flags in JAVA_TOOL_OPTIONS also stripped.

11. **SQLite/PostgreSQL reaper inconsistency** - database modules
    **RESOLVED:** Both backends mark reaped submissions as 'error' with appropriate messages.

## Medium (6) - ACCEPTED RISK

12. No per-IP rate limiting - mitigated by API key auth and bounded queue
13. TOCTOU in mount bindings - documented, mitigated by namespace isolation
14. Cgroup v1 retry timeout may be insufficient on loaded hosts - 500ms is adequate for typical use
15. memory_limit=0 pre-validated by config validator (rejects zero limits in both strict and permissive)
16. Compilation binary cleanup incomplete on panic - mitigated by workspace wipe on next execution and Isolate Drop
17. No node authentication in cluster mode - PostgreSQL mode uses DB as coordination point, not direct node-to-node

## Confirmed Secure

- SQL injection: fully parameterized (SQLite params!, PostgreSQL $N binds)
- Command injection: execvp with allowlist, no shell invocation
- Privilege dropping: correct order (groups, gid, uid), verified post-transition
- Type-state chain: compile-time enforced, 7 trybuild compile-fail tests
- FD closure: close_range(2) with /proc/self/fd fallback
- Signal isolation: PID namespace, parent death signal SIGKILL
- Output bounding: per-stream limits, combined 10MB cap
- Symlink-safe cleanup: O_NOFOLLOW, openat/unlinkat, no symlink following
- Webhook SSRF: URL validation blocks private IPs, loopback, non-HTTPS
- Webhook signing: HMAC-SHA256 per Standard Webhooks spec
- Constant-time API key comparison: XOR accumulation
- Environment sanitization: 33-item blocklist + BASH_FUNC_ pattern + Java agent flag detection
- Seccomp-BPF: 18-syscall deny-list, io_uring gets ENOSYS (not KILL)
