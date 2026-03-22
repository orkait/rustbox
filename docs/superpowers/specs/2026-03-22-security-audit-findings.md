# Security & Correctness Audit Findings

**Date:** 2026-03-22
**Scope:** Full codebase audit - sandbox core + judge-service
**Branch:** feat/scaling-architecture

## Critical (4)

1. **PostgreSQL reaper sets status='pending' instead of 'error'** - `judge-service/src/database/postgres.rs:350` - Crashed jobs get re-executed, causing duplicate results and potential double-execution of untrusted code
2. **Worker mark_running() failure silently continues** - `judge-service/src/worker.rs:166-168` - If DB update fails, worker continues execution but DB thinks job is still pending. Another worker may claim same job.
3. **Worker mark_completed() failure leaves 'running' forever** - `judge-service/src/worker.rs:194-196` - Submission stuck in 'running' until reaper (5 min default)
4. **API key comparison not constant-time** - `judge-service/src/api.rs:31` - Standard PartialEq short-circuits, enabling timing side-channel to recover API key

## High (7)

5. **No stdin size limit** - `judge-service/src/api.rs:115` - Unbounded stdin field, memory exhaustion
6. **Error messages leak internal paths** - `judge-service/src/worker.rs:202` - Rustbox error strings exposed to API callers
7. **SQLite Mutex poison on panic** - `judge-service/src/database/sqlite.rs:35+` - lock().unwrap() across all methods
8. **Cgroup v2 remove: 50ms kill, no retry** - `src/kernel/cgroup_v2.rs:327-342` - Unlike v1 (500ms with retry)
9. **Isolate::new() orphans directory** - `src/runtime/isolate.rs:192-230` - No cleanup if instances.json write fails
10. **Missing env blocklist items** - `src/exec/preexec.rs:556` - BASH_FUNC_*, IFS, GCONV_PATH, HOSTALIASES, LOCALDOMAIN, RES_OPTIONS, http_proxy
11. **SQLite/PostgreSQL reaper inconsistency** - sqlite marks 'error', postgres marks 'pending'

## Medium (6)

12. No per-IP rate limiting
13. TOCTOU in mount bindings (documented TODO)
14. Cgroup v1 retry timeout may be insufficient
15. memory_limit=0 not pre-validated
16. Compilation binary cleanup incomplete on panic
17. No node authentication in cluster mode

## Confirmed Secure

- SQL injection: fully parameterized
- Command injection: execvp, no shell
- Privilege dropping: correct order, verified
- Type-state chain: compile-time enforced
- FD closure: comprehensive
- Signal isolation: PID namespace
- Output bounding: 10MB limit
- Symlink-safe cleanup: AT_SYMLINK_NOFOLLOW
