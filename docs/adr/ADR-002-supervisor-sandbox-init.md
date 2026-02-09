# ADR-002: Three-Process Supervisor/Sandbox-Init/Payload Model

**Status**: Accepted  
**Date**: 2026-02-08  
**Deciders**: Rustbox Core Team  
**Related**: `plan.md` Section 5, 5.0

## Context

Secure process isolation requires careful separation of concerns:
- **Lifecycle Management**: Timeout enforcement, signal escalation, resource cleanup
- **Namespace Init**: PID 1 inside sandbox for proper signal handling and zombie reaping
- **Payload Execution**: Untrusted user code with dropped privileges

Running untrusted code directly as PID 1 in a PID namespace creates signal handling and reaping complications. A single-process model cannot cleanly separate orchestration from isolation.

## Decision

Rustbox adopts a **three-role execution model** inspired by IOI Isolate:

### 1. Supervisor (Host, Trusted)
- Runs in host namespace with elevated privileges
- Owns timeout timers and signal escalation
- Manages cgroup lifecycle and resource monitoring
- Collects evidence and emits verdicts
- Performs cleanup and state management

### 2. Sandbox-Init (PID 1 in Sandbox, Trusted, Minimal)
- Acts as init/reaper inside PID namespace
- Handles zombie reaping for payload descendants
- Forwards signals appropriately
- Minimal implementation to reduce attack surface
- **Implementation**: Re-execute rustbox binary with `--proxy` flag

### 3. Payload (Untrusted)
- User-submitted code
- Runs with dropped privileges (unprivileged uid/gid)
- Subject to all isolation controls
- Cannot escape namespace or resource limits

## Architecture Invariants

1. **Payload Never Runs Before Controls Applied**: Strict controls must be kernel-enforced or launch is denied
2. **Single Owner for Kill/Reap**: Supervisor is exclusively responsible for termination
3. **Idempotent Cleanup**: Cleanup is safe under retries and crash recovery
4. **Atomic State Updates**: State writes are lock-protected and fsync-disciplined
5. **Auditable Decision Points**: Security decisions produce structured events
6. **Pre-Exec Ordering Enforced**: Type-state chain prevents illegal control ordering
7. **Single Legal Exec Path**: Only one code path can execute payload after all gates complete

## Process Communication

- **Error Pipe**: Early/internal errors from sandbox-init → supervisor
- **Status Pipe**: Sandbox-init PID + final wait status → supervisor
- **Parent Death Signal**: `PR_SET_PDEATHSIG` ensures sandbox-init dies with supervisor

## Consequences

### Positive
- **Clean Separation**: Orchestration logic isolated from sandbox environment
- **Robust Reaping**: Proper PID 1 behavior for zombie cleanup
- **Signal Safety**: Supervisor can send signals without namespace complications
- **Crash Recovery**: Supervisor death triggers automatic sandbox termination
- **Proven Pattern**: Based on battle-tested IOI Isolate design

### Negative
- **Complexity**: Three processes instead of one
- **IPC Overhead**: Pipes for communication between processes
- **Binary Re-Execution**: Sandbox-init requires rustbox binary available in sandbox

### Mitigation
- Keep sandbox-init implementation minimal and auditable
- Use efficient pipe-based communication
- Document process model clearly for maintainers
- Provide comprehensive lifecycle tests

## Implementation Details

### Supervisor Responsibilities
- Parse policy and validate configuration
- Acquire box lock and prepare runtime context
- Fork sandbox-init with appropriate namespaces
- Monitor timeout and enforce kill escalation
- Collect cgroup statistics and evidence
- Emit audit events and final verdict
- Perform cleanup and release lock

### Sandbox-Init Responsibilities
- Set up mount namespace and filesystem isolation
- Apply resource limits (rlimits)
- Drop capabilities and privileges
- Fork payload process
- Reap zombie descendants
- Forward exit status to supervisor

### Payload Execution
- Runs with unprivileged uid/gid
- Subject to cgroup limits
- Isolated in PID/mount/network namespaces
- Cannot gain privileges (`no_new_privs`)
- Optional syscall filtering (explicit opt-in only)

## Compliance

This decision implements `plan.md` Section 5.0:
> "Rustbox uses a three-role execution model: Supervisor (host, trusted), Proxy/init (PID 1 inside sandbox, trusted, minimal), Payload (untrusted user program)."

## Implementation

- Task: `P0-LIFECYCLE-001` - Parent Death Contract
- Task: `P1-LIFECYCLE-002` - pidfd-Based Supervision
- Task: `P1-LIFECYCLE-003` - Fallback Group Kill/Reap
- Files: `rustbox/src/supervisor.rs`, `rustbox/src/executor.rs`

## References

- `plan.md` Section 5: Target Runtime Architecture
- IOI Isolate: https://github.com/ioi/isolate
- `isolate/learn.md` Section 4: Core Runtime Design
- `tasklist.md` P0-LIFECYCLE-001, P1-LIFECYCLE-002, P1-LIFECYCLE-003
