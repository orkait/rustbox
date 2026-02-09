# ADR-003: Cgroup Backend Selection and Abstraction

**Status**: Accepted  
**Date**: 2026-02-08  
**Deciders**: Rustbox Core Team  
**Related**: `plan.md` Section 8.1, 8.2

## Context

Linux cgroups provide resource control and accounting, but exist in two incompatible versions:
- **cgroup v1**: Legacy, widely deployed, stable API
- **cgroup v2**: Modern, unified hierarchy, better semantics

Judge systems must work reliably across diverse host environments. Resource limits are mandatory for security, so cgroup availability directly impacts strict mode viability.

## Decision

Rustbox implements **dual cgroup backend support** with explicit selection:

### Backend Selection Policy
1. **Default**: cgroup v2 (when available)
2. **Override**: `--cgroup-v1` flag forces v1
3. **Fallback**: Automatic v1 fallback if v2 unavailable
4. **Strict Rejection**: If selected backend cannot enforce mandatory limits, strict mode launch is denied

### Abstraction Layer
- `CgroupBackend` trait defines common interface
- `CgroupV1` and `CgroupV2` implementations
- Backend selection reported in capability output and audit events

### Required Semantics (Both Backends)
- **Memory Limit**: Hard limit enforcement
- **Process Limit**: Maximum process count
- **CPU Accounting**: Time usage tracking
- **OOM Detection**: Out-of-memory event detection
- **Membership**: Process attachment and enumeration
- **Peak Memory**: Maximum memory usage (v2 native, v1 sampled)

### v2-Specific Enhancements
- `memory.oom.group=1`: Whole-cgroup OOM kill in strict mode
- `memory.peak`: Native peak memory tracking
- `memory.events`: Structured OOM event detection

## Consequences

### Positive
- **Broad Compatibility**: Works on both v1 and v2 hosts
- **Future-Proof**: v2 is the Linux kernel's future direction
- **Explicit Behavior**: Backend choice is visible and deterministic
- **Better Semantics**: v2 provides superior OOM and accounting features

### Negative
- **Implementation Complexity**: Two backends to maintain
- **Testing Burden**: Must validate both backends
- **Semantic Differences**: v1/v2 have subtle behavioral differences

### Mitigation
- Comprehensive parity test suite (`P1-CGROUPPAR-001`)
- Clear documentation of backend differences
- Explicit backend reporting in all outputs
- Fallback behavior tested in CI matrix

## Backend Selection Algorithm

```
if --cgroup-v1 flag:
    backend = CgroupV1
    if v1 unavailable:
        fail with error
else:
    if v2 available:
        backend = CgroupV2
    else if v1 available:
        backend = CgroupV1
    else:
        if strict mode:
            fail with error
        else:
            warn and continue without cgroups
```

## Parity Requirements

Core limit scenarios must produce equivalent statuses across backends:
- Memory limit breach → `MLE`
- CPU time limit breach → `TLE` with `verdict_cause=tle_cpu_*`
- Process limit breach → `PLE`
- Normal exit → `OK`

Differences in evidence collection are acceptable if verdict classification remains consistent.

## Spawn-to-Cgroup Race Prevention

Both backends must guarantee **attach-before-exec**:
- Process attached to sandbox cgroup before any user code executes
- No runnable window between fork and cgroup attachment
- Pre-exec child activity fully accounted to sandbox cgroup

This is proven via adversarial race test suite (`P1-RACE-001`).

## Compliance

This decision implements `plan.md` Section 8.1:
> "default: cgroup v2. explicit override: `--cgroup-v1` forces v1. automatic fallback: if v2 unavailable, use v1. strict-mode rejection: if selected backend cannot enforce mandatory limits."

## Implementation

- Task: `P1-CGROUP-001` - Cgroup Backend Interface
- Task: `P1-CGROUP2-001` - v2 OOM Semantics
- Task: `P1-CGROUP2-002` - v2 Peak Memory Accounting
- Task: `P1-CGROUPSEL-001` - Selection Policy and Flag Behavior
- Task: `P1-CGROUPPAR-001` - v1/v2 Outcome Parity Suite
- Task: `P1-RACE-001` - Spawn-to-Cgroup Race Elimination
- Files: `rustbox/src/cgroup_backend.rs`, `rustbox/src/cgroup.rs`, `rustbox/src/cgroup_v2.rs`

## References

- `plan.md` Section 8: Resource Governance and Cgroup Policy
- Linux cgroup v2 documentation: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html
- `tasklist.md` P1-CGROUP-001, P1-CGROUPSEL-001, P1-CGROUPPAR-001, P1-RACE-001
