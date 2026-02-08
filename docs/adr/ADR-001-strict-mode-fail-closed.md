# ADR-001: Strict Mode Fail-Closed Semantics

**Status**: Accepted  
**Date**: 2026-02-08  
**Deciders**: Rustbox Core Team  
**Related**: `plan.md` Section 2, 4.1

## Context

Rustbox is designed for judge-grade execution of hostile untrusted code in competitive programming environments. The security model must be unambiguous: either all mandatory controls are kernel-enforced, or execution is denied.

Traditional sandboxes often degrade silently when controls cannot be applied, leading to false security assumptions and production incidents.

## Decision

Rustbox implements **strict mode as fail-closed by default**:

1. **Mandatory Controls**: If any mandatory control cannot be enforced, payload launch is rejected before execution.

2. **No False Claims**: Rustbox never reports full isolation when controls are only configured but not applied.

3. **Explicit Degradation**: Permissive mode exists for development/testing but explicitly marks execution as unsafe for hostile code.

4. **Capability Reporting**: Every execution emits a capability report showing:
   - `configured_controls`: What was requested
   - `applied_controls`: What was actually enforced
   - `missing_controls`: What could not be applied
   - `mode`: strict/permissive/dev
   - `unsafe_execution_reason`: Why execution is unsafe (if applicable)

## Consequences

### Positive
- **Security Clarity**: Operators know exactly what protections are active
- **No Silent Degradation**: Failures are explicit and actionable
- **Audit Trail**: Every execution has evidence of applied controls
- **Trust**: Judge systems can rely on reported isolation guarantees

### Negative
- **Deployment Friction**: Strict mode requires proper host configuration
- **Compatibility**: Some environments may not support all controls
- **Operational Overhead**: Failed launches require investigation

### Mitigation
- Provide clear error messages with remediation steps
- Offer `--dry-run` and `health` commands to validate environment before production
- Document minimum host requirements explicitly
- Permissive mode available for non-hostile workloads

## Compliance

This decision is **non-negotiable** per `plan.md` Section 2.1:
> "Strict mode is fail-closed. If any mandatory control cannot be enforced, payload launch is rejected."

## Implementation

- Task: `P0-REP-001` - Truthful Capability Reporting
- Task: `P15-CONFIG-002` - Strict Startup Validation
- Files: `rustbox/src/types.rs`, `rustbox/src/executor.rs`, `rustbox/src/security_logging.rs`

## References

- `plan.md` Section 2: Non-Negotiable Fundamentals
- `plan.md` Section 4: Security Modes and Runtime Contract
- `tasklist.md` P0-REP-001, P15-CONFIG-002
