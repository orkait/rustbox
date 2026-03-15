# Pull Request

## Description
<!-- Provide a clear description of the changes -->

## Related Tasks
<!-- Link to tasklist.md tasks, e.g., P0-LCK-001, P1-NS-001 -->

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to change)
- [ ] Security-critical change (requires two-engineer review)

## Security Review Checklist

**This section is MANDATORY for security-critical changes.**

Security-critical changes include modifications to:
- Process lifecycle and supervision
- Privilege management (capabilities, uid/gid, no_new_privs)
- Filesystem mounts and isolation
- Cgroup management and resource limits
- Syscall filtering
- Namespace setup and configuration
- Lock management and state persistence
- Cleanup and failure paths

### Required for Security-Critical Changes
- [ ] **Two-Engineer Review**: This PR has been reviewed by at least two engineers
- [ ] **Threat Model**: Changes have been evaluated against threat model in `plan.md` Section 3
- [ ] **Failure Paths**: All failure paths have been tested (explicit errors, early returns, partial setup, async failures)
- [ ] **Invariants**: All relevant invariants from `plan.md` are preserved
- [ ] **Tests**: Security tests added/updated (adversarial, failure-injection, stress)
- [ ] **Evidence**: Test evidence linked in `tasklist.md` for related tasks
- [ ] **Capability Report**: Changes to controls are reflected in capability reporting
- [ ] **Audit Events**: Security-relevant decisions emit structured audit events

### Reviewer Attestation
**Primary Reviewer**: @<!-- username -->
- [ ] I have reviewed the code for security implications
- [ ] I have verified failure paths are handled correctly
- [ ] I have confirmed tests cover adversarial scenarios

**Secondary Reviewer** (required for security-critical): @<!-- username -->
- [ ] I have independently reviewed the security aspects
- [ ] I agree with the primary reviewer's assessment
- [ ] I have verified compliance with `plan.md` invariants

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Security tests pass (if applicable)
- [ ] Stress tests pass (if applicable)
- [ ] Manual testing completed

## Documentation
- [ ] Code comments added/updated
- [ ] `README.md` updated (if needed)
- [ ] `plan.md` updated (if needed)
- [ ] `tasklist.md` updated (if needed)
- [ ] ADRs created/updated (if architectural decision)

## Checklist
- [ ] Code follows Rust style guidelines (`cargo fmt`)
- [ ] Lints pass (`cargo clippy`)
- [ ] No new compiler warnings
- [ ] Commit messages are clear and descriptive
- [ ] Branch is up to date with main

## Risk Assessment
<!-- Describe potential risks and mitigation strategies -->

## Rollback Plan
<!-- How can this change be reverted if issues arise? -->
