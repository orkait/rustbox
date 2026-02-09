# Security Release Checklist (REL-001)

**Purpose**: Ensure no release without strict-mode and parity proof.  
**Status**: Template - Ready for RC validation  
**Version**: 1.0  
**Last Updated**: 2026-02-08

## Overview

This checklist must be completed and signed before any Rustbox v1 release candidate can proceed to production. All items must be verified with evidence links.

## Release Information

- **Release Version**: _____________
- **Release Date**: _____________
- **Release Manager**: _____________
- **Security Reviewer**: _____________
- **Build Commit**: _____________
- **Build Artifacts**: _____________

## 1. Core Security Controls

### 1.1 Strict Mode Enforcement
- [ ] Strict mode is default in production builds
- [ ] Missing mandatory controls reject execution (no silent degradation)
- [ ] Capability report includes configured/applied/missing controls
- [ ] No false security claims in any code path
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 1.2 Isolation Guarantees
- [ ] PID namespace isolation mandatory in strict mode
- [ ] Mount namespace isolation mandatory in strict mode
- [ ] Mount propagation hardening (MS_PRIVATE|MS_REC) before any mounts
- [ ] Host mount table invariance proven across all failure paths
- [ ] Process containment proven from kernel truth (/proc, cgroup membership)
- [ ] Zero orphans, zero transient out-of-cgroup PIDs
- [ ] Zero attributable zombies post-cleanup
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 1.3 Resource Enforcement
- [ ] Spawn-to-cgroup race eliminated (attach-before-exec proven)
- [ ] Memory limits enforced via cgroup
- [ ] CPU time limits enforced via cgroup accounting
- [ ] Wall time limits enforced via supervisor monotonic timer
- [ ] Process limits enforced via cgroup pids.max
- [ ] OOM detection working (memory.events on v2)
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 1.4 Privilege Minimization
- [ ] Capability drop (all sets: bounding, ambient, effective, permitted, inheritable)
- [ ] no_new_privs enforcement (PR_SET_NO_NEW_PRIVS)
- [ ] UID/GID transition (setresgid then setresuid)
- [ ] Root UID/GID rejected in strict mode
- [ ] Supplementary groups cleared
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 1.5 Lifecycle Safety
- [ ] Parent death signal (PR_SET_PDEATHSIG)
- [ ] pidfd-based supervision (race-free signaling)
- [ ] Fallback group kill/reap (bounded waits, full reap)
- [ ] Async-safe signal handlers
- [ ] Graceful → forced kill escalation
- [ ] Zero-leak cleanup guarantee
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 1.6 Type-State Safety
- [ ] Illegal pre-exec orderings cannot compile
- [ ] Single payload exec entry point (only from ExecReady state)
- [ ] Compile-fail tests pass (9 negative cases)
- [ ] No alternate exec() paths exist in codebase
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

## 2. Cgroup Backend Parity

### 2.1 v1/v2 Outcome Parity
- [ ] Memory limit scenarios produce consistent statuses across v1 and v2
- [ ] CPU time limit scenarios produce consistent statuses
- [ ] Wall time limit scenarios produce consistent statuses
- [ ] Process limit scenarios produce consistent statuses
- [ ] OOM behavior equivalent across backends
- [ ] Cgroup parity test suite passes (10/10 tests)
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 2.2 Backend Selection
- [ ] v2 default, v1 override/fallback working
- [ ] Strict mode rejects unavailable backends
- [ ] Backend selection logged for audit trail
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

## 3. Verdict Provenance and Classification

### 3.1 Status Taxonomy
- [ ] Status strings frozen (OK, TLE, MLE, RE, IE, SIG, SV, ABUSE, PLE, FSE)
- [ ] VerdictActor enum closed (judge, kernel, runtime)
- [ ] VerdictCause enum closed and versioned for v1
- [ ] CPU vs wall timeout distinction mandatory
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 3.2 Evidence-Backed Verdicts
- [ ] All non-OK verdicts include actor/cause/evidence
- [ ] Evidence bundle schema frozen and versioned
- [ ] Missing required evidence forces IE (no guessing)
- [ ] Forbidden inference patterns rejected (RSS-only => MLE, SIGKILL-only => TLE/MLE, etc.)
- [ ] Appeal-safety tests pass (missing/contradictory evidence → IE)
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 3.3 Execution Envelope Identity
- [ ] Envelope hash (SHA256) computed from canonical inputs
- [ ] Envelope includes kernel, namespaces, cgroup backend, limits, mount policy, uid/gid, version, language runtime, syscall filtering
- [ ] Same inputs produce same hash
- [ ] Different inputs produce different hash
- [ ] Envelope ID attached to JSON output and audit events
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

## 4. Observability and Audit

### 4.1 Structured Audit Events
- [ ] Event schema v1 frozen and versioned
- [ ] Correlation IDs (request_id, run_id, box_id, root_pid, session_id)
- [ ] Event types (start, capability decision, limit violations, signal escalation, cleanup, final status)
- [ ] Integration with provenance and envelope systems
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 4.2 Metrics and SLO Signals
- [ ] Execution outcome counters (OK, TLE, MLE, RE, IE, SIG, SV, ABUSE, PLE, FSE)
- [ ] Verdict actor/cause counters
- [ ] Resource limit violation counters
- [ ] Cleanup outcome counters
- [ ] Worker health gauges
- [ ] Latency histograms (cold start, execution, cleanup)
- [ ] Prometheus export format working
- [ ] SLO definitions documented
- [ ] Alert rules defined (critical, warning, info)
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 4.3 Health and Dry-Run Controls
- [ ] health_check() returns system capabilities
- [ ] dry_run() shows what controls would be applied
- [ ] Backend selection visibility (cgroup, pidfd, namespaces)
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

## 5. Failure Path Integrity

### 5.1 Failure-Injection Matrix
- [ ] Matrix covers failure classes (explicit_err, early_return, partial_setup, async_failure)
- [ ] Matrix covers resources (mount, cgroup, process, fd, tempdir)
- [ ] Baseline equivalence proven for all scenarios
- [ ] No additional mounts/cgroups/processes/zombies/tempdirs after cleanup
- [ ] No host propagation drift
- [ ] No leaked supervisor/control FDs
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 5.2 Cleanup Failure Escalation
- [ ] Cleanup baseline-equivalence failure emits IE
- [ ] Worker/instance marked unhealthy after cleanup uncertainty
- [ ] No automatic retry on same unhealthy worker
- [ ] Health and audit surfaces expose quarantine reason
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

## 6. Syscall Filtering Contract

### 6.1 Default-Off Behavior
- [ ] Syscall filtering disabled by default
- [ ] Explicit --enable-syscall-filtering flag required
- [ ] No automatic enablement in judge mode
- [ ] No compatibility/correctness/safety guarantees
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 6.2 Metadata and Attribution
- [ ] Filtering state recorded in CapabilityReport
- [ ] Envelope hash includes filtering state
- [ ] Failures attributed to filter/profile, not judge
- [ ] Reference catalogs labeled descriptive-only
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

## 7. Configuration Validation

### 7.1 Config-to-Enforcement Matrix
- [ ] Every config field enforced or explicitly deprecated
- [ ] No silent ignores
- [ ] Matrix validated at startup
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 7.2 Strict Startup Validation
- [ ] Invalid configs rejected in strict mode
- [ ] Zero limits rejected
- [ ] Wall time < CPU time rejected
- [ ] Root UID/GID rejected in strict mode
- [ ] Missing mandatory namespaces rejected
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

## 8. Test Coverage

### 8.1 Core Test Suites
- [ ] Unit tests: 177+ passing (excluding flaky health tests)
- [ ] Integration tests: 86+ passing
- [ ] Compile-fail tests: 9 negative cases passing
- [ ] Total: 278+ tests passing
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 8.2 Adversarial Security Tests
- [ ] Path traversal tests
- [ ] Symlink attack tests
- [ ] Fork bomb tests
- [ ] Timeout evasion tests
- [ ] Spawn-to-cgroup race proof (100+ iterations, zero escapes)
- [ ] Process containment proof (no orphans, no transient out-of-cgroup PIDs, no zombies)
- [ ] Filesystem mount invariance proof (empty normalized host mountinfo diff)
- [ ] Privilege escalation tests
- [ ] Appeal-safety tests (missing evidence → IE)
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 8.3 Reliability Tests
- [ ] Zero-leak cleanup guarantee (250+ stress iterations)
- [ ] Failure-injection matrix (all scenarios pass)
- [ ] Crash recovery tests
- [ ] Lock integrity under concurrency
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

## 9. Compatibility Matrix

### 9.1 Supported Platforms
- [ ] Ubuntu 20.04 tested
- [ ] Ubuntu 22.04 tested
- [ ] Debian stable tested
- [ ] Cgroup v2 default tested
- [ ] Cgroup v1 override/fallback tested
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 9.2 Known Limitations
- [ ] Linux-only documented
- [ ] Minimum kernel version documented (4.3+ for pidfd, 5.1+ recommended)
- [ ] Rootless strict explicitly unsupported (documented)
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

## 10. Supply Chain Security

### 10.1 Static Analysis
- [ ] cargo fmt passes
- [ ] cargo clippy --strict passes
- [ ] No unsafe code without explicit justification
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 10.2 Dependency Audit
- [ ] cargo audit passes (no known vulnerabilities)
- [ ] All dependencies reviewed and justified
- [ ] Dependency update policy documented
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 10.3 Build Reproducibility
- [ ] Build is reproducible (same inputs → same binary)
- [ ] Build artifacts signed
- [ ] Build provenance documented
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

## 11. Documentation

### 11.1 User Documentation
- [ ] README.md complete with judge-v1 scope
- [ ] Installation instructions
- [ ] Configuration guide
- [ ] Language presets documented (C++, Java, Python)
- [ ] Syscall filtering warnings prominent
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 11.2 Operator Documentation
- [ ] Metrics documentation (docs/operations/metrics.md)
- [ ] Runbooks (5 comprehensive runbooks)
- [ ] Health check procedures
- [ ] Troubleshooting guides
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 11.3 Architecture Documentation
- [ ] ADRs (ADR-001, ADR-002, ADR-003)
- [ ] plan.md canonical and up-to-date
- [ ] tasklist.md complete
- [ ] VERIFICATION.md confirms compliance
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

## 12. Rollback Plan

### 12.1 Rollback Procedures
- [ ] Rollback procedure documented
- [ ] Rollback tested in staging
- [ ] Rollback decision criteria defined
- [ ] Rollback communication plan
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 12.2 Backward Compatibility
- [ ] JSON schema v1 backward compatible
- [ ] Evidence bundle schema backward compatible
- [ ] No breaking changes in v1.x releases
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

## 13. Incident Response

### 13.1 Incident Procedures
- [ ] Incident response runbooks complete
- [ ] On-call rotation defined
- [ ] Escalation paths documented
- [ ] Post-incident review process defined
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

### 13.2 Security Contact
- [ ] Security contact email published
- [ ] Vulnerability disclosure policy published
- [ ] Security advisory process defined
- **Evidence**: _____________
- **Verified By**: _____________
- **Date**: _____________

## Final Sign-Off

### Release Manager Approval
- **Name**: _____________
- **Signature**: _____________
- **Date**: _____________
- **Comments**: _____________

### Security Reviewer Approval
- **Name**: _____________
- **Signature**: _____________
- **Date**: _____________
- **Comments**: _____________

### Engineering Lead Approval
- **Name**: _____________
- **Signature**: _____________
- **Date**: _____________
- **Comments**: _____________

## Release Decision

- [ ] **APPROVED FOR RELEASE** - All checklist items verified with evidence
- [ ] **CONDITIONAL APPROVAL** - Release approved with documented exceptions (list below)
- [ ] **REJECTED** - Release blocked, issues must be resolved (list below)

### Exceptions/Issues:
_____________________________________________________________________________
_____________________________________________________________________________
_____________________________________________________________________________

### Next Steps:
_____________________________________________________________________________
_____________________________________________________________________________
_____________________________________________________________________________

---

**Checklist Version**: 1.0  
**Template Last Updated**: 2026-02-08  
**Based On**: plan.md, tasklist.md, VERIFICATION.md
