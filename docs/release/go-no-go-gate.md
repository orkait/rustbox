# Judge-V1 Go/No-Go Gate (REL-V1-001)

**Purpose**: Ensure v1 ships only if minimum isolation and verdict correctness are proven.  
**Status**: Template - Ready for v1 gate review  
**Version**: 1.0  
**Last Updated**: 2026-02-08

## Overview

This is the final gate before Rustbox v1 release. All criteria must be met with evidence. This gate confirms that the system meets judge-grade baseline requirements, not just partial progress.

## Release Information

- **Release Version**: v1.0.0
- **Gate Review Date**: _____________
- **Gate Review Lead**: _____________
- **Security Reviewer**: _____________
- **Engineering Lead**: _____________
- **Product Owner**: _____________

## Gate Criteria

All criteria must be **PASS** with evidence links. Any **FAIL** blocks release.

## 1. Scope and Defaults (Judge-V1 Focus)

### V1-SCOPE-001 - Judge-V1 Scope Freeze
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Deferred feature list documented, no scope creep
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### V1-DEFAULT-001 - Judge Strict Default Profile
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Defaults set to strict, no network, single-process, controlled writable area, no_new_privs required
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

## 2. Core Security Controls (P0 Stop-Ship)

### P0-REP-001 - Truthful Capability Reporting
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Output includes configured/applied/missing controls and downgrade reason, no false security claims
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### P0-STATUS-001 - Stable Status Taxonomy
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Status strings frozen (OK, TLE, MLE, RE, IE, SIG, SV, ABUSE, PLE, FSE), VerdictActor/VerdictCause enums closed
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### P0-PROV-001 - Verdict Provenance Contract
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Every non-OK verdict includes actor/cause/evidence, missing evidence forces IE
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### P0-JSON-001 - Stable Judge JSON Result Schema
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: JSON schema frozen for v1, backward compatible, evidence bundle schema versioned
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### P0-CLEAN-002 - Failure-Injection Matrix
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Matrix covers explicit/early-return/partial-setup/async failure classes, baseline equivalence proven
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### P0-CLEAN-003 - Cleanup Failure Escalation
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Cleanup failure emits IE, marks worker unhealthy, blocks new submissions, no auto-retry
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

## 3. Isolation Core (P1)

### P1-NS-001 - Runtime Namespace Wiring
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Namespace configuration executed in runtime, strict launch denied unless requirements applied
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### P1-TYPESTATE-003 - Compile-Fail Guardrails
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: 9 compile-fail tests pass, early exec and out-of-order transitions fail to compile
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### P1-LIFECYCLE-003 - Fallback Group Kill/Reap
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Graceful → forced kill escalation, bounded waits, full reap, descendants cannot survive
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### P1-RACE-001 - Spawn-to-Cgroup Race Elimination
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Attach-before-exec proven, 100+ adversarial runs per backend mode, zero escapes/leaks
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### P1-CONTAIN-001 - Kernel-Truth Process Containment Proof
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: No orphan, no transient out-of-cgroup PID, no attributable zombie, no post-cleanup leak
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### P1-FS-003 - Host Mountinfo Invariance Proof Matrix
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Empty normalized host mountinfo diff across success/failure/panic/kill paths
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### P1-CGROUPPAR-001 - v1/v2 Outcome Parity Suite
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Memory/cpu/pids cases produce consistent statuses across v1 and v2 backends
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### P1-DIVERGENCE-001 - CPU vs Wall Divergence Classifier
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Divergence classification deterministic (cpu_bound, sleep_or_block_bound, host_interference_suspected, mixed)
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### P1-IO-002 - Output Integrity Classification
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Output end-state classification explicit (complete, truncated_by_judge_limit, truncated_by_program_close, crash_mid_write, write_error)
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### P1-ABUSE-001 - Deterministic Exploit Pattern Classifier
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: ABUSE emitted only for high-confidence deterministic triggers (fork-bomb, FD exhaustion, signal storm, exec churn)
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### P1-LEAK-001 - Zero-Leak Cleanup Guarantee
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Zero leaked processes/mounts/cgroups/zombies after 250+ stress iterations
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### P1-ENVHASH-001 - Execution Envelope Hash
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Envelope ID computed from canonical inputs, same inputs → same hash, different inputs → different hash
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

## 4. Hardening (P1.5)

### P15-SECCOMP-003 - Filtering Metadata and Failure Attribution
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Filtering state recorded, envelope hash includes filtering, failures attributed to filter not judge, default-off, explicit enable flag, reference-catalog non-guarantee language
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

## 5. Quality Gates

### QA-SEC-001 - Adversarial Regression Suite
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Path traversal, symlink races, fork bomb, timeout evasion, spawn-to-cgroup race proof, process-containment proof, filesystem mount-invariance proof, privilege escalation, appeal-safety tests pass
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### QA-REL-001 - Stress and Crash Reliability Suite
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Long-run and crash-recovery suites pass, failure-matrix replay under load, no leaked resources
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### QA-COMPAT-001 - Compatibility Matrix Enforcement
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Ubuntu 20.04/22.04/Debian tested, strict/permissive tested, v2 default/v1 override/fallback tested
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

## 6. Release Gates

### REL-001 - Security Release Checklist
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: All checklist items verified with evidence, signed by release manager and security reviewer
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### REL-002 - RC Soak and Hardening Report
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Soak run completed, unresolved high-severity issues zero, reliability/security claims backed by evidence
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

## 7. Judge-V1 Specific Requirements

### 7.1 Minimum Isolation Baseline
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: PID namespace, mount namespace, UID/GID drop, network disabled, cgroup limits, whole-tree kill/reap
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### 7.2 Classification Correctness
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: CPU-time vs wall-time distinction, memory-limit vs OOM-kill distinction, judge-kill vs kernel-signal distinction
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### 7.3 Provenance Completeness
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: All non-OK outcomes have complete provenance (actor, cause, evidence sources, limit snapshot, signal context)
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### 7.4 Envelope Stability
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Envelope hash stable for reproducible reruns, includes all canonical inputs
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### 7.5 Zero-Leak Cleanup
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Cleanup leaves zero leaked processes/mounts/cgroups in stress suite
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### 7.6 Spawn-to-Cgroup Race Proof
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: 100+ adversarial runs per backend mode, zero escapes, all descendants in cgroup, CPU/memory charged correctly
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### 7.7 Process Containment Proof
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: No orphan, no transient out-of-cgroup PID, no attributable zombie, no post-cleanup leak
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### 7.8 Filesystem Mount Invariance Proof
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Empty normalized host mountinfo diff across success/failure/panic/kill paths
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### 7.9 Provenance Integrity
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Closed actor/cause enums, evidence-bundle schema frozen, IE-on-missing-evidence behavior
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### 7.10 Failure-Path Matrix Integrity
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Explicit/early-return/partial-setup/async classes covered, baseline equivalence proven
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### 7.11 Cleanup-Failure Escalation
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: IE + quarantine on cleanup uncertainty, no auto-retry on unhealthy worker
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

### 7.12 Syscall Filtering Contract
- [ ] **PASS** [ ] **FAIL**
- **Criteria**: Default-off, explicit enable flag, reference-catalog non-guarantee language, metadata attribution
- **Evidence**: _____________
- **Verified By**: _____________
- **Comments**: _____________

## 8. Test Coverage Summary

### 8.1 Test Counts
- **Unit Tests**: _____________ passing (target: 177+)
- **Integration Tests**: _____________ passing (target: 86+)
- **Compile-Fail Tests**: _____________ passing (target: 9)
- **Total Tests**: _____________ passing (target: 278+)

### 8.2 Critical Test Suites
- [ ] Adversarial security suite
- [ ] Spawn-to-cgroup race proof (100+ iterations)
- [ ] Process containment proof
- [ ] Filesystem mount invariance proof
- [ ] Zero-leak cleanup guarantee (250+ iterations)
- [ ] Failure-injection matrix
- [ ] Cgroup v1/v2 parity suite
- [ ] Compile-fail guardrails (9 negative cases)

## 9. Documentation Completeness

### 9.1 User Documentation
- [ ] README.md with judge-v1 scope
- [ ] Installation instructions
- [ ] Configuration guide
- [ ] Language presets (C++, Java, Python)
- [ ] Syscall filtering warnings

### 9.2 Operator Documentation
- [ ] Metrics documentation
- [ ] 5 comprehensive runbooks
- [ ] Health check procedures
- [ ] Troubleshooting guides

### 9.3 Architecture Documentation
- [ ] ADRs (ADR-001, ADR-002, ADR-003)
- [ ] plan.md canonical
- [ ] tasklist.md complete
- [ ] VERIFICATION.md confirms compliance

## 10. Known Limitations and Risks

### 10.1 Documented Limitations
- [ ] Linux-only documented
- [ ] Minimum kernel version documented (4.3+, 5.1+ recommended)
- [ ] Rootless strict explicitly unsupported
- [ ] Syscall filtering no-guarantees documented

### 10.2 Deferred Features (Post-V1)
- [ ] WASM backend
- [ ] eBPF observability extensions
- [ ] CRIU/snapshot features
- [ ] Remote attestation
- [ ] Pluggable policy engines
- [ ] Dynamic syscall filtering tuning
- [ ] Multi-tenant orchestration

### 10.3 Acceptable Risks
| Risk | Likelihood | Impact | Mitigation | Accepted? |
|------|------------|--------|------------|-----------|
|      |            |        |            |           |

## 11. Rollback Plan

### 11.1 Rollback Readiness
- [ ] Rollback procedure documented and tested
- [ ] Rollback decision criteria defined
- [ ] Rollback communication plan ready
- [ ] Backward compatibility verified

### 11.2 Rollback Triggers
- [ ] Critical security vulnerability discovered
- [ ] Widespread containment failures
- [ ] Data corruption or loss
- [ ] Unacceptable performance degradation
- [ ] Other: _____________

## 12. Go/No-Go Decision

### 12.1 Blocking Issues
List any issues that block release:

1. _____________________________________________________________________________
2. _____________________________________________________________________________
3. _____________________________________________________________________________

**Total Blocking Issues**: _____________ (target: 0)

### 12.2 Non-Blocking Issues
List any issues that do not block release but require tracking:

1. _____________________________________________________________________________
2. _____________________________________________________________________________
3. _____________________________________________________________________________

### 12.3 Decision

- [ ] **GO** - All criteria met, release approved
- [ ] **CONDITIONAL GO** - Release approved with documented exceptions (list below)
- [ ] **NO-GO** - Release blocked, issues must be resolved (list above)

**Exceptions (if Conditional GO)**:
_____________________________________________________________________________
_____________________________________________________________________________
_____________________________________________________________________________

**Justification**:
_____________________________________________________________________________
_____________________________________________________________________________
_____________________________________________________________________________

## 13. Sign-Off

### Release Manager
- **Name**: _____________
- **Decision**: [ ] GO [ ] CONDITIONAL GO [ ] NO-GO
- **Signature**: _____________
- **Date**: _____________
- **Comments**: _____________

### Security Reviewer
- **Name**: _____________
- **Decision**: [ ] GO [ ] CONDITIONAL GO [ ] NO-GO
- **Signature**: _____________
- **Date**: _____________
- **Comments**: _____________

### Engineering Lead
- **Name**: _____________
- **Decision**: [ ] GO [ ] CONDITIONAL GO [ ] NO-GO
- **Signature**: _____________
- **Date**: _____________
- **Comments**: _____________

### Product Owner
- **Name**: _____________
- **Decision**: [ ] GO [ ] CONDITIONAL GO [ ] NO-GO
- **Signature**: _____________
- **Date**: _____________
- **Comments**: _____________

## 14. Final Release Authorization

**Release Authorized**: [ ] YES [ ] NO

**Authorization Date**: _____________

**Release Notes**: _____________________________________________________________________________

**Communication Plan**: _____________________________________________________________________________

**Monitoring Plan**: _____________________________________________________________________________

**Post-Release Review Date**: _____________

---

**Gate Version**: 1.0  
**Template Last Updated**: 2026-02-08  
**Based On**: plan.md, tasklist.md, REL-001, REL-002
