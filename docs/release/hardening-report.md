# RC Soak and Hardening Report (REL-002)

**Purpose**: Prove security posture survives sustained real workloads.  
**Status**: Template - Ready for RC soak testing  
**Version**: 1.0  
**Last Updated**: 2026-02-08

## Overview

This report documents the results of sustained soak testing for a Rustbox release candidate. The soak test must demonstrate that reliability and security claims hold under realistic production workloads.

## Release Candidate Information

- **RC Version**: _____________
- **RC Build Commit**: _____________
- **Soak Test Start**: _____________
- **Soak Test End**: _____________
- **Soak Duration**: _____________ hours
- **Test Environment**: _____________
- **Test Lead**: _____________

## 1. Soak Test Configuration

### 1.1 Test Environment
- **Platform**: _____________
- **Kernel Version**: _____________
- **Cgroup Version**: _____________
- **CPU**: _____________
- **Memory**: _____________
- **Disk**: _____________
- **Network**: _____________

### 1.2 Workload Profile
- **Total Executions**: _____________
- **Execution Rate**: _____________ per second
- **Language Mix**:
  - C++: _____% (_____executions)
  - Java: _____% (_____executions)
  - Python: _____% (_____executions)
- **Workload Types**:
  - Normal completion: _____% 
  - Timeout (TLE): _____% 
  - Memory limit (MLE): _____% 
  - Runtime error (RE): _____% 
  - Other: _____%

### 1.3 Stress Scenarios
- [ ] Concurrent execution stress (max concurrent: _____)
- [ ] Memory pressure stress
- [ ] CPU saturation stress
- [ ] Fork bomb containment stress
- [ ] Timeout evasion stress
- [ ] Rapid start/stop churn
- [ ] Mixed workload stress

## 2. Reliability Metrics

### 2.1 Execution Outcomes
| Status | Count | Percentage | Expected % | Deviation |
|--------|-------|------------|------------|-----------|
| OK     |       |            |            |           |
| TLE    |       |            |            |           |
| MLE    |       |            |            |           |
| RE     |       |            |            |           |
| IE     |       |            |            |           |
| SIG    |       |            |            |           |
| SV     |       |            |            |           |
| ABUSE  |       |            |            |           |
| PLE    |       |            |            |           |
| FSE    |       |            |            |           |

**Analysis**: _____________________________________________________________________________

### 2.2 Infrastructure Errors (IE)
- **Total IE Count**: _____________
- **IE Rate**: _____________% (target: < 0.01%)
- **IE Breakdown**:
  - Cleanup failures: _____________
  - Evidence collection errors: _____________
  - Backend unavailable: _____________
  - Other: _____________

**Root Causes**: _____________________________________________________________________________

**Mitigation**: _____________________________________________________________________________

### 2.3 Cleanup Reliability
- **Total Cleanup Attempts**: _____________
- **Successful Cleanups**: _____________
- **Failed Cleanups**: _____________
- **Cleanup Success Rate**: _____________% (target: > 99.99%)
- **Cleanup Failures by Type**:
  - Mount cleanup: _____________
  - Cgroup cleanup: _____________
  - Process cleanup: _____________
  - Filesystem cleanup: _____________

**Analysis**: _____________________________________________________________________________

### 2.4 Resource Leak Detection
- **Leaked Processes**: _____________ (target: 0)
- **Leaked Mounts**: _____________ (target: 0)
- **Leaked Cgroups**: _____________ (target: 0)
- **Leaked File Descriptors**: _____________ (target: 0)
- **Leaked Temp Directories**: _____________ (target: 0)
- **Zombie Processes**: _____________ (target: 0)

**Evidence**: _____________________________________________________________________________

### 2.5 Worker Health
- **Workers Quarantined**: _____________
- **Quarantine Reasons**:
  - Cleanup failure: _____________
  - Repeated IE: _____________
  - Resource exhaustion: _____________
  - Other: _____________
- **Workers Recovered**: _____________
- **Worker Uptime**: _____________% (target: > 99.9%)

**Analysis**: _____________________________________________________________________________

## 3. Performance Metrics

### 3.1 Latency Distribution
| Metric | p50 | p95 | p99 | p99.9 | Max |
|--------|-----|-----|-----|-------|-----|
| Cold Start (C++) | | | | | |
| Cold Start (Java) | | | | | |
| Cold Start (Python) | | | | | |
| Execution Time | | | | | |
| Cleanup Time | | | | | |
| End-to-End | | | | | |

**Budget Compliance**:
- C++ cold start p50 < 100ms: [ ] PASS [ ] FAIL
- Python cold start p50 < 150ms: [ ] PASS [ ] FAIL
- Java cold start p50 < 250ms: [ ] PASS [ ] FAIL

**Analysis**: _____________________________________________________________________________

### 3.2 Throughput
- **Peak Throughput**: _____________ executions/second
- **Sustained Throughput**: _____________ executions/second
- **Throughput Degradation**: _____________% over soak duration

**Analysis**: _____________________________________________________________________________

### 3.3 Resource Utilization
- **Peak CPU**: _____________%
- **Peak Memory**: _____________ GB
- **Peak Disk I/O**: _____________ MB/s
- **Peak Network**: _____________ MB/s (if applicable)

**Analysis**: _____________________________________________________________________________

## 4. Security Metrics

### 4.1 Containment Violations
- **Escape Attempts Detected**: _____________
- **Successful Escapes**: _____________ (target: 0)
- **Containment Violation Types**:
  - Process escape: _____________
  - Mount escape: _____________
  - Cgroup escape: _____________
  - Privilege escalation: _____________

**Evidence**: _____________________________________________________________________________

### 4.2 Verdict Provenance
- **Verdicts with Complete Evidence**: _____________% (target: 100%)
- **Verdicts Missing Evidence**: _____________
- **Verdicts with Contradictory Evidence**: _____________
- **IE Due to Missing Evidence**: _____________

**Analysis**: _____________________________________________________________________________

### 4.3 Abuse Detection
- **Abuse Patterns Detected**: _____________
- **Abuse Breakdown**:
  - Fork bomb: _____________
  - FD exhaustion: _____________
  - Signal storm: _____________
  - Exec churn: _____________
- **False Positives**: _____________ (target: 0)
- **False Negatives**: _____________ (target: 0)

**Analysis**: _____________________________________________________________________________

## 5. Cgroup Backend Parity

### 5.1 v1 vs v2 Outcome Consistency
- **Total Executions on v1**: _____________
- **Total Executions on v2**: _____________
- **Outcome Mismatches**: _____________ (target: 0)
- **Mismatch Types**:
  - Memory limit: _____________
  - CPU limit: _____________
  - Process limit: _____________
  - OOM behavior: _____________

**Analysis**: _____________________________________________________________________________

### 5.2 Backend Selection
- **v2 Default Success Rate**: _____________% (target: > 99%)
- **v1 Fallback Triggers**: _____________
- **Backend Selection Failures**: _____________

**Analysis**: _____________________________________________________________________________

## 6. Observability and Audit

### 6.1 Audit Event Coverage
- **Total Audit Events**: _____________
- **Events by Type**:
  - Start: _____________
  - Capability decision: _____________
  - Limit violation: _____________
  - Signal escalation: _____________
  - Cleanup: _____________
  - Final status: _____________
- **Missing Correlation IDs**: _____________ (target: 0)
- **Malformed Events**: _____________ (target: 0)

**Analysis**: _____________________________________________________________________________

### 6.2 Metrics Export
- **Metrics Endpoint Availability**: _____________% (target: 100%)
- **Metrics Export Failures**: _____________
- **Prometheus Scrape Errors**: _____________

**Analysis**: _____________________________________________________________________________

### 6.3 Health Check Reliability
- **Health Check Success Rate**: _____________% (target: 100%)
- **Health Check Failures**: _____________
- **Health Check Latency p95**: _____________ ms (target: < 100ms)

**Analysis**: _____________________________________________________________________________

## 7. Incident Summary

### 7.1 Critical Incidents (Severity 1)
| Incident ID | Time | Description | Impact | Resolution | Status |
|-------------|------|-------------|--------|------------|--------|
|             |      |             |        |            |        |

**Total Critical Incidents**: _____________ (target: 0)

### 7.2 High Severity Incidents (Severity 2)
| Incident ID | Time | Description | Impact | Resolution | Status |
|-------------|------|-------------|--------|------------|--------|
|             |      |             |        |            |        |

**Total High Severity Incidents**: _____________ (target: 0)

### 7.3 Medium Severity Incidents (Severity 3)
| Incident ID | Time | Description | Impact | Resolution | Status |
|-------------|------|-------------|--------|------------|--------|
|             |      |             |        |            |        |

**Total Medium Severity Incidents**: _____________

### 7.4 Low Severity Incidents (Severity 4)
| Incident ID | Time | Description | Impact | Resolution | Status |
|-------------|------|-------------|--------|------------|--------|
|             |      |             |        |            |        |

**Total Low Severity Incidents**: _____________

## 8. Known Issues

### 8.1 Unresolved High-Severity Issues
| Issue ID | Description | Severity | Impact | Workaround | Target Fix |
|----------|-------------|----------|--------|------------|------------|
|          |             |          |        |            |            |

**Total Unresolved High-Severity**: _____________ (target: 0)

### 8.2 Unresolved Medium-Severity Issues
| Issue ID | Description | Severity | Impact | Workaround | Target Fix |
|----------|-------------|----------|--------|------------|------------|
|          |             |          |        |            |            |

**Total Unresolved Medium-Severity**: _____________

### 8.3 Deferred Issues (Post-v1)
| Issue ID | Description | Severity | Justification | Target Version |
|----------|-------------|----------|---------------|----------------|
|          |             |          |               |                |

## 9. Regression Analysis

### 9.1 Regressions from Previous RC
| Regression ID | Description | Impact | Root Cause | Fix |
|---------------|-------------|--------|------------|-----|
|               |             |        |            |     |

**Total Regressions**: _____________ (target: 0)

### 9.2 Performance Regressions
| Metric | Previous RC | Current RC | Degradation | Acceptable? |
|--------|-------------|------------|-------------|-------------|
|        |             |            |             |             |

**Analysis**: _____________________________________________________________________________

## 10. Hardening Evidence

### 10.1 Adversarial Test Results
- **Path Traversal Tests**: [ ] PASS [ ] FAIL
- **Symlink Attack Tests**: [ ] PASS [ ] FAIL
- **Fork Bomb Tests**: [ ] PASS [ ] FAIL
- **Timeout Evasion Tests**: [ ] PASS [ ] FAIL
- **Spawn-to-Cgroup Race Tests**: [ ] PASS [ ] FAIL (100+ iterations, 0 escapes)
- **Process Containment Tests**: [ ] PASS [ ] FAIL (0 orphans, 0 zombies, 0 leaks)
- **Mount Invariance Tests**: [ ] PASS [ ] FAIL (empty mountinfo diff)
- **Privilege Escalation Tests**: [ ] PASS [ ] FAIL
- **Appeal-Safety Tests**: [ ] PASS [ ] FAIL (missing evidence → IE)

**Evidence Links**: _____________________________________________________________________________

### 10.2 Stress Test Results
- **Zero-Leak Guarantee**: [ ] PASS [ ] FAIL (250+ iterations)
- **Failure-Injection Matrix**: [ ] PASS [ ] FAIL (all scenarios)
- **Crash Recovery**: [ ] PASS [ ] FAIL
- **Lock Integrity**: [ ] PASS [ ] FAIL

**Evidence Links**: _____________________________________________________________________________

### 10.3 Compatibility Matrix
- **Ubuntu 20.04**: [ ] PASS [ ] FAIL
- **Ubuntu 22.04**: [ ] PASS [ ] FAIL
- **Debian Stable**: [ ] PASS [ ] FAIL
- **Cgroup v2 Default**: [ ] PASS [ ] FAIL
- **Cgroup v1 Fallback**: [ ] PASS [ ] FAIL

**Evidence Links**: _____________________________________________________________________________

## 11. Recommendations

### 11.1 Release Recommendation
- [ ] **RECOMMEND RELEASE** - All criteria met, no blocking issues
- [ ] **CONDITIONAL RELEASE** - Release with documented exceptions (list below)
- [ ] **DO NOT RELEASE** - Blocking issues must be resolved (list below)

**Justification**: _____________________________________________________________________________

### 11.2 Required Actions Before Release
1. _____________________________________________________________________________
2. _____________________________________________________________________________
3. _____________________________________________________________________________

### 11.3 Recommended Improvements (Post-v1)
1. _____________________________________________________________________________
2. _____________________________________________________________________________
3. _____________________________________________________________________________

### 11.4 Monitoring Recommendations
1. _____________________________________________________________________________
2. _____________________________________________________________________________
3. _____________________________________________________________________________

## 12. Sign-Off

### Test Lead Approval
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

## Appendices

### Appendix A: Detailed Metrics
_____________________________________________________________________________

### Appendix B: Incident Reports
_____________________________________________________________________________

### Appendix C: Test Logs
_____________________________________________________________________________

### Appendix D: Performance Profiles
_____________________________________________________________________________

---

**Report Version**: 1.0  
**Template Last Updated**: 2026-02-08  
**Based On**: plan.md, tasklist.md, QA documentation
