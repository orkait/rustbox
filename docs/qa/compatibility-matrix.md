# Compatibility Matrix (QA-COMPAT-001)

**Purpose**: Ensure supported environments have known, tested outcomes.  
**Invariant**: Kernel/distro variance does not change security behavior.

## Supported Platforms

### Operating Systems

| OS | Version | Kernel | Cgroup | Status |
|----|---------|--------|--------|--------|
| Ubuntu | 20.04 LTS | 5.4+ | v1/v2 | ✅ Supported |
| Ubuntu | 22.04 LTS | 5.15+ | v2 | ✅ Supported |
| Ubuntu | 24.04 LTS | 6.8+ | v2 | ✅ Supported |
| Debian | 11 (Bullseye) | 5.10+ | v1/v2 | ✅ Supported |
| Debian | 12 (Bookworm) | 6.1+ | v2 | ✅ Supported |
| RHEL | 8.x | 4.18+ | v1/v2 | ⚠️ Tested |
| RHEL | 9.x | 5.14+ | v2 | ⚠️ Tested |
| CentOS | 8 Stream | 4.18+ | v1/v2 | ⚠️ Tested |

**Legend**:
- ✅ Supported: Fully tested and supported
- ⚠️ Tested: Tested but not officially supported
- ❌ Unsupported: Not tested, may not work

### Kernel Requirements

| Feature | Minimum Kernel | Recommended | Required For |
|---------|---------------|-------------|--------------|
| PID namespace | 2.6.24 | 3.8+ | Strict mode |
| Mount namespace | 2.4.19 | 3.8+ | Strict mode |
| Cgroup v1 | 2.6.24 | 4.5+ | Resource limits |
| Cgroup v2 | 4.5 | 5.0+ | OOM detection, peak memory |
| Pidfd | 5.3 | 5.3+ | Race-free signaling |
| close_range | 5.9 | 5.9+ | FD closure |
| memory.peak | 5.19 | 5.19+ | Peak memory accounting |
| memory.oom.group | 5.0 | 5.0+ | Whole-tree OOM |

### Cgroup Compatibility

| Backend | Version | Controllers | OOM Detection | Peak Memory | Status |
|---------|---------|-------------|---------------|-------------|--------|
| v1 | Any | cpu, memory, pids | Partial | ❌ | ✅ Supported |
| v2 | 4.5+ | cpu, memory, pids | ✅ Full | ❌ | ✅ Supported |
| v2 | 5.0+ | cpu, memory, pids | ✅ Full | ❌ | ✅ Supported |
| v2 | 5.19+ | cpu, memory, pids | ✅ Full | ✅ Full | ✅ Recommended |

## Test Matrix

### Core Functionality Tests

Run on all supported platforms:

```bash
# Basic execution
cargo test --lib

# Integration tests
cargo test --test '*'

# Adversarial security
cargo test --test adversarial_security_test
cargo test --test process_containment_test

# Cgroup parity
cargo test --test cgroup_parity_test
```

### Platform-Specific Tests

#### Ubuntu 20.04 (Cgroup v1)

```bash
# Force cgroup v1
rustbox --cgroup-v1 run --code "echo test"

# Verify v1 backend selected
rustbox health | jq '.backend_selection.cgroup_backend'
# Expected: "v1"

# Run parity tests
cargo test --test cgroup_parity_test
```

#### Ubuntu 22.04+ (Cgroup v2)

```bash
# Default cgroup v2
rustbox run --code "echo test"

# Verify v2 backend selected
rustbox health | jq '.backend_selection.cgroup_backend'
# Expected: "v2"

# Test OOM detection
cargo test --test cgroup_parity_test -- oom

# Test peak memory
cargo test --lib cgroup_v2::tests::test_peak_memory
```

#### Kernel 5.3+ (Pidfd)

```bash
# Verify pidfd support
rustbox health | jq '.backend_selection.pidfd_mode'
# Expected: "native"

# Test pidfd signaling
cargo test --lib supervisor::tests
```

#### Kernel <5.3 (Pidfd fallback)

```bash
# Verify fallback mode
rustbox health | jq '.backend_selection.pidfd_mode'
# Expected: "fallback"

# Test fallback signaling
cargo test --lib supervisor::tests
```

## CI Matrix

### GitHub Actions Matrix

```yaml
# .github/workflows/compatibility.yml
name: Compatibility Matrix
on: [push, pull_request]
jobs:
  test:
    strategy:
      matrix:
        os:
          - ubuntu-20.04
          - ubuntu-22.04
          - ubuntu-24.04
        cgroup:
          - v1
          - v2
        mode:
          - strict
          - permissive
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v2
      - name: Setup cgroup ${{ matrix.cgroup }}
        run: ./scripts/setup-cgroup-${{ matrix.cgroup }}.sh
      - name: Run tests
        run: cargo test
      - name: Run parity tests
        run: cargo test --test cgroup_parity_test
```

## Compatibility Assertions

### Cgroup v1/v2 Parity

**Assertion**: Same input produces same verdict on v1 and v2

**Test**:
```bash
# Run on v1
rustbox --cgroup-v1 run --code "..." > result-v1.json

# Run on v2
rustbox run --code "..." > result-v2.json

# Compare verdicts
diff <(jq '.status' result-v1.json) <(jq '.status' result-v2.json)
```

**Expected**: Identical status for:
- OK (normal completion)
- TLE (timeout)
- MLE (memory limit)
- RE (runtime error)
- PLE (process limit)

**Allowed differences**:
- Peak memory (v2 has memory.peak, v1 uses sampled max)
- OOM detection (v2 has memory.events, v1 is heuristic)

### Pidfd Native/Fallback Parity

**Assertion**: Same kill/reap behavior with and without pidfd

**Test**:
```bash
# Test on kernel 5.3+ (native)
cargo test --lib supervisor::tests

# Test on kernel <5.3 (fallback)
cargo test --lib supervisor::tests
```

**Expected**: Identical behavior for:
- Graceful kill (SIGTERM → SIGKILL)
- Process reap
- Zombie handling
- Timeout enforcement

## Known Limitations

### Platform-Specific

**Ubuntu 20.04**:
- Cgroup v2 not default (requires kernel parameter)
- No memory.peak (kernel 5.4)
- Pidfd available (kernel 5.4)

**Debian 11**:
- Cgroup v1 default
- No memory.peak (kernel 5.10)
- Pidfd available (kernel 5.10)

**RHEL 8**:
- Cgroup v1 default
- Older kernel (4.18)
- No pidfd (kernel 4.18)
- Fallback mode required

### Feature Availability

| Feature | Ubuntu 20.04 | Ubuntu 22.04 | Debian 11 | Debian 12 | RHEL 8 |
|---------|--------------|--------------|-----------|-----------|--------|
| Cgroup v2 | ⚠️ Manual | ✅ Default | ⚠️ Manual | ✅ Default | ⚠️ Manual |
| Pidfd | ✅ | ✅ | ✅ | ✅ | ❌ |
| close_range | ❌ | ✅ | ✅ | ✅ | ❌ |
| memory.peak | ❌ | ✅ | ❌ | ✅ | ❌ |
| memory.oom.group | ✅ | ✅ | ✅ | ✅ | ❌ |

## Deployment Recommendations

### Production

**Recommended**:
- Ubuntu 22.04 LTS or later
- Debian 12 or later
- Kernel 5.15+
- Cgroup v2 enabled
- Pidfd support

**Minimum**:
- Ubuntu 20.04 LTS
- Debian 11
- Kernel 5.4+
- Cgroup v1 or v2
- Pidfd fallback acceptable

### Development

**Recommended**:
- Ubuntu 24.04 LTS
- Kernel 6.8+
- Cgroup v2
- All features available

## Validation Checklist

Before deploying to new platform:

- [ ] Run full test suite: `cargo test`
- [ ] Run adversarial tests: `cargo test --test adversarial_security_test`
- [ ] Run containment proof: `cargo test --test process_containment_test`
- [ ] Run cgroup parity: `cargo test --test cgroup_parity_test`
- [ ] Run leak check: `cargo test --test leak_check_test`
- [ ] Verify backend selection: `rustbox health`
- [ ] Check capability report: `rustbox --dry-run run --code "echo test"`
- [ ] Run stress test: `./tests/scripts/stress_test.sh --duration 600`
- [ ] Verify no leaks: `./tests/scripts/leak_check_stress.sh --iterations 100`

## Reporting Issues

If compatibility issue found:

1. **Document environment**:
   - OS and version
   - Kernel version
   - Cgroup version
   - Available features

2. **Reproduce**:
   - Minimal reproduction case
   - Expected vs actual behavior
   - Logs and error messages

3. **Report**:
   - Open GitHub issue
   - Tag with `compatibility`
   - Include environment details

## Related Documentation

- Plan.md Section 15: Verification Matrix
- Plan.md Section 8.1: Backend Selection
- Tests: `tests/cgroup_parity_test.rs`
- Docs: `docs/operations/runbooks/backend-mismatch.md`
