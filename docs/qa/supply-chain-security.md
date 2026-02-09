# Supply Chain Security (QA-SUPPLY-001)

**Purpose**: Enforce build/test quality bars pre-merge.  
**Invariant**: Supply chain and unsafe code drift are prevented.

## Static Analysis

### Rust Format Check

**Tool**: `rustfmt`

**Command**:
```bash
cargo fmt -- --check
```

**Pass Criteria**: No formatting violations

**CI Integration**:
```yaml
- name: Check formatting
  run: cargo fmt -- --check
```

### Clippy Lints

**Tool**: `clippy` (strict mode)

**Command**:
```bash
cargo clippy --all-targets --all-features -- -D warnings
```

**Enabled Lints**:
- All default lints
- `clippy::all`
- `clippy::pedantic` (selected)
- `clippy::cargo`

**Pass Criteria**: Zero warnings

**CI Integration**:
```yaml
- name: Run clippy
  run: cargo clippy --all-targets --all-features -- -D warnings
```

### Cargo Audit

**Tool**: `cargo-audit`

**Command**:
```bash
cargo audit
```

**Checks**:
- Known vulnerabilities in dependencies
- Unmaintained crates
- Yanked crates
- Security advisories

**Pass Criteria**: Zero vulnerabilities

**CI Integration**:
```yaml
- name: Security audit
  run: |
    cargo install cargo-audit
    cargo audit
```

**Frequency**: Daily automated scan

## Dependency Management

### Dependency Review

**Process**:
1. Review all new dependencies
2. Check crate popularity and maintenance
3. Verify license compatibility
4. Review security history
5. Document rationale

**Criteria**:
- Crate has >1000 downloads/month
- Last updated within 6 months
- No known security issues
- Compatible license (MIT, Apache-2.0, BSD)

### Dependency Pinning

**Strategy**: Pin major versions, allow minor/patch updates

**Cargo.toml**:
```toml
[dependencies]
serde = "1.0"  # Allow 1.x updates
clap = "4.4"   # Allow 4.4.x updates
```

### Dependency Audit Log

Maintain `docs/dependencies.md` with:
- Dependency name and version
- Purpose and usage
- Security review date
- Known issues
- Update policy

## Unsafe Code Review

### Unsafe Code Audit

**Locations**:
- `src/capabilities.rs` - prctl, capset
- `src/preexec.rs` - setresuid, setresgid
- `src/supervisor.rs` - pidfd operations
- `src/namespace.rs` - unshare, setns

**Review Checklist**:
- [ ] Unsafe block is minimal
- [ ] Safety invariants documented
- [ ] No undefined behavior
- [ ] Memory safety guaranteed
- [ ] Reviewed by 2+ engineers

### Unsafe Code Policy

**Rules**:
1. Minimize unsafe code
2. Document safety invariants
3. Prefer safe abstractions
4. Two-engineer review required
5. Add safety tests

**Example**:
```rust
// SAFETY: prctl(PR_SET_NO_NEW_PRIVS) is safe because:
// 1. We pass valid arguments
// 2. We check return value
// 3. No memory is accessed
unsafe {
    let ret = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if ret != 0 {
        return Err(IsolateError::Privilege("Failed to set no_new_privs".into()));
    }
}
```

## Fuzz Testing

### Fuzz Targets

**Target 1: Config Parsing**
```rust
// fuzz/fuzz_targets/config_parse.rs
#[macro_use] extern crate libfuzzer_sys;
extern crate rustbox;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<rustbox::types::IsolateConfig>(s);
    }
});
```

**Target 2: Lock File Parsing**
```rust
// fuzz/fuzz_targets/lock_parse.rs
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = rustbox::lock_manager::parse_lock_file(s);
    }
});
```

**Target 3: Path Canonicalization**
```rust
// fuzz/fuzz_targets/path_canon.rs
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = rustbox::filesystem::canonicalize_path(s);
    }
});
```

### Running Fuzz Tests

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run config parsing fuzzer
cargo fuzz run config_parse -- -max_total_time=300

# Run lock file fuzzer
cargo fuzz run lock_parse -- -max_total_time=300

# Run path canonicalization fuzzer
cargo fuzz run path_canon -- -max_total_time=300
```

### Fuzz Coverage

**Minimum Coverage**:
- Config parsing: 1 hour
- Lock file parsing: 1 hour
- Path operations: 1 hour
- JSON parsing: 1 hour

**Frequency**: Weekly automated fuzzing

## Build Reproducibility

### Reproducible Builds

**Goal**: Same source produces same binary

**Requirements**:
- Fixed Rust version
- Pinned dependencies
- Deterministic build flags
- No timestamp embedding

**Verification**:
```bash
# Build twice
cargo clean && cargo build --release
cp target/release/rustbox rustbox1

cargo clean && cargo build --release
cp target/release/rustbox rustbox2

# Compare
sha256sum rustbox1 rustbox2
```

### Build Provenance

**SLSA Level 2 Requirements**:
- Source integrity (git commit hash)
- Build platform (OS, Rust version)
- Build command
- Dependencies (Cargo.lock)
- Build timestamp
- Builder identity

**Provenance File**:
```json
{
  "version": "0.1.0",
  "git_commit": "abc123...",
  "rust_version": "1.75.0",
  "build_platform": "ubuntu-22.04",
  "build_timestamp": "2026-02-08T12:34:56Z",
  "dependencies_hash": "sha256:...",
  "binary_hash": "sha256:..."
}
```

## CI/CD Security

### GitHub Actions Security

**Best Practices**:
- Pin action versions (not @main)
- Use minimal permissions
- No secrets in logs
- Verify checksums
- Use trusted actions only

**Example**:
```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4  # Pinned version
    with:
      persist-credentials: false
```

### Artifact Signing

**Process**:
1. Build release binary
2. Generate SHA256 checksum
3. Sign with GPG key
4. Publish signature

**Commands**:
```bash
# Generate checksum
sha256sum rustbox > rustbox.sha256

# Sign
gpg --detach-sign --armor rustbox.sha256

# Verify
gpg --verify rustbox.sha256.asc rustbox.sha256
sha256sum -c rustbox.sha256
```

## Security Scanning

### Container Scanning

If using Docker:

```bash
# Scan base image
docker scan ubuntu:22.04

# Scan rustbox image
docker scan rustbox:latest
```

### SAST (Static Application Security Testing)

**Tools**:
- `cargo-audit` - Dependency vulnerabilities
- `cargo-deny` - License and security policy
- `clippy` - Code quality and security lints

**Configuration** (`.cargo/deny.toml`):
```toml
[advisories]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"

[licenses]
unlicensed = "deny"
allow = ["MIT", "Apache-2.0", "BSD-3-Clause"]
deny = ["GPL-3.0"]

[bans]
multiple-versions = "warn"
```

## Pre-Merge Checklist

Before merging any PR:

- [ ] `cargo fmt -- --check` passes
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test` passes (all tests)
- [ ] `cargo audit` passes (no vulnerabilities)
- [ ] No new unsafe code (or reviewed if added)
- [ ] Dependencies reviewed (if added)
- [ ] Security tests pass
- [ ] Two-engineer review (for security-critical code)

## Continuous Monitoring

### Daily Scans

```bash
# Dependency audit
cargo audit

# Check for updates
cargo outdated

# License check
cargo deny check licenses
```

### Weekly Scans

```bash
# Fuzz testing
cargo fuzz run config_parse -- -max_total_time=3600
cargo fuzz run lock_parse -- -max_total_time=3600

# Full security scan
cargo clippy --all-targets --all-features -- -D warnings
cargo audit
cargo deny check
```

### Monthly Reviews

- Review all dependencies
- Update dependencies (minor/patch)
- Review unsafe code
- Update security documentation

## Incident Response

If vulnerability found:

1. **Assess severity** (CVSS score)
2. **Identify affected versions**
3. **Develop fix**
4. **Test fix**
5. **Release patch**
6. **Notify users**
7. **Publish advisory**

## Related Documentation

- Plan.md Section 18: Governance and Change Control
- Plan.md Section 2: Non-Negotiable Fundamentals
- GOV-002: Security Review Gate
- `.github/PULL_REQUEST_TEMPLATE.md`
