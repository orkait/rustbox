---
title: Testing
description: CI lanes, fuzz targets, unsafe audit
---

## CI structure

Three lanes, ~2 minutes total:

```
build-and-core-tests (85s) → strict-compile-fail (30s)
supply-chain-audit (25s, parallel)
```

### Build + Core Tests

175 tests across the main crate and judge-service. Single-threaded to prevent workspace race conditions.

### Compile-Fail (Typestate)

Verifies that skipping or reordering typestate steps produces compiler errors. Uses `trybuild`.

### Supply Chain Audit

- **Unsafe boundary audit** - fails if `verdict/` contains any `unsafe` blocks
- **Dependency audit** (cargo-deny) - CVE checks, license validation, source verification

## Local testing

```bash
# All tests (permissive, no root)
cargo test --all -- --nocapture

# Strict mode (requires root)
sudo cargo test --test integration_execution -- --test-threads=1 --include-ignored

# Unsafe audit
bash scripts/unsafe-audit.sh

# Dependency audit
cargo deny check
```

## Fuzz targets

Three targets in `fuzz/` for local use (not in CI):

```bash
cargo +nightly fuzz run fuzz_verdict          # verdict classifier
cargo +nightly fuzz run fuzz_config_deser     # config JSON parsing
cargo +nightly fuzz run fuzz_binding_parse    # directory binding parser
```

## Test tiers

| Tier | Count | When | How |
|------|-------|------|-----|
| Unit | 108 | Every push | `cargo test --all` |
| Integration (permissive) | 19 | Every push | `cargo test --test integration_execution` |
| Integration (strict) | 7 | Manual / pre-release | `sudo ... --include-ignored` |
| Compile-fail | - | Every push | `cargo test --test trybuild` |
| Fuzz | - | Before parser changes | `cargo +nightly fuzz run` |
| Supply chain | - | Every push | `cargo deny check` + `scripts/unsafe-audit.sh` |
