---
title: Testing
description: CI lanes, test tiers, unsafe audit
---

## CI structure

Three lanes, ~2 minutes total:

```
build-and-core-tests (85s) → strict-compile-fail (30s)
supply-chain-audit (25s, parallel)
```

### Build + Core Tests

106 unit tests across the main crate and judge-service. Single-threaded to prevent workspace race conditions. Integration tests (67 total) are ignored in CI because they require root.

### Compile-Fail (Typestate)

8 trybuild compile-fail tests verify that skipping or reordering typestate steps produces compiler errors.

### Supply Chain Audit

- **Dependency audit** (cargo-deny) - CVE checks, license validation, source verification

## Local testing

```bash
# All tests (permissive, no root)
cargo test --all -- --nocapture

# Strict mode (requires root)
sudo cargo test --test integration_execution -- --test-threads=1 --include-ignored

# Using dev.py helpers
python3 dev.py test          # fmt + clippy + cargo test
python3 dev.py stress        # parallel stress (260+ req/s, verifies every result)
python3 dev.py bench         # throughput benchmark (tiers 1-1000)
python3 dev.py adversarial   # 22 adversarial + 4 correctness + 11 recovery

# Dependency audit
cargo deny check
```

## Test tiers

| Tier | Count | When | How |
|------|-------|------|-----|
| Unit | 106 | Every push | `cargo test --all` |
| Integration (ignored in CI, need root) | 67 | Manual / pre-release | `sudo ... --include-ignored` |
| Compile-fail (trybuild) | 8 | Every push | `cargo test --test trybuild` |
| Adversarial | 22 | Manual | `python3 dev.py adversarial` |
| Correctness | 4 | Manual | included in integration suite |
| Recovery | 11 | Manual | included in integration suite |
| Algorithm suite | 33 | Manual | included in integration suite |
| Supply chain | - | Every push | `cargo deny check` |
