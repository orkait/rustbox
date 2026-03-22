+++
title = "Testing"
weight = 3
insert_anchor_links = "right"
+++

# Testing

## CI structure

Three lanes run on every push and PR:

```
build-and-core-tests (85s) ──→ strict-compile-fail (30s)
supply-chain-audit (25s, parallel)
```

Total wall time: ~2 minutes.

### Lane 1: Build + Core Tests

```bash
cargo test --all -- --nocapture --test-threads=1
```

175 tests across the main crate and judge-service. Single-threaded to prevent workspace race conditions between sandbox instances.

### Lane 2: Compile-Fail (Typestate)

```bash
cargo test --test trybuild
```

Verifies that skipping typestate steps or reordering them produces compiler errors. Uses the `trybuild` crate to assert specific error messages.

### Lane 3: Supply Chain Audit

Two checks, no Rust compilation needed:

- **Unsafe boundary audit** (`scripts/unsafe-audit.sh`): Scans every module for `unsafe` blocks. Fails if `verdict/` contains any unsafe code. Reports SAFETY comment coverage.
- **Dependency audit** (cargo-deny): Checks all dependencies against the RustSec advisory database for known CVEs. Validates licenses are permissive (MIT/Apache-2.0/BSD). Blocks dependencies from unknown registries.

## Local testing

```bash
# All tests (permissive, no root)
cargo test --all -- --nocapture

# Strict mode (requires root)
sudo cargo test --test integration_execution -- --test-threads=1 --include-ignored

# Seccomp integration
cargo test --test seccomp_integration -- --nocapture

# Unsafe audit
bash scripts/unsafe-audit.sh

# Dependency audit
cargo deny check
```

## Fuzz targets

Three fuzz targets in `fuzz/` for local use (not in CI - adds 4 minutes for marginal value):

```bash
# Install (one-time)
cargo install cargo-fuzz

# Run a target
cargo +nightly fuzz run fuzz_verdict           # verdict classifier
cargo +nightly fuzz run fuzz_config_deser      # config JSON parsing
cargo +nightly fuzz run fuzz_binding_parse     # directory binding parser

# Run for a fixed duration
cargo +nightly fuzz run fuzz_verdict -- -max_total_time=60
```

These are useful before merging changes to the verdict classifier, config parser, or binding validator. Not useful for routine changes.

## Test tiers

| Tier | What | When | How |
|------|------|------|-----|
| Unit (108) | Module-level logic | Every push | `cargo test --all` |
| Integration (19 permissive) | Full execution pipeline without root | Every push | `cargo test --test integration_execution` |
| Integration (7 strict) | Full pipeline with root, all controls | Manual / pre-release | `sudo cargo test --test integration_execution -- --include-ignored` |
| Compile-fail | Typestate invariants | Every push | `cargo test --test trybuild` |
| Fuzz | Edge-case input bugs | Before merging parser changes | `cargo +nightly fuzz run <target>` |
| Supply chain | CVEs, licenses, unsafe boundary | Every push | `cargo deny check` + `scripts/unsafe-audit.sh` |
