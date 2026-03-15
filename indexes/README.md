# Rustbox Semantic Index

Generated from live codebase analysis (94 files, 1197 symbols, 511 chunks).
Git head: `085c1cfc3396ac0c0c1db5cf337c90dfe535a169`

## Index Files

| File | Covers |
|------|--------|
| [module-map.md](module-map.md) | Complete module hierarchy, ownership, file counts |
| [typestate-chain.md](typestate-chain.md) | The compile-enforced pre-exec ordering system |
| [kernel-primitives.md](kernel-primitives.md) | All kernel-layer modules (namespaces, cgroups, capabilities, mounts, signals) |
| [execution-flow.md](execution-flow.md) | End-to-end execution path from CLI to payload |
| [verdict-system.md](verdict-system.md) | Evidence bundles, verdict classification, JudgeResultV1 schema |
| [config-types.md](config-types.md) | Central type definitions, IsolateConfig, policy |
| [safety-subsystem.md](safety-subsystem.md) | Cleanup, lock manager, workspace, safe_cleanup primitives |
| [language-adapters.md](language-adapters.md) | Judge language adapters (Python, C++, Java) and registry |
| [observability.md](observability.md) | Audit logging, metrics, security events |
| [data-flow.md](data-flow.md) | Key data flows: config → execution → evidence → verdict |
| [symbol-index.md](symbol-index.md) | Searchable index of public symbols by kind |

## Quick Navigation

### Entry Points
- CLI: `src/cli.rs:run()` — mode-gated command dispatch
- Binaries: `src/main.rs` (rustbox), `src/bin/isolate.rs`, `src/bin/judge.rs`

### Core Safety Invariant
`src/exec/preexec.rs` — `FreshChild → ExecReady` typestate chain
Only `Sandbox<ExecReady>` can call `exec_payload()`.

### Verdict Output Contract
`src/utils/json_schema.rs` — `JudgeResultV1` (schema version "1.0", frozen)

### Resource Enforcement
`src/kernel/cgroup.rs` — `CgroupBackend` trait + auto v1/v2 selection
