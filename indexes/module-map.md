# Module Map

Complete module hierarchy organized by functional layer.

## Top-Level Modules (`src/lib.rs`)

```
rustbox
├── kernel/          Linux primitive wrappers — all `unsafe` lives here
├── exec/            Execution orchestration + type-state chain
├── core/            Process model (proxy, supervisor, types)
├── judge/           Language adapter layer (Python / C++ / Java)
├── verdict/         Evidence-backed verdict classification
├── safety/          Cleanup, locking, workspace
├── config/          Configuration, types, policy, presets
├── observability/   Audit logging + metrics
├── utils/           FD closure, env hygiene, output, JSON schema
├── testing/         Mount invariance + race-condition proof helpers
├── runtime/         Isolate lifecycle + security validation
└── cli.rs           CLI entrypoint, mode dispatch
```

---

## `kernel/` — Linux Primitive Wrappers

| File | Symbols | Responsibility |
|------|---------|----------------|
| `src/kernel/mod.rs` | 11 | Re-exports all submodules |
| `src/kernel/namespace.rs` | 21 | `NamespaceIsolation`, builder, `harden_mount_propagation`, loopback setup |
| `src/kernel/cgroup.rs` | 31 | `CgroupBackend` trait, `detect_cgroup_backend()`, `SelectedBackend`, v1/v2 auto-select |
| `src/kernel/cgroup_v1.rs` | 34 | `CgroupV1` — memory/cpu/pids controllers, CFS period |
| `src/kernel/cgroup_v2.rs` | 46 | `CgroupV2` — unified hierarchy, swap limit, cgroup.kill |
| `src/kernel/capabilities.rs` | 33 | `drop_all_capabilities_strict()`, `set_no_new_privs()`, `CapabilityNumber` |
| `src/kernel/credentials.rs` | 9 | `transition_to_unprivileged()`, UID/GID validation |
| `src/kernel/mount.rs` | 1 | Re-export for `filesystem` |
| `src/kernel/mount/filesystem.rs` | 38 | `FilesystemSecurity`, `DeviceNode`, essential device nodes |
| `src/kernel/signal.rs` | 33 | `SignalHandler`, `SHUTDOWN_REQUESTED`, `should_continue()` |
| `src/kernel/pipeline.rs` | 28 | `KernelPipeline`, `KernelStage` trait, ordered stage validation |
| `src/kernel/contract.rs` | 9 | `KernelDomain`, `EnforcementMode`, `REQUIRED_STAGE_ORDER`, requirements |
| `src/kernel/runtime_exec.rs` | 31 | `build_preexec_stage_plan()`, static stage definitions, `run_preexec_pipeline()` |

---

## `exec/` — Execution Orchestration

| File | Symbols | Responsibility |
|------|---------|----------------|
| `src/exec/mod.rs` | 2 | Re-exports executor, preexec |
| `src/exec/preexec.rs` | 35 | **Type-state chain**: `FreshChild → NamespacesReady → MountsPrivate → CgroupAttached → CredsDropped → PrivsLocked → ExecReady`; `Sandbox<S>` wrapper |
| `src/exec/executor.rs` | 32 | `ProcessExecutor` — validate, setup limits, execute via supervisor |

---

## `core/` — Process Lifecycle Model

| File | Symbols | Responsibility |
|------|---------|----------------|
| `src/core/mod.rs` | 3 | Re-exports proxy, supervisor, types |
| `src/core/types.rs` | 19 | `ExecutionProfile`, `SandboxLaunchRequest`, `LaunchEvidence`, `KillReport`, `ProxyStatus` |
| `src/core/proxy.rs` | 13 | Proxy role runner — reads `SandboxLaunchRequest` via pipe, runs type-state chain, writes `ProxyStatus` |
| `src/core/supervisor.rs` | 13 | `launch_with_supervisor()`, `launch_degraded()`, pidfd detection, cgroup attachment, timeout kill |

---

## `judge/` — Language Adapter Layer

| File | Symbols | Responsibility |
|------|---------|----------------|
| `src/judge/mod.rs` | 3 | Re-exports adapter, languages, registry |
| `src/judge/adapter.rs` | 6 | `JudgeAdapter` trait: `language()`, `compile_profile()`, `run_profile()`, `compile_command()`, `run_command()` |
| `src/judge/registry.rs` | 1 | `adapter_for(language)` — dispatches to Python/Cpp/Java |
| `src/judge/languages/python.rs` | 8 | `PythonAdapter` — no-compile, direct exec with `/usr/bin/python3 -u -c` |
| `src/judge/languages/cpp.rs` | 8 | `CppAdapter` — `g++ -O2 -o` compile, then isolated binary exec |
| `src/judge/languages/java.rs` | 9 | `JavaAdapter` — `javac` compile, class name detection, `java` run |

---

## `verdict/` — Evidence-Backed Verdict

| File | Symbols | Responsibility |
|------|---------|----------------|
| `src/verdict/mod.rs` | 1 | Re-exports verdict |
| `src/verdict/verdict.rs` | 21 | `VerdictClassifier::classify()` — pure function over `EvidenceBundle + LimitSnapshot` → `(ExecutionStatus, VerdictProvenance)` |

---

## `safety/` — Cleanup and Integrity

| File | Symbols | Responsibility |
|------|---------|----------------|
| `src/safety/mod.rs` | 4 | Re-exports all submodules |
| `src/safety/cleanup.rs` | 42 | `ResourceLedger`, `CleanupManager`, `BaselineChecker` — idempotent reverse-order cleanup |
| `src/safety/lock_manager.rs` | 47 | `RustboxLockManager`, `BoxLock`, `acquire_box_lock()` — flock-based, stable inodes, stale detection |
| `src/safety/safe_cleanup.rs` | 28 | `FdGuard`, `DirGuard`, `remove_tree_secure()` — fd-relative safe delete |
| `src/safety/workspace.rs` | 23 | `Workspace`, `WorkspaceManager` — per-run artifact isolation in temp dirs |

---

## `config/` — Configuration and Policy

| File | Symbols | Responsibility |
|------|---------|----------------|
| `src/config/mod.rs` | 5 | Re-exports all submodules |
| `src/config/types.rs` | 52 | **Central type library**: `IsolateConfig`, `IsolateError`, `ExecutionStatus`, `EvidenceBundle`, `VerdictProvenance`, `DirectoryBinding`, `CapabilityReport` |
| `src/config/config.rs` | 15 | `RustBoxConfig`, `LanguageConfig`, `MemoryConfig`, `TimeConfig` — `config.json` deserialization |
| `src/config/validator.rs` | 24 | `validate_config()`, `ValidationResult` — config-to-enforcement matrix |
| `src/config/presets.rs` | 32 | `LanguagePresets`, `LanguageEnvelope` — versioned envelopes (cpp17-v1, java17-v1, python3.11-v1) |
| `src/config/policy/mod.rs` | 2 | Re-exports proc_sys, userns |
| `src/config/policy/proc_sys.rs` | 22 | `ProcSysPolicy` — `/proc` and `/sys` mount policies (strict vs permissive) |
| `src/config/policy/userns.rs` | 18 | `UserNamespacePolicy` — RootfulStrict / RootlessStrict (deferred) / Permissive / Disabled |

---

## `observability/` — Audit and Metrics

| File | Symbols | Responsibility |
|------|---------|----------------|
| `src/observability/mod.rs` | 2 | Re-exports audit, metrics |
| `src/observability/audit.rs` | 59 | `SecurityLogger`, `SecurityEvent`, `SecurityEventType` (25 variants), `CorrelationIds`, `events::*` helpers |
| `src/observability/metrics.rs` | 53 | `Counter`, `Gauge`, `Histogram`, `MetricRegistry` — in-process Prometheus-compatible metrics |

---

## `utils/` — Utilities

| File | Symbols | Responsibility |
|------|---------|----------------|
| `src/utils/mod.rs` | 4 | Re-exports all submodules |
| `src/utils/fd_closure.rs` | 9 | `close_inherited_fds()` — `close_range(2)` syscall or `/proc/self/fd` fallback |
| `src/utils/env_hygiene.rs` | 22 | `EnvHygiene`, `EnvPolicy`, `PermissionPolicy` — `clearenv()` then selective restore |
| `src/utils/output.rs` | 14 | `OutputCollector`, `OutputLimits` — bounded stdout/stderr collection |
| `src/utils/json_schema.rs` | 20 | `JudgeResultV1`, `MinimalResult`, `create_capability_report_from_evidence()` |

---

## `runtime/` — Isolate Lifecycle

| File | Symbols | Responsibility |
|------|---------|----------------|
| `src/runtime/mod.rs` | 2 | Re-exports isolate, security |
| `src/runtime/isolate.rs` | 35 | `Isolate` — `init()`, `load()`, `execute_code_string()`, `list_all()`, atomic state writes |
| `src/runtime/security.rs` | 17 | `validate_and_resolve_command()`, `ALLOWED_EXECUTABLES`, path allowlist |

---

## `testing/` — Proof Frameworks

| File | Symbols | Responsibility |
|------|---------|----------------|
| `src/testing/mod.rs` | 2 | Re-exports both modules |
| `src/testing/mount_invariance.rs` | 18 | `capture_baseline()`, `compare_mountinfo()`, `verify_mount_invariance()` — `/proc/self/mountinfo` parsing |
| `src/testing/race_proof.rs` | 24 | `RaceProofConfig`, `RaceProofResult` — concurrent sandbox launch stress testing |

---

## Test Files

| File | Symbols | Coverage |
|------|---------|----------|
| `tests/kernel_integration.rs` | 6 | Privilege drop sequence, credential validation, idempotency |
| `tests/kernel_mount_tests.rs` | 14 | FilesystemSecurity, chroot, path validation, strict bindings |
| `tests/kernel_namespace_tests.rs` | 14 | NamespaceIsolation builder, apply_isolation, harden_mount_propagation |
| `tests/trybuild.rs` | 1 | Dispatches all typestate compile-fail tests |
| `tests/typestate_compile_fail/*.rs` | 7 | Each verifies one illegal state transition is a compile error |
| `benches/cold_start_bench.rs` | 13 | Cold-start latency benchmark with p50/p95/p99 stats |
