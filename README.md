# Rustbox

Secure process isolation for competitive programming judges. Inspired by [IOI Isolate](https://github.com/ioi/isolate).

**Status**: Judge-V1 (v0.1.0) | **Languages**: Python, C++, Java | **Platform**: Linux (cgroups v1/v2)

## What it does

Rustbox executes untrusted code submissions inside kernel-enforced sandboxes with deterministic resource limits and evidence-backed verdicts.

```
                    +-----------+
  source code ----->|  rustbox  |-----> verdict (OK / TLE / MLE / RE / Signaled)
  + language        |  (judge)  |-----> stdout, stderr
  + limits          +-----------+-----> evidence bundle (controls applied, memory peak, cpu time)
                     namespaces
                     cgroups
                     capabilities
                     rlimits
```

## Quick start

```bash
# Build
cargo build --release

# Permissive mode (no root, development only)
target/release/judge execute-code --permissive --box-id 1 --language python --code 'print("hello")'

# Strict mode (root required, production)
sudo target/release/judge execute-code --strict --box-id 1 --language python --code 'print("hello")'

# C++ submission
sudo target/release/judge execute-code --strict --box-id 2 --language cpp --code '
#include <iostream>
int main() { std::cout << 42 << std::endl; }
'

# Java submission
sudo target/release/judge execute-code --strict --box-id 3 --language java --code '
public class Main {
    public static void main(String[] args) {
        System.out.println("hello world");
    }
}
'
```

Output is `JudgeResultV1` JSON on stdout. Diagnostics go to stderr.

## Security model

| Layer | Mechanism | What it enforces |
|-------|-----------|-----------------|
| Process isolation | `CLONE_NEWPID`, `CLONE_NEWIPC` | Sandbox can't see/signal host processes |
| Filesystem | tmpfs chroot + bind mounts | Read-only root, writable workdir only |
| Network | `CLONE_NEWNET` (strict) | No network access |
| Memory | cgroup `memory.max` / `memory.limit_in_bytes` | Physical memory cap |
| CPU time | `RLIMIT_CPU` + cgroup watchdog | Hard CPU time limit |
| Virtual memory | `RLIMIT_AS` (per-language) | Prevents VMA exhaustion (4GB Java, 1GB others) |
| Processes | cgroup `pids.max` + `RLIMIT_NPROC` | Fork bomb prevention |
| Credentials | `setresuid`/`setresgid` to per-box UID (60000+box_id) | No root, per-box isolation |
| Capabilities | All 5 sets zeroed (bounding, ambient, effective, permitted, inheritable) | No privilege escalation |
| Privileges | `PR_SET_NO_NEW_PRIVS` | No suid/sgid exec |

Compilation runs in permissive mode (compiler is trusted). Only the compiled binary executes under strict isolation.

## Architecture

### Three binaries, one CLI

All binaries call `rustbox::cli::run()` with a different mode:

- **`isolate`** — sandbox lifecycle: `init`, `run`, `status`, `cleanup`
- **`judge`** — language adapter: `execute-code`, `check-deps`
- **`rustbox`** — all commands

### Type-state pre-exec chain

The core safety mechanism. Compile-time enforcement that sandbox setup happens in a fixed order:

```
FreshChild → NamespacesConfigured → MountsHardened → CgroupAttached
    → CredentialsDropped → PrivilegesLocked → ExecReady
```

Only `Sandbox<ExecReady>` can call `exec_payload()`. Skipping or reordering steps is a **compile error** (verified by trybuild tests in `tests/typestate_compile_fail/`).

### Module layout

```
src/
  config/       Config loading, validation, per-language defaults, policy
  exec/         Pre-exec type-state chain, process executor
  core/         Supervisor (clone/fork/waitpid), proxy, types
  kernel/       Thin unsafe wrappers: namespaces, cgroups, capabilities,
                mounts, credentials, signals
  runtime/      Isolate lifecycle, security validation
  verdict/      Evidence-backed verdict classification
  safety/       Cleanup, lock manager, workspace
  observability/ Audit logging, metrics
  utils/        FD closure, env hygiene, fork-safe logging, output collection
```

### Execution flow

```
CLI args → IsolateConfig::with_language_defaults(language, box_id)
  → Isolate::new(config)
  → execute_code_string(language, code)
    → [compile step: permissive mode, drops UID]
    → [execute step: strict mode, full isolation]
      → ProcessExecutor::new() → cgroup create + resource limits
      → launch_with_supervisor() → clone(NEWPID|NEWIPC)
        → proxy: read request, fork payload
          → payload: type-state preexec chain → execvp(command)
        → proxy: collect stdout/stderr, wait, report
      → supervisor: wall-time/cpu watchdog, collect evidence
    → ExecutionResult + LaunchEvidence
  → JudgeResultV1 JSON to stdout
```

## Configuration

`config.json` at project root defines per-language defaults:

```json
{
  "languages": {
    "python": {
      "memory": { "limit_mb": 128 },
      "time": { "cpu_time_seconds": 4, "wall_time_seconds": 7 },
      "processes": { "max_processes": 10 },
      "environment": { "PYTHONDONTWRITEBYTECODE": "1" }
    },
    "java": {
      "memory": { "limit_mb": 512 },
      "time": { "cpu_time_seconds": 8, "wall_time_seconds": 10 },
      "processes": { "max_processes": 256 },
      "environment": { "JAVA_TOOL_OPTIONS": "-Xmx256m -Xms64m -XX:+UseSerialGC" }
    },
    "cpp": {
      "memory": { "limit_mb": 256 },
      "time": { "cpu_time_seconds": 8, "wall_time_seconds": 10 },
      "processes": { "max_processes": 8 }
    }
  }
}
```

Searched at `./config.json` (dev) then `/etc/rustbox/config.json` (production/Docker).

## Build and test

```bash
# Build
cargo build                    # debug
cargo build --release          # release

# Test
cargo test --all               # all unit + integration (non-root)
sudo cargo test --test integration_execution -- --include-ignored  # strict mode tests

# Smoke test
target/debug/judge execute-code --permissive --box-id 1 --language python --code 'print(1)'
sudo target/debug/judge execute-code --strict --box-id 2 --language python --code 'print(1)'

# Check language toolchains
target/debug/judge check-deps --verbose
```

### Test structure

| Suite | What | Count |
|-------|------|-------|
| Unit tests | All modules | 179 |
| Integration (Tier 1) | Permissive mode, all 3 languages, verdict types | 19 |
| Integration (Tier 2) | Strict mode with root, full isolation chain | 7 |
| Compile-fail (trybuild) | Type-state invariants | 7 |
| Other integration | Kernel, mount, namespace | 31 |

## Requirements

- Linux with cgroups (v1 or v2)
- Root for strict mode (namespaces, cgroups, credential drop)
- Rust 1.70+
- Language toolchains: `python3`, `g++`, `javac`/`java` (OpenJDK 17+)

## Docker

```bash
docker build -f docker/base/Dockerfile -t rustbox-base .
docker build -f docker/isolate/Dockerfile -t rustbox .
docker run --privileged rustbox judge execute-code --strict --box-id 1 --language python --code 'print(1)'
```

## License

See LICENSE file.

## Acknowledgments

Inspired by [IOI Isolate](https://github.com/ioi/isolate) by Martin Mares and Bernard Blackham.
