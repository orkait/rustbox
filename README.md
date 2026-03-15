<p align="center">
  <h1 align="center">Rustbox</h1>
  <p align="center">
    Kernel-enforced process isolation for competitive programming judges.
    <br />
    Inspired by <a href="https://github.com/ioi/isolate">IOI Isolate</a>.
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-v0.1.0-blue" alt="Status" />
  <img src="https://img.shields.io/badge/languages-Python%20%7C%20C%2B%2B%20%7C%20Java-green" alt="Languages" />
  <img src="https://img.shields.io/badge/platform-Linux-orange" alt="Platform" />
  <img src="https://img.shields.io/badge/tests-237%20passing-brightgreen" alt="Tests" />
  <img src="https://img.shields.io/badge/clippy-0%20warnings-brightgreen" alt="Clippy" />
</p>

---

Rustbox executes untrusted code inside kernel-enforced sandboxes with deterministic resource limits and evidence-backed verdicts. It uses Linux namespaces, cgroups (v1/v2), capability dropping, and rlimits to ensure submitted code cannot escape, interfere with other submissions, or harm the host.

```
                    +-----------+
  source code ----->|  rustbox  |-----> verdict (OK / TLE / MLE / RE / Signaled)
  + language        |  (judge)  |-----> stdout, stderr
  + limits          +-----------+-----> evidence bundle (controls, memory peak, cpu time)
                     namespaces
                     cgroups
                     capabilities
                     rlimits
```

## Quick Start

```bash
# Build
cargo build --release

# Permissive mode (no root needed, for development)
target/release/judge execute-code --permissive --box-id 1 \
  --language python --code 'print("hello")'

# Strict mode (root required, full isolation)
sudo target/release/judge execute-code --strict --box-id 1 \
  --language python --code 'print("hello")'
```

Output is `JudgeResultV1` JSON on stdout:

```json
{
  "verdict": "OK",
  "exit_code": 0,
  "cpu_time_ms": 11,
  "wall_time_ms": 15,
  "memory_peak_kb": 8192,
  "stdout": "hello\n",
  "stderr": ""
}
```

### All Three Languages

```bash
# Python
sudo target/release/judge execute-code --strict --box-id 1 \
  --language python --code 'print(sum(range(100)))'

# C++
sudo target/release/judge execute-code --strict --box-id 2 \
  --language cpp --code '
#include <iostream>
int main() { std::cout << 42 << std::endl; }
'

# Java
sudo target/release/judge execute-code --strict --box-id 3 \
  --language java --code '
public class Main {
    public static void main(String[] args) {
        System.out.println("hello world");
    }
}
'
```

## Security Model

Rustbox applies **7 independent layers** of kernel-enforced isolation. Every layer must pass before untrusted code executes — failure in any layer aborts the sandbox in strict mode.

| Layer | Mechanism | Enforces |
|-------|-----------|----------|
| Process isolation | `CLONE_NEWPID`, `CLONE_NEWIPC` | Can't see/signal host processes |
| Filesystem | tmpfs chroot + read-only bind mounts | Writable workdir only, no host access |
| Network | `CLONE_NEWNET` | No network access (strict mode) |
| Memory | cgroup `memory.max` + `RLIMIT_AS` | Physical + virtual memory caps |
| CPU | `RLIMIT_CPU` + cgroup watchdog | Hard CPU time limit |
| Processes | cgroup `pids.max` + `RLIMIT_NPROC` | Fork bomb prevention |
| Privileges | `setresuid` + all caps zeroed + `PR_SET_NO_NEW_PRIVS` | No root, no escalation, no suid |

### Type-State Pre-Exec Chain

The core safety mechanism. Sandbox setup is enforced **at compile time** through Rust's type system — skipping or reordering steps is a compile error:

```
FreshChild
  -> NamespacesConfigured
    -> MountsHardened
      -> CgroupAttached
        -> CredentialsDropped
          -> PrivilegesLocked
            -> ExecReady    // only this state can call exec_payload()
```

This is verified by 7 [trybuild](https://docs.rs/trybuild) compile-fail tests in `tests/typestate_compile_fail/`.

### Environment Sanitization

A blocklist strips dangerous environment variables **after** config merge, preventing injection through `config.json`:

`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `BASH_ENV`, `PYTHONSTARTUP`, `PYTHONPATH`, `NODE_OPTIONS`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`, `PERL5OPT`, `RUBYOPT`, and more.

## Architecture

### Three Binaries, One CLI

All binaries call `rustbox::cli::run()` with a different mode:

| Binary | Mode | Commands |
|--------|------|----------|
| `isolate` | Sandbox lifecycle | `init`, `run`, `status`, `cleanup` |
| `judge` | Language adapter | `execute-code`, `check-deps` |
| `rustbox` | All commands | Everything above |

### Module Layout

```
src/
  kernel/         Thin unsafe wrappers around Linux primitives
                    namespaces, cgroups v1/v2, capabilities, mounts,
                    credentials, signals
  exec/           Type-state pre-exec chain, process executor
  core/           Supervisor (clone/waitpid), proxy (PID 1), types
  config/         Config loading, validation, per-language defaults, policy
  runtime/        Isolate lifecycle, security validation, language adapters
  verdict/        Evidence-backed verdict classification
  safety/         Idempotent cleanup, lock manager, workspace
  observability/  Audit logging, Prometheus metrics
  utils/          FD closure, env hygiene, fork-safe logging
  judge/          Language-specific adapters (Python, C++, Java)
  testing/        Mount invariance and race condition proof frameworks
```

### Execution Flow

```
CLI args
  -> IsolateConfig::with_language_defaults(language, box_id)
  -> Isolate::new(config)
  -> execute_code_string(language, code)
       |
       |-- [compile step: permissive mode, drops UID]     # C++/Java only
       |
       '-- [execute step: strict mode, full isolation]
             -> ProcessExecutor::new()                    # cgroup create + limits
             -> launch_with_supervisor()                  # clone(NEWPID|NEWIPC|NEWNET)
                  -> proxy: fork payload child
                       -> type-state pre-exec chain       # 7 steps, compile-time enforced
                       -> execvp(command)
                  -> proxy: collect stdout/stderr, wait, report status
             -> supervisor: wall-time/cpu watchdog, collect evidence
             -> ExecutionResult + LaunchEvidence
  -> JudgeResultV1 JSON to stdout
```

## Configuration

`config.json` defines per-language resource limits and environment:

```json
{
  "languages": {
    "python": {
      "memory": { "limit_mb": 128 },
      "time": { "cpu_time_seconds": 4, "wall_time_seconds": 7 },
      "processes": { "max_processes": 10 },
      "environment": { "PYTHONDONTWRITEBYTECODE": "1" }
    },
    "cpp": {
      "memory": { "limit_mb": 256 },
      "time": { "cpu_time_seconds": 8, "wall_time_seconds": 10 },
      "processes": { "max_processes": 8 }
    },
    "java": {
      "memory": { "limit_mb": 512 },
      "time": { "cpu_time_seconds": 8, "wall_time_seconds": 10 },
      "processes": { "max_processes": 256 },
      "environment": { "JAVA_TOOL_OPTIONS": "-Xmx256m -Xms64m -XX:+UseSerialGC" }
    }
  }
}
```

Config is loaded from `./config.json` (dev) or `/etc/rustbox/config.json` (production). When running as root, world-writable config files are rejected.

## Build and Test

```bash
# Build
cargo build                    # debug
cargo build --release          # release

# Test (non-root, 237 tests)
cargo test --all

# Strict mode tests (root required)
sudo cargo test --test integration_execution -- --include-ignored

# Clippy (zero warnings)
cargo clippy --all-targets

# Smoke test
target/debug/judge execute-code --permissive --box-id 1 --language python --code 'print(1)'

# Check language toolchains
target/debug/judge check-deps --verbose
```

### Test Coverage

| Suite | Description | Count |
|-------|-------------|-------|
| Unit | All modules | 186 |
| Integration (permissive) | All languages, verdict types | 19 |
| Integration (strict) | Full isolation chain, requires root | 7 (ignored without root) |
| Compile-fail | Type-state invariant verification | 7 |
| Kernel/mount/namespace | Kernel primitive tests | 31 |

## Docker

### Standalone

```bash
docker build -f docker/base/Dockerfile -t rustbox-base:local .
docker build -f docker/isolate/Dockerfile -t rustbox .

docker run --cap-add SYS_ADMIN --cap-add NET_ADMIN --security-opt no-new-privileges \
  rustbox judge execute-code --strict --box-id 1 --language python --code 'print(1)'
```

### Full Stack (judge service + web UI)

```bash
# Set required credentials
export POSTGRES_PASSWORD=<strong-password>
export REDIS_PASSWORD=<strong-password>

# Start all services
docker compose up -d

# Submit via API
curl -X POST http://localhost:8080/api/submit \
  -H "Content-Type: application/json" \
  -H "x-api-key: $RUSTBOX_API_KEY" \
  -d '{"language": "python", "code": "print(42)"}'
```

## Requirements

| Requirement | Details |
|-------------|---------|
| OS | Linux with cgroups v1 or v2 |
| Privileges | Root for strict mode (namespaces, cgroups, credential drop) |
| Rust | 1.70+ |
| Python | `python3` |
| C++ | `g++` (GCC) |
| Java | `javac` + `java` (OpenJDK 17+) |

## Acknowledgments

Inspired by [IOI Isolate](https://github.com/ioi/isolate) by Martin Mares and Bernard Blackham.
