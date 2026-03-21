<div align="center">

# Rustbox

**Kernel-enforced process isolation for competitive programming judges.**

Inspired by [IOI Isolate](https://github.com/ioi/isolate).

<br />

![Rust](https://img.shields.io/badge/Rust-2021%20edition-f74c00?logo=rust&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-cgroups%20v1%2Fv2-FCC624?logo=linux&logoColor=black)
![Status](https://img.shields.io/badge/status-v0.1.0-blue)
![Tests](https://img.shields.io/badge/tests-144%20unit%20%2B%207%20trybuild-brightgreen)
![Clippy](https://img.shields.io/badge/clippy-0%20warnings-brightgreen)
![Languages](https://img.shields.io/badge/sandbox-Python%20%7C%20C%2B%2B%20%7C%20Java%20%7C%20JS%20%7C%20TS-green)

</div>

---

Rustbox executes untrusted code inside kernel-enforced sandboxes with deterministic resource limits and evidence-backed verdicts. It uses Linux namespaces, cgroups (v1/v2), capability dropping, and rlimits to make sure submitted code can't escape, interfere with other submissions, or touch the host.

```
                    +-----------+
  source code ----->|  rustbox  |-----> status (OK / TLE / MLE / RE / Signaled)
  + language        |  (judge)  |-----> stdout, stderr
  + limits          +-----------+-----> evidence bundle (controls, memory peak, cpu time)
                     namespaces
                     cgroups
                     capabilities
                     rlimits
```

## :rocket: Quick Start

```bash
# Build
cargo build --release

# Permissive mode (no root needed, great for development)
target/release/judge execute-code --permissive --box-id 1 \
  --language python --code 'print("hello")'

# Strict mode (root required, full kernel isolation)
sudo target/release/judge execute-code --strict --box-id 1 \
  --language python --code 'print("hello")'
```

Output is `JudgeResultV1` JSON on stdout. Here's what the key fields look like (full output includes evidence bundle, capability report, and provenance):

```json
{
  "schema_version": "1.0",
  "status": "OK",
  "exit_code": 0,
  "stdout": "hello\n",
  "stderr": "",
  "cpu_time": 0.011,
  "wall_time": 0.015,
  "memory_peak": 8388608,
  "output_integrity": "complete",
  "execution_envelope_id": "sha256:..."
}
```

> `cpu_time` and `wall_time` are in **seconds** (float). `memory_peak` is in **bytes**.

<details>
<summary><strong>:test_tube: All Five Languages</strong></summary>

```bash
# Python
sudo target/release/judge execute-code --strict --box-id 1 \
  --language python --code 'print(sum(range(100)))'

# C++ (compiled then executed)
sudo target/release/judge execute-code --strict --box-id 2 \
  --language cpp --code '
#include <iostream>
int main() { std::cout << 42 << std::endl; }
'

# Java (compiled then executed)
sudo target/release/judge execute-code --strict --box-id 3 \
  --language java --code '
public class Main {
    public static void main(String[] args) {
        System.out.println("hello world");
    }
}
'

# JavaScript (QuickJS - interpreted)
sudo target/release/judge execute-code --strict --box-id 4 \
  --language javascript --code 'console.log(2 + 2)'

# TypeScript (Bun - interpreted)
sudo target/release/judge execute-code --strict --box-id 5 \
  --language typescript --code 'console.log("typed!")'
```

Language aliases: `py`, `c++`/`cxx`/`cc`/`c`, `js`, `ts`

</details>

## :shield: Security Model

Rustbox applies **7 independent layers** of kernel-enforced isolation. Every layer must pass before untrusted code runs - failure in any layer aborts the sandbox in strict mode.

| Layer | Mechanism | What it stops |
|-------|-----------|---------------|
| Process isolation | `CLONE_NEWPID`, `CLONE_NEWIPC` | Can't see or signal host processes |
| Filesystem | tmpfs chroot + read-only bind mounts | Writable workdir only, no host access |
| Network | `CLONE_NEWNET` | No network access (strict mode) |
| Memory | cgroup `memory.max` + `RLIMIT_AS` | Physical + virtual memory caps |
| CPU | `RLIMIT_CPU` + cgroup watchdog | Hard CPU time limit |
| Processes | cgroup `pids.max` + `RLIMIT_NPROC` | Fork bomb prevention |
| Privileges | `setresuid` + all caps zeroed + `PR_SET_NO_NEW_PRIVS` | No root, no escalation, no suid |

### :lock: Type-State Pre-Exec Chain

The core safety mechanism. Sandbox setup is enforced **at compile time** through Rust's type system - skipping or reordering steps is a compile error:

```
FreshChild
  -> NamespacesReady
    -> MountsPrivate
      -> CgroupAttached
        -> CredsDropped
          -> PrivsLocked
            -> ExecReady    // only this state can call exec_payload()
```

Verified by 7 [trybuild](https://docs.rs/trybuild) compile-fail tests in `tests/typestate_compile_fail/`.

### :no_entry: Environment Sanitization

A blocklist strips dangerous environment variables **after** config merge (preventing re-injection through `config.json`):

<details>
<summary>Blocked variables</summary>

**Loader hijack** (VULN-002): `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `LD_DEBUG`, `LD_PROFILE`, `LD_BIND_NOW`, `LD_BIND_NOT`, `LD_DYNAMIC_WEAK`, `LD_USE_LOAD_BIAS`

**Interpreter injection** (VULN-014): `BASH_ENV`, `ENV`, `CDPATH`, `PYTHONSTARTUP`, `PERL5OPT`, `RUBYOPT`, `NODE_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`

**Allowed but validated**: `JAVA_TOOL_OPTIONS` (checked for `-javaagent:`, `-agentpath:`, `-agentlib:` flags). `PYTHONPATH` is allowed since filesystem isolation is the control.

</details>

## :building_construction: Architecture

### :package: Three Binaries, One CLI

All binaries call `rustbox::cli::run()` with a different mode:

| Binary | Mode | Commands |
|--------|------|----------|
| `isolate` | Sandbox lifecycle | `init`, `run`, `status`, `cleanup` |
| `judge` | Language adapter | `execute-code`, `check-deps` |
| `rustbox` | All commands | Everything above |

### :file_folder: Module Layout

```
src/
  kernel/         Thin unsafe wrappers around Linux primitives
                    namespaces, cgroups v1/v2, capabilities, mounts,
                    credentials, signals
  exec/           Type-state pre-exec chain (preexec.rs), process executor
  core/           Supervisor (clone/waitpid), proxy (PID 1 in sandbox), types
  config/         Config loading, validation, per-language presets
  runtime/        Isolate lifecycle, security validation
  verdict/        Evidence-backed verdict classification (pure functions)
  safety/         Idempotent cleanup, file-lock manager
  observability/  Security audit logging (injection + traversal detection)
  utils/          FD closure, env hygiene, fork-safe logging, JSON schema
  judge/          Language adapters (Python, C++, Java, JS, TS)
```

### :arrows_counterclockwise: Execution Flow

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

## :gear: Configuration

`config.json` defines per-language resource limits, environment, filesystem bindings, and compilation settings:

<details>
<summary>Example config.json (simplified)</summary>

```json
{
  "isolate": {
    "box_dir": "/tmp/rustbox",
    "run_dir": "/var/run/rustbox"
  },
  "security": {
    "drop_capabilities": true,
    "use_namespaces": true,
    "use_cgroups": true,
    "no_new_privileges": true
  },
  "languages": {
    "python": {
      "memory": { "limit_mb": 128 },
      "time": { "cpu_time_seconds": 4, "wall_time_seconds": 7 },
      "processes": { "max_processes": 10 },
      "filesystem": {
        "max_file_size_kb": 512,
        "required_binaries": ["/usr/bin/python3"]
      },
      "environment": {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1"
      },
      "compilation": { "enabled": false }
    },
    "cpp": {
      "memory": { "limit_mb": 256 },
      "time": { "cpu_time_seconds": 8, "wall_time_seconds": 10 },
      "processes": { "max_processes": 8 },
      "filesystem": {
        "required_binaries": ["/usr/bin/gcc", "/usr/bin/g++"]
      },
      "compilation": {
        "enabled": true,
        "compiler": "g++ -std=c++17 -O2"
      }
    }
  }
}
```

Each language also supports `java`, `javascript`, and `typescript` sections. See `config.json` for the full schema.

</details>

Config is loaded from `./config.json` (dev) or `/etc/rustbox/config.json` (production). When running as root, world-writable config files are rejected.

## :hammer_and_wrench: Build and Test

```bash
# Build
cargo build                    # debug
cargo build --release          # release

# Run all tests (non-root)
cargo test --all

# Strict mode integration tests (root required)
sudo cargo test --test integration_execution -- --include-ignored

# Clippy (zero warnings)
cargo clippy --all-targets -- -D warnings

# Smoke test
target/debug/judge execute-code --permissive --box-id 1 --language python --code 'print(1)'

# Check language toolchains
target/debug/judge check-deps --verbose
```

### :bar_chart: Test Suites

| Suite | What it tests | Count |
|-------|---------------|-------|
| Unit | Types, config, verdict classifier, cleanup, presets, language adapters | 144 |
| Integration (permissive) | All 5 languages, verdict types, stdin, timeouts | 19 |
| Integration (strict) | Full isolation chain under root | 7 (ignored without root) |
| Compile-fail (trybuild) | Type-state invariants - verifies misordering is a compile error | 7 |

## :whale: Docker

### Standalone

```bash
docker build -f docker/base/Dockerfile -t rustbox-base:local .
docker build -f docker/isolate/Dockerfile -t rustbox .

docker run --cap-add SYS_ADMIN --cap-add NET_ADMIN --security-opt no-new-privileges \
  rustbox judge execute-code --strict --box-id 1 --language python --code 'print(1)'
```

<details>
<summary><strong>Full Stack (judge service + web UI)</strong></summary>

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

</details>

## :clipboard: Requirements

| Requirement | Details |
|-------------|---------|
| OS | Linux with cgroups v1 or v2 |
| Privileges | Root for strict mode (namespaces, cgroups, credential drop) |
| Rust | Edition 2021 |
| Python | `python3` in `$PATH` |
| C++ | `g++` (GCC) |
| Java | `javac` + `java` (OpenJDK 17+) |
| JavaScript | [`qjs`](https://bellard.org/quickjs/) (QuickJS) |
| TypeScript | [`bun`](https://bun.sh/) (Bun runtime) |

## :pray: Acknowledgments

Inspired by [IOI Isolate](https://github.com/ioi/isolate) by Martin Mares and Bernard Blackham.
