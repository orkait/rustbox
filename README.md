<div align="center">

# Rustbox

**Kernel-enforced process isolation for competitive programming judges.**

Inspired by [IOI Isolate](https://github.com/ioi/isolate). Built to replace [Judge0](https://github.com/judge0/judge0).

<br />

![Rust](https://img.shields.io/badge/Rust-2021%20edition-f74c00?logo=rust&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-cgroups%20v1%2Fv2-FCC624?logo=linux&logoColor=black)
![Status](https://img.shields.io/badge/status-v0.1.0-blue)
![Tests](https://img.shields.io/badge/tests-108%20unit%20%2B%203%20seccomp%20%2B%207%20trybuild-brightgreen)
![Languages](https://img.shields.io/badge/sandbox-Python%20%7C%20C%2B%2B%20%7C%20Java%20%7C%20JS%20%7C%20TS-green)
![LOC](https://img.shields.io/badge/LOC-~14k%20Rust-orange)
![Deploy](https://img.shields.io/badge/deploy-1%20binary%20%2B%20SQLite-purple)

</div>

---

Rustbox executes untrusted code inside kernel-enforced sandboxes with deterministic resource limits, seccomp-bpf syscall filtering, and evidence-backed verdicts. One binary, no Docker daemon, no Redis - just Linux namespaces, cgroups, and the type system.

```
                    +-----------+
  source code ----->|  rustbox  |-----> verdict (AC / TLE / MLE / RE / SIG)
  + language        |  (judge)  |-----> stdout, stderr
  + limits          +-----------+-----> evidence bundle (controls, memory peak, cpu time)
                     namespaces
                     cgroups + seccomp
                     capabilities
                     rlimits
```

## Why not Judge0?

| | Judge0 | Rustbox |
|---|--------|---------|
| Deployment | 4 containers (Rails + PG + Redis + worker) | 1 binary + SQLite, `docker compose up` |
| Languages | 60+ | 5 (Python, C++, Java, JS, TS) |
| Isolation | Docker containers (namespaces + cgroups via Docker) | Direct namespaces + cgroups + seccomp + capabilities |
| Syscall filtering | Docker default seccomp (~300 rules) | Purpose-built 18-syscall deny-list (io_uring gets ENOSYS, not KILL) |
| Safety model | Runtime checks | Compile-time typestate (misordering = compile error) |
| Verdicts | Exit code + wall time heuristics | Kernel evidence bundles (cgroup OOM events, /proc, waitpid) |
| API modes | Polling only | Async polling + sync `?wait=true` + webhooks (HMAC-SHA256) |
| Security audit | Community-tested, [CVE-2024-28185](https://nvd.nist.gov/vuln/detail/CVE-2024-28185) found and patched | Internal audit: 4 critical + 7 high findings, all resolved |
| Production use | Hundreds of deployments | Pre-production (v0.1.0) |

## :rocket: Quick Start

### CLI (single execution)

```bash
cargo build --release

# Permissive mode (no root, for development)
target/release/judge execute-code --permissive \
  --language python --code 'print("hello")'

# Strict mode (root required, full kernel isolation)
sudo target/release/judge execute-code --strict \
  --language python --code 'print("hello")'
```

### HTTP API (judge service)

```bash
# Start the service
docker compose -f docker-compose.judge.yml up judge -d

# Submit and get result (sync mode)
curl -X POST "http://localhost:4096/api/submit?wait=true" \
  -H "Content-Type: application/json" \
  -d '{"language": "python", "code": "print(42)"}'
```

For production, set `RUSTBOX_API_KEY` to require authentication:

```bash
RUSTBOX_API_KEY=your-secret docker compose -f docker-compose.judge.yml up judge -d

curl -X POST "http://localhost:4096/api/submit?wait=true" \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-secret" \
  -d '{"language": "python", "code": "print(42)"}'
```

<details>
<summary><strong>:bell: Webhook notifications</strong></summary>

Fire-and-forget with signed callbacks (Standard Webhooks spec):

```bash
curl -X POST http://localhost:4096/api/submit \
  -H "Content-Type: application/json" \
  -d '{
    "language": "python",
    "code": "print(42)",
    "webhook_url": "https://myapp.com/api/judge-callback",
    "webhook_secret": "your-secret-key"
  }'
```

Rustbox POSTs the result to your URL with HMAC-SHA256 signature headers:

```
webhook-id: <submission-uuid>
webhook-timestamp: 1674087231
webhook-signature: v1,<base64-hmac>
```

Signed content: `{msg_id}.{timestamp}.{body}` - verify with your secret to prevent forgery.

</details>

<details>
<summary><strong>:test_tube: All five languages</strong></summary>

```bash
# Python
target/release/judge execute-code --permissive --language python --code 'print(sum(range(100)))'

# C++ (compiled then executed)
target/release/judge execute-code --permissive --language cpp --code '
#include <iostream>
int main() { std::cout << 42 << std::endl; }
'

# Java (compiled then executed)
target/release/judge execute-code --permissive --language java --code '
public class Main {
    public static void main(String[] args) {
        System.out.println("hello world");
    }
}
'

# JavaScript (QuickJS)
target/release/judge execute-code --permissive --language javascript --code 'console.log(2 + 2)'

# TypeScript (Bun)
target/release/judge execute-code --permissive --language typescript --code 'console.log("typed!")'
```

Language aliases: `py`, `c++`/`cxx`, `js`, `ts`

</details>

## :shield: Security Model

Rustbox applies **8 independent layers** of kernel-enforced isolation. Every layer must pass before untrusted code runs - failure in any layer aborts the sandbox in strict mode.

| Layer | Mechanism | What it stops |
|-------|-----------|---------------|
| Process isolation | `CLONE_NEWPID`, `CLONE_NEWIPC` | Can't see or signal host processes |
| Filesystem | tmpfs chroot + read-only bind mounts | Writable workdir only, no host access |
| Network | `CLONE_NEWNET` | No network access |
| Memory | cgroup `memory.max` + `RLIMIT_AS` | Physical + virtual memory caps |
| CPU | `RLIMIT_CPU` + cgroup watchdog | Hard CPU time limit |
| Processes | cgroup `pids.max` + `RLIMIT_NPROC` | Fork bomb prevention |
| Privileges | `setresuid` + all caps zeroed + `PR_SET_NO_NEW_PRIVS` | No root, no escalation, no suid |
| Syscall filtering | seccomp-bpf deny-list (18 syscalls) | Blocks io_uring, ptrace, bpf, module loading |

### :lock: Type-state pre-exec chain

Sandbox setup is enforced **at compile time** through Rust's type system - skipping or reordering steps is a compile error:

```
FreshChild -> NamespacesReady -> MountsPrivate -> CgroupAttached
  -> CredsDropped -> PrivsLocked -> [seccomp filter] -> ExecReady
```

Only `Sandbox<ExecReady>` can call `exec_payload()`. Verified by 7 [trybuild](https://docs.rs/trybuild) compile-fail tests.

### :no_entry: Seccomp deny-list

Following the [nsjail](https://github.com/google/nsjail) pattern (DEFAULT ALLOW + block dangerous syscalls):

| Family | Syscalls | Action |
|--------|----------|--------|
| io_uring | `io_uring_setup`, `io_uring_enter`, `io_uring_register` | ERRNO(ENOSYS) |
| Tracing | `ptrace`, `process_vm_readv`, `process_vm_writev` | KILL_PROCESS |
| Kernel subsystems | `bpf`, `userfaultfd`, `perf_event_open` | KILL_PROCESS |
| Module loading | `kexec_load`, `init_module`, `finit_module`, `delete_module` | KILL_PROCESS |
| Mount/swap | `mount`, `umount2`, `pivot_root`, `swapon`, `swapoff` | KILL_PROCESS |

Override with `--seccomp-policy policy.json` or disable with `--no-seccomp`.

## :building_construction: Architecture

### Execution flow

```
CLI / HTTP API
  -> Isolate::new()                    allocate UID from pool, create cgroup
  -> execute_code_string(lang, code)   write source, dispatch by language
       -> supervisor::clone()          proxy in new namespaces (PID, mount, net, IPC)
            -> proxy::fork()           payload child through typestate chain
                 7 setup stages        namespaces, mounts, cgroup, rlimits, creds, caps, seccomp
                 -> execvp()           replace process image
            -> proxy: collect stdout/stderr, wait, report
       -> supervisor: wall/CPU watchdog via cgroup, collect evidence
  -> classify verdict from kernel evidence
  -> cleanup: verify baseline, remove cgroup, wipe workdir, release UID
```

### Module layout

```
src/
  kernel/         Thin unsafe wrappers: namespaces, cgroups v1/v2, capabilities,
                  mounts, credentials, signals, seccomp
  exec/           Type-state pre-exec chain (preexec.rs)
  core/           Supervisor (clone/waitpid), proxy (PID 1 in sandbox)
  runtime/        Isolate lifecycle (new/execute/cleanup), command security
  config/         Config loading, validation, per-language presets
  verdict/        Evidence-backed verdict classification
  safety/         UID pool (lock-free atomic bitset), cleanup, workspace management
  observability/  Security audit logging (injection + traversal detection)
  utils/          FD closure, env hygiene, fork-safe logging, JSON schema

judge-service/    HTTP API: submit, poll, webhooks, SQLite/PostgreSQL
```

## :gear: Configuration

### Judge service (environment variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `RUSTBOX_PORT` | 4096 | HTTP listen port |
| `RUSTBOX_WORKERS` | 2 | Concurrent sandbox workers |
| `RUSTBOX_QUEUE_SIZE` | 100 | Max pending submissions |
| `RUSTBOX_DATABASE_URL` | `sqlite:rustbox.db` | SQLite or PostgreSQL URL |
| `RUSTBOX_API_KEY` | (none) | API key for authentication |
| `RUSTBOX_MAX_CODE_BYTES` | 65536 | Max source code size |
| `RUSTBOX_MAX_STDIN_BYTES` | 262144 | Max stdin size |
| `RUSTBOX_SYNC_WAIT_TIMEOUT_SECS` | 30 | Timeout for `?wait=true` |
| `RUSTBOX_WEBHOOK_TIMEOUT_SECS` | 10 | Webhook delivery timeout |
| `RUSTBOX_ALLOW_LOCALHOST_WEBHOOKS` | false | Allow HTTP + localhost in dev |
| `RUSTBOX_STALE_TIMEOUT_SECS` | 300 | Reaper timeout for stuck jobs |

### Per-language defaults (`config.json`)

<details>
<summary>Example</summary>

```json
{
  "languages": {
    "python": {
      "memory": { "limit_mb": 128 },
      "time": { "cpu_time_seconds": 4, "wall_time_seconds": 7 },
      "processes": { "max_processes": 10 },
      "environment": {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1"
      }
    },
    "cpp": {
      "memory": { "limit_mb": 256 },
      "time": { "cpu_time_seconds": 8, "wall_time_seconds": 10 },
      "compilation": { "compiler": "g++ -std=c++17 -O2" }
    }
  }
}
```

</details>

## :hammer_and_wrench: Build and Test

```bash
cargo build                          # debug build
cargo build --release                # release build
cargo test --all                     # all tests (non-root)
cargo test --test integration_execution -- --test-threads=1  # integration tests
sudo cargo test --test integration_execution -- --include-ignored  # strict mode (root)
target/debug/judge check-deps --verbose  # verify language toolchains
```

| Suite | Count | What it tests |
|-------|-------|---------------|
| Unit | 108 | Config, verdict classifier, presets, seccomp, kernel primitives |
| Integration (permissive) | 19 | All 5 languages, verdicts, stdin, timeouts |
| Integration (strict) | 7 | Full isolation chain under root (ignored without root) |
| Seccomp | 3 | io_uring blocked, no-seccomp flag, seccomp+python works |
| Compile-fail (trybuild) | 7 | Type-state invariants |
| Judge-service | 6 | Submit, poll, idempotency, languages, health |

## :whale: Docker

### Docker Compose (recommended)

```bash
# SQLite mode (single node)
docker compose -f docker-compose.judge.yml up judge

# PostgreSQL mode (multi-node ready)
docker compose -f docker-compose.judge.yml --profile postgres up
```

### Manual docker run

```bash
docker build -f docker/base/Dockerfile -t rustbox .

# Judge service with minimal capabilities (no --privileged)
docker run -p 4096:4096 \
  --cap-add SYS_ADMIN --cap-add SETUID --cap-add SETGID \
  --cap-add NET_ADMIN --cap-add MKNOD --cap-add DAC_OVERRIDE \
  --security-opt seccomp=unconfined \
  --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --stop-timeout 45 \
  rustbox judge-service

# Single execution (strict mode)
docker run \
  --cap-add SYS_ADMIN --cap-add SETUID --cap-add SETGID \
  --cap-add NET_ADMIN --cap-add MKNOD --cap-add DAC_OVERRIDE \
  --security-opt seccomp=unconfined \
  --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  rustbox judge execute-code --strict --language python --code 'print(1)'
```

<details>
<summary><strong>Why not --privileged?</strong></summary>

`--privileged` gives the container full host capabilities, access to all devices, and disables Docker's seccomp profile. If an attacker escapes rustbox's sandbox inside a `--privileged` container, they get full host access.

The minimal capability set above gives rustbox exactly what it needs for strict mode:

| Capability | Used for |
|------------|----------|
| `SYS_ADMIN` | clone with new namespaces, mount, chroot |
| `SETUID` / `SETGID` | Credential drop to sandbox UID |
| `NET_ADMIN` | Network namespace loopback setup |
| `MKNOD` | Device nodes (/dev/null, /dev/urandom) in chroot |
| `DAC_OVERRIDE` | Cgroup filesystem writes |

`seccomp=unconfined` is needed because Docker's default seccomp profile blocks `clone` with namespace flags, `mount`, and `pivot_root` - syscalls rustbox needs during sandbox setup. Rustbox installs its own seccomp filter before executing untrusted code.

</details>

### Health checks

```bash
# Liveness (always 200 if process is running)
curl http://localhost:4096/api/health

# Readiness (503 if cgroups/namespaces unavailable)
curl http://localhost:4096/api/health/ready
```

The Docker image uses `jlink` to build a minimal 62MB Java runtime instead of a full 285MB JDK.

## :clipboard: Requirements

| Requirement | Details |
|-------------|---------|
| OS | Linux with cgroups v1 or v2 |
| Privileges | Root for strict mode |
| Rust | Edition 2021 |
| Python | `python3` in `$PATH` |
| C++ | `g++` (GCC) |
| Java | `javac` + `java` (OpenJDK 21) |
| JavaScript | [`qjs`](https://bellard.org/quickjs/) (QuickJS) |
| TypeScript | [`bun`](https://bun.sh/) |

## :pray: Acknowledgments

- [IOI Isolate](https://github.com/ioi/isolate) by Martin Mares and Bernard Blackham - the original sandbox for competitive programming
- [nsjail](https://github.com/google/nsjail) by Google - seccomp and Kafel policy design inspiration
- [Standard Webhooks](https://www.standardwebhooks.com/) - webhook signature specification
