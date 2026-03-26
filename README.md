<div align="center">

# Rustbox

**Kernel-enforced process isolation for competitive programming judges.**

Inspired by [IOI Isolate](https://github.com/ioi/isolate). Built to replace [Judge0](https://github.com/judge0/judge0).

<br />

![Rust](https://img.shields.io/badge/Rust-2021%20edition-f74c00?logo=rust&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-cgroups%20v1%2Fv2-FCC624?logo=linux&logoColor=black)
![License](https://img.shields.io/badge/license-GPL--3.0-blue)
![Tests](https://img.shields.io/badge/tests-113%20unit%20%2B%208%20trybuild-brightgreen)
![Languages](https://img.shields.io/badge/sandbox-8%20languages-green)

[Documentation](https://rustbox-docs.pages.dev) - [API Reference](https://rustbox-docs.pages.dev/api) - [Architecture](https://rustbox-docs.pages.dev/architecture)

</div>

---

Rustbox executes untrusted code inside kernel-enforced sandboxes with deterministic resource limits, seccomp-bpf syscall filtering, and evidence-backed verdicts. One binary, no Docker daemon, no Redis - just Linux namespaces, cgroups, and the type system.

## Quick Start

```bash
# Build
cargo build --release

# Run Python (permissive mode, no root needed)
target/release/judge execute-code --permissive \
  --language python --code 'print("hello")'

# Run C++ (compiled + executed)
target/release/judge execute-code --permissive \
  --language cpp --code '#include<iostream>
int main() { std::cout << 42 << std::endl; }'
```

Supported languages: **Python, C, C++, Java, Go, Rust, JavaScript, TypeScript**

## HTTP API

```bash
# Start the judge service
docker compose -f docker-compose.judge.yml up -d

# Submit code and wait for result
curl -s -X POST "http://localhost:4096/api/submit?wait=true" \
  -H "Content-Type: application/json" \
  -d '{"language": "python", "code": "print(42)"}' | jq
```

```json
{
  "status": "completed",
  "verdict": "AC",
  "stdout": "42\n",
  "cpu_time": 0.012,
  "wall_time": 0.045,
  "memory_peak": 3145728
}
```

<details>
<summary><strong>Async + Webhooks</strong></summary>

```bash
# Async submission (returns immediately)
curl -X POST http://localhost:4096/api/submit \
  -H "Content-Type: application/json" \
  -d '{"language": "python", "code": "print(42)"}'
# -> {"id": "550e8400-..."}

# Poll for result
curl http://localhost:4096/api/result/550e8400-...

# Or use webhooks (HMAC-SHA256 signed, Standard Webhooks spec)
curl -X POST http://localhost:4096/api/submit \
  -H "Content-Type: application/json" \
  -d '{
    "language": "python",
    "code": "print(42)",
    "webhook_url": "https://myapp.com/callback",
    "webhook_secret": "your-secret"
  }'
```

</details>

## Why not Judge0?

| | Judge0 | Rustbox |
|---|--------|---------|
| Deploy | 4 containers (Rails + PG + Redis + worker) | 1 binary + SQLite |
| Isolation | Docker containers | Direct namespaces + cgroups + seccomp |
| Syscall filtering | Docker default (~300 rules) | 42-syscall deny-list |
| Safety model | Runtime checks | Compile-time typestate |
| Verdicts | Exit code heuristics | Kernel evidence bundles |
| API | Polling only | Polling + sync + webhooks |

## Security Model

8 layers of kernel-enforced isolation, applied in a compile-time verified order:

```
FreshChild -> NamespacesReady -> MountsPrivate -> CgroupAttached
  -> RootTransitioned -> CredsDropped -> PrivsLocked -> [seccomp] -> ExecReady
```

| Layer | What it stops |
|-------|---------------|
| PID + IPC namespaces | Can't see or signal host processes |
| Mount namespace + tmpfs chroot | No host filesystem access |
| Network namespace | No network, no DNS |
| Cgroups (memory + CPU + PIDs) | OOM protection, fork bomb prevention |
| rlimits (AS, CPU, FSIZE, NPROC) | Virtual memory + file size caps |
| Credential drop + cap zero | No root, no escalation |
| `PR_SET_NO_NEW_PRIVS` | No suid, no privilege regain |
| seccomp-bpf (42 syscalls) | Blocks io_uring, ptrace, bpf, mount, keyring |

Only `Sandbox<ExecReady>` can call `exec_payload()`. Misordering is a compile error. Verified by 8 [trybuild](https://docs.rs/trybuild) tests.

See [full security docs](https://rustbox-docs.pages.dev/architecture/isolation) for the complete seccomp deny-list and isolation details.

## Docker

```bash
# Recommended: docker compose
docker compose -f docker-compose.judge.yml up -d

# Manual: minimal capabilities (no --privileged)
docker run -p 4096:4096 \
  --cap-add SYS_ADMIN --cap-add SETUID --cap-add SETGID \
  --cap-add NET_ADMIN --cap-add MKNOD --cap-add DAC_OVERRIDE \
  --security-opt seccomp=unconfined \
  --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  rustbox judge-service
```

Set `RUSTBOX_API_KEY=your-secret` for production. See [configuration docs](https://rustbox-docs.pages.dev/getting-started/configuration) for all environment variables.

## Development

```bash
cargo test --all                     # all tests
cargo test --test trybuild           # compile-fail typestate tests
cargo clippy --all                   # lint
target/debug/judge check-deps        # verify language runtimes
```

| Suite | Count |
|-------|-------|
| Unit tests | 113 |
| Integration (permissive) | 19 |
| Integration (strict, root) | 7 |
| Seccomp | 3 |
| Compile-fail (trybuild) | 8 |
| Judge-service e2e | 16 |

## Architecture

```
src/
  kernel/      namespaces, cgroups v1/v2, capabilities, mounts, seccomp
  exec/        type-state pre-exec chain
  sandbox/     supervisor (clone/waitpid), proxy (PID 1)
  runtime/     isolate lifecycle, command validation
  config/      config loading, validation, language presets
  verdict/     evidence-backed verdict classification
  safety/      UID pool, cleanup, workspace management

judge-service/ HTTP API (axum), SQLite/PostgreSQL, webhooks
```

See [architecture docs](https://rustbox-docs.pages.dev/architecture) for the full module map and execution flow.

## License

[GPL-3.0](LICENSE)

## Acknowledgments

- [IOI Isolate](https://github.com/ioi/isolate) - the original sandbox for competitive programming
- [nsjail](https://github.com/google/nsjail) - seccomp and policy design inspiration
- [Standard Webhooks](https://www.standardwebhooks.com/) - webhook signature spec
