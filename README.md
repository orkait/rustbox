<div align="center">

# 🦀 Rustbox

**Kernel-enforced code execution sandbox for untrusted workloads**

Two profiles, one binary. Judge mode for competitive programming, executor mode for LLM agents.

<br />

![Rust](https://img.shields.io/badge/Rust-2021-f74c00?logo=rust&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-cgroups%20v2-FCC624?logo=linux&logoColor=black)
![License](https://img.shields.io/badge/license-Proprietary-blue)
![Tests](https://img.shields.io/badge/tests-106%20unit%20%2B%2070%20adversarial-brightgreen)
![Languages](https://img.shields.io/badge/sandbox-8%20languages-green)
![Throughput](https://img.shields.io/badge/throughput-260%2B%20req%2Fs-orange)

</div>

---

Rustbox executes untrusted code inside kernel-enforced sandboxes with deterministic resource limits, seccomp-bpf syscall filtering, and evidence-backed verdicts. Single binary, no Docker daemon, no Redis - Linux namespaces, cgroups, and the Rust type system.

## ⚡ Quick Start

```bash
# Build
cargo build --release -p rustbox -p judge-service

# Run Python (needs root for sandbox isolation)
sudo target/release/rustbox execute-code \
  --language python --code 'print("hello")'

# Run C++ (compiled + executed)
sudo target/release/rustbox execute-code \
  --language cpp --code '#include<iostream>
int main() { std::cout << 42 << std::endl; }'
```

Supported languages: **Python, C, C++, Java, Go, Rust, JavaScript, TypeScript**

## 🌐 HTTP API

```bash
# Start judge service
docker compose up judge

# Submit and wait for result
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
  "wall_time": 0.025,
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

# Or use webhooks (HMAC-SHA256, Standard Webhooks spec)
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

## 🎯 Two Profiles

| | Judge | Executor |
|---|---|---|
| Use case | Competitive programming | LLM agents, notebooks |
| Memory | 256 MB | 2 GB |
| Wall time | 7 seconds | 60 seconds |
| Network | Blocked | Filtered (metadata/private blocked) |
| Processes | 10 | 64 |
| Config | `config.json` | `config-executor.json` |
| Dockerfile | `Dockerfile` | `Dockerfile.executor` |

```bash
docker compose up judge       # tight limits
docker compose up executor    # relaxed limits
docker compose up judge-pg    # judge + Postgres (multi-node)
```

## 🔒 Security Model

11 stages of kernel-enforced isolation, applied in a compile-time verified order:

```
FreshChild -> NamespacesReady -> MountsPrivate -> CgroupAttached
  -> RootTransitioned -> HygieneApplied -> CredsDropped
  -> PrivsLocked -> [verify signals + session + caps] -> [seccomp] -> ExecReady
```

| Layer | What it stops |
|---|---|
| PID + IPC + UTS namespaces | Can't see or signal host processes |
| Mount namespace + tmpfs chroot | No host filesystem access |
| Network namespace | No network, no DNS (judge mode) |
| Cgroups v2 (memory + CPU + PIDs) | OOM kill, fork bomb prevention, CPU throttle |
| rlimits (AS, FSIZE, NOFILE, STACK) | Virtual memory + file size + fd caps |
| Credential drop + all 5 cap sets zeroed | No root, no escalation |
| `PR_SET_NO_NEW_PRIVS` | No suid, no privilege regain |
| seccomp-bpf (52 rules) | Blocks clone, io_uring, ptrace, bpf, mount, kexec |

Only `Sandbox<ExecReady>` can call `exec_payload()`. Misordering is a compile error.

<details>
<summary><strong>Adversarial test results (22 exploits, 0 escapes)</strong></summary>

```
fork_bomb          RE    pids.max blocked fork()
thread_bomb        RE    pids.max blocked threads
memory_bomb        TLE   memory.max + wall timer
cpu_spin           TLE   wall timer killed
sigxcpu_catch      TLE   SIGXCPU catch bypassed by wall timer
read_etc_passwd    RE    chroot hid /etc/passwd
read_etc_shadow    RE    chroot hid /etc/shadow
write_to_bin       RE    filesystem read-only
escape_chroot      RE    chdir("..") contained
read_proc_cpuinfo  RE    /proc subset=pid
read_proc_meminfo  RE    /proc subset=pid
read_sys_hardware  RE    /sys empty tmpfs
clone_newuser      RE    seccomp SIGSYS (exit 159)
mount_attempt      RE    seccomp SIGSYS
ptrace_attempt     RE    seccomp SIGSYS
fd_exhaustion      RE    RLIMIT_NOFILE
file_size_bomb     RE    RLIMIT_FSIZE
inode_bomb         RE    tmpfs inode limit
tcp_connect        RE    network namespace
dns_lookup         RE    network namespace
setuid_root        RE    credential drop
setgid_root        RE    credential drop
```

</details>

## 🏗 Architecture

```
src/
  kernel/      namespaces, cgroups v2, capabilities, mounts, seccomp, pidfd
  exec/        typestate pre-exec chain (11 stages, compile-time enforced)
  sandbox/     supervisor (Command + pre_exec + try_wait), proxy (fork + exec)
  runtime/     isolate lifecycle, command validation
  config/      config loading, validation, constants
  verdict/     evidence-backed verdict classification
  safety/      UID pool (atomic + flock), secure cleanup

judge-service/ HTTP API (axum), SQLite (r2d2 pool) / PostgreSQL, webhooks
```

**Execution flow:** HTTP -> queue -> spawn_blocking -> Isolate::new (UID + cgroup + workdir) -> launch_with_supervisor (Command + pre_exec(unshare) + stdin pipe + stdout/stderr reader threads + try_wait wall timeout) -> proxy (fork + typestate chain + execvp) -> post-mortem evidence collection -> verdict

## 🧪 Testing

```bash
python dev.py test          # cargo fmt + clippy + test
python dev.py stress        # parallel stress (260+ req/s, verifies every result)
python dev.py bench         # throughput benchmark (tiers 1-1000)
python dev.py adversarial   # 22 adversarial + 4 correctness + 11 recovery
python dev.py curl          # quick smoke test
```

| Suite | Count | What |
|---|---|---|
| Unit tests (lib) | 106 | Core sandbox logic |
| Integration (root) | 67 | Full sandbox execution |
| Compile-fail (trybuild) | 8 | Typestate misordering |
| Adversarial (Docker) | 22 | Fork bomb, seccomp bypass, chroot escape |
| Correctness (Docker) | 4 | Hello world, sieve, exit code, syntax error |
| Recovery (Docker) | 11 | Attack-then-verify interleaving |
| Algorithm suite | 33 | 13 problems x 3 languages |

## 🐳 Docker

```bash
# Judge profile (default)
docker build -t rustbox .
docker run --privileged --cpus=4 --memory=4g -p 4096:4096 rustbox

# Executor profile
docker build -t rustbox-executor -f Dockerfile.executor .
docker run --privileged --cpus=4 --memory=8g -p 4096:4096 rustbox-executor
```

Set `RUSTBOX_API_KEY=your-secret` for production.

## 📊 Performance

Measured with parallel Python ThreadPoolExecutor (every result verified correct):

| CPUs | Throughput | p50 | p95 |
|---|---|---|---|
| 4 | 260 req/s | 39ms | 86ms |
| 12 | 290 req/s | 39ms | 86ms |

Bottleneck is kernel cgroup/mount serialization, not CPU.

## 🙏 Acknowledgments

- [IOI Isolate](https://github.com/ioi/isolate) - the original sandbox for competitive programming
- [nsjail](https://github.com/google/nsjail) - seccomp and policy design inspiration
- [Standard Webhooks](https://www.standardwebhooks.com/) - webhook signature spec
