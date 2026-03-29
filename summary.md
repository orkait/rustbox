# Rustbox - Complete Engineering Summary

## What Rustbox Is

A Linux-native code execution sandbox that runs untrusted code and proves what happened. Not a container runtime (Docker), not a microVM (Firecracker), not a wrapper around existing tools (Judge0). Direct kernel primitives composed in a fixed order that's enforced at compile time.

Two things make it different from everything else:
1. **Typestate chain** - the security setup order is enforced by the Rust compiler. You can't call execvp() without completing all 9 security steps. This isn't a convention or a runtime check - it's a type error if you try to skip a step.
2. **Evidence-backed verdicts** - the system doesn't just say "TLE" or "MLE". It proves it: which cgroup counters fired, which signals were sent, which controls were active, what the memory peak was. The verdict is traceable.

Single 3MB binary. 25ms cold start. 140 RPS measured on 12 cores.

---

## The Two Profiles

**Judge** - competitive programming mode. Maximum lockdown. No network, no packages, no mercy. The code runs for 3-8 seconds in a bare sandbox with just the language runtime. This is what Codeforces and AtCoder need.

**Executor** - LLM agent mode. Controlled access. Network (filtered), packages (numpy/pandas/14 total), relaxed limits (60s wall, 2GB memory). This is what Claude Code, GPT tool-use, and notebook runners need.

Same Docker image. Profile selected per-request. The packages exist on disk in both images but are only bind-mounted into the sandbox when profile=executor. Judge mode literally cannot see them.

---

## Why Every Decision Was Made

### Why we deleted degraded mode

Degraded mode was a development convenience: when clone() failed with EPERM (non-root), fall back to running the code with `std::process::Command` and minimal hardening. The problem:

- The non-root pre_exec closure only hardened when `geteuid() == 0`. Non-root degraded = bare process. Zero isolation.
- Even root degraded only dropped caps 0-40 (kernel supports 63), had no seccomp, and bypassed the typestate chain entirely.
- It was a second exec path that drifted from the primary path. Every security fix had to be applied twice.

We deleted it. One exec path. If you're not root, you get a clear error at the CLI. No silent degradation.

### Why we chose pre-cached packages over runtime pip install

pip install at runtime means:
- 30 seconds wasted per execution (pip download + compile)
- Network access required (opens exfiltration surface)
- Supply chain attack risk (malicious packages on pypi)
- venv creation per sandbox (2-3 seconds overhead)
- Disk space per sandbox (numpy alone is 30MB)
- Cache invalidation complexity

Pre-cached packages mean:
- 0ms install time (bind-mount read-only)
- No network needed for packages
- No supply chain risk (packages built once, auditable)
- No per-sandbox disk usage
- One line: `PYTHONPATH=/opt/packages/python`

The customer builds the image with their packages. The user sends code. rustbox mounts the packages. Zero runtime installs.

### Why we don't care about exfiltration

The sandbox contains: the user's code, their stdin data, and public Linux binaries (/bin, /lib, /usr). There are no secrets inside. No API keys, no database credentials, no other user's data.

If the user sends their own data to evil.com via the executor's network, they're sending their own data. That's like worrying that someone using a calculator might type in a secret number.

We block cloud metadata (169.254.169.254) because that's OUR infrastructure secret. We block private networks (10/172/192) because those are the operator's internal services. Everything else is the user's business.

### Why we dropped warm pooling

Warm pooling would pre-create sandboxes (cgroup + workdir + veth ready) and a request would grab one from the pool instead of creating from scratch. This would cut cold start from 25ms to ~1ms.

We dropped it because:
- 25ms is already 5-80x faster than Docker/Firecracker/Judge0
- Nobody notices 25ms inside a 500ms Python execution
- Pooling adds lifecycle management, reset logic, error recovery, pool sizing
- The typestate chain can't be split cleanly (seccomp/creds are irreversible)
- If a customer needs more throughput, add a second machine. Simpler than pool management.

### Why bridge + nftables, not per-sandbox iptables

iptables has a global kernel lock. Every `iptables -A` takes an exclusive lock on the entire filter table. At 140 RPS with 5 rules per sandbox (create + cleanup), that's 1400 lock acquisitions per second, all serialized. Measured impact: throughput drops from 140 to ~40 RPS.

Bridge with one-time nftables rules:
- 7 nftables rules applied once at startup (blocks metadata, private nets, inter-sandbox)
- Per-sandbox: just veth create + bridge attach (~3ms, no nftables changes, no locks)
- Cleanup: delete veth (~1ms, auto-deletes sandbox side)
- Throughput impact: ~5% (140 → ~133 RPS)

For egress/ingress quotas (100MB each): supervisor polls `/sys/class/net/veth-rb-{uid}/statistics/tx_bytes` every 10ms. Same pattern as CPU quota polling. No per-sandbox nftables rules needed.

### Why /16 subnet not /30

Each sandbox gets a unique IP on the bridge. Originally used /30 subnets (4 IPs each, 2 usable). The gateway (10.200.0.1) was not on the same /30 subnet as the sandbox IP, so `ip route add default via 10.200.0.1` failed with "Nexthop has invalid gateway."

Changed to /16 for all sandboxes. Everyone is on 10.200.0.0/16, gateway is 10.200.0.1, routing works. Inter-sandbox traffic blocked by nftables rule that drops 10.200.0.0/16 destinations (after allowing the gateway).

### Why OPENBLAS_NUM_THREADS=1

numpy, scipy, and opencv bundle OpenBLAS for linear algebra. OpenBLAS reads `/proc/cpuinfo` during initialization to detect CPU topology and select optimized SIMD kernels. Our sandboxed /proc uses `subset=pid` which hides `/proc/cpuinfo`. OpenBLAS can't find it and SEGFAULTs.

Setting `OPENBLAS_NUM_THREADS=1` tells OpenBLAS to skip the CPU topology detection and use a single-threaded codepath. The math still works, just doesn't auto-parallelize. For a 60-second sandbox, the performance difference is negligible.

### Why we removed RLIMIT_CPU

RLIMIT_CPU sends SIGXCPU when the process exceeds the soft CPU time limit. SIGXCPU is a catchable signal. A malicious program can `signal(SIGXCPU, SIG_IGN)` and keep running until the hard limit (soft+1 second).

The cgroup CPU polling in the supervisor checks `cpu.stat usage_usec` every 10ms and sends SIGKILL (uncatchable) when the limit is exceeded. This is strictly better: same enforcement, can't be caught.

---

## Every Bug Caught

### During refactoring (found by code analysis)

| Bug | How found | Impact if shipped |
|---|---|---|
| 64x default relaxation | Changed max_file_size_kb to max_file_size_mb, set default to 64 instead of 1 | Every sandbox gets 64MB file size instead of 1MB |
| 1024x alias trap | Added `alias = "max_file_size_kb"` for backward compat. Old config `1024` parsed as MB = 1GB | Old configs silently get 1GB file size limit |
| 30s vs 20s wall timeout | Supervisor fallback was 30s, IsolateConfig default was 20s | Two different "default" wall times depending on code path |
| Duplicate signal tracking | cli.rs had its own AtomicI32, kernel/signal.rs had AtomicU32 | Race between two signal stores, undefined behavior on concurrent signals |
| Dead time_limit field | Written in 5 places, read in 0 places | Confusion about which time limit to use |
| wipe_workdir silently ignoring failures | All removal errors swallowed with `let _` | Data leak between sandbox runs |
| packages_enabled never set to true | ExecutionProfile::from_config() hardcoded false, resolved limits disconnected | Executor mode ships with packages invisible - identical to judge |
| write_resolv_conf never called | Function defined but no call site in execution flow | DNS doesn't work in executor mode - no resolv.conf in chroot |
| NAT priority magic int | `priority 100` bare integer in nftables ruleset | Violates zero magic values rule |

### During red team testing (found by running exploits)

| Bug | Exploit | Impact if shipped |
|---|---|---|
| memfd_create + execve bypass | Create in-memory binary, exec via /proc/self/fd/{n} | Attacker runs arbitrary native binaries bypassing command allowlist |
| /proc/cpuinfo leak | Read /proc/cpuinfo in sandbox | Reveals host CPU model, core count, flags |
| /proc/meminfo leak | Read /proc/meminfo | Reveals host total memory |
| /sys hardware info | Read /sys sysfs | Reveals host hardware topology |
| SIGXCPU catchable | Install signal handler for SIGXCPU | Process survives CPU limit, gets extra computation time |
| clone(CLONE_NEWUSER) unblocked | Create nested user namespace | Expands kernel attack surface for CVE exploitation |
| Newer syscalls unblocked | process_madvise, statmount, lsm_set_self_attr etc. | Potential future kernel exploit vectors |

### During Docker testing (found by running packages)

| Bug | Symptom | Root cause |
|---|---|---|
| pip not installed | Executor image ships without Python packages, silently | Dockerfile installed python3.11 but not python3-pip |
| pip failure hidden | `|| true` swallowed errors | Dockerfile pattern masks build failures |
| matplotlib import fails | ModuleNotFoundError: unittest | Dockerfile deleted /usr/lib/python3.11/unittest to save space |
| cv2 SIGSEGV | Signal 11 on import | OpenBLAS reads /proc/cpuinfo, SEGFAULT in sandboxed /proc |
| /30 subnet unreachable gateway | "Nexthop has invalid gateway" | Sandbox IP on /30 subnet, gateway on different subnet |
| UID pool creates 100 users | Java getpwuid() fails for UIDs 60100-60999 | Dockerfile `seq 60000 60099` instead of `seq 60000 60999` |
| Bridge not created at startup | "Device does not exist" on executor request | setup_bridge() never called before first request |

---

## Red Team Report (30+ exploits)

Ran actual malicious code inside the sandbox in Docker. Every attack vector tested:

**Namespace escape**: clone(CLONE_NEWUSER) → KILLED by seccomp. unshare(CLONE_NEWNS) → KILLED. setns → KILLED.

**Host info**: /proc/cpuinfo → not found (subset=pid). /proc/meminfo → not found. /sys → empty tmpfs. /etc/hostname → not in chroot.

**Filesystem**: /etc/shadow → not in chroot. write to /bin → read-only. chroot ../ → stuck at chroot root. symlink attack → target doesn't exist. device node → EPERM (no CAP_MKNOD). mount() → KILLED.

**Privilege escalation**: setuid(0) → EPERM. ptrace → KILLED. io_uring → ENOSYS. kernel module → KILLED. bpf() → KILLED. memfd_create+exec → KILLED (after fix).

**Network**: TCP connect → unreachable. DNS → name resolution failed. HTTP to cloud metadata → unreachable. raw ICMP → EPERM. unix socket to docker → not in chroot.

**DoS**: Fork bomb → stopped at 2 forks. Memory bomb → OOM killed. Disk fill → stopped at 1MB. Inode bomb → stopped at 16380. FD exhaust → stopped at 29. CPU spin with SIGXCPU handler → KILLED by wall timer (no SIGXCPU sent).

**Kernel exploits**: reboot → KILLED. clock_settime → KILLED. kexec → KILLED. process_madvise → KILLED. open_by_handle_at → KILLED.

**Total: 0 escapes.**

---

## Scaling (measured, not projected)

| Machine | Peak RPS | Max concurrent tested | Failures |
|---|---|---|---|
| 4 CPU / 4GB | 60 | 1000 | 0 |
| 12 CPU / 24GB | 140 | 2000 | 0 |

Scaling is sub-linear (3x CPU → 2.3x RPS). The bottleneck is kernel serialization in cgroup creation and mount operations, not CPU computation. Single sandbox latency is 25ms on both machines.

Adding executor networking (veth creation) adds ~3ms per sandbox. At 140 RPS that's ~420ms/sec of kernel work - well within capacity.

---

## Behaviour Analyses Run (5 total)

1. **Sandbox enforcement system** - 35 state combinations, found C1 (degraded bare process), H1-H4, M1-M4
2. **Config layer magic numbers** - traced every value through 4 tiers, found H1 (wall timeout mismatch), caught 64x and 1024x bugs
3. **Executor network implementation** - 41 interactions, found bridge prerequisite (br_netfilter), inter-sandbox isolation need
4. **Three-tier config exposure** - 40 interactions, found H1 (no absolute ceiling), H2 (config default>max not validated), M1 (DNS IPs not validated)
5. **Security red team** - 72 attack vectors, found H1 (CLONE_NEWUSER), H2 (rate limiter default), memfd_create bypass

---

## What's Still Open

**H2: Rate limiter default** - `RUSTBOX_RATE_LIMIT` defaults to 0 (disabled). At 1000 concurrent requests, UID pool exhausts. Need to decide: default to 30/min per IP, or per-API-key session cap, or both. Deferred for discussion.

**Command allowlist hardcoded** - Adding a new language runtime requires code change + rebuild. Should derive from config.json runtime commands. Medium effort, not a v1 blocker.

**No depth limit in safe_cleanup recursion** - Adversarial deeply-nested directories could stack overflow the cleanup. Unlikely in practice but violates defense-in-depth.

---

## What's Deferred to v2

| Feature | Why deferred | Effort |
|---|---|---|
| IsolateConfig split | 25-field god struct, touches every file | Large |
| Language execution trait | Replace if/else compilation branching | Medium |
| Separate compile/run isolates | Fragile config save/restore pattern | Medium |
| Length-prefixed proxy protocol | Crash-safe framing | Small |
| Cgroup reuse | Reset vs recreate for latency | Large |
| Warm sandbox pool | Pre-created sandboxes | Large |
| Overlayfs | Share packages across sandboxes at scale | Medium |
| CPU pinning (cpuset) | Fair benchmarking | Small |
| Resource usage timeline | CPU/memory sampled during execution | Small |
| pivot_root vs chroot | Stronger root transition | Small |
| Streaming output (SSE) | Real-time stdout for long executions | Medium |
| Zip/tar upload | Multi-file project support | Medium |
| Horizontal scaling | Multiple nodes | Large |

---

## Numbers

| Metric | Start of session | End of session |
|---|---|---|
| Overall rating | 8.18 | 9.38 |
| Unit tests | 108 | 136 |
| Benchmark tests | 0 | 33 |
| Executor package tests | 0 | 20 |
| Exec paths | 3 | 1 |
| Magic values | 26+ | 0 |
| Named constants | 2 | 95 |
| Seccomp rules | 42 | 50 |
| Dead code removed | 0 | ~500 lines |
| Bugs found & fixed | 0 | 16+ |
| Exploits attempted | 0 | 30+ |
| Escapes | - | 0 |
| Packages (executor) | 0 | 14 Python + nlohmann/json + Gson |
| Pool leaks across all tests | - | 0 |
