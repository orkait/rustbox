---
title: Testing
description: How we prove the sandbox works - unit tests, adversarial attacks, and stress benchmarks
---

## The short version

```bash
python3 dev.py test          # does it compile clean?
python3 dev.py adversarial   # can malicious code escape?
python3 dev.py stress        # does it hold under load?
```

## CI

Two jobs, every push:

| Job | Time | What |
|---|---|---|
| `build-and-test` | ~50s | fmt check, clippy, 106 unit tests, 8 compile-fail tests |
| `supply-chain-audit` | ~25s | cargo-deny (CVE, license, source verification) |

Integration tests (67 total) are `#[ignore]` in CI - they need root for namespace isolation. Run them manually with `sudo cargo test --include-ignored`.

## Test tiers

| What | Count | How | Needs root? |
|---|---|---|---|
| Unit tests | 106 | `cargo test --workspace` | No |
| Compile-fail (typestate) | 8 | `cargo test --test trybuild` | No |
| Adversarial exploits | 22 | `dev.py adversarial` (Docker) | Yes (Docker) |
| Correctness | 4 | Included in adversarial suite | Yes (Docker) |
| Recovery (attack-then-verify) | 11 | Included in adversarial suite | Yes (Docker) |
| Algorithm suite | 33 | 13 problems x 3 languages | Yes (Docker) |
| Integration (Rust) | 67 | `sudo cargo test --include-ignored` | Yes (host) |
| Stress | configurable | `dev.py stress` (Docker) | Yes (Docker) |

## Adversarial tests

22 exploit attempts, run inside Docker with full sandbox isolation. Every one must fail:

- **Process containment** - fork bomb, thread bomb
- **Memory** - allocate until OOM
- **Time** - infinite loop, SIGXCPU handler catch attempt
- **Filesystem** - read /etc/passwd, write to /bin, escape chroot
- **Proc/sys** - read /proc/cpuinfo, /proc/meminfo, walk /sys
- **Syscall filtering** - unshare(CLONE_NEWUSER), mount(), ptrace()
- **Resource exhaustion** - fd exhaustion, file size bomb, inode bomb
- **Network** - TCP connect, DNS lookup
- **Privilege escalation** - setuid(0), setgid(0)

The recovery suite interleaves attacks with correctness checks - fork bomb, then verify sieve(500000) still works. Proves the service recovers cleanly between malicious inputs.

## Compile-fail tests

8 trybuild tests verify the typestate chain catches mistakes at compile time:

- Skip namespace setup - compiler error
- Skip mount hardening - compiler error
- Skip cgroup attach - compiler error
- Skip root transition - compiler error
- Early exec from FreshChild - compiler error
- Early exec from NamespacesReady - compiler error
- Early exec from MountsPrivate - compiler error
- Reuse consumed state - compiler error

If any of these compile successfully, the typestate safety guarantee is broken.

## Stress testing

`dev.py stress` submits requests in parallel using Python's `ThreadPoolExecutor`, verifies every result:

```
  1x   1/1       25ms    39.5/s  PASS
  5x   5/5       27ms   182.3/s  PASS
 10x  10/10      49ms   203.9/s  PASS
 25x  25/25      77ms   324.3/s  PASS
 50x  50/50     200ms   249.9/s  PASS
```

`dev.py bench` extends to 1000x for throughput measurement. Every single response is checked for `verdict=AC` and `stdout=41538`.
