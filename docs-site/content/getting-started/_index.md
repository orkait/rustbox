+++
title = "Getting Started"
weight = 1
sort_by = "weight"
insert_anchor_links = "right"
+++

# Getting Started

## Installation

rustbox builds three binaries from one codebase. Pick whichever name you like - they're identical under the hood.

```bash
cargo build --release

# All three are the same binary with different CLI modes:
# target/release/rustbox   - accepts all commands
# target/release/isolate   - sandbox-only commands
# target/release/judge     - judge-focused commands (recommended)
```

### System requirements

- Linux with cgroups v2 (or v1 fallback)
- Python 3, g++, OpenJDK 21 for the respective languages
- Root access for strict mode (permissive mode works without it)

Check what's available:

```bash
judge check-deps --verbose
```

## Your first execution

Start with permissive mode. No root needed, no setup.

```bash
# Python
judge execute-code --permissive --language python --code 'print(2 ** 10)'

# C++
judge execute-code --permissive --language cpp --code '#include<iostream>
int main(){std::cout<<42<<std::endl;}'

# Java
judge execute-code --permissive --language java --code 'public class Main {
    public static void main(String[] args) {
        System.out.println(42);
    }
}'
```

The output is a JSON verdict with stdout, stderr, timing, memory usage, and exit code.

## Permissive vs Strict

| | Permissive | Strict |
|---|---|---|
| Needs root | No | Yes |
| Namespaces | Skipped | PID + mount + network |
| Cgroups | Best-effort | Enforced |
| Seccomp | Applied | Applied |
| Credential drop | Skipped (can't without root) | Enforced |
| Use case | Development, CI | Production |

> **Design Note:** Permissive mode isn't "insecure mode". It still applies seccomp filters, rlimits, and whatever controls it can without root. It gracefully degrades instead of failing. This lets you develop and test without `sudo` while strict mode guarantees the full chain in production.

## Strict mode

```bash
sudo judge execute-code --strict --language python --code 'print(1)'
```

Strict mode fails closed. If any security control can't be applied (cgroup creation fails, namespace setup fails, capability drop fails), the execution is rejected outright. There's no "try anyway" path.

## Next steps

- [Configuration](/getting-started/configuration/) - tune limits, add languages, customise behaviour
- [API Reference](/api/) - use the HTTP service instead of CLI
