+++
title = "rustbox"
sort_by = "weight"
insert_anchor_links = "right"
+++

# rustbox

**Kernel-enforced sandboxing for untrusted code execution.**

rustbox runs arbitrary code from strangers on the internet and makes sure they can't do anything interesting with your server. It's built for competitive programming judges - where every submission is untrusted by default and verdicts must be provably correct.

If you're building an online judge, a code playground, or anything that executes user-submitted code, this is the isolation layer you put between their `import os; os.system("rm -rf /")` and your infrastructure.

---

## What makes it different

Most sandboxing tools bolt security on as an afterthought. rustbox starts from the kernel and works up:

- **8 layers of Linux isolation** - namespaces, cgroups, seccomp, capabilities, chroot, rlimits, credential drop, NO_NEW_PRIVS
- **Compile-time safety** - the typestate chain makes it impossible to run code without applying all security controls first
- **Evidence-based verdicts** - every TLE, MLE, and RE is backed by kernel evidence, not guesswork
- **2.8MB binary** - no Docker, no VMs, no JVM. Just a static binary that talks to the Linux kernel

## Quick taste

```bash
# Permissive mode (no root needed, good for development)
judge execute-code --permissive --language python --code 'print("hello")'

# Strict mode (full isolation, requires root)
sudo judge execute-code --strict --language python --code 'print("hello")'
```

## Where to start

- **[Getting Started](/getting-started/)** - install, configure, run your first sandbox
- **[API Reference](/api/)** - REST endpoints for the judge-service
- **[Architecture](/architecture/)** - how the security model works (and why)
- **[Internals](/internals/)** - for contributors: seccomp, cgroups, testing
