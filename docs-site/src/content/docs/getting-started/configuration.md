---
title: Configuration
description: Tune limits, add languages, customise behaviour
---

rustbox uses a layered configuration system. Defaults come from `config.json`, CLI flags override them, and the judge-service reads environment variables on top.

## config.json

Lives at the project root. Defines per-language resource limits, environment variables, and compilation settings.

```json
{
  "languages": {
    "python": {
      "memory_limit_mb": 128,
      "cpu_time_limit_secs": 4,
      "wall_time_limit_secs": 7,
      "max_processes": 10,
      "command": ["python3", "-c"],
      "environment": { "PYTHONDONTWRITEBYTECODE": "1" }
    },
    "cpp": {
      "memory_limit_mb": 256,
      "cpu_time_limit_secs": 8,
      "wall_time_limit_secs": 10,
      "max_processes": 8,
      "compile_command": ["g++", "-O2", "-std=c++17", "-o"],
      "run_command": ["./solution"]
    }
  }
}
```

:::note[Design Note]
Limits are per-language, not global. A Python solution with 128MB is generous. A Java solution with 128MB is a death sentence - the JVM alone needs ~100MB to start. We set sensible defaults so users don't have to think about this.
:::

## CLI overrides

CLI flags take precedence over `config.json`:

```bash
judge execute-code --permissive \
  --language python \
  --code 'while True: pass' \
  --cpu-time 1 \
  --wall-time 3 \
  --memory 64
```

## Judge-service environment variables

The HTTP service reads these at startup. All have sensible defaults.

| Variable | Default | What it does |
|----------|---------|-------------|
| `RUSTBOX_HOST` | `0.0.0.0` | Bind address |
| `RUSTBOX_PORT` | `3000` | Listen port |
| `RUSTBOX_WORKERS` | `4` | Concurrent sandbox workers |
| `RUSTBOX_API_KEY` | _(none)_ | Require this key in `x-api-key` header |
| `RUSTBOX_MAX_CODE_BYTES` | `65536` | Maximum source code size |
| `RUSTBOX_MAX_STDIN_BYTES` | `65536` | Maximum stdin payload |
| `RUSTBOX_SYNC_WAIT_TIMEOUT` | `30` | Seconds before `?wait=true` times out |
| `RUSTBOX_WEBHOOK_TIMEOUT` | `5` | Seconds for webhook HTTP delivery |
| `RUSTBOX_ALLOW_LOCALHOST_WEBHOOKS` | `false` | Allow `http://localhost` webhook URLs (dev mode) |
| `DATABASE_URL` | `sqlite://rustbox.db` | SQLite (default) or PostgreSQL connection string |

:::note[Design Note]
We deliberately don't support YAML or TOML config files for the judge-service. Environment variables are the standard for containerised deployments, and they're the only thing that works consistently across Docker, Kubernetes, systemd, and bare metal. One fewer config file to manage.
:::

## Seccomp configuration

Seccomp filtering is on by default. The built-in deny-list blocks 18 dangerous syscalls.

```bash
# Disable seccomp (not recommended)
judge execute-code --no-seccomp --language python --code '...'

# Use a custom policy file
judge execute-code --seccomp-policy /path/to/policy.json --language python --code '...'
```

The default deny-list:

| Syscall | Action | Why |
|---------|--------|-----|
| `io_uring_*` | ENOSYS | Bypass seccomp entirely |
| `ptrace` | KILL | Debug/inspect other processes |
| `process_vm_*` | KILL | Read/write other process memory |
| `bpf` | KILL | Load kernel modules |
| `mount`, `umount2` | KILL | Modify filesystem |
| `reboot` | KILL | Self-explanatory |
| `kexec_*` | KILL | Load new kernel |
| `init_module`, `delete_module` | KILL | Kernel module manipulation |
| `pivot_root`, `chroot` | KILL | Escape sandbox filesystem |

:::note[Design Note]
We use a deny-list (block known-dangerous, allow everything else) rather than an allowlist (block everything, allow known-safe). Complex runtimes like Python, Java, and the JVM make hundreds of different syscalls. Maintaining an allowlist for each runtime is fragile and breaks with every minor version update. The deny-list approach blocks the specific syscalls that enable sandbox escape while letting runtimes work naturally.
:::
