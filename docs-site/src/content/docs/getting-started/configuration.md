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
      "memory": { "limit_mb": 128, "limit_kb": 131072 },
      "time": { "cpu_time_seconds": 4, "wall_time_seconds": 7 },
      "processes": { "max_processes": 10 },
      "environment": { "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1" },
      "compilation": { "enabled": false }
    },
    "cpp": {
      "memory": { "limit_mb": 256, "limit_kb": 262144 },
      "time": { "cpu_time_seconds": 8, "wall_time_seconds": 10 },
      "processes": { "max_processes": 8 },
      "compilation": {
        "enabled": true,
        "compiler": "g++",
        "compiler_args": ["-O2", "-std=c++17", "-o", "{output}", "{source}"]
      }
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
  --cpu 1 \
  --wall-time 3 \
  --mem 64
```

## Judge-service environment variables

The HTTP service reads these at startup. All have sensible defaults.

| Variable | Default | What it does |
|----------|---------|-------------|
| `RUSTBOX_PORT` | `4096` | Listen port |
| `RUSTBOX_WORKERS` | `2` | Concurrent sandbox workers |
| `RUSTBOX_QUEUE_SIZE` | `100` | Max pending submissions |
| `RUSTBOX_DATABASE_URL` | `sqlite:rustbox.db` | SQLite or PostgreSQL connection string |
| `RUSTBOX_API_KEY` | _(none)_ | Require this key in `x-api-key` header |
| `RUSTBOX_NODE_ID` | _(auto UUID)_ | Node identifier for multi-node setups |
| `RUSTBOX_MAX_CODE_BYTES` | `65536` | Maximum source code size |
| `RUSTBOX_MAX_STDIN_BYTES` | `262144` | Maximum stdin payload (256KB) |
| `RUSTBOX_SYNC_WAIT_TIMEOUT_SECS` | `30` | Seconds before `?wait=true` times out |
| `RUSTBOX_SYNC_POLL_INTERVAL_MS` | `200` | Poll interval for sync mode |
| `RUSTBOX_WEBHOOK_TIMEOUT_SECS` | `10` | Seconds for webhook HTTP delivery |
| `RUSTBOX_ALLOW_LOCALHOST_WEBHOOKS` | `false` | Allow `http://localhost` webhook URLs (dev mode) |
| `RUSTBOX_STALE_TIMEOUT_SECS` | `300` | Reaper timeout for stuck jobs |
| `RUSTBOX_REAPER_INTERVAL_SECS` | `60` | How often the reaper runs |

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
| `io_uring_*` | ENOSYS | Kernel attack surface, bypasses seccomp |
| `ptrace` | KILL | Debug/inspect other processes |
| `process_vm_readv`, `process_vm_writev` | KILL | Read/write other process memory |
| `bpf` | KILL | eBPF program loading |
| `userfaultfd` | KILL | Page fault interception |
| `perf_event_open` | KILL | Performance monitoring abuse |
| `kexec_load` | KILL | Load new kernel |
| `init_module`, `finit_module`, `delete_module` | KILL | Kernel module manipulation |
| `mount`, `umount2`, `pivot_root` | KILL | Filesystem manipulation |
| `swapon`, `swapoff` | KILL | Swap manipulation |

:::note[Design Note]
We use a deny-list (block known-dangerous, allow everything else) rather than an allowlist (block everything, allow known-safe). Complex runtimes like Python, Java, and the JVM make hundreds of different syscalls. Maintaining an allowlist for each runtime is fragile and breaks with every minor version update. The deny-list approach blocks the specific syscalls that enable sandbox escape while letting runtimes work naturally.
:::
