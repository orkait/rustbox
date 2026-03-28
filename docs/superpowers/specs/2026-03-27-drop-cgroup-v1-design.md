# Drop cgroup v1 Support

## Context

Rustbox maintains dual cgroup backends (v1 and v2). cgroup v1 is legacy - every major distro defaults to v2 since 2021, RHEL 9 removed v1 entirely. The sandbox contention issue (PR #30) is architecturally v1: 15+ controller mount points cause kernel mount lock contention under concurrent load. On v2 (unified hierarchy, ~3-5 mounts), the issue doesn't exist.

Maintaining v1 costs ~800 lines of dual-backend code and forced 4 security/compatibility regressions (non-recursive MS_PRIVATE, removed sysfs, removed /dev/shm, removed procfs hidepid) as workarounds for v1 contention.

## Decision

Remove cgroup v1 support entirely. Keep the `CgroupBackend` trait (testing, extensibility). Revert the 4 risky contention workarounds since they're unnecessary on v2.

## Behavior

- **Strict mode (root):** Requires cgroup v2. Fails with actionable error if unavailable.
- **Permissive mode (non-root):** Warns if v2 unavailable, continues without cgroup enforcement. Existing behavior, just without v1 fallback.

## Changes

### Delete

| File | Lines | Reason |
|------|-------|--------|
| `src/kernel/cgroup_v1.rs` | 489 | Entire v1 backend |

### Modify

| File | Change |
|------|--------|
| `src/kernel/mod.rs` | Remove `pub mod cgroup_v1` |
| `src/kernel/cgroup.rs` | Remove `CgroupBackendType::V1`, `BackendSelector::ForceV1`, `from_force_v1()`, v1 detection path, v1 branches in selector. Remove `create_cgroup_backend()` wrapper. Update error message to mention v2 requirement. Keep trait, shared helpers, `CgroupV2` selection. |
| `src/config/types/isolation.rs` | Remove `force_cgroup_v1` field from `IsolateConfig` and its `Default` impl |
| `src/cli.rs` | Remove `--cgroup-v1` CLI arg, remove `config.force_cgroup_v1` assignment |
| `src/runtime/isolate.rs` | Replace `create_cgroup_backend(config.force_cgroup_v1, ...)` with direct v2 selection |
| `src/kernel/namespace.rs` | Revert to `MS_REC\|MS_PRIVATE` on `/`, remove `/tmp`-only workaround |
| `src/kernel/mount/filesystem.rs` | Restore sysfs mount, /dev/shm mount, procfs hidepid cascade |
| `src/sandbox/supervisor.rs` | Remove `force_v1` passthrough if present |

### Unchanged

| File | Reason |
|------|--------|
| `src/kernel/cgroup_v2.rs` | Sole backend, untouched |
| `src/sandbox/proxy.rs` | Safe fixes stay (watchdog thread) |
| `src/sandbox/supervisor.rs` | Safe fixes stay (3s budget, timed_out fix, IE classification) |
| `src/kernel/runtime_exec.rs` | Safe fix stays (no redundant unshare) |

### Reverted contention workarounds

| Workaround | Revert to | Why safe on v2 |
|------------|-----------|----------------|
| Non-recursive `MS_PRIVATE` on `/` | `MS_REC\|MS_PRIVATE` on `/` | v2 has ~5 mounts, not 25+. No contention. |
| Removed sysfs mount | Restore `mount_hardened_sysfs()` | Java needs `/sys/devices/system/cpu` |
| Removed /dev/shm mount | Restore `mount_limited_shm()` | Java uses shm for internal IPC |
| Single procfs (no hidepid) | Restore `mount_hardened_procfs()` cascade | 1-4 attempts is fine on v2 |

## Error message (v2 unavailable, strict mode)

```
Cgroup v2 not available on this host.
Rustbox requires cgroup v2 for resource enforcement.
Enable with: systemd.unified_cgroup_hierarchy=1 on kernel command line
```

Container environments get the existing docker hint appended.

## Tests

- Remove v1-specific assertions from `cgroup.rs::tests`
- Delete tests from `cgroup_v1.rs` (file deleted)
- `cgroup_v2.rs::tests` unchanged
- All integration/unit tests unchanged (none exercise v1 directly)
- Run `cargo test --all`, `cargo clippy --all`, `cargo fmt --check`

## Net impact

- ~600 lines deleted
- 4 security/compatibility regressions reverted
- Full `MS_REC|MS_PRIVATE`, sysfs, /dev/shm, procfs hidepid restored
- Contention issue eliminated at the root (v2 unified hierarchy)
