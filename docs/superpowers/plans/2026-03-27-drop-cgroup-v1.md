# Drop cgroup v1 Support - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove cgroup v1 backend, simplify cgroup selection to v2-only, revert 4 risky contention workarounds that are unnecessary on v2.

**Architecture:** Delete `cgroup_v1.rs`, strip v1 types/branches from `cgroup.rs`, remove `force_cgroup_v1` from config/CLI, revert mount workarounds in `namespace.rs` and `filesystem.rs`. Keep `CgroupBackend` trait for testability.

**Tech Stack:** Rust, Linux cgroups v2, nix crate, libc

**Spec:** `docs/superpowers/specs/2026-03-27-drop-cgroup-v1-design.md`

---

### Task 1: Delete cgroup v1 backend and remove module declaration

**Files:**
- Delete: `src/kernel/cgroup_v1.rs`
- Modify: `src/kernel/mod.rs:3`

- [ ] **Step 1: Delete cgroup_v1.rs**

```bash
rm src/kernel/cgroup_v1.rs
```

- [ ] **Step 2: Remove module declaration from kernel/mod.rs**

In `src/kernel/mod.rs`, remove line 3:
```rust
pub mod cgroup_v1;
```

The file should read:
```rust
pub mod capabilities;
pub mod cgroup;
pub mod cgroup_v2;
pub mod contract;
pub mod credentials;
pub mod mount;
pub mod namespace;
pub mod pipeline;
mod runtime_exec;
pub mod seccomp;
pub mod signal;

pub use contract::{
    EnforcementMode, KernelDomain, KernelRequirement, RequirementLevel, KERNEL_REQUIREMENTS,
    REQUIRED_STAGE_ORDER,
};
pub use pipeline::{KernelPipeline, KernelRunReport, KernelStage};
pub use runtime_exec::exec_payload;
```

- [ ] **Step 3: Verify it compiles (will fail - cgroup.rs still references v1)**

Run: `cargo check 2>&1 | head -20`
Expected: Errors about `cgroup_v1::CgroupV1` not found. This is correct - Task 2 fixes it.

- [ ] **Step 4: Commit**

```bash
git add -A src/kernel/cgroup_v1.rs src/kernel/mod.rs
git commit -m "refactor: delete cgroup v1 backend module"
```

---

### Task 2: Strip v1 from cgroup.rs

**Files:**
- Modify: `src/kernel/cgroup.rs`

- [ ] **Step 1: Rewrite cgroup.rs to v2-only**

Replace the entire contents of `src/kernel/cgroup.rs` with:

```rust
use crate::config::types::{CgroupEvidence, IsolateError, Result};
use std::path::PathBuf;

use super::cgroup_v2::CgroupV2;

pub(crate) fn sanitize_instance_id(instance_id: &str) -> String {
    let sanitized: String = instance_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = sanitized.trim_matches('_').to_string();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." || trimmed.contains("..") {
        "default".to_string()
    } else {
        trimmed
    }
}

pub trait CgroupBackend: Send + Sync {
    fn backend_name(&self) -> &str;
    fn create(&self, instance_id: &str) -> Result<()>;
    fn remove(&self, instance_id: &str) -> Result<()>;
    fn attach_process(&self, instance_id: &str, pid: u32) -> Result<()>;
    fn set_memory_limit(&self, instance_id: &str, limit_bytes: u64) -> Result<()>;
    fn set_process_limit(&self, instance_id: &str, limit: u32) -> Result<()>;
    fn set_cpu_limit(&self, instance_id: &str, limit_usec: u64) -> Result<()>;
    fn get_memory_usage(&self) -> Result<u64>;
    fn get_memory_peak(&self) -> Result<u64>;
    fn get_cpu_usage(&self) -> Result<u64>;
    fn get_process_count(&self) -> Result<u32>;
    fn check_oom(&self) -> Result<bool>;
    fn get_oom_kill_count(&self) -> Result<u64>;
    fn collect_evidence(&self, instance_id: &str) -> Result<CgroupEvidence>;
    fn get_cgroup_path(&self, instance_id: &str) -> PathBuf;
    fn is_empty(&self) -> Result<bool>;
}

pub(crate) fn read_cgroup_u64(path: &std::path::Path, field_name: &str) -> Result<u64> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        IsolateError::Cgroup(format!(
            "failed to read {} ({}): {}",
            field_name,
            path.display(),
            e
        ))
    })?;
    raw.trim().parse::<u64>().map_err(|e| {
        IsolateError::Cgroup(format!(
            "failed to parse {} ({}): {}",
            field_name,
            path.display(),
            e
        ))
    })
}

pub(crate) fn read_cgroup_optional_limit(
    path: &std::path::Path,
    field_name: &str,
) -> Result<Option<u64>> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(IsolateError::Cgroup(format!(
                "failed to read {} ({}): {}",
                field_name,
                path.display(),
                err
            )));
        }
    };
    let value = raw.trim();
    if value == "max" {
        return Ok(None);
    }
    value.parse::<u64>().map(Some).map_err(|err| {
        IsolateError::Cgroup(format!(
            "failed to parse {} ({}): {}",
            field_name,
            path.display(),
            err
        ))
    })
}

pub(crate) fn write_cgroup_value(
    path: &std::path::Path,
    value: &impl ToString,
    strict_mode: bool,
    name: &str,
) -> Result<()> {
    if let Err(err) = std::fs::write(path, value.to_string()) {
        if strict_mode {
            return Err(IsolateError::Cgroup(format!(
                "failed to write {} ({}): {}",
                name,
                path.display(),
                err
            )));
        }
        log::warn!(
            "failed to write {} ({}), continuing in permissive mode: {}",
            name,
            path.display(),
            err
        );
    }
    Ok(())
}

pub(crate) fn collect_cgroup_metric<T>(
    strict_mode: bool,
    field_name: &str,
    result: Result<T>,
    fallback: T,
) -> Result<T> {
    match result {
        Ok(value) => Ok(value),
        Err(err) if strict_mode => Err(IsolateError::Cgroup(format!(
            "failed collecting {} in strict mode: {}",
            field_name, err
        ))),
        Err(err) => {
            log::warn!(
                "failed collecting {} in permissive mode: {}",
                field_name,
                err
            );
            Ok(fallback)
        }
    }
}

pub(crate) fn collect_cgroup_optional_metric<T>(
    strict_mode: bool,
    field_name: &str,
    result: Result<T>,
) -> Result<Option<T>> {
    collect_cgroup_metric(strict_mode, field_name, result.map(Some), None)
}

#[must_use]
pub fn is_cgroup_v2_available() -> bool {
    std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

pub fn select_cgroup_backend(
    strict_mode: bool,
    instance_id: &str,
) -> Result<Box<dyn CgroupBackend>> {
    if is_cgroup_v2_available() {
        let backend = CgroupV2::new(instance_id, strict_mode)?;
        return Ok(Box::new(backend));
    }

    let mut msg = "Cgroup v2 not available on this host.\n\
                   Rustbox requires cgroup v2 for resource enforcement.\n\
                   Enable with: systemd.unified_cgroup_hierarchy=1 on kernel command line"
        .to_string();
    if crate::utils::container::is_container() {
        msg.push_str(".\n");
        msg.push_str(crate::utils::container::docker_cgroup_hint());
    }
    Err(IsolateError::Cgroup(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_instance_id_blocks_path_traversal() {
        assert_eq!(sanitize_instance_id(".."), "default");
        assert_eq!(sanitize_instance_id("../../../etc/passwd"), "default");
        assert_eq!(sanitize_instance_id("foo..bar"), "default");
        assert_eq!(sanitize_instance_id("a/.."), "default");
        assert_eq!(sanitize_instance_id("."), "default");
    }

    #[test]
    fn sanitize_instance_id_allows_valid_ids() {
        assert_eq!(sanitize_instance_id("box-42"), "box-42");
        assert_eq!(sanitize_instance_id("rustbox_1"), "rustbox_1");
        assert_eq!(sanitize_instance_id("test.instance"), "test.instance");
    }

    #[test]
    fn v2_detection_returns_bool() {
        let _ = is_cgroup_v2_available();
    }
}
```

- [ ] **Step 2: Verify it compiles (will fail - callers still use old API)**

Run: `cargo check 2>&1 | head -20`
Expected: Errors in `runtime/isolate.rs` about `create_cgroup_backend`. This is correct - Task 3 fixes it.

- [ ] **Step 3: Commit**

```bash
git add src/kernel/cgroup.rs
git commit -m "refactor: simplify cgroup.rs to v2-only selection"
```

---

### Task 3: Remove force_cgroup_v1 from IsolateConfig

**Files:**
- Modify: `src/config/types/isolation.rs:110,163`

- [ ] **Step 1: Remove field and default**

In `src/config/types/isolation.rs`, remove the `force_cgroup_v1` field from `IsolateConfig` (line 110-111):
```rust
    #[serde(default)]
    pub force_cgroup_v1: bool,
```

And remove the corresponding default value (line 163):
```rust
            force_cgroup_v1: false,
```

- [ ] **Step 2: Commit**

```bash
git add src/config/types/isolation.rs
git commit -m "refactor: remove force_cgroup_v1 from IsolateConfig"
```

---

### Task 4: Update runtime/isolate.rs to use new cgroup API

**Files:**
- Modify: `src/runtime/isolate.rs:121-122`

- [ ] **Step 1: Replace create_cgroup_backend call**

In `src/runtime/isolate.rs`, change lines 121-124 from:
```rust
        let cgroup = match cgroup::create_cgroup_backend(
            config.force_cgroup_v1,
            config.strict_mode,
            &config.instance_id,
        ) {
```

To:
```rust
        let cgroup = match cgroup::select_cgroup_backend(
            config.strict_mode,
            &config.instance_id,
        ) {
```

- [ ] **Step 2: Verify it compiles (will fail - cli.rs still references removed fields)**

Run: `cargo check 2>&1 | head -20`
Expected: Errors in `cli.rs` about `cgroup_v1` field. Task 5 fixes it.

- [ ] **Step 3: Commit**

```bash
git add src/runtime/isolate.rs
git commit -m "refactor: use select_cgroup_backend (v2-only API)"
```

---

### Task 5: Remove --cgroup-v1 CLI flag

**Files:**
- Modify: `src/cli.rs:76-77,220,266`

- [ ] **Step 1: Remove the CLI arg definition**

In `src/cli.rs`, remove lines 76-77 from the `ExecuteCode` variant:
```rust
        #[arg(long = "cgroup-v1")]
        cgroup_v1: bool,
```

- [ ] **Step 2: Remove the destructured field**

In `src/cli.rs`, remove `cgroup_v1,` from the match arm destructuring around line 220.

- [ ] **Step 3: Remove the config assignment**

In `src/cli.rs`, remove line 266:
```rust
            config.force_cgroup_v1 = cgroup_v1;
```

- [ ] **Step 4: Verify full compilation**

Run: `cargo check`
Expected: Clean compilation with no errors.

- [ ] **Step 5: Commit**

```bash
git add src/cli.rs
git commit -m "refactor: remove --cgroup-v1 CLI flag"
```

---

### Task 6: Revert non-recursive MS_PRIVATE workaround

**Files:**
- Modify: `src/kernel/namespace.rs:165-195`

- [ ] **Step 1: Restore MS_REC|MS_PRIVATE on /**

Replace the `harden_mount_propagation()` function in `src/kernel/namespace.rs` (starting at line 165) with:

```rust
pub fn harden_mount_propagation() -> Result<()> {
    use nix::mount::{mount, MsFlags};

    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| {
        IsolateError::Namespace(format!(
            "CRITICAL: Failed to harden mount propagation (MS_PRIVATE|MS_REC on /): {}",
            e
        ))
    })?;

    Ok(())
}
```

This removes the non-recursive workaround and the `/tmp`-only fallback. On v2 (unified hierarchy, ~5 mounts), the recursive walk is fast and doesn't contend.

- [ ] **Step 2: Verify compilation**

Run: `cargo check`
Expected: Clean.

- [ ] **Step 3: Commit**

```bash
git add src/kernel/namespace.rs
git commit -m "security: restore MS_REC|MS_PRIVATE mount propagation hardening"
```

---

### Task 7: Restore sysfs, /dev/shm, and procfs hidepid in filesystem.rs

**Files:**
- Modify: `src/kernel/mount/filesystem.rs:610-633`

- [ ] **Step 1: Restore setup_hardened_mounts**

Replace the `setup_hardened_mounts` method in `src/kernel/mount/filesystem.rs` (starting at line 610) with:

```rust
    #[cfg(unix)]
    fn setup_hardened_mounts(&self, chroot_path: &Path) -> Result<()> {
        let sys_path = chroot_path.join("sys");
        if sys_path.exists() {
            self.mount_hardened_sysfs(&sys_path)?;
        }

        let dev_path = chroot_path.join("dev");
        if dev_path.exists() {
            self.mount_hardened_devfs(&dev_path)?;
        }

        let proc_path = chroot_path.join("proc");
        if proc_path.exists() {
            self.mount_hardened_procfs(&proc_path)?;
        }

        let shm_path = chroot_path.join("dev").join("shm");
        if !shm_path.exists() {
            let _ = fs::create_dir_all(&shm_path);
        }
        if shm_path.exists() {
            self.mount_limited_shm(&shm_path)?;
        }

        let tmp_path = chroot_path.join("tmp");
        if tmp_path.exists() {
            self.mount_hardened_tmp(&tmp_path)?;
        }

        Ok(())
    }
```

This restores:
- sysfs mount (Java CPU topology)
- /dev/shm mount (Java shared memory IPC)
- procfs hidepid cascade (defense-in-depth)

- [ ] **Step 2: Verify compilation**

Run: `cargo check`
Expected: Clean.

- [ ] **Step 3: Commit**

```bash
git add src/kernel/mount/filesystem.rs
git commit -m "security: restore sysfs, /dev/shm, and procfs hidepid mounts"
```

---

### Task 8: Run full test suite and verify

**Files:** None (verification only)

- [ ] **Step 1: Run cargo fmt**

Run: `cargo fmt --all`

- [ ] **Step 2: Run cargo clippy**

Run: `cargo clippy --all -- -D warnings`
Expected: Clean, no warnings.

- [ ] **Step 3: Run all tests**

Run: `cargo test --all`
Expected: All tests pass. Tests in `cgroup_v1.rs` are gone. Tests in `cgroup.rs` are updated. Tests in `cgroup_v2.rs` unchanged. No test references v1-specific types.

- [ ] **Step 4: Verify no v1 references remain**

Run: `grep -rn 'cgroup_v1\|CgroupV1\|force_cgroup_v1\|ForceV1\|CgroupBackendType::V1' src/`
Expected: No matches.

- [ ] **Step 5: Commit any fmt/clippy fixes**

```bash
git add -A
git commit -m "chore: fmt + clippy fixes after v1 removal"
```

(Skip this commit if there were no changes.)

---

### Task 9: Clean up SANDBOX_CONTENTION_ISSUE.md

**Files:**
- Delete: `SANDBOX_CONTENTION_ISSUE.md`

- [ ] **Step 1: Delete the issue document**

The contention issue is resolved by dropping v1. The document is untracked and no longer relevant.

```bash
rm SANDBOX_CONTENTION_ISSUE.md
```

- [ ] **Step 2: Final commit**

```bash
git add -A
git commit -m "chore: remove sandbox contention issue doc (resolved by dropping cgroup v1)"
```
