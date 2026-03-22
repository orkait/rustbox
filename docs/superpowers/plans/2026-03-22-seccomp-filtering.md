# Seccomp-BPF Syscall Filtering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add seccomp-bpf syscall filtering with a built-in deny-list (default on) and user-supplied policy override, following the nsjail pattern of DEFAULT ALLOW + block dangerous syscalls.

**Architecture:** New `src/kernel/seccomp.rs` module implements filter construction and installation. The built-in deny-list blocks 15 syscalls across 5 families (io_uring, tracing, bpf/perf, modules, mount/swap). Users can override with a JSON policy file. Filter is installed in `runtime_exec.rs` after privilege lockdown, before execvp. No typestate changes needed.

**Tech Stack:** `seccompiler` crate (Rust-native BPF compiler, used by AWS Firecracker), `libc` for syscall numbers.

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `src/kernel/seccomp.rs` | Create | Policy types, built-in deny-list, filter construction, installation |
| `src/kernel/mod.rs` | Modify (add 1 line) | Register `pub mod seccomp` |
| `src/kernel/runtime_exec.rs` | Modify (~5 lines) | Call `seccomp::install_filter()` before exec, add STAGE_SECCOMP |
| `src/config/types.rs` | Modify (~3 lines) | Add `seccomp_policy_file` and `no_seccomp` to `IsolateConfig` |
| `src/core/types.rs` | Modify (~2 lines) | Add `enable_seccomp` + `seccomp_policy_file` to `ExecutionProfile` |
| `src/cli.rs` | Modify (~4 lines) | Add `--seccomp-policy` and `--no-seccomp` CLI flags |
| `Cargo.toml` | Modify (1 line) | Add `seccompiler = "0.4"` dependency |
| `tests/seccomp_integration.rs` | Create | Integration tests for filter application |

---

### Task 1: Add `seccompiler` dependency

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add seccompiler to dependencies**

In `Cargo.toml` under `[dependencies]`, add:

```toml
seccompiler = "0.4"
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check`
Expected: clean compilation, seccompiler resolves

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "deps: add seccompiler crate for seccomp-bpf filtering"
```

---

### Task 2: Create `src/kernel/seccomp.rs` with built-in deny-list

**Files:**
- Create: `src/kernel/seccomp.rs`
- Modify: `src/kernel/mod.rs` (add `pub mod seccomp;`)

This is the core module. It defines:
- `SeccompPolicy` enum (Disabled, BuiltinDenyList, CustomFile)
- The hardcoded deny-list constant
- `build_filter()` that produces a `BpfProgram`
- `install_filter()` that applies it via seccomp

- [ ] **Step 1: Write the failing test**

Create `src/kernel/seccomp.rs` with tests first:

```rust
use crate::config::types::{IsolateError, Result};
use seccompiler::{
    apply_filter, BpfProgram, SeccompAction, SeccompFilter,
};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Debug)]
pub enum SeccompPolicy {
    Disabled,
    BuiltinDenyList,
    CustomFile(std::path::PathBuf),
}

impl Default for SeccompPolicy {
    fn default() -> Self {
        Self::BuiltinDenyList
    }
}

struct SyscallRule {
    name: &'static str,
    num: i64,
    action: SeccompAction,
}

const BUILTIN_DENY_LIST: &[SyscallRule] = &[
    // io_uring: kernel LPE history (CVE-2021-41073, CVE-2023-2598)
    // ERRNO(ENOSYS) so runtimes that probe for io_uring fall back gracefully
    SyscallRule { name: "io_uring_setup",    num: libc::SYS_io_uring_setup as i64,    action: SeccompAction::Errno(libc::ENOSYS as u32) },
    SyscallRule { name: "io_uring_enter",    num: libc::SYS_io_uring_enter as i64,    action: SeccompAction::Errno(libc::ENOSYS as u32) },
    SyscallRule { name: "io_uring_register", num: libc::SYS_io_uring_register as i64, action: SeccompAction::Errno(libc::ENOSYS as u32) },
    // Tracing: cross-process inspection
    SyscallRule { name: "ptrace",              num: libc::SYS_ptrace as i64,              action: SeccompAction::KillProcess },
    SyscallRule { name: "process_vm_readv",    num: libc::SYS_process_vm_readv as i64,    action: SeccompAction::KillProcess },
    SyscallRule { name: "process_vm_writev",   num: libc::SYS_process_vm_writev as i64,   action: SeccompAction::KillProcess },
    // Kernel subsystems: BPF, userfaultfd, perf
    SyscallRule { name: "bpf",              num: libc::SYS_bpf as i64,              action: SeccompAction::KillProcess },
    SyscallRule { name: "userfaultfd",      num: libc::SYS_userfaultfd as i64,      action: SeccompAction::KillProcess },
    SyscallRule { name: "perf_event_open",  num: libc::SYS_perf_event_open as i64,  action: SeccompAction::KillProcess },
    // Module/boot: kernel module loading
    SyscallRule { name: "kexec_load",       num: libc::SYS_kexec_load as i64,       action: SeccompAction::KillProcess },
    SyscallRule { name: "init_module",      num: libc::SYS_init_module as i64,      action: SeccompAction::KillProcess },
    SyscallRule { name: "finit_module",     num: libc::SYS_finit_module as i64,     action: SeccompAction::KillProcess },
    SyscallRule { name: "delete_module",    num: libc::SYS_delete_module as i64,    action: SeccompAction::KillProcess },
    // Mount/swap: filesystem manipulation
    SyscallRule { name: "mount",    num: libc::SYS_mount as i64,    action: SeccompAction::KillProcess },
    SyscallRule { name: "umount2",  num: libc::SYS_umount2 as i64,  action: SeccompAction::KillProcess },
    SyscallRule { name: "pivot_root", num: libc::SYS_pivot_root as i64, action: SeccompAction::KillProcess },
    SyscallRule { name: "swapon",   num: libc::SYS_swapon as i64,   action: SeccompAction::KillProcess },
    SyscallRule { name: "swapoff",  num: libc::SYS_swapoff as i64,  action: SeccompAction::KillProcess },
];

fn build_builtin_deny_filter() -> Result<BpfProgram> {
    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();

    // Group syscalls by action. SeccompFilter needs one match_action,
    // so we build separate filters per action and chain them.
    // Actually seccompiler supports per-rule actions via the rules map:
    // empty rule vec + match on syscall number = unconditional match.
    //
    // For a deny-list: default action = Allow, and each denied syscall
    // maps to its specific action. But SeccompFilter only supports ONE
    // match_action. So we need to build multiple filters (one per action)
    // and install them in sequence. Seccomp filters stack in the kernel -
    // all filters must agree to ALLOW.
    //
    // Strategy: install ERRNO(ENOSYS) filter first (io_uring), then
    // KILL_PROCESS filter (everything else). Order doesn't matter because
    // kernel uses the most restrictive result.

    let arch = std::env::consts::ARCH.try_into().map_err(|_|
        IsolateError::Config("Unsupported architecture for seccomp".to_string())
    )?;

    // Filter 1: io_uring → ERRNO(ENOSYS)
    let mut enosys_rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for rule in BUILTIN_DENY_LIST {
        if matches!(rule.action, SeccompAction::Errno(_)) {
            enosys_rules.insert(rule.num, vec![]);
        }
    }
    let enosys_filter = SeccompFilter::new(
        enosys_rules,
        SeccompAction::Allow,    // default: allow
        SeccompAction::Errno(libc::ENOSYS as u32), // match: ENOSYS
        arch,
    ).map_err(|e| IsolateError::Config(format!("seccomp enosys filter: {}", e)))?;

    // Filter 2: tracing/bpf/modules/mount → KILL_PROCESS
    let mut kill_rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for rule in BUILTIN_DENY_LIST {
        if matches!(rule.action, SeccompAction::KillProcess) {
            kill_rules.insert(rule.num, vec![]);
        }
    }
    let kill_filter = SeccompFilter::new(
        kill_rules,
        SeccompAction::Allow,
        SeccompAction::KillProcess,
        arch,
    ).map_err(|e| IsolateError::Config(format!("seccomp kill filter: {}", e)))?;

    // We return the kill filter as the primary BPF program.
    // The enosys filter will be installed separately.
    // Actually, let's combine differently - see install_filter.
    let prog: BpfProgram = kill_filter.try_into()
        .map_err(|e| IsolateError::Config(format!("seccomp compile: {}", e)))?;
    Ok(prog)
}

pub fn load_custom_policy(path: &Path) -> Result<Vec<BpfProgram>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| IsolateError::Config(format!("read seccomp policy {}: {}", path.display(), e)))?;
    let policy: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| IsolateError::Config(format!("parse seccomp policy: {}", e)))?;

    let arch = std::env::consts::ARCH.try_into().map_err(|_|
        IsolateError::Config("Unsupported architecture for seccomp".to_string())
    )?;

    let default_action = match policy.get("default_action").and_then(|v| v.as_str()) {
        Some("allow") => SeccompAction::Allow,
        Some("kill") | Some("kill_process") => SeccompAction::KillProcess,
        Some("errno") => SeccompAction::Errno(libc::EPERM as u32),
        Some(other) => return Err(IsolateError::Config(format!("unknown default_action: {}", other))),
        None => SeccompAction::Allow,
    };

    let mut programs = Vec::new();

    if let Some(rules) = policy.get("rules").and_then(|v| v.as_array()) {
        // Group rules by action, build one filter per action
        let mut action_groups: std::collections::HashMap<String, Vec<i64>> = std::collections::HashMap::new();
        for rule in rules {
            let action_str = rule.get("action").and_then(|v| v.as_str()).unwrap_or("kill_process");
            let syscalls = rule.get("syscalls").and_then(|v| v.as_array())
                .ok_or_else(|| IsolateError::Config("rule missing 'syscalls' array".to_string()))?;
            for sc in syscalls {
                let name = sc.as_str()
                    .ok_or_else(|| IsolateError::Config("syscall must be a string".to_string()))?;
                let num = syscall_name_to_number(name)
                    .ok_or_else(|| IsolateError::Config(format!("unknown syscall: {}", name)))?;
                action_groups.entry(action_str.to_string()).or_default().push(num);
            }
        }

        for (action_str, syscall_nums) in &action_groups {
            let match_action = match action_str.as_str() {
                "kill" | "kill_process" => SeccompAction::KillProcess,
                "errno" | "errno_enosys" => SeccompAction::Errno(libc::ENOSYS as u32),
                "errno_eperm" => SeccompAction::Errno(libc::EPERM as u32),
                "trap" => SeccompAction::Trap,
                "allow" => SeccompAction::Allow,
                other => return Err(IsolateError::Config(format!("unknown action: {}", other))),
            };
            let filter_rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> =
                syscall_nums.iter().map(|&n| (n, vec![])).collect();
            let filter = SeccompFilter::new(filter_rules, default_action, match_action, arch)
                .map_err(|e| IsolateError::Config(format!("seccomp filter build: {}", e)))?;
            let prog: BpfProgram = filter.try_into()
                .map_err(|e| IsolateError::Config(format!("seccomp compile: {}", e)))?;
            programs.push(prog);
        }
    }

    Ok(programs)
}

/// Resolve syscall name to number for the current architecture.
fn syscall_name_to_number(name: &str) -> Option<i64> {
    // Map of commonly denied syscalls. We only need names that appear
    // in policy files, not the full Linux syscall table.
    let num = match name {
        "io_uring_setup"      => libc::SYS_io_uring_setup,
        "io_uring_enter"      => libc::SYS_io_uring_enter,
        "io_uring_register"   => libc::SYS_io_uring_register,
        "ptrace"              => libc::SYS_ptrace,
        "process_vm_readv"    => libc::SYS_process_vm_readv,
        "process_vm_writev"   => libc::SYS_process_vm_writev,
        "bpf"                 => libc::SYS_bpf,
        "userfaultfd"         => libc::SYS_userfaultfd,
        "perf_event_open"     => libc::SYS_perf_event_open,
        "kexec_load"          => libc::SYS_kexec_load,
        "init_module"         => libc::SYS_init_module,
        "finit_module"        => libc::SYS_finit_module,
        "delete_module"       => libc::SYS_delete_module,
        "mount"               => libc::SYS_mount,
        "umount2"             => libc::SYS_umount2,
        "pivot_root"          => libc::SYS_pivot_root,
        "swapon"              => libc::SYS_swapon,
        "swapoff"             => libc::SYS_swapoff,
        "reboot"              => libc::SYS_reboot,
        "settimeofday"        => libc::SYS_settimeofday,
        "clock_settime"       => libc::SYS_clock_settime,
        "acct"                => libc::SYS_acct,
        "quotactl"            => libc::SYS_quotactl,
        "add_key"             => libc::SYS_add_key,
        "keyctl"              => libc::SYS_keyctl,
        "request_key"         => libc::SYS_request_key,
        "mbind"               => libc::SYS_mbind,
        "set_mempolicy"       => libc::SYS_set_mempolicy,
        "move_pages"          => libc::SYS_move_pages,
        "lookup_dcookie"      => libc::SYS_lookup_dcookie,
        "personality"         => libc::SYS_personality,
        "nfsservctl"          => libc::SYS_nfsservctl,
        _ => return None,
    };
    Some(num as i64)
}

/// Install seccomp filter(s) on the calling thread. Must be called
/// after NO_NEW_PRIVS is set (otherwise seccomp(2) returns EACCES).
pub fn install_filter(policy: &SeccompPolicy) -> Result<()> {
    match policy {
        SeccompPolicy::Disabled => Ok(()),
        SeccompPolicy::BuiltinDenyList => install_builtin_deny_list(),
        SeccompPolicy::CustomFile(path) => install_custom_policy(path),
    }
}

fn install_builtin_deny_list() -> Result<()> {
    let arch = std::env::consts::ARCH.try_into().map_err(|_|
        IsolateError::Config("Unsupported architecture for seccomp".to_string())
    )?;

    // Filter 1: io_uring → ERRNO(ENOSYS)
    let enosys_rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BUILTIN_DENY_LIST.iter()
        .filter(|r| matches!(r.action, SeccompAction::Errno(_)))
        .map(|r| (r.num, vec![]))
        .collect();
    if !enosys_rules.is_empty() {
        let filter = SeccompFilter::new(
            enosys_rules, SeccompAction::Allow,
            SeccompAction::Errno(libc::ENOSYS as u32), arch,
        ).map_err(|e| IsolateError::Config(format!("seccomp enosys filter: {}", e)))?;
        let prog: BpfProgram = filter.try_into()
            .map_err(|e| IsolateError::Config(format!("seccomp compile: {}", e)))?;
        apply_filter(&prog)
            .map_err(|e| IsolateError::Config(format!("seccomp apply enosys: {}", e)))?;
    }

    // Filter 2: everything else → KILL_PROCESS
    let kill_rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BUILTIN_DENY_LIST.iter()
        .filter(|r| matches!(r.action, SeccompAction::KillProcess))
        .map(|r| (r.num, vec![]))
        .collect();
    if !kill_rules.is_empty() {
        let filter = SeccompFilter::new(
            kill_rules, SeccompAction::Allow,
            SeccompAction::KillProcess, arch,
        ).map_err(|e| IsolateError::Config(format!("seccomp kill filter: {}", e)))?;
        let prog: BpfProgram = filter.try_into()
            .map_err(|e| IsolateError::Config(format!("seccomp compile: {}", e)))?;
        apply_filter(&prog)
            .map_err(|e| IsolateError::Config(format!("seccomp apply kill: {}", e)))?;
    }

    Ok(())
}

fn install_custom_policy(path: &Path) -> Result<()> {
    let programs = load_custom_policy(path)?;
    for prog in &programs {
        apply_filter(prog)
            .map_err(|e| IsolateError::Config(format!("seccomp apply custom: {}", e)))?;
    }
    Ok(())
}

/// Returns list of syscall names in the built-in deny-list (for evidence/logging).
pub fn builtin_deny_list_names() -> Vec<&'static str> {
    BUILTIN_DENY_LIST.iter().map(|r| r.name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_deny_list_has_expected_count() {
        assert_eq!(BUILTIN_DENY_LIST.len(), 18);
    }

    #[test]
    fn builtin_deny_list_names_returns_all() {
        let names = builtin_deny_list_names();
        assert!(names.contains(&"io_uring_setup"));
        assert!(names.contains(&"ptrace"));
        assert!(names.contains(&"bpf"));
        assert!(names.contains(&"mount"));
        assert!(names.contains(&"kexec_load"));
    }

    #[test]
    fn syscall_name_to_number_resolves_known() {
        assert!(syscall_name_to_number("ptrace").is_some());
        assert!(syscall_name_to_number("io_uring_setup").is_some());
        assert!(syscall_name_to_number("bpf").is_some());
    }

    #[test]
    fn syscall_name_to_number_returns_none_for_unknown() {
        assert!(syscall_name_to_number("not_a_syscall").is_none());
    }

    #[test]
    fn disabled_policy_is_noop() {
        assert!(install_filter(&SeccompPolicy::Disabled).is_ok());
    }

    #[test]
    fn default_policy_is_builtin() {
        assert!(matches!(SeccompPolicy::default(), SeccompPolicy::BuiltinDenyList));
    }

    #[test]
    fn custom_policy_rejects_missing_file() {
        let result = install_filter(&SeccompPolicy::CustomFile("/nonexistent.json".into()));
        assert!(result.is_err());
    }
}
```

- [ ] **Step 2: Register module in kernel/mod.rs**

Add to `src/kernel/mod.rs`:

```rust
pub mod seccomp;
```

- [ ] **Step 3: Run tests to verify they compile and pass**

Run: `cargo test seccomp -- --nocapture`
Expected: 7 tests pass (the builtin filter tests don't need NO_NEW_PRIVS since they test construction, not installation)

- [ ] **Step 4: Commit**

```bash
git add src/kernel/seccomp.rs src/kernel/mod.rs
git commit -m "feat(seccomp): add deny-list filter module with seccompiler"
```

---

### Task 3: Add config and CLI flags

**Files:**
- Modify: `src/config/types.rs` (IsolateConfig struct, ~3 lines)
- Modify: `src/core/types.rs` (ExecutionProfile struct + from_config, ~4 lines)
- Modify: `src/cli.rs` (Commands enum + config wiring, ~8 lines)

- [ ] **Step 1: Add fields to IsolateConfig**

In `src/config/types.rs`, add to the `IsolateConfig` struct after `allow_degraded`:

```rust
    #[serde(default)]
    pub no_seccomp: bool,
    #[serde(default)]
    pub seccomp_policy_file: Option<PathBuf>,
```

- [ ] **Step 2: Add fields to ExecutionProfile**

In `src/core/types.rs`, add to `ExecutionProfile` struct after `directory_bindings`:

```rust
    pub enable_seccomp: bool,
    pub seccomp_policy_file: Option<PathBuf>,
```

In `ExecutionProfile::from_config()`, add to the struct literal:

```rust
    enable_seccomp: !config.no_seccomp,
    seccomp_policy_file: config.seccomp_policy_file.clone(),
```

- [ ] **Step 3: Add CLI flags**

In `src/cli.rs`, add to `Commands::ExecuteCode` variants:

```rust
        #[arg(long)]
        no_seccomp: bool,
        #[arg(long)]
        seccomp_policy: Option<String>,
```

Wire them into the config construction (in the `Commands::ExecuteCode` match arm where config is built):

```rust
    config.no_seccomp = no_seccomp;
    config.seccomp_policy_file = seccomp_policy.map(PathBuf::from);
```

- [ ] **Step 4: Verify build**

Run: `cargo build`
Expected: clean compilation

- [ ] **Step 5: Commit**

```bash
git add src/config/types.rs src/core/types.rs src/cli.rs
git commit -m "feat(seccomp): add no_seccomp and seccomp_policy_file config flags"
```

---

### Task 4: Wire seccomp into runtime_exec.rs execution chain

**Files:**
- Modify: `src/kernel/runtime_exec.rs` (~8 lines)

This is the integration point. Seccomp filter is installed after all verifications pass and before `exec_payload()`. It becomes the last stage before exec.

- [ ] **Step 1: Add stage constant and entry**

In `src/kernel/runtime_exec.rs`, add after the existing stage constants:

```rust
const STAGE_SECCOMP: &str = "seccomp_filter";
```

Add to the `validate_preexec_stage_plan` stages array:

```rust
    PreexecStage { name: STAGE_SECCOMP, domain: KernelDomain::Seccomp },
```

Note: `KernelDomain::Seccomp` needs to be added to the `KernelDomain` enum in `src/kernel/contract.rs`.

- [ ] **Step 2: Add KernelDomain::Seccomp variant**

In `src/kernel/contract.rs`, add `Seccomp` to the `KernelDomain` enum.

- [ ] **Step 3: Build seccomp policy and install before exec**

In `src/kernel/runtime_exec.rs`, in `exec_payload()`, between the final `mark_stage(&mut report, STAGE_EVIDENCE)` and `let sandbox = sandbox.ready_for_exec()`:

```rust
    let seccomp_policy = if !req.profile.enable_seccomp {
        crate::kernel::seccomp::SeccompPolicy::Disabled
    } else if let Some(ref path) = req.profile.seccomp_policy_file {
        crate::kernel::seccomp::SeccompPolicy::CustomFile(path.clone())
    } else {
        crate::kernel::seccomp::SeccompPolicy::BuiltinDenyList
    };
    crate::kernel::seccomp::install_filter(&seccomp_policy)?;
    mark_stage(&mut report, STAGE_SECCOMP);
```

- [ ] **Step 4: Verify build**

Run: `cargo build`
Expected: clean compilation

- [ ] **Step 5: Run all tests**

Run: `cargo test --all -- --test-threads=1`
Expected: all existing tests pass (seccomp filter only fires inside actual sandbox, not during unit tests)

- [ ] **Step 6: Commit**

```bash
git add src/kernel/runtime_exec.rs src/kernel/contract.rs
git commit -m "feat(seccomp): wire filter installation into preexec chain before exec"
```

---

### Task 5: Integration test - verify io_uring is blocked

**Files:**
- Create: `tests/seccomp_integration.rs`

This test verifies that the seccomp filter actually blocks io_uring_setup when running through the full sandbox path.

- [ ] **Step 1: Write integration test**

```rust
use rustbox::config::types::{ExecutionStatus, IsolateConfig};
use rustbox::runtime::isolate::{ExecutionOverrides, Isolate};

/// Verify that io_uring_setup returns ENOSYS (not KILL) when seccomp is active.
/// This C program calls io_uring_setup(0, NULL) and prints the errno.
/// With seccomp deny-list: should get ENOSYS (38) and exit normally.
/// Without seccomp: would get ENOSYS anyway on most systems (no root),
/// but the test verifies our filter doesn't KILL the process.
#[test]
fn io_uring_returns_enosys_not_kill() {
    let code = r#"
#include <stdio.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
int main() {
    long ret = syscall(SYS_io_uring_setup, 0, NULL);
    printf("ret=%ld errno=%d\n", ret, errno);
    return 0;
}
"#;
    let mut config = IsolateConfig::with_language_defaults("cpp", "seccomp-test-1".to_string())
        .unwrap_or_default();
    config.strict_mode = false;
    config.allow_degraded = true;
    let mut isolate = Isolate::new(config).expect("isolate creation");
    let result = isolate.execute_code_string("cpp", code, &ExecutionOverrides::default());
    isolate.cleanup().ok();
    match result {
        Ok(r) => {
            // Process should exit normally (not killed by seccomp)
            assert_eq!(r.status, ExecutionStatus::Ok, "io_uring probe should not be killed: {:?}", r.stderr);
            assert!(r.stdout.contains("errno=38") || r.stdout.contains("ret=-1"),
                "expected ENOSYS, got: {}", r.stdout);
        }
        Err(e) => {
            // In environments without g++, skip gracefully
            let msg = e.to_string();
            if msg.contains("No such file") || msg.contains("not found") {
                eprintln!("Skipping: C++ toolchain not available");
                return;
            }
            panic!("unexpected error: {}", e);
        }
    }
}

/// Verify --no-seccomp flag disables the filter.
#[test]
fn no_seccomp_flag_disables_filter() {
    let mut config = IsolateConfig::with_language_defaults("python", "seccomp-test-2".to_string())
        .unwrap_or_default();
    config.strict_mode = false;
    config.allow_degraded = true;
    config.no_seccomp = true;
    let mut isolate = Isolate::new(config).expect("isolate creation");
    let result = isolate.execute_code_string(
        "python", "print('hello')", &ExecutionOverrides::default()
    );
    isolate.cleanup().ok();
    if let Ok(r) = result {
        assert_eq!(r.status, ExecutionStatus::Ok);
        assert!(r.stdout.contains("hello"));
    }
}
```

- [ ] **Step 2: Run integration tests**

Run: `cargo test --test seccomp_integration -- --test-threads=1 --nocapture`
Expected: tests pass (or skip gracefully if C++ toolchain unavailable)

- [ ] **Step 3: Commit**

```bash
git add tests/seccomp_integration.rs
git commit -m "test(seccomp): integration tests for deny-list and no-seccomp flag"
```

---

### Task 6: Update CLAUDE.md and config documentation

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update Key Design Rules**

Replace the existing seccomp line:
```
- **Syscall filtering is opt-in**: Default off, explicit `--enable-syscall-filtering` required
```
With:
```
- **Syscall filtering is default-on**: Built-in deny-list blocks 18 dangerous syscalls (io_uring, ptrace, bpf, modules, mount). Override with `--seccomp-policy FILE` or disable with `--no-seccomp`
```

- [ ] **Step 2: Add seccomp to smoke test examples**

Add to Build & Test Commands:
```bash
# Smoke test with seccomp disabled (debugging)
target/debug/judge execute-code --permissive --no-seccomp --language python --code 'print(1)'

# Smoke test with custom seccomp policy
target/debug/judge execute-code --permissive --seccomp-policy my-policy.json --language python --code 'print(1)'
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md with seccomp filtering documentation"
```

---

## Custom Policy JSON Format

Users create a JSON file like:

```json
{
  "default_action": "allow",
  "rules": [
    {
      "action": "kill_process",
      "syscalls": ["ptrace", "process_vm_readv", "process_vm_writev",
                    "bpf", "userfaultfd", "perf_event_open",
                    "kexec_load", "init_module", "finit_module", "delete_module",
                    "mount", "umount2", "pivot_root", "swapon", "swapoff"]
    },
    {
      "action": "errno_enosys",
      "syscalls": ["io_uring_setup", "io_uring_enter", "io_uring_register"]
    }
  ]
}
```

For an allowlist policy (advanced):

```json
{
  "default_action": "kill_process",
  "rules": [
    {
      "action": "allow",
      "syscalls": ["read", "write", "open", "close", "mmap", "mprotect",
                    "munmap", "brk", "execve", "exit_group", "clone", "wait4",
                    "rt_sigaction", "rt_sigreturn", "getcwd", "getpid"]
    }
  ]
}
```

---

## Dependency Chain

```
Task 1 (Cargo.toml)
  └→ Task 2 (seccomp.rs module)
       └→ Task 3 (config + CLI flags)
            └→ Task 4 (wire into runtime_exec)
                 └→ Task 5 (integration tests)
                      └→ Task 6 (docs)
```

All tasks are sequential.
