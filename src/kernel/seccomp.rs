use crate::config::types::{IsolateError, Result};
use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompFilter};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Debug, Default)]
pub enum SeccompPolicy {
    Disabled,
    #[default]
    BuiltinDenyList,
    ExecutorDenyList,
    CustomFile(std::path::PathBuf),
}

const EXECUTOR_ALLOWED_SYSCALLS: &[&str] = &[
    "memfd_create",
    "mbind",
    "set_mempolicy",
    "move_pages",
    "personality",
];

struct SyscallRule {
    name: &'static str,
    num: i64,
    action: SeccompAction,
}

// nsjail-informed deny-list: block dangerous unprivileged syscall surface.
// io_uring gets ERRNO(ENOSYS) so runtimes that probe at startup fall back.
// Everything else gets KILL_PROCESS.
const BUILTIN_DENY_LIST: &[SyscallRule] = &[
    // io_uring: kernel LPE history (CVE-2021-41073, CVE-2023-2598)
    SyscallRule {
        name: "io_uring_setup",
        num: libc::SYS_io_uring_setup,
        action: SeccompAction::Errno(libc::ENOSYS as u32),
    },
    SyscallRule {
        name: "io_uring_enter",
        num: libc::SYS_io_uring_enter,
        action: SeccompAction::Errno(libc::ENOSYS as u32),
    },
    SyscallRule {
        name: "io_uring_register",
        num: libc::SYS_io_uring_register,
        action: SeccompAction::Errno(libc::ENOSYS as u32),
    },
    // Tracing: cross-process inspection
    SyscallRule {
        name: "ptrace",
        num: libc::SYS_ptrace,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "process_vm_readv",
        num: libc::SYS_process_vm_readv,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "process_vm_writev",
        num: libc::SYS_process_vm_writev,
        action: SeccompAction::KillProcess,
    },
    // Kernel subsystems
    SyscallRule {
        name: "bpf",
        num: libc::SYS_bpf,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "userfaultfd",
        num: libc::SYS_userfaultfd,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "perf_event_open",
        num: libc::SYS_perf_event_open,
        action: SeccompAction::KillProcess,
    },
    // Module/boot
    SyscallRule {
        name: "kexec_load",
        num: libc::SYS_kexec_load,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "init_module",
        num: libc::SYS_init_module,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "finit_module",
        num: libc::SYS_finit_module,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "delete_module",
        num: libc::SYS_delete_module,
        action: SeccompAction::KillProcess,
    },
    // Mount/swap
    SyscallRule {
        name: "mount",
        num: libc::SYS_mount,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "umount2",
        num: libc::SYS_umount2,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "pivot_root",
        num: libc::SYS_pivot_root,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "swapon",
        num: libc::SYS_swapon,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "swapoff",
        num: libc::SYS_swapoff,
        action: SeccompAction::KillProcess,
    },
    // Namespace/chroot escape: block nested user namespaces and chroot
    SyscallRule {
        name: "unshare",
        num: libc::SYS_unshare,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "chroot",
        num: libc::SYS_chroot,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "setns",
        num: libc::SYS_setns,
        action: SeccompAction::KillProcess,
    },
    // New mount API (Linux 5.2+/5.12+): block to prevent mount manipulation
    SyscallRule {
        name: "move_mount",
        num: libc::SYS_move_mount,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "open_tree",
        num: libc::SYS_open_tree,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "mount_setattr",
        num: libc::SYS_mount_setattr,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "fsopen",
        num: libc::SYS_fsopen,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "fsmount",
        num: libc::SYS_fsmount,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "fsconfig",
        num: libc::SYS_fsconfig,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "fspick",
        num: libc::SYS_fspick,
        action: SeccompAction::KillProcess,
    },
    // DAC bypass (CVE-2014-0038): file handle manipulation
    SyscallRule {
        name: "name_to_handle_at",
        num: libc::SYS_name_to_handle_at,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "open_by_handle_at",
        num: libc::SYS_open_by_handle_at,
        action: SeccompAction::KillProcess,
    },
    // Alternate kexec path
    SyscallRule {
        name: "kexec_file_load",
        num: libc::SYS_kexec_file_load,
        action: SeccompAction::KillProcess,
    },
    // System clock manipulation
    SyscallRule {
        name: "reboot",
        num: libc::SYS_reboot,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "settimeofday",
        num: libc::SYS_settimeofday,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "clock_settime",
        num: libc::SYS_clock_settime,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "acct",
        num: libc::SYS_acct,
        action: SeccompAction::KillProcess,
    },
    // Kernel keyring (CVE-2016-0728, not namespaced)
    SyscallRule {
        name: "add_key",
        num: libc::SYS_add_key,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "keyctl",
        num: libc::SYS_keyctl,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "request_key",
        num: libc::SYS_request_key,
        action: SeccompAction::KillProcess,
    },
    // Execution domain: personality(READ_IMPLIES_EXEC) marks all readable pages executable
    SyscallRule {
        name: "personality",
        num: libc::SYS_personality,
        action: SeccompAction::Errno(libc::EPERM as u32),
    },
    // NUMA: memory policy manipulation
    SyscallRule {
        name: "mbind",
        num: libc::SYS_mbind,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "set_mempolicy",
        num: libc::SYS_set_mempolicy,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "move_pages",
        num: libc::SYS_move_pages,
        action: SeccompAction::KillProcess,
    },
    // Newer syscalls (kernel 5.10+): cross-process, NUMA, mount info, LSM modification
    // In-memory binary execution
    SyscallRule {
        name: "memfd_create",
        num: libc::SYS_memfd_create,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "process_madvise",
        num: crate::config::constants::SYS_PROCESS_MADVISE,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "process_mrelease",
        num: crate::config::constants::SYS_PROCESS_MRELEASE,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "set_mempolicy_home_node",
        num: crate::config::constants::SYS_SET_MEMPOLICY_HOME_NODE,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "map_shadow_stack",
        num: crate::config::constants::SYS_MAP_SHADOW_STACK,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "statmount",
        num: crate::config::constants::SYS_STATMOUNT,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "listmount",
        num: crate::config::constants::SYS_LISTMOUNT,
        action: SeccompAction::KillProcess,
    },
    SyscallRule {
        name: "lsm_set_self_attr",
        num: crate::config::constants::SYS_LSM_SET_SELF_ATTR,
        action: SeccompAction::KillProcess,
    },
];

fn target_arch() -> Result<seccompiler::TargetArch> {
    std::env::consts::ARCH
        .try_into()
        .map_err(|_| IsolateError::Config("Unsupported architecture for seccomp".to_string()))
}

fn build_and_apply(
    rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>>,
    default: SeccompAction,
    on_match: SeccompAction,
) -> Result<()> {
    if rules.is_empty() {
        return Ok(());
    }
    let filter = SeccompFilter::new(rules, default, on_match, target_arch()?)
        .map_err(|e| IsolateError::Config(format!("seccomp filter build: {}", e)))?;
    let prog: BpfProgram = filter
        .try_into()
        .map_err(|e| IsolateError::Config(format!("seccomp compile: {}", e)))?;
    apply_filter(&prog).map_err(|e| IsolateError::Config(format!("seccomp apply: {}", e)))?;
    Ok(())
}

/// Install seccomp filter(s) on the calling thread.
/// Must be called after NO_NEW_PRIVS is set.
pub fn install_filter(policy: &SeccompPolicy) -> Result<()> {
    match policy {
        SeccompPolicy::Disabled => Ok(()),
        SeccompPolicy::BuiltinDenyList => install_builtin_deny_list(false),
        SeccompPolicy::ExecutorDenyList => install_builtin_deny_list(true),
        SeccompPolicy::CustomFile(path) => install_custom_policy(path),
    }
}

fn install_builtin_deny_list(executor_mode: bool) -> Result<()> {
    // Seccomp filters stack: kernel uses the most restrictive result.
    // We need multiple filters because SeccompFilter only supports one match_action.

    let is_allowed =
        |name: &str| -> bool { executor_mode && EXECUTOR_ALLOWED_SYSCALLS.contains(&name) };

    // Filter 1: io_uring → ERRNO(ENOSYS)
    let enosys_rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BUILTIN_DENY_LIST
        .iter()
        .filter(|r| matches!(r.action, SeccompAction::Errno(_)) && !is_allowed(r.name))
        .map(|r| (r.num, vec![]))
        .collect();
    build_and_apply(
        enosys_rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
    )?;

    // Filter 2: tracing/bpf/modules/mount → KILL_PROCESS
    let kill_rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BUILTIN_DENY_LIST
        .iter()
        .filter(|r| matches!(r.action, SeccompAction::KillProcess) && !is_allowed(r.name))
        .map(|r| (r.num, vec![]))
        .collect();
    build_and_apply(kill_rules, SeccompAction::Allow, SeccompAction::KillProcess)?;

    // Filter 3: clone with CLONE_NEWUSER → KILL_PROCESS
    // Blocks nested user namespace creation which expands kernel attack surface.
    // clone() itself must remain allowed (threads, fork), only the user-namespace flag is blocked.
    let clone_newuser_flag = libc::CLONE_NEWUSER as u64;
    let clone_rule = seccompiler::SeccompRule::new(vec![seccompiler::SeccompCondition::new(
        0,
        seccompiler::SeccompCmpArgLen::Qword,
        seccompiler::SeccompCmpOp::MaskedEq(clone_newuser_flag),
        clone_newuser_flag,
    )
    .map_err(|e| IsolateError::Config(format!("seccomp clone condition: {}", e)))?])
    .map_err(|e| IsolateError::Config(format!("seccomp clone rule: {}", e)))?;
    let mut clone_rules = BTreeMap::new();
    clone_rules.insert(libc::SYS_clone, vec![clone_rule]);
    build_and_apply(
        clone_rules,
        SeccompAction::Allow,
        SeccompAction::KillProcess,
    )?;

    Ok(())
}

fn install_custom_policy(path: &Path) -> Result<()> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        IsolateError::Config(format!("read seccomp policy {}: {}", path.display(), e))
    })?;
    let policy: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| IsolateError::Config(format!("parse seccomp policy: {}", e)))?;

    let default_action = match policy.get("default_action").and_then(|v| v.as_str()) {
        Some("allow") => SeccompAction::Allow,
        Some("kill") | Some("kill_process") => SeccompAction::KillProcess,
        Some("errno") => SeccompAction::Errno(libc::EPERM as u32),
        Some(other) => {
            return Err(IsolateError::Config(format!(
                "unknown default_action: {}",
                other
            )))
        }
        None => SeccompAction::Allow,
    };

    let rules = policy
        .get("rules")
        .and_then(|v| v.as_array())
        .ok_or_else(|| IsolateError::Config("seccomp policy missing 'rules' array".to_string()))?;

    let mut action_groups: std::collections::HashMap<String, Vec<i64>> =
        std::collections::HashMap::new();
    for rule in rules {
        let action_str = rule
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("kill_process");
        let syscalls = rule
            .get("syscalls")
            .and_then(|v| v.as_array())
            .ok_or_else(|| IsolateError::Config("rule missing 'syscalls' array".to_string()))?;
        for sc in syscalls {
            let name = sc
                .as_str()
                .ok_or_else(|| IsolateError::Config("syscall must be a string".to_string()))?;
            let num = syscall_name_to_number(name)
                .ok_or_else(|| IsolateError::Config(format!("unknown syscall: {}", name)))?;
            action_groups
                .entry(action_str.to_string())
                .or_default()
                .push(num);
        }
    }

    for (action_str, nums) in &action_groups {
        let match_action = match action_str.as_str() {
            "kill" | "kill_process" => SeccompAction::KillProcess,
            "errno" | "errno_enosys" => SeccompAction::Errno(libc::ENOSYS as u32),
            "errno_eperm" => SeccompAction::Errno(libc::EPERM as u32),
            "trap" => SeccompAction::Trap,
            "allow" => SeccompAction::Allow,
            other => return Err(IsolateError::Config(format!("unknown action: {}", other))),
        };
        let filter_rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> =
            nums.iter().map(|&n| (n, vec![])).collect();
        build_and_apply(filter_rules, default_action.clone(), match_action)?;
    }

    Ok(())
}

fn syscall_name_to_number(name: &str) -> Option<i64> {
    let num = match name {
        "io_uring_setup" => libc::SYS_io_uring_setup,
        "io_uring_enter" => libc::SYS_io_uring_enter,
        "io_uring_register" => libc::SYS_io_uring_register,
        "ptrace" => libc::SYS_ptrace,
        "process_vm_readv" => libc::SYS_process_vm_readv,
        "process_vm_writev" => libc::SYS_process_vm_writev,
        "bpf" => libc::SYS_bpf,
        "userfaultfd" => libc::SYS_userfaultfd,
        "perf_event_open" => libc::SYS_perf_event_open,
        "kexec_load" => libc::SYS_kexec_load,
        "init_module" => libc::SYS_init_module,
        "finit_module" => libc::SYS_finit_module,
        "delete_module" => libc::SYS_delete_module,
        "mount" => libc::SYS_mount,
        "umount2" => libc::SYS_umount2,
        "pivot_root" => libc::SYS_pivot_root,
        "swapon" => libc::SYS_swapon,
        "swapoff" => libc::SYS_swapoff,
        "reboot" => libc::SYS_reboot,
        "settimeofday" => libc::SYS_settimeofday,
        "clock_settime" => libc::SYS_clock_settime,
        "acct" => libc::SYS_acct,
        "add_key" => libc::SYS_add_key,
        "keyctl" => libc::SYS_keyctl,
        "request_key" => libc::SYS_request_key,
        "mbind" => libc::SYS_mbind,
        "set_mempolicy" => libc::SYS_set_mempolicy,
        "move_pages" => libc::SYS_move_pages,
        "personality" => libc::SYS_personality,
        "unshare" => libc::SYS_unshare,
        "chroot" => libc::SYS_chroot,
        "setns" => libc::SYS_setns,
        "move_mount" => libc::SYS_move_mount,
        "open_tree" => libc::SYS_open_tree,
        "mount_setattr" => libc::SYS_mount_setattr,
        "fsopen" => libc::SYS_fsopen,
        "fsmount" => libc::SYS_fsmount,
        "fsconfig" => libc::SYS_fsconfig,
        "fspick" => libc::SYS_fspick,
        "name_to_handle_at" => libc::SYS_name_to_handle_at,
        "open_by_handle_at" => libc::SYS_open_by_handle_at,
        "kexec_file_load" => libc::SYS_kexec_file_load,
        "read" => libc::SYS_read,
        "write" => libc::SYS_write,
        "open" => libc::SYS_open,
        "close" => libc::SYS_close,
        "mmap" => libc::SYS_mmap,
        "mprotect" => libc::SYS_mprotect,
        "munmap" => libc::SYS_munmap,
        "brk" => libc::SYS_brk,
        "execve" => libc::SYS_execve,
        "exit_group" => libc::SYS_exit_group,
        "clone" => libc::SYS_clone,
        "wait4" => libc::SYS_wait4,
        "rt_sigaction" => libc::SYS_rt_sigaction,
        "rt_sigreturn" => libc::SYS_rt_sigreturn,
        "getcwd" => libc::SYS_getcwd,
        "getpid" => libc::SYS_getpid,
        "memfd_create" => libc::SYS_memfd_create,
        "process_madvise" => crate::config::constants::SYS_PROCESS_MADVISE,
        "process_mrelease" => crate::config::constants::SYS_PROCESS_MRELEASE,
        "set_mempolicy_home_node" => crate::config::constants::SYS_SET_MEMPOLICY_HOME_NODE,
        "map_shadow_stack" => crate::config::constants::SYS_MAP_SHADOW_STACK,
        "statmount" => crate::config::constants::SYS_STATMOUNT,
        "listmount" => crate::config::constants::SYS_LISTMOUNT,
        "lsm_set_self_attr" => crate::config::constants::SYS_LSM_SET_SELF_ATTR,
        _ => return None,
    };
    Some(num)
}

#[must_use]
pub fn builtin_deny_list_names() -> Vec<&'static str> {
    BUILTIN_DENY_LIST.iter().map(|r| r.name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_deny_list_has_expected_count() {
        assert_eq!(BUILTIN_DENY_LIST.len(), 50);
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
        assert!(matches!(
            SeccompPolicy::default(),
            SeccompPolicy::BuiltinDenyList
        ));
    }

    #[test]
    fn custom_policy_rejects_missing_file() {
        let result = install_filter(&SeccompPolicy::CustomFile("/nonexistent.json".into()));
        assert!(result.is_err());
    }
}
