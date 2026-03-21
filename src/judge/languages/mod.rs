pub mod cpp;
pub mod java;
pub mod javascript;
pub mod python;

use crate::core::types::ExecutionProfile;
use std::path::PathBuf;

/// Shared sandbox base profile. Every language adapter starts from this
/// and overrides only the fields that differ (via struct update syntax).
pub(crate) fn base_profile() -> ExecutionProfile {
    ExecutionProfile {
        command: Vec::new(),
        stdin_data: None,
        environment: Vec::new(),
        inherit_fds: false,
        workdir: PathBuf::from("."),
        chroot_dir: None,
        uid: Some(65534),
        gid: Some(65534),
        strict_mode: true,
        enable_pid_namespace: true,
        enable_mount_namespace: true,
        enable_network_namespace: true,
        enable_user_namespace: false,
        allow_degraded: false,
        memory_limit: Some(256 * 1024 * 1024),
        file_size_limit: Some(64 * 1024 * 1024),
        stack_limit: Some(8 * 1024 * 1024),
        core_limit: Some(0),
        process_limit: Some(1),
        cpu_time_limit_ms: Some(10_000),
        wall_time_limit_ms: Some(15_000),
        fd_limit: Some(64),
        virtual_memory_limit: Some(1024 * 1024 * 1024),
        directory_bindings: Vec::new(),
    }
}
