use crate::core::types::{ExecutionProfile, RunWorkspace};
use crate::judge::adapter::JudgeAdapter;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct CppAdapter;

fn profile(memory_mb: u64, process_limit: u32, cpu_ms: u64, wall_ms: u64) -> ExecutionProfile {
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
        enable_syscall_filtering: false,
        memory_limit: Some(memory_mb * 1024 * 1024),
        file_size_limit: Some(64 * 1024 * 1024),
        stack_limit: Some(8 * 1024 * 1024),
        core_limit: Some(0),
        process_limit: Some(process_limit),
        cpu_time_limit_ms: Some(cpu_ms),
        wall_time_limit_ms: Some(wall_ms),
        fd_limit: Some(128),
        directory_bindings: Vec::new(),
    }
}

impl JudgeAdapter for CppAdapter {
    fn language(&self) -> &'static str {
        "cpp"
    }

    fn compile_profile(&self) -> ExecutionProfile {
        // Compile needs more threads/processes than runtime envelope.
        profile(768, 160, 30_000, 45_000)
    }

    fn run_profile(&self) -> ExecutionProfile {
        profile(256, 1, 10_000, 15_000)
    }

    fn compile_command(&self, workspace: &RunWorkspace) -> Vec<String> {
        vec![
            "/usr/bin/g++".to_string(),
            "-std=c++17".to_string(),
            "-O2".to_string(),
            "-pipe".to_string(),
            "-o".to_string(),
            workspace.workdir.join("solution").to_string_lossy().to_string(),
            workspace
                .workdir
                .join("solution.cpp")
                .to_string_lossy()
                .to_string(),
        ]
    }

    fn run_command(&self, workspace: &RunWorkspace) -> Vec<String> {
        vec![workspace.workdir.join("solution").to_string_lossy().to_string()]
    }
}
