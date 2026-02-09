use crate::core::types::{ExecutionProfile, RunWorkspace};
use crate::judge::adapter::JudgeAdapter;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct PythonAdapter;

fn base_profile() -> ExecutionProfile {
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
        directory_bindings: Vec::new(),
    }
}

impl JudgeAdapter for PythonAdapter {
    fn language(&self) -> &'static str {
        "python"
    }

    fn compile_profile(&self) -> ExecutionProfile {
        // Python has no compile stage; returning run envelope keeps interface uniform.
        self.run_profile()
    }

    fn run_profile(&self) -> ExecutionProfile {
        base_profile()
    }

    fn compile_command(&self, _workspace: &RunWorkspace) -> Vec<String> {
        Vec::new()
    }

    fn run_command(&self, workspace: &RunWorkspace) -> Vec<String> {
        vec![
            "/usr/bin/python3".to_string(),
            "-B".to_string(),
            "-S".to_string(),
            workspace
                .workdir
                .join("solution.py")
                .to_string_lossy()
                .to_string(),
        ]
    }
}
