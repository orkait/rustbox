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
        allow_degraded: false,
        memory_limit: Some(memory_mb * 1024 * 1024),
        file_size_limit: Some(64 * 1024 * 1024),
        stack_limit: Some(8 * 1024 * 1024),
        core_limit: Some(0),
        process_limit: Some(process_limit),
        cpu_time_limit_ms: Some(cpu_ms),
        wall_time_limit_ms: Some(wall_ms),
        fd_limit: Some(128),
        virtual_memory_limit: Some(1024 * 1024 * 1024), // 1 GB
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
            workspace
                .workdir
                .join("solution")
                .to_string_lossy()
                .to_string(),
            workspace
                .workdir
                .join("solution.cpp")
                .to_string_lossy()
                .to_string(),
        ]
    }

    fn run_command(&self, workspace: &RunWorkspace) -> Vec<String> {
        vec![workspace
            .workdir
            .join("solution")
            .to_string_lossy()
            .to_string()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn workspace() -> RunWorkspace {
        RunWorkspace {
            root: PathBuf::from("/tmp/rustbox/box-1"),
            workdir: PathBuf::from("/tmp/rustbox/box-1"),
            temp_dir: PathBuf::from("/tmp/rustbox/box-1"),
        }
    }

    #[test]
    fn compile_command_uses_gpp_with_cpp17() {
        let cmd = CppAdapter.compile_command(&workspace());
        assert_eq!(cmd[0], "/usr/bin/g++");
        assert!(cmd.contains(&"-std=c++17".to_string()), "missing -std=c++17");
        assert!(cmd.contains(&"-O2".to_string()), "missing -O2");
        assert!(!cmd.contains(&"-static".to_string()), "-static must not be present (no static libc in image)");
    }

    #[test]
    fn compile_command_output_is_solution_binary() {
        let cmd = CppAdapter.compile_command(&workspace());
        let o_pos = cmd.iter().position(|s| s == "-o").expect("missing -o flag");
        assert!(cmd[o_pos + 1].ends_with("solution"), "output binary must be named 'solution'");
    }

    #[test]
    fn compile_command_source_is_solution_cpp() {
        let cmd = CppAdapter.compile_command(&workspace());
        assert!(cmd.last().unwrap().ends_with("solution.cpp"));
    }

    #[test]
    fn run_command_executes_compiled_binary() {
        let cmd = CppAdapter.run_command(&workspace());
        assert_eq!(cmd.len(), 1);
        assert!(cmd[0].ends_with("solution"));
    }

    #[test]
    fn run_profile_uid_gid_are_nobody() {
        let profile = CppAdapter.run_profile();
        assert_eq!(profile.uid, Some(65534));
        assert_eq!(profile.gid, Some(65534));
    }

    #[test]
    fn language_tag_is_cpp() {
        assert_eq!(CppAdapter.language(), "cpp");
    }
}
