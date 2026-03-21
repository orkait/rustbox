use crate::core::types::{ExecutionProfile, RunWorkspace};
use crate::judge::adapter::JudgeAdapter;

#[derive(Debug, Clone, Default)]
pub struct CppAdapter;

impl JudgeAdapter for CppAdapter {
    fn language(&self) -> &'static str {
        "cpp"
    }

    fn compile_profile(&self) -> ExecutionProfile {
        ExecutionProfile {
            memory_limit: Some(768 * 1024 * 1024),
            process_limit: Some(160),
            cpu_time_limit_ms: Some(30_000),
            wall_time_limit_ms: Some(45_000),
            fd_limit: Some(128),
            ..super::base_profile()
        }
    }

    fn run_profile(&self) -> ExecutionProfile {
        ExecutionProfile {
            fd_limit: Some(128),
            ..super::base_profile()
        }
    }

    fn compile_command(&self, workspace: &RunWorkspace) -> Vec<String> {
        vec![
            "/usr/bin/g++".to_string(),
            "-std=c++17".to_string(),
            "-O2".to_string(),
            "-pipe".to_string(),
            "-o".to_string(),
            workspace.workdir.join("solution").to_string_lossy().to_string(),
            workspace.workdir.join("solution.cpp").to_string_lossy().to_string(),
        ]
    }

    fn run_command(&self, workspace: &RunWorkspace) -> Vec<String> {
        vec![workspace.workdir.join("solution").to_string_lossy().to_string()]
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
        assert!(cmd.contains(&"-std=c++17".to_string()));
        assert!(cmd.contains(&"-O2".to_string()));
        assert!(!cmd.contains(&"-static".to_string()));
    }

    #[test]
    fn compile_command_output_is_solution_binary() {
        let cmd = CppAdapter.compile_command(&workspace());
        let o_pos = cmd.iter().position(|s| s == "-o").expect("missing -o flag");
        assert!(cmd[o_pos + 1].ends_with("solution"));
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
