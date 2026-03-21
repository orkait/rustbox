use crate::core::types::{ExecutionProfile, RunWorkspace};
use crate::judge::adapter::JudgeAdapter;

#[derive(Debug, Clone, Default)]
pub struct JavaScriptAdapter;

#[derive(Debug, Clone, Default)]
pub struct TypeScriptAdapter;

impl JudgeAdapter for JavaScriptAdapter {
    fn language(&self) -> &'static str {
        "javascript"
    }

    fn compile_profile(&self) -> ExecutionProfile {
        self.run_profile()
    }

    fn run_profile(&self) -> ExecutionProfile {
        ExecutionProfile {
            memory_limit: Some(256 * 1024 * 1024),
            process_limit: Some(4),
            fd_limit: Some(64),
            virtual_memory_limit: Some(512 * 1024 * 1024),
            ..super::base_profile()
        }
    }

    fn compile_command(&self, _workspace: &RunWorkspace) -> Vec<String> {
        Vec::new()
    }

    fn run_command(&self, workspace: &RunWorkspace) -> Vec<String> {
        vec![
            "/usr/local/bin/qjs".to_string(),
            "--std".to_string(),
            workspace.workdir.join("solution.js").to_string_lossy().to_string(),
        ]
    }
}

impl JudgeAdapter for TypeScriptAdapter {
    fn language(&self) -> &'static str {
        "typescript"
    }

    fn compile_profile(&self) -> ExecutionProfile {
        self.run_profile()
    }

    fn run_profile(&self) -> ExecutionProfile {
        ExecutionProfile {
            memory_limit: Some(512 * 1024 * 1024),
            process_limit: Some(16),
            fd_limit: Some(128),
            virtual_memory_limit: Some(2 * 1024 * 1024 * 1024),
            ..super::base_profile()
        }
    }

    fn compile_command(&self, _workspace: &RunWorkspace) -> Vec<String> {
        Vec::new()
    }

    fn run_command(&self, workspace: &RunWorkspace) -> Vec<String> {
        vec![
            "/usr/local/bin/bun".to_string(),
            "run".to_string(),
            workspace.workdir.join("solution.ts").to_string_lossy().to_string(),
        ]
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
    fn js_compile_command_is_empty() {
        assert!(JavaScriptAdapter.compile_command(&workspace()).is_empty());
    }

    #[test]
    fn ts_compile_command_is_empty() {
        assert!(TypeScriptAdapter.compile_command(&workspace()).is_empty());
    }

    #[test]
    fn js_run_command_uses_qjs_with_std_on_solution_js() {
        let cmd = JavaScriptAdapter.run_command(&workspace());
        assert_eq!(cmd[0], "/usr/local/bin/qjs");
        assert!(cmd.contains(&"--std".to_string()));
        assert!(cmd.last().unwrap().ends_with("solution.js"));
    }

    #[test]
    fn ts_run_command_uses_bun_on_solution_ts() {
        let cmd = TypeScriptAdapter.run_command(&workspace());
        assert_eq!(cmd[0], "/usr/local/bin/bun");
        assert_eq!(cmd[1], "run");
        assert!(cmd.last().unwrap().ends_with("solution.ts"));
    }

    #[test]
    fn js_language_tag() {
        assert_eq!(JavaScriptAdapter.language(), "javascript");
    }

    #[test]
    fn ts_language_tag() {
        assert_eq!(TypeScriptAdapter.language(), "typescript");
    }

    #[test]
    fn run_profile_uid_gid_are_nobody() {
        assert_eq!(JavaScriptAdapter.run_profile().uid, Some(65534));
        assert_eq!(TypeScriptAdapter.run_profile().uid, Some(65534));
    }
}
