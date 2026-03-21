use crate::core::types::{ExecutionProfile, RunWorkspace};
use crate::judge::adapter::JudgeAdapter;

#[derive(Debug, Clone, Default)]
pub struct PythonAdapter;

impl JudgeAdapter for PythonAdapter {
    fn language(&self) -> &'static str {
        "python"
    }

    fn compile_profile(&self) -> ExecutionProfile {
        self.run_profile()
    }

    fn run_profile(&self) -> ExecutionProfile {
        super::base_profile()
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
    fn compile_command_is_empty() {
        assert!(PythonAdapter.compile_command(&workspace()).is_empty());
    }

    #[test]
    fn run_command_invokes_python3_with_no_bytecode_and_no_site() {
        let cmd = PythonAdapter.run_command(&workspace());
        assert_eq!(cmd[0], "/usr/bin/python3");
        assert!(cmd.contains(&"-B".to_string()));
        assert!(cmd.contains(&"-S".to_string()));
        assert!(cmd.last().unwrap().ends_with("solution.py"));
    }

    #[test]
    fn run_profile_uid_gid_are_nobody() {
        let profile = PythonAdapter.run_profile();
        assert_eq!(profile.uid, Some(65534));
        assert_eq!(profile.gid, Some(65534));
    }

    #[test]
    fn language_tag_is_python() {
        assert_eq!(PythonAdapter.language(), "python");
    }
}
