use crate::core::types::{ExecutionProfile, RunWorkspace};

/// Judge adapter contract for language-specific compile/run stages.
pub trait JudgeAdapter: Send + Sync {
    fn language(&self) -> &'static str;
    fn compile_profile(&self) -> ExecutionProfile;
    fn run_profile(&self) -> ExecutionProfile;
    fn compile_command(&self, workspace: &RunWorkspace) -> Vec<String>;
    fn run_command(&self, workspace: &RunWorkspace) -> Vec<String>;
}
