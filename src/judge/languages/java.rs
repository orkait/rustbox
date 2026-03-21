use crate::core::types::{ExecutionProfile, RunWorkspace};
use crate::judge::adapter::JudgeAdapter;

#[derive(Debug, Clone, Default)]
pub struct JavaAdapter;

fn detect_class_name(workspace: &RunWorkspace) -> String {
    let source = workspace.workdir.join("Main.java");
    let Ok(content) = std::fs::read_to_string(&source) else {
        return "Main".to_string();
    };
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("public class ") {
            let name = rest
                .split_whitespace()
                .next()
                .unwrap_or("Main")
                .trim_end_matches('{')
                .trim();
            if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                return name.to_string();
            }
        }
    }
    "Main".to_string()
}

fn java_env() -> Vec<(String, String)> {
    vec![("JAVA_TOOL_OPTIONS".to_string(), "-Dfile.encoding=UTF-8".to_string())]
}

impl JudgeAdapter for JavaAdapter {
    fn language(&self) -> &'static str {
        "java"
    }

    fn compile_profile(&self) -> ExecutionProfile {
        ExecutionProfile {
            environment: java_env(),
            memory_limit: Some(768 * 1024 * 1024),
            process_limit: Some(320),
            cpu_time_limit_ms: Some(30_000),
            wall_time_limit_ms: Some(45_000),
            fd_limit: Some(256),
            virtual_memory_limit: Some(4 * 1024 * 1024 * 1024),
            ..super::base_profile()
        }
    }

    fn run_profile(&self) -> ExecutionProfile {
        ExecutionProfile {
            environment: java_env(),
            memory_limit: Some(512 * 1024 * 1024),
            process_limit: Some(256),
            wall_time_limit_ms: Some(20_000),
            fd_limit: Some(256),
            virtual_memory_limit: Some(4 * 1024 * 1024 * 1024),
            ..super::base_profile()
        }
    }

    fn compile_command(&self, workspace: &RunWorkspace) -> Vec<String> {
        vec![
            "/usr/bin/javac".to_string(),
            "-proc:none".to_string(),
            "-encoding".to_string(),
            "UTF-8".to_string(),
            workspace.workdir.join("Main.java").to_string_lossy().to_string(),
        ]
    }

    fn run_command(&self, workspace: &RunWorkspace) -> Vec<String> {
        let class_name = detect_class_name(workspace);
        vec![
            "/usr/bin/java".to_string(),
            "-Xmx256m".to_string(),
            "-Xss1m".to_string(),
            "-XX:+UseSerialGC".to_string(),
            "-cp".to_string(),
            workspace.workdir.to_string_lossy().to_string(),
            class_name,
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

    fn workspace_with_source(source: &str) -> (RunWorkspace, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Main.java"), source).unwrap();
        let path = dir.path().to_path_buf();
        let ws = RunWorkspace { root: path.clone(), workdir: path.clone(), temp_dir: path };
        (ws, dir)
    }

    #[test]
    fn compile_command_uses_javac_with_utf8() {
        let cmd = JavaAdapter.compile_command(&workspace());
        assert_eq!(cmd[0], "/usr/bin/javac");
        assert!(cmd.contains(&"-encoding".to_string()));
        assert!(cmd.contains(&"UTF-8".to_string()));
        assert!(cmd.last().unwrap().ends_with("Main.java"));
    }

    #[test]
    fn run_command_uses_java_with_heap_and_gc_flags() {
        let cmd = JavaAdapter.run_command(&workspace());
        assert_eq!(cmd[0], "/usr/bin/java");
        assert!(cmd.contains(&"-Xmx256m".to_string()));
        assert!(cmd.contains(&"-Xss1m".to_string()));
        assert!(cmd.contains(&"-XX:+UseSerialGC".to_string()));
    }

    #[test]
    fn run_command_sets_classpath_to_workdir() {
        let cmd = JavaAdapter.run_command(&workspace());
        let cp_pos = cmd.iter().position(|s| s == "-cp").expect("missing -cp");
        assert_eq!(cmd[cp_pos + 1], "/tmp/rustbox/box-1");
    }

    #[test]
    fn detect_class_name_extracts_public_class() {
        let (ws, _dir) = workspace_with_source("public class Solution {\n  public static void main(String[] args) {}\n}");
        let cmd = JavaAdapter.run_command(&ws);
        assert_eq!(cmd.last().unwrap(), "Solution");
    }

    #[test]
    fn detect_class_name_defaults_to_main_when_no_source() {
        let cmd = JavaAdapter.run_command(&workspace());
        assert_eq!(cmd.last().unwrap(), "Main");
    }

    #[test]
    fn detect_class_name_handles_brace_on_same_line() {
        let (ws, _dir) = workspace_with_source("public class Foo {");
        let cmd = JavaAdapter.run_command(&ws);
        assert_eq!(cmd.last().unwrap(), "Foo");
    }

    #[test]
    fn run_profile_uid_gid_are_nobody() {
        let profile = JavaAdapter.run_profile();
        assert_eq!(profile.uid, Some(65534));
        assert_eq!(profile.gid, Some(65534));
    }

    #[test]
    fn language_tag_is_java() {
        assert_eq!(JavaAdapter.language(), "java");
    }
}
