use crate::core::types::{ExecutionProfile, RunWorkspace};
use crate::judge::adapter::JudgeAdapter;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct JavaAdapter;

fn profile(memory_mb: u64, process_limit: u32, cpu_ms: u64, wall_ms: u64) -> ExecutionProfile {
    ExecutionProfile {
        command: Vec::new(),
        stdin_data: None,
        environment: vec![("JAVA_TOOL_OPTIONS".to_string(), "-Dfile.encoding=UTF-8".to_string())],
        workdir: PathBuf::from("."),
        uid: Some(65534),
        gid: Some(65534),
        strict_mode: true,
        enable_pid_namespace: true,
        enable_mount_namespace: true,
        enable_network_namespace: true,
        enable_user_namespace: false,
        enable_syscall_filtering: false,
        memory_limit: Some(memory_mb * 1024 * 1024),
        process_limit: Some(process_limit),
        cpu_time_limit_ms: Some(cpu_ms),
        wall_time_limit_ms: Some(wall_ms),
        fd_limit: Some(256),
    }
}

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
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    "Main".to_string()
}

impl JudgeAdapter for JavaAdapter {
    fn language(&self) -> &'static str {
        "java"
    }

    fn compile_profile(&self) -> ExecutionProfile {
        profile(768, 320, 30_000, 45_000)
    }

    fn run_profile(&self) -> ExecutionProfile {
        profile(512, 256, 10_000, 20_000)
    }

    fn compile_command(&self, workspace: &RunWorkspace) -> Vec<String> {
        vec![
            "/usr/bin/javac".to_string(),
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

