use crate::config::constants;
use crate::config::types::{ExecutionResult, ExecutionStatus, IsolateConfig, IsolateError, Result};
use std::fs;
use std::time::Duration;

use super::isolate::{ExecutionOverrides, Isolate};

impl Isolate {
    fn load_language_config(language: &str) -> Option<crate::config::loader::LanguageConfig> {
        crate::config::loader::RustBoxConfig::load_default()
            .ok()
            .and_then(|cfg| cfg.languages.get(&language.to_lowercase()).cloned())
    }

    pub fn execute_code_string(
        &mut self,
        language: &str,
        code: &str,
        overrides: &ExecutionOverrides,
    ) -> Result<ExecutionResult> {
        let lang_key = match language.to_lowercase().as_str() {
            "py" => "python".to_string(),
            "c++" | "cxx" => "cpp".to_string(),
            "js" => "javascript".to_string(),
            "ts" => "typescript".to_string(),
            "rs" => "rust".to_string(),
            other => other.to_string(),
        };

        let lang_cfg = Self::load_language_config(&lang_key)
            .ok_or_else(|| IsolateError::Config(format!("Unsupported language: {}", language)))?;

        if let Some(ref comp) = lang_cfg.compilation {
            self.compile_and_execute(code, &lang_key, &lang_cfg, comp, overrides)
        } else {
            self.execute_interpreted(code, &lang_cfg, overrides)
        }
    }

    fn execute_interpreted(
        &mut self,
        code: &str,
        lang_cfg: &crate::config::loader::LanguageConfig,
        overrides: &ExecutionOverrides,
    ) -> Result<ExecutionResult> {
        if !self.wipe_workdir() {
            return Err(IsolateError::Filesystem(
                "workdir not clean before execution; refusing to run with leftover files".into(),
            ));
        }

        let source_file_name = lang_cfg.runtime.source_file.as_deref().ok_or_else(|| {
            IsolateError::Config("interpreted language must have runtime.source_file".into())
        })?;
        let source_file = self.config().workdir.join(source_file_name);

        let mut command: Vec<String> = lang_cfg.runtime.command.clone();
        command.push(source_file.to_string_lossy().to_string());

        write_source_no_follow(&source_file, code)?;
        let result = self.execute_with_overrides(&command, overrides);
        let _ = fs::remove_file(&source_file);
        result
    }

    fn compile_and_execute(
        &mut self,
        code: &str,
        lang_key: &str,
        lang_cfg: &crate::config::loader::LanguageConfig,
        comp: &crate::config::loader::CompilationConfig,
        overrides: &ExecutionOverrides,
    ) -> Result<ExecutionResult> {
        if !self.wipe_workdir() {
            return Err(IsolateError::Filesystem(
                "workdir not clean before execution; refusing to run with leftover files".into(),
            ));
        }

        let class_name = if lang_key == "java" {
            extract_java_class_name(code).unwrap_or_else(|| "Main".to_string())
        } else {
            "Main".to_string()
        };

        let source_name = comp
            .source_file
            .replace("{class}", &class_name)
            .replace("{source}", "solution");
        let source_file = self.config().workdir.join(&source_name);
        write_source_no_follow(&source_file, code)?;

        let compile_cmd: Vec<String> = comp
            .command
            .iter()
            .map(|arg| {
                arg.replace("{source}", &source_name)
                    .replace("{class}", &class_name)
            })
            .collect();

        let run_cmd: Vec<String> = lang_cfg
            .runtime
            .command
            .iter()
            .map(|arg| arg.replace("{class}", &class_name))
            .collect();

        let saved = self.config().clone();
        apply_compile_limits(self.config_mut(), &saved, comp, overrides);
        self.update_cgroup_limits();

        let compile_result = match self.execute(&compile_cmd, None) {
            Ok(r) => r,
            Err(e) => {
                *self.config_mut() = saved;
                self.update_cgroup_limits();
                self.wipe_workdir();
                return Err(e);
            }
        };

        if !compile_result.success {
            *self.config_mut() = saved;
            self.update_cgroup_limits();
            self.wipe_workdir();
            let prefix = format!("{} Compilation Error", lang_key);
            return Ok(build_compile_failure_result(
                compile_result,
                &prefix,
                "compilation failed",
            ));
        }

        let _ = fs::remove_file(&source_file);
        *self.config_mut() = saved;
        self.update_cgroup_limits();
        let result = self.execute_with_overrides(&run_cmd, overrides);
        self.wipe_workdir();
        result
    }
}

fn apply_compile_limits(
    config: &mut IsolateConfig,
    original: &IsolateConfig,
    comp: &crate::config::loader::CompilationConfig,
    overrides: &ExecutionOverrides,
) {
    let limits = comp.limits.as_ref();

    use crate::config::loader::{
        default_compile_cpu_time_sec, default_compile_max_processes, default_compile_memory_mb,
        default_compile_wall_time_sec,
    };
    let mem_mb = limits
        .map(|l| l.memory_mb)
        .unwrap_or_else(default_compile_memory_mb);
    config.memory_limit = Some(
        overrides
            .max_memory
            .map(|mb| mb * constants::MB)
            .unwrap_or(mem_mb * constants::MB),
    );
    config.process_limit = Some(
        limits
            .map(|l| l.max_processes)
            .unwrap_or_else(default_compile_max_processes),
    );

    let cpu = limits
        .map(|l| l.cpu_time_sec)
        .unwrap_or_else(default_compile_cpu_time_sec);
    let wall = limits
        .map(|l| l.wall_time_sec)
        .unwrap_or_else(default_compile_wall_time_sec);
    let orig_cpu = original.cpu_time_limit.map(|d| d.as_secs()).unwrap_or(8);
    let orig_wall = original.wall_time_limit.map(|d| d.as_secs()).unwrap_or(10);
    let final_cpu = overrides
        .max_cpu
        .or(overrides.max_time)
        .unwrap_or(orig_cpu)
        .max(cpu);
    let final_wall = overrides.max_wall_time.unwrap_or(orig_wall).max(wall);
    config.cpu_time_limit = Some(Duration::from_secs(final_cpu));
    config.wall_time_limit = Some(Duration::from_secs(final_wall));

    if let Some(fd) = limits.and_then(|l| l.fd_limit) {
        config.fd_limit = Some(fd);
    }
    if let Some(fs_mb) = limits.and_then(|l| l.file_size_mb) {
        config.file_size_limit = Some(fs_mb * constants::MB);
    }
}

fn build_compile_failure_result(r: ExecutionResult, prefix: &str, msg: &str) -> ExecutionResult {
    let status = match r.status {
        ExecutionStatus::TimeLimit => ExecutionStatus::TimeLimit,
        ExecutionStatus::MemoryLimit => ExecutionStatus::MemoryLimit,
        _ => ExecutionStatus::RuntimeError,
    };
    let detail = if !r.stderr.trim().is_empty() {
        r.stderr.clone()
    } else if !r.stdout.trim().is_empty() {
        r.stdout.clone()
    } else {
        r.error_message
            .clone()
            .unwrap_or_else(|| "no compiler output".to_string())
    };

    ExecutionResult {
        status,
        exit_code: r.exit_code,
        stdout: String::new(),
        stderr: format!("{}:\n{}", prefix, detail),
        output_integrity: r.output_integrity,
        wall_time: r.wall_time,
        cpu_time: r.cpu_time,
        memory_peak: r.memory_peak,
        success: false,
        signal: None,
        error_message: Some(msg.to_string()),
    }
}

fn write_source_no_follow(path: &std::path::Path, code: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if path.is_symlink() {
        return Err(IsolateError::Filesystem(format!(
            "symlink at source path rejected: {}",
            path.display()
        )));
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(crate::config::constants::PERM_FILE_SOURCE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            IsolateError::Filesystem(format!(
                "failed to create source file {}: {}",
                path.display(),
                e
            ))
        })?;
    use std::io::Write;
    file.write_all(code.as_bytes())?;
    Ok(())
}

fn extract_java_class_name(code: &str) -> Option<String> {
    for line in code.lines() {
        if let Some(rest) = line.trim().strip_prefix("public class ") {
            let name = rest.split_whitespace().next()?.trim_end_matches('{').trim();
            if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                return Some(name.to_string());
            }
        }
    }
    None
}
