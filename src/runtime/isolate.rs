use crate::config::types::{ExecutionResult, IsolateConfig, IsolateError, Result};
use crate::config::validator::validate_config;
use crate::kernel::cgroup::{self, CgroupBackend};
use crate::observability::audit::events;
use crate::runtime::security::command_validation;
use crate::safety::cleanup::BaselineChecker;
use crate::safety::uid_pool;
use crate::sandbox::types::{LaunchEvidence, SandboxLaunchRequest};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug, Default)]
pub struct ExecutionOverrides {
    pub stdin_data: Option<String>,
    pub max_cpu: Option<u64>,
    pub max_memory: Option<u64>,
    pub max_time: Option<u64>,
    pub max_wall_time: Option<u64>,
    pub fd_limit: Option<u64>,
    pub process_limit: Option<u32>,
}

pub(crate) fn apply_overrides_to_config(
    base: &IsolateConfig,
    overrides: &ExecutionOverrides,
) -> IsolateConfig {
    let mut config = base.clone();
    if let Some(v) = overrides.max_cpu {
        config.cpu_time_limit = Some(Duration::from_secs(v));
        config.time_limit = Some(Duration::from_secs(v));
    }
    if let Some(v) = overrides.max_memory {
        config.memory_limit = Some(v * 1024 * 1024);
    }
    if let Some(v) = overrides.max_time {
        config.cpu_time_limit = Some(Duration::from_secs(v));
    }
    if let Some(v) = overrides.max_wall_time {
        config.wall_time_limit = Some(Duration::from_secs(v));
    }
    if let Some(v) = overrides.fd_limit {
        config.fd_limit = Some(v);
    }
    if let Some(v) = overrides.process_limit {
        config.process_limit = Some(v);
    }
    config
}

pub struct Isolate {
    config: IsolateConfig,
    base_path: PathBuf,
    cgroup: Option<Box<dyn CgroupBackend>>,
    baseline: Option<BaselineChecker>,
    last_launch_evidence: Option<LaunchEvidence>,
    _uid_guard: Option<uid_pool::UidGuard>,
}

impl Isolate {
    fn select_state_root() -> Result<PathBuf> {
        let candidates = vec![
            IsolateConfig::runtime_root_dir(),
            std::env::temp_dir().join("rustbox"),
        ];
        for candidate in &candidates {
            if fs::create_dir_all(candidate).is_ok() {
                return Ok(candidate.clone());
            }
        }
        Err(IsolateError::Config(
            "No writable state root available".to_string(),
        ))
    }

    fn ensure_workdir(&mut self) -> Result<()> {
        let workdir = self.base_path.join("workdir");
        fs::create_dir_all(&workdir)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&workdir, fs::Permissions::from_mode(0o755))?;
            if unsafe { libc::geteuid() } == 0 {
                if let (Some(uid), Some(gid)) = (self.config.uid, self.config.gid) {
                    use nix::unistd::{chown, Gid, Uid};
                    chown(&workdir, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
                        .map_err(|e| IsolateError::Config(format!("chown workdir: {}", e)))?;
                }
            }
        }

        self.config.workdir = workdir;
        Ok(())
    }

    /// Allocate all resources. Nothing else allocates after this.
    /// On failure, cleans up any partially-created state (directory, cgroup).
    pub fn new(mut config: IsolateConfig) -> Result<Self> {
        let uid_guard = uid_pool::UidGuard::allocate()?;
        let pool_uid = uid_guard.uid();
        config.uid = Some(pool_uid);
        config.gid = Some(pool_uid);
        config.instance_id = format!("rustbox/{}", pool_uid);

        if config.strict_mode && unsafe { libc::geteuid() } != 0 {
            return Err(IsolateError::Privilege(
                "Strict mode requires root".to_string(),
            ));
        }

        let validation = validate_config(&config)?;
        for warning in validation.warnings {
            log::warn!("Config: {}", warning);
        }

        let mut base_path = Self::select_state_root()?;
        base_path.push(pool_uid.to_string());
        fs::create_dir_all(&base_path)?;

        let cgroup = match cgroup::select_cgroup_backend(
            config.strict_mode,
            &config.instance_id,
        ) {
            Ok(cg) => match cg.create(&config.instance_id) {
                Ok(()) => {
                    if let Some(mem) = config.memory_limit {
                        if let Err(e) = cg.set_memory_limit(&config.instance_id, mem) {
                            let _ = cg.remove(&config.instance_id);
                            let _ = crate::safety::safe_cleanup::remove_tree_secure(&base_path);
                            return Err(e);
                        }
                    }
                    if let Some(procs) = config.process_limit {
                        if let Err(e) = cg.set_process_limit(&config.instance_id, procs) {
                            let _ = cg.remove(&config.instance_id);
                            let _ = crate::safety::safe_cleanup::remove_tree_secure(&base_path);
                            return Err(e);
                        }
                    }
                    Some(cg)
                }
                Err(e) if config.strict_mode => {
                    let _ = crate::safety::safe_cleanup::remove_tree_secure(&base_path);
                    return Err(e);
                }
                Err(_) => None,
            },
            Err(e) if config.strict_mode => {
                let _ = crate::safety::safe_cleanup::remove_tree_secure(&base_path);
                return Err(e);
            }
            Err(_) => None,
        };

        let baseline = BaselineChecker::capture_baseline().ok();

        Ok(Self {
            config,
            base_path,
            cgroup,
            baseline,
            last_launch_evidence: None,
            _uid_guard: Some(uid_guard),
        })
    }

    pub fn execute(
        &mut self,
        command: &[String],
        stdin_data: Option<&str>,
    ) -> Result<ExecutionResult> {
        self.execute_with_overrides(
            command,
            &ExecutionOverrides {
                stdin_data: stdin_data.map(str::to_string),
                ..Default::default()
            },
        )
    }

    /// Pure execution. No allocation, no deallocation.
    pub fn execute_with_overrides(
        &mut self,
        command: &[String],
        overrides: &ExecutionOverrides,
    ) -> Result<ExecutionResult> {
        self.ensure_workdir()?;

        let config = apply_overrides_to_config(&self.config, overrides);

        if command.is_empty() {
            return Err(IsolateError::Config("Empty command".to_string()));
        }

        let validated = match command_validation::validate_and_resolve_command(&command[0]) {
            Ok(path) => path,
            Err(e) => {
                events::command_injection_attempt(&command[0], None);
                return Err(e);
            }
        };
        let mut argv = vec![validated.to_string_lossy().to_string()];
        argv.extend(command.iter().skip(1).cloned());

        if self.cgroup.is_none() && config.strict_mode {
            return Err(IsolateError::Cgroup(
                "No cgroup backend for strict mode".to_string(),
            ));
        }

        let request = SandboxLaunchRequest::from_config(
            &config,
            &argv,
            overrides.stdin_data.as_deref(),
            self.cgroup
                .as_ref()
                .map(|cg| cg.get_cgroup_path(&config.instance_id)),
        );

        let outcome =
            crate::sandbox::supervisor::launch_with_supervisor(request, self.cgroup.as_deref())?;

        self.last_launch_evidence = Some(outcome.evidence);
        Ok(outcome.result)
    }

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
            self.compile_and_execute_from_config(code, &lang_key, &lang_cfg, comp, overrides)
        } else {
            self.execute_interpreted_from_config(code, &lang_cfg, overrides)
        }
    }

    fn execute_interpreted_from_config(
        &mut self,
        code: &str,
        lang_cfg: &crate::config::loader::LanguageConfig,
        overrides: &ExecutionOverrides,
    ) -> Result<ExecutionResult> {
        self.ensure_workdir()?;
        self.wipe_workdir();

        let source_file_name = lang_cfg.runtime.source_file.as_deref().ok_or_else(|| {
            IsolateError::Config("interpreted language must have runtime.source_file".into())
        })?;
        let source_file = self.config.workdir.join(source_file_name);

        let mut command: Vec<String> = lang_cfg.runtime.command.clone();
        command.push(source_file.to_string_lossy().to_string());

        write_source_no_follow(&source_file, code)?;
        let result = self.execute_with_overrides(&command, overrides);
        let _ = fs::remove_file(&source_file);
        result
    }

    fn compile_and_execute_from_config(
        &mut self,
        code: &str,
        lang_key: &str,
        lang_cfg: &crate::config::loader::LanguageConfig,
        comp: &crate::config::loader::CompilationConfig,
        overrides: &ExecutionOverrides,
    ) -> Result<ExecutionResult> {
        self.ensure_workdir()?;
        self.wipe_workdir();

        let class_name = if lang_key == "java" {
            extract_java_class_name(code).unwrap_or_else(|| "Main".to_string())
        } else {
            "Main".to_string()
        };

        let source_name = comp
            .source_file
            .replace("{class}", &class_name)
            .replace("{source}", "solution");
        let source_file = self.config.workdir.join(&source_name);
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

        let saved = self.config.clone();
        Self::apply_compile_limits(&mut self.config, &saved, comp, overrides);
        self.update_cgroup_limits();

        let compile_result = match self.execute(&compile_cmd, None) {
            Ok(r) => r,
            Err(e) => {
                self.config = saved;
                self.update_cgroup_limits();
                self.wipe_workdir();
                return Err(e);
            }
        };

        if !compile_result.success {
            self.config = saved;
            self.update_cgroup_limits();
            self.wipe_workdir();
            let prefix = format!("{} Compilation Error", lang_key);
            return Ok(Self::build_compile_failure_result(
                compile_result,
                &prefix,
                "compilation failed",
            ));
        }

        let _ = fs::remove_file(&source_file);
        self.config = saved;
        self.update_cgroup_limits();
        let result = self.execute_with_overrides(&run_cmd, overrides);
        self.wipe_workdir();
        result
    }

    fn apply_compile_limits(
        config: &mut IsolateConfig,
        original: &IsolateConfig,
        comp: &crate::config::loader::CompilationConfig,
        overrides: &ExecutionOverrides,
    ) {
        let limits = comp.limits.as_ref();
        let is_root = unsafe { libc::geteuid() } == 0;
        if !is_root {
            config.strict_mode = false;
            config.allow_degraded = true;
        }

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
                .map(|mb| mb * 1024 * 1024)
                .unwrap_or(mem_mb * 1024 * 1024),
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
        config.time_limit = Some(Duration::from_secs(final_cpu));
        config.wall_time_limit = Some(Duration::from_secs(final_wall));

        if let Some(fd) = limits.and_then(|l| l.fd_limit) {
            config.fd_limit = Some(fd);
        }
        if let Some(fs_mb) = limits.and_then(|l| l.file_size_mb) {
            config.file_size_limit = Some(fs_mb * 1024 * 1024);
        }
    }

    fn build_compile_failure_result(
        r: ExecutionResult,
        prefix: &str,
        msg: &str,
    ) -> ExecutionResult {
        let status = match r.status {
            crate::config::types::ExecutionStatus::TimeLimit => {
                crate::config::types::ExecutionStatus::TimeLimit
            }
            crate::config::types::ExecutionStatus::MemoryLimit => {
                crate::config::types::ExecutionStatus::MemoryLimit
            }
            _ => crate::config::types::ExecutionStatus::RuntimeError,
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

    fn wipe_workdir(&self) {
        let workdir = &self.config.workdir;
        if workdir.as_os_str().is_empty() || !workdir.exists() {
            return;
        }
        if let Ok(entries) = fs::read_dir(workdir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() && !path.is_symlink() {
                    let _ = crate::safety::safe_cleanup::remove_tree_secure(&path);
                } else {
                    let _ = fs::remove_file(&path);
                }
            }
        }
    }

    /// Deallocate everything. Only place that frees resources.
    pub fn cleanup(mut self) -> Result<()> {
        let mut evidence = self.last_launch_evidence.take();

        if let Some(checker) = self.baseline.take() {
            if let Some(ref mut ev) = evidence {
                if checker.verify_baseline().is_err() {
                    ev.cleanup_verified = false;
                    ev.process_lifecycle.descendant_containment =
                        "baseline_verification_failed".to_string();
                }
            }
        }

        if let Some(cg) = self.cgroup.take() {
            let _ = cg.remove(&self.config.instance_id);
        }
        if self.base_path.exists() {
            let _ = crate::safety::safe_cleanup::remove_tree_secure(&self.base_path);
        }
        drop(self._uid_guard.take());
        Ok(())
    }

    fn update_cgroup_limits(&self) {
        if let Some(ref cg) = self.cgroup {
            if let Some(mem) = self.config.memory_limit {
                let _ = cg.set_memory_limit(&self.config.instance_id, mem);
            }
            if let Some(procs) = self.config.process_limit {
                let _ = cg.set_process_limit(&self.config.instance_id, procs);
            }
        }
    }

    pub fn config(&self) -> &IsolateConfig {
        &self.config
    }
    pub fn config_mut(&mut self) -> &mut IsolateConfig {
        &mut self.config
    }
    pub fn take_last_launch_evidence(&mut self) -> Option<LaunchEvidence> {
        self.last_launch_evidence.take()
    }

    pub fn add_directory_bindings(
        &mut self,
        bindings: Vec<crate::config::types::DirectoryBinding>,
    ) -> Result<()> {
        for binding in &bindings {
            if !binding.maybe && !binding.source.exists() {
                return Err(IsolateError::Config(format!(
                    "Source directory does not exist: {}",
                    binding.source.display()
                )));
            }
            if binding.source.exists() && !binding.source.is_dir() {
                return Err(IsolateError::Config(format!(
                    "Not a directory: {}",
                    binding.source.display()
                )));
            }
            if !binding.target.is_absolute() {
                return Err(IsolateError::Config(format!(
                    "Target must be absolute: {}",
                    binding.target.display()
                )));
            }
        }
        self.config.directory_bindings.extend(bindings);
        Ok(())
    }
}

impl Drop for Isolate {
    fn drop(&mut self) {
        self.wipe_workdir();
        if let Some(cg) = self.cgroup.take() {
            let _ = cg.remove(&self.config.instance_id);
        }
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
        .mode(0o644)
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
