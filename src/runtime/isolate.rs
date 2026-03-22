use crate::config::types::{ExecutionResult, IsolateConfig, IsolateError, Result};
use crate::config::validator::validate_config;
use crate::core::types::{LaunchEvidence, SandboxLaunchRequest};
use crate::kernel::cgroup::{self, CgroupBackend};
use crate::observability::audit::events;
use crate::runtime::security::command_validation;
use crate::safety::cleanup::BaselineChecker;
use crate::safety::uid_pool;
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
        Err(IsolateError::Config("No writable state root available".to_string()))
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
            return Err(IsolateError::Privilege("Strict mode requires root".to_string()));
        }

        let validation = validate_config(&config)?;
        for warning in validation.warnings {
            log::warn!("Config: {}", warning);
        }

        let mut base_path = Self::select_state_root()?;
        base_path.push(pool_uid.to_string());
        fs::create_dir_all(&base_path)?;

        let cgroup = match cgroup::create_cgroup_backend(
            config.force_cgroup_v1, config.strict_mode, &config.instance_id,
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
            config, base_path, cgroup, baseline,
            last_launch_evidence: None,
            _uid_guard: Some(uid_guard),
        })
    }

    pub fn execute(
        &mut self,
        command: &[String],
        stdin_data: Option<&str>,
    ) -> Result<ExecutionResult> {
        self.execute_with_overrides(command, &ExecutionOverrides {
            stdin_data: stdin_data.map(str::to_string),
            ..Default::default()
        })
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
            return Err(IsolateError::Cgroup("No cgroup backend for strict mode".to_string()));
        }

        let request = SandboxLaunchRequest::from_config(
            &config, &argv, overrides.stdin_data.as_deref(),
            self.cgroup.as_ref().map(|cg| cg.get_cgroup_path(&config.instance_id)),
        );

        let outcome = crate::core::supervisor::launch_with_supervisor(
            request, self.cgroup.as_deref(),
        )?;

        self.last_launch_evidence = Some(outcome.evidence);
        Ok(outcome.result)
    }

    pub fn execute_code_string(
        &mut self, language: &str, code: &str, overrides: &ExecutionOverrides,
    ) -> Result<ExecutionResult> {
        match language.to_lowercase().as_str() {
            "python" | "py" => self.execute_interpreted(code, "solution.py", &["/usr/bin/python3", "-u"], overrides),
            "javascript" | "js" => self.execute_interpreted(code, "solution.js", &["/usr/local/bin/bun", "run"], overrides),
            "typescript" | "ts" => self.execute_interpreted(code, "solution.ts", &["/usr/local/bin/bun", "run"], overrides),
            "c" => self.compile_and_execute_c(code, overrides),
            "cpp" | "c++" => self.compile_and_execute_cpp(code, overrides),
            "go" => self.compile_and_execute_go(code, overrides),
            "rust" | "rs" => self.compile_and_execute_rust(code, overrides),
            "java" => self.compile_and_execute_java(code, overrides),
            _ => Err(IsolateError::Config(format!("Unsupported language: {}", language))),
        }
    }

    fn execute_interpreted(
        &mut self, code: &str, filename: &str, prefix_args: &[&str], overrides: &ExecutionOverrides,
    ) -> Result<ExecutionResult> {
        self.ensure_workdir()?;
        self.wipe_workdir();

        let source_file = self.config.workdir.join(filename);
        let mut command: Vec<String> = prefix_args.iter().map(|s| s.to_string()).collect();
        command.push(source_file.to_string_lossy().to_string());

        fs::write(&source_file, code)?;
        let result = self.execute_with_overrides(&command, overrides);
        let _ = fs::remove_file(&source_file);
        result
    }

    fn configure_compile_phase(
        config: &mut IsolateConfig, original: &IsolateConfig, overrides: &ExecutionOverrides,
        default_memory_mb: u64, min_process_limit: u32,
    ) {
        config.strict_mode = false;
        config.allow_degraded = unsafe { libc::geteuid() } != 0;
        config.process_limit = Some(min_process_limit);
        config.memory_limit = Some(
            overrides.max_memory.map(|mb| mb * 1024 * 1024).unwrap_or(default_memory_mb * 1024 * 1024),
        );
        let orig_cpu = original.cpu_time_limit.map(|d| d.as_secs()).unwrap_or(8);
        let orig_wall = original.wall_time_limit.map(|d| d.as_secs()).unwrap_or(10);
        let cpu = overrides.max_cpu.or(overrides.max_time).unwrap_or(orig_cpu).max(15);
        let wall = overrides.max_wall_time.unwrap_or(orig_wall).max(30);
        config.cpu_time_limit = Some(Duration::from_secs(cpu));
        config.time_limit = Some(Duration::from_secs(cpu));
        config.wall_time_limit = Some(Duration::from_secs(wall));
    }

    fn build_compile_failure_result(r: ExecutionResult, prefix: &str, msg: &str) -> ExecutionResult {
        let status = match r.status {
            crate::config::types::ExecutionStatus::TimeLimit => crate::config::types::ExecutionStatus::TimeLimit,
            crate::config::types::ExecutionStatus::MemoryLimit => crate::config::types::ExecutionStatus::MemoryLimit,
            _ => crate::config::types::ExecutionStatus::RuntimeError,
        };
        let detail = if !r.stderr.trim().is_empty() { r.stderr.clone() }
            else if !r.stdout.trim().is_empty() { r.stdout.clone() }
            else { r.error_message.clone().unwrap_or_else(|| "no compiler output".to_string()) };

        ExecutionResult {
            status, exit_code: r.exit_code, stdout: String::new(),
            stderr: format!("{}:\n{}", prefix, detail),
            output_integrity: r.output_integrity, wall_time: r.wall_time,
            cpu_time: r.cpu_time, memory_peak: r.memory_peak,
            success: false, signal: None, error_message: Some(msg.to_string()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn compile_and_execute<F>(
        &mut self, code: &str, source_file: PathBuf,
        compile_cmd: Vec<String>, run_cmd: Vec<String>,
        overrides: &ExecutionOverrides, prefix: &str, msg: &str,
        mut configure: F,
    ) -> Result<ExecutionResult>
    where F: FnMut(&mut IsolateConfig, &IsolateConfig, &ExecutionOverrides),
    {
        self.ensure_workdir()?;
        self.wipe_workdir();
        fs::write(&source_file, code)?;

        let saved = self.config.clone();
        configure(&mut self.config, &saved, overrides);

        let compile_result = match self.execute(&compile_cmd, None) {
            Ok(r) => r,
            Err(e) => { self.config = saved; self.wipe_workdir(); return Err(e); }
        };

        if !compile_result.success {
            self.config = saved;
            self.wipe_workdir();
            return Ok(Self::build_compile_failure_result(compile_result, prefix, msg));
        }

        let _ = fs::remove_file(&source_file);
        self.config = saved;
        let result = self.execute_with_overrides(&run_cmd, overrides);
        self.wipe_workdir();
        result
    }

    fn compile_and_execute_c(&mut self, code: &str, overrides: &ExecutionOverrides) -> Result<ExecutionResult> {
        self.ensure_workdir()?;
        let src = self.config.workdir.join("solution.c");
        self.compile_and_execute(
            code, src,
            vec!["/usr/bin/gcc".into(), "-pipe".into(), "-o".into(), "solution".into(), "solution.c".into(), "-std=c17".into(), "-O2".into(), "-lm".into(), "-DONLINE_JUDGE".into()],
            vec!["./solution".into()],
            overrides, "Compilation Error", "Compilation failed",
            |c, o, v| Self::configure_compile_phase(c, o, v, 256, 120),
        )
    }

    fn compile_and_execute_go(&mut self, code: &str, overrides: &ExecutionOverrides) -> Result<ExecutionResult> {
        self.ensure_workdir()?;
        let src = self.config.workdir.join("solution.go");
        self.compile_and_execute(
            code, src,
            vec!["/usr/local/go/bin/go".into(), "build".into(), "-trimpath".into(), "-ldflags".into(), "-s -w".into(), "-o".into(), "solution".into(), "solution.go".into()],
            vec!["./solution".into()],
            overrides, "Compilation Error", "Compilation failed",
            |c, o, v| {
                Self::configure_compile_phase(c, o, v, 1024, 1024);
                c.fd_limit = Some(1024);
                c.file_size_limit = Some(256 * 1024 * 1024);
                c.environment.push(("CGO_ENABLED".into(), "0".into()));
                c.environment.push(("GOCACHE".into(), "/tmp/go-cache".into()));
                c.environment.push(("GOPATH".into(), "/tmp/gopath".into()));
                c.environment.push(("GOTMPDIR".into(), "/tmp".into()));
                c.environment.push(("GONOSUMCHECK".into(), "*".into()));
                c.environment.push(("GOFLAGS".into(), "-buildvcs=false".into()));
                c.environment.push(("HOME".into(), "/tmp".into()));
            },
        )
    }

    fn compile_and_execute_rust(&mut self, code: &str, overrides: &ExecutionOverrides) -> Result<ExecutionResult> {
        self.ensure_workdir()?;
        let src = self.config.workdir.join("solution.rs");
        self.compile_and_execute(
            code, src,
            vec!["/usr/local/bin/rustc".into(), "-O".into(), "--edition".into(), "2021".into(), "-C".into(), "codegen-units=1".into(), "-o".into(), "solution".into(), "solution.rs".into()],
            vec!["./solution".into()],
            overrides, "Compilation Error", "Compilation failed",
            |c, o, v| {
                Self::configure_compile_phase(c, o, v, 1024, 64);
                c.fd_limit = Some(512);
                c.file_size_limit = Some(256 * 1024 * 1024);
            },
        )
    }

    fn compile_and_execute_cpp(&mut self, code: &str, overrides: &ExecutionOverrides) -> Result<ExecutionResult> {
        self.ensure_workdir()?;
        let src = self.config.workdir.join("solution.cpp");
        self.compile_and_execute(
            code, src,
            vec!["/usr/bin/g++".into(), "-pipe".into(), "-o".into(), "solution".into(), "solution.cpp".into(), "-std=c++17".into(), "-O2".into(), "-DONLINE_JUDGE".into()],
            vec!["./solution".into()],
            overrides, "Compilation Error", "Compilation failed",
            |c, o, v| Self::configure_compile_phase(c, o, v, 256, 120),
        )
    }

    fn compile_and_execute_java(&mut self, code: &str, overrides: &ExecutionOverrides) -> Result<ExecutionResult> {
        self.ensure_workdir()?;
        let class = extract_java_class_name(code).unwrap_or_else(|| "Main".to_string());
        let src = self.config.workdir.join(format!("{}.java", class));
        self.compile_and_execute(
            code, src,
            vec!["javac".into(), "-encoding".into(), "UTF-8".into(), "-proc:none".into(), "-cp".into(), ".".into(), format!("{}.java", class)],
            vec!["java".into(), "-Xmx256m".into(), "-Xms32m".into(), "-Xss64m".into(), "-XX:+UseSerialGC".into(), "-XX:+ExitOnOutOfMemoryError".into(), "-XX:TieredStopAtLevel=1".into(), "-XX:MaxMetaspaceSize=64m".into(), "-Dfile.encoding=UTF-8".into(), "-cp".into(), ".".into(), class],
            overrides, "Java Compilation Error", "Java compilation failed",
            |c, o, v| Self::configure_compile_phase(c, o, v, 512, 1024),
        )
    }

    fn wipe_workdir(&self) {
        let workdir = &self.config.workdir;
        if workdir.as_os_str().is_empty() || !workdir.exists() { return; }
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
                    ev.process_lifecycle.descendant_containment = "baseline_verification_failed".to_string();
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

    pub fn config(&self) -> &IsolateConfig { &self.config }
    pub fn config_mut(&mut self) -> &mut IsolateConfig { &mut self.config }
    pub fn take_last_launch_evidence(&mut self) -> Option<LaunchEvidence> { self.last_launch_evidence.take() }

    pub fn add_directory_bindings(&mut self, bindings: Vec<crate::config::types::DirectoryBinding>) -> Result<()> {
        for binding in &bindings {
            if !binding.maybe && !binding.source.exists() {
                return Err(IsolateError::Config(format!("Source directory does not exist: {}", binding.source.display())));
            }
            if binding.source.exists() && !binding.source.is_dir() {
                return Err(IsolateError::Config(format!("Not a directory: {}", binding.source.display())));
            }
            if !binding.target.is_absolute() {
                return Err(IsolateError::Config(format!("Target must be absolute: {}", binding.target.display())));
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
