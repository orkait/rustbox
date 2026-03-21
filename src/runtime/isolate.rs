use crate::config::types::{ExecutionResult, IsolateConfig, IsolateError, Result};
use crate::core::types::LaunchEvidence;
/// Main isolate management interface
use crate::exec::executor::ProcessExecutor;
use crate::safety::lock_manager::{acquire_box_lock, with_file_lock, BoxLockGuard};
use log::warn;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Persistent isolate instance configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
struct IsolateInstance {
    config: IsolateConfig,
    created_at: chrono::DateTime<chrono::Utc>,
    last_used: chrono::DateTime<chrono::Utc>,
}

/// Per-run execution overrides applied on top of persisted instance config.
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

    if let Some(cpu_seconds) = overrides.max_cpu {
        config.cpu_time_limit = Some(Duration::from_secs(cpu_seconds));
        config.time_limit = Some(Duration::from_secs(cpu_seconds));
    }

    if let Some(memory_mb) = overrides.max_memory {
        config.memory_limit = Some(memory_mb * 1024 * 1024); // Convert MB to bytes
    }

    if let Some(time_seconds) = overrides.max_time {
        config.cpu_time_limit = Some(Duration::from_secs(time_seconds));
    }

    if let Some(wall_time_seconds) = overrides.max_wall_time {
        config.wall_time_limit = Some(Duration::from_secs(wall_time_seconds));
    }

    if let Some(fd_limit_val) = overrides.fd_limit {
        config.fd_limit = Some(fd_limit_val);
    }

    if let Some(proc_limit) = overrides.process_limit {
        config.process_limit = Some(proc_limit);
    }

    config
}

/// Atomically write content to a file: write to temp → fsync → rename → fsync parent dir.
/// Prevents data loss on crash (ext4/xfs can lose renames without parent dir fsync).
fn atomic_write(target: &Path, content: &[u8]) -> std::io::Result<()> {
    let parent = target
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent dir"))?;

    // Write to a temp file in the same directory (same filesystem for rename)
    let temp_path = parent.join(format!(
        ".{}.tmp.{}",
        target.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));

    {
        let mut f = fs::File::create(&temp_path)?;
        f.write_all(content)?;
        f.sync_all()?; // fsync the data
    }

    // Atomic rename
    fs::rename(&temp_path, target)?;

    // fsync the parent directory to ensure the rename is durable
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

/// Main isolate manager for handling multiple isolated environments
pub struct Isolate {
    instance: IsolateInstance,
    base_path: PathBuf,
    box_lock_guard: Option<BoxLockGuard>,
    last_launch_evidence: Option<LaunchEvidence>,
}

impl Isolate {
    fn candidate_state_roots() -> Vec<PathBuf> {
        let preferred = IsolateConfig::runtime_root_dir();
        let fallback = std::env::temp_dir().join("rustbox");

        if preferred == fallback {
            vec![preferred]
        } else {
            vec![preferred, fallback]
        }
    }

    fn select_state_root() -> Result<PathBuf> {
        let mut failures = Vec::new();

        for candidate in Self::candidate_state_roots() {
            match fs::create_dir_all(&candidate) {
                Ok(_) => {
                    let probe = candidate.join(format!(".write_probe_{}", std::process::id()));
                    match fs::write(&probe, b"ok") {
                        Ok(_) => {
                            let _ = fs::remove_file(probe);
                            return Ok(candidate);
                        }
                        Err(e) => failures.push(format!("{} => {}", candidate.display(), e)),
                    }
                }
                Err(e) => failures.push(format!("{} => {}", candidate.display(), e)),
            }
        }

        Err(IsolateError::Config(format!(
            "No writable rustbox state root available: {}",
            failures.join("; ")
        )))
    }

    fn ensure_instance_workdir(&mut self) -> Result<()> {
        let workdir = self.base_path.join("workdir");
        fs::create_dir_all(&workdir).map_err(IsolateError::Io)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&workdir, fs::Permissions::from_mode(0o755))
                .map_err(IsolateError::Io)?;

            if unsafe { libc::geteuid() } == 0 {
                if let (Some(uid), Some(gid)) = (self.instance.config.uid, self.instance.config.gid)
                {
                    use nix::unistd::{chown, Gid, Uid};
                    chown(&workdir, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))).map_err(
                        |e| {
                            IsolateError::Config(format!(
                                "Failed to set workdir ownership {}:{} on {}: {}",
                                uid,
                                gid,
                                workdir.display(),
                                e
                            ))
                        },
                    )?;
                }
            }
        }

        self.instance.config.workdir = workdir;
        Ok(())
    }

    /// Extract box ID from instance_id (format: "rustbox/{box_id}")
    fn extract_box_id(instance_id: &str) -> Result<u32> {
        if let Some(box_id_str) = instance_id.strip_prefix("rustbox/") {
            box_id_str.parse::<u32>().map_err(|_| {
                IsolateError::Config(format!("Invalid box ID in instance_id: {}", instance_id))
            })
        } else {
            Err(IsolateError::Config(format!(
                "Instance ID must start with 'rustbox/': {}",
                instance_id
            )))
        }
    }

    /// Create a new isolate instance
    pub fn new(config: IsolateConfig) -> Result<Self> {
        if config.instance_id.contains("..") || config.instance_id.starts_with('/') {
            return Err(IsolateError::Config(format!(
                "instance_id contains unsafe path components: {}", config.instance_id
            )));
        }

        let mut base_path = Self::select_state_root()?;
        base_path.push(&config.instance_id);

        // Create base directory
        fs::create_dir_all(&base_path).map_err(IsolateError::Io)?;

        let instance = IsolateInstance {
            config,
            created_at: chrono::Utc::now(),
            last_used: chrono::Utc::now(),
        };

        let mut isolate = Self {
            instance,
            base_path,
            box_lock_guard: None,
            last_launch_evidence: None,
        };

        // Acquire lock before any operations
        isolate.acquire_lock(true)?;

        // Save the new instance
        isolate.atomic_instances_update(|instances| {
            instances.insert(
                isolate.instance.config.instance_id.clone(),
                isolate.instance.clone(),
            );
        })?;

        Ok(isolate)
    }

    /// Load an existing isolate instance
    pub fn load(instance_id: &str) -> Result<Option<Self>> {
        let mut config_file = Self::select_state_root()?;
        config_file.push("instances.json");

        if !config_file.exists() {
            return Ok(None);
        }

        let instances = Self::load_all_instances()?;
        if let Some(instance) = instances.get(instance_id) {
            let mut base_path = Self::select_state_root()?;
            base_path.push(instance_id);

            if base_path.exists() {
                let isolate = Self {
                    instance: instance.clone(),
                    base_path,
                    box_lock_guard: None,
                    last_launch_evidence: None,
                };
                // Don't acquire lock for load - only for exclusive operations
                Ok(Some(isolate))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// List all isolate instances
    pub fn list_all() -> Result<Vec<String>> {
        let instances = Self::load_all_instances()?;
        Ok(instances.keys().cloned().collect())
    }

    /// Execute a command in this isolate
    pub fn execute(
        &mut self,
        command: &[String],
        stdin_data: Option<&str>,
    ) -> Result<ExecutionResult> {
        let overrides = ExecutionOverrides {
            stdin_data: stdin_data.map(str::to_string),
            ..ExecutionOverrides::default()
        };
        self.execute_with_overrides(command, &overrides)
    }

    /// Execute a command in this isolate with runtime resource overrides
    pub fn execute_with_overrides(
        &mut self,
        command: &[String],
        overrides: &ExecutionOverrides,
    ) -> Result<ExecutionResult> {
        // Acquire lock for execution to prevent conflicts
        if self.box_lock_guard.is_none() {
            self.acquire_lock(false)?;
        }

        self.ensure_instance_workdir()?;

        // Update last used timestamp
        self.instance.last_used = chrono::Utc::now();
        self.save()?;

        // Clone config and apply overrides
        let config = apply_overrides_to_config(&self.instance.config, overrides);

        // Create executor with modified config
        let mut executor = ProcessExecutor::new(config)?;

        // Execute the command
        let result = executor.execute(command, overrides.stdin_data.as_deref())?;
        self.last_launch_evidence = executor.take_launch_evidence();
        Ok(result)
    }

    /// Execute code directly from string input (Judge0-style)
    pub fn execute_code_string(
        &mut self,
        language: &str,
        code: &str,
        overrides: &ExecutionOverrides,
    ) -> Result<ExecutionResult> {
        match language.to_lowercase().as_str() {
            "python" | "py" => self.execute_python_string(code, overrides),
            "cpp" | "c++" | "cxx" => self.compile_and_execute_cpp(code, overrides),
            "java" => self.compile_and_execute_java(code, overrides),
            "javascript" | "js" => self.execute_js_string(code, overrides),
            "typescript" | "ts" => self.execute_ts_string(code, overrides),
            _ => Err(IsolateError::Config(format!(
                "Unsupported language: {}",
                language
            ))),
        }
    }

    /// Execute JavaScript via QuickJS
    fn execute_js_string(
        &mut self,
        code: &str,
        overrides: &ExecutionOverrides,
    ) -> Result<ExecutionResult> {
        self.ensure_instance_workdir()?;
        // Clear any artifacts from a prior run before writing new user data.
        self.wipe_workdir_contents();

        let source_file = self.instance.config.workdir.join("solution.js");
        let command = vec![
            "/usr/local/bin/qjs".to_string(),
            "--std".to_string(),
            source_file.to_string_lossy().to_string(),
        ];
        fs::write(&source_file, code)?;
        let result = self.execute_with_overrides(&command, overrides);

        // Delete source file immediately — on both the Ok and Err paths.
        // Rustbox does not own user data; execution and cleanup are first-class.
        let _ = fs::remove_file(&source_file);

        result
    }

    /// Execute TypeScript via Bun
    fn execute_ts_string(
        &mut self,
        code: &str,
        overrides: &ExecutionOverrides,
    ) -> Result<ExecutionResult> {
        self.ensure_instance_workdir()?;
        // Clear any artifacts from a prior run before writing new user data.
        self.wipe_workdir_contents();

        let source_file = self.instance.config.workdir.join("solution.ts");
        let command = vec![
            "/usr/local/bin/bun".to_string(),
            "run".to_string(),
            source_file.to_string_lossy().to_string(),
        ];
        fs::write(&source_file, code)?;
        let result = self.execute_with_overrides(&command, overrides);

        // Delete source file and any Bun cache artifacts immediately.
        // Rustbox does not own user data; execution and cleanup are first-class.
        let _ = fs::remove_file(&source_file);

        result
    }

    /// Execute Python code from string.
    /// Writes to a file in workdir rather than passing via `-c` so that the
    /// source code is NOT visible in /proc/PID/cmdline (SEC-1).
    fn execute_python_string(
        &mut self,
        code: &str,
        overrides: &ExecutionOverrides,
    ) -> Result<ExecutionResult> {
        self.ensure_instance_workdir()?;
        self.wipe_workdir_contents();

        let source_file = self.instance.config.workdir.join("solution.py");
        let command = vec![
            "/usr/bin/python3".to_string(),
            "-u".to_string(),
            source_file.to_string_lossy().to_string(),
        ];
        fs::write(&source_file, code)?;
        let result = self.execute_with_overrides(&command, overrides);

        let _ = fs::remove_file(&source_file);

        result
    }

    fn build_compile_failure_result(
        compile_result: ExecutionResult,
        stderr_prefix: &str,
        error_message: &str,
    ) -> ExecutionResult {
        let status = match compile_result.status {
            crate::config::types::ExecutionStatus::TimeLimit => {
                crate::config::types::ExecutionStatus::TimeLimit
            }
            crate::config::types::ExecutionStatus::MemoryLimit => {
                crate::config::types::ExecutionStatus::MemoryLimit
            }
            _ => crate::config::types::ExecutionStatus::RuntimeError,
        };

        // Destructure to avoid redundant clones on owned fields
        let ExecutionResult {
            exit_code,
            stderr,
            stdout,
            error_message: compile_error,
            output_integrity,
            wall_time,
            cpu_time,
            memory_peak,
            ..
        } = compile_result;

        let detail = if !stderr.trim().is_empty() {
            stderr
        } else if !stdout.trim().is_empty() {
            stdout
        } else {
            compile_error.unwrap_or_else(|| "no compiler stderr".to_string())
        };

        ExecutionResult {
            status,
            exit_code,
            stdout: String::new(),
            stderr: format!("{}:\n{}", stderr_prefix, detail),
            output_integrity,
            wall_time,
            cpu_time,
            memory_peak,
            success: false,
            signal: None,
            error_message: Some(error_message.to_string()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn compile_and_execute_with_spec<F>(
        &mut self,
        code: &str,
        source_file: PathBuf,
        compile_command: Vec<String>,
        execute_command: Vec<String>,
        overrides: &ExecutionOverrides,
        stderr_prefix: &str,
        error_message: &str,
        restore_before_execute: bool,
        restore_on_return: bool,
        mut configure_compile: F,
    ) -> Result<ExecutionResult>
    where
        F: FnMut(&mut IsolateConfig, &IsolateConfig, &ExecutionOverrides),
    {
        self.ensure_instance_workdir()?;
        // Clear any artifacts from a prior run before writing new user data.
        self.wipe_workdir_contents();

        fs::write(&source_file, code)?;

        let original_config = self.instance.config.clone();
        configure_compile(&mut self.instance.config, &original_config, overrides);

        let compile_result = match self.execute(&compile_command, None) {
            Ok(r) => r,
            Err(e) => {
                self.instance.config = original_config;
                // Wipe source + any partial compiler output before returning.
                self.wipe_workdir_contents();
                return Err(e);
            }
        };
        if !compile_result.success {
            if restore_on_return {
                self.instance.config = original_config;
            }
            // Wipe source before returning the compile-error verdict.
            self.wipe_workdir_contents();
            return Ok(Self::build_compile_failure_result(
                compile_result,
                stderr_prefix,
                error_message,
            ));
        }

        // Compilation succeeded — source is no longer needed.
        // Delete it now so it isn't on disk during the execution phase.
        let _ = fs::remove_file(&source_file);

        if restore_before_execute {
            self.instance.config = original_config.clone();
        }

        let result = self.execute_with_overrides(&execute_command, overrides);
        if restore_on_return {
            self.instance.config = original_config;
        }

        // Wipe compiled artifacts (binary, .class files, anything the sandboxed
        // process may have written) immediately after execution completes.
        // Rustbox does not own user data; execution and cleanup are first-class.
        self.wipe_workdir_contents();

        result
    }

    /// Compile and execute C++ code from string
    fn compile_and_execute_cpp(
        &mut self,
        code: &str,
        overrides: &ExecutionOverrides,
    ) -> Result<ExecutionResult> {
        // Ensure workdir is initialized before computing source_file path.
        self.ensure_instance_workdir()?;
        let source_file = self.instance.config.workdir.join("solution.cpp");
        let compile_command = vec![
            "/usr/bin/g++".to_string(),
            "-o".to_string(),
            "solution".to_string(),
            "solution.cpp".to_string(),
            "-std=c++17".to_string(),
            "-O2".to_string(),
        ];
        let execute_command = vec!["./solution".to_string()];

        self.compile_and_execute_with_spec(
            code,
            source_file,
            compile_command,
            execute_command,
            overrides,
            "Compilation Error",
            "Compilation failed",
            true,
            true,
            |config, original_config, runtime_overrides| {
                // Compilation uses a trusted compiler on untrusted source.
                // Run in permissive mode so the compiler can access host toolchains.
                // The compiled binary is executed under the original (strict) config.
                config.strict_mode = false;
                // Only allow degraded fallback when non-root (already unprivileged).
                // When root, the namespace path MUST succeed to ensure UID drop.
                config.allow_degraded = unsafe { libc::geteuid() } != 0;

                // C++ toolchain can fan out many helper processes/threads (cc1plus/as/ld).
                // Keep compile phase process headroom well above runtime defaults.
                config.process_limit = Some(120);

                if let Some(memory) = runtime_overrides.max_memory {
                    config.memory_limit = Some(memory * 1024 * 1024);
                } else {
                    config.memory_limit = Some(256 * 1024 * 1024); // 256MB for C++
                }

                // Compilation needs a wider window than execution defaults.
                let original_cpu_secs = original_config
                    .cpu_time_limit
                    .map(|d| d.as_secs())
                    .unwrap_or(8);
                let original_wall_secs = original_config
                    .wall_time_limit
                    .map(|d| d.as_secs())
                    .unwrap_or(10);
                let compile_cpu_secs = runtime_overrides
                    .max_cpu
                    .or(runtime_overrides.max_time)
                    .unwrap_or(original_cpu_secs)
                    .max(15);
                let compile_wall_secs = runtime_overrides
                    .max_wall_time
                    .unwrap_or(original_wall_secs)
                    .max(30);
                config.cpu_time_limit = Some(Duration::from_secs(compile_cpu_secs));
                config.time_limit = Some(Duration::from_secs(compile_cpu_secs));
                config.wall_time_limit = Some(Duration::from_secs(compile_wall_secs));
            },
        )
    }

    /// Compile and execute Java code from string
    fn compile_and_execute_java(
        &mut self,
        code: &str,
        overrides: &ExecutionOverrides,
    ) -> Result<ExecutionResult> {
        // Ensure workdir is initialized before computing source_file path.
        self.ensure_instance_workdir()?;
        // Extract class name from code (simple heuristic)
        let class_name = self
            .extract_java_class_name(code)
            .unwrap_or_else(|| "Main".to_string());
        let source_file = self
            .instance
            .config
            .workdir
            .join(format!("{}.java", class_name));
        let compile_command = vec![
            "javac".to_string(),
            "-proc:none".to_string(), // disable annotation processing
            "-cp".to_string(),
            ".".to_string(),
            format!("{}.java", class_name),
        ];
        let execute_command = vec![
            "java".to_string(),
            "-cp".to_string(),
            ".".to_string(),
            class_name,
        ];

        self.compile_and_execute_with_spec(
            code,
            source_file,
            compile_command,
            execute_command,
            overrides,
            "Java Compilation Error",
            "Java compilation failed",
            true,
            true,
            |config, original_config, runtime_overrides| {
                // Compilation uses a trusted compiler on untrusted source.
                // Run in permissive mode so javac can access host JVM paths.
                // The compiled class is executed under the original (strict) config.
                config.strict_mode = false;
                // Only allow degraded fallback when non-root (already unprivileged).
                // When root, the namespace path MUST succeed to ensure UID drop.
                config.allow_degraded = unsafe { libc::geteuid() } != 0;

                // Increase resource limits for JVM
                if let Some(memory) = runtime_overrides.max_memory {
                    config.memory_limit = Some(memory * 1024 * 1024);
                } else {
                    config.memory_limit = Some(512 * 1024 * 1024); // 512MB default for Java
                }

                // JVM/Javac can fan out many threads; too-low pids.max causes hard launch failures.
                // Keep a higher floor while still allowing user overrides to increase further.
                let requested_process_limit = runtime_overrides
                    .process_limit
                    .or(original_config.process_limit)
                    .unwrap_or(16);
                config.process_limit = Some(requested_process_limit.max(1024));

                // JVM startup is slow; give compilation generous time limits.
                let original_cpu_secs = original_config
                    .cpu_time_limit
                    .map(|d| d.as_secs())
                    .unwrap_or(8);
                let original_wall_secs = original_config
                    .wall_time_limit
                    .map(|d| d.as_secs())
                    .unwrap_or(10);
                let compile_cpu_secs = runtime_overrides
                    .max_cpu
                    .or(runtime_overrides.max_time)
                    .unwrap_or(original_cpu_secs)
                    .max(15);
                let compile_wall_secs = runtime_overrides
                    .max_wall_time
                    .unwrap_or(original_wall_secs)
                    .max(30);
                config.cpu_time_limit = Some(Duration::from_secs(compile_cpu_secs));
                config.time_limit = Some(Duration::from_secs(compile_cpu_secs));
                config.wall_time_limit = Some(Duration::from_secs(compile_wall_secs));
            },
        )
    }

    /// Extract Java class name from source code (simple regex-based extraction)
    fn extract_java_class_name(&self, code: &str) -> Option<String> {
        // Look for "public class ClassName" pattern
        for line in code.lines() {
            let line = line.trim();
            if line.starts_with("public class ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let class_name = parts[2].trim_end_matches('{').trim();
                    // Sanitize: only allow Java identifier characters (alphanumeric + underscore)
                    // to prevent path traversal via crafted class names like "../../../tmp/evil"
                    if class_name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                        return Some(class_name.to_string());
                    }
                    return None; // reject names with path separators, dots, etc.
                }
            }
        }
        None
    }

    /// Wipe every file and subdirectory inside workdir without removing the
    /// directory itself. Called before AND after each execution so that:
    ///   - No prior-run artifacts are visible to the next run.
    ///   - User-submitted source + compiled artifacts are deleted as soon as
    ///     execution completes, not deferred to Isolate::cleanup().
    ///
    /// Uses remove_tree_secure (openat/unlinkat) so a sandboxed process that
    /// planted a symlink inside workdir cannot redirect deletion outside the dir.
    fn wipe_workdir_contents(&self) {
        let workdir = &self.instance.config.workdir;
        if !workdir.as_os_str().is_empty() && workdir.exists() {
            if let Ok(entries) = fs::read_dir(workdir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() && !path.is_symlink() {
                        if let Err(e) =
                            crate::safety::safe_cleanup::remove_tree_secure(&path)
                        {
                            warn!(
                                "wipe_workdir_contents: failed to remove dir {}: {}",
                                path.display(),
                                e
                            );
                        }
                    } else if let Err(e) = fs::remove_file(&path) {
                        warn!(
                            "wipe_workdir_contents: failed to remove file {}: {}",
                            path.display(),
                            e
                        );
                    }
                }
            }
        }
    }

    /// Clean up this isolate instance
    pub fn cleanup(mut self) -> Result<()> {
        let instance_id = self.instance.config.instance_id.clone();

        // Acquire lock for cleanup to prevent conflicts
        if self.box_lock_guard.is_none() {
            self.acquire_lock(false)?;
        }

        // Remove from storage atomically
        self.atomic_instances_update(|instances| {
            instances.remove(&instance_id);
        })?;

        // Clean up filesystem — use remove_tree_secure (openat/unlinkat) rather
        // than fs::remove_dir_all so a symlink planted by sandboxed code cannot
        // redirect deletion to paths outside the sandbox base directory.
        if self.base_path.exists() {
            crate::safety::safe_cleanup::remove_tree_secure(&self.base_path)?;
        }

        // Release lock before removing lock file
        self.release_lock();

        // Lock will be automatically released by BoxLockManager when dropped

        Ok(())
    }

    /// Get configuration
    pub fn config(&self) -> &IsolateConfig {
        &self.instance.config
    }

    /// Get mutable configuration for runtime overrides.
    pub fn config_mut(&mut self) -> &mut IsolateConfig {
        &mut self.instance.config
    }

    /// Consume launch evidence from the most recent execution.
    pub fn take_last_launch_evidence(&mut self) -> Option<LaunchEvidence> {
        self.last_launch_evidence.take()
    }

    /// Add directory bindings to the isolate configuration
    pub fn add_directory_bindings(
        &mut self,
        bindings: Vec<crate::config::types::DirectoryBinding>,
    ) -> Result<()> {
        // Validate all bindings before applying any
        for binding in &bindings {
            // Check if source exists (unless maybe flag is set)
            if !binding.maybe && !binding.source.exists() {
                return Err(IsolateError::Config(format!(
                    "Source directory does not exist: {}",
                    binding.source.display()
                )));
            }

            // Validate source is actually a directory
            if binding.source.exists() && !binding.source.is_dir() {
                return Err(IsolateError::Config(format!(
                    "Source path is not a directory: {}",
                    binding.source.display()
                )));
            }

            // Validate target path format
            if !binding.target.is_absolute() {
                return Err(IsolateError::Config(format!(
                    "Target path must be absolute (start with /): {}",
                    binding.target.display()
                )));
            }
        }

        // Add bindings to configuration
        self.instance.config.directory_bindings.extend(bindings);

        // Update last_used timestamp
        self.instance.last_used = chrono::Utc::now();

        // Save updated configuration
        self.save()?;

        Ok(())
    }

    /// Save instance configuration with atomic operations
    pub fn save(&self) -> Result<()> {
        self.atomic_instances_update(|instances| {
            instances.insert(
                self.instance.config.instance_id.clone(),
                self.instance.clone(),
            );
        })
    }

    /// Load all instances from storage (lock-protected against concurrent writes)
    fn load_all_instances() -> Result<HashMap<String, IsolateInstance>> {
        let instances_dir = Self::select_state_root()?;

        let instances_file = instances_dir.join("instances.json");

        if !instances_file.exists() {
            return Ok(HashMap::new());
        }

        // Read under the same file lock used by atomic_instances_update to prevent
        // partial reads during concurrent writes
        with_file_lock(&instances_file, || {
            let content = fs::read_to_string(&instances_file)?;
            if content.trim().is_empty() {
                return Ok(HashMap::new());
            }

            match serde_json::from_str(&content) {
                Ok(parsed) => Ok(parsed),
                Err(e) => {
                    // Corruption recovery: back up the corrupt file and return empty
                    warn!(
                        "instances.json is corrupted during read ({}), backing up and returning empty",
                        e
                    );
                    let backup_path = instances_dir.join("instances.json.corrupted");
                    let _ = fs::copy(&instances_file, &backup_path);
                    Ok(HashMap::new())
                }
            }
        })
        .map_err(|e| match e {
            crate::config::types::LockError::FilesystemError(io_err) => IsolateError::Io(io_err),
            crate::config::types::LockError::SystemError { message } => IsolateError::Config(message),
            _ => IsolateError::Lock(e.to_string()),
        })
    }

    /// Acquire exclusive lock for this isolate instance using enhanced lock manager
    fn acquire_lock(&mut self, _is_init: bool) -> Result<()> {
        // Extract box_id from instance_id
        let box_id = Self::extract_box_id(&self.instance.config.instance_id)?;

        // Use the new enhanced lock system directly
        let lock_guard = acquire_box_lock(box_id).map_err(IsolateError::AdvancedLock)?;

        // Store the lock guard
        self.box_lock_guard = Some(lock_guard);
        Ok(())
    }

    /// Atomic update of instances.json using enhanced lock manager
    fn atomic_instances_update<F>(&self, update_fn: F) -> Result<()>
    where
        F: FnOnce(&mut HashMap<String, IsolateInstance>),
    {
        let instances_dir = Self::select_state_root()?;
        fs::create_dir_all(&instances_dir)?;
        let instances_file = instances_dir.join("instances.json");

        // Use the enhanced lock manager's file locking (now uses dedicated .lock inode)
        with_file_lock(&instances_file, || {
            // Load current instances with corruption recovery
            let mut instances = if instances_file.exists() {
                let content = fs::read_to_string(&instances_file)?;
                if content.trim().is_empty() {
                    HashMap::new()
                } else {
                    match serde_json::from_str(&content) {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            // Corruption recovery: back up the corrupt file and start fresh
                            warn!(
                                "instances.json is corrupted ({}), backing up and starting fresh",
                                e
                            );
                            let backup_path = instances_dir.join("instances.json.corrupted");
                            let _ = fs::copy(&instances_file, &backup_path);
                            HashMap::new()
                        }
                    }
                }
            } else {
                HashMap::new()
            };

            // Apply update
            update_fn(&mut instances);

            // Write atomically with fsync
            let content = serde_json::to_string_pretty(&instances).map_err(|e| {
                crate::config::types::LockError::SystemError {
                    message: format!("Failed to serialize instances: {}", e),
                }
            })?;

            atomic_write(&instances_file, content.as_bytes())?;

            Ok(())
        })
        .map_err(|e| match e {
            crate::config::types::LockError::FilesystemError(io_err) => IsolateError::Io(io_err),
            crate::config::types::LockError::SystemError { message } => {
                IsolateError::Config(message)
            }
            _ => IsolateError::Lock(e.to_string()),
        })
    }

    /// Acquire execution lock for loaded isolate (public version of acquire_lock)
    pub fn acquire_execution_lock(&mut self) -> Result<()> {
        if self.box_lock_guard.is_some() {
            return Ok(()); // Already have lock
        }
        self.acquire_lock(false)
    }

    /// Release the lock (happens automatically on drop)
    fn release_lock(&mut self) {
        self.box_lock_guard = None; // Lock guard automatically releases on drop
    }
}

impl Drop for Isolate {
    fn drop(&mut self) {
        // Defense-in-depth: wipe any residual user data from workdir even if
        // the caller forgot to call cleanup() (panic, early return, library
        // misuse). The execute methods already wipe inline, so this is a
        // safety net — not the primary cleanup path. (SEC-3)
        self.wipe_workdir_contents();
        // Lock is automatically released when file descriptor is closed
        self.release_lock();
    }
}
