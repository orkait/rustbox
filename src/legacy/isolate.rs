/// Main isolate management interface
use crate::exec::executor::ProcessExecutor;
use crate::core::types::LaunchEvidence;
use crate::safety::lock_manager::{acquire_box_lock, with_file_lock, BoxLockGuard};
use crate::config::types::{ExecutionResult, IsolateConfig, IsolateError, Result};
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

/// Atomically write content to a file: write to temp → fsync → rename → fsync parent dir.
/// Prevents data loss on crash (ext4/xfs can lose renames without parent dir fsync).
fn atomic_write(target: &Path, content: &[u8]) -> std::io::Result<()> {
    let parent = target
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent dir"))?;

    // Write to a temp file in the same directory (same filesystem for rename)
    let temp_path = parent.join(format!(
        ".{}.tmp.{}",
        target
            .file_name()
            .unwrap_or_default()
            .to_string_lossy(),
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
        let legacy = std::env::temp_dir().join("rustbox");

        if preferred == legacy {
            vec![preferred]
        } else {
            vec![preferred, legacy]
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
                    chown(&workdir, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
                        .map_err(|e| {
                            IsolateError::Config(format!(
                                "Failed to set workdir ownership {}:{} on {}: {}",
                                uid,
                                gid,
                                workdir.display(),
                                e
                            ))
                        })?;
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
        // Acquire lock for execution to prevent conflicts
        if self.box_lock_guard.is_none() {
            self.acquire_lock(false)?;
        }

        self.ensure_instance_workdir()?;

        // Update last used timestamp
        self.instance.last_used = chrono::Utc::now();
        self.save()?;

        // Create executor with current config
        let mut executor = ProcessExecutor::new(self.instance.config.clone())?;

        // Execute the command
        let result = executor.execute(command, stdin_data)?;
        self.last_launch_evidence = executor.take_launch_evidence();
        Ok(result)
    }

    /// Execute a command in this isolate with runtime resource overrides
    pub fn execute_with_overrides(
        &mut self,
        command: &[String],
        stdin_data: Option<&str>,
        max_cpu: Option<u64>,
        max_memory: Option<u64>,
        max_time: Option<u64>,
        max_wall_time: Option<u64>,
        fd_limit: Option<u64>,
        process_limit: Option<u32>,
    ) -> Result<ExecutionResult> {
        // Acquire lock for execution to prevent cross-run conflicts.
        if self.box_lock_guard.is_none() {
            self.acquire_lock(false)?;
        }

        self.ensure_instance_workdir()?;

        // Update last used timestamp
        self.instance.last_used = chrono::Utc::now();
        self.save()?;

        // Clone config and apply overrides
        let mut config = self.instance.config.clone();

        if let Some(cpu_seconds) = max_cpu {
            config.cpu_time_limit = Some(Duration::from_secs(cpu_seconds));
            config.time_limit = Some(Duration::from_secs(cpu_seconds));
        }

        if let Some(memory_mb) = max_memory {
            config.memory_limit = Some(memory_mb * 1024 * 1024); // Convert MB to bytes
        }

        if let Some(time_seconds) = max_time {
            config.cpu_time_limit = Some(Duration::from_secs(time_seconds));
        }

        if let Some(wall_time_seconds) = max_wall_time {
            config.wall_time_limit = Some(Duration::from_secs(wall_time_seconds));
        }

        if let Some(fd_limit_val) = fd_limit {
            config.fd_limit = Some(fd_limit_val);
        }

        // P0-CLI-001: Apply process limit override
        if let Some(proc_limit) = process_limit {
            config.process_limit = Some(proc_limit);
        }

        // Create executor with modified config
        let mut executor = ProcessExecutor::new(config)?;

        // Execute the command
        let result = executor.execute(command, stdin_data)?;
        self.last_launch_evidence = executor.take_launch_evidence();
        Ok(result)
    }

    /// Execute code directly from string input (Judge0-style)
    pub fn execute_code_string(
        &mut self,
        language: &str,
        code: &str,
        stdin_data: Option<&str>,
        max_cpu: Option<u64>,
        max_memory: Option<u64>,
        max_time: Option<u64>,
        max_wall_time: Option<u64>,
        fd_limit: Option<u64>,
        process_limit: Option<u32>,
    ) -> Result<ExecutionResult> {
        match language.to_lowercase().as_str() {
            "python" | "py" => self
                .execute_python_string(code, stdin_data, max_cpu, max_memory, max_time, max_wall_time, fd_limit, process_limit),
            "cpp" | "c++" | "cxx" => self
                .compile_and_execute_cpp(code, stdin_data, max_cpu, max_memory, max_time, max_wall_time, fd_limit, process_limit),
            "java" => self.compile_and_execute_java(
                code, stdin_data, max_cpu, max_memory, max_time, max_wall_time, fd_limit, process_limit,
            ),
            _ => Err(IsolateError::Config(format!(
                "Unsupported language: {}",
                language
            ))),
        }
    }

    /// Execute Python code directly from string
    fn execute_python_string(
        &mut self,
        code: &str,
        stdin_data: Option<&str>,
        max_cpu: Option<u64>,
        max_memory: Option<u64>,
        max_time: Option<u64>,
        max_wall_time: Option<u64>,
        fd_limit: Option<u64>,
        process_limit: Option<u32>,
    ) -> Result<ExecutionResult> {
        let command = vec![
            "/usr/bin/python3".to_string(),
            "-u".to_string(),
            "-c".to_string(),
            code.to_string(),
        ];
        self.execute_with_overrides(
            &command, stdin_data, max_cpu, max_memory, max_time, max_wall_time, fd_limit, process_limit,
        )
    }

    /// Compile and execute C++ code from string
    fn compile_and_execute_cpp(
        &mut self,
        code: &str,
        stdin_data: Option<&str>,
        max_cpu: Option<u64>,
        max_memory: Option<u64>,
        max_time: Option<u64>,
        max_wall_time: Option<u64>,
        fd_limit: Option<u64>,
        process_limit: Option<u32>,
    ) -> Result<ExecutionResult> {
        self.ensure_instance_workdir()?;

        // Write source code to file in sandbox
        let source_file = self.instance.config.workdir.join("solution.cpp");
        fs::write(&source_file, code)?;

        // Temporarily increase process limit for C++ compilation
        let original_config = self.instance.config.clone();

        // C++ toolchain can fan out many helper processes/threads (cc1plus/as/ld).
        // Keep compile phase process headroom well above runtime defaults.
        self.instance.config.process_limit = Some(120);

        if let Some(memory) = max_memory {
            self.instance.config.memory_limit = Some(memory * 1024 * 1024);
        } else {
            self.instance.config.memory_limit = Some(256 * 1024 * 1024); // 256MB for C++
        }

        // Compilation is a host-toolchain phase and needs a wider window than
        // execution defaults to avoid false compile failures on slower hosts.
        let original_cpu_secs = original_config
            .cpu_time_limit
            .map(|d| d.as_secs())
            .unwrap_or(8);
        let original_wall_secs = original_config
            .wall_time_limit
            .map(|d| d.as_secs())
            .unwrap_or(10);
        let compile_cpu_secs = max_cpu
            .or(max_time)
            .unwrap_or(original_cpu_secs)
            .max(15);
        let compile_wall_secs = max_wall_time
            .unwrap_or(original_wall_secs)
            .max(30);
        self.instance.config.cpu_time_limit = Some(Duration::from_secs(compile_cpu_secs));
        self.instance.config.time_limit = Some(Duration::from_secs(compile_cpu_secs));
        self.instance.config.wall_time_limit = Some(Duration::from_secs(compile_wall_secs));

        // Compile the code
        let compile_command = vec![
            "/usr/bin/g++".to_string(),
            "-o".to_string(),
            "solution".to_string(),
            "solution.cpp".to_string(),
            "-std=c++17".to_string(),
            "-O2".to_string(),
        ];

        let compile_result = self.execute(&compile_command, None)?;

        if !compile_result.success {
            // Restore original config
            self.instance.config = original_config;
            let status = match compile_result.status {
                crate::config::types::ExecutionStatus::TimeLimit => {
                    crate::config::types::ExecutionStatus::TimeLimit
                }
                crate::config::types::ExecutionStatus::MemoryLimit => {
                    crate::config::types::ExecutionStatus::MemoryLimit
                }
                _ => crate::config::types::ExecutionStatus::RuntimeError,
            };
            let detail = if !compile_result.stderr.trim().is_empty() {
                compile_result.stderr.clone()
            } else if !compile_result.stdout.trim().is_empty() {
                compile_result.stdout.clone()
            } else {
                compile_result
                    .error_message
                    .clone()
                    .unwrap_or_else(|| "no compiler stderr".to_string())
            };
            return Ok(ExecutionResult {
                status,
                exit_code: compile_result.exit_code,
                stdout: "".to_string(),
                stderr: format!("Compilation Error:\n{}", detail),
                wall_time: compile_result.wall_time,
                cpu_time: compile_result.cpu_time,
                memory_peak: compile_result.memory_peak,
                success: false,
                signal: None,
                error_message: Some("Compilation failed".to_string()),
            });
        }

        // Restore runtime isolation contract before executing submission payload.
        self.instance.config = original_config.clone();

        // Execute the compiled binary
        let execute_command = vec!["./solution".to_string()];
        let result = self.execute_with_overrides(
            &execute_command,
            stdin_data,
            max_cpu,
            max_memory,
            max_time,
            max_wall_time,
            fd_limit,
            process_limit,
        );

        // Restore original config
        self.instance.config = original_config;
        result
    }

    /// Compile and execute Java code from string
    fn compile_and_execute_java(
        &mut self,
        code: &str,
        stdin_data: Option<&str>,
        max_cpu: Option<u64>,
        max_memory: Option<u64>,
        max_time: Option<u64>,
        max_wall_time: Option<u64>,
        fd_limit: Option<u64>,
        process_limit: Option<u32>,
    ) -> Result<ExecutionResult> {
        self.ensure_instance_workdir()?;

        // Extract class name from code (simple heuristic)
        let class_name = self
            .extract_java_class_name(code)
            .unwrap_or("Main".to_string());
        let source_file = self
            .instance
            .config
            .workdir
            .join(format!("{}.java", class_name));
        fs::write(&source_file, code)?;

        // Temporarily modify config for Java compilation and execution.
        let original_config = self.instance.config.clone();

        // Keep strict isolation for Java under the proxy/init model.

        // Increase resource limits for JVM
        if let Some(memory) = max_memory {
            self.instance.config.memory_limit = Some(memory * 1024 * 1024);
        } else {
            self.instance.config.memory_limit = Some(512 * 1024 * 1024); // 512MB default for Java
        }

        // JVM/Javac can fan out many threads; too-low pids.max causes hard launch failures.
        // Keep a higher floor while still allowing user overrides to increase further.
        let requested_process_limit = process_limit
            .or(original_config.process_limit)
            .unwrap_or(16);
        self.instance.config.process_limit = Some(requested_process_limit.max(256));

        // Compile the code with relaxed settings
        let compile_command = vec![
            "javac".to_string(),
            "-cp".to_string(),
            ".".to_string(),
            format!("{}.java", class_name),
        ];

        let compile_result = self.execute(&compile_command, None)?;

        if !compile_result.success {
            let status = match compile_result.status {
                crate::config::types::ExecutionStatus::TimeLimit => {
                    crate::config::types::ExecutionStatus::TimeLimit
                }
                crate::config::types::ExecutionStatus::MemoryLimit => {
                    crate::config::types::ExecutionStatus::MemoryLimit
                }
                _ => crate::config::types::ExecutionStatus::RuntimeError,
            };
            let detail = if !compile_result.stderr.trim().is_empty() {
                compile_result.stderr.clone()
            } else if !compile_result.stdout.trim().is_empty() {
                compile_result.stdout.clone()
            } else {
                compile_result
                    .error_message
                    .clone()
                    .unwrap_or_else(|| "no compiler stderr".to_string())
            };
            return Ok(ExecutionResult {
                status,
                exit_code: compile_result.exit_code,
                stdout: "".to_string(),
                stderr: format!("Java Compilation Error:\n{}", detail),
                wall_time: compile_result.wall_time,
                cpu_time: compile_result.cpu_time,
                memory_peak: compile_result.memory_peak,
                success: false,
                signal: None,
                error_message: Some("Java compilation failed".to_string()),
            });
        }

        // Execute the compiled class with relaxed settings
        let execute_command = vec![
            "java".to_string(),
            "-cp".to_string(),
            ".".to_string(),
            class_name,
        ];

        let result = self.execute_with_overrides(
            &execute_command,
            stdin_data,
            max_cpu,
            max_memory,
            max_time,
            max_wall_time,
            fd_limit,
            process_limit,
        );

        result
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
                    return Some(class_name.to_string());
                }
            }
        }
        None
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

        // Clean up filesystem
        if self.base_path.exists() {
            fs::remove_dir_all(&self.base_path).map_err(IsolateError::Io)?;
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
            if binding.target.is_absolute() && binding.target.starts_with("/") {
                // This is good - absolute path in sandbox
            } else {
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
            crate::config::types::LockError::SystemError { message } => IsolateError::Config(message),
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
        // Lock is automatically released when file descriptor is closed
        self.release_lock();
    }
}
