/// Process execution and monitoring with reliable resource limits
use crate::cgroup::Cgroup;
use crate::filesystem::FilesystemSecurity;
use crate::security::command_validation;
use crate::security_logging::events;
use crate::types::{ExecutionResult, ExecutionStatus, IsolateConfig, IsolateError, Result};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

/// Process executor that handles isolation and monitoring with focus on reliability
pub struct ProcessExecutor {
    config: IsolateConfig,
    cgroup: Option<Cgroup>,
    filesystem_security: FilesystemSecurity,
}

impl ProcessExecutor {
    /// Create a new process executor
    pub fn new(config: IsolateConfig) -> Result<Self> {
        let cgroup = if crate::cgroup::cgroups_available() {
            match Cgroup::new(&config.instance_id, config.strict_mode) {
                Ok(cgroup) => Some(cgroup),
                Err(e) => {
                    eprintln!("Failed to create cgroup controller: {:?}", e);
                    if config.strict_mode {
                        return Err(e);
                    } else {
                        eprintln!("⚠️  WARNING: Resource monitoring disabled - this is unsafe for untrusted code");
                        None
                    }
                }
            }
        } else {
            if config.strict_mode {
                return Err(IsolateError::Cgroup(
                    "Cgroups required for reliable resource monitoring in strict mode".to_string(),
                ));
            }
            eprintln!("⚠️  WARNING: Cgroups unavailable - resource monitoring disabled");
            eprintln!("   This configuration is UNSAFE for untrusted code execution");
            None
        };

        // Create filesystem security controller
        let filesystem_security = FilesystemSecurity::new(
            config.chroot_dir.clone(),
            config.workdir.clone(),
            config.strict_mode,
        );

        // Set up filesystem isolation if chroot is specified
        if config.chroot_dir.is_some() {
            filesystem_security.setup_isolation()?;
        }

        // Set up directory bindings
        if !config.directory_bindings.is_empty() {
            filesystem_security.setup_directory_bindings(&config.directory_bindings)?;
        }

        Ok(Self {
            config,
            cgroup,
            filesystem_security,
        })
    }

    /// Setup resource limits using cgroups only
    fn setup_resource_limits(&self) -> Result<()> {
        if let Some(ref cgroup) = self.cgroup {
            // Set memory limit
            if let Some(memory_limit) = self.config.memory_limit {
                cgroup.set_memory_limit(memory_limit)?;
            }

            // Set process limit
            if let Some(process_limit) = self.config.process_limit {
                cgroup.set_process_limit(process_limit as u64)?;
            }

            // Set CPU shares
            cgroup.set_cpu_limit(1024)?;

            // Validate that resource monitoring is working
            self.validate_resource_monitoring()?;
        } else if self.config.strict_mode {
            return Err(IsolateError::Cgroup(
                "Resource limits cannot be enforced without cgroups".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate command for security before execution
    fn validate_command(&self, command: &[String]) -> Result<PathBuf> {
        if command.is_empty() {
            return Err(IsolateError::Config("Empty command provided".to_string()));
        }

        // Use security module to validate and resolve command
        match command_validation::validate_and_resolve_command(&command[0]) {
            Ok(path) => Ok(path),
            Err(e) => {
                // Log security event for command injection attempt
                let box_id = self.config.instance_id.parse::<u32>().ok();
                events::command_injection_attempt(command[0].clone(), box_id);
                Err(e)
            }
        }
    }

    /// Validate that resource monitoring is working properly
    fn validate_resource_monitoring(&self) -> Result<()> {
        if let Some(ref cgroup) = self.cgroup {
            // Test that we can read basic cgroup files
            let _ = cgroup
                .get_cpu_usage()
                .map_err(|_| IsolateError::Cgroup("CPU monitoring not functional".to_string()))?;

            let _ = cgroup.get_peak_memory_usage().map_err(|_| {
                IsolateError::Cgroup("Memory monitoring not functional".to_string())
            })?;

            // Verify memory limit was set if configured
            if let Some(expected_limit) = self.config.memory_limit {
                if let Ok((_, _, actual_limit)) = cgroup.get_memory_stats() {
                    if actual_limit == u64::MAX || actual_limit < expected_limit {
                        return Err(IsolateError::Cgroup(
                            "Memory limit not properly configured".to_string(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Execute a command with isolation
    pub fn execute(
        &mut self,
        command: &[String],
        stdin_data: Option<&str>,
    ) -> Result<ExecutionResult> {
        self.execute_single_process(command, stdin_data)
    }

    /// Execute a command with minimal isolation for maximum reliability
    pub fn execute_single_process(
        &mut self,
        command: &[String],
        stdin_data: Option<&str>,
    ) -> Result<ExecutionResult> {
        if command.is_empty() {
            return Err(IsolateError::Config("Empty command provided".to_string()));
        }

        let start_time = Instant::now();

        // Validate command for security BEFORE any execution
        let validated_command = self.validate_command(command)?;

        // Setup resource limits
        self.setup_resource_limits()?;

        // Create the command with validated executable path
        let mut cmd = Command::new(validated_command);
        if command.len() > 1 {
            cmd.args(&command[1..]);
        }

        // Determine the working directory
        // If we have directory bindings, use the first one as the working directory
        // This allows commands to reference files in the bound directory directly
        let effective_workdir = if !self.config.directory_bindings.is_empty() {
            &self.config.directory_bindings[0].target
        } else {
            &self.config.workdir
        };

        // Configure basic I/O
        cmd.current_dir(effective_workdir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Set basic environment
        cmd.env_clear();
        cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin");

        // Set Java environment if needed
        if std::path::Path::new("/usr/lib/jvm/java-17-openjdk-amd64").exists() {
            cmd.env("JAVA_HOME", "/usr/lib/jvm/java-17-openjdk-amd64");
        }

        // Set Go environment if needed
        if std::path::Path::new("/usr/lib/go-1.22").exists() {
            cmd.env("GOROOT", "/usr/lib/go-1.22");
            cmd.env("GOCACHE", "/tmp/gocache");
            cmd.env("GOPATH", "/tmp/gopath");
        }

        // Add custom environment variables
        for (key, value) in &self.config.environment {
            cmd.env(key, value);
        }

        // Setup resource limits using rlimits in pre_exec hook
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let config_clone = self.config.clone();
            let filesystem_security = self.filesystem_security.clone();
            unsafe {
                cmd.pre_exec(move || {
                    // Apply filesystem isolation (chroot) first if configured
                    if config_clone.chroot_dir.is_some() {
                        if let Err(e) = filesystem_security.apply_chroot() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                format!("Failed to apply chroot: {}", e),
                            ));
                        }
                    }

                    // Set file descriptor limit if specified
                    if let Some(fd_limit) = config_clone.fd_limit {
                        #[cfg(unix)]
                        use nix::sys::resource::{setrlimit, Resource};
                        setrlimit(Resource::RLIMIT_NOFILE, fd_limit, fd_limit).map_err(|e| {
                            std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("setrlimit failed: {}", e),
                            )
                        })?;
                    }

                    Ok(())
                });
            }
        }

        // Start the process
        let mut child = cmd
            .spawn()
            .map_err(|e| IsolateError::Process(format!("Failed to start process: {}", e)))?;

        let pid = child.id();

        // Add process to cgroup after spawning
        if let Some(ref cgroup) = self.cgroup {
            cgroup.add_process(pid)?;
        }

        // Handle stdin
        if let Some(data) = stdin_data {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(data.as_bytes());
                drop(stdin); // Close stdin
            }
        }

        // Wait for process with timeout
        let wall_time_limit = self
            .config
            .wall_time_limit
            .unwrap_or(Duration::from_secs(30));

        self.wait_with_timeout(child, wall_time_limit, start_time, pid)
    }

    /// Simple and reliable timeout implementation with proper CPU time monitoring
    fn wait_with_timeout(
        &self,
        mut child: std::process::Child,
        timeout: Duration,
        start_time: Instant,
        pid: u32,
    ) -> Result<ExecutionResult> {
        let child_id = child.id();
        let timeout_start = Instant::now();

        // Check if we have a CPU time limit
        let cpu_time_limit = self.config.cpu_time_limit;

        // Create streams for non-blocking output collection
        let stdout_stream = child.stdout.take();
        let stderr_stream = child.stderr.take();

        // Start background threads to collect output without blocking
        let mut stdout_handle = if let Some(mut stdout) = stdout_stream {
            Some(thread::spawn(move || {
                let mut buffer = Vec::new();
                let _ = stdout.read_to_end(&mut buffer);
                buffer
            }))
        } else {
            None
        };

        let mut stderr_handle = if let Some(mut stderr) = stderr_stream {
            Some(thread::spawn(move || {
                let mut buffer = Vec::new();
                let _ = stderr.read_to_end(&mut buffer);
                buffer
            }))
        } else {
            None
        };

        // Simple polling loop with optimized timing
        loop {
            match child.try_wait() {
                Ok(Some(exit_status)) => {
                    // Process completed - collect output from background threads
                    let stdout = if let Some(handle) = stdout_handle.take() {
                        handle.join().unwrap_or_default()
                    } else {
                        Vec::new()
                    };

                    let stderr = if let Some(handle) = stderr_handle.take() {
                        handle.join().unwrap_or_default()
                    } else {
                        Vec::new()
                    };

                    let wall_time = start_time.elapsed().as_secs_f64();
                    let (cpu_time, memory_peak) = self.get_resource_usage(pid);

                    return Ok(ExecutionResult {
                        exit_code: exit_status.code(),
                        status: if exit_status.success() {
                            ExecutionStatus::Success
                        } else {
                            ExecutionStatus::RuntimeError
                        },
                        stdout: String::from_utf8_lossy(&stdout).to_string(),
                        stderr: String::from_utf8_lossy(&stderr).to_string(),
                        cpu_time,
                        wall_time,
                        memory_peak,
                        signal: {
                            #[cfg(unix)]
                            {
                                exit_status.signal()
                            }
                            #[cfg(not(unix))]
                            {
                                None
                            }
                        },
                        success: exit_status.success(),
                        error_message: None,
                    });
                }
                Ok(None) => {
                    // Process still running - check limits
                    let elapsed = timeout_start.elapsed();
                    let (cpu_time, memory_peak) = self.get_resource_usage(pid);

                    // Check resource limits using cgroups exclusively
                    if let Some(ref cgroup) = self.cgroup {
                        let (memory_limited, _cpu_limited) = cgroup.is_resource_limited();

                        if memory_limited {
                            // Memory limit exceeded - log security event
                            let box_id = self.config.instance_id.parse::<u32>().ok();
                            events::resource_limit_exceeded(
                                "memory".to_string(),
                                self.config
                                    .memory_limit
                                    .map(|m| format!("{} bytes", m))
                                    .unwrap_or_else(|| "unknown".to_string()),
                                box_id,
                            );

                            self.terminate_process(child_id);
                            let _ = child.wait();

                            // Suppress output for memory limit violations
                            let _ = if let Some(handle) = stdout_handle.take() {
                                handle.join()
                            } else {
                                Ok(Vec::new())
                            };

                            let _ = if let Some(handle) = stderr_handle.take() {
                                handle.join()
                            } else {
                                Ok(Vec::new())
                            };

                            let wall_time = start_time.elapsed().as_secs_f64();

                            return Ok(ExecutionResult {
                                exit_code: None,
                                status: ExecutionStatus::MemoryLimit,
                                stdout: String::new(),
                                stderr: String::new(),
                                cpu_time,
                                wall_time,
                                memory_peak,
                                signal: Some(9), // SIGKILL
                                success: false,
                                error_message: Some("Memory Limit Exceeded".to_string()),
                            });
                        }
                    }

                    // Check CPU time limit
                    if let Some(cpu_limit) = cpu_time_limit {
                        if cpu_time >= cpu_limit.as_secs_f64() {
                            // CPU time limit exceeded
                            self.terminate_process(child_id);
                            let _ = child.wait();

                            // Suppress output for time limit violations
                            let _ = if let Some(handle) = stdout_handle.take() {
                                handle.join()
                            } else {
                                Ok(Vec::new())
                            };

                            let _ = if let Some(handle) = stderr_handle.take() {
                                handle.join()
                            } else {
                                Ok(Vec::new())
                            };

                            let wall_time = start_time.elapsed().as_secs_f64();

                            return Ok(ExecutionResult {
                                exit_code: None,
                                status: ExecutionStatus::TimeLimit,
                                stdout: String::new(),
                                stderr: String::new(),
                                cpu_time,
                                wall_time,
                                memory_peak,
                                signal: Some(9), // SIGKILL
                                success: false,
                                error_message: Some("Time Limit Exceeded".to_string()),
                            });
                        }
                    }

                    // Check wall time limit
                    if elapsed >= timeout {
                        // Wall time limit exceeded
                        self.terminate_process(child_id);
                        let _ = child.wait();

                        // Suppress output for wall time limit violations
                        let _ = if let Some(handle) = stdout_handle.take() {
                            handle.join()
                        } else {
                            Ok(Vec::new())
                        };

                        let _ = if let Some(handle) = stderr_handle.take() {
                            handle.join()
                        } else {
                            Ok(Vec::new())
                        };

                        let wall_time = start_time.elapsed().as_secs_f64();
                        let (cpu_time, memory_peak) = self.get_resource_usage(pid);

                        return Ok(ExecutionResult {
                            exit_code: None,
                            status: ExecutionStatus::TimeLimit,
                            stdout: String::new(),
                            stderr: String::new(),
                            cpu_time,
                            wall_time,
                            memory_peak,
                            signal: Some(9), // SIGKILL
                            success: false,
                            error_message: Some("Time Limit Exceeded".to_string()),
                        });
                    }

                    // Brief sleep only when process is still running to avoid busy waiting
                    thread::sleep(Duration::from_millis(1));
                }
                Err(e) => {
                    return Err(IsolateError::Process(format!(
                        "Process monitoring error: {}",
                        e
                    )));
                }
            }
        }
    }

    /// Terminate a process gracefully then forcefully
    fn terminate_process(&self, pid: u32) {
        #[cfg(unix)]
        unsafe {
            // Send SIGTERM first
            libc::kill(pid as i32, libc::SIGTERM);
        }

        // Wait a bit for graceful shutdown
        thread::sleep(Duration::from_millis(100));

        #[cfg(unix)]
        unsafe {
            // Send SIGKILL if still running
            libc::kill(pid as i32, libc::SIGKILL);
        }
    }

    /// Get resource usage exclusively from cgroups for security and reliability
    fn get_resource_usage(&self, _pid: u32) -> (f64, u64) {
        if let Some(ref cgroup) = self.cgroup {
            let (cpu_time, memory_peak, _oom_killed) = cgroup.get_resource_stats();
            (cpu_time, memory_peak)
        } else {
            // Without cgroups, we cannot reliably monitor resources
            // This is a security risk for untrusted code execution
            (0.0, 0)
        }
    }

    /// Cleanup resources
    pub fn cleanup(&mut self) -> Result<()> {
        if let Some(cgroup) = self.cgroup.take() {
            cgroup.cleanup()?;
        }
        Ok(())
    }
}
