/// Process execution and monitoring with reliable resource limits
use crate::kernel::cgroup::backend::{self, CgroupBackend};
use crate::kernel::mount::filesystem::FilesystemSecurity;
use crate::legacy::security::command_validation;
use crate::observability::audit::events;
use crate::config::validator::validate_config;
use crate::config::types::{ExecutionResult, IsolateConfig, IsolateError, Result};
use crate::core::types::{LaunchEvidence, SandboxLaunchRequest};
use std::path::PathBuf;

/// Process executor that handles isolation and monitoring with focus on reliability
pub struct ProcessExecutor {
    config: IsolateConfig,
    cgroup: Option<Box<dyn CgroupBackend>>,
    last_launch_evidence: Option<LaunchEvidence>,
}

impl ProcessExecutor {
    /// Create a new process executor
    pub fn new(config: IsolateConfig) -> Result<Self> {
        // Strict mode is fail-closed and requires elevated privileges.
        if config.strict_mode && unsafe { libc::geteuid() } != 0 {
            return Err(IsolateError::Privilege(
                "Strict mode requires root privileges".to_string(),
            ));
        }

        // Validate config-to-enforcement contract before any runtime setup.
        // In strict mode this fails fast on invalid/unsafe configuration.
        let validation = validate_config(&config)?;
        for warning in validation.warnings {
            log::warn!("Configuration warning: {}", warning);
        }

        // Syscall filtering is explicit opt-in and currently fail-closed until
        // seccomp-bpf installation is fully implemented.
        if config.enable_syscall_filtering {
            let msg =
                "Syscall filtering requested but seccomp-bpf installation is not implemented";
            if config.strict_mode {
                return Err(IsolateError::Privilege(msg.to_string()));
            }
            return Err(IsolateError::Config(format!("{} (permissive mode)", msg)));
        }

        let cgroup = match backend::create_cgroup_backend(false, config.strict_mode, &config.instance_id)
        {
            Ok(cgroup) => {
                if let Err(e) = cgroup.create(&config.instance_id) {
                    eprintln!("Failed to create cgroup instance '{}': {:?}", config.instance_id, e);
                    if config.strict_mode {
                        return Err(e);
                    }
                    eprintln!("⚠️  WARNING: Resource monitoring disabled - this is unsafe for untrusted code");
                    None
                } else {
                    Some(cgroup)
                }
            }
            Err(e) => {
                eprintln!("Failed to initialize cgroup backend: {:?}", e);
                if config.strict_mode {
                    return Err(e);
                }
                eprintln!("⚠️  WARNING: Cgroups unavailable - resource monitoring disabled");
                eprintln!("   This configuration is UNSAFE for untrusted code execution");
                None
            }
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
            last_launch_evidence: None,
        })
    }

    /// Setup resource limits using cgroups only
    fn setup_resource_limits(&self) -> Result<()> {
        if let Some(ref cgroup) = self.cgroup {
            // Set memory limit
            if let Some(memory_limit) = self.config.memory_limit {
                cgroup.set_memory_limit(&self.config.instance_id, memory_limit)?;
            }

            // Set process limit
            if let Some(process_limit) = self.config.process_limit {
                cgroup.set_process_limit(&self.config.instance_id, process_limit)?;
            }

            // Set CPU shares
            cgroup.set_cpu_limit(&self.config.instance_id, 1024)?;

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

            let _ = cgroup.get_memory_peak().map_err(|_| {
                IsolateError::Cgroup("Memory monitoring not functional".to_string())
            })?;
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

        // Validate command for security BEFORE any execution
        let validated_command = self.validate_command(command)?;
        let mut argv = vec![validated_command.to_string_lossy().to_string()];
        argv.extend(command.iter().skip(1).cloned());

        // Setup resource limits
        self.setup_resource_limits()?;

        let request = SandboxLaunchRequest::from_config(
            &self.config,
            &argv,
            stdin_data,
            self.cgroup
                .as_ref()
                .map(|cg| cg.get_cgroup_path(&self.config.instance_id)),
        );

        let outcome = crate::core::supervisor::launch_with_supervisor(
            request,
            self.cgroup.as_deref(),
        )?;
        self.last_launch_evidence = Some(outcome.evidence.clone());
        Ok(outcome.result)
    }

    pub fn take_launch_evidence(&mut self) -> Option<LaunchEvidence> {
        self.last_launch_evidence.take()
    }

    /// Cleanup resources
    pub fn cleanup(&mut self) -> Result<()> {
        if let Some(cgroup) = self.cgroup.take() {
            cgroup.remove(&self.config.instance_id)?;
        }
        Ok(())
    }
}
