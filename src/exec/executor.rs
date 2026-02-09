use crate::config::types::{ExecutionResult, IsolateConfig, IsolateError, Result};
use crate::config::validator::validate_config;
use crate::core::types::{LaunchEvidence, SandboxLaunchRequest};
/// Process execution and monitoring with reliable resource limits
use crate::kernel::cgroup::backend::{self, CgroupBackend};
use crate::observability::audit::events;
use crate::runtime::security::command_validation;
use crate::safety::cleanup::BaselineChecker;
use std::path::PathBuf;

/// Process executor that handles isolation and monitoring with focus on reliability
pub struct ProcessExecutor {
    config: IsolateConfig,
    cgroup: Option<Box<dyn CgroupBackend>>,
    last_launch_evidence: Option<LaunchEvidence>,
    baseline_checker: Option<BaselineChecker>,
    baseline_capture_error: Option<String>,
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

        // Capture host-clean baseline before creating execution-time resources.
        let (baseline_checker, baseline_capture_error) = match BaselineChecker::capture_baseline() {
            Ok(checker) => (Some(checker), None),
            Err(err) => (None, Some(err.to_string())),
        };

        let cgroup = match backend::create_cgroup_backend(
            config.force_cgroup_v1,
            config.strict_mode,
            &config.instance_id,
        ) {
            Ok(cgroup) => {
                if let Err(e) = cgroup.create(&config.instance_id) {
                    eprintln!(
                        "Failed to create cgroup instance '{}': {:?}",
                        config.instance_id, e
                    );
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

        Ok(Self {
            config,
            cgroup,
            last_launch_evidence: None,
            baseline_checker,
            baseline_capture_error,
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

        let outcome =
            crate::core::supervisor::launch_with_supervisor(request, self.cgroup.as_deref())?;
        let mut evidence = outcome.evidence.clone();
        let mut cleanup_verified = true;

        if let Some(err) = self.baseline_capture_error.take() {
            cleanup_verified = false;
            evidence
                .evidence_collection_errors
                .push(format!("baseline_capture: {err}"));
        }

        if let Err(err) = self.cleanup() {
            cleanup_verified = false;
            evidence
                .evidence_collection_errors
                .push(format!("executor_cleanup: {err}"));
        }

        match self.baseline_checker.take() {
            Some(checker) => {
                if let Err(err) = checker.verify_baseline() {
                    cleanup_verified = false;
                    evidence
                        .evidence_collection_errors
                        .push(format!("baseline_verification: {err}"));
                }
            }
            None => cleanup_verified = false,
        }

        evidence.cleanup_verified = cleanup_verified;
        if !cleanup_verified {
            evidence.process_lifecycle.descendant_containment =
                "baseline_verification_failed".to_string();
        }

        self.last_launch_evidence = Some(evidence);
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

impl Drop for ProcessExecutor {
    fn drop(&mut self) {
        // Best-effort safety net: cleanup must still run when execute()
        // returns early before explicit cleanup paths.
        if self.cgroup.is_some() {
            if let Err(err) = self.cleanup() {
                log::warn!(
                    "ProcessExecutor drop cleanup failed for {}: {}",
                    self.config.instance_id,
                    err
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::CgroupEvidence;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct MockCgroupBackend {
        remove_calls: Arc<AtomicUsize>,
    }

    impl CgroupBackend for MockCgroupBackend {
        fn backend_name(&self) -> &str {
            "mock"
        }

        fn create(&self, _instance_id: &str) -> Result<()> {
            Ok(())
        }

        fn remove(&self, _instance_id: &str) -> Result<()> {
            self.remove_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn attach_process(&self, _instance_id: &str, _pid: u32) -> Result<()> {
            Ok(())
        }

        fn set_memory_limit(&self, _instance_id: &str, _limit_bytes: u64) -> Result<()> {
            Ok(())
        }

        fn set_process_limit(&self, _instance_id: &str, _limit: u32) -> Result<()> {
            Ok(())
        }

        fn set_cpu_limit(&self, _instance_id: &str, _limit_usec: u64) -> Result<()> {
            Ok(())
        }

        fn get_memory_usage(&self) -> Result<u64> {
            Ok(0)
        }

        fn get_memory_peak(&self) -> Result<u64> {
            Ok(0)
        }

        fn get_cpu_usage(&self) -> Result<u64> {
            Ok(0)
        }

        fn get_process_count(&self) -> Result<u32> {
            Ok(0)
        }

        fn check_oom(&self) -> Result<bool> {
            Ok(false)
        }

        fn get_oom_kill_count(&self) -> Result<u64> {
            Ok(0)
        }

        fn collect_evidence(&self, _instance_id: &str) -> Result<CgroupEvidence> {
            Ok(CgroupEvidence {
                memory_peak: None,
                memory_limit: None,
                oom_events: 0,
                oom_kill_events: 0,
                cpu_usage_usec: None,
                process_count: None,
                process_limit: None,
            })
        }

        fn get_cgroup_path(&self, _instance_id: &str) -> PathBuf {
            PathBuf::from("/tmp/mock-cgroup")
        }

        fn is_empty(&self) -> Result<bool> {
            Ok(true)
        }
    }

    #[test]
    fn drop_runs_cleanup_after_early_execution_error() {
        let remove_calls = Arc::new(AtomicUsize::new(0));

        {
            let mut config = IsolateConfig::default();
            config.instance_id = "drop-cleanup-test".to_string();

            let mut executor = ProcessExecutor {
                config,
                cgroup: Some(Box::new(MockCgroupBackend {
                    remove_calls: remove_calls.clone(),
                })),
                last_launch_evidence: None,
                baseline_checker: None,
                baseline_capture_error: None,
            };

            // Empty argv is rejected before explicit execute() cleanup path.
            let result = executor.execute_single_process(&[], None);
            assert!(result.is_err());
        }

        assert_eq!(remove_calls.load(Ordering::SeqCst), 1);
    }
}
