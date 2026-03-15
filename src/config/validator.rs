// Config Validation (P15-CONFIG-002)
// Strict startup validation per plan.md Section 15
// Strict mode must validate config at startup and fail fast with actionable errors

use crate::config::types::{IsolateConfig, IsolateError, Result};
use std::path::Path;

/// Validation result with detailed errors
#[derive(Debug)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl Default for ValidationResult {
    fn default() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

impl ValidationResult {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_error(&mut self, error: String) {
        self.valid = false;
        self.errors.push(error);
    }

    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }
}

/// Validate config at startup
/// Per plan.md Section 15-CONFIG-002: Strict mode must fail fast on invalid config
pub fn validate_config(config: &IsolateConfig) -> Result<ValidationResult> {
    let mut result = ValidationResult::new();

    // Validate limits
    validate_limits(config, &mut result);

    // Validate paths
    validate_paths(config, &mut result);

    // Validate namespace configuration
    validate_namespaces(config, &mut result);

    // Validate UID/GID
    validate_credentials(config, &mut result);

    // Validate mode compatibility
    validate_mode_compatibility(config, &mut result);

    // In strict mode, errors are fatal
    if config.strict_mode && !result.is_valid() {
        let error_msg = format!(
            "Config validation failed in strict mode:\n{}",
            result.errors.join("\n")
        );
        return Err(IsolateError::Config(error_msg));
    }

    Ok(result)
}

/// Validate resource limits
fn validate_limits(config: &IsolateConfig, result: &mut ValidationResult) {
    // Memory limit validation
    if let Some(memory_limit) = config.memory_limit {
        if memory_limit == 0 {
            result.add_error("memory_limit cannot be zero".to_string());
        }
        if memory_limit < 1024 * 1024 {
            result.add_warning(format!(
                "memory_limit {} is very low (< 1MB), may cause OOM",
                memory_limit
            ));
        }
        if memory_limit > 8 * 1024 * 1024 * 1024 {
            result.add_warning(format!(
                "memory_limit {} bytes exceeds recommended maximum of 8GB",
                memory_limit
            ));
        }
    }

    // CPU time limit validation
    if let Some(cpu_time) = config.cpu_time_limit {
        if cpu_time.as_secs() == 0 && cpu_time.subsec_millis() == 0 {
            result.add_error("cpu_time_limit cannot be zero".to_string());
        }
        if cpu_time.as_secs() > 600 {
            result.add_warning(format!(
                "cpu_time_limit {} seconds exceeds recommended maximum of 600 seconds",
                cpu_time.as_secs()
            ));
        }
    }

    // Wall time limit validation
    if let Some(wall_time) = config.wall_time_limit {
        if wall_time.as_secs() == 0 && wall_time.subsec_millis() == 0 {
            result.add_error("wall_time_limit cannot be zero".to_string());
        }
        if wall_time.as_secs() > 600 {
            result.add_warning(format!(
                "wall_time_limit {} seconds exceeds recommended maximum of 600 seconds",
                wall_time.as_secs()
            ));
        }
    }

    // Process limit validation
    if let Some(process_limit) = config.process_limit {
        if process_limit == 0 {
            result.add_error("process_limit cannot be zero".to_string());
        }
        if process_limit > 4096 {
            result.add_warning(format!(
                "process_limit {} exceeds recommended maximum of 4096",
                process_limit
            ));
        }
    }

    // Validate wall time >= cpu time (if both set)
    if let (Some(cpu_time), Some(wall_time)) = (config.cpu_time_limit, config.wall_time_limit) {
        if wall_time < cpu_time {
            result.add_error(format!(
                "wall_time_limit ({:?}) must be >= cpu_time_limit ({:?})",
                wall_time, cpu_time
            ));
        }
    }
}

/// Validate paths
fn validate_paths(config: &IsolateConfig, result: &mut ValidationResult) {
    // Validate workdir
    if !config.workdir.is_absolute() {
        result.add_error(format!(
            "workdir must be absolute path: {:?}",
            config.workdir
        ));
    }

    // Validate chroot_dir if set
    if let Some(ref chroot_dir) = config.chroot_dir {
        if !chroot_dir.is_absolute() {
            result.add_error(format!(
                "chroot_dir must be absolute path: {:?}",
                chroot_dir
            ));
        }

        if !chroot_dir.exists() {
            result.add_warning(format!("chroot_dir does not exist: {:?}", chroot_dir));
        }
    }

    // Validate stdin_file if set
    if let Some(ref stdin_file) = config.stdin_file {
        if stdin_file.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            result.add_error(format!(
                "stdin_file contains path traversal: {:?}", stdin_file
            ));
        }
    }

    // Validate stdout_file if set
    if let Some(ref stdout_file) = config.stdout_file {
        if stdout_file.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            result.add_error(format!(
                "stdout_file contains path traversal: {:?}", stdout_file
            ));
        }
        if let Some(parent) = stdout_file.parent() {
            if !parent.exists() {
                result.add_error(format!(
                    "stdout_file parent directory does not exist: {:?}",
                    parent
                ));
            }
        }
    }

    // Validate stderr_file if set
    if let Some(ref stderr_file) = config.stderr_file {
        if stderr_file.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            result.add_error(format!(
                "stderr_file contains path traversal: {:?}", stderr_file
            ));
        }
        if let Some(parent) = stderr_file.parent() {
            if !parent.exists() {
                result.add_error(format!(
                    "stderr_file parent directory does not exist: {:?}",
                    parent
                ));
            }
        }
    }
}

/// Validate namespace configuration
fn validate_namespaces(config: &IsolateConfig, result: &mut ValidationResult) {
    // In strict mode, PID and mount namespaces are mandatory for judge-v1
    if config.strict_mode {
        if !config.enable_pid_namespace {
            result.add_error(
                "enable_pid_namespace must be true in strict mode (judge-v1 requirement)"
                    .to_string(),
            );
        }

        if !config.enable_mount_namespace {
            result.add_error(
                "enable_mount_namespace must be true in strict mode (judge-v1 requirement)"
                    .to_string(),
            );
        }

        if !config.enable_network_namespace {
            result.add_error(
                "enable_network_namespace must be true in strict mode".to_string(),
            );
        }
    }

    // User namespace validation
    if config.enable_user_namespace {
        result.add_warning(
            "User namespace is not fully supported in judge-v1 GA (rootful strict is the target)"
                .to_string(),
        );
    }
}

/// Validate credentials
fn validate_credentials(config: &IsolateConfig, result: &mut ValidationResult) {
    // In strict mode, UID/GID must be set for unprivileged execution.
    if config.strict_mode {
        if config.uid.is_none() {
            result.add_error(
                "uid must be set in strict mode for unprivileged payload execution".to_string(),
            );
        }

        if config.gid.is_none() {
            result.add_error(
                "gid must be set in strict mode for unprivileged payload execution".to_string(),
            );
        }

        // Validate UID/GID are not root
        if let Some(uid) = config.uid {
            if uid == 0 {
                result.add_error(
                    "uid cannot be 0 (root) for untrusted payload in strict mode".to_string(),
                );
            }
        }

        if let Some(gid) = config.gid {
            if gid == 0 {
                result.add_error(
                    "gid cannot be 0 (root) for untrusted payload in strict mode".to_string(),
                );
            }
        }
    }
}

/// Validate mode compatibility flags
fn validate_mode_compatibility(config: &IsolateConfig, result: &mut ValidationResult) {
    if config.strict_mode && config.allow_degraded {
        result.add_error(
            "allow_degraded is incompatible with strict mode".to_string(),
        );
    }
}

/// Check if required controls are available on this system
pub fn check_system_capabilities() -> Result<Vec<String>> {
    let mut missing = Vec::new();

    // Check if cgroups are available
    if !Path::new("/sys/fs/cgroup").exists() {
        missing.push("cgroups not available".to_string());
    }

    // Check if namespaces are available (Linux-specific)
    #[cfg(target_os = "linux")]
    {
        if !Path::new("/proc/self/ns").exists() {
            missing.push("namespaces not available".to_string());
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        missing.push("Linux-only features not available on this platform".to_string());
    }

    Ok(missing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_valid_default_config() {
        let config = IsolateConfig::default();
        let result = validate_config(&config);

        // Default config should be valid (may have warnings)
        assert!(result.is_ok());
    }

    #[test]
    fn test_zero_memory_limit() {
        let config = IsolateConfig {
            memory_limit: Some(0),
            strict_mode: false, // Permissive to get ValidationResult
            ..IsolateConfig::default()
        };

        let result = validate_config(&config).unwrap();
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("memory_limit cannot be zero")));
    }

    #[test]
    fn test_zero_cpu_time_limit() {
        let config = IsolateConfig {
            cpu_time_limit: Some(Duration::from_secs(0)),
            strict_mode: false,
            ..IsolateConfig::default()
        };

        let result = validate_config(&config).unwrap();
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("cpu_time_limit cannot be zero")));
    }

    #[test]
    fn test_wall_time_less_than_cpu_time() {
        let config = IsolateConfig {
            cpu_time_limit: Some(Duration::from_secs(10)),
            wall_time_limit: Some(Duration::from_secs(5)),
            strict_mode: false,
            ..IsolateConfig::default()
        };

        let result = validate_config(&config).unwrap();
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("wall_time_limit") && e.contains("cpu_time_limit")));
    }

    #[test]
    fn test_root_uid_rejected_in_strict_mode() {
        let config = IsolateConfig {
            uid: Some(0),
            ..IsolateConfig::default()
        };

        let result = validate_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_root_gid_rejected_in_strict_mode() {
        let config = IsolateConfig {
            gid: Some(0),
            ..IsolateConfig::default()
        };

        let result = validate_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_uid_rejected_in_strict_mode() {
        let config = IsolateConfig {
            uid: None,
            ..IsolateConfig::default()
        };

        let result = validate_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_gid_rejected_in_strict_mode() {
        let config = IsolateConfig {
            gid: None,
            ..IsolateConfig::default()
        };

        let result = validate_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_pid_namespace_in_strict_mode() {
        let config = IsolateConfig {
            enable_pid_namespace: false,
            ..IsolateConfig::default()
        };

        let result = validate_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_mount_namespace_in_strict_mode() {
        let config = IsolateConfig {
            enable_mount_namespace: false,
            ..IsolateConfig::default()
        };

        let result = validate_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_allow_degraded_incompatible_with_strict() {
        let config = IsolateConfig {
            strict_mode: true,
            allow_degraded: true,
            ..IsolateConfig::default()
        };

        let result = validate_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_allow_degraded_ok_in_permissive() {
        let config = IsolateConfig {
            strict_mode: false,
            allow_degraded: true,
            ..IsolateConfig::default()
        };

        let result = validate_config(&config).unwrap();
        assert!(
            !result.errors.iter().any(|e| e.contains("allow_degraded")),
            "allow_degraded should be accepted in permissive mode"
        );
    }

    #[test]
    fn test_upper_bound_memory_warning() {
        let config = IsolateConfig {
            memory_limit: Some(16 * 1024 * 1024 * 1024), // 16GB
            strict_mode: false,
            ..IsolateConfig::default()
        };

        let result = validate_config(&config).unwrap();
        assert!(result.warnings.iter().any(|w| w.contains("8GB")));
    }

    #[test]
    fn test_upper_bound_process_warning() {
        let config = IsolateConfig {
            process_limit: Some(10000),
            strict_mode: false,
            ..IsolateConfig::default()
        };

        let result = validate_config(&config).unwrap();
        assert!(result.warnings.iter().any(|w| w.contains("4096")));
    }

    #[test]
    fn test_upper_bound_time_warning() {
        let config = IsolateConfig {
            cpu_time_limit: Some(Duration::from_secs(1000)),
            strict_mode: false,
            ..IsolateConfig::default()
        };

        let result = validate_config(&config).unwrap();
        assert!(result.warnings.iter().any(|w| w.contains("600 seconds")));
    }

    #[test]
    fn test_check_system_capabilities() {
        let missing = check_system_capabilities().unwrap();

        // If the path exists on this machine it must NOT be reported missing.
        if Path::new("/sys/fs/cgroup").exists() {
            assert!(
                !missing.iter().any(|m| m.contains("cgroups")),
                "cgroups reported missing but /sys/fs/cgroup exists: {:?}",
                missing
            );
        }

        #[cfg(target_os = "linux")]
        if Path::new("/proc/self/ns").exists() {
            assert!(
                !missing.iter().any(|m| m.contains("namespaces")),
                "namespaces reported missing but /proc/self/ns exists: {:?}",
                missing
            );
        }
    }
}
