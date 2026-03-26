use crate::config::types::{IsolateConfig, IsolateError, Result};
use std::path::Path;

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

pub fn validate_config(config: &IsolateConfig) -> Result<ValidationResult> {
    let mut result = ValidationResult::new();
    validate_limits(config, &mut result);
    validate_paths(config, &mut result);
    validate_namespaces(config, &mut result);
    validate_credentials(config, &mut result);
    validate_mode_compatibility(config, &mut result);

    if config.strict_mode && !result.is_valid() {
        return Err(IsolateError::Config(format!(
            "Config validation failed in strict mode:\n{}",
            result.errors.join("\n")
        )));
    }
    Ok(result)
}

fn validate_limits(config: &IsolateConfig, result: &mut ValidationResult) {
    if let Some(v) = config.memory_limit {
        if v == 0 {
            result.add_error("memory_limit cannot be zero".into());
        }
        if v < 1024 * 1024 {
            result.add_warning(format!(
                "memory_limit {} is very low (< 1MB), may cause OOM",
                v
            ));
        }
        if v > 8 * 1024 * 1024 * 1024 {
            result.add_warning(format!(
                "memory_limit {} bytes exceeds recommended maximum of 8GB",
                v
            ));
        }
    }

    for (name, limit) in [
        ("cpu_time_limit", config.cpu_time_limit),
        ("wall_time_limit", config.wall_time_limit),
    ] {
        if let Some(t) = limit {
            if t.is_zero() {
                result.add_error(format!("{} cannot be zero", name));
            }
            if t.as_secs() > 600 {
                result.add_warning(format!(
                    "{} {} seconds exceeds recommended maximum of 600 seconds",
                    name,
                    t.as_secs()
                ));
            }
        }
    }

    if let Some(v) = config.process_limit {
        if v == 0 {
            result.add_error("process_limit cannot be zero".into());
        }
        if v > 4096 {
            result.add_warning(format!(
                "process_limit {} exceeds recommended maximum of 4096",
                v
            ));
        }
    }

    if let (Some(cpu), Some(wall)) = (config.cpu_time_limit, config.wall_time_limit) {
        if wall < cpu {
            result.add_error(format!(
                "wall_time_limit ({:?}) must be >= cpu_time_limit ({:?})",
                wall, cpu
            ));
        }
    }
}

fn check_path_traversal(path: &Path, name: &str, result: &mut ValidationResult) {
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        result.add_error(format!("{} contains path traversal: {:?}", name, path));
    }
}

fn check_parent_exists(path: &Path, name: &str, result: &mut ValidationResult) {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            result.add_error(format!(
                "{} parent directory does not exist: {:?}",
                name, parent
            ));
        }
    }
}

fn validate_paths(config: &IsolateConfig, result: &mut ValidationResult) {
    if !config.workdir.is_absolute() {
        result.add_error(format!(
            "workdir must be absolute path: {:?}",
            config.workdir
        ));
    }

    if let Some(ref p) = config.chroot_dir {
        if !p.is_absolute() {
            result.add_error(format!("chroot_dir must be absolute path: {:?}", p));
        }
        if !p.exists() {
            result.add_warning(format!("chroot_dir does not exist: {:?}", p));
        }
    }

    if let Some(ref p) = config.stdin_file {
        check_path_traversal(p, "stdin_file", result);
    }
    for (name, path) in [
        ("stdout_file", &config.stdout_file),
        ("stderr_file", &config.stderr_file),
    ] {
        if let Some(ref p) = path {
            check_path_traversal(p, name, result);
            check_parent_exists(p, name, result);
        }
    }
}

fn validate_namespaces(config: &IsolateConfig, result: &mut ValidationResult) {
    if config.strict_mode {
        for (enabled, msg) in [
            (
                config.enable_pid_namespace,
                "enable_pid_namespace must be true in strict mode (judge-v1 requirement)",
            ),
            (
                config.enable_mount_namespace,
                "enable_mount_namespace must be true in strict mode (judge-v1 requirement)",
            ),
            (
                config.enable_network_namespace,
                "enable_network_namespace must be true in strict mode",
            ),
        ] {
            if !enabled {
                result.add_error(msg.into());
            }
        }
    }
    if config.enable_user_namespace {
        result.add_warning(
            "User namespace is not fully supported in judge-v1 GA (rootful strict is the target)"
                .into(),
        );
    }
}

fn validate_credentials(config: &IsolateConfig, result: &mut ValidationResult) {
    if config.strict_mode {
        for (val, name) in [(config.uid, "uid"), (config.gid, "gid")] {
            match val {
                None => result.add_error(format!(
                    "{} must be set in strict mode for unprivileged payload execution",
                    name
                )),
                Some(0) => result.add_error(format!(
                    "{} cannot be 0 (root) for untrusted payload in strict mode",
                    name
                )),
                _ => {}
            }
        }
    }
}

fn validate_mode_compatibility(config: &IsolateConfig, result: &mut ValidationResult) {
    if config.strict_mode && config.allow_degraded {
        result.add_error("allow_degraded is incompatible with strict mode".into());
    }
}

pub fn check_system_capabilities() -> Result<Vec<String>> {
    let mut missing = Vec::new();
    if !Path::new("/sys/fs/cgroup").exists() {
        missing.push("cgroups not available".into());
    }
    #[cfg(target_os = "linux")]
    if !Path::new("/proc/self/ns").exists() {
        missing.push("namespaces not available".into());
    }
    #[cfg(not(target_os = "linux"))]
    missing.push("Linux-only features not available on this platform".into());
    Ok(missing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn permissive(f: impl FnOnce(&mut IsolateConfig)) -> ValidationResult {
        let mut c = IsolateConfig {
            strict_mode: false,
            ..IsolateConfig::default()
        };
        f(&mut c);
        validate_config(&c).unwrap()
    }

    fn strict_err(f: impl FnOnce(&mut IsolateConfig)) {
        let mut c = IsolateConfig::default();
        f(&mut c);
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn valid_default_config() {
        assert!(validate_config(&IsolateConfig::default()).is_ok());
    }

    #[test]
    fn zero_limits_are_errors() {
        let r = permissive(|c| c.memory_limit = Some(0));
        assert!(r
            .errors
            .iter()
            .any(|e| e.contains("memory_limit cannot be zero")));
        let r = permissive(|c| c.cpu_time_limit = Some(Duration::ZERO));
        assert!(r
            .errors
            .iter()
            .any(|e| e.contains("cpu_time_limit cannot be zero")));
    }

    #[test]
    fn wall_time_less_than_cpu_time() {
        let r = permissive(|c| {
            c.cpu_time_limit = Some(Duration::from_secs(10));
            c.wall_time_limit = Some(Duration::from_secs(5));
        });
        assert!(!r.is_valid());
    }

    #[test]
    fn strict_mode_rejects_root_uid_gid() {
        strict_err(|c| c.uid = Some(0));
        strict_err(|c| c.gid = Some(0));
    }

    #[test]
    fn strict_mode_requires_uid_gid() {
        strict_err(|c| c.uid = None);
        strict_err(|c| c.gid = None);
    }

    #[test]
    fn strict_mode_requires_namespaces() {
        strict_err(|c| c.enable_pid_namespace = false);
        strict_err(|c| c.enable_mount_namespace = false);
    }

    #[test]
    fn allow_degraded_incompatible_with_strict() {
        strict_err(|c| c.allow_degraded = true);
    }

    #[test]
    fn allow_degraded_ok_in_permissive() {
        let r = permissive(|c| c.allow_degraded = true);
        assert!(!r.errors.iter().any(|e| e.contains("allow_degraded")));
    }

    #[test]
    fn upper_bound_warnings() {
        let r = permissive(|c| c.memory_limit = Some(16 * 1024 * 1024 * 1024));
        assert!(r.warnings.iter().any(|w| w.contains("8GB")));
        let r = permissive(|c| c.process_limit = Some(10000));
        assert!(r.warnings.iter().any(|w| w.contains("4096")));
        let r = permissive(|c| c.cpu_time_limit = Some(Duration::from_secs(1000)));
        assert!(r.warnings.iter().any(|w| w.contains("600 seconds")));
    }

    #[test]
    fn check_system_capabilities_runs() {
        let missing = check_system_capabilities().unwrap();
        if Path::new("/sys/fs/cgroup").exists() {
            assert!(!missing.iter().any(|m| m.contains("cgroups")));
        }
    }
}
