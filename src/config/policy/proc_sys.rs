/// /proc and /sys Policy Implementation
/// Implements P1-PROC-001: Strict /proc Policy
/// Implements P1-SYS-001: Strict /sys Policy
///
/// Per plan.md Section 10: /proc and /sys Policy
/// - Strict defaults: mount hardened /proc in sandbox namespace
/// - Do not mount /sys unless explicitly enabled by policy
/// - Any override must appear in capability report and audit events
use crate::config::types::{IsolateError, Result};
use std::path::Path;

#[cfg(unix)]
use nix::mount::{mount, MsFlags};

/// /proc mount policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcPolicy {
    /// Mount hardened /proc (default in strict mode)
    Hardened,
    /// Mount standard /proc
    Standard,
    /// Do not mount /proc
    None,
}

/// /sys mount policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysPolicy {
    /// Do not mount /sys (default in strict mode)
    Disabled,
    /// Mount /sys (requires explicit policy)
    Enabled,
}

/// Policy configuration for /proc and /sys
#[derive(Debug, Clone)]
pub struct ProcSysPolicy {
    /// /proc mount policy
    pub proc_policy: ProcPolicy,
    /// /sys mount policy
    pub sys_policy: SysPolicy,
    /// Strict mode flag
    pub strict_mode: bool,
}

impl ProcSysPolicy {
    /// Create default policy for strict mode
    /// Per plan.md: Hardened /proc, no /sys
    pub fn strict_default() -> Self {
        Self {
            proc_policy: ProcPolicy::Hardened,
            sys_policy: SysPolicy::Disabled,
            strict_mode: true,
        }
    }

    /// Create permissive policy
    pub fn permissive() -> Self {
        Self {
            proc_policy: ProcPolicy::Standard,
            sys_policy: SysPolicy::Disabled,
            strict_mode: false,
        }
    }

    /// Validate policy in strict mode
    pub fn validate(&self) -> Result<()> {
        if self.strict_mode {
            // In strict mode, /sys should be disabled by default
            if self.sys_policy == SysPolicy::Enabled {
                log::warn!(
                    "⚠️  /sys is enabled in strict mode. This exposes host kernel interfaces."
                );
            }
        }
        Ok(())
    }

    /// Apply /proc policy
    #[cfg(unix)]
    pub fn apply_proc_policy(&self, proc_path: &Path) -> Result<()> {
        match self.proc_policy {
            ProcPolicy::Hardened => {
                self.mount_hardened_proc(proc_path)?;
                log::info!("Mounted hardened /proc at {}", proc_path.display());
            }
            ProcPolicy::Standard => {
                self.mount_standard_proc(proc_path)?;
                log::info!("Mounted standard /proc at {}", proc_path.display());
            }
            ProcPolicy::None => {
                log::info!("/proc mount disabled by policy");
            }
        }
        Ok(())
    }

    /// Mount hardened /proc
    /// Per plan.md: Mount hardened /proc in sandbox namespace
    #[cfg(unix)]
    fn mount_hardened_proc(&self, proc_path: &Path) -> Result<()> {
        // Mount proc with hidepid=2 for process hiding
        // This prevents processes from seeing other processes
        mount(
            Some("proc"),
            proc_path,
            Some("proc"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            Some("hidepid=2"),
        )
        .map_err(|e| IsolateError::Filesystem(format!("Failed to mount hardened /proc: {}", e)))?;

        Ok(())
    }

    /// Mount standard /proc
    #[cfg(unix)]
    fn mount_standard_proc(&self, proc_path: &Path) -> Result<()> {
        mount(
            Some("proc"),
            proc_path,
            Some("proc"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .map_err(|e| IsolateError::Filesystem(format!("Failed to mount standard /proc: {}", e)))?;

        Ok(())
    }

    /// Apply /sys policy
    #[cfg(unix)]
    pub fn apply_sys_policy(&self, sys_path: &Path) -> Result<()> {
        match self.sys_policy {
            SysPolicy::Enabled => {
                self.mount_sys(sys_path)?;
                log::warn!(
                    "⚠️  AUDIT: /sys mounted at {} (explicit policy override)",
                    sys_path.display()
                );
            }
            SysPolicy::Disabled => {
                log::info!("/sys mount disabled by policy (strict default)");
            }
        }
        Ok(())
    }

    /// Mount /sys
    #[cfg(unix)]
    fn mount_sys(&self, sys_path: &Path) -> Result<()> {
        mount(
            Some("sysfs"),
            sys_path,
            Some("sysfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .map_err(|e| IsolateError::Filesystem(format!("Failed to mount /sys: {}", e)))?;

        Ok(())
    }

    #[cfg(not(unix))]
    pub fn apply_proc_policy(&self, _proc_path: &Path) -> Result<()> {
        log::warn!("/proc policy not supported on non-Unix systems");
        Ok(())
    }

    #[cfg(not(unix))]
    pub fn apply_sys_policy(&self, _sys_path: &Path) -> Result<()> {
        log::warn!("/sys policy not supported on non-Unix systems");
        Ok(())
    }

    /// Get policy description for capability report
    pub fn get_proc_policy_description(&self) -> String {
        match self.proc_policy {
            ProcPolicy::Hardened => "hardened (hidepid=2)".to_string(),
            ProcPolicy::Standard => "standard".to_string(),
            ProcPolicy::None => "disabled".to_string(),
        }
    }

    /// Get /sys policy description for capability report
    pub fn get_sys_policy_description(&self) -> String {
        match self.sys_policy {
            SysPolicy::Enabled => "enabled (explicit override)".to_string(),
            SysPolicy::Disabled => "disabled (strict default)".to_string(),
        }
    }
}

impl Default for ProcSysPolicy {
    fn default() -> Self {
        Self::strict_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_default_policy() {
        let policy = ProcSysPolicy::strict_default();
        assert_eq!(policy.proc_policy, ProcPolicy::Hardened);
        assert_eq!(policy.sys_policy, SysPolicy::Disabled);
        assert!(policy.strict_mode);
    }

    #[test]
    fn test_permissive_policy() {
        let policy = ProcSysPolicy::permissive();
        assert_eq!(policy.proc_policy, ProcPolicy::Standard);
        assert_eq!(policy.sys_policy, SysPolicy::Disabled);
        assert!(!policy.strict_mode);
    }

    #[test]
    fn test_policy_validation() {
        let policy = ProcSysPolicy::strict_default();
        assert!(policy.validate().is_ok());

        let policy_with_sys = ProcSysPolicy {
            proc_policy: ProcPolicy::Hardened,
            sys_policy: SysPolicy::Enabled,
            strict_mode: true,
        };
        // Should succeed but log warning
        assert!(policy_with_sys.validate().is_ok());
    }

    #[test]
    fn test_proc_policy_description() {
        let policy = ProcSysPolicy::strict_default();
        assert_eq!(policy.get_proc_policy_description(), "hardened (hidepid=2)");

        let policy = ProcSysPolicy {
            proc_policy: ProcPolicy::Standard,
            sys_policy: SysPolicy::Disabled,
            strict_mode: false,
        };
        assert_eq!(policy.get_proc_policy_description(), "standard");

        let policy = ProcSysPolicy {
            proc_policy: ProcPolicy::None,
            sys_policy: SysPolicy::Disabled,
            strict_mode: false,
        };
        assert_eq!(policy.get_proc_policy_description(), "disabled");
    }

    #[test]
    fn test_sys_policy_description() {
        let policy = ProcSysPolicy::strict_default();
        assert_eq!(
            policy.get_sys_policy_description(),
            "disabled (strict default)"
        );

        let policy = ProcSysPolicy {
            proc_policy: ProcPolicy::Hardened,
            sys_policy: SysPolicy::Enabled,
            strict_mode: true,
        };
        assert_eq!(
            policy.get_sys_policy_description(),
            "enabled (explicit override)"
        );
    }
}
