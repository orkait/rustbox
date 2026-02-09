// Syscall Filtering (P15-SECCOMP-001, P15-SECCOMP-002, P15-SECCOMP-003)
// Per plan.md Section 6.1: Syscall filtering is DISABLED BY DEFAULT
// and requires explicit --enable-syscall-filtering flag

use crate::config::types::{IsolateError, Result};
use std::collections::HashSet;

/// Syscall filtering policy
/// Per plan.md: Filtering is disabled by default and never enabled implicitly
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyscallFilterPolicy {
    /// Disabled (default) - no syscall filtering
    Disabled,
    
    /// Custom allowlist - user provides explicit list of allowed syscalls
    CustomAllowlist {
        syscalls: HashSet<String>,
        profile_id: String,
    },
    
    /// Reference catalog - use provided reference catalog (descriptive only, no guarantees)
    ReferenceCatalog {
        architecture: String,
        catalog_name: String,
        profile_id: String,
    },
}

impl Default for SyscallFilterPolicy {
    fn default() -> Self {
        // Per plan.md: Syscall filtering is disabled by default
        SyscallFilterPolicy::Disabled
    }
}

/// Syscall filter source for metadata
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallFilterSource {
    /// No filtering (default)
    None,
    
    /// Custom user-provided allowlist
    CustomAllowlist,
    
    /// Reference catalog (descriptive, non-guaranteed)
    ReferenceCatalog,
}

impl std::fmt::Display for SyscallFilterSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyscallFilterSource::None => write!(f, "none"),
            SyscallFilterSource::CustomAllowlist => write!(f, "custom_allowlist"),
            SyscallFilterSource::ReferenceCatalog => write!(f, "reference_catalog"),
        }
    }
}

/// Syscall filtering configuration
#[derive(Debug, Clone)]
pub struct SyscallFilterConfig {
    /// Whether filtering is enabled (requires explicit flag)
    pub enabled: bool,
    
    /// Filtering policy
    pub policy: SyscallFilterPolicy,
    
    /// Profile identifier for metadata
    pub profile_id: Option<String>,
}

impl Default for SyscallFilterConfig {
    fn default() -> Self {
        Self {
            enabled: false, // DISABLED BY DEFAULT
            policy: SyscallFilterPolicy::Disabled,
            profile_id: None,
        }
    }
}

impl SyscallFilterConfig {
    /// Create a disabled config (default)
    pub fn disabled() -> Self {
        Self::default()
    }
    
    /// Create a custom allowlist config
    /// Requires explicit enable flag
    pub fn custom_allowlist(syscalls: HashSet<String>, profile_id: String) -> Self {
        Self {
            enabled: true,
            policy: SyscallFilterPolicy::CustomAllowlist { syscalls, profile_id: profile_id.clone() },
            profile_id: Some(profile_id),
        }
    }
    
    /// Create a reference catalog config
    /// Requires explicit enable flag
    pub fn reference_catalog(architecture: String, catalog_name: String, profile_id: String) -> Self {
        Self {
            enabled: true,
            policy: SyscallFilterPolicy::ReferenceCatalog {
                architecture,
                catalog_name,
                profile_id: profile_id.clone(),
            },
            profile_id: Some(profile_id),
        }
    }
    
    /// Get filter source for metadata
    pub fn get_source(&self) -> SyscallFilterSource {
        if !self.enabled {
            return SyscallFilterSource::None;
        }
        
        match &self.policy {
            SyscallFilterPolicy::Disabled => SyscallFilterSource::None,
            SyscallFilterPolicy::CustomAllowlist { .. } => SyscallFilterSource::CustomAllowlist,
            SyscallFilterPolicy::ReferenceCatalog { .. } => SyscallFilterSource::ReferenceCatalog,
        }
    }
    
    /// Get profile ID for metadata
    pub fn get_profile_id(&self) -> String {
        self.profile_id.clone().unwrap_or_else(|| "none".to_string())
    }
}

/// Install syscall filter
/// This is the ONLY legal way to enable syscall filtering
/// Per plan.md: Must be called AFTER no_new_privs and BEFORE exec
pub fn install_syscall_filter(config: &SyscallFilterConfig, strict_mode: bool) -> Result<()> {
    if !config.enabled {
        log::info!("Syscall filtering disabled (default)");
        return Ok(());
    }
    
    log::warn!("Syscall filtering enabled - no compatibility/correctness/safety guarantees");
    log::warn!("Filtering is descriptive/reference-only, not a recommendation");
    
    match &config.policy {
        SyscallFilterPolicy::Disabled => {
            // Should not reach here if enabled=true, but handle gracefully
            log::info!("Syscall filtering policy is disabled");
            Ok(())
        }
        
        SyscallFilterPolicy::CustomAllowlist { syscalls, profile_id } => {
            log::info!("Installing custom syscall allowlist: profile_id={}", profile_id);
            log::info!("Allowed syscalls: {} total", syscalls.len());

            // Fail closed until real seccomp installation is implemented.
            let msg = "Syscall filtering requested but seccomp-bpf installation is not implemented";
            if strict_mode {
                return Err(IsolateError::Privilege(msg.to_string()));
            }
            Err(IsolateError::Config(format!("{} (permissive mode)", msg)))
        }
        
        SyscallFilterPolicy::ReferenceCatalog { architecture, catalog_name, profile_id } => {
            log::info!(
                "Installing reference syscall catalog: arch={}, catalog={}, profile_id={}",
                architecture, catalog_name, profile_id
            );
            log::warn!("Reference catalogs are descriptive only - no guarantees for dynamic runtimes");

            // Fail closed until real seccomp installation is implemented.
            let msg = "Reference syscall catalog selected but seccomp-bpf installation is not implemented";
            if strict_mode {
                return Err(IsolateError::Privilege(msg.to_string()));
            }
            Err(IsolateError::Config(format!("{} (permissive mode)", msg)))
        }
    }
}

/// Check if syscall filtering is supported on this system
pub fn is_seccomp_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check if seccomp is available
        // This is a simple check - actual support depends on kernel config
        std::path::Path::new("/proc/sys/kernel/seccomp").exists()
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Get seccomp support status for capability reporting
pub fn get_seccomp_status() -> String {
    if is_seccomp_supported() {
        "available".to_string()
    } else {
        "unavailable".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_policy_is_disabled() {
        let policy = SyscallFilterPolicy::default();
        assert_eq!(policy, SyscallFilterPolicy::Disabled);
    }
    
    #[test]
    fn test_default_config_is_disabled() {
        let config = SyscallFilterConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.policy, SyscallFilterPolicy::Disabled);
        assert_eq!(config.get_source(), SyscallFilterSource::None);
    }
    
    #[test]
    fn test_custom_allowlist_config() {
        let mut syscalls = HashSet::new();
        syscalls.insert("read".to_string());
        syscalls.insert("write".to_string());
        syscalls.insert("exit".to_string());
        
        let config = SyscallFilterConfig::custom_allowlist(
            syscalls.clone(),
            "test-profile".to_string()
        );
        
        assert!(config.enabled);
        assert_eq!(config.get_source(), SyscallFilterSource::CustomAllowlist);
        assert_eq!(config.get_profile_id(), "test-profile");
        
        match &config.policy {
            SyscallFilterPolicy::CustomAllowlist { syscalls: s, profile_id } => {
                assert_eq!(s.len(), 3);
                assert_eq!(profile_id, "test-profile");
            }
            _ => panic!("Expected CustomAllowlist policy"),
        }
    }
    
    #[test]
    fn test_reference_catalog_config() {
        let config = SyscallFilterConfig::reference_catalog(
            "x86_64".to_string(),
            "minimal".to_string(),
            "ref-x86_64-minimal".to_string()
        );
        
        assert!(config.enabled);
        assert_eq!(config.get_source(), SyscallFilterSource::ReferenceCatalog);
        assert_eq!(config.get_profile_id(), "ref-x86_64-minimal");
        
        match &config.policy {
            SyscallFilterPolicy::ReferenceCatalog { architecture, catalog_name, profile_id } => {
                assert_eq!(architecture, "x86_64");
                assert_eq!(catalog_name, "minimal");
                assert_eq!(profile_id, "ref-x86_64-minimal");
            }
            _ => panic!("Expected ReferenceCatalog policy"),
        }
    }
    
    #[test]
    fn test_install_disabled_filter() {
        let config = SyscallFilterConfig::disabled();
        let result = install_syscall_filter(&config, true);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_install_custom_allowlist() {
        let mut syscalls = HashSet::new();
        syscalls.insert("read".to_string());
        syscalls.insert("write".to_string());
        
        let config = SyscallFilterConfig::custom_allowlist(
            syscalls,
            "test".to_string()
        );
        
        let result = install_syscall_filter(&config, true);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_install_reference_catalog() {
        let config = SyscallFilterConfig::reference_catalog(
            "x86_64".to_string(),
            "minimal".to_string(),
            "ref-test".to_string()
        );
        
        let result = install_syscall_filter(&config, true);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_seccomp_support_check() {
        let status = get_seccomp_status();
        println!("Seccomp status: {}", status);
        
        // Should return either "available" or "unavailable"
        assert!(status == "available" || status == "unavailable");
    }
    
    #[test]
    fn test_filter_source_display() {
        assert_eq!(SyscallFilterSource::None.to_string(), "none");
        assert_eq!(SyscallFilterSource::CustomAllowlist.to_string(), "custom_allowlist");
        assert_eq!(SyscallFilterSource::ReferenceCatalog.to_string(), "reference_catalog");
    }
}
