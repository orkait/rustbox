/// User Namespace Policy Contract
/// Implements P1-USERNS-001: User Namespace Policy Contract
/// Per plan.md Section 11: User Namespace Policy

use crate::config::types::{IsolateError, Result};

/// User namespace policy
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UserNamespacePolicy {
    /// Rootful strict mode (GA target)
    /// Requires elevated privileges, no user namespace
    RootfulStrict,
    
    /// Rootless strict mode (deferred until complete userns mapping workflow)
    /// Not yet supported - requires setgroups, uid_map, gid_map implementation
    RootlessStrict,
    
    /// Permissive mode with user namespace
    /// For development/testing only
    Permissive,
    
    /// Disabled - no user namespace
    Disabled,
}

impl Default for UserNamespacePolicy {
    fn default() -> Self {
        // Per plan.md Section 11: Current GA target is rootful strict
        UserNamespacePolicy::RootfulStrict
    }
}

/// User namespace configuration
#[derive(Debug, Clone)]
pub struct UserNamespaceConfig {
    /// Policy
    pub policy: UserNamespacePolicy,
    
    /// Enable user namespace (only in permissive mode)
    pub enable_userns: bool,
    
    /// UID mapping (for rootless, when implemented)
    pub uid_map: Option<String>,
    
    /// GID mapping (for rootless, when implemented)
    pub gid_map: Option<String>,
    
    /// Handle setgroups (for rootless, when implemented)
    pub setgroups_deny: bool,
}

impl Default for UserNamespaceConfig {
    fn default() -> Self {
        UserNamespaceConfig {
            policy: UserNamespacePolicy::default(),
            enable_userns: false,
            uid_map: None,
            gid_map: None,
            setgroups_deny: true,
        }
    }
}

/// Validate user namespace configuration
pub fn validate_userns_config(config: &UserNamespaceConfig, strict_mode: bool) -> Result<()> {
    match config.policy {
        UserNamespacePolicy::RootfulStrict => {
            if config.enable_userns {
                return Err(IsolateError::Config(
                    "User namespace not supported in rootful strict mode".to_string()
                ));
            }
            
            if strict_mode && (config.uid_map.is_some() || config.gid_map.is_some()) {
                return Err(IsolateError::Config(
                    "UID/GID mapping not supported in rootful strict mode".to_string()
                ));
            }
            
            Ok(())
        }
        
        UserNamespacePolicy::RootlessStrict => {
            // Rootless strict is explicitly unsupported until mapping workflow is complete
            Err(IsolateError::Config(
                "Rootless strict mode is not yet supported. \
                 Deferred until complete userns mapping workflow (setgroups, uid_map, gid_map) \
                 is implemented and validated. Use rootful strict mode instead.".to_string()
            ))
        }
        
        UserNamespacePolicy::Permissive => {
            if strict_mode {
                return Err(IsolateError::Config(
                    "Permissive user namespace policy not allowed in strict mode".to_string()
                ));
            }
            
            // Permissive mode allows user namespace for development/testing
            Ok(())
        }
        
        UserNamespacePolicy::Disabled => {
            if config.enable_userns {
                return Err(IsolateError::Config(
                    "User namespace enabled but policy is Disabled".to_string()
                ));
            }
            
            Ok(())
        }
    }
}

/// Check if host supports unprivileged user namespaces
pub fn check_unprivileged_userns_support() -> bool {
    // Check /proc/sys/kernel/unprivileged_userns_clone (Debian/Ubuntu)
    if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        if content.trim() == "1" {
            return true;
        }
    }
    
    // Check /proc/sys/user/max_user_namespaces (RHEL/CentOS)
    if let Ok(content) = std::fs::read_to_string("/proc/sys/user/max_user_namespaces") {
        if let Ok(max) = content.trim().parse::<u32>() {
            if max > 0 {
                return true;
            }
        }
    }
    
    // Default: assume disabled for safety
    false
}

/// Get user namespace behavior description
pub fn get_userns_behavior_description(config: &UserNamespaceConfig) -> String {
    match config.policy {
        UserNamespacePolicy::RootfulStrict => {
            "Rootful strict mode (GA): No user namespace, requires elevated privileges".to_string()
        }
        UserNamespacePolicy::RootlessStrict => {
            "Rootless strict mode: NOT SUPPORTED (deferred until complete userns mapping workflow)".to_string()
        }
        UserNamespacePolicy::Permissive => {
            if config.enable_userns {
                "Permissive mode: User namespace enabled (development/testing only)".to_string()
            } else {
                "Permissive mode: User namespace disabled".to_string()
            }
        }
        UserNamespacePolicy::Disabled => {
            "User namespace disabled".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_userns_policy_default() {
        let policy = UserNamespacePolicy::default();
        assert_eq!(policy, UserNamespacePolicy::RootfulStrict);
    }

    #[test]
    fn test_userns_config_default() {
        let config = UserNamespaceConfig::default();
        assert_eq!(config.policy, UserNamespacePolicy::RootfulStrict);
        assert!(!config.enable_userns);
        assert!(config.uid_map.is_none());
        assert!(config.gid_map.is_none());
        assert!(config.setgroups_deny);
    }

    #[test]
    fn test_validate_rootful_strict() {
        let config = UserNamespaceConfig::default();
        
        // Should succeed in strict mode
        let result = validate_userns_config(&config, true);
        assert!(result.is_ok());
        
        // Should fail if userns enabled
        let mut bad_config = config.clone();
        bad_config.enable_userns = true;
        let result = validate_userns_config(&bad_config, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rootless_strict() {
        let mut config = UserNamespaceConfig::default();
        config.policy = UserNamespacePolicy::RootlessStrict;
        
        // Should fail - not yet supported
        let result = validate_userns_config(&config, true);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not yet supported"));
    }

    #[test]
    fn test_validate_permissive() {
        let mut config = UserNamespaceConfig::default();
        config.policy = UserNamespacePolicy::Permissive;
        config.enable_userns = true;
        
        // Should succeed in permissive mode
        let result = validate_userns_config(&config, false);
        assert!(result.is_ok());
        
        // Should fail in strict mode
        let result = validate_userns_config(&config, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_disabled() {
        let mut config = UserNamespaceConfig::default();
        config.policy = UserNamespacePolicy::Disabled;
        
        // Should succeed
        let result = validate_userns_config(&config, true);
        assert!(result.is_ok());
        
        // Should fail if userns enabled
        config.enable_userns = true;
        let result = validate_userns_config(&config, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_unprivileged_userns_support() {
        let supported = check_unprivileged_userns_support();
        println!("Unprivileged user namespaces supported: {}", supported);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_get_userns_behavior_description() {
        let config = UserNamespaceConfig::default();
        let desc = get_userns_behavior_description(&config);
        assert!(desc.contains("Rootful strict"));
        
        let mut config = UserNamespaceConfig::default();
        config.policy = UserNamespacePolicy::RootlessStrict;
        let desc = get_userns_behavior_description(&config);
        assert!(desc.contains("NOT SUPPORTED"));
    }
}
