/// Environment and Permission Hygiene
/// Implements P1-HYGIENE-001: Environment and Permission Hygiene
/// Per plan.md Section 12: Output, FD, and Environment Hygiene
use crate::config::types::{IsolateError, Result};
use crate::utils::fork_safe_log::{fs_info_parts, fs_warn_parts, itoa_i32};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Format a `u32` as octal into a stack-allocated buffer without heap allocation.
#[inline]
fn octal_buf(value: u32, buf: &mut [u8; 12]) -> &str {
    if value == 0 {
        buf[11] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&buf[11..]) };
    }
    let mut i = 12;
    let mut v = value;
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 8) as u8;
        v /= 8;
    }
    unsafe { core::str::from_utf8_unchecked(&buf[i..]) }
}

/// Environment sanitization policy
#[derive(Debug, Clone)]
pub struct EnvPolicy {
    /// Sanitize dangerous LD_* variables
    pub sanitize_ld_vars: bool,
    /// Set deterministic PATH
    pub set_deterministic_path: bool,
    /// Set deterministic HOME
    pub set_deterministic_home: bool,
    /// Set deterministic locale
    pub set_deterministic_locale: bool,
    /// Set deterministic temp vars
    pub set_deterministic_temp: bool,
    /// Strict mode (fail on errors)
    pub strict_mode: bool,
}

impl Default for EnvPolicy {
    fn default() -> Self {
        EnvPolicy {
            sanitize_ld_vars: true,
            set_deterministic_path: true,
            set_deterministic_home: true,
            set_deterministic_locale: true,
            set_deterministic_temp: true,
            strict_mode: true,
        }
    }
}

/// Permission policy for filesystem artifacts
#[derive(Debug, Clone)]
pub struct PermissionPolicy {
    /// Umask for new files
    pub umask: u32,
    /// Temp directory permissions (octal)
    pub temp_dir_perms: u32,
    /// Work directory permissions (octal)
    pub work_dir_perms: u32,
    /// Strict mode (fail on errors)
    pub strict_mode: bool,
}

impl Default for PermissionPolicy {
    fn default() -> Self {
        PermissionPolicy {
            umask: 0o077,          // Owner only by default
            temp_dir_perms: 0o700, // Owner rwx only
            work_dir_perms: 0o755, // Owner rwx, others rx
            strict_mode: true,
        }
    }
}

/// Environment hygiene manager
pub struct EnvHygiene {
    env_policy: EnvPolicy,
    perm_policy: PermissionPolicy,
}

impl EnvHygiene {
    /// Create new environment hygiene manager
    pub fn new(env_policy: EnvPolicy, perm_policy: PermissionPolicy) -> Self {
        EnvHygiene {
            env_policy,
            perm_policy,
        }
    }

    /// Sanitize environment variables
    /// Returns sanitized environment map
    pub fn sanitize_environment(&self) -> Result<HashMap<String, String>> {
        let mut env_map = HashMap::new();

        // Collect current environment
        for (key, value) in env::vars() {
            env_map.insert(key, value);
        }

        // Sanitize LD_* variables (dangerous for loader abuse)
        if self.env_policy.sanitize_ld_vars {
            let ld_vars: &[&str] = &[
                "LD_PRELOAD",
                "LD_LIBRARY_PATH",
                "LD_AUDIT",
                "LD_BIND_NOW",
                "LD_DEBUG",
                "LD_PROFILE",
                "LD_USE_LOAD_BIAS",
                "LD_DYNAMIC_WEAK",
            ];

            for &var in ld_vars {
                if env_map.remove(var).is_some() {
                    fs_info_parts(&["Removed dangerous environment variable: ", var]);
                }
            }
        }

        // Set deterministic PATH
        if self.env_policy.set_deterministic_path {
            env_map.insert(
                "PATH".to_string(),
                "/usr/local/bin:/usr/bin:/bin".to_string(),
            );
        }

        // Set deterministic HOME
        if self.env_policy.set_deterministic_home {
            env_map.insert("HOME".to_string(), "/tmp/sandbox".to_string());
        }

        // Set deterministic locale
        if self.env_policy.set_deterministic_locale {
            env_map.insert("LANG".to_string(), "C.UTF-8".to_string());
            env_map.insert("LC_ALL".to_string(), "C.UTF-8".to_string());
        }

        // Set deterministic temp vars
        if self.env_policy.set_deterministic_temp {
            env_map.insert("TMPDIR".to_string(), "/tmp".to_string());
            env_map.insert("TEMP".to_string(), "/tmp".to_string());
            env_map.insert("TMP".to_string(), "/tmp".to_string());
        }

        Ok(env_map)
    }

    /// Apply umask
    pub fn apply_umask(&self) -> Result<()> {
        #[cfg(unix)]
        {
            use nix::sys::stat::{umask, Mode};

            let mode = Mode::from_bits(self.perm_policy.umask).ok_or_else(|| {
                IsolateError::Config(format!("Invalid umask: {:o}", self.perm_policy.umask))
            })?;

            umask(mode);
            let mut obuf = [0u8; 12];
            let ostr = octal_buf(self.perm_policy.umask, &mut obuf);
            fs_info_parts(&["Applied umask: ", ostr]);
        }

        Ok(())
    }

    /// Set directory permissions
    pub fn set_directory_permissions(&self, path: &Path, is_temp: bool) -> Result<()> {
        if !path.exists() {
            if self.perm_policy.strict_mode {
                return Err(IsolateError::Filesystem(format!(
                    "Directory does not exist: {}",
                    path.display()
                )));
            } else {
                fs_warn_parts(&[
                    "Directory does not exist (permissive mode): ",
                    path.to_str().unwrap_or("<?>"),
                ]);
                return Ok(());
            }
        }

        let perms = if is_temp {
            self.perm_policy.temp_dir_perms
        } else {
            self.perm_policy.work_dir_perms
        };

        let permissions = fs::Permissions::from_mode(perms);

        fs::set_permissions(path, permissions).map_err(|e| {
            if self.perm_policy.strict_mode {
                IsolateError::Filesystem(format!(
                    "Failed to set permissions on {}: {}",
                    path.display(),
                    e
                ))
            } else {
                let mut ebuf = [0u8; 20];
                let eno = itoa_i32(e.raw_os_error().unwrap_or(-1), &mut ebuf);
                fs_warn_parts(&["Failed to set permissions (permissive mode): errno ", eno]);
                IsolateError::Filesystem(format!(
                    "Failed to set permissions on {}: {}",
                    path.display(),
                    e
                ))
            }
        })?;

        let mut obuf = [0u8; 12];
        let ostr = octal_buf(perms, &mut obuf);
        fs_info_parts(&["Set permissions ", ostr, " on ", path.to_str().unwrap_or("<?>")]);

        Ok(())
    }

    /// Get sanitized environment as Vec for exec
    pub fn get_exec_env(&self) -> Result<Vec<String>> {
        let env_map = self.sanitize_environment()?;

        let mut env_vec: Vec<String> = env_map
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();

        env_vec.sort(); // Deterministic ordering
        Ok(env_vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_policy_default() {
        let policy = EnvPolicy::default();
        assert!(policy.sanitize_ld_vars);
        assert!(policy.set_deterministic_path);
        assert!(policy.set_deterministic_home);
        assert!(policy.set_deterministic_locale);
        assert!(policy.set_deterministic_temp);
        assert!(policy.strict_mode);
    }

    #[test]
    fn test_permission_policy_default() {
        let policy = PermissionPolicy::default();
        assert_eq!(policy.umask, 0o077);
        assert_eq!(policy.temp_dir_perms, 0o700);
        assert_eq!(policy.work_dir_perms, 0o755);
        assert!(policy.strict_mode);
    }

    #[test]
    fn test_env_hygiene_creation() {
        let env_policy = EnvPolicy::default();
        let perm_policy = PermissionPolicy::default();
        let hygiene = EnvHygiene::new(env_policy, perm_policy);

        assert!(hygiene.env_policy.sanitize_ld_vars);
        assert_eq!(hygiene.perm_policy.umask, 0o077);
    }

    #[test]
    fn test_sanitize_environment() {
        let env_policy = EnvPolicy::default();
        let perm_policy = PermissionPolicy::default();
        let hygiene = EnvHygiene::new(env_policy, perm_policy);

        let env_map = hygiene
            .sanitize_environment()
            .expect("Failed to sanitize environment");

        // Should have deterministic values
        assert_eq!(
            env_map.get("PATH"),
            Some(&"/usr/local/bin:/usr/bin:/bin".to_string())
        );
        assert_eq!(env_map.get("HOME"), Some(&"/tmp/sandbox".to_string()));
        assert_eq!(env_map.get("LANG"), Some(&"C.UTF-8".to_string()));
        assert_eq!(env_map.get("TMPDIR"), Some(&"/tmp".to_string()));

        // Should not have dangerous LD_* variables
        assert!(!env_map.contains_key("LD_PRELOAD"));
        assert!(!env_map.contains_key("LD_LIBRARY_PATH"));
    }

    #[test]
    fn test_get_exec_env() {
        let env_policy = EnvPolicy::default();
        let perm_policy = PermissionPolicy::default();
        let hygiene = EnvHygiene::new(env_policy, perm_policy);

        let exec_env = hygiene.get_exec_env().expect("Failed to get exec env");

        // Should be sorted
        let mut sorted = exec_env.clone();
        sorted.sort();
        assert_eq!(exec_env, sorted);

        // Should contain deterministic values
        assert!(exec_env.iter().any(|s| s.starts_with("PATH=")));
        assert!(exec_env.iter().any(|s| s.starts_with("HOME=")));
    }

    #[test]
    fn test_apply_umask() {
        let env_policy = EnvPolicy::default();
        let perm_policy = PermissionPolicy::default();
        let hygiene = EnvHygiene::new(env_policy, perm_policy);

        let result = hygiene.apply_umask();
        assert!(result.is_ok());
    }
}
