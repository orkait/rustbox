use crate::config::constants;
use crate::config::types::{IsolateError, Result};
use crate::utils::fork_safe_log::{fs_info_parts, fs_warn_parts};
use std::collections::HashMap;
use std::env;

pub const DANGEROUS_ENV_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "LD_PROFILE",
    "LD_BIND_NOW",
    "LD_BIND_NOT",
    "LD_DYNAMIC_WEAK",
    "LD_USE_LOAD_BIAS",
    "BASH_ENV",
    "ENV",
    "CDPATH",
    "PYTHONSTARTUP",
    "PERL5OPT",
    "RUBYOPT",
    "NODE_OPTIONS",
    "IFS",
    "GCONV_PATH",
    "HOSTALIASES",
    "LOCALDOMAIN",
    "RES_OPTIONS",
    "http_proxy",
    "https_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ftp_proxy",
    "FTP_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
];

pub const JAVA_AGENT_FLAGS: &[&str] = &["-javaagent:", "-agentpath:", "-agentlib:"];

pub fn strip_dangerous_env(env_map: &mut HashMap<String, String>) {
    for key in DANGEROUS_ENV_VARS {
        if env_map.remove(*key).is_some() {
            fs_warn_parts(&[
                "Removed dangerous environment variable after profile merge: ",
                key,
            ]);
        }
    }

    let bash_func_keys: Vec<String> = env_map
        .keys()
        .filter(|k| k.starts_with("BASH_FUNC_"))
        .cloned()
        .collect();
    for key in &bash_func_keys {
        env_map.remove(key);
        fs_warn_parts(&[
            "Removed dangerous BASH_FUNC_ variable after profile merge: ",
            key,
        ]);
    }

    if let Some(jto) = env_map.get("JAVA_TOOL_OPTIONS") {
        let lower = jto.to_lowercase();
        if JAVA_AGENT_FLAGS.iter().any(|flag| lower.contains(flag)) {
            env_map.remove("JAVA_TOOL_OPTIONS");
            fs_warn_parts(&["Removed JAVA_TOOL_OPTIONS containing agent flag"]);
        }
    }
}

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

#[derive(Debug, Clone)]
pub struct EnvPolicy {
    pub sanitize_ld_vars: bool,
    pub set_deterministic_path: bool,
    pub set_deterministic_home: bool,
    pub set_deterministic_locale: bool,
    pub set_deterministic_temp: bool,
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

#[derive(Debug, Clone)]
pub struct PermissionPolicy {
    pub umask: u32,
    pub temp_dir_perms: u32,
    pub work_dir_perms: u32,
    pub strict_mode: bool,
}

impl Default for PermissionPolicy {
    fn default() -> Self {
        PermissionPolicy {
            umask: constants::PERM_UMASK_RESTRICTIVE,
            temp_dir_perms: constants::PERM_DIR_TEMP,
            work_dir_perms: constants::PERM_DIR_STANDARD,
            strict_mode: true,
        }
    }
}

pub struct EnvHygiene {
    env_policy: EnvPolicy,
    perm_policy: PermissionPolicy,
}

impl EnvHygiene {
    pub fn new(env_policy: EnvPolicy, perm_policy: PermissionPolicy) -> Self {
        EnvHygiene {
            env_policy,
            perm_policy,
        }
    }

    pub fn sanitize_environment(&self) -> Result<HashMap<String, String>> {
        let mut env_map: HashMap<String, String> = env::vars().collect();

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

        if self.env_policy.set_deterministic_path {
            env_map.insert("PATH".to_string(), constants::SANDBOX_PATH.to_string());
        }

        if self.env_policy.set_deterministic_home {
            env_map.insert("HOME".to_string(), constants::SANDBOX_HOME.to_string());
        }

        if self.env_policy.set_deterministic_locale {
            env_map.insert("LANG".to_string(), constants::SANDBOX_LOCALE.to_string());
            env_map.insert("LC_ALL".to_string(), constants::SANDBOX_LOCALE.to_string());
        }

        if self.env_policy.set_deterministic_temp {
            env_map.insert("TMPDIR".to_string(), "/tmp".to_string());
            env_map.insert("TEMP".to_string(), "/tmp".to_string());
            env_map.insert("TMP".to_string(), "/tmp".to_string());
        }

        Ok(env_map)
    }

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

        assert_eq!(
            env_map.get("PATH"),
            Some(&constants::SANDBOX_PATH.to_string())
        );
        assert_eq!(
            env_map.get("HOME"),
            Some(&constants::SANDBOX_HOME.to_string())
        );
        assert_eq!(
            env_map.get("LANG"),
            Some(&constants::SANDBOX_LOCALE.to_string())
        );
        assert_eq!(env_map.get("TMPDIR"), Some(&"/tmp".to_string()));

        assert!(!env_map.contains_key("LD_PRELOAD"));
        assert!(!env_map.contains_key("LD_LIBRARY_PATH"));
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
