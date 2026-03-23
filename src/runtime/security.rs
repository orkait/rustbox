use crate::config::types::{IsolateError, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Invalid command path: {0}")]
    InvalidCommand(String),

    #[error("Command not allowed: {0}")]
    CommandNotAllowed(String),

    #[error("Path traversal attack detected")]
    PathTraversal,

    #[error("Invalid source path: {0}")]
    InvalidSourcePath(String),

    #[error("Blocked source path: {0}")]
    BlockedSourcePath(String),

    #[error("Chroot escape attempt detected")]
    ChrootEscape,

    #[error("Symlink not allowed in directory binding")]
    SymlinkNotAllowed,
}

impl From<SecurityError> for IsolateError {
    fn from(err: SecurityError) -> Self {
        IsolateError::Config(err.to_string())
    }
}

pub mod command_validation {
    use super::*;

    static ALLOWED_EXECUTABLES: &[&str] = &[
        "/usr/bin/python3",
        "/usr/bin/python3.11",
        "/usr/bin/python3.10",
        "/usr/bin/python3.12",
        "/usr/bin/python",
        "/usr/bin/gcc",
        "/usr/bin/gcc-13",
        "/usr/bin/x86_64-linux-gnu-gcc-13",
        "/usr/bin/g++",
        "/usr/bin/g++-13",
        "/usr/bin/x86_64-linux-gnu-g++-13",
        "/usr/bin/clang",
        "/usr/bin/clang++",
        "/usr/bin/java",
        "/usr/lib/jvm/java-21-openjdk-amd64/bin/java",
        "/usr/bin/javac",
        "/usr/lib/jvm/java-21-openjdk-amd64/bin/javac",
        "/usr/local/bin/bun",
        "/usr/bin/node",
        "/usr/local/go/bin/go",
        "/usr/local/bin/rustc",
        "/usr/local/rust/bin/rustc",
        "/bin/sh",
        "/bin/bash",
        "/usr/bin/rustc",
        "/usr/bin/cargo",
        "/usr/bin/make",
        "/usr/bin/cmake",
    ];

    static SAFE_SYSTEM_COMMANDS: &[&str] = &[
        "/bin/cat",
        "/usr/bin/cat",
        "/bin/echo",
        "/usr/bin/echo",
        "/bin/ls",
        "/usr/bin/ls",
        "/usr/bin/head",
        "/usr/bin/tail",
        "/usr/bin/wc",
        "/usr/bin/sort",
        "/usr/bin/uniq",
        "/bin/grep",
        "/usr/bin/grep",
    ];

    pub fn validate_and_resolve_command(command: &str) -> Result<PathBuf> {
        if command == "./solution" {
            return Ok(PathBuf::from("./solution"));
        }

        let resolved_path = if command.starts_with('/') {
            PathBuf::from(command)
        } else {
            resolve_command_in_path(command)?
        };

        let canonical = resolved_path.canonicalize().map_err(|_| {
            SecurityError::InvalidCommand(format!("Cannot canonicalize: {}", command))
        })?;

        if !is_allowed_path(&canonical) {
            return Err(
                SecurityError::CommandNotAllowed(canonical.to_string_lossy().to_string()).into(),
            );
        }

        validate_path_security(&canonical)?;

        Ok(canonical)
    }

    fn is_allowed_path(canonical: &Path) -> bool {
        let check = |allowed: &str| -> bool {
            let allowed_path = Path::new(allowed);
            if canonical == allowed_path {
                return true;
            }
            if let Ok(canon_allowed) = allowed_path.canonicalize() {
                return canonical == canon_allowed;
            }
            false
        };

        ALLOWED_EXECUTABLES.iter().any(|p| check(p))
            || SAFE_SYSTEM_COMMANDS.iter().any(|p| check(p))
    }

    fn resolve_command_in_path(command: &str) -> Result<PathBuf> {
        let secure_paths = ["/usr/local/bin", "/usr/local/go/bin", "/usr/bin", "/bin"];

        for path_dir in &secure_paths {
            let candidate = Path::new(path_dir).join(command);
            if candidate.exists() && candidate.is_file() {
                return Ok(candidate);
            }
        }

        Err(
            SecurityError::InvalidCommand(format!("Command not found in secure PATH: {}", command))
                .into(),
        )
    }

    fn validate_path_security(path: &Path) -> Result<()> {
        let path_str = path.to_string_lossy();

        if path_str.contains("..") {
            return Err(SecurityError::PathTraversal.into());
        }

        let secure_prefixes = [
            "/usr/bin/",
            "/usr/local/bin/",
            "/usr/local/go/bin/",
            "/usr/local/rust/bin/",
            "/bin/",
            "/usr/lib/jvm/",
            "/tmp/rustbox/",
            "/tmp/rustbox-uid-",
        ];

        if !secure_prefixes
            .iter()
            .any(|prefix| path_str.starts_with(prefix))
        {
            return Err(SecurityError::CommandNotAllowed(format!(
                "Path not under secure prefix: {}",
                path_str
            ))
            .into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::command_validation::validate_and_resolve_command;

    #[test]
    fn solution_binary_is_accepted_without_canonicalization() {
        let result = validate_and_resolve_command("./solution");
        assert!(result.is_ok(), "compiled solution must be allowed");
        assert_eq!(result.unwrap().to_str().unwrap(), "./solution");
    }

    #[test]
    fn nonexistent_absolute_path_is_rejected() {
        let result = validate_and_resolve_command("/nonexistent/malicious");
        assert!(result.is_err(), "nonexistent path must be rejected");
    }

    #[test]
    fn path_not_in_allowlist_is_rejected() {
        #[cfg(target_os = "linux")]
        if std::path::Path::new("/usr/bin/id").exists() {
            let result = validate_and_resolve_command("/usr/bin/id");
            assert!(result.is_err(), "/usr/bin/id must not be in the allowlist");
        }
    }

    #[test]
    fn python3_is_in_allowlist() {
        #[cfg(target_os = "linux")]
        if std::path::Path::new("/usr/bin/python3").exists() {
            let result = validate_and_resolve_command("/usr/bin/python3");
            assert!(result.is_ok(), "/usr/bin/python3 must be allowed");
        }
    }

    #[test]
    fn gpp_is_in_allowlist() {
        #[cfg(target_os = "linux")]
        if std::path::Path::new("/usr/bin/g++").exists() {
            let result = validate_and_resolve_command("/usr/bin/g++");
            assert!(result.is_ok(), "/usr/bin/g++ must be allowed");
        }
    }

    #[test]
    fn java_symlink_resolves_to_allowed_path() {
        #[cfg(target_os = "linux")]
        if std::path::Path::new("/usr/bin/java").exists() {
            let result = validate_and_resolve_command("/usr/bin/java");
            assert!(
                result.is_ok(),
                "/usr/bin/java must be allowed (canonical: {:?})",
                std::path::Path::new("/usr/bin/java").canonicalize()
            );
        }
    }

    #[test]
    fn javac_symlink_resolves_to_allowed_path() {
        #[cfg(target_os = "linux")]
        if std::path::Path::new("/usr/bin/javac").exists() {
            let result = validate_and_resolve_command("/usr/bin/javac");
            assert!(
                result.is_ok(),
                "/usr/bin/javac must be allowed (canonical: {:?})",
                std::path::Path::new("/usr/bin/javac").canonicalize()
            );
        }
    }
}
pub mod path_validation {
    use super::*;

    const BLOCKED_PATHS: &[&str] = &[
        "/etc",
        "/root",
        "/home",
        "/proc",
        "/sys",
        "/dev",
        "/var/log",
        "/var/lib",
        "/boot",
        "/usr/bin",
        "/usr/sbin",
        "/sbin",
        "/lib",
        "/usr/lib",
        "/usr/include",
        "/opt",
        "/run",
    ];

    pub fn validate_source_path(path: &Path) -> Result<PathBuf> {
        let canonical = path.canonicalize().map_err(|e| {
            SecurityError::InvalidSourcePath(format!("Cannot access {}: {}", path.display(), e))
        })?;

        let path_str = canonical.to_string_lossy();
        for blocked in BLOCKED_PATHS {
            if path_str.starts_with(blocked) {
                return Err(SecurityError::BlockedSourcePath(path_str.to_string()).into());
            }
        }

        validate_source_security(&canonical)?;

        Ok(canonical)
    }

    pub fn validate_target_path(path: &Path) -> Result<PathBuf> {
        let path_str = path.to_string_lossy();

        if path.is_absolute() && !path_str.starts_with("/sandbox") && !path_str.starts_with("/tmp")
        {
            return Err(SecurityError::ChrootEscape.into());
        }

        if path_str.contains("..") || path_str.contains("~") {
            return Err(SecurityError::PathTraversal.into());
        }

        Ok(path.to_path_buf())
    }

    fn validate_source_security(path: &Path) -> Result<()> {
        if path.read_link().is_ok() {
            return Err(SecurityError::SymlinkNotAllowed.into());
        }

        if !path.exists() {
            return Err(SecurityError::InvalidSourcePath(format!(
                "Path does not exist: {}",
                path.display()
            ))
            .into());
        }

        if !path.is_dir() {
            return Err(SecurityError::InvalidSourcePath(format!(
                "Path is not a directory: {}",
                path.display()
            ))
            .into());
        }

        Ok(())
    }

    pub fn validate_directory_binding(source: &Path, target: &Path) -> Result<(PathBuf, PathBuf)> {
        let validated_source = validate_source_path(source)?;
        let validated_target = validate_target_path(target)?;

        check_binding_security(&validated_source, &validated_target)?;

        Ok((validated_source, validated_target))
    }

    fn check_binding_security(source: &Path, target: &Path) -> Result<()> {
        let source_str = source.to_string_lossy();
        let target_str = target.to_string_lossy();

        let sensitive_sources = ["/usr", "/lib", "/bin", "/sbin"];
        for sensitive in &sensitive_sources {
            if source_str.starts_with(sensitive) && target_str.contains("tmp") {
                return Err(SecurityError::BlockedSourcePath(format!(
                    "Cannot bind sensitive directory {} to writable location {}",
                    source_str, target_str
                ))
                .into());
            }
        }

        Ok(())
    }
}
