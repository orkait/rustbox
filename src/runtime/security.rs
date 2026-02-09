/// Security validation module for command injection prevention and path validation
use crate::config::types::{IsolateError, Result};
use std::path::{Path, PathBuf};

/// Security error types for validation failures
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

/// Command validation module with allowlist-based security
pub mod command_validation {
    use super::*;

    /// Allowlist of permitted executables for secure command execution
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
        "/usr/lib/jvm/java-17-openjdk-amd64/bin/java",
        "/usr/bin/javac",
        "/usr/lib/jvm/java-17-openjdk-amd64/bin/javac",
        "/usr/bin/node",
        "/usr/bin/go",
        "/usr/lib/go-1.22/bin/go",
        "/bin/sh",
        "/bin/bash",
        "/usr/bin/rustc",
        "/usr/bin/cargo",
        "/usr/bin/make",
        "/usr/bin/cmake",
    ];

    /// Additional safe system commands that are commonly needed
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
        "/usr/bin/awk",
        "/bin/sed",
        "/usr/bin/sed",
    ];

    /// Validate and resolve command path with security checks
    pub fn validate_and_resolve_command(command: &str) -> Result<PathBuf> {
        // 1. Handle special case for compiled solution executables
        if command == "./solution" {
            // Keep this relative so it resolves against ProcessExecutor::current_dir,
            // not the controller's host working directory.
            return Ok(PathBuf::from("./solution"));
        }

        // 2. Handle relative paths by checking PATH
        let resolved_path = if command.starts_with('/') {
            // Absolute path - validate directly
            PathBuf::from(command)
        } else {
            // Relative path - resolve using PATH
            resolve_command_in_path(command)?
        };

        // 3. Canonicalize path to prevent traversal (skip for ./solution as it may not exist yet)
        let canonical = if command == "./solution" {
            resolved_path
        } else {
            resolved_path.canonicalize().map_err(|_| {
                SecurityError::InvalidCommand(format!("Cannot canonicalize: {}", command))
            })?
        };

        // 4. Check against allowlist (accept canonical aliases such as /bin -> /usr/bin)
        if !is_allowed_path(&canonical) {
            return Err(
                SecurityError::CommandNotAllowed(canonical.to_string_lossy().to_string()).into(),
            );
        }

        // 4. Additional security checks
        validate_path_security(&canonical)?;

        Ok(canonical)
    }

    fn is_allowed_path(canonical: &Path) -> bool {
        let check = |allowed: &str| -> bool {
            let allowed_path = Path::new(allowed);
            if canonical == allowed_path {
                return true;
            }
            // Handle symlinked path aliases (e.g. /bin/echo -> /usr/bin/echo).
            if let Ok(canon_allowed) = allowed_path.canonicalize() {
                return canonical == canon_allowed;
            }
            false
        };

        ALLOWED_EXECUTABLES.iter().any(|p| check(p))
            || SAFE_SYSTEM_COMMANDS.iter().any(|p| check(p))
    }

    /// Resolve command in PATH environment variable
    fn resolve_command_in_path(command: &str) -> Result<PathBuf> {
        // Define secure PATH directories
        let secure_paths = ["/usr/local/bin", "/usr/bin", "/bin", "/usr/lib/go-1.22/bin"];

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

    /// Additional security validation for resolved paths
    fn validate_path_security(path: &Path) -> Result<()> {
        let path_str = path.to_string_lossy();

        // Prevent path traversal patterns
        if path_str.contains("..") || path_str.contains("~") {
            return Err(SecurityError::PathTraversal.into());
        }

        // Ensure path is under secure directories
        let secure_prefixes = [
            "/usr/bin/",
            "/usr/local/bin/",
            "/bin/",
            "/usr/lib/go-1.22/bin/",
            "/usr/lib/jvm/",
            "/tmp/rustbox/", // Allow execution of compiled binaries in sandbox directories
        ];

        let mut under_secure_prefix = false;
        for prefix in &secure_prefixes {
            if path_str.starts_with(prefix) {
                under_secure_prefix = true;
                break;
            }
        }

        if !under_secure_prefix {
            return Err(SecurityError::CommandNotAllowed(format!(
                "Path not under secure prefix: {}",
                path_str
            ))
            .into());
        }

        Ok(())
    }
}

/// Path validation module for directory bindings and filesystem access
pub mod path_validation {
    use super::*;

    /// Blocklist of sensitive directories that should never be accessible
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

    /// Validate source path for directory binding
    pub fn validate_source_path(path: &Path) -> Result<PathBuf> {
        // 1. Canonicalize to resolve symlinks and prevent traversal
        let canonical = path.canonicalize().map_err(|e| {
            SecurityError::InvalidSourcePath(format!("Cannot access {}: {}", path.display(), e))
        })?;

        // 2. Check against blocklist
        let path_str = canonical.to_string_lossy();
        for blocked in BLOCKED_PATHS {
            if path_str.starts_with(blocked) {
                return Err(SecurityError::BlockedSourcePath(path_str.to_string()).into());
            }
        }

        // 3. Additional validation
        validate_source_security(&canonical)?;

        Ok(canonical)
    }

    /// Validate target path for directory binding
    pub fn validate_target_path(path: &Path) -> Result<PathBuf> {
        let path_str = path.to_string_lossy();

        // 1. Prevent absolute paths outside sandbox
        if path.is_absolute() && !path_str.starts_with("/sandbox") && !path_str.starts_with("/tmp")
        {
            return Err(SecurityError::ChrootEscape.into());
        }

        // 2. Prevent path traversal
        if path_str.contains("..") || path_str.contains("~") {
            return Err(SecurityError::PathTraversal.into());
        }

        Ok(path.to_path_buf())
    }

    /// Additional security validation for source paths
    fn validate_source_security(path: &Path) -> Result<()> {
        // Check if path is a symlink to prevent symlink attacks
        if path.read_link().is_ok() {
            return Err(SecurityError::SymlinkNotAllowed.into());
        }

        // Ensure path exists and is readable
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

    /// Enhanced directory binding validation
    pub fn validate_directory_binding(source: &Path, target: &Path) -> Result<(PathBuf, PathBuf)> {
        let validated_source = validate_source_path(source)?;
        let validated_target = validate_target_path(target)?;

        // Additional cross-validation
        check_binding_security(&validated_source, &validated_target)?;

        Ok((validated_source, validated_target))
    }

    /// Security checks across source and target binding
    fn check_binding_security(source: &Path, target: &Path) -> Result<()> {
        let source_str = source.to_string_lossy();
        let target_str = target.to_string_lossy();

        // Prevent binding system directories to writable locations
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
