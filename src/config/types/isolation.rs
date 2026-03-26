use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

use super::error::IsolateError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryBinding {
    pub source: PathBuf,
    pub target: PathBuf,
    pub permissions: DirectoryPermissions,
    pub maybe: bool,
    pub is_tmp: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum DirectoryPermissions {
    ReadOnly,
    ReadWrite,
    NoExec,
}

impl DirectoryBinding {
    pub fn parse_secure(binding_str: &str) -> super::error::Result<Self> {
        use crate::observability::audit::events;
        use crate::runtime::security::path_validation;

        let parts: Vec<&str> = binding_str.split(':').collect();
        let path_part = parts[0];
        let options = if parts.len() > 1 { parts[1] } else { "" };

        let (source, target) = if path_part.contains('=') {
            let path_parts: Vec<&str> = path_part.split('=').collect();
            if path_parts.len() != 2 {
                return Err(IsolateError::Config(
                    "Invalid directory binding format. Use: source=target or source=target:options"
                        .to_string(),
                ));
            }
            (
                std::path::Path::new(path_parts[0]),
                std::path::Path::new(path_parts[1]),
            )
        } else {
            let path = std::path::Path::new(path_part);
            (path, path)
        };

        let (validated_source, validated_target) =
            match path_validation::validate_directory_binding(source, target) {
                Ok(paths) => paths,
                Err(e) => {
                    events::path_traversal_attempt(binding_str, None);
                    return Err(e);
                }
            };

        let mut permissions = DirectoryPermissions::ReadOnly;
        let mut maybe = false;
        let mut is_tmp = false;

        for option in options.split(',') {
            match option.trim() {
                "rw" => permissions = DirectoryPermissions::ReadWrite,
                "ro" => permissions = DirectoryPermissions::ReadOnly,
                "noexec" => permissions = DirectoryPermissions::NoExec,
                "maybe" => maybe = true,
                "tmp" => is_tmp = true,
                "" => {}
                _ => {
                    return Err(IsolateError::Config(format!(
                        "Unknown directory binding option: {}",
                        option
                    )))
                }
            }
        }

        Ok(DirectoryBinding {
            source: validated_source,
            target: validated_target,
            permissions,
            maybe,
            is_tmp,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IsolateConfig {
    pub instance_id: String,
    pub workdir: PathBuf,
    pub chroot_dir: Option<PathBuf>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub memory_limit: Option<u64>,
    pub time_limit: Option<Duration>,
    pub cpu_time_limit: Option<Duration>,
    pub wall_time_limit: Option<Duration>,
    pub process_limit: Option<u32>,
    pub file_size_limit: Option<u64>,
    pub stack_limit: Option<u64>,
    pub core_limit: Option<u64>,
    pub fd_limit: Option<u64>,
    pub virtual_memory_limit: Option<u64>,
    #[serde(skip_serializing, default)]
    pub environment: Vec<(String, String)>,
    pub strict_mode: bool,
    #[serde(default)]
    pub inherit_fds: bool,
    pub stdout_file: Option<PathBuf>,
    pub stderr_file: Option<PathBuf>,
    pub enable_tty: bool,
    pub use_pipes: bool,
    pub stdin_data: Option<String>,
    pub stdin_file: Option<PathBuf>,
    pub io_buffer_size: usize,
    pub text_encoding: String,
    pub enable_pid_namespace: bool,
    pub enable_mount_namespace: bool,
    pub enable_network_namespace: bool,
    pub enable_user_namespace: bool,
    #[serde(default)]
    pub allow_degraded: bool,
    #[serde(default)]
    pub no_seccomp: bool,
    #[serde(default)]
    pub seccomp_policy_file: Option<PathBuf>,
    pub directory_bindings: Vec<DirectoryBinding>,
    #[serde(default)]
    pub tmpfs_size_bytes: Option<u64>,
}

impl IsolateConfig {
    pub fn runtime_root_dir() -> PathBuf {
        let euid = unsafe { libc::geteuid() };
        std::env::temp_dir().join(format!("rustbox-uid-{}", euid))
    }
}

impl Default for IsolateConfig {
    fn default() -> Self {
        Self {
            instance_id: uuid::Uuid::new_v4().to_string(),
            workdir: Self::runtime_root_dir(),
            chroot_dir: None,
            uid: Some(65534),
            gid: Some(65534),
            memory_limit: Some(128 * 1024 * 1024),
            time_limit: Some(Duration::from_secs(10)),
            cpu_time_limit: Some(Duration::from_secs(10)),
            wall_time_limit: Some(Duration::from_secs(20)),
            process_limit: Some(10),
            file_size_limit: Some(64 * 1024 * 1024),
            stack_limit: Some(8 * 1024 * 1024),
            core_limit: Some(0),
            fd_limit: Some(64),
            virtual_memory_limit: None,
            environment: Vec::new(),
            strict_mode: true,
            inherit_fds: false,
            stdout_file: None,
            stderr_file: None,
            enable_tty: false,
            use_pipes: false,
            stdin_data: None,
            stdin_file: None,
            io_buffer_size: 8192,
            text_encoding: "utf-8".to_string(),
            enable_pid_namespace: true,
            enable_mount_namespace: true,
            enable_network_namespace: true,
            enable_user_namespace: false,
            allow_degraded: false,
            no_seccomp: false,
            seccomp_policy_file: None,
            directory_bindings: Vec::new(),
            tmpfs_size_bytes: None,
        }
    }
}
