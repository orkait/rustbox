/// Namespace isolation for enhanced security
/// Provides PID, mount, and network namespace isolation capabilities
use crate::types::{IsolateError, Result};

#[cfg(unix)]
use nix::sched::{unshare, CloneFlags};
#[cfg(unix)]
use nix::unistd::sethostname;

/// Namespace isolation controller
pub struct NamespaceIsolation {
    /// Enable PID namespace isolation
    enable_pid_namespace: bool,
    /// Enable mount namespace isolation
    enable_mount_namespace: bool,
    /// Enable network namespace isolation
    enable_network_namespace: bool,
    /// Enable user namespace isolation
    enable_user_namespace: bool,
    /// Enable IPC namespace isolation
    enable_ipc_namespace: bool,
    /// Enable UTS namespace isolation  
    enable_uts_namespace: bool,
}

impl NamespaceIsolation {
    /// Create a new namespace isolation controller
    pub fn new(
        enable_pid: bool,
        enable_mount: bool,
        enable_network: bool,
        enable_user: bool,
        enable_ipc: bool,
        enable_uts: bool,
    ) -> Self {
        Self {
            enable_pid_namespace: enable_pid,
            enable_mount_namespace: enable_mount,
            enable_network_namespace: enable_network,
            enable_user_namespace: enable_user,
            enable_ipc_namespace: enable_ipc,
            enable_uts_namespace: enable_uts,
        }
    }

    /// Create default namespace isolation (all namespaces enabled)
    pub fn new_default() -> Self {
        Self::new(true, true, true, false, true, true)
    }

    /// Check if namespace isolation is supported on this system
    pub fn is_supported() -> bool {
        #[cfg(unix)]
        {
            // Check if we can read /proc/self/ns/ directory
            std::fs::read_dir("/proc/self/ns").is_ok()
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    /// Apply namespace isolation using unshare syscalls
    /// This must be called before forking the target process
    pub fn apply_isolation(&self) -> Result<()> {
        #[cfg(unix)]
        {
            let mut flags = CloneFlags::empty();

            // Build clone flags for unshare
            if self.enable_pid_namespace {
                flags |= CloneFlags::CLONE_NEWPID;
            }
            if self.enable_mount_namespace {
                flags |= CloneFlags::CLONE_NEWNS;
            }
            if self.enable_network_namespace {
                flags |= CloneFlags::CLONE_NEWNET;
            }
            if self.enable_user_namespace {
                flags |= CloneFlags::CLONE_NEWUSER;
            }
            if self.enable_ipc_namespace {
                flags |= CloneFlags::CLONE_NEWIPC;
            }
            if self.enable_uts_namespace {
                flags |= CloneFlags::CLONE_NEWUTS;
            }

            if !flags.is_empty() {
                unshare(flags).map_err(|e| {
                    IsolateError::Namespace(format!("Failed to unshare namespaces: {}", e))
                })?;

                // Set hostname in UTS namespace if enabled
                if self.enable_uts_namespace {
                    if let Err(e) = sethostname("rustbox-sandbox") {
                        log::warn!("Failed to set hostname in UTS namespace: {}", e);
                    }
                }

                log::info!(
                    "Successfully applied namespace isolation: {:?}",
                    self.get_enabled_namespaces()
                );
            }

            Ok(())
        }
        #[cfg(not(unix))]
        {
            if self.is_isolation_enabled() {
                Err(IsolateError::Namespace(
                    "Namespace isolation is only supported on Unix systems".to_string(),
                ))
            } else {
                Ok(())
            }
        }
    }

    /// Check if any isolation is enabled
    pub fn is_isolation_enabled(&self) -> bool {
        self.enable_pid_namespace
            || self.enable_mount_namespace
            || self.enable_network_namespace
            || self.enable_user_namespace
            || self.enable_ipc_namespace
            || self.enable_uts_namespace
    }

    /// Get enabled namespaces as a string
    pub fn get_enabled_namespaces(&self) -> Vec<String> {
        let mut namespaces = Vec::new();

        if self.enable_pid_namespace {
            namespaces.push("PID".to_string());
        }
        if self.enable_mount_namespace {
            namespaces.push("Mount".to_string());
        }
        if self.enable_network_namespace {
            namespaces.push("Network".to_string());
        }
        if self.enable_user_namespace {
            namespaces.push("User".to_string());
        }
        if self.enable_ipc_namespace {
            namespaces.push("IPC".to_string());
        }
        if self.enable_uts_namespace {
            namespaces.push("UTS".to_string());
        }

        namespaces
    }
}