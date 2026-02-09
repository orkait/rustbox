/// Namespace isolation for enhanced security
/// Provides PID, mount, and network namespace isolation capabilities
use crate::config::types::{IsolateError, Result};

use nix::sched::{unshare, CloneFlags};
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
        // Check if we can read /proc/self/ns/ directory
        std::fs::read_dir("/proc/self/ns").is_ok()
    }

    /// Apply namespace isolation using unshare syscalls
    /// This must be called before forking the target process
    pub fn apply_isolation(&self) -> Result<()> {
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

            if self.enable_network_namespace {
                self.bring_up_loopback()?;
            }

            log::info!(
                "Successfully applied namespace isolation: {:?}",
                self.get_enabled_namespaces()
            );
        }

        Ok(())
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

    fn bring_up_loopback(&self) -> Result<()> {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if sock < 0 {
            return Err(IsolateError::Namespace(format!(
                "Failed to open socket for loopback setup: {}",
                std::io::Error::last_os_error()
            )));
        }

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let lo_name = b"lo\0";
        for (idx, b) in lo_name.iter().enumerate() {
            ifr.ifr_name[idx] = *b as libc::c_char;
        }

        let get_flags_rc = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) };
        if get_flags_rc != 0 {
            let err = std::io::Error::last_os_error();
            let _ = unsafe { libc::close(sock) };
            return Err(IsolateError::Namespace(format!(
                "Failed to query loopback flags: {}",
                err
            )));
        }

        let current_flags = unsafe { ifr.ifr_ifru.ifru_flags } as libc::c_int;
        let updated_flags = current_flags | libc::IFF_UP;
        ifr.ifr_ifru.ifru_flags = updated_flags as libc::c_short;

        let set_flags_rc = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) };
        let close_rc = unsafe { libc::close(sock) };
        if close_rc != 0 {
            log::warn!(
                "Failed to close loopback setup socket cleanly: {}",
                std::io::Error::last_os_error()
            );
        }

        if set_flags_rc != 0 {
            return Err(IsolateError::Namespace(format!(
                "Failed to bring up loopback interface: {}",
                std::io::Error::last_os_error()
            )));
        }

        log::info!("Enabled loopback interface inside network namespace");
        Ok(())
    }
}

/// Standalone function to harden mount propagation
/// Per plan.md Section 6: mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)
/// This is CRITICAL - must succeed or abort
///
/// This function is public so it can be called from the type-state chain
pub fn harden_mount_propagation() -> Result<()> {
    use nix::mount::{mount, MsFlags};

    // Make / private and recursive
    // This prevents any mount changes in the sandbox from propagating to the host
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| {
        IsolateError::Namespace(format!(
            "CRITICAL: Failed to harden mount propagation (MS_PRIVATE|MS_REC on /): {}. \
            This is a fatal security failure - sandbox mount changes could propagate to host.",
            e
        ))
    })?;

    log::info!("Mount propagation hardened: / set to MS_PRIVATE|MS_REC");
    Ok(())
}
