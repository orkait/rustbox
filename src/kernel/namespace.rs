//! Process isolation via Linux namespaces.

use crate::config::types::{IsolateError, Result};
use nix::sched::{unshare, CloneFlags};
use nix::unistd::sethostname;

#[derive(Debug, Clone)]
pub struct NamespaceIsolation {
    enable_pid_namespace: bool,
    enable_mount_namespace: bool,
    enable_network_namespace: bool,
    enable_user_namespace: bool,
    enable_ipc_namespace: bool,
    enable_uts_namespace: bool,
}

impl NamespaceIsolation {
    pub fn builder() -> NamespaceIsolationBuilder {
        NamespaceIsolationBuilder::default()
    }

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

    /// All namespaces enabled except user.
    pub fn new_default() -> Self {
        Self::new(true, true, true, false, true, true)
    }

    pub fn is_supported() -> bool {
        std::fs::read_dir("/proc/self/ns").is_ok()
    }

    /// Apply namespace isolation via unshare(2). Must be called before fork.
    pub fn apply_isolation(&self) -> Result<()> {
        let mut flags = CloneFlags::empty();

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

            if self.enable_uts_namespace {
                if let Err(e) = sethostname("rustbox-sandbox") {
                    log::warn!("Failed to set hostname in UTS namespace: {}", e);
                }
            }

            if self.enable_network_namespace {
                self.bring_up_loopback()?;
            }

            log::info!(
                "Namespace isolation applied: {:?}",
                self.get_enabled_namespaces()
            );
        }

        Ok(())
    }

    pub fn is_isolation_enabled(&self) -> bool {
        self.enable_pid_namespace
            || self.enable_mount_namespace
            || self.enable_network_namespace
            || self.enable_user_namespace
            || self.enable_ipc_namespace
            || self.enable_uts_namespace
    }

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
        // SAFETY: socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, 0) creates a UDP socket
        // for ioctl use. Valid parameters, no pointer dereference.
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if sock < 0 {
            return Err(IsolateError::Namespace(format!(
                "Failed to open socket for loopback setup: {}",
                std::io::Error::last_os_error()
            )));
        }

        // SAFETY: zeroed ifreq is a valid initial state for the struct.
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let lo_name = b"lo\0";
        for (idx, b) in lo_name.iter().enumerate() {
            ifr.ifr_name[idx] = *b as libc::c_char;
        }

        // SAFETY: ioctl(SIOCGIFFLAGS) reads interface flags into initialized ifreq.
        let get_flags_rc = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) };
        if get_flags_rc != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(sock) };
            return Err(IsolateError::Namespace(format!(
                "Failed to query loopback flags: {}",
                err
            )));
        }

        // SAFETY: ifr_ifru union was populated by SIOCGIFFLAGS.
        let current_flags = unsafe { ifr.ifr_ifru.ifru_flags } as libc::c_int;
        ifr.ifr_ifru.ifru_flags = (current_flags | libc::IFF_UP) as libc::c_short;

        // SAFETY: ioctl(SIOCSIFFLAGS) sets the IFF_UP flag on the loopback interface.
        let set_flags_rc = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) };

        // SAFETY: close(2) on a valid fd.
        let close_rc = unsafe { libc::close(sock) };
        if close_rc != 0 {
            log::warn!(
                "Failed to close loopback setup socket: {}",
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

/// CRITICAL: Sets mount propagation to MS_PRIVATE|MS_REC on /.
/// Without this, sandbox mounts propagate to host. Must succeed or abort.
pub fn harden_mount_propagation() -> Result<()> {
    use nix::mount::{mount, MsFlags};

    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| {
        IsolateError::Namespace(format!(
            "CRITICAL: Failed to harden mount propagation (MS_PRIVATE|MS_REC on /): {}",
            e
        ))
    })?;

    log::info!("Mount propagation hardened: / set to MS_PRIVATE|MS_REC");
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct NamespaceIsolationBuilder {
    enable_pid: bool,
    enable_mount: bool,
    enable_network: bool,
    enable_user: bool,
    enable_ipc: bool,
    enable_uts: bool,
}

impl NamespaceIsolationBuilder {
    pub fn with_pid(mut self) -> Self {
        self.enable_pid = true;
        self
    }

    pub fn with_mount(mut self) -> Self {
        self.enable_mount = true;
        self
    }

    pub fn with_network(mut self) -> Self {
        self.enable_network = true;
        self
    }

    pub fn with_user(mut self) -> Self {
        self.enable_user = true;
        self
    }

    pub fn with_ipc(mut self) -> Self {
        self.enable_ipc = true;
        self
    }

    pub fn with_uts(mut self) -> Self {
        self.enable_uts = true;
        self
    }

    pub fn with_all_except_user(mut self) -> Self {
        self.enable_pid = true;
        self.enable_mount = true;
        self.enable_network = true;
        self.enable_ipc = true;
        self.enable_uts = true;
        self
    }

    pub fn build(self) -> NamespaceIsolation {
        NamespaceIsolation::new(
            self.enable_pid,
            self.enable_mount,
            self.enable_network,
            self.enable_user,
            self.enable_ipc,
            self.enable_uts,
        )
    }
}
