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

    pub fn new_default() -> Self {
        Self::new(true, true, true, false, true, true)
    }

    pub fn is_supported() -> bool {
        std::fs::read_dir("/proc/self/ns").is_ok()
    }

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
                let _ = sethostname("rustbox-sandbox");
            }
            if self.enable_network_namespace {
                self.bring_up_loopback()?;
            }
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

    pub fn get_enabled_namespaces(&self) -> Vec<&'static str> {
        let mut namespaces = Vec::new();
        if self.enable_pid_namespace {
            namespaces.push("PID");
        }
        if self.enable_mount_namespace {
            namespaces.push("Mount");
        }
        if self.enable_network_namespace {
            namespaces.push("Network");
        }
        if self.enable_user_namespace {
            namespaces.push("User");
        }
        if self.enable_ipc_namespace {
            namespaces.push("IPC");
        }
        if self.enable_uts_namespace {
            namespaces.push("UTS");
        }
        namespaces
    }

    fn bring_up_loopback(&self) -> Result<()> {
        // SAFETY: socket arguments are constants with no aliasing or borrowed memory.
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if sock < 0 {
            return Err(IsolateError::Namespace(format!(
                "Failed to open socket for loopback setup: {}",
                std::io::Error::last_os_error()
            )));
        }

        // SAFETY: zeroed ifreq is a valid initial state.
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let lo = b"lo\0";
        for (idx, b) in lo.iter().enumerate() {
            ifr.ifr_name[idx] = *b as libc::c_char;
        }

        // SAFETY: ioctl writes interface flags into valid ifreq pointer.
        let get_flags = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) };
        if get_flags != 0 {
            let err = std::io::Error::last_os_error();
            // SAFETY: closing valid descriptor.
            unsafe { libc::close(sock) };
            return Err(IsolateError::Namespace(format!(
                "Failed to query loopback flags: {}",
                err
            )));
        }

        // SAFETY: union was populated by SIOCGIFFLAGS.
        let current_flags = unsafe { ifr.ifr_ifru.ifru_flags } as libc::c_int;
        ifr.ifr_ifru.ifru_flags = (current_flags | libc::IFF_UP) as libc::c_short;

        // SAFETY: ioctl reads from initialized ifreq.
        let set_flags = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) };
        let ioctl_err = std::io::Error::last_os_error();
        // SAFETY: close valid descriptor.
        let _ = unsafe { libc::close(sock) };

        if set_flags != 0 {
            return Err(IsolateError::Namespace(format!(
                "Failed to bring up loopback interface: {}",
                ioctl_err
            )));
        }

        Ok(())
    }
}

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
