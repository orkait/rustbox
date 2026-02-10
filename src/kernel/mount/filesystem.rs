//! Filesystem isolation via chroot jail and hardened mount operations.

use crate::config::types::{IsolateError, Result};
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Clone, Debug)]
pub struct FilesystemSecurity {
    chroot_dir: Option<PathBuf>,
    workdir: PathBuf,
    strict_mode: bool,
    tmpfs_size_bytes: u64,
    tmpfs_inode_limit: u64,
}

#[derive(Debug, Clone, Copy)]
struct DeviceNode {
    name: &'static str,
    mode: libc::mode_t,
    major: u32,
    minor: u32,
}

impl DeviceNode {
    const NULL: Self = Self { name: "null", mode: libc::S_IFCHR, major: 1, minor: 3 };
    const ZERO: Self = Self { name: "zero", mode: libc::S_IFCHR, major: 1, minor: 5 };
    const RANDOM: Self = Self { name: "random", mode: libc::S_IFCHR, major: 1, minor: 8 };
    const URANDOM: Self = Self { name: "urandom", mode: libc::S_IFCHR, major: 1, minor: 9 };

    const ESSENTIAL_DEVICES: &'static [Self] = &[
        Self::NULL, Self::ZERO, Self::RANDOM, Self::URANDOM,
    ];
}

impl FilesystemSecurity {
    const DEFAULT_TMPFS_SIZE_BYTES: u64 = 256 * 1024 * 1024;

    pub fn new(
        chroot_dir: Option<PathBuf>,
        workdir: PathBuf,
        strict_mode: bool,
        tmpfs_size_bytes: Option<u64>,
        tmpfs_inode_limit: Option<u64>,
    ) -> Self {
        let size = tmpfs_size_bytes
            .unwrap_or(Self::DEFAULT_TMPFS_SIZE_BYTES)
            .max(4 * 1024 * 1024);
        let default_inodes = (size / 16_384).clamp(4_096, 1_048_576);
        let inodes = tmpfs_inode_limit.unwrap_or(default_inodes).max(1_024);

        Self {
            chroot_dir,
            workdir,
            strict_mode,
            tmpfs_size_bytes: size,
            tmpfs_inode_limit: inodes,
        }
    }

    /// In strict mode, auto-creates a bounded tmpfs root regardless of chroot_dir.
    pub fn setup_isolation(&mut self) -> Result<()> {
        #[cfg(unix)]
        if self.strict_mode {
            if self.chroot_dir.is_some() {
                log::warn!(
                    "Strict mode ignores explicit chroot_dir and uses auto tmpfs root for quota safety"
                );
            }
            let tmpfs_root = self.auto_create_tmpfs_root()?;
            self.chroot_dir = Some(tmpfs_root);
        }

        if let Some(ref chroot_path) = self.chroot_dir {
            self.setup_chroot_jail(chroot_path)?;
            self.mount_standard_bind_set(chroot_path)?;
            self.setup_hardened_mounts(chroot_path)?;
        }

        self.setup_workdir()?;
        Ok(())
    }

    pub fn setup_directory_bindings(
        &self,
        bindings: &[crate::config::types::DirectoryBinding],
    ) -> Result<()> {
        for binding in bindings {
            self.setup_single_binding(binding)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    fn setup_single_binding(&self, binding: &crate::config::types::DirectoryBinding) -> Result<()> {
        use crate::config::types::DirectoryPermissions;

        if self.strict_mode && binding.permissions == DirectoryPermissions::ReadWrite {
            return Err(IsolateError::Config(format!(
                "Read-write directory bindings are disallowed in strict mode: {} -> {}",
                binding.source.display(), binding.target.display()
            )));
        }

        if binding.maybe && !binding.source.exists() {
            log::debug!("Skipping non-existent directory binding: {}", binding.source.display());
            return Ok(());
        }

        let target_path = if let Some(ref chroot_path) = self.chroot_dir {
            chroot_path.join(binding.target.strip_prefix("/").unwrap_or(&binding.target))
        } else if binding.target.is_absolute() {
            self.workdir.join(binding.target.strip_prefix("/").unwrap_or(&binding.target))
        } else {
            self.workdir.join(&binding.target)
        };

        if let Some(parent) = target_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| {
                    IsolateError::Config(format!("Failed to create target parent directory: {}", e))
                })?;
            }
        }

        if !target_path.exists() {
            fs::create_dir_all(&target_path).map_err(|e| {
                IsolateError::Config(format!("Failed to create target directory: {}", e))
            })?;
        }

        if binding.is_tmp {
            log::info!("Created temporary directory at {}", target_path.display());
            return Ok(());
        }

        let read_only = matches!(
            binding.permissions,
            DirectoryPermissions::ReadOnly | DirectoryPermissions::NoExec
        );
        let no_exec = binding.permissions == DirectoryPermissions::NoExec;

        let source_cstr = std::ffi::CString::new(binding.source.to_string_lossy().as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid source path: {}", e)))?;
        let target_cstr = std::ffi::CString::new(target_path.to_string_lossy().as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid target path: {}", e)))?;

        // SAFETY: mount(2) with MS_BIND, valid CString pointers from above.
        let bind_result = unsafe {
            libc::mount(
                source_cstr.as_ptr(), target_cstr.as_ptr(),
                std::ptr::null(), libc::MS_BIND, std::ptr::null(),
            )
        };

        if bind_result != 0 {
            let err = std::io::Error::last_os_error();
            if self.strict_mode {
                return Err(IsolateError::Config(format!(
                    "Failed to bind mount {} to {}: {}",
                    binding.source.display(), target_path.display(), err
                )));
            } else {
                log::warn!(
                    "Failed to bind mount {} to {}: {} (falling back to file copy)",
                    binding.source.display(), target_path.display(), err
                );
                self.copy_directory_contents(&binding.source, &target_path)?;
                log::info!(
                    "Copied directory contents from {} to {} (fallback mode)",
                    binding.source.display(), target_path.display()
                );
            }
        }

        if read_only {
            let mut remount_flags = libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY;
            remount_flags |= libc::MS_NOSUID | libc::MS_NODEV;
            if no_exec {
                remount_flags |= libc::MS_NOEXEC;
            }

            // SAFETY: mount(2) remount with MS_RDONLY on an existing bind mount.
            let remount_result = unsafe {
                libc::mount(
                    std::ptr::null(), target_cstr.as_ptr(),
                    std::ptr::null(), remount_flags, std::ptr::null(),
                )
            };

            if remount_result != 0 {
                let err = std::io::Error::last_os_error();
                if self.strict_mode {
                    return Err(IsolateError::Config(format!(
                        "Failed to remount read-only {} to {}: {}",
                        binding.source.display(), target_path.display(), err
                    )));
                }
                log::warn!(
                    "Failed to remount read-only {} to {}: {}",
                    binding.source.display(), target_path.display(), err
                );
            }
        }

        log::info!(
            "Bound directory {} to {} with permissions {:?}",
            binding.source.display(), target_path.display(), binding.permissions
        );

        Ok(())
    }

    fn copy_directory_contents(&self, source: &Path, target: &Path) -> Result<()> {
        if !source.exists() {
            return Err(IsolateError::Config(format!(
                "Source directory does not exist: {}", source.display()
            )));
        }

        if !target.exists() {
            fs::create_dir_all(target).map_err(|e| {
                IsolateError::Config(format!("Failed to create target directory: {}", e))
            })?;
        }

        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let source_path = entry.path();
            let target_path = target.join(entry.file_name());

            if source_path.is_dir() {
                self.copy_directory_contents(&source_path, &target_path)?;
            } else if source_path.is_file() {
                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(&source_path, &target_path)?;
            }
        }

        Ok(())
    }

    #[cfg(unix)]
    fn auto_create_tmpfs_root(&self) -> Result<PathBuf> {
        let tmpfs_root =
            std::env::temp_dir().join(format!("rustbox-strict-root-{}", std::process::id()));

        fs::create_dir_all(&tmpfs_root)
            .map_err(|e| IsolateError::Config(format!("Failed to create tmpfs root dir: {}", e)))?;

        let target_cstr = std::ffi::CString::new(tmpfs_root.to_string_lossy().as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid tmpfs root path: {}", e)))?;
        let fstype_cstr = std::ffi::CString::new("tmpfs").unwrap();
        let source_cstr = std::ffi::CString::new("tmpfs").unwrap();
        let mount_opts = format!(
            "size={},nr_inodes={},mode=755",
            self.tmpfs_size_bytes, self.tmpfs_inode_limit
        );
        let opts_cstr = std::ffi::CString::new(mount_opts.as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid tmpfs options: {}", e)))?;

        let flags = libc::MS_NOSUID | libc::MS_NODEV;
        // SAFETY: mount(2) with valid CString pointers, tmpfs type, bounded options.
        let result = unsafe {
            libc::mount(
                source_cstr.as_ptr(), target_cstr.as_ptr(),
                fstype_cstr.as_ptr(), flags,
                opts_cstr.as_ptr() as *const libc::c_void,
            )
        };

        if result != 0 {
            let err = std::io::Error::last_os_error();
            return Err(IsolateError::Config(format!(
                "Failed to mount tmpfs at {}: {}", tmpfs_root.display(), err
            )));
        }

        log::info!(
            "Auto-created strict tmpfs root at {} (size={}, nr_inodes={})",
            tmpfs_root.display(), self.tmpfs_size_bytes, self.tmpfs_inode_limit
        );

        let ws_in_root = tmpfs_root.join(self.workdir.strip_prefix("/").unwrap_or(&self.workdir));
        fs::create_dir_all(&ws_in_root).map_err(|e| {
            IsolateError::Config(format!("Failed to create workspace in tmpfs root: {}", e))
        })?;

        if self.workdir.exists() {
            self.copy_directory_contents(&self.workdir, &ws_in_root)?;
            log::info!("Copied workspace {} into strict tmpfs root", self.workdir.display());
        }

        Ok(tmpfs_root)
    }

    /// Bind-mount /bin, /lib, /lib64, /usr read-only into chroot.
    #[cfg(unix)]
    fn mount_standard_bind_set(&self, chroot_path: &Path) -> Result<()> {
        let ro_dirs = ["/bin", "/lib", "/lib64", "/usr"];

        for dir in &ro_dirs {
            let src = Path::new(dir);
            if !src.exists() {
                log::debug!("Skipping non-existent standard dir: {}", dir);
                continue;
            }

            let target = chroot_path.join(dir.strip_prefix('/').unwrap_or(dir));
            if !target.exists() {
                fs::create_dir_all(&target).map_err(|e| {
                    IsolateError::Config(format!("Failed to create bind target {}: {}", target.display(), e))
                })?;
            }

            self.bind_mount_readonly(src, &target)?;
        }

        Ok(())
    }

    /// Two-pass: MS_BIND then MS_BIND|MS_REMOUNT|MS_RDONLY.
    #[cfg(unix)]
    fn bind_mount_readonly(&self, source: &Path, target: &Path) -> Result<()> {
        let src_cstr = std::ffi::CString::new(source.to_string_lossy().as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid source path: {}", e)))?;
        let tgt_cstr = std::ffi::CString::new(target.to_string_lossy().as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid target path: {}", e)))?;

        // SAFETY: mount(2) bind mount with valid CString pointers.
        let result = unsafe {
            libc::mount(
                src_cstr.as_ptr(), tgt_cstr.as_ptr(),
                std::ptr::null(), libc::MS_BIND, std::ptr::null(),
            )
        };
        if result != 0 {
            let err = std::io::Error::last_os_error();
            if self.strict_mode {
                return Err(IsolateError::Config(format!(
                    "Failed to bind mount {} -> {}: {}", source.display(), target.display(), err
                )));
            }
            log::warn!("Failed to bind mount {} -> {}: {}", source.display(), target.display(), err);
            return Ok(());
        }

        // SAFETY: mount(2) remount to make read-only.
        let ro_flags =
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV;
        let result = unsafe {
            libc::mount(
                std::ptr::null(), tgt_cstr.as_ptr(),
                std::ptr::null(), ro_flags, std::ptr::null(),
            )
        };
        if result != 0 {
            let err = std::io::Error::last_os_error();
            if self.strict_mode {
                return Err(IsolateError::Config(format!(
                    "Failed to remount {} read-only: {}", target.display(), err
                )));
            }
            log::warn!("Failed to remount {} read-only: {}", target.display(), err);
        } else {
            log::info!("Bind-mounted {} -> {} (read-only)", source.display(), target.display());
        }

        Ok(())
    }

    #[cfg(unix)]
    fn setup_chroot_jail(&self, chroot_path: &Path) -> Result<()> {
        if !chroot_path.exists() {
            fs::create_dir_all(chroot_path).map_err(|e| {
                IsolateError::Config(format!("Failed to create chroot directory: {}", e))
            })?;
        }

        self.create_chroot_structure(chroot_path)?;
        self.apply_mount_security_flags(chroot_path)?;
        Ok(())
    }

    #[cfg(unix)]
    fn create_chroot_structure(&self, chroot_path: &Path) -> Result<()> {
        let essential_dirs = [
            "tmp", "dev", "proc", "usr/bin", "bin", "lib", "lib64", "etc",
        ];

        for dir in &essential_dirs {
            let dir_path = chroot_path.join(dir);
            if !dir_path.exists() {
                fs::create_dir_all(&dir_path).map_err(|e| {
                    IsolateError::Config(format!("Failed to create chroot dir {}: {}", dir, e))
                })?;
            }

            let metadata = fs::metadata(&dir_path)?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&dir_path, perms)?;
        }

        self.create_essential_devices(chroot_path)?;
        Ok(())
    }

    #[cfg(unix)]
    fn create_essential_devices(&self, chroot_path: &Path) -> Result<()> {
        let dev_dir = chroot_path.join("dev");
        for device in DeviceNode::ESSENTIAL_DEVICES {
            self.create_device_node(&dev_dir, device)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    fn create_device_node(&self, dev_dir: &Path, device: &DeviceNode) -> Result<()> {
        let device_path = dev_dir.join(device.name);
        if device_path.exists() {
            return Ok(());
        }

        let path_cstr = std::ffi::CString::new(device_path.to_string_lossy().as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid path: {}", e)))?;

        // SAFETY: mknod(2) with valid CString path, character device mode, valid major:minor.
        let result = unsafe {
            libc::mknod(
                path_cstr.as_ptr(),
                device.mode | 0o666,
                libc::makedev(device.major, device.minor),
            )
        };

        if result != 0 {
            // Fallback: create regular file if mknod fails (non-root)
            fs::File::create(&device_path).map_err(|e| {
                IsolateError::Config(format!("Failed to create /dev/{}: {}", device.name, e))
            })?;
        }

        Ok(())
    }

    #[cfg(unix)]
    fn apply_mount_security_flags(&self, chroot_path: &Path) -> Result<()> {
        let mount_flags = libc::MS_NOEXEC | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_BIND;

        let path_cstr = std::ffi::CString::new(chroot_path.to_string_lossy().as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid chroot path: {}", e)))?;

        // SAFETY: mount(2) bind mount with security flags on chroot root.
        let result = unsafe {
            libc::mount(
                path_cstr.as_ptr(), path_cstr.as_ptr(),
                std::ptr::null(), mount_flags, std::ptr::null(),
            )
        };

        if result != 0 && self.strict_mode {
            let err = std::io::Error::last_os_error();
            return Err(IsolateError::Config(format!(
                "Failed to apply mount security flags: {}", err
            )));
        }

        Ok(())
    }

    #[cfg(unix)]
    fn setup_hardened_mounts(&self, chroot_path: &Path) -> Result<()> {
        let sys_path = chroot_path.join("sys");
        if sys_path.exists() {
            self.mount_hardened_sysfs(&sys_path)?;
        }

        let dev_path = chroot_path.join("dev");
        if dev_path.exists() {
            self.mount_hardened_devfs(&dev_path)?;
        }

        let proc_path = chroot_path.join("proc");
        if proc_path.exists() {
            self.mount_hardened_procfs(&proc_path)?;
        }

        Ok(())
    }

    #[cfg(unix)]
    fn mount_hardened_sysfs(&self, sys_path: &Path) -> Result<()> {
        let mount_flags = libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV;

        let source_cstr = std::ffi::CString::new("sysfs").unwrap();
        let target_cstr = std::ffi::CString::new(sys_path.to_string_lossy().as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid sys path: {}", e)))?;
        let fstype_cstr = std::ffi::CString::new("sysfs").unwrap();

        // SAFETY: mount(2) sysfs with read-only flags.
        let result = unsafe {
            libc::mount(
                source_cstr.as_ptr(), target_cstr.as_ptr(),
                fstype_cstr.as_ptr(), mount_flags, std::ptr::null(),
            )
        };

        if result != 0 {
            let err = std::io::Error::last_os_error();
            if self.strict_mode {
                return Err(IsolateError::Config(format!("Failed to mount hardened sysfs: {}", err)));
            }
            log::warn!("Failed to mount hardened sysfs: {}", err);
        } else {
            log::info!("Mounted hardened sysfs at {}", sys_path.display());
        }

        Ok(())
    }

    /// Mount tmpfs on /dev with 64K size limit and minimal device nodes.
    #[cfg(unix)]
    fn mount_hardened_devfs(&self, dev_path: &Path) -> Result<()> {
        let mount_flags = libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NOATIME;

        let source_cstr = std::ffi::CString::new("tmpfs").unwrap();
        let target_cstr = std::ffi::CString::new(dev_path.to_string_lossy().as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid dev path: {}", e)))?;
        let fstype_cstr = std::ffi::CString::new("tmpfs").unwrap();
        let options_cstr = std::ffi::CString::new("size=64k,mode=755").unwrap();

        // SAFETY: mount(2) tmpfs with bounded size on /dev.
        let result = unsafe {
            libc::mount(
                source_cstr.as_ptr(), target_cstr.as_ptr(),
                fstype_cstr.as_ptr(), mount_flags,
                options_cstr.as_ptr() as *const libc::c_void,
            )
        };

        if result != 0 {
            let err = std::io::Error::last_os_error();
            if self.strict_mode {
                return Err(IsolateError::Config(format!("Failed to mount tmpfs on /dev: {}", err)));
            }
            log::warn!("Failed to mount tmpfs on /dev: {}", err);
            return Ok(());
        }

        log::info!("Mounted hardened tmpfs at {}", dev_path.display());
        self.create_minimal_devices(dev_path)?;
        Ok(())
    }

    /// Mount procfs with hidepid=2 for process hiding.
    #[cfg(unix)]
    fn mount_hardened_procfs(&self, proc_path: &Path) -> Result<()> {
        let mount_flags = libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV;
        let hidepid_opts = std::ffi::CString::new("hidepid=2").unwrap();

        let source_cstr = std::ffi::CString::new("proc").unwrap();
        let target_cstr = std::ffi::CString::new(proc_path.to_string_lossy().as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid proc path: {}", e)))?;
        let fstype_cstr = std::ffi::CString::new("proc").unwrap();

        // SAFETY: mount(2) procfs with hidepid=2 for process isolation.
        let result = unsafe {
            libc::mount(
                source_cstr.as_ptr(), target_cstr.as_ptr(),
                fstype_cstr.as_ptr(), mount_flags,
                hidepid_opts.as_ptr() as *const libc::c_void,
            )
        };

        if result != 0 {
            let err = std::io::Error::last_os_error();
            if self.strict_mode {
                return Err(IsolateError::Config(format!(
                    "Failed to mount hardened procfs with hidepid=2: {}", err
                )));
            }
            log::warn!("Failed to mount procfs with hidepid=2: {}. Retrying without hidepid.", err);
            // SAFETY: mount(2) procfs fallback without hidepid.
            let fallback = unsafe {
                libc::mount(
                    source_cstr.as_ptr(), target_cstr.as_ptr(),
                    fstype_cstr.as_ptr(), mount_flags, std::ptr::null(),
                )
            };
            if fallback != 0 {
                let fallback_err = std::io::Error::last_os_error();
                log::warn!("Failed to mount fallback procfs: {}", fallback_err);
            }
        } else {
            log::info!("Mounted hardened procfs with hidepid=2 at {}", proc_path.display());
        }

        Ok(())
    }

    #[cfg(unix)]
    fn create_minimal_devices(&self, dev_path: &Path) -> Result<()> {
        for device in DeviceNode::ESSENTIAL_DEVICES {
            let device_path = dev_path.join(device.name);
            let path_cstr = std::ffi::CString::new(device_path.to_string_lossy().as_bytes())
                .map_err(|e| IsolateError::Config(format!("Invalid device path: {}", e)))?;

            // SAFETY: mknod(2) with valid path, char device type, valid major:minor.
            let result = unsafe {
                libc::mknod(
                    path_cstr.as_ptr(),
                    device.mode | 0o666,
                    libc::makedev(device.major, device.minor),
                )
            };

            if result != 0 {
                let err = std::io::Error::last_os_error();
                log::warn!("Failed to create device {}: {}", device.name, err);
            } else {
                log::debug!("Created device node: {}", device_path.display());
            }
        }

        Ok(())
    }

    /// Perform chroot(2). Must be called in child process.
    #[cfg(unix)]
    pub fn apply_chroot(&self) -> Result<()> {
        if let Some(ref chroot_path) = self.chroot_dir {
            let path_cstr = std::ffi::CString::new(chroot_path.to_string_lossy().as_bytes())
                .map_err(|e| IsolateError::Config(format!("Invalid chroot path: {}", e)))?;

            // SAFETY: chroot(2) with valid CString path.
            let result = unsafe { libc::chroot(path_cstr.as_ptr()) };
            if result != 0 {
                let err = std::io::Error::last_os_error();
                return Err(IsolateError::Config(format!("chroot failed: {}", err)));
            }

            std::env::set_current_dir("/").map_err(|e| {
                IsolateError::Config(format!("Failed to change to chroot root: {}", e))
            })?;
        }
        Ok(())
    }

    fn setup_workdir(&self) -> Result<()> {
        let actual_workdir = if self.chroot_dir.is_some() {
            PathBuf::from("/").join(self.workdir.strip_prefix("/").unwrap_or(&self.workdir))
        } else {
            self.workdir.clone()
        };

        if !actual_workdir.exists() {
            fs::create_dir_all(&actual_workdir)
                .map_err(|e| IsolateError::Config(format!("Failed to create workdir: {}", e)))?;
        }

        #[cfg(unix)]
        {
            let metadata = fs::metadata(&actual_workdir)?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&actual_workdir, perms)?;
        }

        Ok(())
    }

    pub fn validate_path(&self, path: &Path) -> Result<()> {
        let canonical_path = path.canonicalize()
            .map_err(|e| IsolateError::Config(format!("Failed to canonicalize path: {}", e)))?;

        if let Some(ref chroot_path) = self.chroot_dir {
            let canonical_chroot = chroot_path.canonicalize().map_err(|e| {
                IsolateError::Config(format!("Failed to canonicalize chroot path: {}", e))
            })?;

            if !canonical_path.starts_with(&canonical_chroot) {
                return Err(IsolateError::Config(format!(
                    "Path {} is outside chroot jail {}",
                    canonical_path.display(), canonical_chroot.display()
                )));
            }
        }

        let dangerous_paths = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/root", "/boot", "/sys", "/proc/sys",
        ];

        let path_str = canonical_path.to_string_lossy();
        for dangerous in &dangerous_paths {
            if path_str.starts_with(dangerous) {
                return Err(IsolateError::Config(format!(
                    "Access to dangerous path {} is forbidden", path_str
                )));
            }
        }

        Ok(())
    }

    pub fn cleanup(&self) -> Result<()> {
        #[cfg(unix)]
        if let Some(ref chroot_path) = self.chroot_dir {
            let path_cstr = std::ffi::CString::new(chroot_path.to_string_lossy().as_bytes())
                .map_err(|e| IsolateError::Config(format!("Invalid chroot path: {}", e)))?;
            // SAFETY: umount(2) on chroot path; non-fatal if not mounted.
            unsafe { libc::umount(path_cstr.as_ptr()); }
        }
        Ok(())
    }

    pub fn is_isolated(&self) -> bool {
        self.chroot_dir.is_some()
    }

    pub fn get_effective_workdir(&self) -> PathBuf {
        if self.chroot_dir.is_some() {
            PathBuf::from("/").join(self.workdir.strip_prefix("/").unwrap_or(&self.workdir))
        } else {
            self.workdir.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{DirectoryBinding, DirectoryPermissions};

    #[test]
    fn strict_mode_rejects_read_write_directory_binding() {
        let fs_sec = FilesystemSecurity::new(
            None, PathBuf::from("/tmp/rustbox-test-workdir"), true, None, None,
        );

        let binding = DirectoryBinding {
            source: PathBuf::from("/tmp/host-data"),
            target: PathBuf::from("/data"),
            permissions: DirectoryPermissions::ReadWrite,
            maybe: true,
            is_tmp: false,
        };

        let result = fs_sec.setup_directory_bindings(&[binding]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Read-write directory bindings are disallowed"));
    }
}
