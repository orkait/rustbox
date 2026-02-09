/// Filesystem security and isolation implementation
use crate::config::types::{IsolateError, Result};
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Filesystem security controller for process isolation
#[derive(Clone, Debug)]
pub struct FilesystemSecurity {
    /// Root directory for chroot jail
    chroot_dir: Option<PathBuf>,
    /// Working directory within the jail
    workdir: PathBuf,
    /// Whether to apply strict filesystem isolation
    strict_mode: bool,
}

impl FilesystemSecurity {
    /// Create a new filesystem security controller
    pub fn new(chroot_dir: Option<PathBuf>, workdir: PathBuf, strict_mode: bool) -> Self {
        Self {
            chroot_dir,
            workdir,
            strict_mode,
        }
    }

    /// Setup filesystem isolation including chroot jail if specified
    pub fn setup_isolation(&self) -> Result<()> {
        if let Some(ref chroot_path) = self.chroot_dir {
            self.setup_chroot_jail(chroot_path)?;
            self.setup_hardened_mounts(chroot_path)?;
        }

        self.setup_workdir()?;
        Ok(())
    }

    /// Setup directory bindings for the sandbox
    pub fn setup_directory_bindings(
        &self,
        bindings: &[crate::config::types::DirectoryBinding],
    ) -> Result<()> {
        for binding in bindings {
            self.setup_single_binding(binding)?;
        }
        Ok(())
    }

    /// Setup a single directory binding
    #[cfg(unix)]
    fn setup_single_binding(&self, binding: &crate::config::types::DirectoryBinding) -> Result<()> {
        use crate::config::types::DirectoryPermissions;

        // Skip if source doesn't exist and maybe flag is set
        if binding.maybe && !binding.source.exists() {
            log::debug!(
                "Skipping non-existent directory binding: {}",
                binding.source.display()
            );
            return Ok(());
        }

        // Determine the actual target path within chroot or working directory
        let target_path = if let Some(ref chroot_path) = self.chroot_dir {
            chroot_path.join(binding.target.strip_prefix("/").unwrap_or(&binding.target))
        } else {
            // If no chroot, use working directory as base for relative paths
            if binding.target.is_absolute() {
                // For absolute paths, create under working directory to avoid permission issues
                self.workdir
                    .join(binding.target.strip_prefix("/").unwrap_or(&binding.target))
            } else {
                self.workdir.join(&binding.target)
            }
        };

        // Create target directory if it doesn't exist
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

        // Handle temporary directory creation
        if binding.is_tmp {
            log::info!("Created temporary directory at {}", target_path.display());
            return Ok(()); // No mounting needed for tmp directories
        }

        // Prepare mount flags based on permissions
        let mut mount_flags = libc::MS_BIND;

        match binding.permissions {
            DirectoryPermissions::ReadOnly => {
                mount_flags |= libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV;
            }
            DirectoryPermissions::ReadWrite => {
                mount_flags |= libc::MS_NOSUID | libc::MS_NODEV;
            }
            DirectoryPermissions::NoExec => {
                mount_flags |= libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
            }
        }

        // Perform bind mount
        let source_cstr = std::ffi::CString::new(binding.source.to_string_lossy().as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid source path: {}", e)))?;
        let target_cstr = std::ffi::CString::new(target_path.to_string_lossy().as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid target path: {}", e)))?;

        let result = unsafe {
            libc::mount(
                source_cstr.as_ptr(),
                target_cstr.as_ptr(),
                std::ptr::null(),
                mount_flags,
                std::ptr::null(),
            )
        };

        if result != 0 {
            let errno = unsafe { *libc::__errno_location() };
            if self.strict_mode {
                return Err(IsolateError::Config(format!(
                    "Failed to bind mount {} to {}: errno {}",
                    binding.source.display(),
                    target_path.display(),
                    errno
                )));
            } else {
                log::warn!(
                    "Failed to bind mount {} to {}: errno {} (falling back to file copy)",
                    binding.source.display(),
                    target_path.display(),
                    errno
                );

                // Fallback: copy files for non-root users
                self.copy_directory_contents(&binding.source, &target_path)?;
                log::info!(
                    "Copied directory contents from {} to {} (fallback mode)",
                    binding.source.display(),
                    target_path.display()
                );
            }
        } else {
            log::info!(
                "Bound directory {} to {} with permissions {:?}",
                binding.source.display(),
                target_path.display(),
                binding.permissions
            );
        }

        Ok(())
    }

    #[cfg(not(unix))]
    fn setup_single_binding(&self, _binding: &crate::config::types::DirectoryBinding) -> Result<()> {
        Err(IsolateError::Config(
            "Directory binding is only supported on Unix systems".to_string(),
        ))
    }

    /// Copy directory contents as fallback when bind mounting fails
    fn copy_directory_contents(&self, source: &Path, target: &Path) -> Result<()> {
        use std::fs;

        if !source.exists() {
            return Err(IsolateError::Config(format!(
                "Source directory does not exist: {}",
                source.display()
            )));
        }

        // Ensure target directory exists
        if !target.exists() {
            fs::create_dir_all(target).map_err(|e| {
                IsolateError::Config(format!("Failed to create target directory: {}", e))
            })?;
        }

        // Copy all files and subdirectories
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let source_path = entry.path();
            let filename = entry.file_name();
            let target_path = target.join(&filename);

            if source_path.is_dir() {
                // Recursively copy subdirectories
                self.copy_directory_contents(&source_path, &target_path)?;
            } else if source_path.is_file() {
                // Copy files
                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(&source_path, &target_path)?;
            }
        }

        Ok(())
    }

    /// Setup chroot jail for filesystem isolation
    #[cfg(unix)]
    fn setup_chroot_jail(&self, chroot_path: &Path) -> Result<()> {
        // Ensure chroot directory exists
        if !chroot_path.exists() {
            fs::create_dir_all(chroot_path).map_err(|e| {
                IsolateError::Config(format!("Failed to create chroot directory: {}", e))
            })?;
        }

        // Create essential directories within chroot
        self.create_chroot_structure(chroot_path)?;

        // Apply mount security flags to prevent dangerous operations
        self.apply_mount_security_flags(chroot_path)?;

        Ok(())
    }

    #[cfg(not(unix))]
    fn setup_chroot_jail(&self, _chroot_path: &Path) -> Result<()> {
        Err(IsolateError::Config(
            "Chroot isolation is only supported on Unix systems".to_string(),
        ))
    }

    /// Create essential directory structure within chroot
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

            // Set secure permissions (755 for directories)
            let metadata = fs::metadata(&dir_path)?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&dir_path, perms)?;
        }

        // Create essential device files
        self.create_essential_devices(chroot_path)?;

        Ok(())
    }

    /// Create essential device files in chroot
    #[cfg(unix)]
    fn create_essential_devices(&self, chroot_path: &Path) -> Result<()> {
        let dev_dir = chroot_path.join("dev");

        // Create /dev/null
        let null_path = dev_dir.join("null");
        if !null_path.exists() {
            // Use mknod to create device file
            let result = unsafe {
                let path_cstr = std::ffi::CString::new(null_path.to_string_lossy().as_bytes())
                    .map_err(|e| IsolateError::Config(format!("Invalid path: {}", e)))?;

                libc::mknod(
                    path_cstr.as_ptr(),
                    libc::S_IFCHR | 0o666,
                    libc::makedev(1, 3), // /dev/null major=1, minor=3
                )
            };

            if result != 0 {
                // If mknod fails, create a regular file as fallback
                fs::File::create(&null_path).map_err(|e| {
                    IsolateError::Config(format!("Failed to create /dev/null: {}", e))
                })?;
            }
        }

        // Create /dev/zero
        let zero_path = dev_dir.join("zero");
        if !zero_path.exists() {
            let result = unsafe {
                let path_cstr = std::ffi::CString::new(zero_path.to_string_lossy().as_bytes())
                    .map_err(|e| IsolateError::Config(format!("Invalid path: {}", e)))?;

                libc::mknod(
                    path_cstr.as_ptr(),
                    libc::S_IFCHR | 0o666,
                    libc::makedev(1, 5), // /dev/zero major=1, minor=5
                )
            };

            if result != 0 {
                // If mknod fails, create a regular file as fallback
                fs::File::create(&zero_path).map_err(|e| {
                    IsolateError::Config(format!("Failed to create /dev/zero: {}", e))
                })?;
            }
        }

        Ok(())
    }

    /// Apply mount security flags to prevent dangerous operations
    #[cfg(unix)]
    fn apply_mount_security_flags(&self, chroot_path: &Path) -> Result<()> {
        // Apply noexec, nosuid, nodev flags to the chroot mount
        let mount_flags = libc::MS_NOEXEC | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_BIND;

        let source_cstr = std::ffi::CString::new(chroot_path.to_string_lossy().as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid chroot path: {}", e)))?;

        let target_cstr = source_cstr.clone();

        let result = unsafe {
            libc::mount(
                source_cstr.as_ptr(),
                target_cstr.as_ptr(),
                std::ptr::null(),
                mount_flags,
                std::ptr::null(),
            )
        };

        if result != 0 && self.strict_mode {
            let errno = unsafe { *libc::__errno_location() };
            return Err(IsolateError::Config(format!(
                "Failed to apply mount security flags: errno {}",
                errno
            )));
        }

        Ok(())
    }

    /// Setup hardened /sys and /dev mounts within chroot
    #[cfg(unix)]
    fn setup_hardened_mounts(&self, chroot_path: &Path) -> Result<()> {
        // Mount hardened /sys with read-only flags
        let sys_path = chroot_path.join("sys");
        if sys_path.exists() {
            self.mount_hardened_sysfs(&sys_path)?;
        }

        // Mount hardened /dev with tmpfs and minimal devices
        let dev_path = chroot_path.join("dev");
        if dev_path.exists() {
            self.mount_hardened_devfs(&dev_path)?;
        }

        // Mount hardened /proc if it exists
        let proc_path = chroot_path.join("proc");
        if proc_path.exists() {
            self.mount_hardened_procfs(&proc_path)?;
        }

        Ok(())
    }

    #[cfg(not(unix))]
    fn setup_hardened_mounts(&self, _chroot_path: &Path) -> Result<()> {
        // No-op on non-Unix systems
        Ok(())
    }

    /// Mount sysfs with hardened security flags
    #[cfg(unix)]
    fn mount_hardened_sysfs(&self, sys_path: &Path) -> Result<()> {
        let mount_flags = libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV;

        let source_cstr = std::ffi::CString::new("sysfs")
            .map_err(|e| IsolateError::Config(format!("Invalid source string: {}", e)))?;
        let target_cstr = std::ffi::CString::new(sys_path.to_string_lossy().as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid sys path: {}", e)))?;
        let fstype_cstr = std::ffi::CString::new("sysfs")
            .map_err(|e| IsolateError::Config(format!("Invalid fstype string: {}", e)))?;

        let result = unsafe {
            libc::mount(
                source_cstr.as_ptr(),
                target_cstr.as_ptr(),
                fstype_cstr.as_ptr(),
                mount_flags,
                std::ptr::null(),
            )
        };

        if result != 0 {
            let errno = unsafe { *libc::__errno_location() };
            if self.strict_mode {
                return Err(IsolateError::Config(format!(
                    "Failed to mount hardened sysfs: errno {}",
                    errno
                )));
            } else {
                log::warn!("Failed to mount hardened sysfs: errno {}", errno);
            }
        } else {
            log::info!("Mounted hardened sysfs at {}", sys_path.display());
        }

        Ok(())
    }

    /// Mount tmpfs on /dev with minimal device nodes
    #[cfg(unix)]
    fn mount_hardened_devfs(&self, dev_path: &Path) -> Result<()> {
        // First mount tmpfs on dev directory
        let mount_flags = libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NOATIME;

        let source_cstr = std::ffi::CString::new("tmpfs")
            .map_err(|e| IsolateError::Config(format!("Invalid source string: {}", e)))?;
        let target_cstr = std::ffi::CString::new(dev_path.to_string_lossy().as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid dev path: {}", e)))?;
        let fstype_cstr = std::ffi::CString::new("tmpfs")
            .map_err(|e| IsolateError::Config(format!("Invalid fstype string: {}", e)))?;
        let options_cstr = std::ffi::CString::new("size=64k,mode=755")
            .map_err(|e| IsolateError::Config(format!("Invalid options string: {}", e)))?;

        let result = unsafe {
            libc::mount(
                source_cstr.as_ptr(),
                target_cstr.as_ptr(),
                fstype_cstr.as_ptr(),
                mount_flags,
                options_cstr.as_ptr() as *const libc::c_void,
            )
        };

        if result != 0 {
            let errno = unsafe { *libc::__errno_location() };
            if self.strict_mode {
                return Err(IsolateError::Config(format!(
                    "Failed to mount tmpfs on /dev: errno {}",
                    errno
                )));
            } else {
                log::warn!("Failed to mount tmpfs on /dev: errno {}", errno);
                return Ok(()); // Continue with existing devices
            }
        } else {
            log::info!("Mounted hardened tmpfs at {}", dev_path.display());
        }

        // Create minimal essential device nodes on the new tmpfs
        self.create_minimal_devices(dev_path)?;

        Ok(())
    }

    /// Mount procfs with hardened security flags
    #[cfg(unix)]
    fn mount_hardened_procfs(&self, proc_path: &Path) -> Result<()> {
        let mount_flags = libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV;

        let source_cstr = std::ffi::CString::new("proc")
            .map_err(|e| IsolateError::Config(format!("Invalid source string: {}", e)))?;
        let target_cstr = std::ffi::CString::new(proc_path.to_string_lossy().as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid proc path: {}", e)))?;
        let fstype_cstr = std::ffi::CString::new("proc")
            .map_err(|e| IsolateError::Config(format!("Invalid fstype string: {}", e)))?;

        let result = unsafe {
            libc::mount(
                source_cstr.as_ptr(),
                target_cstr.as_ptr(),
                fstype_cstr.as_ptr(),
                mount_flags,
                std::ptr::null(),
            )
        };

        if result != 0 {
            let errno = unsafe { *libc::__errno_location() };
            if self.strict_mode {
                return Err(IsolateError::Config(format!(
                    "Failed to mount hardened procfs: errno {}",
                    errno
                )));
            } else {
                log::warn!("Failed to mount hardened procfs: errno {}", errno);
            }
        } else {
            log::info!("Mounted hardened procfs at {}", proc_path.display());
        }

        Ok(())
    }

    /// Create minimal essential device nodes
    #[cfg(unix)]
    fn create_minimal_devices(&self, dev_path: &Path) -> Result<()> {
        let devices = [
            ("null", libc::S_IFCHR, 1, 3),    // /dev/null
            ("zero", libc::S_IFCHR, 1, 5),    // /dev/zero
            ("random", libc::S_IFCHR, 1, 8),  // /dev/random
            ("urandom", libc::S_IFCHR, 1, 9), // /dev/urandom
        ];

        for (name, mode, major, minor) in &devices {
            let device_path = dev_path.join(name);
            let path_cstr = std::ffi::CString::new(device_path.to_string_lossy().as_bytes())
                .map_err(|e| IsolateError::Config(format!("Invalid device path: {}", e)))?;

            let result = unsafe {
                libc::mknod(
                    path_cstr.as_ptr(),
                    mode | 0o666,
                    libc::makedev(*major, *minor),
                )
            };

            if result != 0 {
                let errno = unsafe { *libc::__errno_location() };
                log::warn!("Failed to create device {}: errno {}", name, errno);
                // Continue creating other devices even if one fails
            } else {
                log::debug!("Created device node: {}", device_path.display());
            }
        }

        Ok(())
    }

    /// Perform chroot operation (must be called in child process)
    #[cfg(unix)]
    pub fn apply_chroot(&self) -> Result<()> {
        if let Some(ref chroot_path) = self.chroot_dir {
            let path_cstr = std::ffi::CString::new(chroot_path.to_string_lossy().as_bytes())
                .map_err(|e| IsolateError::Config(format!("Invalid chroot path: {}", e)))?;

            let result = unsafe { libc::chroot(path_cstr.as_ptr()) };

            if result != 0 {
                let errno = unsafe { *libc::__errno_location() };
                return Err(IsolateError::Config(format!(
                    "chroot failed: errno {}",
                    errno
                )));
            }

            // Change to root directory within chroot
            std::env::set_current_dir("/").map_err(|e| {
                IsolateError::Config(format!("Failed to change to chroot root: {}", e))
            })?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    pub fn apply_chroot(&self) -> Result<()> {
        if self.chroot_dir.is_some() {
            return Err(IsolateError::Config(
                "Chroot is only supported on Unix systems".to_string(),
            ));
        }
        Ok(())
    }

    /// Setup working directory with proper permissions
    fn setup_workdir(&self) -> Result<()> {
        // Determine the actual working directory path
        let actual_workdir = if self.chroot_dir.is_some() {
            // If using chroot, workdir is relative to chroot root
            PathBuf::from("/").join(self.workdir.strip_prefix("/").unwrap_or(&self.workdir))
        } else {
            self.workdir.clone()
        };

        // Create workdir if it doesn't exist
        if !actual_workdir.exists() {
            fs::create_dir_all(&actual_workdir)
                .map_err(|e| IsolateError::Config(format!("Failed to create workdir: {}", e)))?;
        }

        // Set secure permissions
        #[cfg(unix)]
        {
            let metadata = fs::metadata(&actual_workdir)?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o755); // rwxr-xr-x
            fs::set_permissions(&actual_workdir, perms)?;
        }

        Ok(())
    }

    /// Validate that a path is within the allowed boundaries
    pub fn validate_path(&self, path: &Path) -> Result<()> {
        let canonical_path = path
            .canonicalize()
            .map_err(|e| IsolateError::Config(format!("Failed to canonicalize path: {}", e)))?;

        // If using chroot, all paths should be within chroot
        if let Some(ref chroot_path) = self.chroot_dir {
            let canonical_chroot = chroot_path.canonicalize().map_err(|e| {
                IsolateError::Config(format!("Failed to canonicalize chroot path: {}", e))
            })?;

            if !canonical_path.starts_with(&canonical_chroot) {
                return Err(IsolateError::Config(format!(
                    "Path {} is outside chroot jail {}",
                    canonical_path.display(),
                    canonical_chroot.display()
                )));
            }
        }

        // Additional validation: prevent access to sensitive system directories
        let dangerous_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/root",
            "/boot",
            "/sys",
            "/proc/sys",
        ];

        let path_str = canonical_path.to_string_lossy();
        for dangerous in &dangerous_paths {
            if path_str.starts_with(dangerous) {
                return Err(IsolateError::Config(format!(
                    "Access to dangerous path {} is forbidden",
                    path_str
                )));
            }
        }

        Ok(())
    }

    /// Cleanup filesystem isolation
    pub fn cleanup(&self) -> Result<()> {
        // Unmount chroot if it was mounted
        #[cfg(unix)]
        if let Some(ref chroot_path) = self.chroot_dir {
            let path_cstr = std::ffi::CString::new(chroot_path.to_string_lossy().as_bytes())
                .map_err(|e| IsolateError::Config(format!("Invalid chroot path: {}", e)))?;

            // Try to unmount, but don't fail if it wasn't mounted
            unsafe {
                libc::umount(path_cstr.as_ptr());
            }
        }

        Ok(())
    }

    /// Check if filesystem isolation is properly configured
    pub fn is_isolated(&self) -> bool {
        self.chroot_dir.is_some()
    }

    /// Get the effective working directory (accounting for chroot)
    pub fn get_effective_workdir(&self) -> PathBuf {
        if self.chroot_dir.is_some() {
            // Within chroot, paths are relative to chroot root
            PathBuf::from("/").join(self.workdir.strip_prefix("/").unwrap_or(&self.workdir))
        } else {
            self.workdir.clone()
        }
    }
}
