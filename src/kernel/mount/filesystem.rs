use crate::config::types::{IsolateError, Result};
use crate::utils::fork_safe_log::{
    fs_debug_parts, fs_info_parts, fs_warn, fs_warn_parts, itoa_buf, itoa_i32,
};
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
    const NULL: Self = Self {
        name: "null",
        mode: libc::S_IFCHR,
        major: 1,
        minor: 3,
    };
    const ZERO: Self = Self {
        name: "zero",
        mode: libc::S_IFCHR,
        major: 1,
        minor: 5,
    };
    const RANDOM: Self = Self {
        name: "random",
        mode: libc::S_IFCHR,
        major: 1,
        minor: 8,
    };
    const URANDOM: Self = Self {
        name: "urandom",
        mode: libc::S_IFCHR,
        major: 1,
        minor: 9,
    };

    const ESSENTIAL_DEVICES: &'static [Self] =
        &[Self::NULL, Self::ZERO, Self::RANDOM, Self::URANDOM];
}

fn path_cstr(path: &Path, label: &str) -> Result<std::ffi::CString> {
    std::ffi::CString::new(path.to_string_lossy().as_bytes())
        .map_err(|e| IsolateError::Config(format!("Invalid {} path: {}", label, e)))
}

fn mount_result(rc: i32, label: &str, strict_mode: bool) -> Result<bool> {
    if rc == 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    if strict_mode {
        return Err(IsolateError::Config(format!("{}: {}", label, err)));
    }
    let mut ebuf = [0u8; 20];
    let eno = itoa_i32(err.raw_os_error().unwrap_or(-1), &mut ebuf);
    fs_warn_parts(&[label, ": errno=", eno]);
    Ok(false)
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

    pub fn setup_isolation(&mut self) -> Result<()> {
        #[cfg(unix)]
        if self.strict_mode {
            if self.chroot_dir.is_some() {
                fs_warn(
                    "Strict mode ignores explicit chroot_dir and uses auto tmpfs root for quota safety",
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
        use std::path::Component;

        if self.strict_mode && binding.permissions == DirectoryPermissions::ReadWrite {
            return Err(IsolateError::Config(format!(
                "Read-write directory bindings are disallowed in strict mode: {} -> {}",
                binding.source.display(),
                binding.target.display()
            )));
        }

        if binding
            .source
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(IsolateError::Config(format!(
                "Path traversal detected in source path: {}",
                binding.source.display()
            )));
        }

        if binding
            .target
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(IsolateError::Config(format!(
                "Path traversal detected in target path: {}",
                binding.target.display()
            )));
        }

        if binding.maybe && !binding.source.exists() {
            fs_debug_parts(&[
                "Skipping non-existent directory binding: ",
                binding.source.to_str().unwrap_or("<?>"),
            ]);
            return Ok(());
        }

        let target_path = if let Some(ref chroot_path) = self.chroot_dir {
            chroot_path.join(binding.target.strip_prefix("/").unwrap_or(&binding.target))
        } else if binding.target.is_absolute() {
            self.workdir
                .join(binding.target.strip_prefix("/").unwrap_or(&binding.target))
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
            fs_info_parts(&[
                "Created temporary directory at ",
                target_path.to_str().unwrap_or("<?>"),
            ]);
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
                source_cstr.as_ptr(),
                target_cstr.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };

        if bind_result != 0 {
            let err = std::io::Error::last_os_error();
            if self.strict_mode {
                return Err(IsolateError::Config(format!(
                    "Failed to bind mount {} to {}: {}",
                    binding.source.display(),
                    target_path.display(),
                    err
                )));
            } else {
                let mut ebuf = [0u8; 20];
                let eno = itoa_i32(err.raw_os_error().unwrap_or(-1), &mut ebuf);
                fs_warn_parts(&[
                    "Failed to bind mount ",
                    binding.source.to_str().unwrap_or("<?>"),
                    " to ",
                    target_path.to_str().unwrap_or("<?>"),
                    ": errno=",
                    eno,
                    " (falling back to file copy)",
                ]);
                Self::copy_directory_contents(&binding.source, &target_path)?;
                fs_info_parts(&[
                    "Copied directory contents from ",
                    binding.source.to_str().unwrap_or("<?>"),
                    " to ",
                    target_path.to_str().unwrap_or("<?>"),
                    " (fallback mode)",
                ]);
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
                    std::ptr::null(),
                    target_cstr.as_ptr(),
                    std::ptr::null(),
                    remount_flags,
                    std::ptr::null(),
                )
            };

            if remount_result != 0 {
                let err = std::io::Error::last_os_error();
                if self.strict_mode {
                    return Err(IsolateError::Config(format!(
                        "Failed to remount read-only {} to {}: {}",
                        binding.source.display(),
                        target_path.display(),
                        err
                    )));
                }
                let mut ebuf = [0u8; 20];
                let eno = itoa_i32(err.raw_os_error().unwrap_or(-1), &mut ebuf);
                fs_warn_parts(&[
                    "Failed to remount read-only ",
                    binding.source.to_str().unwrap_or("<?>"),
                    " to ",
                    target_path.to_str().unwrap_or("<?>"),
                    ": errno=",
                    eno,
                ]);
            }
        }

        let perm_str = match binding.permissions {
            crate::config::types::DirectoryPermissions::ReadOnly => "ReadOnly",
            crate::config::types::DirectoryPermissions::ReadWrite => "ReadWrite",
            crate::config::types::DirectoryPermissions::NoExec => "NoExec",
        };
        fs_info_parts(&[
            "Bound directory ",
            binding.source.to_str().unwrap_or("<?>"),
            " to ",
            target_path.to_str().unwrap_or("<?>"),
            " with permissions ",
            perm_str,
        ]);

        Ok(())
    }

    fn copy_directory_contents(source: &Path, target: &Path) -> Result<()> {
        if !source.exists() {
            return Err(IsolateError::Config(format!(
                "Source directory does not exist: {}",
                source.display()
            )));
        }

        if !target.exists() {
            fs::create_dir_all(target).map_err(|e| {
                IsolateError::Config(format!("Failed to create target directory: {}", e))
            })?;
        }

        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let source_path = entry.path();
            let target_path = target.join(entry.file_name());

            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                Self::copy_directory_contents(&source_path, &target_path)?;
            } else if file_type.is_file() {
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
                source_cstr.as_ptr(),
                target_cstr.as_ptr(),
                fstype_cstr.as_ptr(),
                flags,
                opts_cstr.as_ptr() as *const libc::c_void,
            )
        };

        if result != 0 {
            let err = std::io::Error::last_os_error();
            return Err(IsolateError::Config(format!(
                "Failed to mount tmpfs at {}: {}",
                tmpfs_root.display(),
                err
            )));
        }

        let mut size_buf = [0u8; 20];
        let size_str = itoa_buf(self.tmpfs_size_bytes, &mut size_buf);
        let mut inode_buf = [0u8; 20];
        let inode_str = itoa_buf(self.tmpfs_inode_limit, &mut inode_buf);
        fs_info_parts(&[
            "Auto-created strict tmpfs root at ",
            tmpfs_root.to_str().unwrap_or("<?>"),
            " (size=",
            size_str,
            ", nr_inodes=",
            inode_str,
            ")",
        ]);

        let ws_in_root = tmpfs_root.join(self.workdir.strip_prefix("/").unwrap_or(&self.workdir));
        fs::create_dir_all(&ws_in_root).map_err(|e| {
            IsolateError::Config(format!("Failed to create workspace in tmpfs root: {}", e))
        })?;

        if self.workdir.exists() {
            Self::copy_directory_contents(&self.workdir, &ws_in_root)?;
            fs_info_parts(&[
                "Copied workspace ",
                self.workdir.to_str().unwrap_or("<?>"),
                " into strict tmpfs root",
            ]);
        }

        Ok(tmpfs_root)
    }

    #[cfg(unix)]
    fn mount_standard_bind_set(&self, chroot_path: &Path) -> Result<()> {
        let ro_dirs = ["/bin", "/lib", "/lib64", "/usr"];

        for dir in &ro_dirs {
            let src = Path::new(dir);
            if !src.exists() {
                fs_debug_parts(&["Skipping non-existent standard dir: ", dir]);
                continue;
            }

            let target = chroot_path.join(dir.strip_prefix('/').unwrap_or(dir));
            if !target.exists() {
                fs::create_dir_all(&target).map_err(|e| {
                    IsolateError::Config(format!(
                        "Failed to create bind target {}: {}",
                        target.display(),
                        e
                    ))
                })?;
            }

            self.bind_mount_readonly(src, &target)?;
        }

        Ok(())
    }

    #[cfg(unix)]
    fn bind_mount_readonly(&self, source: &Path, target: &Path) -> Result<()> {
        let src_cstr = std::ffi::CString::new(source.to_string_lossy().as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid source path: {}", e)))?;
        let tgt_cstr = std::ffi::CString::new(target.to_string_lossy().as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid target path: {}", e)))?;

        // SAFETY: mount(2) bind mount with valid CString pointers.
        let result = unsafe {
            libc::mount(
                src_cstr.as_ptr(),
                tgt_cstr.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if result != 0 {
            let err = std::io::Error::last_os_error();
            if self.strict_mode {
                return Err(IsolateError::Config(format!(
                    "Failed to bind mount {} -> {}: {}",
                    source.display(),
                    target.display(),
                    err
                )));
            }
            let mut ebuf = [0u8; 20];
            let eno = itoa_i32(err.raw_os_error().unwrap_or(-1), &mut ebuf);
            fs_warn_parts(&[
                "Failed to bind mount ",
                source.to_str().unwrap_or("<?>"),
                " -> ",
                target.to_str().unwrap_or("<?>"),
                ": errno=",
                eno,
            ]);
            return Ok(());
        }

        // SAFETY: mount(2) remount to make read-only.
        let ro_flags =
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV;
        let result = unsafe {
            libc::mount(
                std::ptr::null(),
                tgt_cstr.as_ptr(),
                std::ptr::null(),
                ro_flags,
                std::ptr::null(),
            )
        };
        if result != 0 {
            let err = std::io::Error::last_os_error();
            if self.strict_mode {
                return Err(IsolateError::Config(format!(
                    "Failed to remount {} read-only: {}",
                    target.display(),
                    err
                )));
            }
            let mut ebuf = [0u8; 20];
            let eno = itoa_i32(err.raw_os_error().unwrap_or(-1), &mut ebuf);
            fs_warn_parts(&[
                "Failed to remount ",
                target.to_str().unwrap_or("<?>"),
                " read-only: errno=",
                eno,
            ]);
        } else {
            fs_info_parts(&[
                "Bind-mounted ",
                source.to_str().unwrap_or("<?>"),
                " -> ",
                target.to_str().unwrap_or("<?>"),
                " (read-only)",
            ]);
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

        self.create_essential_devices(&chroot_path.join("dev"))?;
        Ok(())
    }

    #[cfg(unix)]
    fn create_essential_devices(&self, dev_dir: &Path) -> Result<()> {
        for device in DeviceNode::ESSENTIAL_DEVICES {
            self.create_device_node(dev_dir, device)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    fn create_device_node(&self, dev_dir: &Path, device: &DeviceNode) -> Result<()> {
        let device_path = dev_dir.join(device.name);
        if device_path.exists() {
            return Ok(());
        }
        let cstr = path_cstr(&device_path, "device")?;
        // SAFETY: mknod(2) with valid CString path, character device mode, valid major:minor.
        let rc = unsafe {
            libc::mknod(
                cstr.as_ptr(),
                device.mode | 0o666,
                libc::makedev(device.major, device.minor),
            )
        };
        mount_result(
            rc,
            &format!("Failed to create device node /dev/{}", device.name),
            self.strict_mode,
        )?;
        Ok(())
    }

    #[cfg(unix)]
    fn apply_mount_security_flags(&self, chroot_path: &Path) -> Result<()> {
        let cstr = path_cstr(chroot_path, "chroot")?;
        // SAFETY: mount(2) bind mount on chroot root.
        let rc = unsafe {
            libc::mount(
                cstr.as_ptr(),
                cstr.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if !mount_result(rc, "Failed to bind mount chroot root", self.strict_mode)? {
            return Ok(());
        }
        let flags =
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOEXEC | libc::MS_NOSUID | libc::MS_NODEV;
        // SAFETY: mount(2) remount with security flags.
        let rc = unsafe {
            libc::mount(
                std::ptr::null(),
                cstr.as_ptr(),
                std::ptr::null(),
                flags,
                std::ptr::null(),
            )
        };
        mount_result(rc, "Failed to apply mount security flags", self.strict_mode)?;
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

        let shm_path = chroot_path.join("dev").join("shm");
        if !shm_path.exists() {
            let _ = fs::create_dir_all(&shm_path);
        }
        if shm_path.exists() {
            self.mount_limited_shm(&shm_path)?;
        }

        let tmp_path = chroot_path.join("tmp");
        if tmp_path.exists() {
            self.mount_hardened_tmp(&tmp_path)?;
        }

        Ok(())
    }

    #[cfg(unix)]
    fn mount_limited_shm(&self, shm_path: &Path) -> Result<()> {
        let shm_size = (self.tmpfs_size_bytes / 16).max(1024 * 1024);
        let flags = libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV | libc::MS_NOATIME;
        let src = std::ffi::CString::new("tmpfs").unwrap();
        let tgt = path_cstr(shm_path, "shm")?;
        let fst = std::ffi::CString::new("tmpfs").unwrap();
        let opts = format!("size={},nr_inodes=128,mode=1777", shm_size);
        let opts_c = std::ffi::CString::new(opts.as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid shm options: {}", e)))?;
        // SAFETY: mount(2) tmpfs on /dev/shm with bounded size.
        let rc = unsafe {
            libc::mount(
                src.as_ptr(),
                tgt.as_ptr(),
                fst.as_ptr(),
                flags,
                opts_c.as_ptr() as *const libc::c_void,
            )
        };
        mount_result(rc, "Failed to mount limited /dev/shm", self.strict_mode)?;
        Ok(())
    }

    #[cfg(unix)]
    fn mount_hardened_tmp(&self, tmp_path: &Path) -> Result<()> {
        let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOATIME;
        let src = std::ffi::CString::new("tmpfs").unwrap();
        let tgt = path_cstr(tmp_path, "tmp")?;
        let fst = std::ffi::CString::new("tmpfs").unwrap();
        let opts = format!(
            "size={},nr_inodes={},mode=1777",
            self.tmpfs_size_bytes, self.tmpfs_inode_limit
        );
        let opts_c = std::ffi::CString::new(opts.as_bytes())
            .map_err(|e| IsolateError::Config(format!("Invalid tmp options: {}", e)))?;
        // SAFETY: mount(2) tmpfs on /tmp with bounded size.
        let rc = unsafe {
            libc::mount(
                src.as_ptr(),
                tgt.as_ptr(),
                fst.as_ptr(),
                flags,
                opts_c.as_ptr() as *const libc::c_void,
            )
        };
        mount_result(rc, "Failed to mount hardened /tmp", self.strict_mode)?;
        Ok(())
    }

    #[cfg(unix)]
    fn mount_hardened_sysfs(&self, sys_path: &Path) -> Result<()> {
        let flags = libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV;
        let src = std::ffi::CString::new("sysfs").unwrap();
        let tgt = path_cstr(sys_path, "sys")?;
        let fst = std::ffi::CString::new("sysfs").unwrap();
        // SAFETY: mount(2) sysfs with read-only flags.
        let rc = unsafe {
            libc::mount(
                src.as_ptr(),
                tgt.as_ptr(),
                fst.as_ptr(),
                flags,
                std::ptr::null(),
            )
        };
        mount_result(rc, "Failed to mount hardened sysfs", self.strict_mode)?;
        Ok(())
    }

    #[cfg(unix)]
    fn mount_hardened_devfs(&self, dev_path: &Path) -> Result<()> {
        let flags = libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NOATIME;
        let src = std::ffi::CString::new("tmpfs").unwrap();
        let tgt = path_cstr(dev_path, "dev")?;
        let fst = std::ffi::CString::new("tmpfs").unwrap();
        let opts = std::ffi::CString::new("size=64k,mode=755").unwrap();
        // SAFETY: mount(2) tmpfs with bounded size on /dev.
        let rc = unsafe {
            libc::mount(
                src.as_ptr(),
                tgt.as_ptr(),
                fst.as_ptr(),
                flags,
                opts.as_ptr() as *const libc::c_void,
            )
        };
        if !mount_result(rc, "Failed to mount tmpfs on /dev", self.strict_mode)? {
            return Ok(());
        }
        self.create_essential_devices(dev_path)?;
        Ok(())
    }

    #[cfg(unix)]
    fn mount_hardened_procfs(&self, proc_path: &Path) -> Result<()> {
        let flags = libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV;
        let src = std::ffi::CString::new("proc").unwrap();
        let tgt = path_cstr(proc_path, "proc")?;
        let fst = std::ffi::CString::new("proc").unwrap();

        let opts_cascade = [
            "hidepid=invisible,subset=pid",
            "hidepid=invisible",
            "hidepid=2,subset=pid",
            "hidepid=2",
        ];

        let mut mounted = false;
        for opts in &opts_cascade {
            let opts_c = std::ffi::CString::new(*opts).unwrap();
            // SAFETY: mount(2) procfs with hardened options.
            let rc = unsafe {
                libc::mount(
                    src.as_ptr(),
                    tgt.as_ptr(),
                    fst.as_ptr(),
                    flags,
                    opts_c.as_ptr() as *const libc::c_void,
                )
            };
            if rc == 0 {
                fs_info_parts(&["Mounted procfs with options: ", opts]);
                mounted = true;
                break;
            }
        }

        if !mounted {
            fs_warn_parts(&["All hardened procfs options failed, mounting without hidepid"]);
            // SAFETY: mount(2) procfs fallback without hidepid.
            let rc = unsafe {
                libc::mount(
                    src.as_ptr(),
                    tgt.as_ptr(),
                    fst.as_ptr(),
                    flags,
                    std::ptr::null(),
                )
            };
            mount_result(rc, "Failed to mount fallback procfs", self.strict_mode)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    pub fn apply_chroot(&self) -> Result<()> {
        if let Some(ref chroot_path) = self.chroot_dir {
            let cstr = path_cstr(chroot_path, "chroot")?;
            // SAFETY: chroot(2) with valid CString path.
            if unsafe { libc::chroot(cstr.as_ptr()) } != 0 {
                return Err(IsolateError::Config(format!(
                    "chroot failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            std::env::set_current_dir("/").map_err(|e| {
                IsolateError::Config(format!("Failed to change to chroot root: {}", e))
            })?;
        }
        Ok(())
    }

    fn setup_workdir(&self) -> Result<()> {
        let actual_workdir = if let Some(ref chroot_path) = self.chroot_dir {
            chroot_path.join(self.workdir.strip_prefix("/").unwrap_or(&self.workdir))
        } else {
            self.workdir.clone()
        };

        if !actual_workdir.exists() {
            fs::create_dir_all(&actual_workdir)
                .map_err(|e| IsolateError::Config(format!("Failed to create workdir: {}", e)))?;
        }

        #[cfg(unix)]
        {
            if self.chroot_dir.is_some() {
                let src = path_cstr(&self.workdir, "workdir source")?;
                let dst = path_cstr(&actual_workdir, "workdir target")?;
                let rc = unsafe {
                    libc::mount(
                        src.as_ptr(),
                        dst.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND | libc::MS_REC,
                        std::ptr::null(),
                    )
                };
                if mount_result(
                    rc,
                    "Failed to bind-mount workdir into chroot",
                    self.strict_mode,
                )? {
                    let flags = libc::MS_REMOUNT | libc::MS_BIND | libc::MS_NOSUID | libc::MS_NODEV;
                    let rc2 = unsafe {
                        libc::mount(
                            std::ptr::null(),
                            dst.as_ptr(),
                            std::ptr::null(),
                            flags,
                            std::ptr::null(),
                        )
                    };
                    mount_result(rc2, "Failed to remount workdir", self.strict_mode)?;
                }
            } else {
                let metadata = fs::metadata(&actual_workdir)?;
                let mut perms = metadata.permissions();
                perms.set_mode(0o755);
                fs::set_permissions(&actual_workdir, perms)?;
            }
        }

        Ok(())
    }

    pub fn validate_path(&self, path: &Path) -> Result<()> {
        let canonical_path = path
            .canonicalize()
            .map_err(|e| IsolateError::Config(format!("Failed to canonicalize path: {}", e)))?;

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

    pub fn cleanup(&self) -> Result<()> {
        #[cfg(unix)]
        if let Some(ref chroot_path) = self.chroot_dir {
            let cstr = path_cstr(chroot_path, "chroot")?;
            // SAFETY: umount(2) on chroot path; non-fatal if not mounted.
            unsafe {
                libc::umount(cstr.as_ptr());
            }
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
    #[cfg(unix)]
    use std::os::unix::fs::FileTypeExt;

    #[test]
    fn strict_mode_rejects_read_write_directory_binding() {
        let fs_sec = FilesystemSecurity::new(
            None,
            PathBuf::from("/tmp/rustbox-test-workdir"),
            true,
            None,
            None,
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Read-write directory bindings are disallowed"));
    }

    #[test]
    fn setup_workdir_with_chroot_creates_under_chroot_root() {
        let unique = format!(
            "rustbox-kernel-workdir-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock before epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(format!("rustbox-kernel-root-{}", unique));
        let chroot = root.join("chroot");
        std::fs::create_dir_all(&chroot).expect("failed to create test chroot root");

        let workdir = PathBuf::from(format!("/{}", unique));
        let fs_sec = FilesystemSecurity::new(Some(chroot.clone()), workdir, false, None, None);
        fs_sec
            .setup_workdir()
            .expect("workdir setup inside chroot should succeed");

        assert!(chroot.join(&unique).exists());
        assert!(!PathBuf::from(format!("/{}", unique)).exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn permissive_device_node_creation_never_falls_back_to_regular_files() {
        let dev_root = std::env::temp_dir().join(format!(
            "rustbox-kernel-dev-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock before epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dev_root).expect("failed to create test dev root");

        let fs_sec = FilesystemSecurity::new(None, PathBuf::from("/tmp"), false, None, None);
        fs_sec
            .create_device_node(&dev_root, &DeviceNode::NULL)
            .expect("permissive mode should not error on mknod failure");

        let device_path = dev_root.join(DeviceNode::NULL.name);
        if device_path.exists() {
            let metadata = std::fs::metadata(&device_path).expect("metadata should be readable");
            assert!(metadata.file_type().is_char_device());
        }

        let _ = std::fs::remove_dir_all(&dev_root);
    }
}
