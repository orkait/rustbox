use crate::config::types::{IsolateError, Result};
use std::ffi::CStr;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

struct FdGuard(RawFd);

impl FdGuard {
    fn new(fd: RawFd) -> Self {
        Self(fd)
    }

    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for FdGuard {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

fn open_dir_nofollow(path: &Path) -> Result<FdGuard> {
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        IsolateError::Filesystem(format!(
            "Path contains NUL byte and cannot be opened safely: {}",
            path.display()
        ))
    })?;

    let fd = unsafe {
        libc::open(
            path_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(IsolateError::Filesystem(format!(
            "open directory failed for {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }

    Ok(FdGuard::new(fd))
}

fn fstatat_nofollow(parent_fd: RawFd, name: &CStr) -> Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
    let rc = unsafe {
        libc::fstatat(
            parent_fd,
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return Err(IsolateError::Filesystem(format!(
            "fstatat failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(unsafe { st.assume_init() })
}

fn remove_entry_at(parent_fd: RawFd, name: &CStr, flags: i32) -> Result<()> {
    let rc = unsafe { libc::unlinkat(parent_fd, name.as_ptr(), flags) };
    if rc != 0 {
        return Err(IsolateError::Filesystem(format!(
            "unlinkat failed for entry {:?}: {}",
            name,
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn recurse_remove_dir(parent_fd: RawFd, name: &CStr, root_dev: libc::dev_t) -> Result<()> {
    let child_fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if child_fd < 0 {
        return Err(IsolateError::Filesystem(format!(
            "openat failed for child directory {:?}: {}",
            name,
            std::io::Error::last_os_error()
        )));
    }
    let child_guard = FdGuard::new(child_fd);

    remove_dir_contents_fd(child_guard.as_raw_fd(), root_dev)?;
    remove_entry_at(parent_fd, name, libc::AT_REMOVEDIR)
}

fn remove_dir_contents_fd(dir_fd: RawFd, root_dev: libc::dev_t) -> Result<()> {
    let iter_fd = unsafe { libc::dup(dir_fd) };
    if iter_fd < 0 {
        return Err(IsolateError::Filesystem(format!(
            "dup for directory iteration failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let dir = unsafe { libc::fdopendir(iter_fd) };
    if dir.is_null() {
        unsafe {
            libc::close(iter_fd);
        }
        return Err(IsolateError::Filesystem(format!(
            "fdopendir failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    loop {
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            let errno = unsafe { *libc::__errno_location() };
            unsafe {
                libc::closedir(dir);
            }
            if errno != 0 {
                return Err(IsolateError::Filesystem(format!(
                    "readdir failed: {}",
                    std::io::Error::from_raw_os_error(errno)
                )));
            }
            break;
        }

        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }

        let st = fstatat_nofollow(dir_fd, name)?;
        let file_type = st.st_mode & libc::S_IFMT;

        if file_type == libc::S_IFDIR {
            if st.st_dev != root_dev {
                unsafe {
                    libc::closedir(dir);
                }
                return Err(IsolateError::Filesystem(format!(
                    "Refusing to cross filesystem boundary at directory {:?}",
                    name
                )));
            }
            recurse_remove_dir(dir_fd, name, root_dev)?;
        } else {
            remove_entry_at(dir_fd, name, 0)?;
        }
    }

    Ok(())
}

/// Remove a tree without following symlinks, using openat/fstatat/unlinkat.
/// This is for security-sensitive cleanup paths where remove_dir_all is unsafe.
pub fn remove_tree_secure(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let parent = path.parent().ok_or_else(|| {
        IsolateError::Filesystem(format!("Cannot remove path without parent: {}", path.display()))
    })?;
    let name_os = path.file_name().ok_or_else(|| {
        IsolateError::Filesystem(format!("Cannot remove path without file name: {}", path.display()))
    })?;
    let name_c = std::ffi::CString::new(name_os.as_bytes()).map_err(|_| {
        IsolateError::Filesystem(format!(
            "Path contains NUL byte and cannot be removed safely: {}",
            path.display()
        ))
    })?;

    let parent_fd = open_dir_nofollow(parent)?;
    let st = fstatat_nofollow(parent_fd.as_raw_fd(), &name_c)?;
    let file_type = st.st_mode & libc::S_IFMT;

    if file_type == libc::S_IFDIR {
        recurse_remove_dir(parent_fd.as_raw_fd(), &name_c, st.st_dev)?;
    } else {
        remove_entry_at(parent_fd.as_raw_fd(), &name_c, 0)?;
    }

    Ok(())
}
