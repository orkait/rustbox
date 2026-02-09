use crate::config::types::{IsolateError, Result};
use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const OPEN_DIR_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;

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
            // SAFETY: fd is owned by this guard and closed exactly once on drop.
            unsafe {
                libc::close(self.0);
            }
            self.0 = -1;
        }
    }
}

struct DirGuard(*mut libc::DIR);

impl DirGuard {
    fn open_from_fd(fd: RawFd) -> io::Result<Self> {
        // SAFETY: fd is a valid directory descriptor from dup().
        let dir = unsafe { libc::fdopendir(fd) };
        if dir.is_null() {
            let err = io::Error::last_os_error();
            // SAFETY: fdopendir failed and did not take ownership.
            unsafe {
                libc::close(fd);
            }
            Err(err)
        } else {
            Ok(Self(dir))
        }
    }

    fn as_ptr(&self) -> *mut libc::DIR {
        self.0
    }
}

impl Drop for DirGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: DIR* is owned by this guard and closed exactly once.
            unsafe {
                libc::closedir(self.0);
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

fn map_io(context: &str, err: io::Error) -> IsolateError {
    IsolateError::Filesystem(format!("{}: {}", context, err))
}

fn os_to_cstring(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains interior NUL byte",
        )
    })
}

fn open_dir(path: &Path) -> io::Result<FdGuard> {
    let path_c = os_to_cstring(path.as_os_str())?;
    // SAFETY: C string is valid for libc open call.
    let fd = unsafe { libc::open(path_c.as_ptr(), OPEN_DIR_FLAGS) };
    if fd >= 0 {
        Ok(FdGuard::new(fd))
    } else {
        Err(io::Error::last_os_error())
    }
}

fn openat_dir(parent_fd: RawFd, name: &CStr) -> io::Result<FdGuard> {
    // SAFETY: parent_fd is an open directory fd and name is a valid C string.
    let fd = unsafe { libc::openat(parent_fd, name.as_ptr(), OPEN_DIR_FLAGS) };
    if fd >= 0 {
        Ok(FdGuard::new(fd))
    } else {
        Err(io::Error::last_os_error())
    }
}

fn is_missing(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::NotFound
}

fn is_notdir_or_loop(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::ENOTDIR) | Some(libc::ELOOP))
}

fn unlinkat_ignoring_missing(parent_fd: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: parent_fd and C string are valid for unlinkat.
    let rc = unsafe { libc::unlinkat(parent_fd, name.as_ptr(), flags) };
    if rc == 0 {
        return Ok(());
    }

    let err = io::Error::last_os_error();
    if is_missing(&err) {
        Ok(())
    } else {
        Err(err)
    }
}

fn fstatat_nofollow(parent_fd: RawFd, name: &CStr) -> io::Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: buffer pointer and arguments are valid for fstatat.
    let rc = unsafe {
        libc::fstatat(
            parent_fd,
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        // SAFETY: fstatat succeeded and initialized `st`.
        Ok(unsafe { st.assume_init() })
    } else {
        Err(io::Error::last_os_error())
    }
}

fn list_dir_entries(dir_fd: RawFd) -> io::Result<Vec<CString>> {
    // SAFETY: duplicating an fd is safe and returns a new owned descriptor.
    let iter_fd = unsafe { libc::dup(dir_fd) };
    if iter_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let dir = DirGuard::open_from_fd(iter_fd)?;
    let mut names = Vec::new();

    loop {
        #[cfg(target_os = "linux")]
        // SAFETY: errno location is thread-local and writable.
        unsafe {
            *libc::__errno_location() = 0;
        }

        // SAFETY: dir pointer is valid while DirGuard is alive.
        let entry = unsafe { libc::readdir(dir.as_ptr()) };
        if entry.is_null() {
            let err = io::Error::last_os_error();
            if err.raw_os_error().unwrap_or(0) != 0 {
                return Err(err);
            }
            break;
        }

        // SAFETY: d_name is NUL-terminated by readdir.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }

        names.push(CString::new(bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "directory entry contains interior NUL byte",
            )
        })?);
    }

    Ok(names)
}

fn remove_dir_contents(dir_fd: RawFd) -> io::Result<()> {
    let entries = list_dir_entries(dir_fd)?;

    for name in entries {
        let st = match fstatat_nofollow(dir_fd, &name) {
            Ok(stat) => stat,
            Err(err) if is_missing(&err) => continue,
            Err(err) => return Err(err),
        };

        let file_type = st.st_mode & libc::S_IFMT;
        if file_type == libc::S_IFDIR {
            match openat_dir(dir_fd, &name) {
                Ok(child_fd) => {
                    remove_dir_contents(child_fd.as_raw_fd())?;
                    unlinkat_ignoring_missing(dir_fd, &name, libc::AT_REMOVEDIR)?;
                }
                Err(err) if is_missing(&err) => continue,
                Err(err) if is_notdir_or_loop(&err) => {
                    // Type changed between stat/open; remove as non-directory.
                    unlinkat_ignoring_missing(dir_fd, &name, 0)?;
                }
                Err(err) => return Err(err),
            }
        } else {
            unlinkat_ignoring_missing(dir_fd, &name, 0)?;
        }
    }

    Ok(())
}

fn remove_entry_at(parent_fd: RawFd, name: &CStr) -> io::Result<()> {
    match openat_dir(parent_fd, name) {
        Ok(dir_fd) => {
            remove_dir_contents(dir_fd.as_raw_fd())?;
            unlinkat_ignoring_missing(parent_fd, name, libc::AT_REMOVEDIR)
        }
        Err(err) if is_missing(&err) => Ok(()),
        Err(err) if is_notdir_or_loop(&err) => unlinkat_ignoring_missing(parent_fd, name, 0),
        Err(err) => Err(err),
    }
}

/// Remove a path without following symlinks.
///
/// Directory trees are removed via openat/fstatat/unlinkat traversal.
/// Non-directory entries (including symlinks) are unlinked directly.
pub fn remove_tree_secure(path: &Path) -> Result<()> {
    let name_os = path.file_name().ok_or_else(|| {
        IsolateError::Filesystem(format!(
            "cannot remove path without terminal component: {}",
            path.display()
        ))
    })?;
    let name_c = os_to_cstring(name_os)
        .map_err(|e| map_io(&format!("invalid path component: {}", path.display()), e))?;

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let parent_fd = open_dir(parent)
        .map_err(|e| map_io(&format!("open parent directory {}", parent.display()), e))?;

    remove_entry_at(parent_fd.as_raw_fd(), &name_c)
        .map_err(|e| map_io(&format!("remove tree {}", path.display()), e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    #[test]
    fn remove_tree_secure_is_idempotent_for_missing_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("missing");
        remove_tree_secure(&missing).unwrap();
    }

    #[test]
    fn remove_tree_secure_does_not_follow_symlink_target() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested").join("file.txt"), b"data").unwrap();

        let outside = tmp.path().join("outside.txt");
        fs::write(&outside, b"outside").unwrap();
        symlink(&outside, root.join("nested").join("outside-link")).unwrap();

        remove_tree_secure(&root).unwrap();

        assert!(!root.exists());
        assert!(outside.exists());
        assert_eq!(fs::read_to_string(&outside).unwrap(), "outside");
    }
}
