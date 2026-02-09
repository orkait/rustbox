/// File Descriptor Closure Hardening
/// Implements P1-FD-001: FD Closure Hardening (close_range + fallback)
///
/// Per plan.md Section 12: Output, FD, and Environment Hygiene
/// - Prefer close_range
/// - Fallback to iterating /proc/self/fd
/// - No inherited unexpected FDs in strict mode
use crate::config::types::{IsolateError, Result};
use std::fs;

#[cfg(unix)]
use nix::unistd::close;

/// Close all file descriptors except stdin, stdout, stderr
/// Per plan.md: Use close_range when available, fallback to /proc/self/fd iteration
pub fn close_inherited_fds(strict_mode: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // Try close_range first (Linux 5.9+)
        if try_close_range() {
            log::info!("Closed inherited FDs using close_range");
            return Ok(());
        }
    }

    // Fallback to /proc/self/fd iteration
    close_fds_via_proc(strict_mode)
}

/// Try to use close_range syscall
#[cfg(target_os = "linux")]
fn try_close_range() -> bool {
    use std::os::raw::c_int;

    // close_range syscall number on x86_64
    const SYS_CLOSE_RANGE: i64 = 436;
    const CLOSE_RANGE_UNSHARE: c_int = 1 << 1;

    // Close all FDs from 3 onwards (keep 0, 1, 2)
    let result = unsafe {
        libc::syscall(
            SYS_CLOSE_RANGE,
            3 as c_int,
            !0 as c_int, // Max FD
            CLOSE_RANGE_UNSHARE,
        )
    };

    result == 0
}

/// Close FDs by iterating /proc/self/fd
fn close_fds_via_proc(strict_mode: bool) -> Result<()> {
    let fd_dir = "/proc/self/fd";

    let entries = fs::read_dir(fd_dir).map_err(|e| {
        if strict_mode {
            return IsolateError::Filesystem(format!("Failed to read {}: {}", fd_dir, e));
        } else {
            log::warn!("Failed to read {} (permissive mode): {}", fd_dir, e);
            return IsolateError::Filesystem(format!("Failed to read {}: {}", fd_dir, e));
        }
    })?;

    let mut closed_count = 0;
    let mut failed_closes = Vec::new();

    for entry in entries.flatten() {
        if let Ok(file_name) = entry.file_name().into_string() {
            if let Ok(fd) = file_name.parse::<i32>() {
                // Keep stdin (0), stdout (1), stderr (2)
                // Also keep the FD we're using to read /proc/self/fd
                if fd > 2 {
                    #[cfg(unix)]
                    {
                        if let Err(e) = close(fd) {
                            // Ignore EBADF (already closed)
                            if e != nix::errno::Errno::EBADF {
                                failed_closes.push((fd, e));
                            }
                        } else {
                            closed_count += 1;
                        }
                    }
                }
            }
        }
    }

    if !failed_closes.is_empty() && strict_mode {
        let error_msg = failed_closes
            .iter()
            .map(|(fd, err)| format!("fd {}: {}", fd, err))
            .collect::<Vec<_>>()
            .join(", ");

        return Err(IsolateError::Filesystem(format!(
            "Failed to close {} FD(s): {}",
            failed_closes.len(),
            error_msg
        )));
    }

    log::info!("Closed {} inherited FDs via /proc/self/fd", closed_count);
    Ok(())
}

/// Get list of open file descriptors
pub fn get_open_fds() -> Result<Vec<i32>> {
    let fd_dir = "/proc/self/fd";

    let entries = fs::read_dir(fd_dir)
        .map_err(|e| IsolateError::Filesystem(format!("Failed to read {}: {}", fd_dir, e)))?;

    let mut fds = Vec::new();

    for entry in entries.flatten() {
        if let Ok(file_name) = entry.file_name().into_string() {
            if let Ok(fd) = file_name.parse::<i32>() {
                fds.push(fd);
            }
        }
    }

    fds.sort();
    Ok(fds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_open_fds() {
        let fds = get_open_fds();
        assert!(fds.is_ok());

        let fds = fds.unwrap();
        // Should at least have stdin, stdout, stderr
        assert!(fds.len() >= 3);
        assert!(fds.contains(&0)); // stdin
        assert!(fds.contains(&1)); // stdout
        assert!(fds.contains(&2)); // stderr
    }

    #[test]
    fn test_close_inherited_fds_permissive() {
        // In permissive mode, should not fail
        let result = close_inherited_fds(false);
        assert!(result.is_ok());
    }
}
