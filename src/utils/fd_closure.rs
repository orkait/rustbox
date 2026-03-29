use crate::config::types::{IsolateError, Result};
use crate::utils::fork_safe_log::{fs_info, fs_info_parts, fs_warn_parts, itoa_buf, itoa_i32};
use std::fs;

#[cfg(unix)]
use nix::unistd::close;

pub fn close_inherited_fds(strict_mode: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if try_close_range() {
            fs_info("Closed inherited FDs using close_range");
            return Ok(());
        }
    }

    close_fds_via_proc(strict_mode)
}

#[cfg(target_os = "linux")]
fn try_close_range() -> bool {
    use std::os::raw::c_int;

    #[cfg(target_arch = "x86_64")]
    const SYS_CLOSE_RANGE: i64 = 436;
    #[cfg(target_arch = "aarch64")]
    const SYS_CLOSE_RANGE: i64 = 436;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("SYS_CLOSE_RANGE not defined for this architecture");
    const CLOSE_RANGE_UNSHARE: c_int = 1 << 1;

    let result = unsafe {
        libc::syscall(
            SYS_CLOSE_RANGE,
            3 as c_int,
            !0 as c_int,
            CLOSE_RANGE_UNSHARE,
        )
    };

    result == 0
}

fn close_fds_via_proc(strict_mode: bool) -> Result<()> {
    let fd_dir = "/proc/self/fd";

    let entries = fs::read_dir(fd_dir).map_err(|e| {
        if strict_mode {
            IsolateError::Filesystem(format!("Failed to read {}: {}", fd_dir, e))
        } else {
            let mut ebuf = [0u8; 20];
            let eno = itoa_i32(e.raw_os_error().unwrap_or(-1), &mut ebuf);
            fs_warn_parts(&["Failed to read ", fd_dir, " (permissive mode): errno ", eno]);
            IsolateError::Filesystem(format!("Failed to read {}: {}", fd_dir, e))
        }
    })?;

    let mut closed_count = 0;
    let mut failed_closes = Vec::new();

    for entry in entries.flatten() {
        if let Ok(file_name) = entry.file_name().into_string() {
            if let Ok(fd) = file_name.parse::<i32>() {
                if fd > 2 {
                    #[cfg(unix)]
                    {
                        if let Err(e) = close(fd) {
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

    let mut cbuf = [0u8; 20];
    let count_str = itoa_buf(closed_count as u64, &mut cbuf);
    fs_info_parts(&["Closed ", count_str, " inherited FDs via /proc/self/fd"]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_close_inherited_fds_permissive() {
        let result = close_inherited_fds(false);
        assert!(result.is_ok());
    }
}
