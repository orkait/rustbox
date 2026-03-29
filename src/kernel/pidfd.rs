//! Safe wrappers around Linux `pidfd` (kernel >= 5.3).
//!
//! A `pidfd` is a stable file descriptor tied to a specific process instance,
//! not just a PID number. This eliminates TOCTOU races where a PID is reused
//! between check and kill.
//!
//! Falls back gracefully on kernels that don't support pidfd.

use std::io;
use std::os::unix::io::RawFd;

/// Check at runtime whether the current kernel supports `pidfd_open`.
/// Cached after first call via a static atomic.
pub fn pidfd_available() -> bool {
    use std::sync::atomic::{AtomicI8, Ordering};
    static CACHED: AtomicI8 = AtomicI8::new(-1);
    match CACHED.load(Ordering::Relaxed) {
        1 => return true,
        0 => return false,
        _ => {}
    }
    let rc = unsafe { libc::syscall(libc::SYS_pidfd_open, 1i32, 0u32) };
    let available = rc >= 0;
    if available {
        unsafe { libc::close(rc as i32) };
    }
    CACHED.store(if available { 1 } else { 0 }, Ordering::Relaxed);
    available
}

/// Open a pidfd synchronously. Returns the raw fd, caller must close it.
pub fn pidfd_open_raw(pid: i32) -> io::Result<RawFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd as RawFd)
    }
}

/// Send a signal via pidfd (race-free, won't hit a recycled PID).
pub fn pidfd_send_signal(pidfd: RawFd, sig: libc::c_int) -> io::Result<()> {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            sig,
            std::ptr::null::<libc::siginfo_t>(),
            0u32,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Blocking poll on a raw pidfd with timeout. Returns true if the process
/// exited before the timeout, false if the timeout elapsed.
pub fn pidfd_wait_timeout(fd: RawFd, timeout_ms: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    rc > 0 && (pfd.revents & libc::POLLIN) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pidfd_availability_check_does_not_panic() {
        let _ = pidfd_available();
    }

    #[test]
    fn open_self_pid_succeeds_on_supported_kernels() {
        if !pidfd_available() {
            eprintln!("pidfd not available on this kernel, skipping test");
            return;
        }
        let pid = unsafe { libc::getpid() };
        let pfd = pidfd_open_raw(pid).expect("open self pidfd");
        // Self is alive; send SIGCONT (no-op) to verify send_signal works.
        pidfd_send_signal(pfd, libc::SIGCONT).expect("send_signal SIGCONT to self");
        unsafe { libc::close(pfd) };
    }
}
