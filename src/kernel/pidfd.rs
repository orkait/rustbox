//! Safe async wrapper around Linux `pidfd` (kernel >= 5.3).
//!
//! A `pidfd` is a stable file descriptor tied to a specific process instance,
//! not just a PID number. This eliminates TOCTOU races where a PID is reused
//! between check and kill. When the process exits, the fd becomes readable
//! in epoll, which integrates naturally with Tokio's event loop.
//!
//! Falls back gracefully on kernels that don't support pidfd.

use std::io;
use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};
use tokio::io::unix::AsyncFd;

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
    // Probe with init's PID (always 1) using PIDFD_NONBLOCK.
    // We don't actually use the resulting fd; just check the syscall succeeds.
    let rc = unsafe { libc::syscall(libc::SYS_pidfd_open, 1i32, 0u32) };
    let available = rc >= 0;
    if available {
        // Close the probe fd.
        unsafe { libc::close(rc as i32) };
    }
    CACHED.store(if available { 1 } else { 0 }, Ordering::Relaxed);
    available
}

/// An async handle to a running process via `pidfd`.
///
/// Becomes readable (via Tokio epoll) when the process exits.
/// `send_signal` targets only the specific process instance, not a recycled PID.
pub struct AsyncPidfd {
    inner: AsyncFd<OwnedFd>,
}

impl AsyncPidfd {
    /// Open a pidfd for the given PID.
    ///
    /// # Errors
    /// Returns `ENOSYS` if the kernel doesn't support pidfd_open (< 5.3).
    /// Returns `EPERM` if the caller lacks permission to observe the process.
    /// Returns `ESRCH` if the process has already exited.
    pub fn open(pid: i32) -> io::Result<Self> {
        // SYS_pidfd_open = 434 on x86-64
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, libc::O_NONBLOCK as u32) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let owned = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
        Ok(Self {
            inner: AsyncFd::new(owned)?,
        })
    }

    /// Wait asynchronously until the process exits.
    ///
    /// The pidfd becomes readable (POLLIN) when the process terminates.
    pub async fn wait_exit(&self) -> io::Result<()> {
        // AsyncFd::readable() returns when epoll says the fd is readable.
        let mut guard = self.inner.readable().await?;
        guard.retain_ready(); // don't clear the ready flag
        Ok(())
    }

    /// Send a signal to the specific process this fd refers to.
    ///
    /// Unlike `kill(pid, sig)`, this is race-free: if the process has already
    /// exited and the PID was reused, this call will fail with ESRCH rather
    /// than accidentally signalling the wrong process.
    pub fn send_signal(&self, sig: libc::c_int) -> io::Result<()> {
        use std::os::unix::io::AsRawFd;
        // SYS_pidfd_send_signal = 424 on x86-64
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.inner.as_raw_fd(),
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

    /// Raw fd number, for logging/debugging.
    pub fn as_raw_fd(&self) -> RawFd {
        use std::os::unix::io::AsRawFd;
        self.inner.as_raw_fd()
    }
}

/// Open a pidfd synchronously (for use in the proxy before tokio exists).
/// Returns the raw fd, caller must close it.
pub fn pidfd_open_raw(pid: i32) -> io::Result<RawFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd as RawFd)
    }
}

/// Blocking poll on a raw pidfd with timeout. Returns true if the process
/// exited before the timeout, false if the timeout elapsed.
///
/// Used in synchronous proxy context (no Tokio runtime).
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
        // Just ensure the probe doesn't crash.
        let _ = pidfd_available();
    }

    #[tokio::test]
    async fn open_self_pid_succeeds_on_supported_kernels() {
        if !pidfd_available() {
            eprintln!("pidfd not available on this kernel, skipping test");
            return;
        }
        let pid = unsafe { libc::getpid() };
        let pfd = AsyncPidfd::open(pid).expect("open self pidfd");
        // Self is obviously alive; send SIGCONT (no-op) to verify send_signal works.
        pfd.send_signal(libc::SIGCONT)
            .expect("send_signal SIGCONT to self");
    }
}
