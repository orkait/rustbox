//! Runtime detection of Linux `pidfd` support (kernel >= 5.3).

/// Check at runtime whether the current kernel supports `pidfd_open`.
/// Cached after first call via a static atomic.
pub(crate) fn pidfd_available() -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pidfd_availability_check_does_not_panic() {
        let _ = pidfd_available();
    }
}
