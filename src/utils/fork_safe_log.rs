//! Fork-safe logging for code that runs after clone()/fork().
//!
//! After `clone()` or `fork()`, the child process inherits mutex state from
//! the parent. If any parent thread held a mutex (e.g. stderr lock, env_logger
//! internal lock, **global allocator lock**) at the time of clone, that mutex
//! is permanently locked in the child — the thread that held it doesn't exist
//! in the child process.
//!
//! **All code running in the payload child (preexec chain, credentials,
//! capabilities, mount setup, namespace setup, fd closure, env hygiene) MUST
//! use this module instead of `log::*`, `eprintln!`, or `println!`.**
//!
//! **Callers MUST NOT use `format!()` to build the message** — `format!()`
//! allocates on the heap via the global allocator, which uses mutexes.
//! Use `fs_warn_parts` / `fs_info_parts` with pre-split string segments,
//! or `itoa_buf` for numeric values.
//!
//! The functions here use raw `write(2, ...)` syscall which is async-signal-safe
//! and does not acquire any Rust or libc mutex.

/// Raw write of a byte slice to stderr. No newline appended.
/// Public so callers can build custom multi-segment output (e.g. loop-based join)
/// without heap allocation.
#[inline]
pub fn raw_write(buf: &[u8]) {
    unsafe {
        libc::write(
            libc::STDERR_FILENO,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
        );
    }
}

/// Format a `u64` into a stack-allocated buffer without heap allocation.
/// Returns the formatted slice within the provided buffer.
#[inline]
pub fn itoa_buf(value: u64, buf: &mut [u8; 20]) -> &str {
    if value == 0 {
        buf[19] = b'0';
        // SAFETY: b'0' is valid UTF-8
        return unsafe { core::str::from_utf8_unchecked(&buf[19..]) };
    }
    let mut i = 20;
    let mut v = value;
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    // SAFETY: digits 0-9 are valid UTF-8
    unsafe { core::str::from_utf8_unchecked(&buf[i..]) }
}

/// Format an `i32` into a stack-allocated buffer without heap allocation.
#[inline]
pub fn itoa_i32(value: i32, buf: &mut [u8; 20]) -> &str {
    if value >= 0 {
        return itoa_buf(value as u64, buf);
    }
    // Negative: format absolute value then prepend '-'
    let abs = (value as i64).unsigned_abs();
    let s = itoa_buf(abs, buf);
    let start = 20 - s.len() - 1;
    buf[start] = b'-';
    unsafe { core::str::from_utf8_unchecked(&buf[start..]) }
}

/// Write multiple string segments to stderr as a single warning line.
/// Zero heap allocation. Each segment gets its own `write(2)` call.
///
/// ```ignore
/// fs_warn_parts(&["failed to setresuid(", uid_str, "): ", err_str]);
/// ```
#[inline]
pub fn fs_warn_parts(parts: &[&str]) {
    raw_write(b"[WARN] ");
    for part in parts {
        raw_write(part.as_bytes());
    }
    raw_write(b"\n");
}

/// Info-level: no-op. Child stderr is captured as the submission's stderr
/// output — diagnostic messages would pollute user-visible output.
/// Only `fs_warn_parts` emits (for actual errors that need attention).
#[inline]
pub fn fs_info_parts(_parts: &[&str]) {}

/// Debug-level: no-op. Same reason as `fs_info_parts`.
#[inline]
pub fn fs_debug_parts(_parts: &[&str]) {}

// --- Convenience wrappers for single-message calls (static strings only) ---

/// Fork-safe warning with a single static string. No allocation.
#[inline]
pub fn fs_warn(msg: &str) {
    fs_warn_parts(&[msg]);
}

/// Fork-safe info with a single static string. No allocation.
#[inline]
pub fn fs_info(msg: &str) {
    fs_info_parts(&[msg]);
}

/// Fork-safe debug with a single static string. No-op in release builds.
#[inline]
pub fn fs_debug(msg: &str) {
    fs_debug_parts(&[msg]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn itoa_buf_formats_zero() {
        let mut buf = [0u8; 20];
        assert_eq!(itoa_buf(0, &mut buf), "0");
    }

    #[test]
    fn itoa_buf_formats_positive() {
        let mut buf = [0u8; 20];
        assert_eq!(itoa_buf(65534, &mut buf), "65534");
        assert_eq!(itoa_buf(1, &mut buf), "1");
        assert_eq!(itoa_buf(18446744073709551615, &mut buf), "18446744073709551615");
    }

    #[test]
    fn itoa_i32_formats_negative() {
        let mut buf = [0u8; 20];
        assert_eq!(itoa_i32(-1, &mut buf), "-1");
        assert_eq!(itoa_i32(-42, &mut buf), "-42");
        assert_eq!(itoa_i32(0, &mut buf), "0");
        assert_eq!(itoa_i32(100, &mut buf), "100");
    }
}
