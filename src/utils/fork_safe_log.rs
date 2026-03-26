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

#[inline]
pub fn itoa_i32(value: i32, buf: &mut [u8; 20]) -> &str {
    if value >= 0 {
        return itoa_buf(value as u64, buf);
    }
    let abs = (value as i64).unsigned_abs();
    let s = itoa_buf(abs, buf);
    let start = 20 - s.len() - 1;
    buf[start] = b'-';
    unsafe { core::str::from_utf8_unchecked(&buf[start..]) }
}

#[inline]
pub fn fs_warn_parts(parts: &[&str]) {
    raw_write(b"[WARN] ");
    for part in parts {
        raw_write(part.as_bytes());
    }
    raw_write(b"\n");
}

#[inline]
pub fn fs_info_parts(parts: &[&str]) {
    if cfg!(debug_assertions) || verbose_sandbox_log() {
        raw_write(b"[INFO] ");
        for part in parts {
            raw_write(part.as_bytes());
        }
        raw_write(b"\n");
    }
}

#[inline]
pub fn fs_debug_parts(parts: &[&str]) {
    if verbose_sandbox_log() {
        raw_write(b"[DEBUG] ");
        for part in parts {
            raw_write(part.as_bytes());
        }
        raw_write(b"\n");
    }
}

fn verbose_sandbox_log() -> bool {
    static ENABLED: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(2);
    let cached = ENABLED.load(std::sync::atomic::Ordering::Relaxed);
    if cached != 2 {
        return cached == 1;
    }
    let val = std::env::var_os("RUSTBOX_VERBOSE_LOG").is_some();
    ENABLED.store(val as u8, std::sync::atomic::Ordering::Relaxed);
    val
}

#[inline]
pub fn fs_warn(msg: &str) {
    fs_warn_parts(&[msg]);
}

#[inline]
pub fn fs_info(msg: &str) {
    fs_info_parts(&[msg]);
}

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
        assert_eq!(
            itoa_buf(18446744073709551615, &mut buf),
            "18446744073709551615"
        );
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
