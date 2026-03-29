use crate::config::types::{IsolateError, Result};
use crate::utils::fork_safe_log::{fs_debug_parts, itoa_i32, raw_write};
use std::fs;

const PR_CAPBSET_DROP: libc::c_int = 24;
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
const PR_GET_NO_NEW_PRIVS: libc::c_int = 39;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_int = 4;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
const CAP_ZERO_HEX: &str = "0000000000000000";
const REQUIRED_CAP_LINES: [&str; 5] = ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"];

fn kernel_last_cap() -> u32 {
    fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(40)
}

pub fn drop_bounding_and_ambient() -> Result<()> {
    drop_bounding_capabilities()?;
    drop_ambient_capabilities()?;
    Ok(())
}

pub fn drop_process_caps_and_verify(strict_mode: bool) -> Result<()> {
    drop_process_capabilities()?;
    verify_capabilities_zeroed(strict_mode)
}

fn drop_bounding_capabilities() -> Result<()> {
    let last_cap = kernel_last_cap();
    let mut failures = Vec::new();
    for cap in 0..=last_cap {
        // SAFETY: prctl(PR_CAPBSET_DROP) is safe for any cap number.
        let rc = unsafe { libc::prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINVAL) {
                failures.push((cap, err));
            }
        }
    }
    if !failures.is_empty() {
        let detail: Vec<String> = failures
            .iter()
            .map(|(cap, err)| format!("cap {}: {}", cap, err))
            .collect();
        return Err(IsolateError::Privilege(format!(
            "PR_CAPBSET_DROP failed for: {}",
            detail.join(", ")
        )));
    }
    Ok(())
}

fn drop_ambient_capabilities() -> Result<()> {
    // SAFETY: prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL) clears ambient set.
    let rc = unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINVAL) {
            let mut ebuf = [0u8; 20];
            let eno = itoa_i32(err.raw_os_error().unwrap_or(-1), &mut ebuf);
            fs_debug_parts(&[
                "ambient capability clearing not supported (EINVAL): errno=",
                eno,
            ]);
            return Ok(());
        }
        return Err(IsolateError::Privilege(format!(
            "failed to clear ambient capabilities: {}",
            err
        )));
    }
    Ok(())
}

fn drop_process_capabilities() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        #[repr(C)]
        struct CapUserHeader {
            version: u32,
            pid: i32,
        }

        #[repr(C)]
        struct CapUserData {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }

        let header = CapUserHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let data = [
            CapUserData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            CapUserData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];

        #[cfg(target_arch = "x86_64")]
        const SYS_CAPSET: libc::c_long = 126;
        #[cfg(target_arch = "aarch64")]
        const SYS_CAPSET: libc::c_long = 91;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        compile_error!("SYS_capset number not defined for this architecture");

        // SAFETY: syscall with initialized header/data structures and valid pointers.
        let rc =
            unsafe { libc::syscall(SYS_CAPSET, &header as *const CapUserHeader, data.as_ptr()) };

        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) {
                let mut ebuf = [0u8; 20];
                let eno = itoa_i32(err.raw_os_error().unwrap_or(-1), &mut ebuf);
                fs_debug_parts(&["capset returned EPERM after privilege drop: errno=", eno]);
                return Ok(());
            }
            return Err(IsolateError::Privilege(format!("capset failed: {}", err)));
        }
    }
    Ok(())
}

fn verify_capabilities_zeroed(strict_mode: bool) -> Result<()> {
    let status = fs::read_to_string("/proc/self/status").map_err(|e| {
        IsolateError::Privilege(format!(
            "cannot read /proc/self/status for capability verification: {}",
            e
        ))
    })?;

    let mut non_zero = Vec::new();
    for line in status.lines() {
        if REQUIRED_CAP_LINES
            .iter()
            .any(|prefix| line.starts_with(prefix))
        {
            let value = line.split_whitespace().nth(1).unwrap_or_default();
            if value != CAP_ZERO_HEX {
                non_zero.push(line.trim().to_string());
            }
        }
    }

    if non_zero.is_empty() {
        return Ok(());
    }

    let message = format!(
        "capability sets not fully zero after drop: {}",
        non_zero.join(", ")
    );

    let is_root = unsafe { libc::geteuid() } == 0;
    if strict_mode || is_root {
        Err(IsolateError::Privilege(message))
    } else {
        raw_write(b"[WARN] ");
        raw_write(message.as_bytes());
        raw_write(b" (permissive non-root mode)\n");
        Ok(())
    }
}

pub fn set_no_new_privs() -> Result<()> {
    // SAFETY: PR_SET_NO_NEW_PRIVS is a process attribute setter.
    let rc = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(IsolateError::Privilege(
            "failed to set PR_SET_NO_NEW_PRIVS".to_string(),
        ));
    }
    Ok(())
}

#[must_use = "check the returned value to verify NO_NEW_PRIVS state"]
pub fn check_no_new_privs() -> Result<bool> {
    // SAFETY: PR_GET_NO_NEW_PRIVS is read-only.
    let rc = unsafe { libc::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if rc < 0 {
        return Err(IsolateError::Privilege(
            "failed to read PR_GET_NO_NEW_PRIVS".to_string(),
        ));
    }
    Ok(rc == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_last_cap_is_sane() {
        let last = kernel_last_cap();
        assert!(
            last >= 36,
            "kernel should support at least CAP_MAC_ADMIN(36)"
        );
        assert!(last <= 63, "cap_last_cap exceeds max supported (63)");
    }

    #[test]
    fn no_new_privs_api_is_callable() {
        let _ = check_no_new_privs();
    }
}
