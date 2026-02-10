//! All operations are idempotent and best-effort.
use crate::config::types::{IsolateError, Result};
use super::{CapabilityNumber, PR_CAPBSET_DROP, PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL,
            PR_SET_NO_NEW_PRIVS, LINUX_CAPABILITY_VERSION_3};
use std::fs;

/// Drop all capabilities from all sets (bounding, ambient, effective, permitted, inheritable).
pub fn drop_all_capabilities() -> Result<()> {
    drop_bounding_capabilities()?;
    drop_ambient_capabilities()?;
    drop_process_capabilities()?;
    Ok(())
}

fn drop_bounding_capabilities() -> Result<()> {
    for cap in 0..=CapabilityNumber::MAX_CAP {
        // SAFETY: prctl(PR_CAPBSET_DROP) with any cap number is safe; invalid caps are ignored.
        let _ = unsafe { libc::prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) };
    }
    Ok(())
}

fn drop_ambient_capabilities() -> Result<()> {
    // SAFETY: prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL) is safe. Returns error
    // on older kernels without ambient capability support (non-fatal).
    let result = unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) };
    if result != 0 {
        log::warn!("Failed to clear ambient capabilities (may not be supported)");
    }
    Ok(())
}

/// Zero all capability sets via raw capset(2) syscall.
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

        // Version 3 requires two data entries: caps 0-31 and caps 32-63.
        let data = [
            CapUserData { effective: 0, permitted: 0, inheritable: 0 },
            CapUserData { effective: 0, permitted: 0, inheritable: 0 },
        ];

        #[cfg(target_arch = "x86_64")]
        const SYS_CAPSET: libc::c_long = 126;
        #[cfg(target_arch = "aarch64")]
        const SYS_CAPSET: libc::c_long = 91;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        compile_error!("SYS_capset number not defined for this architecture");

        // SAFETY: capset(2) with valid header (version 3, pid 0 = current) and
        // two zeroed data entries. Properly initialized structs, valid pointers.
        let rc = unsafe {
            libc::syscall(
                SYS_CAPSET,
                &header as *const CapUserHeader,
                data.as_ptr() as *const CapUserData,
            )
        };

        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) {
                log::debug!("capset returned EPERM (expected after credential drop): {}", err);
            } else {
                log::warn!("capset failed: {}", err);
            }
        } else {
            log::info!("Zeroed all capability sets via capset(2)");
        }
    }

    verify_capabilities_zeroed();
    Ok(())
}

fn verify_capabilities_zeroed() {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        log::warn!("Cannot read /proc/self/status for capability verification");
        return;
    };

    for line in status.lines() {
        let is_cap_line = line.starts_with("CapInh:")
            || line.starts_with("CapPrm:")
            || line.starts_with("CapEff:");

        if is_cap_line {
            let value = line.split_whitespace().nth(1).unwrap_or("");
            if value != "0000000000000000" {
                log::warn!(
                    "Capability not zeroed after drop: {} (bounding set + no_new_privs still protect)",
                    line.trim()
                );
            }
        }
    }
}

/// Prevent privilege escalation via execve (setuid, file capabilities).
/// Idempotent and irreversible once set.
pub fn set_no_new_privs() -> Result<()> {
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1) is safe and idempotent.
    let result = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result != 0 {
        return Err(IsolateError::Privilege(
            "Failed to set PR_SET_NO_NEW_PRIVS".to_string(),
        ));
    }
    log::info!("Set PR_SET_NO_NEW_PRIVS");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_bounding_capabilities_is_idempotent() {
        let _ = drop_bounding_capabilities();
        let _ = drop_bounding_capabilities();
    }

    #[test]
    fn drop_ambient_capabilities_is_idempotent() {
        let _ = drop_ambient_capabilities();
        let _ = drop_ambient_capabilities();
    }

    #[test]
    fn set_no_new_privs_is_idempotent() {
        let first = set_no_new_privs();
        let second = set_no_new_privs();
        assert_eq!(first.is_ok(), second.is_ok());
    }
}
