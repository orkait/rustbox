use crate::config::types::{IsolateError, Result};
use crate::utils::fork_safe_log::{fs_debug_parts, itoa_i32, raw_write};
use std::fs;

const PR_CAPBSET_READ: libc::c_int = 23;
const PR_CAPBSET_DROP: libc::c_int = 24;
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
const PR_GET_NO_NEW_PRIVS: libc::c_int = 39;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_int = 4;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
const CAP_ZERO_HEX: &str = "0000000000000000";
const REQUIRED_CAP_LINES: [&str; 5] = ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"];

/// Capability number newtype for type-safe range checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CapabilityNumber(u32);

impl CapabilityNumber {
    pub const MAX_CAP: u32 = 40;

    pub fn new(cap: u32) -> Option<Self> {
        if cap <= Self::MAX_CAP {
            Some(Self(cap))
        } else {
            None
        }
    }

    pub const fn value(self) -> u32 {
        self.0
    }
}

/// Drop capabilities from bounding, ambient, and process sets.
pub fn drop_all_capabilities() -> Result<()> {
    drop_bounding_capabilities()?;
    drop_ambient_capabilities()?;
    drop_process_capabilities()?;
    Ok(())
}

/// Drop only bounding and ambient sets.
/// Must be called while still effective root (before setresuid).
/// PR_CAPBSET_DROP requires CAP_SETPCAP in the effective set.
pub fn drop_bounding_and_ambient() -> Result<()> {
    drop_bounding_capabilities()?;
    drop_ambient_capabilities()?;
    Ok(())
}

/// Strict-aware capability drop for the lock_privileges step.
/// Bounding/ambient are already cleared; only zero the process sets and verify.
pub fn drop_process_caps_and_verify(strict_mode: bool) -> Result<()> {
    drop_process_capabilities()?;
    verify_capabilities_zeroed(strict_mode)
}

/// Strict-aware capability drop used by the pre-exec type-state chain.
pub fn drop_all_capabilities_strict(strict_mode: bool) -> Result<()> {
    drop_all_capabilities()?;
    verify_capabilities_zeroed(strict_mode)
}

fn drop_bounding_capabilities() -> Result<()> {
    let mut failures = Vec::new();
    for cap in 0..=CapabilityNumber::MAX_CAP {
        // SAFETY: prctl(PR_CAPBSET_DROP) is safe for any cap number.
        let rc = unsafe { libc::prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            // EINVAL means the capability doesn't exist on this kernel — not a failure.
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
        // EINVAL means ambient capabilities are not supported by this kernel — not a failure.
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
        let rc = unsafe {
            libc::syscall(
                SYS_CAPSET,
                &header as *const CapUserHeader,
                data.as_ptr(),
            )
        };

        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) {
                let mut ebuf = [0u8; 20];
                let eno = itoa_i32(err.raw_os_error().unwrap_or(-1), &mut ebuf);
                fs_debug_parts(&["capset returned EPERM after privilege drop: errno=", eno]);
                return Ok(());
            }
            return Err(IsolateError::Privilege(format!(
                "capset failed: {}", err
            )));
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
        if REQUIRED_CAP_LINES.iter().any(|prefix| line.starts_with(prefix)) {
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

    // When running as root (euid 0), capability verification is fatal in ALL modes.
    // Retained capabilities allow privilege escalation regardless of mode.
    // When running as non-root, capset EPERM is expected (CAP_SETPCAP required),
    // so we only enforce in strict mode where root is a prerequisite.
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

/// Set PR_SET_NO_NEW_PRIVS=1; idempotent and irreversible.
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

pub fn get_bounding_set() -> Result<Vec<CapabilityNumber>> {
    let mut caps = Vec::new();
    for cap in 0..=CapabilityNumber::MAX_CAP {
        // SAFETY: PR_CAPBSET_READ is read-only.
        let rc = unsafe { libc::prctl(PR_CAPBSET_READ, cap, 0, 0, 0) };
        if rc == 1 {
            caps.push(CapabilityNumber(cap));
        }
    }
    Ok(caps)
}

pub fn get_capability_status() -> Result<String> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|e| IsolateError::Privilege(format!("failed to read /proc/self/status: {}", e)))?;
    let lines: Vec<&str> = status.lines().filter(|line| line.starts_with("Cap")).collect();
    Ok(lines.join("\n"))
}

pub fn get_current_ids() -> String {
    #[cfg(target_os = "linux")]
    {
        use nix::unistd::{getegid, geteuid, getgid, getuid};
        format!(
            "UID: real={}, effective={} | GID: real={}, effective={}",
            getuid().as_raw(),
            geteuid().as_raw(),
            getgid().as_raw(),
            getegid().as_raw()
        )
    }

    #[cfg(not(target_os = "linux"))]
    {
        "UID/GID information unavailable on non-Linux platforms".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_number_range_is_checked() {
        assert!(CapabilityNumber::new(0).is_some());
        assert!(CapabilityNumber::new(40).is_some());
        assert!(CapabilityNumber::new(41).is_none());
    }

    #[test]
    fn no_new_privs_api_is_callable() {
        let _ = check_no_new_privs();
    }

    #[test]
    fn capability_status_contains_cap_lines() {
        let status = get_capability_status().unwrap();
        assert!(status.contains("Cap"));
    }
}
