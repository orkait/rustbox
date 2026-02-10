//! Read-only capability introspection.

use crate::config::types::{IsolateError, Result};
use super::{CapabilityNumber, PR_CAPBSET_READ, PR_GET_NO_NEW_PRIVS};
use std::fs;

pub fn check_no_new_privs() -> Result<bool> {
    // SAFETY: prctl(PR_GET_NO_NEW_PRIVS) reads a process attribute, no side effects.
    let result = unsafe { libc::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if result < 0 {
        return Err(IsolateError::Privilege(
            "Failed to check PR_GET_NO_NEW_PRIVS".to_string(),
        ));
    }
    Ok(result == 1)
}

pub fn get_bounding_set() -> Result<Vec<CapabilityNumber>> {
    let mut caps = Vec::new();
    for cap in 0..=CapabilityNumber::MAX_CAP {
        // SAFETY: prctl(PR_CAPBSET_READ) reads kernel state, no side effects.
        let result = unsafe { libc::prctl(PR_CAPBSET_READ, cap, 0, 0, 0) };
        if result == 1 {
            caps.push(CapabilityNumber(cap));
        }
    }
    Ok(caps)
}

/// Returns Cap* lines from /proc/self/status for debugging.
pub fn get_capability_status() -> Result<String> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|e| IsolateError::Privilege(format!("Failed to read /proc/self/status: {}", e)))?;

    let cap_lines: Vec<&str> = status.lines().filter(|l| l.starts_with("Cap")).collect();
    Ok(cap_lines.join("\n"))
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
        "UID/GID information not available on this platform".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_no_new_privs_returns_bool() {
        let result = check_no_new_privs();
        assert!(result.is_ok());
    }

    #[test]
    fn get_bounding_set_returns_vec() {
        let result = get_bounding_set();
        assert!(result.is_ok());
    }

    #[test]
    fn get_capability_status_contains_cap_lines() {
        let result = get_capability_status();
        assert!(result.is_ok());
        assert!(result.unwrap().contains("Cap"));
    }

    #[test]
    fn get_current_ids_returns_string() {
        let ids = get_current_ids();
        assert!(ids.contains("UID:"));
        assert!(ids.contains("GID:"));
    }
}
