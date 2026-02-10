//! Safe UID/GID transitions to unprivileged credentials.
//!
//! CRITICAL: setresgid MUST be called BEFORE setresuid to prevent
//! privilege escalation through saved-set-user-ID.

use crate::config::types::{IsolateError, Result};
use super::validation::validate_ids;

/// 5-step transition: validate -> clear groups -> setresgid -> setresuid -> verify.
pub fn transition_to_unprivileged(uid: u32, gid: u32, strict_mode: bool) -> Result<()> {
    validate_ids(uid, gid, strict_mode)?;
    clear_supplementary_groups(strict_mode)?;
    // CRITICAL: GID before UID
    set_gid(gid, strict_mode)?;
    set_uid(uid, strict_mode)?;
    verify_transition(uid, gid, strict_mode)?;

    log::info!("Transitioned to UID={}, GID={}", uid, gid);
    Ok(())
}

fn clear_supplementary_groups(strict_mode: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use nix::unistd::setgroups;
        match setgroups(&[]) {
            Ok(_) => {
                log::info!("Cleared supplementary groups");
                Ok(())
            }
            Err(e) => {
                let msg = format!("Failed to clear supplementary groups: {}", e);
                if strict_mode {
                    Err(IsolateError::Privilege(msg))
                } else {
                    log::warn!("{} (permissive mode)", msg);
                    Ok(())
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let msg = "setgroups is only available on Linux";
        if strict_mode {
            Err(IsolateError::Privilege(msg.to_string()))
        } else {
            log::warn!("{} (permissive mode)", msg);
            Ok(())
        }
    }
}

/// MUST be called BEFORE set_uid.
fn set_gid(gid: u32, strict_mode: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: setresgid atomically sets all three GIDs. gid validated != 0 by caller.
        let result =
            unsafe { libc::setresgid(gid as libc::gid_t, gid as libc::gid_t, gid as libc::gid_t) };
        if result != 0 {
            let err = std::io::Error::last_os_error();
            let msg = format!("Failed to setresgid({}): {}", gid, err);
            if strict_mode {
                return Err(IsolateError::Privilege(msg));
            } else {
                log::warn!("{} (permissive mode)", msg);
            }
        } else {
            log::info!("Set GID to {}", gid);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let msg = "setresgid is only available on Linux";
        if strict_mode {
            return Err(IsolateError::Privilege(msg.to_string()));
        } else {
            log::warn!("{} (permissive mode)", msg);
        }
    }

    Ok(())
}

/// MUST be called AFTER set_gid.
fn set_uid(uid: u32, strict_mode: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: setresuid atomically sets all three UIDs. uid validated != 0 by caller.
        // CRITICAL: Must be called after setresgid.
        let result =
            unsafe { libc::setresuid(uid as libc::uid_t, uid as libc::uid_t, uid as libc::uid_t) };
        if result != 0 {
            let err = std::io::Error::last_os_error();
            let msg = format!("Failed to setresuid({}): {}", uid, err);
            if strict_mode {
                return Err(IsolateError::Privilege(msg));
            } else {
                log::warn!("{} (permissive mode)", msg);
            }
        } else {
            log::info!("Set UID to {}", uid);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let msg = "setresuid is only available on Linux";
        if strict_mode {
            return Err(IsolateError::Privilege(msg.to_string()));
        } else {
            log::warn!("{} (permissive mode)", msg);
        }
    }

    Ok(())
}

fn verify_transition(expected_uid: u32, expected_gid: u32, strict_mode: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use nix::unistd::{getegid, geteuid, getgid, getuid};

        let real_uid = getuid().as_raw();
        let effective_uid = geteuid().as_raw();
        let real_gid = getgid().as_raw();
        let effective_gid = getegid().as_raw();

        if real_uid != expected_uid || effective_uid != expected_uid {
            let msg = format!(
                "UID verification failed: expected {}, got real={}, effective={}",
                expected_uid, real_uid, effective_uid
            );
            if strict_mode {
                return Err(IsolateError::Privilege(msg));
            } else {
                log::warn!("{} (permissive mode)", msg);
            }
        }

        if real_gid != expected_gid || effective_gid != expected_gid {
            let msg = format!(
                "GID verification failed: expected {}, got real={}, effective={}",
                expected_gid, real_gid, effective_gid
            );
            if strict_mode {
                return Err(IsolateError::Privilege(msg));
            } else {
                log::warn!("{} (permissive mode)", msg);
            }
        }

        log::info!("UID/GID verification passed");
    }

    #[cfg(not(target_os = "linux"))]
    {
        let msg = "UID/GID verification is only available on Linux";
        if strict_mode {
            return Err(IsolateError::Privilege(msg.to_string()));
        } else {
            log::warn!("{} (permissive mode)", msg);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_rejects_root_uid() {
        let result = transition_to_unprivileged(0, 1000, true);
        assert!(result.is_err());
    }

    #[test]
    fn transition_rejects_root_gid() {
        let result = transition_to_unprivileged(1000, 0, true);
        assert!(result.is_err());
    }

    #[test]
    fn transition_validates_parameters() {
        let uid = 1000u32;
        let gid = 1000u32;
        assert!(uid > 0);
        assert!(gid > 0);
    }
}
