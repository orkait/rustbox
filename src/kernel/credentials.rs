//! UID/GID transitions for privilege dropping.
//!
//! This module runs inside a fork/clone child. All I/O MUST use raw `write(2)`
//! to stderr instead of `log::*` or `eprintln!` to avoid post-fork mutex
//! deadlocks (inherited locked mutexes from parent threads).

use crate::config::types::{IsolateError, Result};
use crate::utils::fork_safe_log::{fs_warn_parts, itoa_buf, itoa_i32};

/// Reject root UIDs/GIDs in strict mode.
pub fn validate_ids(uid: u32, gid: u32, strict_mode: bool) -> Result<()> {
    if uid == 0 || gid == 0 {
        if strict_mode {
            return Err(IsolateError::Privilege(format!(
                "cannot transition to root UID/GID (uid={}, gid={})",
                uid, gid
            )));
        }
        let mut ubuf = [0u8; 20];
        let mut gbuf = [0u8; 20];
        let uid_s = itoa_buf(uid as u64, &mut ubuf);
        let gid_s = itoa_buf(gid as u64, &mut gbuf);
        fs_warn_parts(&[
            "cannot transition to root UID/GID (uid=", uid_s, ", gid=", gid_s,
            ") (permissive mode)",
        ]);
    }
    Ok(())
}

/// Ordered transition: validate -> clear groups -> setresgid -> setresuid -> verify.
pub fn transition_to_unprivileged(uid: u32, gid: u32, strict_mode: bool) -> Result<()> {
    validate_ids(uid, gid, strict_mode)?;
    clear_supplementary_groups(strict_mode)?;
    set_gid(gid, strict_mode)?;
    set_uid(uid, strict_mode)?;
    verify_transition(uid, gid, strict_mode)?;
    Ok(())
}

fn clear_supplementary_groups(strict_mode: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use nix::unistd::setgroups;
        match setgroups(&[]) {
            Ok(()) => Ok(()),
            Err(err) => {
                if strict_mode {
                    Err(IsolateError::Privilege(format!(
                        "failed to clear supplementary groups: {}",
                        err
                    )))
                } else {
                    let mut ebuf = [0u8; 20];
                    let eno = itoa_i32(err as i32, &mut ebuf);
                    fs_warn_parts(&[
                        "failed to clear supplementary groups in permissive mode: errno=", eno,
                    ]);
                    Ok(())
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        if strict_mode {
            Err(IsolateError::Privilege(
                "setgroups is only supported on Linux".to_string(),
            ))
        } else {
            Ok(())
        }
    }
}

fn set_gid(gid: u32, strict_mode: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: setresgid on current process with explicit raw gids.
        let rc = unsafe {
            libc::setresgid(
                gid as libc::gid_t,
                gid as libc::gid_t,
                gid as libc::gid_t,
            )
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if strict_mode {
                return Err(IsolateError::Privilege(format!(
                    "failed to setresgid({}): {}",
                    gid, err
                )));
            }
            let mut gbuf = [0u8; 20];
            let mut ebuf = [0u8; 20];
            let gid_s = itoa_buf(gid as u64, &mut gbuf);
            let eno = itoa_i32(err.raw_os_error().unwrap_or(-1), &mut ebuf);
            fs_warn_parts(&[
                "failed to setresgid(", gid_s, ") in permissive mode: errno=", eno,
            ]);
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        if strict_mode {
            Err(IsolateError::Privilege(
                "setresgid is only supported on Linux".to_string(),
            ))
        } else {
            Ok(())
        }
    }
}

fn set_uid(uid: u32, strict_mode: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: setresuid on current process with explicit raw uids.
        let rc = unsafe {
            libc::setresuid(
                uid as libc::uid_t,
                uid as libc::uid_t,
                uid as libc::uid_t,
            )
        };
        // Use fs_warn for post-setresuid messages (UID may have changed, log mutex unsafe)
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if strict_mode {
                return Err(IsolateError::Privilege(format!(
                    "failed to setresuid({}): {}",
                    uid, err
                )));
            }
            let mut ubuf = [0u8; 20];
            let mut ebuf = [0u8; 20];
            let uid_s = itoa_buf(uid as u64, &mut ubuf);
            let eno = itoa_i32(err.raw_os_error().unwrap_or(-1), &mut ebuf);
            fs_warn_parts(&[
                "failed to setresuid(", uid_s, ") in permissive mode: errno=", eno,
            ]);
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        if strict_mode {
            Err(IsolateError::Privilege(
                "setresuid is only supported on Linux".to_string(),
            ))
        } else {
            Ok(())
        }
    }
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
            if strict_mode {
                return Err(IsolateError::Privilege(format!(
                    "UID verification failed: expected {}, got real={}, effective={}",
                    expected_uid, real_uid, effective_uid
                )));
            }
            let mut ebuf = [0u8; 20];
            let mut rbuf = [0u8; 20];
            let mut efbuf = [0u8; 20];
            let exp_s = itoa_buf(expected_uid as u64, &mut ebuf);
            let real_s = itoa_buf(real_uid as u64, &mut rbuf);
            let eff_s = itoa_buf(effective_uid as u64, &mut efbuf);
            fs_warn_parts(&[
                "UID verification failed: expected ", exp_s,
                ", got real=", real_s, ", effective=", eff_s,
                " (permissive mode)",
            ]);
        }

        if real_gid != expected_gid || effective_gid != expected_gid {
            if strict_mode {
                return Err(IsolateError::Privilege(format!(
                    "GID verification failed: expected {}, got real={}, effective={}",
                    expected_gid, real_gid, effective_gid
                )));
            }
            let mut ebuf = [0u8; 20];
            let mut rbuf = [0u8; 20];
            let mut efbuf = [0u8; 20];
            let exp_s = itoa_buf(expected_gid as u64, &mut ebuf);
            let real_s = itoa_buf(real_gid as u64, &mut rbuf);
            let eff_s = itoa_buf(effective_gid as u64, &mut efbuf);
            fs_warn_parts(&[
                "GID verification failed: expected ", exp_s,
                ", got real=", real_s, ", effective=", eff_s,
                " (permissive mode)",
            ]);
        }

        // Verify saved-set-UID via getresuid(2)
        let mut ruid: libc::uid_t = 0;
        let mut euid: libc::uid_t = 0;
        let mut suid: libc::uid_t = 0;
        // SAFETY: getresuid writes to valid mut pointers on the current process.
        if unsafe { libc::getresuid(&mut ruid, &mut euid, &mut suid) } != 0 {
            return Err(IsolateError::Privilege("getresuid failed".to_string()));
        }
        if suid != expected_uid {
            if strict_mode {
                return Err(IsolateError::Privilege(format!(
                    "saved-set-UID mismatch: expected {}, got {}",
                    expected_uid, suid
                )));
            }
            let mut ebuf = [0u8; 20];
            let mut sbuf = [0u8; 20];
            let exp_s = itoa_buf(expected_uid as u64, &mut ebuf);
            let suid_s = itoa_buf(suid as u64, &mut sbuf);
            fs_warn_parts(&[
                "saved-set-UID mismatch: expected ", exp_s,
                ", got ", suid_s,
                " (permissive mode)",
            ]);
        }

        // Verify saved-set-GID via getresgid(2)
        let mut rgid: libc::gid_t = 0;
        let mut egid: libc::gid_t = 0;
        let mut sgid: libc::gid_t = 0;
        // SAFETY: getresgid writes to valid mut pointers on the current process.
        if unsafe { libc::getresgid(&mut rgid, &mut egid, &mut sgid) } != 0 {
            return Err(IsolateError::Privilege("getresgid failed".to_string()));
        }
        if sgid != expected_gid {
            if strict_mode {
                return Err(IsolateError::Privilege(format!(
                    "saved-set-GID mismatch: expected {}, got {}",
                    expected_gid, sgid
                )));
            }
            let mut ebuf = [0u8; 20];
            let mut sbuf = [0u8; 20];
            let exp_s = itoa_buf(expected_gid as u64, &mut ebuf);
            let sgid_s = itoa_buf(sgid as u64, &mut sbuf);
            fs_warn_parts(&[
                "saved-set-GID mismatch: expected ", exp_s,
                ", got ", sgid_s,
                " (permissive mode)",
            ]);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        return if strict_mode {
            Err(IsolateError::Privilege(
                "credential verification not supported on non-Linux".to_string(),
            ))
        } else {
            Ok(())
        };
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_ids_rejects_root_in_strict_mode() {
        assert!(validate_ids(0, 1000, true).is_err());
        assert!(validate_ids(1000, 0, true).is_err());
    }

    #[test]
    fn validate_ids_allows_root_in_permissive_mode() {
        assert!(validate_ids(0, 0, false).is_ok());
    }

    #[test]
    fn validate_ids_accepts_non_root() {
        assert!(validate_ids(65534, 65534, true).is_ok());
    }
}
