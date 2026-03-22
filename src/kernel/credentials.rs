use crate::config::types::{IsolateError, Result};
use crate::utils::fork_safe_log::{fs_warn_parts, itoa_buf, itoa_i32};

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

pub fn transition_to_unprivileged(uid: u32, gid: u32, strict_mode: bool) -> Result<()> {
    validate_ids(uid, gid, strict_mode)?;
    clear_supplementary_groups(strict_mode)?;
    set_resid("gid", gid, strict_mode)?;
    set_resid("uid", uid, strict_mode)?;
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
                        "failed to clear supplementary groups: {}", err
                    )))
                } else {
                    let mut ebuf = [0u8; 20];
                    let eno = itoa_i32(err as i32, &mut ebuf);
                    fs_warn_parts(&["failed to clear supplementary groups in permissive mode: errno=", eno]);
                    Ok(())
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        if strict_mode {
            Err(IsolateError::Privilege("setgroups is only supported on Linux".to_string()))
        } else {
            Ok(())
        }
    }
}

fn set_resid(kind: &str, id: u32, strict_mode: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: setresuid/setresgid on current process with explicit raw ids.
        let rc = unsafe {
            if kind == "uid" {
                libc::setresuid(id as libc::uid_t, id as libc::uid_t, id as libc::uid_t)
            } else {
                libc::setresgid(id as libc::gid_t, id as libc::gid_t, id as libc::gid_t)
            }
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            let syscall = if kind == "uid" { "setresuid" } else { "setresgid" };
            if strict_mode {
                return Err(IsolateError::Privilege(format!(
                    "failed to {}({}): {}", syscall, id, err
                )));
            }
            let mut ibuf = [0u8; 20];
            let mut ebuf = [0u8; 20];
            let id_s = itoa_buf(id as u64, &mut ibuf);
            let eno = itoa_i32(err.raw_os_error().unwrap_or(-1), &mut ebuf);
            fs_warn_parts(&["failed to ", syscall, "(", id_s, ") in permissive mode: errno=", eno]);
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let syscall = if kind == "uid" { "setresuid" } else { "setresgid" };
        if strict_mode {
            Err(IsolateError::Privilege(format!("{} is only supported on Linux", syscall)))
        } else {
            Ok(())
        }
    }
}

fn verify_id_pair(label: &str, expected: u32, real: u32, effective: u32, strict_mode: bool) -> Result<()> {
    if real != expected || effective != expected {
        if strict_mode {
            return Err(IsolateError::Privilege(format!(
                "{} verification failed: expected {}, got real={}, effective={}",
                label, expected, real, effective
            )));
        }
        let mut ebuf = [0u8; 20];
        let mut rbuf = [0u8; 20];
        let mut efbuf = [0u8; 20];
        let exp_s = itoa_buf(expected as u64, &mut ebuf);
        let real_s = itoa_buf(real as u64, &mut rbuf);
        let eff_s = itoa_buf(effective as u64, &mut efbuf);
        fs_warn_parts(&[
            label, " verification failed: expected ", exp_s,
            ", got real=", real_s, ", effective=", eff_s, " (permissive mode)",
        ]);
    }
    Ok(())
}

fn verify_saved_id(label: &str, expected: u32, saved: u32, strict_mode: bool) -> Result<()> {
    if saved != expected {
        if strict_mode {
            return Err(IsolateError::Privilege(format!(
                "saved-set-{} mismatch: expected {}, got {}",
                label, expected, saved
            )));
        }
        let mut ebuf = [0u8; 20];
        let mut sbuf = [0u8; 20];
        let exp_s = itoa_buf(expected as u64, &mut ebuf);
        let saved_s = itoa_buf(saved as u64, &mut sbuf);
        fs_warn_parts(&[
            "saved-set-", label, " mismatch: expected ", exp_s,
            ", got ", saved_s, " (permissive mode)",
        ]);
    }
    Ok(())
}

fn verify_transition(expected_uid: u32, expected_gid: u32, strict_mode: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use nix::unistd::{getegid, geteuid, getgid, getuid};

        verify_id_pair("UID", expected_uid, getuid().as_raw(), geteuid().as_raw(), strict_mode)?;
        verify_id_pair("GID", expected_gid, getgid().as_raw(), getegid().as_raw(), strict_mode)?;

        let mut ruid: libc::uid_t = 0;
        let mut euid: libc::uid_t = 0;
        let mut suid: libc::uid_t = 0;
        // SAFETY: getresuid writes to valid mut pointers on the current process.
        if unsafe { libc::getresuid(&mut ruid, &mut euid, &mut suid) } != 0 {
            return Err(IsolateError::Privilege("getresuid failed".to_string()));
        }
        verify_saved_id("UID", expected_uid, suid, strict_mode)?;

        let mut rgid: libc::gid_t = 0;
        let mut egid: libc::gid_t = 0;
        let mut sgid: libc::gid_t = 0;
        // SAFETY: getresgid writes to valid mut pointers on the current process.
        if unsafe { libc::getresgid(&mut rgid, &mut egid, &mut sgid) } != 0 {
            return Err(IsolateError::Privilege("getresgid failed".to_string()));
        }
        verify_saved_id("GID", expected_gid, sgid, strict_mode)?;
    }

    #[cfg(not(target_os = "linux"))]
    {
        return if strict_mode {
            Err(IsolateError::Privilege("credential verification not supported on non-Linux".to_string()))
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
