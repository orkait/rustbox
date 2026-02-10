//! Credential validation logic.

use crate::config::types::{IsolateError, Result};

/// Reject root UIDs/GIDs (0) in strict mode.
pub fn validate_ids(uid: u32, gid: u32, strict_mode: bool) -> Result<()> {
    if uid == 0 || gid == 0 {
        let msg = format!(
            "Cannot transition to root UID/GID (uid={}, gid={})",
            uid, gid
        );
        if strict_mode {
            return Err(IsolateError::Privilege(msg));
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
    fn validate_ids_rejects_root_uid_in_strict_mode() {
        assert!(validate_ids(0, 1000, true).is_err());
    }

    #[test]
    fn validate_ids_rejects_root_gid_in_strict_mode() {
        assert!(validate_ids(1000, 0, true).is_err());
    }

    #[test]
    fn validate_ids_accepts_non_root_in_strict_mode() {
        assert!(validate_ids(1000, 1000, true).is_ok());
    }

    #[test]
    fn validate_ids_warns_root_in_permissive_mode() {
        assert!(validate_ids(0, 1000, false).is_ok());
    }
}
