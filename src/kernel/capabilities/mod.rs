//! Linux capability management for privilege minimization.
//!
//! All capability drops are idempotent, best-effort, and never panic.

mod drop;
mod query;

pub use drop::{drop_all_capabilities, set_no_new_privs};
pub use query::{check_no_new_privs, get_bounding_set, get_capability_status, get_current_ids};

/// Capability number newtype for type safety.
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

    pub fn value(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilitySet {
    Bounding,
    Ambient,
    Effective,
    Permitted,
    Inheritable,
}

pub(crate) const PR_CAPBSET_READ: libc::c_int = 23;
pub(crate) const PR_CAPBSET_DROP: libc::c_int = 24;
pub(crate) const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
pub(crate) const PR_GET_NO_NEW_PRIVS: libc::c_int = 39;
pub(crate) const PR_CAP_AMBIENT: libc::c_int = 47;
pub(crate) const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_int = 4;
pub(crate) const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_number_validates_range() {
        assert!(CapabilityNumber::new(0).is_some());
        assert!(CapabilityNumber::new(40).is_some());
        assert!(CapabilityNumber::new(41).is_none());
        assert!(CapabilityNumber::new(100).is_none());
    }

    #[test]
    fn capability_number_preserves_value() {
        let cap = CapabilityNumber::new(5).unwrap();
        assert_eq!(cap.value(), 5);
    }
}
