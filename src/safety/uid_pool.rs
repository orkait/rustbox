use crate::config::types::{IsolateError, Result};
use std::sync::atomic::{AtomicU64, Ordering};

const BASE_UID: u32 = 60000;
const POOL_SIZE: u32 = 1000;
const WORDS: usize = (POOL_SIZE as usize).div_ceil(64);

static POOL: [AtomicU64; WORDS] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; WORDS]
};

pub fn is_pool_uid(uid: u32) -> bool {
    (BASE_UID..BASE_UID + POOL_SIZE).contains(&uid)
}

pub fn allocate() -> Result<u32> {
    for word_idx in 0..WORDS {
        loop {
            let current = POOL[word_idx].load(Ordering::Relaxed);
            if current == u64::MAX {
                break;
            }
            let bit = (!current).trailing_zeros();
            if bit >= 64 {
                break;
            }
            let slot = word_idx as u32 * 64 + bit;
            if slot >= POOL_SIZE {
                break;
            }
            let mask = 1u64 << bit;
            if POOL[word_idx]
                .compare_exchange_weak(current, current | mask, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(BASE_UID + slot);
            }
        }
    }
    Err(IsolateError::ResourceLimit(
        "UID pool exhausted: all 1000 sandbox slots are in use".to_string(),
    ))
}

pub fn release(uid: u32) {
    if !is_pool_uid(uid) {
        return;
    }
    let slot = uid - BASE_UID;
    let word_idx = (slot / 64) as usize;
    let bit = slot % 64;
    let mask = 1u64 << bit;
    let prev = POOL[word_idx].fetch_and(!mask, Ordering::Release);
    debug_assert!(prev & mask != 0, "double-free: UID {}", uid);
}

pub fn active_count() -> u32 {
    let mut count = 0u32;
    for word_idx in 0..WORDS {
        count += POOL[word_idx].load(Ordering::Relaxed).count_ones();
    }
    count
}

pub struct UidGuard {
    uid: u32,
    released: bool,
}

impl UidGuard {
    pub fn allocate() -> Result<Self> {
        let uid = allocate()?;
        Ok(Self {
            uid,
            released: false,
        })
    }

    pub fn uid(&self) -> u32 {
        self.uid
    }
}

impl Drop for UidGuard {
    fn drop(&mut self) {
        if !self.released {
            release(self.uid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_pool_uid_validates_range() {
        assert!(!is_pool_uid(0));
        assert!(!is_pool_uid(59999));
        assert!(is_pool_uid(60000));
        assert!(is_pool_uid(60999));
        assert!(!is_pool_uid(61000));
        assert!(!is_pool_uid(65534));
    }

    #[test]
    fn guard_allocates_in_valid_range() {
        let guard = UidGuard::allocate().unwrap();
        assert!(is_pool_uid(guard.uid()));
    }

    #[test]
    fn guard_releases_on_drop() {
        let before = active_count();
        {
            let _guard = UidGuard::allocate().unwrap();
            assert_eq!(active_count(), before + 1);
        }
        assert_eq!(active_count(), before);
    }

    #[test]
    fn guards_allocate_unique_uids() {
        let a = UidGuard::allocate().unwrap();
        let b = UidGuard::allocate().unwrap();
        assert_ne!(a.uid(), b.uid());
    }

    #[test]
    fn pool_exhaustion_returns_error() {
        let mut guards = Vec::new();
        loop {
            match UidGuard::allocate() {
                Ok(g) => guards.push(g),
                Err(_) => break,
            }
        }
        assert!(UidGuard::allocate().is_err());
    }

    #[test]
    fn release_ignores_non_pool_uids() {
        release(0);
        release(65534);
    }
}
