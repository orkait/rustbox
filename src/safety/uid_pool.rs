use crate::config::types::{IsolateError, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

struct PoolConfig {
    base_uid: u32,
    pool_size: u32,
    words: usize,
}

fn pool_config() -> &'static PoolConfig {
    static CONFIG: OnceLock<PoolConfig> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let base_uid: u32 = std::env::var("RUSTBOX_UID_BASE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60000);
        let pool_size: u32 = std::env::var("RUSTBOX_UID_POOL_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1000)
            .min(4096);
        let words = (pool_size as usize).div_ceil(64);
        PoolConfig {
            base_uid,
            pool_size,
            words,
        }
    })
}

const MAX_POOL_WORDS: usize = 64; // supports up to 4096 UIDs

static POOL: [AtomicU64; MAX_POOL_WORDS] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; MAX_POOL_WORDS]
};

#[must_use]
pub fn is_pool_uid(uid: u32) -> bool {
    let cfg = pool_config();
    (cfg.base_uid..cfg.base_uid + cfg.pool_size).contains(&uid)
}

pub fn allocate() -> Result<u32> {
    let cfg = pool_config();
    for word_idx in 0..cfg.words {
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
            if slot >= cfg.pool_size {
                break;
            }
            let mask = 1u64 << bit;
            if POOL[word_idx]
                .compare_exchange_weak(current, current | mask, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(cfg.base_uid + slot);
            }
        }
    }
    Err(IsolateError::ResourceLimit(format!(
        "UID pool exhausted: all {} sandbox slots are in use",
        cfg.pool_size
    )))
}

pub fn release(uid: u32) {
    let cfg = pool_config();
    if !is_pool_uid(uid) {
        return;
    }
    let slot = uid - cfg.base_uid;
    let word_idx = (slot / 64) as usize;
    let bit = slot % 64;
    let mask = 1u64 << bit;
    let prev = POOL[word_idx].fetch_and(!mask, Ordering::Release);
    assert!(prev & mask != 0, "double-free: UID {}", uid);
}

#[must_use]
pub fn active_count() -> u32 {
    let cfg = pool_config();
    let mut count = 0u32;
    for word_idx in 0..cfg.words {
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
        let cfg = pool_config();
        let base = cfg.base_uid;
        let end = base + cfg.pool_size;
        assert!(!is_pool_uid(0));
        assert!(!is_pool_uid(base.wrapping_sub(1)));
        assert!(is_pool_uid(base));
        assert!(is_pool_uid(end - 1));
        assert!(!is_pool_uid(end));
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
