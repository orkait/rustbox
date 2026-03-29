use crate::config::constants;
use crate::config::types::{IsolateError, Result};
use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

struct PoolConfig {
    base_uid: u32,
    pool_size: u32,
    words: usize,
    pool_dir: PathBuf,
}

fn pool_config() -> &'static PoolConfig {
    static CONFIG: OnceLock<PoolConfig> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let base_uid: u32 = match std::env::var("RUSTBOX_UID_BASE") {
            Ok(ref v) => match v.parse() {
                Ok(parsed) => parsed,
                Err(_) => {
                    log::warn!(
                        "RUSTBOX_UID_BASE='{}' is not a valid u32, using default {}",
                        v,
                        constants::DEFAULT_UID_POOL_BASE
                    );
                    constants::DEFAULT_UID_POOL_BASE
                }
            },
            Err(_) => constants::DEFAULT_UID_POOL_BASE,
        };
        let raw_pool_size: u32 = match std::env::var("RUSTBOX_UID_POOL_SIZE") {
            Ok(ref v) => match v.parse() {
                Ok(parsed) => parsed,
                Err(_) => {
                    log::warn!(
                        "RUSTBOX_UID_POOL_SIZE='{}' is not a valid u32, using default {}",
                        v,
                        constants::DEFAULT_UID_POOL_SIZE
                    );
                    constants::DEFAULT_UID_POOL_SIZE
                }
            },
            Err(_) => constants::DEFAULT_UID_POOL_SIZE,
        };
        let pool_size = raw_pool_size.min(constants::MAX_POOL_SIZE);
        if pool_size < raw_pool_size {
            log::warn!(
                "RUSTBOX_UID_POOL_SIZE={} exceeds maximum {}, capped",
                raw_pool_size,
                constants::MAX_POOL_SIZE
            );
        }
        let words = (pool_size as usize).div_ceil(64);

        let euid = unsafe { libc::geteuid() };
        let pool_dir = std::env::temp_dir()
            .join(format!("rustbox-uid-{}", euid))
            .join("pool");

        PoolConfig {
            base_uid,
            pool_size,
            words,
            pool_dir,
        }
    })
}

// Layer 1: In-memory bitmap for intra-process (thread) coordination.
// flock is per-process so it cannot distinguish threads.
const MAX_POOL_WORDS: usize = 64;

macro_rules! atomic_array {
    ($val:expr; $n:expr) => {{
        const INIT: AtomicU64 = AtomicU64::new($val);
        [INIT; $n]
    }};
}

#[allow(clippy::declare_interior_mutable_const)]
static POOL: [AtomicU64; MAX_POOL_WORDS] = atomic_array!(0; MAX_POOL_WORDS);

fn bitmap_try_claim(slot: u32) -> bool {
    let word_idx = (slot / constants::BITS_PER_WORD as u32) as usize;
    let bit = slot % constants::BITS_PER_WORD as u32;
    let mask = 1u64 << bit;
    loop {
        let current = POOL[word_idx].load(Ordering::Relaxed);
        if current & mask != 0 {
            return false;
        }
        if POOL[word_idx]
            .compare_exchange_weak(current, current | mask, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
    }
}

fn bitmap_release(slot: u32) {
    let word_idx = (slot / constants::BITS_PER_WORD as u32) as usize;
    let bit = slot % constants::BITS_PER_WORD as u32;
    let mask = 1u64 << bit;
    POOL[word_idx].fetch_and(!mask, Ordering::Release);
}

fn slot_path(cfg: &PoolConfig, slot: u32) -> PathBuf {
    cfg.pool_dir.join(format!("{:05}.lock", slot))
}

fn ensure_pool_dir(cfg: &PoolConfig) -> Result<()> {
    fs::create_dir_all(&cfg.pool_dir).map_err(|e| {
        IsolateError::ResourceLimit(format!(
            "failed to create UID pool directory {}: {}",
            cfg.pool_dir.display(),
            e
        ))
    })
}

// Layer 2: flock for cross-process coordination.
fn try_flock(path: &std::path::Path) -> Result<Option<OwnedFd>> {
    let path_c = std::ffi::CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| IsolateError::ResourceLimit("pool lock path contains NUL byte".to_string()))?;

    let fd = unsafe {
        libc::open(
            path_c.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC,
            constants::PERM_FILE_PRIVATE as libc::mode_t,
        )
    };
    if fd < 0 {
        return Err(IsolateError::ResourceLimit(format!(
            "failed to open pool lock file {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }

    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    let rc = unsafe { libc::flock(owned.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        Ok(Some(owned))
    } else {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            Ok(None)
        } else {
            Err(IsolateError::ResourceLimit(format!(
                "flock failed on {}: {}",
                path.display(),
                err
            )))
        }
    }
}

#[must_use]
pub fn is_pool_uid(uid: u32) -> bool {
    let cfg = pool_config();
    (cfg.base_uid..cfg.base_uid + cfg.pool_size).contains(&uid)
}

fn allocate() -> Result<(u32, OwnedFd)> {
    let cfg = pool_config();
    ensure_pool_dir(cfg)?;

    for slot in 0..cfg.pool_size {
        // Layer 1: claim in-process bitmap (prevents thread collision)
        if !bitmap_try_claim(slot) {
            continue;
        }

        // Layer 2: claim cross-process flock
        let path = slot_path(cfg, slot);
        match try_flock(&path) {
            Ok(Some(fd)) => return Ok((cfg.base_uid + slot, fd)),
            Ok(None) => {
                // Another process holds this slot - undo bitmap and try next
                bitmap_release(slot);
                continue;
            }
            Err(e) => {
                bitmap_release(slot);
                return Err(e);
            }
        }
    }

    Err(IsolateError::ResourceLimit(format!(
        "UID pool exhausted: all {} sandbox slots are in use",
        cfg.pool_size
    )))
}

#[must_use]
pub fn active_count() -> u32 {
    let cfg = pool_config();

    // In-process count from bitmap (fast, always available)
    let mut local_count = 0u32;
    for word in POOL.iter().take(cfg.words) {
        local_count += word.load(Ordering::Relaxed).count_ones();
    }

    // Cross-process count from flock probing (includes other processes)
    if !cfg.pool_dir.exists() {
        return local_count;
    }
    let mut flock_count = 0u32;
    for slot in 0..cfg.pool_size {
        let path = slot_path(cfg, slot);
        if !path.exists() {
            continue;
        }
        match try_flock(&path) {
            Ok(Some(_lock)) => {
                // We acquired it, so slot is free. Lock drops here.
            }
            Ok(None) => {
                // Another process holds it
                flock_count += 1;
            }
            Err(_) => {}
        }
    }

    // Return the higher of the two counts.
    // local_count includes this process's slots (flock can't detect same-process locks).
    // flock_count includes other processes' slots (bitmap can't see other processes).
    // A slot held by this process shows in local_count but NOT flock_count.
    // A slot held by another process shows in flock_count but NOT local_count.
    // Sum = total system-wide active count.
    local_count + flock_count
}

pub struct UidGuard {
    uid: u32,
    _lock_fd: Option<OwnedFd>,
}

impl UidGuard {
    pub fn allocate() -> Result<Self> {
        let (uid, fd) = allocate()?;
        Ok(Self {
            uid,
            _lock_fd: Some(fd),
        })
    }

    pub fn uid(&self) -> u32 {
        self.uid
    }
}

impl Drop for UidGuard {
    fn drop(&mut self) {
        // Drop the fd first (releases flock for cross-process)
        self._lock_fd.take();
        // Then release bitmap (frees slot for intra-process threads)
        if is_pool_uid(self.uid) {
            let slot = self.uid - pool_config().base_uid;
            bitmap_release(slot);
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
        let uid;
        {
            let guard = UidGuard::allocate().unwrap();
            uid = guard.uid();
            let slot = uid - pool_config().base_uid;
            let word_idx = (slot / constants::BITS_PER_WORD as u32) as usize;
            let bit = slot % constants::BITS_PER_WORD as u32;
            assert!(
                POOL[word_idx].load(Ordering::Relaxed) & (1u64 << bit) != 0,
                "bitmap bit must be set while guard is alive"
            );
        }
        let slot = uid - pool_config().base_uid;
        let word_idx = (slot / constants::BITS_PER_WORD as u32) as usize;
        let bit = slot % constants::BITS_PER_WORD as u32;
        assert!(
            POOL[word_idx].load(Ordering::Relaxed) & (1u64 << bit) == 0,
            "bitmap bit must be cleared after guard drops"
        );
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
}
