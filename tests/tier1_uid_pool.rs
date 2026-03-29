mod common;

use rustbox::config::constants;
use rustbox::config::profile::SecurityProfile;
use rustbox::safety::uid_pool::{self, UidGuard};
use std::collections::HashSet;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

#[test]
fn guard_allocates_in_pool_range() {
    let guard = UidGuard::allocate().expect("allocation must succeed");
    let uid = guard.uid();
    let base = constants::DEFAULT_UID_POOL_BASE;
    let end = base + constants::DEFAULT_UID_POOL_SIZE;
    assert!(
        uid >= base && uid < end,
        "uid {} must be in range [{}, {})",
        uid,
        base,
        end
    );
}

#[test]
fn guard_drop_releases_uid() {
    let uid;
    {
        let guard = UidGuard::allocate().expect("allocation must succeed");
        uid = guard.uid();
        assert!(uid_pool::is_pool_uid(uid));
    }
    let guard2 = UidGuard::allocate().expect("re-allocation after drop must succeed");
    assert!(uid_pool::is_pool_uid(guard2.uid()));
}

#[test]
fn two_guards_get_unique_uids() {
    let a = UidGuard::allocate().expect("first allocation");
    let b = UidGuard::allocate().expect("second allocation");
    assert_ne!(
        a.uid(),
        b.uid(),
        "two concurrent guards must have different UIDs"
    );
}

#[test]
fn is_pool_uid_boundary_checks() {
    let base = constants::DEFAULT_UID_POOL_BASE;
    let size = constants::DEFAULT_UID_POOL_SIZE;
    assert!(!uid_pool::is_pool_uid(0));
    assert!(!uid_pool::is_pool_uid(base.wrapping_sub(1)));
    assert!(uid_pool::is_pool_uid(base));
    assert!(uid_pool::is_pool_uid(base + size - 1));
    assert!(!uid_pool::is_pool_uid(base + size));
    assert!(!uid_pool::is_pool_uid(constants::NOBODY_UID));
}

#[test]
fn concurrent_allocations_are_unique() {
    let barrier = Arc::new(Barrier::new(20));
    let uids = Arc::new(Mutex::new(HashSet::new()));
    let mut handles = Vec::new();

    for _ in 0..20 {
        let b = Arc::clone(&barrier);
        let u = Arc::clone(&uids);
        handles.push(thread::spawn(move || {
            b.wait();
            let guard = UidGuard::allocate().expect("concurrent allocation must succeed");
            let uid = guard.uid();
            let mut set = u.lock().unwrap();
            assert!(
                set.insert(uid),
                "uid {} was already allocated by another thread",
                uid
            );
            drop(set);
            std::thread::sleep(constants::IO_JOIN_POLL_INTERVAL);
            drop(guard);
        }));
    }

    for h in handles {
        h.join().expect("thread must not panic");
    }

    let final_set = uids.lock().unwrap();
    assert_eq!(
        final_set.len(),
        20,
        "all 20 threads must have gotten unique UIDs"
    );
}

#[test]
fn active_count_reflects_allocations() {
    let before = uid_pool::active_count();
    let guard = UidGuard::allocate().expect("allocation must succeed");
    let during = uid_pool::active_count();
    assert!(
        during > before,
        "active count must increase after allocation (before={}, during={})",
        before,
        during
    );
    drop(guard);
}

#[test]
fn release_ignores_non_pool_uids() {
    uid_pool::release(0);
    uid_pool::release(constants::NOBODY_UID);
    uid_pool::release(999);
}

#[test]
fn uid_propagates_to_execution_profile() {
    common::init_subsystems();
    let (isolate, _lang) = common::build_isolate(SecurityProfile::Judge, "python", false);
    let config = isolate.config();
    let uid = config.uid;
    assert!(uid.is_some(), "isolate must have a UID set");
    let uid_val = uid.unwrap();
    assert!(uid_val != 0, "isolate UID must not be root");
}
