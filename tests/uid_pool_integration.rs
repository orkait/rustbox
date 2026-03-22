use rustbox::safety::uid_pool;
use std::collections::HashSet;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

fn test_config() -> rustbox::config::types::IsolateConfig {
    let mut config = rustbox::config::types::IsolateConfig::with_language_defaults(
        "python", "rustbox/0".to_string(),
    ).unwrap();
    config.strict_mode = false;
    config.allow_degraded = true;
    config
}

#[test]
fn single_allocation_per_isolate_lifecycle() {
    let _ = rustbox::observability::audit::init_security_logger(None);

    let before = uid_pool::active_count();

    let config = test_config();
    assert_eq!(uid_pool::active_count(), before, "config creation must not allocate from pool");

    // Step 2: Isolate::new allocates exactly 1
    let isolate = rustbox::runtime::isolate::Isolate::new(config).unwrap();
    assert_eq!(
        uid_pool::active_count(),
        before + 1,
        "Isolate::new must allocate exactly 1 UID"
    );

    let uid = isolate.config().uid.unwrap();
    assert!(uid_pool::is_pool_uid(uid), "allocated uid {} must be in pool range", uid);
    assert_eq!(isolate.config().gid, Some(uid), "gid must match uid");
    assert_eq!(
        isolate.config().instance_id,
        format!("rustbox/{}", uid),
        "instance_id must reflect pool uid"
    );

    // Step 3: execute does NOT allocate again
    // (we can't run execute without root, but we can verify the count doesn't change
    // by checking that no code path between new() and cleanup() calls allocate)
    assert_eq!(
        uid_pool::active_count(),
        before + 1,
        "no additional allocation should happen after Isolate::new"
    );

    // Step 4: cleanup releases exactly 1
    isolate.cleanup().unwrap();
    assert_eq!(
        uid_pool::active_count(),
        before,
        "cleanup must release the UID back to pool"
    );
}

#[test]
fn drop_releases_if_cleanup_not_called() {
    let _ = rustbox::observability::audit::init_security_logger(None);

    let before = uid_pool::active_count();

    {
        let config = test_config();
        let _isolate = rustbox::runtime::isolate::Isolate::new(config).unwrap();
        assert_eq!(uid_pool::active_count(), before + 1);
        // _isolate drops here without explicit cleanup
    }

    assert_eq!(
        uid_pool::active_count(),
        before,
        "Drop must release the UID if cleanup was not called"
    );
}

#[test]
fn cleanup_then_drop_does_not_double_release() {
    let _ = rustbox::observability::audit::init_security_logger(None);

    let before = uid_pool::active_count();

    let config = test_config();
    let isolate = rustbox::runtime::isolate::Isolate::new(config).unwrap();
    assert_eq!(uid_pool::active_count(), before + 1);

    isolate.cleanup().unwrap();
    // cleanup consumed self, Drop runs on the consumed value but _uid_guard is None
    assert_eq!(
        uid_pool::active_count(),
        before,
        "count must be back to baseline after cleanup"
    );
}

#[test]
fn uid_propagates_through_execution_profile() {
    let _ = rustbox::observability::audit::init_security_logger(None);

    let config = test_config();
    let isolate = rustbox::runtime::isolate::Isolate::new(config).unwrap();
    let uid = isolate.config().uid.unwrap();

    let profile = rustbox::core::types::ExecutionProfile::from_config(
        isolate.config(),
        &["/bin/true".to_string()],
        None,
    );
    assert_eq!(profile.uid, Some(uid), "ExecutionProfile must carry the pool uid");
    assert_eq!(profile.gid, Some(uid), "ExecutionProfile gid must match");

    let request = rustbox::core::types::SandboxLaunchRequest::from_config(
        isolate.config(),
        &["/bin/true".to_string()],
        None,
        None,
    );
    assert_eq!(request.profile.uid, Some(uid), "SandboxLaunchRequest must carry the pool uid");
    assert_eq!(request.instance_id, format!("rustbox/{}", uid));

    isolate.cleanup().unwrap();
}

#[test]
fn multiple_isolates_get_distinct_uids() {
    let _ = rustbox::observability::audit::init_security_logger(None);

    let before = uid_pool::active_count();

    let c1 = test_config();
    let c2 = test_config();
    let c3 = test_config();

    let i1 = rustbox::runtime::isolate::Isolate::new(c1).unwrap();
    let i2 = rustbox::runtime::isolate::Isolate::new(c2).unwrap();
    let i3 = rustbox::runtime::isolate::Isolate::new(c3).unwrap();

    assert_eq!(uid_pool::active_count(), before + 3);

    let uid1 = i1.config().uid.unwrap();
    let uid2 = i2.config().uid.unwrap();
    let uid3 = i3.config().uid.unwrap();

    assert_ne!(uid1, uid2);
    assert_ne!(uid2, uid3);
    assert_ne!(uid1, uid3);

    i1.cleanup().unwrap();
    assert_eq!(uid_pool::active_count(), before + 2);
    i2.cleanup().unwrap();
    assert_eq!(uid_pool::active_count(), before + 1);
    i3.cleanup().unwrap();
    assert_eq!(uid_pool::active_count(), before);
}

#[test]
fn concurrent_isolate_creation_no_uid_collision() {
    let _ = rustbox::observability::audit::init_security_logger(None);

    let thread_count = 20;
    let barrier = Arc::new(Barrier::new(thread_count));
    let release_barrier = Arc::new(Barrier::new(thread_count));
    let results: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();

    for _ in 0..thread_count {
        let barrier = barrier.clone();
        let release_barrier = release_barrier.clone();
        let results = results.clone();
        handles.push(thread::spawn(move || {
            let config = test_config();
            barrier.wait();
            let isolate = rustbox::runtime::isolate::Isolate::new(config).unwrap();
            let uid = isolate.config().uid.unwrap();
            results.lock().unwrap().push(uid);
            release_barrier.wait();
            isolate.cleanup().unwrap();
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let uids = results.lock().unwrap();
    let unique: HashSet<u32> = uids.iter().copied().collect();
    assert_eq!(uids.len(), unique.len(), "simultaneously held UIDs must be unique");
    assert_eq!(uids.len(), thread_count);
}

#[test]
fn rapid_create_destroy_cycles_hold_under_load() {
    let _ = rustbox::observability::audit::init_security_logger(None);

    let before = uid_pool::active_count();
    let thread_count = 10;
    let cycles = 20;
    let barrier = Arc::new(Barrier::new(thread_count));
    let mut handles = Vec::new();

    for _ in 0..thread_count {
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            for cycle in 0..cycles {
                let config = test_config();
                let isolate = rustbox::runtime::isolate::Isolate::new(config)
                    .unwrap_or_else(|e| panic!("Isolate::new failed cycle {}: {}", cycle, e));
                assert!(uid_pool::is_pool_uid(isolate.config().uid.unwrap()));
                isolate.cleanup()
                    .unwrap_or_else(|e| panic!("cleanup failed cycle {}: {}", cycle, e));
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        uid_pool::active_count(),
        before,
        "pool must be balanced after all cycles complete"
    );
}
