//! Integration tests for kernel module
//!
//! These tests verify cross-module interactions and ordering requirements.

use rustbox::kernel::capabilities::{
    check_no_new_privs, drop_bounding_and_ambient, drop_process_caps_and_verify, set_no_new_privs,
};
use rustbox::kernel::credentials::transition_to_unprivileged;

#[test]
#[ignore]
fn test_full_privilege_drop_sequence() {
    // This test verifies the complete privilege drop sequence:
    // 1. Drop bounding and ambient capabilities
    // 2. Drop process capabilities
    // 3. Set no_new_privs

    // Step 1: Drop bounding and ambient (best-effort)
    let _ = drop_bounding_and_ambient();

    // Step 2: Drop process caps (best-effort, permissive mode)
    let _ = drop_process_caps_and_verify(false);

    // Step 3: Set no_new_privs (should always work)
    let result = set_no_new_privs();

    match result {
        Ok(_) => {
            let is_set = check_no_new_privs().unwrap();
            assert!(is_set, "no_new_privs should be set after successful call");
        }
        Err(e) => {
            println!("set_no_new_privs failed (expected without root): {:?}", e);
        }
    }
}

#[test]
#[ignore]
fn test_credential_transition_validates_before_syscall() {
    let result = transition_to_unprivileged(0, 1000, true);
    assert!(result.is_err(), "Should reject root UID");

    let result = transition_to_unprivileged(1000, 0, true);
    assert!(result.is_err(), "Should reject root GID");
}

#[test]
#[ignore]
fn test_idempotency_of_privilege_operations() {
    let _ = drop_bounding_and_ambient();
    let _ = drop_bounding_and_ambient();

    let first = set_no_new_privs();
    let second = set_no_new_privs();

    assert_eq!(
        first.is_ok(),
        second.is_ok(),
        "set_no_new_privs should be idempotent"
    );
}

#[test]
#[ignore]
fn test_no_panic_on_permission_denied() {
    // Skip when root: dropping caps then setgroups() triggers glibc's
    // NPTL setxid broadcast abort when threads have mismatched capabilities.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("Skipping: this test is for non-root (verifies graceful EPERM handling)");
        return;
    }

    let _ = drop_bounding_and_ambient();
    let _ = drop_process_caps_and_verify(false);
    let _ = transition_to_unprivileged(1000, 1000, false);
    let _ = set_no_new_privs();
}

#[test]
#[ignore]
fn test_strict_mode_vs_permissive_mode() {
    let strict_result = transition_to_unprivileged(0, 1000, true);
    assert!(strict_result.is_err(), "Strict mode should reject root UID");

    // Skip the permissive path as root: earlier tests drop capabilities from
    // this thread, and glibc's setgroups NPTL broadcast aborts on cap mismatch.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }

    let permissive_result = transition_to_unprivileged(0, 1000, false);
    assert!(
        permissive_result.is_ok(),
        "Permissive mode should not error on root UID"
    );
}
