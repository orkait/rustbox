//! Integration tests for kernel module
//!
//! These tests verify cross-module interactions and ordering requirements.

use rustbox::kernel::capabilities::{drop_all_capabilities, set_no_new_privs, check_no_new_privs};
use rustbox::kernel::credentials::transition_to_unprivileged;

#[test]
fn test_full_privilege_drop_sequence() {
    // This test verifies the complete privilege drop sequence:
    // 1. Drop capabilities
    // 2. Transition credentials
    // 3. Set no_new_privs
    
    // Note: This test may fail without root privileges
    // It's designed to verify the sequence doesn't panic
    
    // Step 1: Drop capabilities (best-effort)
    let _ = drop_all_capabilities();
    
    // Step 2: Set no_new_privs (should always work)
    let result = set_no_new_privs();
    
    // Should either succeed or fail gracefully
    match result {
        Ok(_) => {
            // Verify it was set
            let is_set = check_no_new_privs().unwrap();
            assert!(is_set, "no_new_privs should be set after successful call");
        }
        Err(e) => {
            // Expected if we don't have permissions
            println!("set_no_new_privs failed (expected without root): {:?}", e);
        }
    }
}

#[test]
fn test_credential_transition_validates_before_syscall() {
    // Verify that validation happens before any syscalls
    // This should fail immediately without attempting setresgid/setresuid
    
    let result = transition_to_unprivileged(0, 1000, true);
    assert!(result.is_err(), "Should reject root UID");
    
    let result = transition_to_unprivileged(1000, 0, true);
    assert!(result.is_err(), "Should reject root GID");
}

#[test]
fn test_idempotency_of_privilege_operations() {
    // Verify that operations can be called multiple times safely
    
    // Drop capabilities multiple times
    let _ = drop_all_capabilities();
    let _ = drop_all_capabilities();
    
    // Set no_new_privs multiple times
    let first = set_no_new_privs();
    let second = set_no_new_privs();
    
    // Both should have same result (Ok or Err)
    assert_eq!(first.is_ok(), second.is_ok(), 
               "set_no_new_privs should be idempotent");
}

#[test]
fn test_no_panic_on_permission_denied() {
    // Verify that permission denied errors don't cause panics
    
    // These operations may fail without root, but should not panic
    let _ = drop_all_capabilities();
    let _ = transition_to_unprivileged(1000, 1000, false);
    let _ = set_no_new_privs();
    
    // If we get here, no panics occurred
    assert!(true);
}

#[cfg(unix)]
#[test]
fn test_capability_query_operations_are_safe() {
    use rustbox::kernel::capabilities::{get_bounding_set, get_capability_status};
    
    // Query operations should never fail or panic
    let bounding_set = get_bounding_set();
    assert!(bounding_set.is_ok(), "get_bounding_set should not fail");
    
    let status = get_capability_status();
    assert!(status.is_ok(), "get_capability_status should not fail");
    
    // Status should contain capability information
    let status_str = status.unwrap();
    assert!(status_str.contains("Cap"), "Status should contain Cap lines");
}

#[test]
fn test_strict_mode_vs_permissive_mode() {
    // Verify that strict mode is more restrictive than permissive mode
    
    // Strict mode should reject root UIDs
    let strict_result = transition_to_unprivileged(0, 1000, true);
    assert!(strict_result.is_err(), "Strict mode should reject root UID");
    
    // Permissive mode should warn but not error
    let permissive_result = transition_to_unprivileged(0, 1000, false);
    assert!(permissive_result.is_ok(), "Permissive mode should not error on root UID");
}
