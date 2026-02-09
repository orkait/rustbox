/// This test should FAIL to compile
/// Attempting to skip namespace setup and go directly to mount hardening

use rustbox::preexec::{Sandbox, FreshChild};

fn main() {
    let sandbox = Sandbox::<FreshChild>::new("test".to_string(), false);
    
    // This should fail: FreshChild doesn't have harden_mount_propagation method
    // Only NamespacesReady has this method
    sandbox.harden_mount_propagation();
}
