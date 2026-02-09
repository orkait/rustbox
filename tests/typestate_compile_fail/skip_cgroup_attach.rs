/// This test should FAIL to compile
/// Attempting to skip cgroup attach and go directly to credential drop

use rustbox::preexec::{Sandbox, FreshChild};

fn main() {
    let sandbox = Sandbox::<FreshChild>::new("test".to_string(), false);
    
    let sandbox = sandbox.setup_namespaces(false, false, false, false)
        .expect("namespace setup failed");
    
    let sandbox = sandbox.harden_mount_propagation()
        .expect("mount hardening failed");
    
    // This should fail: MountsPrivate doesn't have drop_credentials method
    // Only CgroupAttached has this method
    sandbox.drop_credentials(None, None);
}
