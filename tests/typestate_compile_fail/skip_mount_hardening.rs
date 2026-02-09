/// This test should FAIL to compile
/// Attempting to skip mount hardening and go directly to cgroup attach

use rustbox::preexec::{Sandbox, FreshChild};

fn main() {
    let sandbox = Sandbox::<FreshChild>::new("test".to_string(), false);
    
    let sandbox = sandbox.setup_namespaces(false, false, false, false)
        .expect("namespace setup failed");
    
    // This should fail: NamespacesReady doesn't have attach_to_cgroup method
    // Only MountsPrivate has this method
    sandbox.attach_to_cgroup(None);
}
