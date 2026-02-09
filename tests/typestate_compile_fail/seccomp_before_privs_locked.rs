/// This test should FAIL to compile
/// Attempting to enable seccomp before privileges are locked

use rustbox::preexec::{Sandbox, FreshChild};

fn main() {
    let sandbox = Sandbox::<FreshChild>::new("test".to_string(), false);
    
    let sandbox = sandbox.setup_namespaces(false, false, false, false)
        .expect("namespace setup failed");
    
    let sandbox = sandbox.harden_mount_propagation()
        .expect("mount hardening failed");
    
    let sandbox = sandbox.attach_to_cgroup(None)
        .expect("cgroup attach failed");
    
    let sandbox = sandbox.drop_credentials(None, None)
        .expect("credential drop failed");
    
    // This should fail: CredsDropped doesn't have enable_seccomp method
    // Only PrivsLocked has this method
    let seccomp_config = rustbox::seccomp::SyscallFilterConfig::disabled();
    sandbox.enable_seccomp(&seccomp_config);
}
