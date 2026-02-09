/// This test should FAIL to compile
/// Attempting to call seccomp twice (both without_seccomp and enable_seccomp)

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
    
    let sandbox = sandbox.lock_privileges()
        .expect("privilege lock failed");
    
    // First seccomp call
    let sandbox = sandbox.without_seccomp();
    
    // This should fail: ExecReady doesn't have enable_seccomp or without_seccomp
    // Once you reach ExecReady, you can only exec
    let seccomp_config = rustbox::seccomp::SyscallFilterConfig::disabled();
    sandbox.enable_seccomp(&seccomp_config);
}
