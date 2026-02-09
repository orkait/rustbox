/// This test should FAIL to compile
/// Attempting to exec from NamespacesReady state should be impossible

use rustbox::preexec::{Sandbox, FreshChild};

fn main() {
    let sandbox = Sandbox::<FreshChild>::new("test".to_string(), false);
    
    let sandbox = sandbox.setup_namespaces(false, false, false, false)
        .expect("namespace setup failed");
    
    // This should fail: NamespacesReady doesn't have exec_payload method
    sandbox.exec_payload(&["echo".to_string()]);
}
