/// This test should FAIL to compile
/// Attempting to reuse a state after it has been consumed

use rustbox::preexec::{Sandbox, FreshChild};

fn main() {
    let sandbox = Sandbox::<FreshChild>::new("test".to_string(), false);
    
    // First transition consumes sandbox
    let sandbox2 = sandbox.setup_namespaces(false, false, false, false)
        .expect("namespace setup failed");
    
    // This should fail: sandbox was moved and can no longer be used
    sandbox.setup_namespaces(false, false, false, false);
}
