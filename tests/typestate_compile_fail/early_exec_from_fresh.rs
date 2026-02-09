/// This test should FAIL to compile
/// Attempting to exec from FreshChild state should be impossible

use rustbox::preexec::{Sandbox, FreshChild};

fn main() {
    let sandbox = Sandbox::<FreshChild>::new("test".to_string(), false);
    
    // This should fail: FreshChild doesn't have exec_payload method
    sandbox.exec_payload(&["echo".to_string()]);
}
