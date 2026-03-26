use rustbox::exec::preexec::{CgroupAttached, Sandbox};

fn main() {
    let sandbox: Sandbox<CgroupAttached> = todo!();
    let _ = sandbox.drop_credentials(None, None);
}
