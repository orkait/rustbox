use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static SIGNAL_RECEIVED: AtomicU32 = AtomicU32::new(0);

pub fn request_shutdown(signal: i32) {
    SIGNAL_RECEIVED.store(signal as u32, Ordering::SeqCst);
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

pub fn received_signal() -> u32 {
    SIGNAL_RECEIVED.load(Ordering::SeqCst)
}
