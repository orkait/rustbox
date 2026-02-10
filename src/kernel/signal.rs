//! Async-safe signal handling for process lifecycle management.

use log::info;
use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static SIGNAL_RECEIVED: AtomicU32 = AtomicU32::new(0);
const SIGNAL_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Async-signal-safe shutdown trigger. Safe to call from signal handlers.
pub fn request_shutdown(signal: i32) {
    SIGNAL_RECEIVED.store(signal as u32, Ordering::SeqCst);
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

pub fn received_signal() -> u32 {
    SIGNAL_RECEIVED.load(Ordering::SeqCst)
}

pub fn should_continue() -> bool {
    !SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

pub struct SignalHandler;

impl SignalHandler {
    /// Must be called early in main() before any threads are spawned.
    pub fn init() -> Result<Self, String> {
        Self::install_signal_handlers()?;
        Ok(Self)
    }

    fn install_signal_handlers() -> Result<(), String> {
        let sig_action = SigAction::new(
            SigHandler::Handler(Self::signal_handler),
            SaFlags::SA_RESTART,
            SigSet::empty(),
        );

        // SAFETY: The handler only performs atomic stores, which is async-signal-safe.
        unsafe {
            signal::sigaction(Signal::SIGINT, &sig_action)
                .map_err(|e| format!("Failed to install SIGINT handler: {}", e))?;
            signal::sigaction(Signal::SIGTERM, &sig_action)
                .map_err(|e| format!("Failed to install SIGTERM handler: {}", e))?;
            signal::sigaction(Signal::SIGHUP, &sig_action)
                .map_err(|e| format!("Failed to install SIGHUP handler: {}", e))?;
        }

        info!("Signal handlers installed (SIGINT, SIGTERM, SIGHUP)");
        Ok(())
    }

    /// Async-signal-safe: only atomic operations, no allocations/locks/I/O.
    extern "C" fn signal_handler(signal: libc::c_int) {
        request_shutdown(signal);
    }

    pub fn shutdown_requested(&self) -> bool {
        SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
    }

    pub fn get_signal(&self) -> u32 {
        SIGNAL_RECEIVED.load(Ordering::SeqCst)
    }

    #[allow(dead_code)]
    pub fn reset(&self) {
        SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
        SIGNAL_RECEIVED.store(0, Ordering::SeqCst);
    }

    pub fn wait_for_signal(&self, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if self.shutdown_requested() {
                return true;
            }
            std::thread::sleep(SIGNAL_POLL_INTERVAL);
        }
        false
    }
}

/// Cleanup handler run from main loop (never from signal handler).
pub struct CleanupHandler {
    cleanup_fn: Box<dyn FnOnce() + Send>,
}

impl CleanupHandler {
    pub fn new<F>(cleanup_fn: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self {
            cleanup_fn: Box::new(cleanup_fn),
        }
    }

    pub fn run(self) {
        (self.cleanup_fn)();
    }
}

pub struct ShutdownCoordinator {
    signal_handler: SignalHandler,
    cleanup_handlers: Vec<CleanupHandler>,
}

impl ShutdownCoordinator {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            signal_handler: SignalHandler::init()?,
            cleanup_handlers: Vec::new(),
        })
    }

    pub fn register_cleanup<F>(&mut self, cleanup_fn: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.cleanup_handlers.push(CleanupHandler::new(cleanup_fn));
    }

    pub fn shutdown_requested(&self) -> bool {
        self.signal_handler.shutdown_requested()
    }

    pub fn get_signal(&self) -> u32 {
        self.signal_handler.get_signal()
    }

    pub fn run_cleanup(self) {
        let signal = self.get_signal();
        if signal != 0 {
            info!("Running cleanup handlers after signal {}", signal);
        } else {
            info!("Running cleanup handlers");
        }

        for handler in self.cleanup_handlers {
            handler.run();
        }

        info!("Cleanup complete");
    }
}

/// RAII guard that blocks SIGINT/SIGTERM/SIGHUP for a critical section.
pub struct SignalBlockGuard {
    _marker: (),
}

impl SignalBlockGuard {
    pub fn block() -> Result<Self, String> {
        let mut mask = SigSet::empty();
        mask.add(Signal::SIGINT);
        mask.add(Signal::SIGTERM);
        mask.add(Signal::SIGHUP);

        signal::sigprocmask(signal::SigmaskHow::SIG_BLOCK, Some(&mask), None)
            .map_err(|e| format!("Failed to block signals: {}", e))?;

        Ok(Self { _marker: () })
    }
}

impl Drop for SignalBlockGuard {
    fn drop(&mut self) {
        let mut mask = SigSet::empty();
        mask.add(Signal::SIGINT);
        mask.add(Signal::SIGTERM);
        mask.add(Signal::SIGHUP);
        let _ = signal::sigprocmask(signal::SigmaskHow::SIG_UNBLOCK, Some(&mask), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_handler_init() {
        let handler = SignalHandler::init();
        assert!(handler.is_ok());
    }

    #[test]
    fn test_shutdown_flag() {
        let handler = SignalHandler::init().unwrap();
        assert!(!handler.shutdown_requested());

        SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
        assert!(handler.shutdown_requested());

        SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
    }

    #[test]
    fn test_signal_block() {
        let guard = SignalBlockGuard::block();
        assert!(guard.is_ok());
    }

    #[test]
    fn test_shutdown_coordinator() {
        let coordinator = ShutdownCoordinator::new().unwrap();
        assert!(!coordinator.shutdown_requested());
    }
}
