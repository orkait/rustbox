use log::info;
use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal};
/// Async-safe signal handling for rustbox
/// Implements P0-SIG-001: Async-Safe Signal Path and Main-Loop Handling
/// Per plan.md Section 2: Non-Negotiable Fundamentals
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Global shutdown flag (async-safe atomic)
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Global signal received (async-safe atomic)
static SIGNAL_RECEIVED: AtomicU32 = AtomicU32::new(0);

/// Signal handler state
pub struct SignalHandler;

impl SignalHandler {
    /// Initialize signal handlers
    /// Must be called early in main() before any threads are spawned
    pub fn init() -> Result<Self, String> {
        // Install async-safe signal handlers
        Self::install_signal_handlers()?;

        Ok(Self)
    }

    /// Install signal handlers for SIGINT, SIGTERM, SIGHUP
    fn install_signal_handlers() -> Result<(), String> {
        // SIGINT (Ctrl+C)
        let sig_action = SigAction::new(
            SigHandler::Handler(Self::signal_handler),
            SaFlags::SA_RESTART,
            SigSet::empty(),
        );

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

    /// Async-safe signal handler
    /// Only performs atomic operations - no allocations, no locks, no I/O
    extern "C" fn signal_handler(signal: libc::c_int) {
        // Store signal number atomically
        SIGNAL_RECEIVED.store(signal as u32, Ordering::SeqCst);

        // Set shutdown flag atomically
        SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);

        // That's it - no other operations allowed in signal handler
        // Main loop will check these flags and perform cleanup
    }

    /// Check if shutdown was requested
    pub fn shutdown_requested(&self) -> bool {
        SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
    }

    /// Get signal that was received (0 if none)
    pub fn get_signal(&self) -> u32 {
        SIGNAL_RECEIVED.load(Ordering::SeqCst)
    }

    /// Reset shutdown flag (for testing)
    #[allow(dead_code)]
    pub fn reset(&self) {
        SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
        SIGNAL_RECEIVED.store(0, Ordering::SeqCst);
    }

    /// Wait for signal with timeout
    /// Returns true if signal received, false if timeout
    pub fn wait_for_signal(&self, timeout: std::time::Duration) -> bool {
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            if self.shutdown_requested() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        false
    }
}

/// Cleanup handler that runs on shutdown
/// This is called from main loop, not from signal handler
pub struct CleanupHandler {
    cleanup_fn: Box<dyn FnOnce() + Send>,
}

impl CleanupHandler {
    /// Create new cleanup handler
    pub fn new<F>(cleanup_fn: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self {
            cleanup_fn: Box::new(cleanup_fn),
        }
    }

    /// Run cleanup
    pub fn run(self) {
        (self.cleanup_fn)();
    }
}

/// Graceful shutdown coordinator
/// Manages cleanup on signal reception
pub struct ShutdownCoordinator {
    signal_handler: SignalHandler,
    cleanup_handlers: Vec<CleanupHandler>,
}

impl ShutdownCoordinator {
    /// Create new shutdown coordinator
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            signal_handler: SignalHandler::init()?,
            cleanup_handlers: Vec::new(),
        })
    }

    /// Register cleanup handler
    pub fn register_cleanup<F>(&mut self, cleanup_fn: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.cleanup_handlers.push(CleanupHandler::new(cleanup_fn));
    }

    /// Check if shutdown requested
    pub fn shutdown_requested(&self) -> bool {
        self.signal_handler.shutdown_requested()
    }

    /// Get received signal
    pub fn get_signal(&self) -> u32 {
        self.signal_handler.get_signal()
    }

    /// Run all cleanup handlers
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

/// Main loop helper that checks for signals
/// Returns true if should continue, false if should shutdown
pub fn should_continue() -> bool {
    !SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

/// Block signals for critical section
/// Returns guard that will unblock on drop
pub struct SignalBlockGuard {
    _marker: (),
}

impl SignalBlockGuard {
    /// Block common signals (SIGINT, SIGTERM, SIGHUP)
    pub fn block() -> Result<Self, String> {
        let mut mask = SigSet::empty();
        mask.add(Signal::SIGINT);
        mask.add(Signal::SIGTERM);
        mask.add(Signal::SIGHUP);

        // Block the signals
        signal::sigprocmask(signal::SigmaskHow::SIG_BLOCK, Some(&mask), None)
            .map_err(|e| format!("Failed to block signals: {}", e))?;

        Ok(Self { _marker: () })
    }
}

impl Drop for SignalBlockGuard {
    fn drop(&mut self) {
        // Unblock the signals
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

        // Simulate signal
        SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
        assert!(handler.shutdown_requested());

        // Reset for other tests
        SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
    }

    #[test]
    fn test_signal_block() {
        let guard = SignalBlockGuard::block();
        assert!(guard.is_ok());
        // Guard will unblock on drop
    }

    #[test]
    fn test_shutdown_coordinator() {
        let coordinator = ShutdownCoordinator::new().unwrap();
        assert!(!coordinator.shutdown_requested());
        // Just verify creation works - actual cleanup testing requires integration tests
    }
}
