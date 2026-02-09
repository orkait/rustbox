//! Policy modules
//!
//! Specific policy enforcement for /proc, /sys, and user namespaces.

pub mod proc_sys;
pub mod userns;

// Re-export commonly used items
pub use proc_sys::*;
pub use userns::*;
