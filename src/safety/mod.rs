//! Safety and cleanup
//!
//! Ensures host-clean baseline equivalence through idempotent cleanup.

pub mod cleanup;
pub mod lock_manager;
pub mod safe_cleanup;
pub mod workspace;
