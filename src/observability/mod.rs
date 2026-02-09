//! Observability
//!
//! Structured audit events and metrics for operational visibility.

pub mod audit;
pub mod metrics;
// Deleted: health (static mut UB, not needed for CLI tool)
// Deleted: ops (runtime checks not needed, config validation at parse time is sufficient)
// pub mod health;
// pub mod ops;
