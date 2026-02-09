//! Cgroup resource governance
//!
//! Provides abstraction over cgroup v1 and v2 backends with automatic selection.

pub mod backend;
pub mod v1;
pub mod v2;

// Re-export commonly used items
pub use backend::CgroupBackend;
pub use v1::Cgroup;
pub use v2::CgroupV2;
