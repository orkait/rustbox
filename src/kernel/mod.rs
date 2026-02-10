//! Thin wrappers around Linux kernel primitives.
//!
//! All `unsafe` code is concentrated here with explicit SAFETY comments.
//! Dependency direction: signal -> namespace -> capabilities -> credentials -> mount -> cgroup

pub mod capabilities;
pub mod credentials;
pub mod cgroup;
pub mod mount;
pub mod namespace;
pub mod signal;
