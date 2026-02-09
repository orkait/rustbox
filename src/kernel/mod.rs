//! Linux kernel primitive wrappers
//!
//! This module contains thin wrappers around Linux kernel interfaces.
//! All `unsafe` code should be concentrated here with explicit safety preconditions.

pub mod capabilities;
pub mod cgroup;
pub mod mount;
pub mod namespace;
pub mod signal;
