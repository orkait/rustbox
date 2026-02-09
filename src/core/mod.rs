//! Language-agnostic sandbox core.
//!
//! Core owns process model, lifecycle, namespace/cgroup orchestration,
//! and evidence collection. Language-specific compile/run logic lives in
//! judge adapters.

pub mod proxy;
pub mod supervisor;
pub mod types;
