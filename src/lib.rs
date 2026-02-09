//! rustbox: A process isolation and resource control system
//! Inspired by IOI Isolate, focused on secure process execution with kernel-enforced boundaries
//!
//! # Architecture
//!
//! This crate is organized by Linux kernel primitive families:
//!
//! ## Kernel Primitives ([`kernel`])
//! - [`kernel::namespace`]: Linux namespace isolation (PID, mount, network, user)
//! - [`kernel::cgroup`]: Resource governance (v1/v2 backends, limits, accounting)
//! - [`kernel::capabilities`]: Capability management and privilege dropping
//! - [`kernel::seccomp`]: Syscall filtering (optional, explicit opt-in)
//! - [`kernel::mount`]: Filesystem isolation and mount management
//! - [`kernel::signal`]: Signal handling and lifecycle contracts
//!
//! ## Execution Control ([`exec`])
//! - [`exec::supervisor`]: Three-process lifecycle model (supervisor/proxy/payload)
//! - [`exec::executor`]: Execution orchestration and pre-exec chain
//! - [`exec::preexec`]: Type-state enforced pre-exec ordering
//!
//! ## Evidence & Verdict ([`verdict`])
//! - [`verdict::verdict`]: Evidence-backed verdict classification
//! - [`verdict::envelope`]: Execution envelope identity (SHA256 fingerprint)
//! - [`verdict::timeout`]: Timeout accounting and CPU/wall divergence
//! - [`verdict::abuse`]: Deterministic exploit pattern detection
//!
//! ## Safety & Cleanup ([`safety`])
//! - [`safety::cleanup`]: Idempotent cleanup with baseline equivalence
//! - [`safety::lock_manager`]: State integrity with stable lock inodes
//! - [`safety::workspace`]: Run-scoped artifact isolation
//!
//! ## Observability ([`observability`])
//! - [`observability::audit`]: Structured audit events
//! - [`observability::metrics`]: Prometheus metrics export
//! // Deleted: health, ops (not needed for CLI tool)
//!
//! ## Configuration & Policy ([`config`])
//! - [`config::config`]: Configuration loading and validation
//! - [`config::validator`]: Config-to-enforcement matrix
//! - [`config::types`]: Shared type definitions and closed enums
//! - [`config::presets`]: Versioned language runtime envelopes
//! - [`config::policy`]: Policy enforcement modules
//!
//! ## Utilities ([`utils`])
//! - [`utils::fd_closure`]: FD closure hardening
//! - [`utils::env_hygiene`]: Environment and permission hygiene
//! - [`utils::output`]: Bounded output collection
//! - [`utils::json_schema`]: JSON schema validation
//!
//! ## Testing Infrastructure ([`testing`])
//! - [`testing::mount_invariance`]: Mount invariance proof framework
//! - [`testing::race_proof`]: Race condition proof framework
//!
//! # Design Principles
//!
//! Rustbox follows kernel-first engineering principles:
//!
//! 1. **Invariants before code** - Define guarantees, then implement
//! 2. **Kernel as truth** - Evidence from `/proc`, cgroups, wait status
//! 3. **Safety without Drop** - Cleanup is hygiene, not the safety barrier
//! 4. **Types prevent errors** - Illegal states are unrepresentable
//! 5. **Minimal unsafe** - Thin wrappers with explicit preconditions
//! 6. **Evidence-backed claims** - Never guess verdicts from symptoms

// Kernel Primitives
pub mod kernel;

// Execution Control
pub mod exec;

// Language-agnostic sandbox runtime core
pub mod core;

// Judge adapters (language-specific compile/run envelopes)
pub mod judge;

// Evidence & Verdict
pub mod verdict;

// Safety & Cleanup
pub mod safety;

// Observability
pub mod observability;

// Configuration & Policy
pub mod config;

// Utilities
pub mod utils;

// Testing Infrastructure
pub mod testing;

// CLI entrypoint wiring shared by isolate/judge/rustbox binaries.
pub mod cli;

// Legacy/Compatibility (to be refactored)
pub mod legacy;

// Re-export commonly used types for convenience
pub use config::types::*;

// Backward-compatible root aliases for existing tests/docs.
pub mod types {
    pub use crate::config::types::*;
}
pub use exec::preexec;
pub use kernel::seccomp;
pub use observability::audit as security_logging;
pub use safety::cleanup;
pub use testing::mount_invariance;
pub use testing::race_proof;
// Deferred to post-V1: envelope
// pub use verdict::envelope;
