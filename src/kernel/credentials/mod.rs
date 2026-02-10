//! UID/GID transitions for privilege dropping.
//!
//! CRITICAL: setresgid MUST be called BEFORE setresuid.

mod transition;
mod validation;

pub use transition::transition_to_unprivileged;
pub use validation::validate_ids;
