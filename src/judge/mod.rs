//! Judge adapters.
//!
//! Core runtime stays language-agnostic. Adapters define compile/run commands
//! and envelope profiles for each language.

pub mod adapter;
pub mod languages;
pub mod registry;

