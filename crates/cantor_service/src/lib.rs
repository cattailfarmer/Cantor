//! Bounded local resident service for Cantor's deterministic semantic core.
//!
//! This crate owns transport and operator-controlled generation lifecycle. All
//! semantic query, inspection, trust, and proof behavior remains in
//! `cantor_core`.

pub mod artifacts;
pub mod model;
pub mod runtime;
pub mod transport;

pub use artifacts::*;
pub use model::*;
pub use runtime::*;
pub use transport::*;
