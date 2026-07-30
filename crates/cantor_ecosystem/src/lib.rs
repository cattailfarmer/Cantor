//! Deterministic, effect-free Cantor supervised ecosystem protocol.
//!
//! This crate implements only the `cantor-supervised-mock-loop/0.1` profile:
//! one commissioned manager, one mock Codex worker, one purpose-scoped Cantor
//! participant, one deterministic Observer review, and one immutable returned
//! transcript. It does not control live Codex threads, perform external
//! effects, persist runtime state, invoke models, or implement multi-worker
//! orchestration.

pub mod adapter;
pub mod model;
pub mod review;
pub mod runtime;
pub mod transcript;

pub use adapter::*;
pub use model::*;
pub use review::*;
pub use runtime::*;
pub use transcript::*;

/// Version of the bounded supervised mock-loop profile.
pub const MOCK_LOOP_PROFILE: &str = "cantor-supervised-mock-loop/0.1";
/// Version of a commission admitted by this profile.
pub const COMMISSION_PROFILE: &str = "cantor-commission/0.1";
/// Version of a work packet admitted by this profile.
pub const WORK_PACKET_PROFILE: &str = "cantor-work-packet/0.1";
/// Version of the shared ecosystem envelope.
pub const MESSAGE_PROFILE: &str = "cantor-ecosystem-message/0.1";
