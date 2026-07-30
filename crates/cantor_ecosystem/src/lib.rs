//! Deterministic, effect-free Cantor supervised ecosystem protocol.
//!
//! The base `cantor-supervised-mock-loop/0.1` profile supplies one commissioned
//! manager, one worker, one purpose-scoped Cantor participant, one deterministic
//! Observer review, and one immutable returned transcript. The optional
//! read-only live adapter binds that same logical cycle to a hash-pinned Codex
//! App Server process and exactly one stable Cantor MCP query. Neither profile
//! grants effects, persists runtime state, or implements multi-worker
//! orchestration.

pub mod adapter;
pub mod live_codex;
pub mod model;
pub mod phase3_evidence;
pub mod platform_preflight_forms;
pub mod review;
pub mod runtime;
pub mod topology_forms;
pub mod transcript;
pub mod workspace_admission;

pub use adapter::*;
pub use live_codex::*;
pub use model::*;
pub use phase3_evidence::*;
pub use platform_preflight_forms::*;
pub use review::*;
pub use runtime::*;
pub use topology_forms::*;
pub use transcript::*;
pub use workspace_admission::*;

/// Version of the bounded supervised mock-loop profile.
pub const MOCK_LOOP_PROFILE: &str = "cantor-supervised-mock-loop/0.1";
/// Version of a commission admitted by this profile.
pub const COMMISSION_PROFILE: &str = "cantor-commission/0.1";
/// Version of a work packet admitted by this profile.
pub const WORK_PACKET_PROFILE: &str = "cantor-work-packet/0.1";
/// Version of the shared ecosystem envelope.
pub const MESSAGE_PROFILE: &str = "cantor-ecosystem-message/0.1";
