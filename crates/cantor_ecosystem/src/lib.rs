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
pub mod provider_free_self_work_composition;
pub mod review;
pub mod runtime;
pub mod self_work_update_broker_b1;
pub mod sjs_commit_envelope_journal;
pub mod sjs_commit_placement_acquisition;
pub mod sjs_repository_graph;
pub mod staged_diff_acquisition;
pub mod topology_forms;
pub mod transcript;
pub mod windows_entry_policy;
pub mod windows_stream_info_parser;
pub mod windows_supplied_content_digest;
pub mod windows_supplied_directory_topology_projection;
pub mod windows_supplied_entry_observation;
pub mod windows_supplied_entry_stability;
pub mod windows_supplied_ordered_topology_inventory_digest;
pub mod windows_supplied_ordered_topology_inventory_digest_reconciliation;
pub mod windows_supplied_regular_file_topology_projection;
pub mod windows_supplied_root_topology_projection;
pub mod windows_supplied_topology_inventory_assembly;
pub mod windows_topology_acquisition_lineage;
pub mod workspace_admission;

pub use adapter::*;
pub use live_codex::*;
pub use model::*;
pub use phase3_evidence::*;
pub use platform_preflight_forms::*;
pub use provider_free_self_work_composition::*;
pub use review::*;
pub use runtime::*;
pub use self_work_update_broker_b1::*;
pub use topology_forms::*;
pub use transcript::*;
pub use windows_entry_policy::*;
pub use windows_stream_info_parser::*;
pub use windows_supplied_entry_observation::*;
pub use workspace_admission::*;

/// Version of the bounded supervised mock-loop profile.
pub const MOCK_LOOP_PROFILE: &str = "cantor-supervised-mock-loop/0.1";
/// Version of a commission admitted by this profile.
pub const COMMISSION_PROFILE: &str = "cantor-commission/0.1";
/// Version of a work packet admitted by this profile.
pub const WORK_PACKET_PROFILE: &str = "cantor-work-packet/0.1";
/// Version of the shared ecosystem envelope.
pub const MESSAGE_PROFILE: &str = "cantor-ecosystem-message/0.1";
