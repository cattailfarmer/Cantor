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
pub mod b1_operator_policy_governance_bundle_verification;
pub mod b1_operator_policy_governance_bundle_verification_evidence;
pub mod b1_public_verifying_key_custody_attestation_verification;
pub mod b1_public_verifying_key_custody_attestation_verification_evidence;
pub mod b1_public_verifying_key_revocation_snapshot_verification;
pub mod b1_public_verifying_key_revocation_snapshot_verification_evidence;
pub mod b1_trusted_time_witness_receipt_verification;
pub mod b1_trusted_time_witness_receipt_verification_evidence;
pub mod live_codex;
pub mod model;
pub mod phase3_evidence;
pub mod platform_preflight_forms;
pub mod provider_free_self_work_composition;
pub mod review;
pub mod runtime;
pub mod self_work_update_broker_b1;
pub mod self_work_update_broker_b1_cdrive_preflight;
pub mod self_work_update_broker_b1_cdrive_preflight_producer_plan;
pub mod self_work_update_broker_b1_cdrive_preparation_commission_admission;
pub mod self_work_update_broker_b1_cdrive_production_broker;
pub mod self_work_update_broker_b1_cdrive_production_broker_evidence;
pub mod self_work_update_broker_b1_cdrive_production_preparation_commission_proposal;
pub mod self_work_update_broker_b1_cdrive_production_preparation_commission_proposal_evidence;
pub mod self_work_update_broker_b1_cdrive_production_preparation_operator_authority_ceremony_plan;
pub mod self_work_update_broker_b1_cdrive_production_preparation_operator_authority_ceremony_plan_evidence;
pub mod self_work_update_broker_b1_cdrive_production_preparation_operator_decision_verification;
pub mod self_work_update_broker_b1_cdrive_production_preparation_operator_decision_verification_evidence;
pub mod self_work_update_broker_b1_cdrive_production_preparation_plan;
pub mod self_work_update_broker_b1_cdrive_production_preparation_plan_evidence;
#[cfg(windows)]
mod self_work_update_broker_b1_cdrive_windows_containment;
pub mod self_work_update_broker_b1_cdrive_worktree_preparation;
pub mod self_work_update_broker_b1_operator_authority_packet_readiness;
pub mod self_work_update_broker_b1_operator_authority_packet_readiness_evidence;
pub mod self_work_update_broker_b1_permission_profile;
pub mod sjs_commit_envelope_journal;
pub mod sjs_commit_placement_acquisition;
pub mod sjs_compiled_lookahead_repository_slice_observation;
pub mod sjs_compiled_lookahead_repository_stitch_projection;
pub mod sjs_repository_graph;
pub mod staged_diff_acquisition;
pub mod succeeding_sop_fixture_persistence;
pub mod succeeding_sop_fixture_rollback;
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
pub use self_work_update_broker_b1_cdrive_preflight::*;
pub use self_work_update_broker_b1_cdrive_preflight_producer_plan::*;
pub use self_work_update_broker_b1_cdrive_preparation_commission_admission::*;
pub use self_work_update_broker_b1_cdrive_production_broker::*;
pub use self_work_update_broker_b1_cdrive_production_broker_evidence::*;
pub use self_work_update_broker_b1_cdrive_production_preparation_commission_proposal::*;
pub use self_work_update_broker_b1_cdrive_production_preparation_commission_proposal_evidence::*;
pub use self_work_update_broker_b1_cdrive_production_preparation_operator_decision_verification::*;
pub use self_work_update_broker_b1_cdrive_production_preparation_operator_decision_verification_evidence::*;
pub use self_work_update_broker_b1_cdrive_production_preparation_operator_authority_ceremony_plan::*;
pub use self_work_update_broker_b1_cdrive_production_preparation_operator_authority_ceremony_plan_evidence::*;
pub use self_work_update_broker_b1_operator_authority_packet_readiness::*;
pub use self_work_update_broker_b1_operator_authority_packet_readiness_evidence::*;
pub use b1_operator_policy_governance_bundle_verification::*;
pub use b1_operator_policy_governance_bundle_verification_evidence::*;
pub use b1_public_verifying_key_custody_attestation_verification::*;
pub use b1_public_verifying_key_custody_attestation_verification_evidence::*;
pub use b1_public_verifying_key_revocation_snapshot_verification::*;
pub use b1_public_verifying_key_revocation_snapshot_verification_evidence::*;
pub use b1_trusted_time_witness_receipt_verification::*;
pub use b1_trusted_time_witness_receipt_verification_evidence::*;
pub use self_work_update_broker_b1_cdrive_production_preparation_plan::*;
pub use self_work_update_broker_b1_cdrive_production_preparation_plan_evidence::*;
pub use self_work_update_broker_b1_cdrive_worktree_preparation::*;
pub use self_work_update_broker_b1_permission_profile::*;
pub use succeeding_sop_fixture_persistence::*;
pub use succeeding_sop_fixture_rollback::*;
pub use topology_forms::*;
pub use transcript::*;
pub use windows_entry_policy::*;
pub use windows_stream_info_parser::*;
pub use windows_supplied_entry_observation::*;
pub use workspace_admission::*;

// Reuse the production-broker integration contract inside the library harness.
// Windows Application Control can independently refuse a freshly linked
// integration-test executable; compiling the same assertions into the ordinary
// library harness preserves exact semantic coverage without changing policy.
#[cfg(test)]
extern crate self as cantor_ecosystem;
#[cfg(test)]
#[path = "../tests/self_work_update_broker_b1_cdrive_production_broker.rs"]
mod self_work_update_broker_b1_cdrive_production_broker_contract_tests;

/// Version of the bounded supervised mock-loop profile.
pub const MOCK_LOOP_PROFILE: &str = "cantor-supervised-mock-loop/0.1";
/// Version of a commission admitted by this profile.
pub const COMMISSION_PROFILE: &str = "cantor-commission/0.1";
/// Version of a work packet admitted by this profile.
pub const WORK_PACKET_PROFILE: &str = "cantor-work-packet/0.1";
/// Version of the shared ecosystem envelope.
pub const MESSAGE_PROFILE: &str = "cantor-ecosystem-message/0.1";
