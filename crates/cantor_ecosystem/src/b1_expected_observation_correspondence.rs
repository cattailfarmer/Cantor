//! Partial A6 implementation: typed forms and comparison-only computation.
//!
//! This module does not yet verify a complete A6 request or issue an A6 receipt.
//! The comparison helper checks supplied observation structure and a supplied
//! preparation plan. A5 replay, signed proposal binding, raw descriptor admission,
//! canonical self-digests and independent evidence remain required outer gates.
//! A matching comparison is not a live observation, freshness or permission.
use crate::{
    B1CDriveProductionPreparationPlan, B1CDriveProductionPreparationPlanRequest,
    B1CDriveProductionPreparationRoleKind, B1CDriveProductionPreparationUpstreamIdentity,
    B1OaprRequest, KcvInputClass, OdcvVerificationReceipt, TwvEffectAccount,
    validate_b1_cdrive_production_preparation_plan,
};
use cantor_core::ContentDigest;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt};

pub const EOCV_BUNDLE_PROFILE: &str = "cantor-b1-expected-observation-bundle/0.1";
pub const EOCV_REQUEST_PROFILE: &str = "cantor-b1-expected-observation-request/0.1";
pub const EOCV_RECEIPT_PROFILE: &str = "cantor-b1-expected-observation-receipt/0.1";
pub const EOCV_EVIDENCE_PROFILE: &str = "cantor-b1-expected-observation-evidence/0.1";
pub const EOCV_SOURCE_SNAPSHOT_UUID: &str = "d10dd69e-34d1-43db-ab46-109a11cc80e0";
pub const EOCV_CANONICAL_UUID: &str = "a992244a-31b1-4d0a-ad9e-39a1cc667c99";
pub const EOCV_SIGNATURE_UUID: &str = "a4448ba3-5cc5-473f-a039-84b5347518ae";
pub const EOCV_SOURCE_CUSTODY_COMMIT: &str = "4f1417d111911f0fd27437f13b480157332442b2";
pub const EOCV_FORMATION_COMMIT: &str = "6d3dadd8cde9a91e51f6a9d0d398fbc22f8eb7f4";
pub const EOCV_FORMATION_BOOKEND_COMMIT: &str = "9e145958dc2d1ce3ac70d5dc0825edf616f8ca45";
pub const EOCV_A5_IMPLEMENTATION_COMMIT: &str = "9b3dd715439c26aa34181dace0e525681a1f29b9";
pub const EOCV_A5_BOOKEND_COMMIT: &str = "f72237acd50fdc296b7e47825a84200528f6c850";
pub const EOCV_A5_PROOF_UUID: &str = "498a8437-f165-4b57-ad07-b25f1c8c25ec";
pub const EOCV_PLAN_IMPLEMENTATION_COMMIT: &str = "2ae87673cfd343cc7a4685a5d0ebbdfc37256ea3";
pub const EOCV_PLAN_BOOKEND_COMMIT: &str = "1b70fbd46a3bf6c1970d590ec6ec02ddc84d2cde";
pub const EOCV_PLAN_PROOF_UUID: &str = "eef4785a-3020-4cb5-82c3-e32b7a84882a";
pub const EOCV_MAX_FORM_BYTES: usize = 1_048_576;
pub const EOCV_MAX_EVIDENCE_BYTES: u64 = 16_777_216;
pub const EOCV_MAX_EVIDENCE_REFERENCES: usize = 48;
pub const EOCV_MATCHED_STATUS: &str =
    "supplied_observation_expectations_matched_freshness_and_execution_unresolved";
pub const EOCV_MISMATCHED_STATUS: &str =
    "supplied_observation_expectations_mismatched_execution_unresolved";
pub const EOCV_AUTHORITY: &str = "supplied_observation_correspondence_only";
const MAX_TEXT_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EocvJunctionKind {
    Junction,
    Missing,
    Other,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EocvPresenceAssertion {
    Absent,
    Present,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EocvMismatchReason {
    CarrierCommitMismatch,
    BranchMismatch,
    RemoteMismatch,
    ProjectMismatch,
    ObservationTimeMismatch,
    CapacityBelowFloor,
    BuildJunctionMismatch,
    UpstreamIdentityMismatch,
    RoleNotAbsent,
    ReservedRefNotAbsent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EocvObservationBundle {
    pub profile: String,
    pub bundle_uuid: String,
    pub a5_receipt_sha256: ContentDigest,
    pub expected_carrier_commit: String,
    pub observed_carrier_commit: String,
    pub observed_branch: String,
    pub observed_remote: String,
    pub observed_project: String,
    pub observed_unix_ms: u64,
    pub observed_cdrive_free_bytes: u64,
    pub build_junctions: Vec<EocvJunctionObservation>,
    pub upstream_identities: Vec<B1CDriveProductionPreparationUpstreamIdentity>,
    pub role_observations: Vec<EocvRoleObservation>,
    pub reserved_ref_observation: EocvReservedRefObservation,
    pub input_class: KcvInputClass,
    pub evidence_references: Vec<String>,
    pub bundle_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EocvVerificationRequest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_custody_commit: String,
    pub formation_commit: String,
    pub formation_bookend_commit: String,
    pub a5_implementation_commit: String,
    pub a5_bookend_commit: String,
    pub a5_proof_uuid: String,
    pub plan_implementation_commit: String,
    pub plan_bookend_commit: String,
    pub plan_proof_uuid: String,
    pub a5_verification_request_sha256: ContentDigest,
    pub a5_receipt_sha256: ContentDigest,
    pub preparation_plan_request_raw_sha256: ContentDigest,
    pub preparation_plan_request_sha256: ContentDigest,
    pub preparation_plan_raw_sha256: ContentDigest,
    pub preparation_plan_sha256: ContentDigest,
    pub authority_packet_request: B1OaprRequest,
    pub authority_packet_request_sha256: ContentDigest,
    pub authority_packet_sha256: ContentDigest,
    pub a6_candidate_uuid: String,
    pub a6_descriptor_sha256: ContentDigest,
    pub observation_bundle_bytes: u64,
    pub observation_bundle_raw_sha256: ContentDigest,
    pub expected_bundle_uuid: String,
    pub expected_carrier_commit: String,
    pub input_class: KcvInputClass,
    pub evidence_references: Vec<String>,
    pub maximum_attempts: u8,
    pub automatic_retry_count: u8,
    pub automatic_cleanup_count: u8,
    pub request_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EocvVerificationReceipt {
    pub profile: String,
    pub status: String,
    pub authority: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_custody_commit: String,
    pub formation_commit: String,
    pub formation_bookend_commit: String,
    pub a5_implementation_commit: String,
    pub a5_bookend_commit: String,
    pub a5_proof_uuid: String,
    pub plan_implementation_commit: String,
    pub plan_bookend_commit: String,
    pub plan_proof_uuid: String,
    pub request_sha256: ContentDigest,
    pub a5_verification_request_sha256: ContentDigest,
    pub a5_receipt_sha256: ContentDigest,
    pub a5_receipt: OdcvVerificationReceipt,
    pub preparation_plan_request_raw_sha256: ContentDigest,
    pub preparation_plan_request_sha256: ContentDigest,
    pub preparation_plan_raw_sha256: ContentDigest,
    pub preparation_plan_sha256: ContentDigest,
    pub proposal_sha256: ContentDigest,
    pub authority_packet_request_sha256: ContentDigest,
    pub authority_packet_sha256: ContentDigest,
    pub a6_candidate_uuid: String,
    pub a6_descriptor_sha256: ContentDigest,
    pub observation_bundle_bytes: u64,
    pub observation_bundle_raw_sha256: ContentDigest,
    pub observation_bundle_sha256: ContentDigest,
    pub bundle_uuid: String,
    pub expected_carrier_commit: String,
    pub observed_carrier_commit: String,
    pub legacy_decision_expected_current_commit: String,
    pub preparation_plan_expected_current_commit: String,
    pub observed_unix_ms: u64,
    pub a4_observed_unix_ms: u64,
    pub observed_cdrive_free_bytes: u64,
    pub minimum_cdrive_free_bytes: u64,
    pub comparison_account: EocvComparisonAccount,
    pub input_class: KcvInputClass,
    pub fixture_only: bool,
    pub maximum_attempts: u8,
    pub automatic_retry_count: u8,
    pub automatic_cleanup_count: u8,
    pub a5_correspondence_receipt_verified: bool,
    pub preparation_plan_replayed: bool,
    pub proposal_plan_correspondence_verified: bool,
    pub packet_replayed: bool,
    pub descriptor_correspondence_verified: bool,
    pub observation_bundle_bytes_matched: bool,
    pub comparison_reconstructed: bool,
    pub production_authority_claimed: bool,
    pub fresh_observation_proved: bool,
    pub observation_source_identity_proved: bool,
    pub observation_source_completeness_proved: bool,
    pub observation_freshness_proved: bool,
    pub atomic_observation_proved: bool,
    pub decision_signature_binds_a6_observation: bool,
    pub expected_carrier_authority_proved: bool,
    pub live_authorization_admitted: bool,
    pub private_execution_permit_present: bool,
    pub production_broker_projection_present: bool,
    pub physical_preparation_authorized: bool,
    pub ready_for_physical_execution: bool,
    pub execution_authorized: bool,
    pub effect_account: TwvEffectAccount,
    pub receipt_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EocvJunctionObservation {
    pub source: String,
    pub kind: EocvJunctionKind,
    pub target: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EocvRoleObservation {
    pub kind: B1CDriveProductionPreparationRoleKind,
    pub path: String,
    pub state: EocvPresenceAssertion,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EocvReservedRefObservation {
    pub reference: String,
    pub state: EocvPresenceAssertion,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EocvComparisonAccount {
    pub carrier_commit_matches: bool,
    pub branch_matches: bool,
    pub remote_matches: bool,
    pub project_matches: bool,
    pub observation_time_matches_a4: bool,
    pub capacity_meets_minimum: bool,
    pub build_junctions_match: bool,
    pub upstream_identities_match: bool,
    pub all_roles_absent_asserted: bool,
    pub reserved_ref_absent_asserted: bool,
    pub mismatch_reasons: Vec<EocvMismatchReason>,
    pub all_expectations_match: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EocvEvidenceArtifact {
    pub path: String,
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EocvEvidenceManifest {
    pub profile: String,
    pub manifest_uuid: String,
    pub fixture_only: bool,
    pub artifacts: Vec<EocvEvidenceArtifact>,
    pub artifact_count: u8,
    pub total_artifact_bytes: u64,
    pub retained_authority_packet_sha256: ContentDigest,
    pub retained_a5_receipt_sha256: ContentDigest,
    pub retained_preparation_plan_sha256: ContentDigest,
    pub retained_observation_bundle_sha256: ContentDigest,
    pub retained_receipt_sha256: ContentDigest,
    pub deterministic_replay_count: u8,
    pub required_fresh_process_replay_count: u8,
    pub byte_identical: bool,
    pub effect_count: u32,
    pub manifest_sha256: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EocvFaultCode {
    Path,
    Profile,
    Size,
    Shape,
    Identity,
    Lineage,
    Coordinate,
    Dependency,
    Predecessor,
    RawBytes,
    Digest,
    Plan,
    Bundle,
    Expectation,
    Receipt,
    Truth,
    Effect,
    Evidence,
    Arithmetic,
    MachineForm,
    Restart,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EocvFault {
    pub code: EocvFaultCode,
    pub message: String,
}
impl fmt::Display for EocvFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}
impl std::error::Error for EocvFault {}

pub const EOCV_MISMATCH_REASONS: [EocvMismatchReason; 10] = [
    EocvMismatchReason::CarrierCommitMismatch,
    EocvMismatchReason::BranchMismatch,
    EocvMismatchReason::RemoteMismatch,
    EocvMismatchReason::ProjectMismatch,
    EocvMismatchReason::ObservationTimeMismatch,
    EocvMismatchReason::CapacityBelowFloor,
    EocvMismatchReason::BuildJunctionMismatch,
    EocvMismatchReason::UpstreamIdentityMismatch,
    EocvMismatchReason::RoleNotAbsent,
    EocvMismatchReason::ReservedRefNotAbsent,
];

/// Compute only the supplied comparison account, not a full A6 verification.
///
/// The outer verifier must still replay A5, bind this exact plan to its signed
/// proposal, admit raw bundle bytes and validate all request/digest identities.
/// This helper neither observes these values nor authenticates the caller's
/// expected carrier, time or proposed reference.
pub fn compare_eocv_supplied_values(
    bundle: &EocvObservationBundle,
    plan_request: &B1CDriveProductionPreparationPlanRequest,
    plan: &B1CDriveProductionPreparationPlan,
    expected_carrier: &str,
    a4_observed_unix_ms: u64,
    proposed_ref: &str,
) -> Result<EocvComparisonAccount, EocvFault> {
    validate_b1_cdrive_production_preparation_plan(plan_request, plan)
        .map_err(|_| fault(EocvFaultCode::Plan, "supplied preparation plan differs"))?;
    validate_comparison_inputs(bundle, plan_request, plan, expected_carrier, proposed_ref)?;
    let flags = [
        bundle.observed_carrier_commit == expected_carrier,
        bundle.observed_branch == plan_request.branch,
        bundle.observed_remote == plan_request.canonical_remote,
        bundle.observed_project == plan_request.working_project,
        bundle.observed_unix_ms == a4_observed_unix_ms,
        bundle.observed_cdrive_free_bytes >= plan_request.minimum_cdrive_free_bytes,
        bundle
            .build_junctions
            .iter()
            .zip(&plan_request.build_junctions)
            .all(|(observed, expected)| {
                observed.kind == EocvJunctionKind::Junction
                    && observed.target.as_deref() == Some(expected.target.as_str())
            }),
        bundle.upstream_identities == plan_request.upstream_identities,
        bundle
            .role_observations
            .iter()
            .all(|role| role.state == EocvPresenceAssertion::Absent),
        bundle.reserved_ref_observation.state == EocvPresenceAssertion::Absent,
    ];
    Ok(comparison_from_flags(flags))
}

/// Reject a forged conjunction or reordered/suppressed mismatch account.
/// This is account consistency, not verification of its source observations.
pub fn validate_eocv_comparison_account(account: &EocvComparisonAccount) -> Result<(), EocvFault> {
    let expected = comparison_from_flags([
        account.carrier_commit_matches,
        account.branch_matches,
        account.remote_matches,
        account.project_matches,
        account.observation_time_matches_a4,
        account.capacity_meets_minimum,
        account.build_junctions_match,
        account.upstream_identities_match,
        account.all_roles_absent_asserted,
        account.reserved_ref_absent_asserted,
    ]);
    if *account != expected {
        return Err(fault(EocvFaultCode::Receipt, "comparison summary differs"));
    }
    Ok(())
}

fn comparison_from_flags(flags: [bool; 10]) -> EocvComparisonAccount {
    let mismatch_reasons = flags
        .iter()
        .enumerate()
        .filter_map(|(index, matched)| (!matched).then_some(EOCV_MISMATCH_REASONS[index]))
        .collect();
    EocvComparisonAccount {
        carrier_commit_matches: flags[0],
        branch_matches: flags[1],
        remote_matches: flags[2],
        project_matches: flags[3],
        observation_time_matches_a4: flags[4],
        capacity_meets_minimum: flags[5],
        build_junctions_match: flags[6],
        upstream_identities_match: flags[7],
        all_roles_absent_asserted: flags[8],
        reserved_ref_absent_asserted: flags[9],
        mismatch_reasons,
        all_expectations_match: flags.into_iter().all(|flag| flag),
    }
}

fn validate_comparison_inputs(
    bundle: &EocvObservationBundle,
    plan_request: &B1CDriveProductionPreparationPlanRequest,
    plan: &B1CDriveProductionPreparationPlan,
    expected_carrier: &str,
    proposed_ref: &str,
) -> Result<(), EocvFault> {
    if bundle.profile != EOCV_BUNDLE_PROFILE {
        return Err(fault(
            EocvFaultCode::Profile,
            "observation bundle profile differs",
        ));
    }
    if !is_hex(expected_carrier, 40)
        || !is_hex(&bundle.observed_carrier_commit, 40)
        || bundle.expected_carrier_commit != expected_carrier
    {
        return Err(fault(
            EocvFaultCode::Expectation,
            "supplied carrier expectation differs",
        ));
    }
    if !safe_text(&bundle.observed_branch)
        || !safe_text(&bundle.observed_remote)
        || !safe_text(&bundle.observed_project)
        || !safe_text(proposed_ref)
    {
        return Err(fault(EocvFaultCode::Shape, "observation text differs"));
    }
    if bundle.evidence_references.is_empty()
        || bundle.evidence_references.len() > EOCV_MAX_EVIDENCE_REFERENCES
        || bundle
            .evidence_references
            .iter()
            .any(|value| !safe_text(value))
        || bundle
            .evidence_references
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != bundle.evidence_references.len()
    {
        return Err(fault(EocvFaultCode::Size, "evidence references differ"));
    }
    if bundle.build_junctions.len() != 2 || plan_request.build_junctions.len() != 2 {
        return Err(fault(EocvFaultCode::Coordinate, "junction count differs"));
    }
    for (observed, expected) in bundle
        .build_junctions
        .iter()
        .zip(&plan_request.build_junctions)
    {
        if observed.source != expected.source {
            return Err(fault(
                EocvFaultCode::Coordinate,
                "junction source coordinate differs",
            ));
        }
        match (observed.kind, observed.target.as_deref()) {
            (EocvJunctionKind::Junction, Some(target)) if safe_text(target) => {}
            (
                EocvJunctionKind::Missing | EocvJunctionKind::Other | EocvJunctionKind::Unknown,
                None,
            ) => {}
            _ => return Err(fault(EocvFaultCode::Shape, "junction target shape differs")),
        }
    }
    if bundle.upstream_identities.len() != 4 || plan_request.upstream_identities.len() != 4 {
        return Err(fault(EocvFaultCode::Coordinate, "upstream count differs"));
    }
    for (observed, expected) in bundle
        .upstream_identities
        .iter()
        .zip(&plan_request.upstream_identities)
    {
        if observed.role != expected.role {
            return Err(fault(
                EocvFaultCode::Coordinate,
                "upstream role coordinate differs",
            ));
        }
        if !safe_text(&observed.profile)
            || observed.artifact_sha256.algorithm != "sha256"
            || !is_hex(&observed.artifact_sha256.value, 64)
        {
            return Err(fault(
                EocvFaultCode::Shape,
                "upstream identity shape differs",
            ));
        }
    }
    if bundle.role_observations.len() != 5 || plan.roles.len() != 5 {
        return Err(fault(EocvFaultCode::Coordinate, "role count differs"));
    }
    for (observed, expected) in bundle.role_observations.iter().zip(&plan.roles) {
        if observed.kind != expected.kind || observed.path != expected.path {
            return Err(fault(
                EocvFaultCode::Coordinate,
                "role path coordinate differs",
            ));
        }
    }
    if bundle.reserved_ref_observation.reference != proposed_ref {
        return Err(fault(
            EocvFaultCode::Coordinate,
            "reserved reference coordinate differs",
        ));
    }
    Ok(())
}
fn safe_text(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && !value.chars().any(char::is_control)
}
fn is_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn fault(code: EocvFaultCode, message: &str) -> EocvFault {
    EocvFault {
        code,
        message: message.to_owned(),
    }
}
