//! A6 supplied expected-observation correspondence over the complete A5 chain.
//!
//! Full verification replays A5 and its signed inherited plan before admitting
//! exact raw bundle bytes. Comparison-only helpers remain explicitly narrower.
//! A matching comparison is not a live observation, freshness or permission.
use crate::{
    B1CDriveProductionPreparationPlan, B1CDriveProductionPreparationPlanRequest,
    B1CDriveProductionPreparationRoleKind, B1CDriveProductionPreparationUpstreamIdentity,
    B1OaprRequest, KcvInputClass, OdcvVerificationReceipt, TwvEffectAccount,
    validate_b1_cdrive_production_preparation_plan,
};
use cantor_core::{ContentDigest, sha256_bytes};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{collections::BTreeSet, fmt};

pub const EOCV_BUNDLE_PROFILE: &str = "cantor-b1-expected-observation-bundle/0.1";
pub const EOCV_REQUEST_PROFILE: &str = "cantor-b1-expected-observation-request/0.1";
pub const EOCV_RECEIPT_PROFILE: &str = "cantor-b1-expected-observation-receipt/0.1";
pub const EOCV_EVIDENCE_PROFILE: &str = "cantor-b1-expected-observation-evidence/0.1";
pub const EOCV_SOURCE_SNAPSHOT_UUID: &str = "d10dd69e-34d1-43db-ab46-109a11cc80e0";
pub const EOCV_SOURCE_UUID: &str = "43e434fd-5c4c-4d12-bc3d-8104ec927531";
pub const EOCV_SOURCE_BOOKEND_COMMIT: &str = "23cc6c17667efefa88ca27a1af2d1e410a9ccd00";
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
    bounded_value(bundle)?;
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
    value.len() <= MAX_TEXT_BYTES
        && !value.trim().is_empty()
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

/// Borrowed complete predecessor chain. None of these receipts is trusted:
/// the full unchanged A5 verifier reconstructs them before A6 admission.
pub struct EocvPredecessor<'a> {
    pub upstream: crate::OdcvPredecessor<'a>,
    pub a5_policy: &'a crate::B1CDriveOperatorDecisionPolicy,
    pub a5_legacy_request: &'a crate::B1CDriveOperatorDecisionRequest,
    pub raw_a5_envelope: &'a [u8],
    pub a5_request: &'a crate::OdcvVerificationRequest,
    pub a5_receipt: &'a OdcvVerificationReceipt,
}

/// Verify supplied correspondence only. This performs no observation or effect.
/// The three raw forms exclude the retained transport LF.
pub fn verify_eocv_expected_observation(
    request: &EocvVerificationRequest,
    predecessor: &EocvPredecessor<'_>,
    raw_plan_request: &[u8],
    raw_plan: &[u8],
    raw_bundle: &[u8],
) -> Result<EocvVerificationReceipt, EocvFault> {
    validate_request_shape(request)?;
    // Resource checks are not content admission. Reject oversized raw carriers
    // before expensive cryptographic replay; parse/admit only after A5 succeeds.
    raw_form_bound(raw_plan_request)?;
    raw_form_bound(raw_plan)?;
    raw_form_bound(raw_bundle)?;
    let a5 = crate::verify_odcv_operator_decision(
        predecessor.a5_request,
        &predecessor.upstream,
        predecessor.a5_policy,
        predecessor.a5_legacy_request,
        predecessor.raw_a5_envelope,
    )
    .map_err(predecessor_fault)?;
    if a5 != *predecessor.a5_receipt
        || request.a5_verification_request_sha256 != predecessor.a5_request.request_sha256
        || request.a5_receipt_sha256 != a5.receipt_sha256
    {
        return Err(fault(
            EocvFaultCode::Predecessor,
            "full A5 receipt or request binding differs",
        ));
    }

    // Preserve the original raw and semantic plan; no new host values are
    // substituted into its historical request.
    if request.preparation_plan_request_raw_sha256 != sha256_bytes(raw_plan_request)
        || request.preparation_plan_raw_sha256 != sha256_bytes(raw_plan)
    {
        return Err(fault(
            EocvFaultCode::RawBytes,
            "preparation form raw identity differs",
        ));
    }
    let plan_request = crate::from_b1_cdrive_production_preparation_request_machine_form(
        std::str::from_utf8(raw_plan_request).map_err(machine_fault)?,
    )
    .map_err(plan_fault)?;
    let plan = crate::from_b1_cdrive_production_preparation_plan_machine_form(
        &plan_request,
        std::str::from_utf8(raw_plan).map_err(machine_fault)?,
    )
    .map_err(plan_fault)?;
    let compiled =
        crate::compile_b1_cdrive_production_preparation_plan(&plan_request).map_err(plan_fault)?;
    if compiled != plan
        || request.preparation_plan_request_sha256 != plan_request.request_sha256
        || request.preparation_plan_sha256 != plan.plan_sha256
    {
        return Err(fault(
            EocvFaultCode::Plan,
            "reconstructed preparation identities differ",
        ));
    }
    let proposal_request =
        crate::canonical_b1_cdrive_production_preparation_commission_proposal_request()
            .map_err(plan_fault)?;
    let proposal = crate::from_b1_cdrive_production_preparation_commission_proposal_machine_form(
        &proposal_request,
        &predecessor.a5_legacy_request.proposal_machine_form,
    )
    .map_err(plan_fault)?;
    let legacy = predecessor.a5_legacy_request;
    if proposal.inherited_plan_sha256 != plan.plan_sha256
        || proposal.roles != plan.roles
        || proposal.operations != plan.operations
        || proposal.proposal_sha256 != legacy.proposal_self_sha256
        || legacy.branch != plan_request.branch
        || legacy.canonical_remote != plan_request.canonical_remote
        || legacy.working_project != plan_request.working_project
    {
        return Err(fault(
            EocvFaultCode::Plan,
            "signed proposal does not bind supplied plan",
        ));
    }

    let first = crate::compile_b1oapr_packet(&request.authority_packet_request)
        .map_err(predecessor_fault)?;
    let second = crate::compile_b1oapr_packet(&request.authority_packet_request)
        .map_err(predecessor_fault)?;
    if first != second
        || crate::to_b1oapr_packet_machine_form(&request.authority_packet_request, &first)
            .map_err(predecessor_fault)?
            != crate::to_b1oapr_packet_machine_form(&request.authority_packet_request, &second)
                .map_err(predecessor_fault)?
        || request.authority_packet_request_sha256
            != request.authority_packet_request.request_sha256
        || request.authority_packet_sha256 != first.packet_sha256
    {
        return Err(fault(
            EocvFaultCode::Digest,
            "current packet reconstruction differs",
        ));
    }
    validate_packet_transition(
        &predecessor.a5_request.authority_packet_request,
        &request.authority_packet_request,
    )?;
    let descriptor = &request.authority_packet_request.descriptors[5];
    if descriptor.ordinal != 6
        || descriptor.authority_name != "fresh_observation"
        || descriptor.artifact_kind != "expected_current_observation_bundle_candidate"
        || descriptor.required_verifier_profile != "expected-current-observation-verifier/0.1"
        || descriptor.confidentiality != crate::B1OaprConfidentiality::PublicMetadata
        || descriptor.dependency_ordinal != Some(5)
        || descriptor.candidate_uuid != request.a6_candidate_uuid
        || descriptor.descriptor_sha256 != request.a6_descriptor_sha256
    {
        return Err(fault(
            EocvFaultCode::Coordinate,
            "A6 descriptor coordinate differs",
        ));
    }
    let fixture = is_fixture(request.input_class);
    let origin = if fixture {
        crate::B1OaprCandidateOrigin::DeterministicFixtureCandidate
    } else {
        crate::B1OaprCandidateOrigin::ExternallySuppliedCandidate
    };
    if descriptor.origin != origin || descriptor.fixture_only != fixture {
        return Err(fault(
            EocvFaultCode::Identity,
            "A6 descriptor class differs",
        ));
    }
    // Candidate raw identity must be established before any bundle parsing.
    if request.observation_bundle_bytes != raw_bundle.len() as u64
        || descriptor.declared_bytes != raw_bundle.len() as u64
        || request.observation_bundle_raw_sha256 != sha256_bytes(raw_bundle)
        || descriptor.content_sha256 != request.observation_bundle_raw_sha256
    {
        return Err(fault(
            EocvFaultCode::RawBytes,
            "A6 raw bundle identity differs",
        ));
    }
    let bundle =
        from_eocv_bundle_machine_form(std::str::from_utf8(raw_bundle).map_err(machine_fault)?)?;
    if bundle.bundle_uuid != request.expected_bundle_uuid
        || bundle.bundle_uuid == a5.decision_uuid
        || bundle.a5_receipt_sha256 != a5.receipt_sha256
        || bundle.expected_carrier_commit != request.expected_carrier_commit
        || bundle.input_class != request.input_class
    {
        return Err(fault(
            EocvFaultCode::Bundle,
            "bundle lineage expectation or class differs",
        ));
    }
    let comparison = compare_eocv_supplied_values(
        &bundle,
        &plan_request,
        &plan,
        &request.expected_carrier_commit,
        a5.observed_unix_ms,
        &proposal.proposed_ref,
    )?;
    let receipt = build_receipt(
        request,
        a5,
        legacy,
        &plan_request,
        &bundle,
        &proposal.proposal_sha256,
        comparison,
    )?;
    validate_eocv_receipt_fields(&receipt)?;
    Ok(receipt)
}

fn validate_packet_transition(
    prior: &B1OaprRequest,
    current: &B1OaprRequest,
) -> Result<(), EocvFault> {
    if prior.descriptors.len() != 9 || current.descriptors.len() != 9 {
        return Err(fault(
            EocvFaultCode::Coordinate,
            "packet coordinate count differs",
        ));
    }
    if prior.descriptors[..5] != current.descriptors[..5]
        || prior.descriptors[6..] != current.descriptors[6..]
    {
        return Err(fault(
            EocvFaultCode::Dependency,
            "A6 changes another descriptor",
        ));
    }
    let mut normalized = current.clone();
    normalized.descriptors[5] = prior.descriptors[5].clone();
    normalized.request_sha256 = prior.request_sha256.clone();
    if normalized != *prior {
        return Err(fault(
            EocvFaultCode::Lineage,
            "A6 changes packet subjects or policy",
        ));
    }
    Ok(())
}

fn validate_request_shape(request: &EocvVerificationRequest) -> Result<(), EocvFault> {
    bounded_value(request)?;
    if request.profile != EOCV_REQUEST_PROFILE {
        return Err(fault(EocvFaultCode::Profile, "request profile differs"));
    }
    if request.source_snapshot_uuid != EOCV_SOURCE_SNAPSHOT_UUID
        || request.canonical_uuid != EOCV_CANONICAL_UUID
        || request.signature_uuid != EOCV_SIGNATURE_UUID
        || request.source_custody_commit != EOCV_SOURCE_CUSTODY_COMMIT
        || request.formation_commit != EOCV_FORMATION_COMMIT
        || request.formation_bookend_commit != EOCV_FORMATION_BOOKEND_COMMIT
        || request.a5_implementation_commit != EOCV_A5_IMPLEMENTATION_COMMIT
        || request.a5_bookend_commit != EOCV_A5_BOOKEND_COMMIT
        || request.a5_proof_uuid != EOCV_A5_PROOF_UUID
        || request.plan_implementation_commit != EOCV_PLAN_IMPLEMENTATION_COMMIT
        || request.plan_bookend_commit != EOCV_PLAN_BOOKEND_COMMIT
        || request.plan_proof_uuid != EOCV_PLAN_PROOF_UUID
    {
        return Err(fault(
            EocvFaultCode::Lineage,
            "request governance lineage differs",
        ));
    }
    if !valid_eocv_uuid(&request.a6_candidate_uuid)
        || !valid_bundle_uuid(&request.expected_bundle_uuid)
        || !is_hex(&request.expected_carrier_commit, 40)
    {
        return Err(fault(
            EocvFaultCode::Identity,
            "request identity or expected carrier shape differs",
        ));
    }
    validate_references(&request.evidence_references)?;
    if request.observation_bundle_bytes == 0
        || request.observation_bundle_bytes > EOCV_MAX_FORM_BYTES as u64
    {
        return Err(fault(
            EocvFaultCode::Size,
            "declared bundle bytes exceed bound",
        ));
    }
    if request.maximum_attempts != 1
        || request.automatic_retry_count != 0
        || request.automatic_cleanup_count != 0
    {
        return Err(fault(
            EocvFaultCode::Effect,
            "attempt retry cleanup policy differs",
        ));
    }
    if request.request_sha256 != eocv_request_digest(request)? {
        return Err(fault(EocvFaultCode::Digest, "request self digest differs"));
    }
    Ok(())
}

/// Shape and canonical self-digest only; plan coordinates and A5 correspondence
/// are validated by verify_eocv_expected_observation, never by this encoder alone.
pub fn to_eocv_bundle_machine_form(bundle: &EocvObservationBundle) -> Result<String, EocvFault> {
    validate_bundle_shape(bundle)?;
    serde_json::to_string(bundle).map_err(machine_fault)
}
pub fn from_eocv_bundle_machine_form(text: &str) -> Result<EocvObservationBundle, EocvFault> {
    let bundle = parse_eocv_canonical(text)?;
    validate_bundle_shape(&bundle)?;
    Ok(bundle)
}
fn validate_bundle_shape(bundle: &EocvObservationBundle) -> Result<(), EocvFault> {
    bounded_value(bundle)?;
    if bundle.profile != EOCV_BUNDLE_PROFILE {
        return Err(fault(EocvFaultCode::Profile, "bundle profile differs"));
    }
    if !valid_bundle_uuid(&bundle.bundle_uuid)
        || !is_hex(&bundle.expected_carrier_commit, 40)
        || !is_hex(&bundle.observed_carrier_commit, 40)
        || !valid_digest(&bundle.a5_receipt_sha256)
    {
        return Err(fault(
            EocvFaultCode::Identity,
            "bundle identity shape differs",
        ));
    }
    validate_references(&bundle.evidence_references)?;
    if !safe_text(&bundle.observed_branch)
        || !safe_text(&bundle.observed_remote)
        || !safe_text(&bundle.observed_project)
        || !safe_text(&bundle.reserved_ref_observation.reference)
    {
        return Err(fault(
            EocvFaultCode::Shape,
            "bundle observation text differs",
        ));
    }
    if bundle.build_junctions.len() != 2
        || bundle.upstream_identities.len() != 4
        || bundle.role_observations.len() != 5
    {
        return Err(fault(
            EocvFaultCode::Coordinate,
            "bundle coordinate counts differ",
        ));
    }
    for junction in &bundle.build_junctions {
        if !safe_text(&junction.source) {
            return Err(fault(EocvFaultCode::Shape, "junction source shape differs"));
        }
        match (junction.kind, junction.target.as_deref()) {
            (EocvJunctionKind::Junction, Some(target)) if safe_text(target) => {}
            (
                EocvJunctionKind::Missing | EocvJunctionKind::Other | EocvJunctionKind::Unknown,
                None,
            ) => {}
            _ => return Err(fault(EocvFaultCode::Shape, "junction target shape differs")),
        }
    }
    if bundle
        .upstream_identities
        .iter()
        .any(|u| !safe_text(&u.profile) || !valid_digest(&u.artifact_sha256))
        || bundle
            .role_observations
            .iter()
            .any(|role| !safe_text(&role.path))
    {
        return Err(fault(
            EocvFaultCode::Shape,
            "bundle role identity shape differs",
        ));
    }
    if bundle.bundle_sha256 != eocv_bundle_digest(bundle)? {
        return Err(fault(EocvFaultCode::Digest, "bundle self digest differs"));
    }
    Ok(())
}
fn validate_references(references: &[String]) -> Result<(), EocvFault> {
    if references.is_empty()
        || references.len() > EOCV_MAX_EVIDENCE_REFERENCES
        || references.iter().any(|v| !safe_text(v))
        || references.iter().collect::<BTreeSet<_>>().len() != references.len()
    {
        return Err(fault(
            EocvFaultCode::Evidence,
            "opaque evidence references differ",
        ));
    }
    Ok(())
}
pub fn to_eocv_request_machine_form(
    request: &EocvVerificationRequest,
) -> Result<String, EocvFault> {
    validate_request_shape(request)?;
    serde_json::to_string(request).map_err(machine_fault)
}
pub fn from_eocv_request_machine_form(text: &str) -> Result<EocvVerificationRequest, EocvFault> {
    let request = parse_eocv_canonical(text)?;
    validate_request_shape(&request)?;
    Ok(request)
}
pub fn validate_eocv_receipt(
    request: &EocvVerificationRequest,
    predecessor: &EocvPredecessor<'_>,
    raw_plan_request: &[u8],
    raw_plan: &[u8],
    raw_bundle: &[u8],
    receipt: &EocvVerificationReceipt,
) -> Result<(), EocvFault> {
    validate_eocv_receipt_fields(receipt)?;
    if *receipt
        != verify_eocv_expected_observation(
            request,
            predecessor,
            raw_plan_request,
            raw_plan,
            raw_bundle,
        )?
    {
        return Err(fault(
            EocvFaultCode::Receipt,
            "receipt differs from full reconstructed chain",
        ));
    }
    Ok(())
}
pub fn to_eocv_receipt_machine_form(
    request: &EocvVerificationRequest,
    predecessor: &EocvPredecessor<'_>,
    raw_plan_request: &[u8],
    raw_plan: &[u8],
    raw_bundle: &[u8],
    receipt: &EocvVerificationReceipt,
) -> Result<String, EocvFault> {
    validate_eocv_receipt(
        request,
        predecessor,
        raw_plan_request,
        raw_plan,
        raw_bundle,
        receipt,
    )?;
    serde_json::to_string(receipt).map_err(machine_fault)
}
pub fn from_eocv_receipt_machine_form(
    request: &EocvVerificationRequest,
    predecessor: &EocvPredecessor<'_>,
    raw_plan_request: &[u8],
    raw_plan: &[u8],
    raw_bundle: &[u8],
    text: &str,
) -> Result<EocvVerificationReceipt, EocvFault> {
    let receipt = parse_eocv_canonical(text)?;
    validate_eocv_receipt(
        request,
        predecessor,
        raw_plan_request,
        raw_plan,
        raw_bundle,
        &receipt,
    )?;
    Ok(receipt)
}
pub fn eocv_bundle_digest(bundle: &EocvObservationBundle) -> Result<ContentDigest, EocvFault> {
    bounded_value(bundle)?;
    let mut normalized = bundle.clone();
    normalized.bundle_sha256 = sha256_bytes(b"");
    eocv_domain_digest("cantor.b1.expected-observation.bundle.v1", &normalized)
}
pub fn eocv_request_digest(request: &EocvVerificationRequest) -> Result<ContentDigest, EocvFault> {
    bounded_value(request)?;
    let mut normalized = request.clone();
    normalized.request_sha256 = sha256_bytes(b"");
    eocv_domain_digest("cantor.b1.expected-observation.request.v1", &normalized)
}
pub fn eocv_receipt_digest(receipt: &EocvVerificationReceipt) -> Result<ContentDigest, EocvFault> {
    bounded_value(receipt)?;
    let mut normalized = receipt.clone();
    normalized.receipt_sha256 = sha256_bytes(b"");
    eocv_domain_digest("cantor.b1.expected-observation.receipt.v1", &normalized)
}
pub(crate) fn eocv_domain_digest<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<ContentDigest, EocvFault> {
    let canonical = serde_json::to_vec(value).map_err(machine_fault)?;
    let capacity = domain
        .len()
        .checked_add(1)
        .and_then(|v| v.checked_add(canonical.len()))
        .ok_or_else(|| fault(EocvFaultCode::Arithmetic, "digest domain length overflow"))?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(sha256_bytes(&bytes))
}
pub(crate) fn parse_eocv_canonical<T: DeserializeOwned + Serialize>(
    text: &str,
) -> Result<T, EocvFault> {
    if text.is_empty()
        || text.len() > EOCV_MAX_FORM_BYTES
        || text.starts_with('\u{feff}')
        || text.contains('\r')
        || text.contains('\n')
    {
        return Err(fault(
            EocvFaultCode::MachineForm,
            "machine form framing or size differs",
        ));
    }
    let raw: Value = serde_json::from_str(text).map_err(machine_fault)?;
    measure_value(&raw, 1, &mut 0)?;
    let value: T = serde_json::from_value(raw).map_err(machine_fault)?;
    if serde_json::to_string(&value).map_err(machine_fault)? != text {
        return Err(fault(
            EocvFaultCode::MachineForm,
            "machine form is not compact canonical JSON",
        ));
    }
    Ok(value)
}
fn bounded_value<T: Serialize>(value: &T) -> Result<(), EocvFault> {
    let bytes = serde_json::to_vec(value).map_err(machine_fault)?;
    if bytes.len() > EOCV_MAX_FORM_BYTES {
        return Err(fault(EocvFaultCode::Size, "typed form exceeds byte limit"));
    }
    measure_value(
        &serde_json::to_value(value).map_err(machine_fault)?,
        1,
        &mut 0,
    )
}
fn measure_value(value: &Value, depth: usize, fields: &mut usize) -> Result<(), EocvFault> {
    if depth > 32 {
        return Err(fault(EocvFaultCode::Size, "JSON depth exceeds bound"));
    }
    match value {
        Value::Object(items) => {
            *fields = fields
                .checked_add(items.len())
                .ok_or_else(|| fault(EocvFaultCode::Arithmetic, "JSON field count overflow"))?;
            if *fields > 4096 {
                return Err(fault(EocvFaultCode::Size, "JSON field count exceeds bound"));
            }
            for (key, value) in items {
                if !safe_text(key) {
                    return Err(fault(EocvFaultCode::Shape, "JSON key differs"));
                }
                measure_value(value, depth + 1, fields)?;
            }
        }
        Value::Array(items) => {
            if items.len() > 4096 {
                return Err(fault(EocvFaultCode::Size, "JSON array exceeds bound"));
            }
            for value in items {
                measure_value(value, depth + 1, fields)?;
            }
        }
        Value::String(value)
            if value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) =>
        {
            return Err(fault(EocvFaultCode::Shape, "JSON text exceeds bounds"));
        }
        _ => {}
    }
    Ok(())
}
fn raw_form_bound(bytes: &[u8]) -> Result<(), EocvFault> {
    if bytes.is_empty() || bytes.len() > EOCV_MAX_FORM_BYTES {
        return Err(fault(EocvFaultCode::Size, "raw form exceeds byte bound"));
    }
    Ok(())
}
pub(crate) fn valid_eocv_uuid(value: &str) -> bool {
    crate::b1_operator_decision_chain_verification::valid_odcv_uuid(value)
}
fn valid_bundle_uuid(value: &str) -> bool {
    valid_eocv_uuid(value)
        && ![
            EOCV_SOURCE_UUID,
            EOCV_SOURCE_SNAPSHOT_UUID,
            EOCV_CANONICAL_UUID,
            EOCV_SIGNATURE_UUID,
        ]
        .contains(&value)
}
fn valid_digest(value: &ContentDigest) -> bool {
    value.algorithm == "sha256" && is_hex(&value.value, 64)
}
fn is_fixture(class: KcvInputClass) -> bool {
    class == KcvInputClass::DeterministicFixtureCandidate
}
fn predecessor_fault(error: impl fmt::Display) -> EocvFault {
    fault(EocvFaultCode::Predecessor, &error.to_string())
}
fn plan_fault(error: impl fmt::Display) -> EocvFault {
    fault(EocvFaultCode::Plan, &error.to_string())
}
fn machine_fault(error: impl fmt::Display) -> EocvFault {
    fault(EocvFaultCode::MachineForm, &error.to_string())
}
pub(crate) fn eocv_fault(code: EocvFaultCode, message: impl fmt::Display) -> EocvFault {
    fault(code, &message.to_string())
}

fn build_receipt(
    request: &EocvVerificationRequest,
    a5: OdcvVerificationReceipt,
    legacy: &crate::B1CDriveOperatorDecisionRequest,
    plan_request: &B1CDriveProductionPreparationPlanRequest,
    bundle: &EocvObservationBundle,
    proposal_sha256: &ContentDigest,
    comparison: EocvComparisonAccount,
) -> Result<EocvVerificationReceipt, EocvFault> {
    let mut receipt = EocvVerificationReceipt {
        profile: EOCV_RECEIPT_PROFILE.to_owned(),
        status: if comparison.all_expectations_match {
            EOCV_MATCHED_STATUS
        } else {
            EOCV_MISMATCHED_STATUS
        }
        .to_owned(),
        authority: EOCV_AUTHORITY.to_owned(),
        source_snapshot_uuid: request.source_snapshot_uuid.clone(),
        canonical_uuid: request.canonical_uuid.clone(),
        signature_uuid: request.signature_uuid.clone(),
        source_custody_commit: request.source_custody_commit.clone(),
        formation_commit: request.formation_commit.clone(),
        formation_bookend_commit: request.formation_bookend_commit.clone(),
        a5_implementation_commit: request.a5_implementation_commit.clone(),
        a5_bookend_commit: request.a5_bookend_commit.clone(),
        a5_proof_uuid: request.a5_proof_uuid.clone(),
        plan_implementation_commit: request.plan_implementation_commit.clone(),
        plan_bookend_commit: request.plan_bookend_commit.clone(),
        plan_proof_uuid: request.plan_proof_uuid.clone(),
        request_sha256: request.request_sha256.clone(),
        a5_verification_request_sha256: request.a5_verification_request_sha256.clone(),
        a5_receipt_sha256: request.a5_receipt_sha256.clone(),
        preparation_plan_request_raw_sha256: request.preparation_plan_request_raw_sha256.clone(),
        preparation_plan_request_sha256: request.preparation_plan_request_sha256.clone(),
        preparation_plan_raw_sha256: request.preparation_plan_raw_sha256.clone(),
        preparation_plan_sha256: request.preparation_plan_sha256.clone(),
        authority_packet_request_sha256: request.authority_packet_request_sha256.clone(),
        authority_packet_sha256: request.authority_packet_sha256.clone(),
        a6_candidate_uuid: request.a6_candidate_uuid.clone(),
        a6_descriptor_sha256: request.a6_descriptor_sha256.clone(),
        observation_bundle_raw_sha256: request.observation_bundle_raw_sha256.clone(),
        expected_carrier_commit: request.expected_carrier_commit.clone(),
        proposal_sha256: proposal_sha256.clone(),
        observation_bundle_bytes: request.observation_bundle_bytes,
        observation_bundle_sha256: bundle.bundle_sha256.clone(),
        bundle_uuid: bundle.bundle_uuid.clone(),
        observed_carrier_commit: bundle.observed_carrier_commit.clone(),
        legacy_decision_expected_current_commit: legacy.expected_current_commit.clone(),
        preparation_plan_expected_current_commit: plan_request.expected_current_commit.clone(),
        observed_unix_ms: bundle.observed_unix_ms,
        a4_observed_unix_ms: a5.observed_unix_ms,
        observed_cdrive_free_bytes: bundle.observed_cdrive_free_bytes,
        minimum_cdrive_free_bytes: plan_request.minimum_cdrive_free_bytes,
        comparison_account: comparison,
        input_class: request.input_class,
        fixture_only: is_fixture(request.input_class),
        maximum_attempts: request.maximum_attempts,
        automatic_retry_count: request.automatic_retry_count,
        automatic_cleanup_count: request.automatic_cleanup_count,
        a5_correspondence_receipt_verified: true,
        preparation_plan_replayed: true,
        proposal_plan_correspondence_verified: true,
        packet_replayed: true,
        descriptor_correspondence_verified: true,
        observation_bundle_bytes_matched: true,
        comparison_reconstructed: true,
        production_authority_claimed: false,
        fresh_observation_proved: false,
        observation_source_identity_proved: false,
        observation_source_completeness_proved: false,
        observation_freshness_proved: false,
        atomic_observation_proved: false,
        decision_signature_binds_a6_observation: false,
        expected_carrier_authority_proved: false,
        live_authorization_admitted: false,
        private_execution_permit_present: false,
        production_broker_projection_present: false,
        physical_preparation_authorized: false,
        ready_for_physical_execution: false,
        execution_authorized: false,
        a5_receipt: a5,
        effect_account: TwvEffectAccount::default(),
        receipt_sha256: sha256_bytes(b""),
    };
    receipt.receipt_sha256 = eocv_receipt_digest(&receipt)?;
    Ok(receipt)
}

/// Internal shape/account gate only. Public receipt admission also reconstructs
/// the complete upstream chain and compares every data-driven receipt field.
pub(crate) fn validate_eocv_receipt_fields(
    receipt: &EocvVerificationReceipt,
) -> Result<(), EocvFault> {
    bounded_value(receipt)?;
    let expected_status = if receipt.comparison_account.all_expectations_match {
        EOCV_MATCHED_STATUS
    } else {
        EOCV_MISMATCHED_STATUS
    };
    if receipt.profile != EOCV_RECEIPT_PROFILE
        || receipt.status != expected_status
        || receipt.authority != EOCV_AUTHORITY
    {
        return Err(fault(
            EocvFaultCode::Profile,
            "receipt profile status or authority differs",
        ));
    }
    if receipt.production_authority_claimed
        || receipt.fresh_observation_proved
        || receipt.observation_source_identity_proved
        || receipt.observation_source_completeness_proved
        || receipt.observation_freshness_proved
        || receipt.atomic_observation_proved
        || receipt.decision_signature_binds_a6_observation
        || receipt.expected_carrier_authority_proved
        || receipt.live_authorization_admitted
        || receipt.private_execution_permit_present
        || receipt.production_broker_projection_present
        || receipt.physical_preparation_authorized
        || receipt.ready_for_physical_execution
        || receipt.execution_authorized
    {
        return Err(fault(
            EocvFaultCode::Truth,
            "receipt promotes observation or execution authority",
        ));
    }
    if !receipt.a5_correspondence_receipt_verified
        || !receipt.preparation_plan_replayed
        || !receipt.proposal_plan_correspondence_verified
        || !receipt.packet_replayed
        || !receipt.descriptor_correspondence_verified
        || !receipt.observation_bundle_bytes_matched
        || !receipt.comparison_reconstructed
    {
        return Err(fault(
            EocvFaultCode::Truth,
            "receipt correspondence truth differs",
        ));
    }
    if receipt.effect_account != TwvEffectAccount::default()
        || receipt.maximum_attempts != 1
        || receipt.automatic_retry_count != 0
        || receipt.automatic_cleanup_count != 0
    {
        return Err(fault(
            EocvFaultCode::Effect,
            "receipt effect or attempt account differs",
        ));
    }
    if receipt.fixture_only != is_fixture(receipt.input_class)
        || receipt.a5_receipt_sha256 != receipt.a5_receipt.receipt_sha256
        || receipt.a4_observed_unix_ms != receipt.a5_receipt.observed_unix_ms
    {
        return Err(fault(
            EocvFaultCode::Receipt,
            "receipt nested identity or class differs",
        ));
    }
    crate::b1_operator_decision_chain_verification::validate_odcv_receipt_fields(
        &receipt.a5_receipt,
    )
    .map_err(predecessor_fault)?;
    validate_eocv_comparison_account(&receipt.comparison_account)?;
    if receipt.receipt_sha256 != eocv_receipt_digest(receipt)? {
        return Err(fault(EocvFaultCode::Digest, "receipt self digest differs"));
    }
    Ok(())
}
