//! Pure SWA-06B1 review and satisfaction-signature admission.
//!
//! This module verifies an exact SWA-06A receipt, supplied source-preservation
//! correspondence, and a detached Ed25519 signature under a supplied reviewer
//! policy. It does not perform review, issue signatures, write source, or
//! activate an SOP.

use std::{collections::BTreeSet, fmt};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{
    ContentDigest, SUCCEEDING_SOP_PROPOSAL_PROFILE, SemanticId, SucceedingSopVerificationReceipt,
    sha256_bytes, validate_succeeding_sop_verification_receipt,
};

pub const SUCCEEDING_SOP_REVIEWER_POLICY_PROFILE: &str =
    "cantor-succeeding-sop-reviewer-policy/0.1";
pub const SUCCEEDING_SOP_SOURCE_PRESERVATION_PROFILE: &str =
    "cantor-succeeding-sop-source-preservation/0.1";
pub const SUCCEEDING_SOP_REVIEW_PAYLOAD_PROFILE: &str = "cantor-succeeding-sop-review-payload/0.1";
pub const SUCCEEDING_SOP_SATISFACTION_SIGNATURE_PROFILE: &str =
    "cantor-succeeding-sop-satisfaction-signature/0.1";
pub const SUCCEEDING_SOP_REVIEW_ADMISSION_REQUEST_PROFILE: &str =
    "cantor-succeeding-sop-review-admission-request/0.1";
pub const SUCCEEDING_SOP_REVIEW_ADMISSION_RECEIPT_PROFILE: &str =
    "cantor-succeeding-sop-review-admission-receipt/0.1";
pub const SUCCEEDING_SOP_SATISFACTION_SIGNATURE_PROTOCOL_UUID: &str =
    "ad10f10f-d506-48ef-a805-f8b0a133766c";
pub const SUCCEEDING_SOP_REVIEW_ADMISSION_MAX_MACHINE_FORM_BYTES: usize = 16 * 1024 * 1024;
pub const SUCCEEDING_SOP_REVIEW_ADMISSION_NON_AUTHORITY: &str = "Pure verification of a supplied SWA-06A receipt, reviewer policy, source-preservation record, semantic-review payload, and detached Ed25519 satisfaction signature. Signature verification proves payload integrity and possession of the key pinned by the supplied policy only. It does not prove policy governance, reviewer competence, semantic truth, freshness, physical source custody, or activation authority. No review is performed, no signature or key is created, no source or workspace is read or written, no SOP is persisted, admitted, booted, activated, or made current, no process or test is run, no update is applied, no commit or push occurs, no provider or model is contacted, and no external, remote, FPGA, or Minecraft authority is granted.";

pub const SUCCEEDING_SOP_REVIEW_CHECKS: [&str; 6] = [
    "activation_scope_reviewed",
    "authority_boundary_reviewed",
    "causal_lineage_reviewed",
    "source_intent_reviewed",
    "source_preservation_reviewed",
    "unresolved_frontier_reviewed",
];

pub const SUCCEEDING_SOP_ACTIVATION_OBLIGATIONS: [&str; 6] = [
    "assign_activation_recovery_owner",
    "govern_activation_policy_separately",
    "never_self_activate",
    "persist_activation_registry_atomically",
    "preserve_supersession_and_rollback",
    "reacquire_and_verify_source_storage",
];

pub const SUCCEEDING_SOP_REVIEW_ADMISSION_VERIFIED_CHECKS: [&str; 9] = [
    "authority_denial",
    "deterministic_digests",
    "policy_shape",
    "preservation_correspondence",
    "review_payload_correspondence",
    "reviewer_separation",
    "satisfaction_protocol",
    "signature_integrity",
    "upstream_replay",
];

const POLICY_DOMAIN: &str = "cantor.succeeding-sop-review.policy.v1";
const PRESERVATION_DOMAIN: &str = "cantor.succeeding-sop-review.preservation.v1";
const PAYLOAD_DOMAIN: &str = "cantor.succeeding-sop-review.payload.v1";
const REQUEST_DOMAIN: &str = "cantor.succeeding-sop-review.admission-request.v1";
const RECEIPT_DOMAIN: &str = "cantor.succeeding-sop-review.admission-receipt.v1";
const MAX_POLICY_EVIDENCE_REFS: usize = 32;
const MAX_PRESERVATION_EVIDENCE_REFS: usize = 32;
const MAX_REVIEW_EVIDENCE_REFS: usize = 64;
const MAX_SOURCE_PATH_BYTES: usize = 1024;

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopReviewerPolicyUseStatus {
    ExternallyGoverned,
    SyntheticFixtureOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopReviewDecision {
    Approved,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopReviewAdmissionStatus {
    CryptographicallyVerifiedAwaitingPhysicalActivation,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopReviewAdmissionAuthority {
    ReviewSignatureCorrespondenceOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopReviewerPolicy {
    pub profile: String,
    pub use_status: SucceedingSopReviewerPolicyUseStatus,
    pub policy_ref: SemanticId,
    pub reviewer_ref: SemanticId,
    pub verifying_key_hex: String,
    pub allowed_proposal_profile: String,
    pub satisfaction_signature_protocol_uuid: String,
    pub governance_evidence_refs: BTreeSet<SemanticId>,
    pub non_authority: String,
    pub policy_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopSourcePreservationRecord {
    pub profile: String,
    pub preservation_ref: SemanticId,
    pub source_snapshot_ref: SemanticId,
    pub source_path: String,
    pub source_subject: String,
    pub source_sha256: ContentDigest,
    pub source_bytes: u64,
    pub proposal_digest: ContentDigest,
    pub preserved: bool,
    pub immutable: bool,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub preservation_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopReviewPayload {
    pub profile: String,
    pub satisfaction_signature_protocol_uuid: String,
    pub policy_ref: SemanticId,
    pub policy_digest: ContentDigest,
    pub reviewer_ref: SemanticId,
    pub author_ref: SemanticId,
    pub proposal_ref: SemanticId,
    pub request_digest: ContentDigest,
    pub proposal_digest: ContentDigest,
    pub verification_digest: ContentDigest,
    pub source_subject: String,
    pub source_sha256: ContentDigest,
    pub source_bytes: u64,
    pub unresolved_frontier: BTreeSet<String>,
    pub preservation_ref: SemanticId,
    pub preservation_digest: ContentDigest,
    pub decision: SucceedingSopReviewDecision,
    pub review_checks: BTreeSet<String>,
    pub review_evidence_refs: BTreeSet<SemanticId>,
    pub payload_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopSatisfactionSignatureEnvelope {
    pub profile: String,
    pub payload: SucceedingSopReviewPayload,
    pub signature_hex: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopReviewAdmissionRequest {
    pub profile: String,
    pub admission_id: SemanticId,
    pub proposal_verification: SucceedingSopVerificationReceipt,
    pub reviewer_policy: SucceedingSopReviewerPolicy,
    pub source_preservation: SucceedingSopSourcePreservationRecord,
    pub satisfaction_signature: SucceedingSopSatisfactionSignatureEnvelope,
    pub activation_obligations: BTreeSet<String>,
    pub non_authority: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopReviewAdmissionReceipt {
    pub profile: String,
    pub request: SucceedingSopReviewAdmissionRequest,
    pub admission_ref: SemanticId,
    pub proposal_ref: SemanticId,
    pub reviewer_ref: SemanticId,
    pub policy_ref: SemanticId,
    pub preservation_ref: SemanticId,
    pub satisfaction_signature_protocol_uuid: String,
    pub policy_use_status: SucceedingSopReviewerPolicyUseStatus,
    pub status: SucceedingSopReviewAdmissionStatus,
    pub authority: SucceedingSopReviewAdmissionAuthority,
    pub cryptographic_signature_verified: bool,
    pub structural_reviewer_independence_verified: bool,
    pub source_preservation_correspondence_verified: bool,
    pub semantic_truth_proved: bool,
    pub policy_governance_proved: bool,
    pub physical_contact: bool,
    pub physical_activation_eligible: bool,
    pub verified_checks: BTreeSet<String>,
    pub activation_obligations: BTreeSet<String>,
    pub policy_digest: ContentDigest,
    pub preservation_digest: ContentDigest,
    pub review_payload_digest: ContentDigest,
    pub request_digest: ContentDigest,
    pub proposal_digest: ContentDigest,
    pub verification_digest: ContentDigest,
    pub non_authority: String,
    pub receipt_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopReviewAdmissionFaultCode {
    InvalidProfile,
    InvalidUpstream,
    InvalidPolicy,
    InvalidIdentity,
    InvalidEvidence,
    InvalidPreservation,
    InvalidPath,
    InvalidReview,
    InvalidProtocol,
    InvalidSignature,
    InvalidAuthority,
    InvalidCorrespondence,
    InvalidDigest,
    InvalidBound,
    InvalidMachineForm,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopReviewAdmissionFault {
    pub code: SucceedingSopReviewAdmissionFaultCode,
    pub message: String,
}

impl fmt::Display for SucceedingSopReviewAdmissionFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for SucceedingSopReviewAdmissionFault {}

pub fn admit_succeeding_sop_review(
    request: &SucceedingSopReviewAdmissionRequest,
) -> Result<SucceedingSopReviewAdmissionReceipt, SucceedingSopReviewAdmissionFault> {
    validate_succeeding_sop_review_admission_request(request)?;
    let receipt = build_receipt(request)?;
    validate_succeeding_sop_review_admission_receipt(&receipt)?;
    Ok(receipt)
}

pub fn validate_succeeding_sop_review_admission_request(
    request: &SucceedingSopReviewAdmissionRequest,
) -> Result<(), SucceedingSopReviewAdmissionFault> {
    if request.profile != SUCCEEDING_SOP_REVIEW_ADMISSION_REQUEST_PROFILE {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidProfile,
            "admission request profile differs",
        ));
    }
    validate_succeeding_sop_verification_receipt(&request.proposal_verification).map_err(
        |error| {
            fault(
                SucceedingSopReviewAdmissionFaultCode::InvalidUpstream,
                error.to_string(),
            )
        },
    )?;
    validate_identity_separation(request)?;
    validate_reviewer_policy(&request.reviewer_policy)?;
    validate_source_preservation(&request.proposal_verification, &request.source_preservation)?;
    validate_review_payload(request)?;
    validate_signature(request)?;
    if request.activation_obligations != required_activation_obligations() {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidAuthority,
            "activation obligations differ",
        ));
    }
    if request.non_authority != SUCCEEDING_SOP_REVIEW_ADMISSION_NON_AUTHORITY {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidAuthority,
            "request non-authority differs",
        ));
    }
    Ok(())
}

pub fn validate_succeeding_sop_review_admission_receipt(
    receipt: &SucceedingSopReviewAdmissionReceipt,
) -> Result<(), SucceedingSopReviewAdmissionFault> {
    validate_succeeding_sop_review_admission_request(&receipt.request)?;
    validate_digest(&receipt.receipt_digest, "receipt digest")?;
    let expected = build_receipt(&receipt.request)?;
    if receipt != &expected {
        let digest_only_differs = {
            let mut supplied = receipt.clone();
            supplied.receipt_digest = empty_digest();
            let mut rebuilt = expected;
            rebuilt.receipt_digest = empty_digest();
            supplied == rebuilt
        };
        return Err(fault(
            if digest_only_differs {
                SucceedingSopReviewAdmissionFaultCode::InvalidDigest
            } else {
                SucceedingSopReviewAdmissionFaultCode::InvalidCorrespondence
            },
            "admission receipt differs from the exact request",
        ));
    }
    Ok(())
}

pub fn succeeding_sop_reviewer_policy_digest(
    policy: &SucceedingSopReviewerPolicy,
) -> Result<ContentDigest, SucceedingSopReviewAdmissionFault> {
    let mut body = policy.clone();
    body.policy_digest = empty_digest();
    sha256_form(POLICY_DOMAIN, &body)
}

pub fn succeeding_sop_source_preservation_digest(
    preservation: &SucceedingSopSourcePreservationRecord,
) -> Result<ContentDigest, SucceedingSopReviewAdmissionFault> {
    let mut body = preservation.clone();
    body.preservation_digest = empty_digest();
    sha256_form(PRESERVATION_DOMAIN, &body)
}

pub fn succeeding_sop_review_payload_digest(
    payload: &SucceedingSopReviewPayload,
) -> Result<ContentDigest, SucceedingSopReviewAdmissionFault> {
    let mut body = payload.clone();
    body.payload_digest = empty_digest();
    sha256_form(PAYLOAD_DOMAIN, &body)
}

pub fn succeeding_sop_review_payload_bytes(
    payload: &SucceedingSopReviewPayload,
) -> Result<Vec<u8>, SucceedingSopReviewAdmissionFault> {
    validate_review_payload_shape(payload)?;
    serde_json::to_vec(payload).map_err(machine_fault)
}

pub fn succeeding_sop_review_admission_request_digest(
    request: &SucceedingSopReviewAdmissionRequest,
) -> Result<ContentDigest, SucceedingSopReviewAdmissionFault> {
    sha256_form(REQUEST_DOMAIN, request)
}

pub fn succeeding_sop_review_admission_receipt_digest(
    receipt: &SucceedingSopReviewAdmissionReceipt,
) -> Result<ContentDigest, SucceedingSopReviewAdmissionFault> {
    let mut body = receipt.clone();
    body.receipt_digest = empty_digest();
    sha256_form(RECEIPT_DOMAIN, &body)
}

pub fn to_succeeding_sop_review_admission_request_machine_form(
    request: &SucceedingSopReviewAdmissionRequest,
) -> Result<String, SucceedingSopReviewAdmissionFault> {
    validate_succeeding_sop_review_admission_request(request)?;
    machine_form(request)
}

pub fn from_succeeding_sop_review_admission_request_machine_form(
    value: &str,
) -> Result<SucceedingSopReviewAdmissionRequest, SucceedingSopReviewAdmissionFault> {
    validate_machine_form_bound(value)?;
    let request = serde_json::from_str(value).map_err(machine_fault)?;
    validate_succeeding_sop_review_admission_request(&request)?;
    Ok(request)
}

pub fn to_succeeding_sop_review_admission_receipt_machine_form(
    receipt: &SucceedingSopReviewAdmissionReceipt,
) -> Result<String, SucceedingSopReviewAdmissionFault> {
    validate_succeeding_sop_review_admission_receipt(receipt)?;
    machine_form(receipt)
}

pub fn from_succeeding_sop_review_admission_receipt_machine_form(
    value: &str,
) -> Result<SucceedingSopReviewAdmissionReceipt, SucceedingSopReviewAdmissionFault> {
    validate_machine_form_bound(value)?;
    let receipt = serde_json::from_str(value).map_err(machine_fault)?;
    validate_succeeding_sop_review_admission_receipt(&receipt)?;
    Ok(receipt)
}

fn validate_reviewer_policy(
    policy: &SucceedingSopReviewerPolicy,
) -> Result<(), SucceedingSopReviewAdmissionFault> {
    if policy.profile != SUCCEEDING_SOP_REVIEWER_POLICY_PROFILE
        || policy.allowed_proposal_profile != SUCCEEDING_SOP_PROPOSAL_PROFILE
    {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidPolicy,
            "reviewer policy profile or proposal scope differs",
        ));
    }
    if policy.satisfaction_signature_protocol_uuid
        != SUCCEEDING_SOP_SATISFACTION_SIGNATURE_PROTOCOL_UUID
    {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidProtocol,
            "reviewer policy protocol differs",
        ));
    }
    if policy.policy_ref == policy.reviewer_ref {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidIdentity,
            "reviewer and policy identities collide",
        ));
    }
    validate_evidence(
        &policy.governance_evidence_refs,
        MAX_POLICY_EVIDENCE_REFS,
        "policy governance evidence",
    )?;
    decode_fixed_hex::<32>(&policy.verifying_key_hex, "reviewer verifying key")?;
    if policy.non_authority != SUCCEEDING_SOP_REVIEW_ADMISSION_NON_AUTHORITY {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidAuthority,
            "reviewer policy non-authority differs",
        ));
    }
    validate_digest(&policy.policy_digest, "policy digest")?;
    if policy.policy_digest != succeeding_sop_reviewer_policy_digest(policy)? {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidDigest,
            "reviewer policy digest differs",
        ));
    }
    Ok(())
}

fn validate_identity_separation(
    request: &SucceedingSopReviewAdmissionRequest,
) -> Result<(), SucceedingSopReviewAdmissionFault> {
    let proposal = &request.proposal_verification.proposal;
    let policy = &request.reviewer_policy;
    let preservation = &request.source_preservation;
    let reserved = [
        &request.admission_id,
        &proposal.proposal_ref,
        &proposal.author_ref,
        &request.proposal_verification.verifier_ref,
        &proposal.lifecycle_ref,
        &proposal.plan_ref,
        &proposal.objective_ref,
        &proposal.selected_step_ref,
        &proposal.selected_attempt_ref,
        &proposal.predecessor_sop_revision_ref,
        &preservation.preservation_ref,
        &preservation.source_snapshot_ref,
    ];
    if reserved.contains(&&policy.reviewer_ref)
        || reserved.contains(&&policy.policy_ref)
        || policy.reviewer_ref == policy.policy_ref
        || request.admission_id == preservation.preservation_ref
        || request.admission_id == preservation.source_snapshot_ref
        || preservation.preservation_ref == preservation.source_snapshot_ref
    {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidIdentity,
            "review admission identities collide",
        ));
    }
    Ok(())
}

fn validate_source_preservation(
    verification: &SucceedingSopVerificationReceipt,
    preservation: &SucceedingSopSourcePreservationRecord,
) -> Result<(), SucceedingSopReviewAdmissionFault> {
    let proposal = &verification.proposal;
    if preservation.profile != SUCCEEDING_SOP_SOURCE_PRESERVATION_PROFILE
        || !preservation.preserved
        || !preservation.immutable
        || preservation.source_subject != proposal.source_subject
        || preservation.source_sha256 != proposal.source_sha256
        || preservation.source_bytes != proposal.source_text.len() as u64
        || preservation.proposal_digest != proposal.proposal_digest
    {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidPreservation,
            "source preservation correspondence differs",
        ));
    }
    validate_source_path(&preservation.source_path)?;
    validate_evidence(
        &preservation.evidence_refs,
        MAX_PRESERVATION_EVIDENCE_REFS,
        "source preservation evidence",
    )?;
    validate_digest(&preservation.preservation_digest, "preservation digest")?;
    if preservation.preservation_digest != succeeding_sop_source_preservation_digest(preservation)?
    {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidDigest,
            "source preservation digest differs",
        ));
    }
    Ok(())
}

fn validate_source_path(value: &str) -> Result<(), SucceedingSopReviewAdmissionFault> {
    let segments = value.split('/').collect::<Vec<_>>();
    let invalid = value.is_empty()
        || value.len() > MAX_SOURCE_PATH_BYTES
        || value.starts_with('/')
        || value.contains('\\')
        || value.contains(':')
        || value.chars().any(char::is_control)
        || !value.ends_with(".sop")
        || segments.first().copied() != Some("source_documents")
        || segments.len() < 3
        || segments
            .iter()
            .any(|segment| segment.is_empty() || *segment == "." || *segment == "..");
    if invalid {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidPath,
            "source preservation path differs",
        ));
    }
    Ok(())
}

fn validate_review_payload(
    request: &SucceedingSopReviewAdmissionRequest,
) -> Result<(), SucceedingSopReviewAdmissionFault> {
    let payload = &request.satisfaction_signature.payload;
    validate_review_payload_shape(payload)?;
    let proposal = &request.proposal_verification.proposal;
    let policy = &request.reviewer_policy;
    let preservation = &request.source_preservation;
    if request.satisfaction_signature.profile != SUCCEEDING_SOP_SATISFACTION_SIGNATURE_PROFILE
        || payload.policy_ref != policy.policy_ref
        || payload.policy_digest != policy.policy_digest
        || payload.reviewer_ref != policy.reviewer_ref
        || payload.author_ref != proposal.author_ref
        || payload.proposal_ref != proposal.proposal_ref
        || payload.request_digest != proposal.request_digest
        || payload.proposal_digest != proposal.proposal_digest
        || payload.verification_digest != request.proposal_verification.verification_digest
        || payload.source_subject != proposal.source_subject
        || payload.source_sha256 != proposal.source_sha256
        || payload.source_bytes != proposal.source_text.len() as u64
        || payload.unresolved_frontier != proposal.unresolved_frontier
        || payload.preservation_ref != preservation.preservation_ref
        || payload.preservation_digest != preservation.preservation_digest
    {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidCorrespondence,
            "review payload differs from policy proposal or preservation",
        ));
    }
    Ok(())
}

fn validate_review_payload_shape(
    payload: &SucceedingSopReviewPayload,
) -> Result<(), SucceedingSopReviewAdmissionFault> {
    if payload.profile != SUCCEEDING_SOP_REVIEW_PAYLOAD_PROFILE {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidProfile,
            "review payload profile differs",
        ));
    }
    if payload.satisfaction_signature_protocol_uuid
        != SUCCEEDING_SOP_SATISFACTION_SIGNATURE_PROTOCOL_UUID
    {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidProtocol,
            "review payload protocol differs",
        ));
    }
    if payload.reviewer_ref == payload.author_ref
        || payload.review_checks != required_review_checks()
    {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidReview,
            "review identity decision or checks differ",
        ));
    }
    validate_evidence(
        &payload.review_evidence_refs,
        MAX_REVIEW_EVIDENCE_REFS,
        "review evidence",
    )?;
    validate_digest(&payload.policy_digest, "review policy digest")?;
    validate_digest(&payload.request_digest, "review request digest")?;
    validate_digest(&payload.proposal_digest, "review proposal digest")?;
    validate_digest(&payload.verification_digest, "review verification digest")?;
    validate_digest(&payload.source_sha256, "review source digest")?;
    validate_digest(&payload.preservation_digest, "review preservation digest")?;
    validate_digest(&payload.payload_digest, "review payload digest")?;
    if payload.payload_digest != succeeding_sop_review_payload_digest(payload)? {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidDigest,
            "review payload digest differs",
        ));
    }
    Ok(())
}

fn validate_signature(
    request: &SucceedingSopReviewAdmissionRequest,
) -> Result<(), SucceedingSopReviewAdmissionFault> {
    let key_bytes = decode_fixed_hex::<32>(
        &request.reviewer_policy.verifying_key_hex,
        "reviewer verifying key",
    )?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
        fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidSignature,
            "reviewer verifying key refused",
        )
    })?;
    let signature_bytes = decode_fixed_hex::<64>(
        &request.satisfaction_signature.signature_hex,
        "satisfaction signature",
    )?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(
            &succeeding_sop_review_payload_bytes(&request.satisfaction_signature.payload)?,
            &signature,
        )
        .map_err(|_| {
            fault(
                SucceedingSopReviewAdmissionFaultCode::InvalidSignature,
                "satisfaction signature refused",
            )
        })
}

fn build_receipt(
    request: &SucceedingSopReviewAdmissionRequest,
) -> Result<SucceedingSopReviewAdmissionReceipt, SucceedingSopReviewAdmissionFault> {
    let proposal = &request.proposal_verification.proposal;
    let mut receipt = SucceedingSopReviewAdmissionReceipt {
        profile: SUCCEEDING_SOP_REVIEW_ADMISSION_RECEIPT_PROFILE.to_owned(),
        request: request.clone(),
        admission_ref: request.admission_id.clone(),
        proposal_ref: proposal.proposal_ref.clone(),
        reviewer_ref: request.reviewer_policy.reviewer_ref.clone(),
        policy_ref: request.reviewer_policy.policy_ref.clone(),
        preservation_ref: request.source_preservation.preservation_ref.clone(),
        satisfaction_signature_protocol_uuid: SUCCEEDING_SOP_SATISFACTION_SIGNATURE_PROTOCOL_UUID
            .to_owned(),
        policy_use_status: request.reviewer_policy.use_status,
        status:
            SucceedingSopReviewAdmissionStatus::CryptographicallyVerifiedAwaitingPhysicalActivation,
        authority: SucceedingSopReviewAdmissionAuthority::ReviewSignatureCorrespondenceOnly,
        cryptographic_signature_verified: true,
        structural_reviewer_independence_verified: true,
        source_preservation_correspondence_verified: true,
        semantic_truth_proved: false,
        policy_governance_proved: false,
        physical_contact: false,
        physical_activation_eligible: false,
        verified_checks: required_verified_checks(),
        activation_obligations: required_activation_obligations(),
        policy_digest: request.reviewer_policy.policy_digest.clone(),
        preservation_digest: request.source_preservation.preservation_digest.clone(),
        review_payload_digest: request
            .satisfaction_signature
            .payload
            .payload_digest
            .clone(),
        request_digest: succeeding_sop_review_admission_request_digest(request)?,
        proposal_digest: proposal.proposal_digest.clone(),
        verification_digest: request.proposal_verification.verification_digest.clone(),
        non_authority: SUCCEEDING_SOP_REVIEW_ADMISSION_NON_AUTHORITY.to_owned(),
        receipt_digest: empty_digest(),
    };
    receipt.receipt_digest = succeeding_sop_review_admission_receipt_digest(&receipt)?;
    Ok(receipt)
}

fn validate_evidence(
    values: &BTreeSet<SemanticId>,
    maximum: usize,
    label: &str,
) -> Result<(), SucceedingSopReviewAdmissionFault> {
    if values.is_empty() || values.len() > maximum {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidEvidence,
            format!("{label} count differs"),
        ));
    }
    Ok(())
}

fn required_review_checks() -> BTreeSet<String> {
    SUCCEEDING_SOP_REVIEW_CHECKS
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn required_activation_obligations() -> BTreeSet<String> {
    SUCCEEDING_SOP_ACTIVATION_OBLIGATIONS
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn required_verified_checks() -> BTreeSet<String> {
    SUCCEEDING_SOP_REVIEW_ADMISSION_VERIFIED_CHECKS
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn validate_digest(
    digest: &ContentDigest,
    label: &str,
) -> Result<(), SucceedingSopReviewAdmissionFault> {
    let valid = digest.algorithm == "sha256"
        && digest.value.len() == 64
        && digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidDigest,
            format!("{label} must be lower-case SHA256"),
        ));
    }
    Ok(())
}

fn sha256_form<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<ContentDigest, SucceedingSopReviewAdmissionFault> {
    let body = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + body.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&body);
    Ok(sha256_bytes(&bytes))
}

fn machine_form<T: Serialize>(value: &T) -> Result<String, SucceedingSopReviewAdmissionFault> {
    let output = serde_json::to_string(value).map_err(machine_fault)?;
    validate_machine_form_bound(&output)?;
    Ok(output)
}

fn validate_machine_form_bound(value: &str) -> Result<(), SucceedingSopReviewAdmissionFault> {
    if value.is_empty() || value.len() > SUCCEEDING_SOP_REVIEW_ADMISSION_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidBound,
            "review admission machine form bound differs",
        ));
    }
    Ok(())
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn decode_fixed_hex<const N: usize>(
    value: &str,
    label: &str,
) -> Result<[u8; N], SucceedingSopReviewAdmissionFault> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
    {
        return Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidSignature,
            format!("{label} form differs"),
        ));
    }
    let mut output = [0_u8; N];
    let bytes = value.as_bytes();
    for index in 0..N {
        output[index] =
            (decode_nibble(bytes[index * 2])? << 4) | decode_nibble(bytes[index * 2 + 1])?;
    }
    Ok(output)
}

fn decode_nibble(byte: u8) -> Result<u8, SucceedingSopReviewAdmissionFault> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(fault(
            SucceedingSopReviewAdmissionFaultCode::InvalidSignature,
            "hexadecimal value differs",
        )),
    }
}

fn machine_fault(error: serde_json::Error) -> SucceedingSopReviewAdmissionFault {
    fault(
        SucceedingSopReviewAdmissionFaultCode::InvalidMachineForm,
        format!("succeeding SOP review admission machine form failed: {error}"),
    )
}

fn fault(
    code: SucceedingSopReviewAdmissionFaultCode,
    message: impl Into<String>,
) -> SucceedingSopReviewAdmissionFault {
    SucceedingSopReviewAdmissionFault {
        code,
        message: message.into(),
    }
}
