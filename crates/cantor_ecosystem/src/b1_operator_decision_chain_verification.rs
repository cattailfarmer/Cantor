//! A5 full-chain operator-decision correspondence, never live authorization.
//!
//! Replays unchanged A4 and legacy decision verifiers. A legacy signature binds
//! its policy/request, not the later A4 witness. No clock, signer or effect runner.
use crate::{
    B1CDriveOperatorDecisionEnvelope, B1CDriveOperatorDecisionFault,
    B1CDriveOperatorDecisionFaultCode, B1CDriveOperatorDecisionKind,
    B1CDriveOperatorDecisionPolicy, B1CDriveOperatorDecisionRequest,
    B1CDriveOperatorDecisionVerification, B1OaprCandidateOrigin, B1OaprConfidentiality,
    B1OaprRequest, KcvInputClass, KrvStatusAssertion, TWV_AUTHORITY, TWV_STATUS, TwvEffectAccount,
    TwvPredecessor, TwvVerificationReceipt, TwvVerificationRequest, compile_b1oapr_packet,
    from_b1_cdrive_operator_decision_envelope_machine_form, to_b1oapr_packet_machine_form,
    validate_b1_cdrive_operator_decision_policy, verify_b1_cdrive_operator_decision,
    verify_twv_time_witness,
};
use cantor_core::{ContentDigest, sha256_bytes};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::fmt;

pub const ODCV_REQUEST_PROFILE: &str = "cantor-b1-operator-decision-chain-request/0.1";
pub const ODCV_RECEIPT_PROFILE: &str = "cantor-b1-operator-decision-chain-receipt/0.1";
pub const ODCV_EVIDENCE_PROFILE: &str = "cantor-b1-operator-decision-chain-evidence/0.1";
pub const ODCV_STATUS: &str = "operator_decision_chain_and_supplied_interval_correspondence_verified_live_authorization_and_execution_unresolved";
pub const ODCV_AUTHORITY: &str = "supplied_operator_decision_chain_correspondence_only";
pub const ODCV_SOURCE_SNAPSHOT_UUID: &str = "dc4d390b-953b-415f-9fd9-2bd6f4838e19";
pub const ODCV_CANONICAL_UUID: &str = "ee06ff6d-ba10-4a02-a157-9533d734912e";
pub const ODCV_SIGNATURE_UUID: &str = "b40dd6f3-9adc-4bd4-b87d-154e92668106";
pub const ODCV_SOURCE_CUSTODY_COMMIT: &str = "a2bcb61130c60244a1bc6ba98a00a652c657ed40";
pub const ODCV_FORMATION_COMMIT: &str = "cf757a4a73ca274722ec62b6953b7aee29d15422";
pub const ODCV_FORMATION_BOOKEND_COMMIT: &str = "4d814e1c72b3b0a44b159986e08e3d3f509dea18";
pub const ODCV_A4_IMPLEMENTATION_COMMIT: &str = "bc212c53a62cf99a3ff0c27544be5e5f4d6cf46e";
pub const ODCV_A4_BOOKEND_COMMIT: &str = "7eeadad031c432648942d8725edb2d56554c251a";
pub const ODCV_A4_PROOF_UUID: &str = "851b534f-6542-43c6-b4d3-472dd0bd70b6";
pub const ODCV_LEGACY_IMPLEMENTATION_COMMIT: &str = "9aaaab269836b8265c74ac9c46c690493c9fe746";
pub const ODCV_LEGACY_BOOKEND_COMMIT: &str = "bfc068ff93ef781cab3d58e7f3fce0be21ac0ccc";
pub const ODCV_LEGACY_PROOF_UUID: &str = "5e48d1ed-a769-46b1-b7c0-a52fe7db5b2b";
pub const ODCV_MAX_FORM_BYTES: usize = 1_048_576;
pub const ODCV_MAX_EVIDENCE_BYTES: u64 = 16_777_216;
pub const ODCV_MAX_EVIDENCE_REFERENCES: usize = 48;
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_FIELDS: usize = 4096;
const MAX_TEXT_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OdcvIntervalRelation {
    BeforeDecisionInterval,
    WithinDecisionInterval,
    AfterDecisionInterval,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OdcvVerificationRequest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_custody_commit: String,
    pub formation_commit: String,
    pub formation_bookend_commit: String,
    pub a4_implementation_commit: String,
    pub a4_bookend_commit: String,
    pub a4_proof_uuid: String,
    pub legacy_implementation_commit: String,
    pub legacy_bookend_commit: String,
    pub legacy_proof_uuid: String,
    pub predecessor_request_sha256: ContentDigest,
    pub predecessor_packet_sha256: ContentDigest,
    pub predecessor_verification_sha256: ContentDigest,
    pub a1_policy_envelope_raw_sha256: ContentDigest,
    pub a1_verification_request_sha256: ContentDigest,
    pub a1_receipt_sha256: ContentDigest,
    pub a2_custody_attestation_raw_sha256: ContentDigest,
    pub a2_verification_request_sha256: ContentDigest,
    pub a2_receipt_sha256: ContentDigest,
    pub a3_revocation_snapshot_raw_sha256: ContentDigest,
    pub a3_verification_request_sha256: ContentDigest,
    pub a3_receipt_sha256: ContentDigest,
    pub a4_time_witness_receipt_raw_sha256: ContentDigest,
    pub a4_verification_request_sha256: ContentDigest,
    pub a4_receipt_sha256: ContentDigest,
    pub authority_packet_request: B1OaprRequest,
    pub authority_packet_request_sha256: ContentDigest,
    pub authority_packet_sha256: ContentDigest,
    pub a5_candidate_uuid: String,
    pub a5_descriptor_sha256: ContentDigest,
    pub operator_decision_policy_sha256: ContentDigest,
    pub operator_decision_request_sha256: ContentDigest,
    pub operator_decision_envelope_bytes: u64,
    pub operator_decision_envelope_raw_sha256: ContentDigest,
    pub expected_policy_revision_uuid: String,
    pub expected_decision_uuid: String,
    pub expected_decision_kind: B1CDriveOperatorDecisionKind,
    pub expected_external_decision_identity: String,
    pub input_class: KcvInputClass,
    pub evidence_references: Vec<String>,
    pub maximum_attempts: u8,
    pub automatic_retry_count: u8,
    pub automatic_cleanup_count: u8,
    pub request_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OdcvVerificationReceipt {
    pub profile: String,
    pub status: String,
    pub authority: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_custody_commit: String,
    pub formation_commit: String,
    pub formation_bookend_commit: String,
    pub a4_implementation_commit: String,
    pub a4_bookend_commit: String,
    pub a4_proof_uuid: String,
    pub legacy_implementation_commit: String,
    pub legacy_bookend_commit: String,
    pub legacy_proof_uuid: String,
    pub predecessor_request_sha256: ContentDigest,
    pub predecessor_packet_sha256: ContentDigest,
    pub predecessor_verification_sha256: ContentDigest,
    pub a1_policy_envelope_raw_sha256: ContentDigest,
    pub a1_verification_request_sha256: ContentDigest,
    pub a1_receipt_sha256: ContentDigest,
    pub a2_custody_attestation_raw_sha256: ContentDigest,
    pub a2_verification_request_sha256: ContentDigest,
    pub a2_receipt_sha256: ContentDigest,
    pub a3_revocation_snapshot_raw_sha256: ContentDigest,
    pub a3_verification_request_sha256: ContentDigest,
    pub a3_receipt_sha256: ContentDigest,
    pub a4_time_witness_receipt_raw_sha256: ContentDigest,
    pub a4_verification_request_sha256: ContentDigest,
    pub a4_receipt_sha256: ContentDigest,
    pub authority_packet_request_sha256: ContentDigest,
    pub authority_packet_sha256: ContentDigest,
    pub request_sha256: ContentDigest,
    pub a5_candidate_uuid: String,
    pub a5_descriptor_sha256: ContentDigest,
    pub operator_decision_policy_sha256: ContentDigest,
    pub operator_decision_request_sha256: ContentDigest,
    pub operator_decision_envelope_bytes: u64,
    pub operator_decision_envelope_raw_sha256: ContentDigest,
    pub policy_uuid: String,
    pub policy_revision_uuid: String,
    pub principal: String,
    pub role: String,
    pub subject: String,
    pub target_policy_key_fingerprint_sha256: ContentDigest,
    pub legacy_policy_key_fingerprint_sha256: ContentDigest,
    pub decision_uuid: String,
    pub decision_kind: B1CDriveOperatorDecisionKind,
    pub external_decision_identity: String,
    pub observed_unix_ms: u64,
    pub issued_at_unix_millis: u64,
    pub expires_at_unix_millis: u64,
    pub comparison_outcome: OdcvIntervalRelation,
    pub supplied_a3_status_assertion: KrvStatusAssertion,
    pub payload_sha256: ContentDigest,
    pub envelope_sha256: ContentDigest,
    pub signature_sha256: ContentDigest,
    pub legacy_verification_sha256: ContentDigest,
    pub input_class: KcvInputClass,
    pub fixture_only: bool,
    pub maximum_attempts: u8,
    pub automatic_retry_count: u8,
    pub automatic_cleanup_count: u8,
    pub packet_replayed: bool,
    pub a1_correspondence_receipt_verified: bool,
    pub a2_correspondence_receipt_verified: bool,
    pub a3_correspondence_receipt_verified: bool,
    pub a4_correspondence_receipt_verified: bool,
    pub a5_candidate_bytes_matched: bool,
    pub descriptor_correspondence_verified: bool,
    pub subject_lineage_correspondence_verified: bool,
    pub decision_policy_key_correspondence_verified: bool,
    pub decision_policy_artifact_bindings_verified: bool,
    pub decision_request_correspondence_verified: bool,
    pub decision_structure_verified: bool,
    pub decision_signature_correspondence_verified: bool,
    pub decision_expectations_verified: bool,
    pub supplied_decision_interval_comparison_verified: bool,
    pub production_authority_claimed: bool,
    pub challenge_freshness_proved: bool,
    pub replay_prevention_proved: bool,
    pub custodian_identity_proved: bool,
    pub protected_storage_proved: bool,
    pub private_key_nonexportability_proved: bool,
    pub exclusive_control_proved: bool,
    pub current_possession_proved: bool,
    pub responder_identity_proved: bool,
    pub responder_authority_proved: bool,
    pub source_completeness_proved: bool,
    pub monotonic_history_proved: bool,
    pub snapshot_freshness_proved: bool,
    pub current_time_compared: bool,
    pub policy_governance_proved: bool,
    pub key_custody_proved: bool,
    pub revocation_truth_proved: bool,
    pub current_nonexpired: bool,
    pub live_authorization_admitted: bool,
    pub fresh_observation_proved: bool,
    pub private_execution_permit_present: bool,
    pub production_broker_projection_present: bool,
    pub physical_preparation_authorized: bool,
    pub ready_for_physical_execution: bool,
    pub execution_authorized: bool,
    pub witness_identity_proved: bool,
    pub witness_authority_proved: bool,
    pub witness_freshness_proved: bool,
    pub trusted_current_time_proved: bool,
    pub decision_signer_identity_proved: bool,
    pub decision_authority_proved: bool,
    pub decision_freshness_proved: bool,
    pub decision_signature_binds_a4_lineage: bool,
    pub effect_account: TwvEffectAccount,
    pub receipt_sha256: ContentDigest,
}

/// Every borrowed receipt is replayed, never accepted as trusted authority.
pub struct OdcvPredecessor<'a> {
    pub upstream: TwvPredecessor<'a>,
    pub raw_a4_witness: &'a [u8],
    pub a4_request: &'a TwvVerificationRequest,
    pub a4_receipt: &'a TwvVerificationReceipt,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OdcvFaultCode {
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
    Key,
    Policy,
    Expectation,
    Decision,
    Interval,
    Signature,
    Receipt,
    Truth,
    Effect,
    Evidence,
    Arithmetic,
    MachineForm,
    Restart,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OdcvFault {
    pub code: OdcvFaultCode,
    pub message: String,
}
impl fmt::Display for OdcvFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}
impl std::error::Error for OdcvFault {}

pub fn verify_odcv_operator_decision(
    request: &OdcvVerificationRequest,
    predecessor: &OdcvPredecessor<'_>,
    policy: &B1CDriveOperatorDecisionPolicy,
    legacy_request: &B1CDriveOperatorDecisionRequest,
    raw_envelope: &[u8],
) -> Result<OdcvVerificationReceipt, OdcvFault> {
    validate_request_shape(request)?;
    let a4 = verify_twv_time_witness(
        predecessor.a4_request,
        &predecessor.upstream,
        predecessor.raw_a4_witness,
    )
    .map_err(predecessor_fault)?;
    if a4 != *predecessor.a4_receipt || a4.status != TWV_STATUS || a4.authority != TWV_AUTHORITY {
        return Err(fault(OdcvFaultCode::Predecessor, "A4 replay differs"));
    }
    let up = &predecessor.upstream;
    if request.predecessor_request_sha256 != up.request.request_sha256
        || request.predecessor_packet_sha256 != up.packet.packet_sha256
        || request.predecessor_verification_sha256 != up.verification.verification_sha256
        || request.a1_policy_envelope_raw_sha256 != sha256_bytes(up.raw_a1_envelope)
        || request.a1_verification_request_sha256 != up.a1_request.request_sha256
        || request.a1_receipt_sha256 != up.a1_receipt.receipt_sha256
        || request.a2_custody_attestation_raw_sha256 != sha256_bytes(up.raw_a2_attestation)
        || request.a2_verification_request_sha256 != up.a2_request.request_sha256
        || request.a2_receipt_sha256 != up.a2_receipt.receipt_sha256
        || request.a3_revocation_snapshot_raw_sha256 != sha256_bytes(up.raw_a3_snapshot)
        || request.a3_verification_request_sha256 != up.a3_request.request_sha256
        || request.a3_receipt_sha256 != up.a3_receipt.receipt_sha256
        || request.a4_time_witness_receipt_raw_sha256 != sha256_bytes(predecessor.raw_a4_witness)
        || request.a4_verification_request_sha256 != predecessor.a4_request.request_sha256
        || request.a4_receipt_sha256 != a4.receipt_sha256
    {
        return Err(fault(
            OdcvFaultCode::Predecessor,
            "upstream raw or receipt binding differs",
        ));
    }
    let first =
        compile_b1oapr_packet(&request.authority_packet_request).map_err(predecessor_fault)?;
    let second =
        compile_b1oapr_packet(&request.authority_packet_request).map_err(predecessor_fault)?;
    if first != second
        || to_b1oapr_packet_machine_form(&request.authority_packet_request, &first)
            .map_err(predecessor_fault)?
            != to_b1oapr_packet_machine_form(&request.authority_packet_request, &second)
                .map_err(predecessor_fault)?
        || request.authority_packet_request_sha256
            != request.authority_packet_request.request_sha256
        || request.authority_packet_sha256 != first.packet_sha256
    {
        return Err(fault(
            OdcvFaultCode::Digest,
            "current packet reconstruction differs",
        ));
    }
    validate_packet_transition(
        &predecessor.a4_request.authority_packet_request,
        &request.authority_packet_request,
        &a4,
    )?;
    let descriptor = &request.authority_packet_request.descriptors[4];
    if descriptor.ordinal != 5
        || descriptor.authority_name != "live_decision"
        || descriptor.artifact_kind != "operator_decision_envelope_candidate"
        || descriptor.required_verifier_profile != "live-operator-decision-verifier/0.1"
        || descriptor.confidentiality != B1OaprConfidentiality::PublicMetadata
        || descriptor.dependency_ordinal != Some(4)
        || descriptor.candidate_uuid != request.a5_candidate_uuid
        || descriptor.descriptor_sha256 != request.a5_descriptor_sha256
    {
        return Err(fault(OdcvFaultCode::Coordinate, "A5 descriptor differs"));
    }
    let fixture = is_fixture(request.input_class);
    let origin = if fixture {
        B1OaprCandidateOrigin::DeterministicFixtureCandidate
    } else {
        B1OaprCandidateOrigin::ExternallySuppliedCandidate
    };
    if descriptor.origin != origin || descriptor.fixture_only != fixture {
        return Err(fault(
            OdcvFaultCode::Identity,
            "A5 descriptor class differs",
        ));
    }
    if raw_envelope.is_empty() || raw_envelope.len() > ODCV_MAX_FORM_BYTES {
        return Err(fault(
            OdcvFaultCode::Size,
            "raw decision envelope exceeds bound",
        ));
    }
    // Byte identity precedes parsing, including all imported decision validation.
    if request.operator_decision_envelope_bytes != raw_envelope.len() as u64
        || descriptor.declared_bytes != raw_envelope.len() as u64
        || request.operator_decision_envelope_raw_sha256 != sha256_bytes(raw_envelope)
        || descriptor.content_sha256 != request.operator_decision_envelope_raw_sha256
    {
        return Err(fault(
            OdcvFaultCode::RawBytes,
            "A5 raw envelope identity differs",
        ));
    }
    bounded_value(policy)?;
    bounded_value(legacy_request)?;
    validate_b1_cdrive_operator_decision_policy(policy).map_err(legacy_fault)?;
    let a1 = &up.a1_envelope.payload;
    if policy.policy_uuid != a1.policy_uuid
        || policy.principal != a1.issuer_principal
        || policy.role != a1.issuer_role
        || policy.subject != a1.subject
        || request.expected_policy_revision_uuid != a1.revision_uuid
    {
        return Err(fault(
            OdcvFaultCode::Policy,
            "policy identity or A1 revision differs",
        ));
    }
    // Fingerprint domains are intentionally distinct. Compare decoded key bytes.
    if decode_fixed_hex::<32>(&policy.verifying_key_hex, "legacy key")?
        != decode_fixed_hex::<32>(&up.a1_envelope.verifying_key_hex, "A1 key")?
    {
        return Err(fault(
            OdcvFaultCode::Key,
            "legacy and A1 decoded keys differ",
        ));
    }
    if policy.policy_governance_artifact_sha256 != sha256_bytes(up.raw_a1_envelope)
        || policy.revocation_list_artifact_sha256 != sha256_bytes(up.raw_a3_snapshot)
        || request.operator_decision_policy_sha256 != policy.policy_sha256
        || request.operator_decision_request_sha256 != legacy_request.request_sha256
    {
        return Err(fault(
            OdcvFaultCode::Policy,
            "policy raw artifacts or decision request differ",
        ));
    }
    let text = std::str::from_utf8(raw_envelope).map_err(machine_fault)?;
    let envelope =
        from_b1_cdrive_operator_decision_envelope_machine_form(legacy_request, policy, text)
            .map_err(legacy_fault)?;
    let legacy = verify_b1_cdrive_operator_decision(legacy_request, policy, &envelope)
        .map_err(legacy_fault)?;
    let payload = &envelope.payload;
    if policy.fixture_only != fixture
        || envelope.fixture_only != fixture
        || payload.fixture_only != fixture
    {
        return Err(fault(
            OdcvFaultCode::Identity,
            "A5 policy or envelope class differs",
        ));
    }
    let class = match payload.decision_kind {
        B1CDriveOperatorDecisionKind::Authorize => "authorize_once",
        B1CDriveOperatorDecisionKind::Reject => "reject",
    };
    if !a1
        .permitted_decision_classes
        .iter()
        .any(|allowed| allowed == class)
        || payload.decision_uuid != request.expected_decision_uuid
        || payload.decision_kind != request.expected_decision_kind
        || payload.external_decision_identity != request.expected_external_decision_identity
    {
        return Err(fault(
            OdcvFaultCode::Expectation,
            "decision class or explicit expectation differs",
        ));
    }
    let receipt = build_receipt(request, predecessor, policy, &envelope, &legacy)?;
    validate_odcv_receipt_fields(&receipt)?;
    Ok(receipt)
}

fn validate_request_shape(request: &OdcvVerificationRequest) -> Result<(), OdcvFault> {
    bounded_value(request)?;
    if request.profile != ODCV_REQUEST_PROFILE {
        return Err(fault(OdcvFaultCode::Profile, "request profile differs"));
    }
    if request.source_snapshot_uuid != ODCV_SOURCE_SNAPSHOT_UUID
        || request.canonical_uuid != ODCV_CANONICAL_UUID
        || request.signature_uuid != ODCV_SIGNATURE_UUID
        || request.source_custody_commit != ODCV_SOURCE_CUSTODY_COMMIT
        || request.formation_commit != ODCV_FORMATION_COMMIT
        || request.formation_bookend_commit != ODCV_FORMATION_BOOKEND_COMMIT
        || request.a4_implementation_commit != ODCV_A4_IMPLEMENTATION_COMMIT
        || request.a4_bookend_commit != ODCV_A4_BOOKEND_COMMIT
        || request.a4_proof_uuid != ODCV_A4_PROOF_UUID
        || request.legacy_implementation_commit != ODCV_LEGACY_IMPLEMENTATION_COMMIT
        || request.legacy_bookend_commit != ODCV_LEGACY_BOOKEND_COMMIT
        || request.legacy_proof_uuid != ODCV_LEGACY_PROOF_UUID
    {
        return Err(fault(
            OdcvFaultCode::Lineage,
            "request governance lineage differs",
        ));
    }
    if !valid_uuid(&request.a5_candidate_uuid)
        || !valid_uuid(&request.expected_policy_revision_uuid)
        || !valid_uuid(&request.expected_decision_uuid)
        || !safe_text(&request.expected_external_decision_identity)
    {
        return Err(fault(
            OdcvFaultCode::Expectation,
            "decision expectation shape differs",
        ));
    }
    if request.evidence_references.is_empty()
        || request.evidence_references.len() > ODCV_MAX_EVIDENCE_REFERENCES
        || request.evidence_references.iter().any(|s| !safe_text(s))
        || request
            .evidence_references
            .iter()
            .enumerate()
            .any(|(i, v)| request.evidence_references[..i].contains(v))
    {
        return Err(fault(
            OdcvFaultCode::Evidence,
            "opaque evidence reference bounds differ",
        ));
    }
    if request.maximum_attempts != 1
        || request.automatic_retry_count != 0
        || request.automatic_cleanup_count != 0
    {
        return Err(fault(
            OdcvFaultCode::Effect,
            "attempt retry cleanup policy differs",
        ));
    }
    if request.request_sha256 != odcv_request_digest(request)? {
        return Err(fault(OdcvFaultCode::Digest, "request self digest differs"));
    }
    Ok(())
}
fn validate_packet_transition(
    prior: &B1OaprRequest,
    current: &B1OaprRequest,
    receipt: &TwvVerificationReceipt,
) -> Result<(), OdcvFault> {
    if prior.descriptors.len() != 9 || current.descriptors.len() != 9 {
        return Err(fault(
            OdcvFaultCode::Coordinate,
            "packet coordinate count differs",
        ));
    }
    if prior.descriptors[..4] != current.descriptors[..4]
        || prior.descriptors[5..] != current.descriptors[5..]
        || current.descriptors[3].candidate_uuid != receipt.a4_candidate_uuid
        || current.descriptors[3].descriptor_sha256 != receipt.a4_descriptor_sha256
        || current.descriptors[3].content_sha256 != receipt.time_witness_receipt_raw_sha256
    {
        return Err(fault(
            OdcvFaultCode::Dependency,
            "A5 transition changes upstream or downstream",
        ));
    }
    let mut normalized = current.clone();
    normalized.descriptors[4] = prior.descriptors[4].clone();
    normalized.request_sha256 = prior.request_sha256.clone();
    if normalized != *prior {
        return Err(fault(
            OdcvFaultCode::Lineage,
            "A5 transition changes more than descriptor",
        ));
    }
    Ok(())
}
/// Pure comparison of supplied integers. It is not a current-time validity test.
pub fn odcv_compare_supplied_interval(
    observed: u64,
    issued: u64,
    expires: u64,
) -> Result<OdcvIntervalRelation, OdcvFault> {
    if issued >= expires {
        return Err(fault(
            OdcvFaultCode::Interval,
            "decision interval is empty or inverted",
        ));
    }
    Ok(if observed < issued {
        OdcvIntervalRelation::BeforeDecisionInterval
    } else if observed < expires {
        OdcvIntervalRelation::WithinDecisionInterval
    } else {
        OdcvIntervalRelation::AfterDecisionInterval
    })
}
fn build_receipt(
    request: &OdcvVerificationRequest,
    predecessor: &OdcvPredecessor<'_>,
    policy: &B1CDriveOperatorDecisionPolicy,
    envelope: &B1CDriveOperatorDecisionEnvelope,
    legacy: &B1CDriveOperatorDecisionVerification,
) -> Result<OdcvVerificationReceipt, OdcvFault> {
    let payload = &envelope.payload;
    let a4 = predecessor.a4_receipt;
    let mut receipt = OdcvVerificationReceipt {
        profile: ODCV_RECEIPT_PROFILE.to_owned(),
        status: ODCV_STATUS.to_owned(),
        authority: ODCV_AUTHORITY.to_owned(),
        source_snapshot_uuid: request.source_snapshot_uuid.clone(),
        canonical_uuid: request.canonical_uuid.clone(),
        signature_uuid: request.signature_uuid.clone(),
        source_custody_commit: request.source_custody_commit.clone(),
        formation_commit: request.formation_commit.clone(),
        formation_bookend_commit: request.formation_bookend_commit.clone(),
        a4_implementation_commit: request.a4_implementation_commit.clone(),
        a4_bookend_commit: request.a4_bookend_commit.clone(),
        a4_proof_uuid: request.a4_proof_uuid.clone(),
        legacy_implementation_commit: request.legacy_implementation_commit.clone(),
        legacy_bookend_commit: request.legacy_bookend_commit.clone(),
        legacy_proof_uuid: request.legacy_proof_uuid.clone(),
        predecessor_request_sha256: request.predecessor_request_sha256.clone(),
        predecessor_packet_sha256: request.predecessor_packet_sha256.clone(),
        predecessor_verification_sha256: request.predecessor_verification_sha256.clone(),
        a1_policy_envelope_raw_sha256: request.a1_policy_envelope_raw_sha256.clone(),
        a1_verification_request_sha256: request.a1_verification_request_sha256.clone(),
        a1_receipt_sha256: request.a1_receipt_sha256.clone(),
        a2_custody_attestation_raw_sha256: request.a2_custody_attestation_raw_sha256.clone(),
        a2_verification_request_sha256: request.a2_verification_request_sha256.clone(),
        a2_receipt_sha256: request.a2_receipt_sha256.clone(),
        a3_revocation_snapshot_raw_sha256: request.a3_revocation_snapshot_raw_sha256.clone(),
        a3_verification_request_sha256: request.a3_verification_request_sha256.clone(),
        a3_receipt_sha256: request.a3_receipt_sha256.clone(),
        a4_time_witness_receipt_raw_sha256: request.a4_time_witness_receipt_raw_sha256.clone(),
        a4_verification_request_sha256: request.a4_verification_request_sha256.clone(),
        a4_receipt_sha256: request.a4_receipt_sha256.clone(),
        authority_packet_request_sha256: request.authority_packet_request_sha256.clone(),
        authority_packet_sha256: request.authority_packet_sha256.clone(),
        request_sha256: request.request_sha256.clone(),
        a5_candidate_uuid: request.a5_candidate_uuid.clone(),
        a5_descriptor_sha256: request.a5_descriptor_sha256.clone(),
        operator_decision_policy_sha256: request.operator_decision_policy_sha256.clone(),
        operator_decision_request_sha256: request.operator_decision_request_sha256.clone(),
        operator_decision_envelope_bytes: request.operator_decision_envelope_bytes,
        operator_decision_envelope_raw_sha256: request
            .operator_decision_envelope_raw_sha256
            .clone(),
        policy_uuid: policy.policy_uuid.clone(),
        policy_revision_uuid: request.expected_policy_revision_uuid.clone(),
        principal: policy.principal.clone(),
        role: policy.role.clone(),
        subject: policy.subject.clone(),
        target_policy_key_fingerprint_sha256: a4.target_policy_key_fingerprint_sha256.clone(),
        legacy_policy_key_fingerprint_sha256: policy.key_fingerprint_sha256.clone(),
        decision_uuid: payload.decision_uuid.clone(),
        decision_kind: payload.decision_kind,
        external_decision_identity: payload.external_decision_identity.clone(),
        observed_unix_ms: a4.observed_unix_ms,
        issued_at_unix_millis: payload.issued_at_unix_millis,
        expires_at_unix_millis: payload.expires_at_unix_millis,
        comparison_outcome: odcv_compare_supplied_interval(
            a4.observed_unix_ms,
            payload.issued_at_unix_millis,
            payload.expires_at_unix_millis,
        )?,
        supplied_a3_status_assertion: predecessor.upstream.a3_receipt.status_assertion,
        payload_sha256: payload.payload_sha256.clone(),
        envelope_sha256: envelope.envelope_sha256.clone(),
        signature_sha256: sha256_bytes(&decode_fixed_hex::<64>(
            &envelope.signature_hex,
            "signature",
        )?),
        legacy_verification_sha256: legacy.verification_sha256.clone(),
        input_class: request.input_class,
        fixture_only: envelope.fixture_only,
        maximum_attempts: request.maximum_attempts,
        automatic_retry_count: request.automatic_retry_count,
        automatic_cleanup_count: request.automatic_cleanup_count,
        packet_replayed: true,
        a1_correspondence_receipt_verified: true,
        a2_correspondence_receipt_verified: true,
        a3_correspondence_receipt_verified: true,
        a4_correspondence_receipt_verified: true,
        a5_candidate_bytes_matched: true,
        descriptor_correspondence_verified: true,
        subject_lineage_correspondence_verified: true,
        decision_policy_key_correspondence_verified: true,
        decision_policy_artifact_bindings_verified: true,
        decision_request_correspondence_verified: true,
        decision_structure_verified: true,
        decision_signature_correspondence_verified: true,
        decision_expectations_verified: true,
        supplied_decision_interval_comparison_verified: true,
        production_authority_claimed: false,
        challenge_freshness_proved: false,
        replay_prevention_proved: false,
        custodian_identity_proved: false,
        protected_storage_proved: false,
        private_key_nonexportability_proved: false,
        exclusive_control_proved: false,
        current_possession_proved: false,
        responder_identity_proved: false,
        responder_authority_proved: false,
        source_completeness_proved: false,
        monotonic_history_proved: false,
        snapshot_freshness_proved: false,
        current_time_compared: false,
        policy_governance_proved: false,
        key_custody_proved: false,
        revocation_truth_proved: false,
        current_nonexpired: false,
        live_authorization_admitted: false,
        fresh_observation_proved: false,
        private_execution_permit_present: false,
        production_broker_projection_present: false,
        physical_preparation_authorized: false,
        ready_for_physical_execution: false,
        execution_authorized: false,
        witness_identity_proved: false,
        witness_authority_proved: false,
        witness_freshness_proved: false,
        trusted_current_time_proved: false,
        decision_signer_identity_proved: false,
        decision_authority_proved: false,
        decision_freshness_proved: false,
        decision_signature_binds_a4_lineage: false,
        effect_account: TwvEffectAccount::default(),
        receipt_sha256: empty_digest(),
    };
    receipt.receipt_sha256 = odcv_receipt_digest(&receipt)?;
    Ok(receipt)
}
pub(crate) fn validate_odcv_receipt_fields(
    receipt: &OdcvVerificationReceipt,
) -> Result<(), OdcvFault> {
    bounded_value(receipt)?;
    if receipt.profile != ODCV_RECEIPT_PROFILE
        || receipt.status != ODCV_STATUS
        || receipt.authority != ODCV_AUTHORITY
    {
        return Err(fault(
            OdcvFaultCode::Profile,
            "receipt profile status or authority differs",
        ));
    }
    if receipt.production_authority_claimed
        || receipt.challenge_freshness_proved
        || receipt.replay_prevention_proved
        || receipt.custodian_identity_proved
        || receipt.protected_storage_proved
        || receipt.private_key_nonexportability_proved
        || receipt.exclusive_control_proved
        || receipt.current_possession_proved
        || receipt.responder_identity_proved
        || receipt.responder_authority_proved
        || receipt.source_completeness_proved
        || receipt.monotonic_history_proved
        || receipt.snapshot_freshness_proved
        || receipt.current_time_compared
        || receipt.policy_governance_proved
        || receipt.key_custody_proved
        || receipt.revocation_truth_proved
        || receipt.current_nonexpired
        || receipt.live_authorization_admitted
        || receipt.fresh_observation_proved
        || receipt.private_execution_permit_present
        || receipt.production_broker_projection_present
        || receipt.physical_preparation_authorized
        || receipt.ready_for_physical_execution
        || receipt.execution_authorized
        || receipt.witness_identity_proved
        || receipt.witness_authority_proved
        || receipt.witness_freshness_proved
        || receipt.trusted_current_time_proved
        || receipt.decision_signer_identity_proved
        || receipt.decision_authority_proved
        || receipt.decision_freshness_proved
        || receipt.decision_signature_binds_a4_lineage
    {
        return Err(fault(
            OdcvFaultCode::Truth,
            "receipt promotes authority or signed A4 coverage",
        ));
    }
    if !receipt.packet_replayed
        || !receipt.a1_correspondence_receipt_verified
        || !receipt.a2_correspondence_receipt_verified
        || !receipt.a3_correspondence_receipt_verified
        || !receipt.a4_correspondence_receipt_verified
        || !receipt.a5_candidate_bytes_matched
        || !receipt.descriptor_correspondence_verified
        || !receipt.subject_lineage_correspondence_verified
        || !receipt.decision_policy_key_correspondence_verified
        || !receipt.decision_policy_artifact_bindings_verified
        || !receipt.decision_request_correspondence_verified
        || !receipt.decision_structure_verified
        || !receipt.decision_signature_correspondence_verified
        || !receipt.decision_expectations_verified
        || !receipt.supplied_decision_interval_comparison_verified
    {
        return Err(fault(
            OdcvFaultCode::Truth,
            "receipt correspondence truth differs",
        ));
    }
    if receipt.effect_account != TwvEffectAccount::default()
        || receipt.maximum_attempts != 1
        || receipt.automatic_retry_count != 0
        || receipt.automatic_cleanup_count != 0
    {
        return Err(fault(
            OdcvFaultCode::Effect,
            "receipt effect or attempt account differs",
        ));
    }
    if receipt.receipt_sha256 != odcv_receipt_digest(receipt)? {
        return Err(fault(OdcvFaultCode::Digest, "receipt self digest differs"));
    }
    Ok(())
}
pub fn validate_odcv_receipt(
    request: &OdcvVerificationRequest,
    predecessor: &OdcvPredecessor<'_>,
    policy: &B1CDriveOperatorDecisionPolicy,
    legacy_request: &B1CDriveOperatorDecisionRequest,
    raw_envelope: &[u8],
    receipt: &OdcvVerificationReceipt,
) -> Result<(), OdcvFault> {
    validate_odcv_receipt_fields(receipt)?;
    if *receipt
        != verify_odcv_operator_decision(
            request,
            predecessor,
            policy,
            legacy_request,
            raw_envelope,
        )?
    {
        return Err(fault(
            OdcvFaultCode::Receipt,
            "receipt differs from full reconstructed chain",
        ));
    }
    Ok(())
}
pub fn odcv_request_digest(request: &OdcvVerificationRequest) -> Result<ContentDigest, OdcvFault> {
    let mut normalized = request.clone();
    normalized.request_sha256 = empty_digest();
    domain_digest("cantor.b1.operator-decision-chain.request.v1", &normalized)
}
pub fn odcv_receipt_digest(receipt: &OdcvVerificationReceipt) -> Result<ContentDigest, OdcvFault> {
    let mut normalized = receipt.clone();
    normalized.receipt_sha256 = empty_digest();
    domain_digest("cantor.b1.operator-decision-chain.receipt.v1", &normalized)
}
pub fn to_odcv_request_machine_form(
    request: &OdcvVerificationRequest,
) -> Result<String, OdcvFault> {
    validate_request_shape(request)?;
    serde_json::to_string(request).map_err(machine_fault)
}
pub fn from_odcv_request_machine_form(text: &str) -> Result<OdcvVerificationRequest, OdcvFault> {
    let request = parse_odcv_canonical(text)?;
    validate_request_shape(&request)?;
    Ok(request)
}
pub fn to_odcv_receipt_machine_form(
    request: &OdcvVerificationRequest,
    predecessor: &OdcvPredecessor<'_>,
    policy: &B1CDriveOperatorDecisionPolicy,
    legacy_request: &B1CDriveOperatorDecisionRequest,
    raw_envelope: &[u8],
    receipt: &OdcvVerificationReceipt,
) -> Result<String, OdcvFault> {
    validate_odcv_receipt(
        request,
        predecessor,
        policy,
        legacy_request,
        raw_envelope,
        receipt,
    )?;
    serde_json::to_string(receipt).map_err(machine_fault)
}
pub fn from_odcv_receipt_machine_form(
    request: &OdcvVerificationRequest,
    predecessor: &OdcvPredecessor<'_>,
    policy: &B1CDriveOperatorDecisionPolicy,
    legacy_request: &B1CDriveOperatorDecisionRequest,
    raw_envelope: &[u8],
    text: &str,
) -> Result<OdcvVerificationReceipt, OdcvFault> {
    let receipt = parse_odcv_canonical(text)?;
    validate_odcv_receipt(
        request,
        predecessor,
        policy,
        legacy_request,
        raw_envelope,
        &receipt,
    )?;
    Ok(receipt)
}
pub fn expected_odcv_downstream_authorities() -> Vec<String> {
    [
        "fresh_observation",
        "private_execution_permit",
        "broker_projection",
        "physical_preparation",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
pub(crate) fn parse_odcv_canonical<T: DeserializeOwned + Serialize>(
    text: &str,
) -> Result<T, OdcvFault> {
    if text.is_empty()
        || text.len() > ODCV_MAX_FORM_BYTES
        || text.starts_with('\u{feff}')
        || text.contains('\r')
        || text.contains('\n')
    {
        return Err(fault(
            OdcvFaultCode::MachineForm,
            "machine form framing or size differs",
        ));
    }
    let raw: Value = serde_json::from_str(text).map_err(machine_fault)?;
    let mut fields = 0;
    measure_value(&raw, 1, &mut fields)?;
    let value: T = serde_json::from_value(raw).map_err(machine_fault)?;
    if serde_json::to_string(&value).map_err(machine_fault)? != text {
        return Err(fault(
            OdcvFaultCode::MachineForm,
            "machine form is not compact canonical JSON",
        ));
    }
    Ok(value)
}
fn bounded_value<T: Serialize>(value: &T) -> Result<(), OdcvFault> {
    let bytes = serde_json::to_vec(value).map_err(machine_fault)?;
    if bytes.len() > ODCV_MAX_FORM_BYTES {
        return Err(fault(OdcvFaultCode::Size, "typed form exceeds byte limit"));
    }
    let raw = serde_json::to_value(value).map_err(machine_fault)?;
    measure_value(&raw, 1, &mut 0)
}
fn measure_value(value: &Value, depth: usize, fields: &mut usize) -> Result<(), OdcvFault> {
    if depth > MAX_JSON_DEPTH {
        return Err(fault(OdcvFaultCode::Size, "JSON depth exceeds bound"));
    }
    match value {
        Value::Object(items) => {
            *fields = fields
                .checked_add(items.len())
                .ok_or_else(|| fault(OdcvFaultCode::Arithmetic, "JSON field count overflow"))?;
            if *fields > MAX_JSON_FIELDS {
                return Err(fault(OdcvFaultCode::Size, "JSON field count exceeds bound"));
            }
            for (key, value) in items {
                if !safe_text(key) {
                    return Err(fault(OdcvFaultCode::Shape, "JSON key differs"));
                }
                measure_value(value, depth + 1, fields)?;
            }
        }
        Value::Array(items) => {
            if items.len() > MAX_JSON_FIELDS {
                return Err(fault(OdcvFaultCode::Size, "JSON array exceeds bound"));
            }
            for value in items {
                measure_value(value, depth + 1, fields)?;
            }
        }
        Value::String(value)
            if value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) =>
        {
            return Err(fault(OdcvFaultCode::Shape, "JSON text exceeds bounds"));
        }
        _ => {}
    }
    Ok(())
}
pub(crate) fn valid_odcv_uuid(value: &str) -> bool {
    valid_uuid(value)
}
fn valid_uuid(value: &str) -> bool {
    value != "00000000-0000-0000-0000-000000000000"
        && value.len() == 36
        && value.as_bytes().iter().enumerate().all(|(i, byte)| {
            if [8, 13, 18, 23].contains(&i) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
            }
        })
}
fn safe_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT_BYTES && !value.chars().any(char::is_control)
}
fn is_fixture(class: KcvInputClass) -> bool {
    class == KcvInputClass::DeterministicFixtureCandidate
}
fn decode_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], OdcvFault> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(fault(
            OdcvFaultCode::Shape,
            format_args!("{label} hex shape differs"),
        ));
    }
    let mut output = [0; N];
    for (i, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[i] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(output)
}
fn hex_nibble(value: u8) -> u8 {
    if value.is_ascii_digit() {
        value - b'0'
    } else {
        value - b'a' + 10
    }
}
fn domain_bytes<T: Serialize>(domain: &str, value: &T) -> Result<Vec<u8>, OdcvFault> {
    let canonical = serde_json::to_vec(value).map_err(machine_fault)?;
    let capacity = domain
        .len()
        .checked_add(1)
        .and_then(|v| v.checked_add(canonical.len()))
        .ok_or_else(|| fault(OdcvFaultCode::Arithmetic, "domain byte length overflow"))?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}
fn domain_digest<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, OdcvFault> {
    Ok(sha256_bytes(&domain_bytes(domain, value)?))
}
fn empty_digest() -> ContentDigest {
    sha256_bytes(b"")
}
fn predecessor_fault(error: impl fmt::Display) -> OdcvFault {
    fault(OdcvFaultCode::Predecessor, error)
}
fn machine_fault(error: impl fmt::Display) -> OdcvFault {
    fault(OdcvFaultCode::MachineForm, error)
}
pub(crate) fn odcv_fault(code: OdcvFaultCode, message: impl fmt::Display) -> OdcvFault {
    fault(code, message)
}
fn fault(code: OdcvFaultCode, message: impl fmt::Display) -> OdcvFault {
    OdcvFault {
        code,
        message: message.to_string(),
    }
}

fn legacy_fault(error: B1CDriveOperatorDecisionFault) -> OdcvFault {
    use B1CDriveOperatorDecisionFaultCode as Legacy;
    let code = match error.code {
        Legacy::Bound => OdcvFaultCode::Size,
        Legacy::MachineForm => OdcvFaultCode::MachineForm,
        Legacy::Identity => OdcvFaultCode::Identity,
        Legacy::Proposal => OdcvFaultCode::Lineage,
        Legacy::Policy => OdcvFaultCode::Policy,
        Legacy::Decision => OdcvFaultCode::Decision,
        Legacy::Signature => OdcvFaultCode::Signature,
        Legacy::Authority => OdcvFaultCode::Truth,
        Legacy::Digest => OdcvFaultCode::Digest,
    };
    fault(code, error)
}
