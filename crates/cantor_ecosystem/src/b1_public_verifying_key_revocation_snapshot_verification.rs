//! Provider-free verification of one supplied A3 revocation snapshot.
//!
//! A successful receipt proves only structural and detached-signature
//! correspondence for supplied bytes. It does not authenticate or authorize
//! the responder, establish a complete or monotonic registry, read a clock, or
//! decide current operative revocation or execution authority.

use std::fmt;

use cantor_core::{ContentDigest, sha256_bytes};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{
    B1OaprCandidateDescriptor, B1OaprCandidateOrigin, B1OaprConfidentiality, B1OaprPacket,
    B1OaprRequest, B1OaprVerification, BpvPolicyEnvelope, BpvVerificationReceipt,
    BpvVerificationRequest, KCV_AUTHORITY, KCV_STATUS, KcvCustodyAttestation, KcvInputClass,
    KcvVerificationReceipt, KcvVerificationRequest, compile_b1oapr_packet, kcv_request_digest,
    to_b1oapr_packet_machine_form, verify_kcv_custody_attestation,
};

pub const KRV_SNAPSHOT_PROFILE: &str = "cantor-b1-public-verifying-key-revocation-snapshot/0.1";
pub const KRV_REQUEST_PROFILE: &str =
    "cantor-b1-public-verifying-key-revocation-verification-request/0.1";
pub const KRV_RECEIPT_PROFILE: &str =
    "cantor-b1-public-verifying-key-revocation-verification-receipt/0.1";
pub const KRV_EVIDENCE_PROFILE: &str =
    "cantor-b1-public-verifying-key-revocation-verification-evidence/0.1";
pub const KRV_STATUS: &str = "revocation_snapshot_signature_correspondence_verified_current_revocation_truth_and_all_execution_authority_unresolved";
pub const KRV_AUTHORITY: &str = "revocation_snapshot_signature_correspondence_only";
pub const KRV_SIGNING_CONTEXT: &str = "cantor-b1-revocation-snapshot-signature/0.1";
pub const KRV_SOURCE_SNAPSHOT_UUID: &str = "c6588e38-3471-4a56-96c7-d86e456e900a";
pub const KRV_CANONICAL_UUID: &str = "aeb226ac-3c59-4b9b-a81e-d59f285f5a2d";
pub const KRV_SIGNATURE_UUID: &str = "5f4844b8-d5c0-47eb-ad0d-21f06dbdab6d";
pub const KRV_SOURCE_CUSTODY_COMMIT: &str = "35d5774be39494afd8e5925cb42b2fc66dfb6b10";
pub const KRV_FORMATION_COMMIT: &str = "4a6ed8d6d4b06e5c71a4e35d2b4758905b8f7da0";
pub const KRV_FORMATION_BOOKEND_COMMIT: &str = "183542f0f282e8788191a7b74f331025aee6cdf4";
pub const KRV_A2_IMPLEMENTATION_COMMIT: &str = "b95f0e24db1bfe4e87796645886f5a0e685e3337";
pub const KRV_A2_BOOKEND_COMMIT: &str = "09b4f72f095a5fc61579e83463792a6f4ec9534a";
pub const KRV_A2_PROOF_UUID: &str = "7e61709e-221f-4a69-b81e-a70011aff5a1";
pub const KRV_MAX_FORM_BYTES: usize = 1_048_576;
pub const KRV_MAX_EVIDENCE_BYTES: u64 = 16_777_216;
pub const KRV_MAX_EVIDENCE_REFERENCES: usize = 48;

const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_FIELDS: usize = 4_096;
const MAX_TEXT_BYTES: usize = 8_192;
const EXACT_BRANCH: &str = "codex/self-hosted-corpus";
const EXACT_REMOTE: &str = "https://github.com/cattailfarmer/Cantor";
const EXACT_SUBJECT: &str = "cantor_b1_cdrive_production_preparation_p0";
const EXACT_SCOPE: &str = "a1_public_verifying_key_revocation_status_at_declared_snapshot_interval";
const SNAPSHOT_DOMAIN: &str = "cantor.b1.revocation-snapshot.digest.v1";
const REQUEST_DOMAIN: &str = "cantor.b1.revocation-snapshot.request.v1";
const RECEIPT_DOMAIN: &str = "cantor.b1.revocation-snapshot.receipt.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KrvStatusAssertion {
    NotRevokedAtSnapshot,
    RevokedAtSnapshot,
    UnknownAtSnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KrvRevocationSnapshot {
    pub profile: String,
    pub snapshot_uuid: String,
    pub candidate_label: String,
    pub responder_label: String,
    pub snapshot_scope: String,
    pub subject: String,
    pub branch: String,
    pub canonical_remote: String,
    pub policy_uuid: String,
    pub policy_revision_uuid: String,
    pub a1_receipt_sha256: ContentDigest,
    pub a2_receipt_sha256: ContentDigest,
    pub a3_candidate_uuid: String,
    pub target_verifying_key_hex: String,
    pub target_public_key_fingerprint_sha256: ContentDigest,
    pub responder_verifying_key_hex: String,
    pub status_assertion: KrvStatusAssertion,
    pub sequence: u64,
    pub prior_snapshot_sha256: Option<ContentDigest>,
    pub this_update_unix_ms: u64,
    pub produced_at_unix_ms: u64,
    pub next_update_unix_ms: u64,
    pub revocation_time_unix_ms: Option<u64>,
    pub revocation_reason: Option<String>,
    pub signing_context: String,
    pub signature_hex: String,
    pub input_class: KcvInputClass,
    pub fixture_only: bool,
    pub production_authority_claimed: bool,
    pub responder_identity_proved: bool,
    pub responder_authority_proved: bool,
    pub source_completeness_proved: bool,
    pub monotonic_history_proved: bool,
    pub snapshot_freshness_proved: bool,
    pub current_time_compared: bool,
    pub revocation_truth_proved: bool,
    pub snapshot_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KrvVerificationRequest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_custody_commit: String,
    pub formation_commit: String,
    pub formation_bookend_commit: String,
    pub a2_implementation_commit: String,
    pub a2_bookend_commit: String,
    pub a2_proof_uuid: String,
    pub predecessor_request_sha256: ContentDigest,
    pub predecessor_packet_sha256: ContentDigest,
    pub predecessor_verification_sha256: ContentDigest,
    pub a1_policy_envelope_raw_sha256: ContentDigest,
    pub a1_verification_request_sha256: ContentDigest,
    pub a1_receipt_sha256: ContentDigest,
    pub a2_custody_attestation_raw_sha256: ContentDigest,
    pub a2_verification_request_sha256: ContentDigest,
    pub a2_receipt_sha256: ContentDigest,
    pub authority_packet_request: B1OaprRequest,
    pub authority_packet_request_sha256: ContentDigest,
    pub authority_packet_sha256: ContentDigest,
    pub a3_candidate_uuid: String,
    pub a3_descriptor_sha256: ContentDigest,
    pub revocation_snapshot_bytes: u64,
    pub revocation_snapshot_raw_sha256: ContentDigest,
    pub input_class: KcvInputClass,
    pub evidence_references: Vec<String>,
    pub maximum_attempts: u8,
    pub automatic_retry_count: u8,
    pub automatic_cleanup_count: u8,
    pub request_sha256: ContentDigest,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KrvEffectAccount {
    pub reference_resolution_count: u32,
    pub private_key_read_count: u32,
    pub signing_count: u32,
    pub revocation_service_contact_count: u32,
    pub clock_read_count: u32,
    pub environment_read_count: u32,
    pub host_observation_count: u32,
    pub process_count: u32,
    pub provider_trial_count: u32,
    pub model_turn_count: u32,
    pub mcp_call_count: u32,
    pub network_contact_count: u32,
    pub broker_invocation_count: u32,
    pub writer_run_count: u32,
    pub filesystem_mutation_count: u32,
    pub git_mutation_count: u32,
    pub persistence_count: u32,
    pub activation_count: u32,
    pub cleanup_count: u32,
    pub remote_hardware_contact_count: u32,
    pub physical_contact: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KrvVerificationReceipt {
    pub profile: String,
    pub status: String,
    pub authority: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub formation_commit: String,
    pub formation_bookend_commit: String,
    pub predecessor_request_sha256: ContentDigest,
    pub predecessor_packet_sha256: ContentDigest,
    pub predecessor_verification_sha256: ContentDigest,
    pub a1_policy_envelope_raw_sha256: ContentDigest,
    pub a1_verification_request_sha256: ContentDigest,
    pub a1_receipt_sha256: ContentDigest,
    pub a2_custody_attestation_raw_sha256: ContentDigest,
    pub a2_verification_request_sha256: ContentDigest,
    pub a2_receipt_sha256: ContentDigest,
    pub authority_packet_request_sha256: ContentDigest,
    pub authority_packet_sha256: ContentDigest,
    pub request_sha256: ContentDigest,
    pub a3_candidate_uuid: String,
    pub a3_descriptor_sha256: ContentDigest,
    pub revocation_snapshot_bytes: u64,
    pub revocation_snapshot_raw_sha256: ContentDigest,
    pub snapshot_uuid: String,
    pub policy_uuid: String,
    pub policy_revision_uuid: String,
    pub target_public_key_fingerprint_sha256: ContentDigest,
    pub status_assertion: KrvStatusAssertion,
    pub sequence: u64,
    pub this_update_unix_ms: u64,
    pub produced_at_unix_ms: u64,
    pub next_update_unix_ms: u64,
    pub snapshot_sha256: ContentDigest,
    pub signature_sha256: ContentDigest,
    pub packet_replayed: bool,
    pub a1_correspondence_receipt_verified: bool,
    pub a2_correspondence_receipt_verified: bool,
    pub a3_candidate_bytes_matched: bool,
    pub descriptor_correspondence_verified: bool,
    pub target_policy_key_correspondence_verified: bool,
    pub snapshot_structure_verified: bool,
    pub interval_structure_verified: bool,
    pub responder_signature_correspondence_verified: bool,
    pub status_assertion_not_revoked: bool,
    pub status_assertion_revoked: bool,
    pub status_assertion_unknown: bool,
    pub fixture_only: bool,
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
    pub effect_account: KrvEffectAccount,
    pub receipt_sha256: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KrvFaultCode {
    Path,
    Profile,
    Size,
    Shape,
    Bound,
    MachineForm,
    Identity,
    Lineage,
    Predecessor,
    Coordinate,
    Dependency,
    RawBytes,
    Digest,
    Key,
    Responder,
    Status,
    Sequence,
    Interval,
    Time,
    Reason,
    Signature,
    Receipt,
    Truth,
    Effect,
    Evidence,
    Arithmetic,
    Rollback,
    Restart,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KrvFault {
    pub code: KrvFaultCode,
    pub message: String,
}

impl fmt::Display for KrvFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for KrvFault {}

#[allow(clippy::too_many_arguments)]
pub fn verify_krv_revocation_snapshot(
    request: &KrvVerificationRequest,
    predecessor_request: &B1OaprRequest,
    predecessor_packet: &B1OaprPacket,
    predecessor_verification: &B1OaprVerification,
    a1_envelope: &BpvPolicyEnvelope,
    raw_a1_envelope: &[u8],
    a1_request: &BpvVerificationRequest,
    a1_receipt: &BpvVerificationReceipt,
    a2_attestation: &KcvCustodyAttestation,
    raw_a2_attestation: &[u8],
    a2_request: &KcvVerificationRequest,
    a2_receipt: &KcvVerificationReceipt,
    raw_snapshot: &[u8],
) -> Result<KrvVerificationReceipt, KrvFault> {
    let (packet, descriptor) = validate_krv_request(
        request,
        predecessor_request,
        predecessor_packet,
        predecessor_verification,
        a1_envelope,
        raw_a1_envelope,
        a1_request,
        a1_receipt,
        a2_attestation,
        raw_a2_attestation,
        a2_request,
        a2_receipt,
        raw_snapshot,
    )?;
    let text = std::str::from_utf8(raw_snapshot).map_err(|_| {
        fault(
            KrvFaultCode::MachineForm,
            "revocation snapshot is not UTF-8",
        )
    })?;
    let snapshot: KrvRevocationSnapshot = parse_canonical(text)?;
    validate_krv_snapshot(&snapshot)?;
    validate_snapshot_correspondence(
        request,
        descriptor,
        a1_envelope,
        a1_receipt,
        a2_receipt,
        &snapshot,
    )?;
    let signature = decode_fixed_hex::<64>(&snapshot.signature_hex, "responder signature")?;
    let mut receipt = KrvVerificationReceipt {
        profile: KRV_RECEIPT_PROFILE.to_owned(),
        status: KRV_STATUS.to_owned(),
        authority: KRV_AUTHORITY.to_owned(),
        source_snapshot_uuid: request.source_snapshot_uuid.clone(),
        canonical_uuid: request.canonical_uuid.clone(),
        signature_uuid: request.signature_uuid.clone(),
        formation_commit: request.formation_commit.clone(),
        formation_bookend_commit: request.formation_bookend_commit.clone(),
        predecessor_request_sha256: request.predecessor_request_sha256.clone(),
        predecessor_packet_sha256: request.predecessor_packet_sha256.clone(),
        predecessor_verification_sha256: request.predecessor_verification_sha256.clone(),
        a1_policy_envelope_raw_sha256: request.a1_policy_envelope_raw_sha256.clone(),
        a1_verification_request_sha256: request.a1_verification_request_sha256.clone(),
        a1_receipt_sha256: request.a1_receipt_sha256.clone(),
        a2_custody_attestation_raw_sha256: request.a2_custody_attestation_raw_sha256.clone(),
        a2_verification_request_sha256: request.a2_verification_request_sha256.clone(),
        a2_receipt_sha256: request.a2_receipt_sha256.clone(),
        authority_packet_request_sha256: request.authority_packet_request_sha256.clone(),
        authority_packet_sha256: packet.packet_sha256,
        request_sha256: request.request_sha256.clone(),
        a3_candidate_uuid: descriptor.candidate_uuid.clone(),
        a3_descriptor_sha256: descriptor.descriptor_sha256.clone(),
        revocation_snapshot_bytes: request.revocation_snapshot_bytes,
        revocation_snapshot_raw_sha256: request.revocation_snapshot_raw_sha256.clone(),
        snapshot_uuid: snapshot.snapshot_uuid.clone(),
        policy_uuid: snapshot.policy_uuid.clone(),
        policy_revision_uuid: snapshot.policy_revision_uuid.clone(),
        target_public_key_fingerprint_sha256: snapshot.target_public_key_fingerprint_sha256.clone(),
        status_assertion: snapshot.status_assertion,
        sequence: snapshot.sequence,
        this_update_unix_ms: snapshot.this_update_unix_ms,
        produced_at_unix_ms: snapshot.produced_at_unix_ms,
        next_update_unix_ms: snapshot.next_update_unix_ms,
        snapshot_sha256: snapshot.snapshot_sha256.clone(),
        signature_sha256: sha256_bytes(&signature),
        packet_replayed: true,
        a1_correspondence_receipt_verified: true,
        a2_correspondence_receipt_verified: true,
        a3_candidate_bytes_matched: true,
        descriptor_correspondence_verified: true,
        target_policy_key_correspondence_verified: true,
        snapshot_structure_verified: true,
        interval_structure_verified: true,
        responder_signature_correspondence_verified: true,
        status_assertion_not_revoked: snapshot.status_assertion
            == KrvStatusAssertion::NotRevokedAtSnapshot,
        status_assertion_revoked: snapshot.status_assertion
            == KrvStatusAssertion::RevokedAtSnapshot,
        status_assertion_unknown: snapshot.status_assertion
            == KrvStatusAssertion::UnknownAtSnapshot,
        fixture_only: snapshot.fixture_only,
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
        effect_account: KrvEffectAccount::default(),
        receipt_sha256: empty_digest(),
    };
    receipt.receipt_sha256 = krv_receipt_digest(&receipt)?;
    validate_krv_receipt(request, &snapshot, &receipt)?;
    Ok(receipt)
}

#[allow(clippy::too_many_arguments)]
pub fn validate_krv_request<'a>(
    request: &'a KrvVerificationRequest,
    predecessor_request: &B1OaprRequest,
    predecessor_packet: &B1OaprPacket,
    predecessor_verification: &B1OaprVerification,
    a1_envelope: &BpvPolicyEnvelope,
    raw_a1_envelope: &[u8],
    a1_request: &BpvVerificationRequest,
    a1_receipt: &BpvVerificationReceipt,
    a2_attestation: &KcvCustodyAttestation,
    raw_a2_attestation: &[u8],
    a2_request: &KcvVerificationRequest,
    a2_receipt: &KcvVerificationReceipt,
    raw_snapshot: &[u8],
) -> Result<(B1OaprPacket, &'a B1OaprCandidateDescriptor), KrvFault> {
    let reconstructed_a2 = verify_kcv_custody_attestation(
        a2_request,
        predecessor_request,
        predecessor_packet,
        predecessor_verification,
        a1_envelope,
        raw_a1_envelope,
        a1_request,
        a1_receipt,
        raw_a2_attestation,
    )
    .map_err(predecessor_fault)?;
    if reconstructed_a2 != *a2_receipt
        || reconstructed_a2.status != KCV_STATUS
        || reconstructed_a2.authority != KCV_AUTHORITY
        || a2_request.request_sha256 != kcv_request_digest(a2_request).map_err(predecessor_fault)?
    {
        return Err(fault(
            KrvFaultCode::Predecessor,
            "A2 correspondence replay differs",
        ));
    }
    let raw_a2_text = std::str::from_utf8(raw_a2_attestation)
        .map_err(|_| fault(KrvFaultCode::MachineForm, "A2 attestation is not UTF-8"))?;
    if serde_json::from_str::<KcvCustodyAttestation>(raw_a2_text).map_err(machine_fault)?
        != *a2_attestation
    {
        return Err(fault(
            KrvFaultCode::Predecessor,
            "typed and raw A2 attestation differ",
        ));
    }
    if request.profile != KRV_REQUEST_PROFILE
        || request.source_snapshot_uuid != KRV_SOURCE_SNAPSHOT_UUID
        || request.canonical_uuid != KRV_CANONICAL_UUID
        || request.signature_uuid != KRV_SIGNATURE_UUID
        || request.source_custody_commit != KRV_SOURCE_CUSTODY_COMMIT
        || request.formation_commit != KRV_FORMATION_COMMIT
        || request.formation_bookend_commit != KRV_FORMATION_BOOKEND_COMMIT
        || request.a2_implementation_commit != KRV_A2_IMPLEMENTATION_COMMIT
        || request.a2_bookend_commit != KRV_A2_BOOKEND_COMMIT
        || request.a2_proof_uuid != KRV_A2_PROOF_UUID
    {
        return Err(fault(KrvFaultCode::Lineage, "request lineage differs"));
    }
    if request.predecessor_request_sha256 != predecessor_request.request_sha256
        || request.predecessor_packet_sha256 != predecessor_packet.packet_sha256
        || request.predecessor_verification_sha256 != predecessor_verification.verification_sha256
        || request.a1_policy_envelope_raw_sha256 != sha256_bytes(raw_a1_envelope)
        || request.a1_verification_request_sha256 != a1_request.request_sha256
        || request.a1_receipt_sha256 != a1_receipt.receipt_sha256
        || request.a2_custody_attestation_raw_sha256 != sha256_bytes(raw_a2_attestation)
        || request.a2_verification_request_sha256 != a2_request.request_sha256
        || request.a2_receipt_sha256 != a2_receipt.receipt_sha256
    {
        return Err(fault(
            KrvFaultCode::Predecessor,
            "A1 or A2 evidence binding differs",
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
            KrvFaultCode::Predecessor,
            "A3 authority packet replay differs",
        ));
    }
    validate_packet_transition(
        &a2_request.authority_packet_request,
        &request.authority_packet_request,
        a2_receipt,
    )?;
    let descriptor = request
        .authority_packet_request
        .descriptors
        .get(2)
        .ok_or_else(|| fault(KrvFaultCode::Coordinate, "A3 descriptor is absent"))?;
    if descriptor.ordinal != 3
        || descriptor.authority_name != "revocation_truth"
        || descriptor.artifact_kind != "revocation_snapshot_candidate"
        || descriptor.required_verifier_profile != "revocation-snapshot-verifier/0.1"
        || descriptor.confidentiality != B1OaprConfidentiality::PublicMetadata
        || descriptor.dependency_ordinal != Some(2)
        || request.a3_candidate_uuid != descriptor.candidate_uuid
        || request.a3_descriptor_sha256 != descriptor.descriptor_sha256
    {
        return Err(fault(KrvFaultCode::Coordinate, "A3 descriptor differs"));
    }
    let raw_len = u64::try_from(raw_snapshot.len())
        .map_err(|_| fault(KrvFaultCode::Arithmetic, "snapshot length overflow"))?;
    if raw_snapshot.is_empty() || raw_snapshot.len() > KRV_MAX_FORM_BYTES {
        return Err(fault(KrvFaultCode::Size, "raw snapshot size differs"));
    }
    if request.revocation_snapshot_bytes != raw_len
        || descriptor.declared_bytes != raw_len
        || request.revocation_snapshot_raw_sha256 != sha256_bytes(raw_snapshot)
        || descriptor.content_sha256 != request.revocation_snapshot_raw_sha256
    {
        return Err(fault(
            KrvFaultCode::RawBytes,
            "raw A3 snapshot identity differs",
        ));
    }
    let expected_fixture = matches!(
        request.input_class,
        KcvInputClass::DeterministicFixtureCandidate
    );
    let expected_origin = match request.input_class {
        KcvInputClass::DeterministicFixtureCandidate => {
            B1OaprCandidateOrigin::DeterministicFixtureCandidate
        }
        KcvInputClass::ExternallySuppliedCandidate => {
            B1OaprCandidateOrigin::ExternallySuppliedCandidate
        }
    };
    if descriptor.origin != expected_origin
        || descriptor.fixture_only != expected_fixture
        || request.evidence_references.is_empty()
        || request.evidence_references.len() > KRV_MAX_EVIDENCE_REFERENCES
        || request
            .evidence_references
            .iter()
            .any(|value| !safe_text(value))
        || has_duplicates(&request.evidence_references)
        || request.maximum_attempts != 1
        || request.automatic_retry_count != 0
        || request.automatic_cleanup_count != 0
    {
        return Err(fault(
            KrvFaultCode::Bound,
            "input class or bounded request account differs",
        ));
    }
    if request.request_sha256 != krv_request_digest(request)? {
        return Err(fault(KrvFaultCode::Digest, "request digest differs"));
    }
    Ok((first, descriptor))
}

pub fn validate_krv_snapshot(snapshot: &KrvRevocationSnapshot) -> Result<(), KrvFault> {
    let expected_fixture = matches!(
        snapshot.input_class,
        KcvInputClass::DeterministicFixtureCandidate
    );
    if snapshot.profile != KRV_SNAPSHOT_PROFILE {
        return Err(fault(KrvFaultCode::Profile, "snapshot profile differs"));
    }
    if !valid_uuid(&snapshot.snapshot_uuid)
        || !valid_uuid(&snapshot.policy_uuid)
        || !valid_uuid(&snapshot.policy_revision_uuid)
        || !valid_uuid(&snapshot.a3_candidate_uuid)
        || snapshot.subject != EXACT_SUBJECT
        || snapshot.branch != EXACT_BRANCH
        || snapshot.canonical_remote != EXACT_REMOTE
        || snapshot.snapshot_scope != EXACT_SCOPE
        || snapshot.candidate_label != expected_candidate_label(snapshot.input_class)
        || snapshot.responder_label != expected_responder_label(snapshot.input_class)
    {
        return Err(fault(KrvFaultCode::Identity, "snapshot identity differs"));
    }
    if snapshot.fixture_only != expected_fixture {
        return Err(fault(
            KrvFaultCode::Identity,
            "snapshot input class differs",
        ));
    }
    if snapshot.production_authority_claimed
        || snapshot.responder_identity_proved
        || snapshot.responder_authority_proved
        || snapshot.source_completeness_proved
        || snapshot.monotonic_history_proved
        || snapshot.snapshot_freshness_proved
        || snapshot.current_time_compared
        || snapshot.revocation_truth_proved
    {
        return Err(fault(
            KrvFaultCode::Truth,
            "snapshot promotes supplied correspondence into authority",
        ));
    }
    if !is_lower_hex(&snapshot.target_verifying_key_hex, 64)
        || !is_lower_hex(&snapshot.responder_verifying_key_hex, 64)
        || !is_lower_hex(&snapshot.signature_hex, 128)
    {
        return Err(fault(KrvFaultCode::Shape, "key or signature shape differs"));
    }
    if snapshot.signing_context != KRV_SIGNING_CONTEXT {
        return Err(fault(
            KrvFaultCode::Responder,
            "snapshot signing context differs",
        ));
    }
    if snapshot.sequence == 0 {
        return Err(fault(KrvFaultCode::Sequence, "snapshot sequence is zero"));
    }
    if (snapshot.sequence == 1) != snapshot.prior_snapshot_sha256.is_none() {
        return Err(fault(
            KrvFaultCode::Rollback,
            "snapshot prior digest relation differs",
        ));
    }
    if snapshot.this_update_unix_ms > snapshot.produced_at_unix_ms
        || snapshot.produced_at_unix_ms >= snapshot.next_update_unix_ms
    {
        return Err(fault(
            KrvFaultCode::Interval,
            "declared snapshot interval differs",
        ));
    }
    match snapshot.status_assertion {
        KrvStatusAssertion::RevokedAtSnapshot => {
            let time = snapshot.revocation_time_unix_ms.ok_or_else(|| {
                fault(
                    KrvFaultCode::Time,
                    "revoked assertion lacks revocation time",
                )
            })?;
            let reason = snapshot
                .revocation_reason
                .as_deref()
                .ok_or_else(|| fault(KrvFaultCode::Reason, "revoked assertion lacks reason"))?;
            if time > snapshot.this_update_unix_ms || !safe_text(reason) {
                return Err(fault(
                    KrvFaultCode::Reason,
                    "revocation time or reason differs",
                ));
            }
        }
        KrvStatusAssertion::NotRevokedAtSnapshot | KrvStatusAssertion::UnknownAtSnapshot => {
            if snapshot.revocation_time_unix_ms.is_some() || snapshot.revocation_reason.is_some() {
                return Err(fault(
                    KrvFaultCode::Status,
                    "non-revoked assertion carries revocation detail",
                ));
            }
        }
    }
    if snapshot.snapshot_sha256 != krv_snapshot_digest(snapshot)? {
        return Err(fault(KrvFaultCode::Digest, "snapshot digest differs"));
    }
    let key_bytes = decode_fixed_hex::<32>(&snapshot.responder_verifying_key_hex, "responder key")?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| fault(KrvFaultCode::Responder, "responder key refused"))?;
    let signature = decode_fixed_hex::<64>(&snapshot.signature_hex, "responder signature")?;
    key.verify_strict(
        &krv_signature_payload_bytes(snapshot)?,
        &Signature::from_bytes(&signature),
    )
    .map_err(|_| fault(KrvFaultCode::Signature, "responder signature refused"))?;
    Ok(())
}

pub fn validate_krv_receipt(
    request: &KrvVerificationRequest,
    snapshot: &KrvRevocationSnapshot,
    receipt: &KrvVerificationReceipt,
) -> Result<(), KrvFault> {
    validate_krv_snapshot(snapshot)?;
    let status_count = u8::from(receipt.status_assertion_not_revoked)
        + u8::from(receipt.status_assertion_revoked)
        + u8::from(receipt.status_assertion_unknown);
    if receipt.profile != KRV_RECEIPT_PROFILE
        || receipt.status != KRV_STATUS
        || receipt.authority != KRV_AUTHORITY
        || receipt.source_snapshot_uuid != request.source_snapshot_uuid
        || receipt.canonical_uuid != request.canonical_uuid
        || receipt.signature_uuid != request.signature_uuid
        || receipt.formation_commit != request.formation_commit
        || receipt.formation_bookend_commit != request.formation_bookend_commit
        || receipt.predecessor_request_sha256 != request.predecessor_request_sha256
        || receipt.predecessor_packet_sha256 != request.predecessor_packet_sha256
        || receipt.predecessor_verification_sha256 != request.predecessor_verification_sha256
        || receipt.a1_policy_envelope_raw_sha256 != request.a1_policy_envelope_raw_sha256
        || receipt.a1_verification_request_sha256 != request.a1_verification_request_sha256
        || receipt.a1_receipt_sha256 != request.a1_receipt_sha256
        || receipt.a2_custody_attestation_raw_sha256 != request.a2_custody_attestation_raw_sha256
        || receipt.a2_verification_request_sha256 != request.a2_verification_request_sha256
        || receipt.a2_receipt_sha256 != request.a2_receipt_sha256
        || receipt.authority_packet_request_sha256 != request.authority_packet_request_sha256
        || receipt.authority_packet_sha256 != request.authority_packet_sha256
        || receipt.request_sha256 != request.request_sha256
        || receipt.a3_candidate_uuid != request.a3_candidate_uuid
        || receipt.a3_descriptor_sha256 != request.a3_descriptor_sha256
        || receipt.revocation_snapshot_bytes != request.revocation_snapshot_bytes
        || receipt.revocation_snapshot_raw_sha256 != request.revocation_snapshot_raw_sha256
        || receipt.snapshot_uuid != snapshot.snapshot_uuid
        || receipt.policy_uuid != snapshot.policy_uuid
        || receipt.policy_revision_uuid != snapshot.policy_revision_uuid
        || receipt.target_public_key_fingerprint_sha256
            != snapshot.target_public_key_fingerprint_sha256
        || receipt.status_assertion != snapshot.status_assertion
        || receipt.sequence != snapshot.sequence
        || receipt.this_update_unix_ms != snapshot.this_update_unix_ms
        || receipt.produced_at_unix_ms != snapshot.produced_at_unix_ms
        || receipt.next_update_unix_ms != snapshot.next_update_unix_ms
        || receipt.snapshot_sha256 != snapshot.snapshot_sha256
        || receipt.signature_sha256
            != sha256_bytes(&decode_fixed_hex::<64>(
                &snapshot.signature_hex,
                "signature",
            )?)
        || receipt.fixture_only != snapshot.fixture_only
        || status_count != 1
        || receipt.status_assertion_not_revoked
            != (snapshot.status_assertion == KrvStatusAssertion::NotRevokedAtSnapshot)
        || receipt.status_assertion_revoked
            != (snapshot.status_assertion == KrvStatusAssertion::RevokedAtSnapshot)
        || receipt.status_assertion_unknown
            != (snapshot.status_assertion == KrvStatusAssertion::UnknownAtSnapshot)
    {
        return Err(fault(
            KrvFaultCode::Receipt,
            "receipt correspondence differs",
        ));
    }
    if !receipt.packet_replayed
        || !receipt.a1_correspondence_receipt_verified
        || !receipt.a2_correspondence_receipt_verified
        || !receipt.a3_candidate_bytes_matched
        || !receipt.descriptor_correspondence_verified
        || !receipt.target_policy_key_correspondence_verified
        || !receipt.snapshot_structure_verified
        || !receipt.interval_structure_verified
        || !receipt.responder_signature_correspondence_verified
    {
        return Err(fault(
            KrvFaultCode::Truth,
            "positive correspondence field differs",
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
    {
        return Err(fault(
            KrvFaultCode::Truth,
            "receipt promotes an authority truth",
        ));
    }
    if receipt.effect_account != KrvEffectAccount::default() {
        return Err(fault(KrvFaultCode::Effect, "receipt reports an effect"));
    }
    if receipt.receipt_sha256 != krv_receipt_digest(receipt)? {
        return Err(fault(KrvFaultCode::Digest, "receipt digest differs"));
    }
    Ok(())
}

pub fn krv_snapshot_digest(snapshot: &KrvRevocationSnapshot) -> Result<ContentDigest, KrvFault> {
    let mut normalized = snapshot.clone();
    normalized.snapshot_sha256 = empty_digest();
    domain_digest(SNAPSHOT_DOMAIN, &normalized)
}

pub fn krv_request_digest(request: &KrvVerificationRequest) -> Result<ContentDigest, KrvFault> {
    let mut normalized = request.clone();
    normalized.request_sha256 = empty_digest();
    domain_digest(REQUEST_DOMAIN, &normalized)
}

pub fn krv_receipt_digest(receipt: &KrvVerificationReceipt) -> Result<ContentDigest, KrvFault> {
    let mut normalized = receipt.clone();
    normalized.receipt_sha256 = empty_digest();
    domain_digest(RECEIPT_DOMAIN, &normalized)
}

pub fn krv_signature_payload_bytes(snapshot: &KrvRevocationSnapshot) -> Result<Vec<u8>, KrvFault> {
    let mut payload = snapshot.clone();
    payload.signature_hex.clear();
    payload.snapshot_sha256 = empty_digest();
    let canonical = serde_json::to_vec(&payload).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(KRV_SIGNING_CONTEXT.len() + 1 + canonical.len());
    bytes.extend_from_slice(KRV_SIGNING_CONTEXT.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

pub fn to_krv_snapshot_machine_form(value: &KrvRevocationSnapshot) -> Result<String, KrvFault> {
    validate_krv_snapshot(value)?;
    serde_json::to_string(value).map_err(machine_fault)
}

pub fn from_krv_snapshot_machine_form(text: &str) -> Result<KrvRevocationSnapshot, KrvFault> {
    let value = parse_canonical(text)?;
    validate_krv_snapshot(&value)?;
    Ok(value)
}

pub fn to_krv_request_machine_form(value: &KrvVerificationRequest) -> Result<String, KrvFault> {
    if value.request_sha256 != krv_request_digest(value)? {
        return Err(fault(KrvFaultCode::Digest, "request digest differs"));
    }
    serde_json::to_string(value).map_err(machine_fault)
}

pub fn from_krv_request_machine_form(text: &str) -> Result<KrvVerificationRequest, KrvFault> {
    let value: KrvVerificationRequest = parse_canonical(text)?;
    if value.request_sha256 != krv_request_digest(&value)? {
        return Err(fault(KrvFaultCode::Digest, "request digest differs"));
    }
    Ok(value)
}

pub fn to_krv_receipt_machine_form(
    request: &KrvVerificationRequest,
    snapshot: &KrvRevocationSnapshot,
    receipt: &KrvVerificationReceipt,
) -> Result<String, KrvFault> {
    validate_krv_receipt(request, snapshot, receipt)?;
    serde_json::to_string(receipt).map_err(machine_fault)
}

pub fn from_krv_receipt_machine_form(
    request: &KrvVerificationRequest,
    snapshot: &KrvRevocationSnapshot,
    text: &str,
) -> Result<KrvVerificationReceipt, KrvFault> {
    let value = parse_canonical(text)?;
    validate_krv_receipt(request, snapshot, &value)?;
    Ok(value)
}

pub fn expected_krv_downstream_authorities() -> Vec<String> {
    [
        "current_time",
        "live_decision",
        "fresh_observation",
        "private_execution_permit",
        "broker_projection",
        "physical_preparation",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn validate_packet_transition(
    a2: &B1OaprRequest,
    current: &B1OaprRequest,
    a2_receipt: &KcvVerificationReceipt,
) -> Result<(), KrvFault> {
    if a2.descriptors.len() != 9 || current.descriptors.len() != 9 {
        return Err(fault(
            KrvFaultCode::Coordinate,
            "packet coordinate count differs",
        ));
    }
    if a2.descriptors[..2] != current.descriptors[..2]
        || a2.descriptors[3..] != current.descriptors[3..]
        || current.descriptors[1].candidate_uuid != a2_receipt.a2_candidate_uuid
        || current.descriptors[1].descriptor_sha256 != a2_receipt.a2_descriptor_sha256
        || current.descriptors[1].content_sha256 != a2_receipt.custody_attestation_raw_sha256
    {
        return Err(fault(
            KrvFaultCode::Dependency,
            "A3 dependency does not resolve to A2",
        ));
    }
    let mut normalized = current.clone();
    normalized.descriptors[2] = a2.descriptors[2].clone();
    normalized.request_sha256 = a2.request_sha256.clone();
    if normalized != *a2 {
        return Err(fault(
            KrvFaultCode::Lineage,
            "packet transition changes more than A3",
        ));
    }
    Ok(())
}

fn validate_snapshot_correspondence(
    request: &KrvVerificationRequest,
    descriptor: &B1OaprCandidateDescriptor,
    a1_envelope: &BpvPolicyEnvelope,
    a1_receipt: &BpvVerificationReceipt,
    a2_receipt: &KcvVerificationReceipt,
    snapshot: &KrvRevocationSnapshot,
) -> Result<(), KrvFault> {
    if snapshot.a3_candidate_uuid != descriptor.candidate_uuid
        || snapshot.input_class != request.input_class
        || snapshot.fixture_only != descriptor.fixture_only
        || snapshot.policy_uuid != a2_receipt.policy_uuid
        || snapshot.policy_revision_uuid != a2_receipt.policy_revision_uuid
        || snapshot.a1_receipt_sha256 != a1_receipt.receipt_sha256
        || snapshot.a2_receipt_sha256 != a2_receipt.receipt_sha256
    {
        return Err(fault(
            KrvFaultCode::Dependency,
            "snapshot A1 A2 or A3 binding differs",
        ));
    }
    if snapshot.target_verifying_key_hex != a1_envelope.verifying_key_hex
        || snapshot.target_public_key_fingerprint_sha256 != a2_receipt.public_key_fingerprint_sha256
    {
        return Err(fault(
            KrvFaultCode::Key,
            "snapshot target key does not equal A1 and A2",
        ));
    }
    Ok(())
}

fn parse_canonical<T: DeserializeOwned + Serialize>(text: &str) -> Result<T, KrvFault> {
    if text.is_empty()
        || text.len() > KRV_MAX_FORM_BYTES
        || text.starts_with('\u{feff}')
        || text.contains('\r')
        || text.contains('\n')
    {
        return Err(fault(KrvFaultCode::Shape, "machine-form framing differs"));
    }
    let raw: Value = serde_json::from_str(text).map_err(machine_fault)?;
    let mut fields = 0_usize;
    measure_value(&raw, 1, &mut fields)?;
    let value: T = serde_json::from_value(raw).map_err(machine_fault)?;
    if serde_json::to_string(&value).map_err(machine_fault)? != text {
        return Err(fault(
            KrvFaultCode::MachineForm,
            "machine form is not compact canonical JSON",
        ));
    }
    Ok(value)
}

fn measure_value(value: &Value, depth: usize, fields: &mut usize) -> Result<(), KrvFault> {
    if depth > MAX_JSON_DEPTH {
        return Err(fault(KrvFaultCode::Size, "JSON depth exceeds bound"));
    }
    match value {
        Value::Object(values) => {
            *fields = fields
                .checked_add(values.len())
                .ok_or_else(|| fault(KrvFaultCode::Arithmetic, "field count overflow"))?;
            if *fields > MAX_JSON_FIELDS {
                return Err(fault(KrvFaultCode::Size, "JSON field count exceeds bound"));
            }
            for (key, nested) in values {
                if !safe_text(key) {
                    return Err(fault(KrvFaultCode::Shape, "JSON key differs"));
                }
                measure_value(nested, depth + 1, fields)?;
            }
        }
        Value::Array(values) => {
            for nested in values {
                measure_value(nested, depth + 1, fields)?;
            }
        }
        Value::String(text) if !safe_text(text) => {
            return Err(fault(KrvFaultCode::Shape, "JSON text differs"));
        }
        _ => {}
    }
    Ok(())
}

fn has_duplicates(values: &[String]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.as_bytes().iter().enumerate().all(|(i, byte)| {
            if [8, 13, 18, 23].contains(&i) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
}

fn safe_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT_BYTES && !value.chars().any(char::is_control)
}

fn expected_candidate_label(input: KcvInputClass) -> &'static str {
    match input {
        KcvInputClass::DeterministicFixtureCandidate => "fixture_a3_revocation_snapshot_candidate",
        KcvInputClass::ExternallySuppliedCandidate => "external_a3_revocation_snapshot_candidate",
    }
}

fn expected_responder_label(input: KcvInputClass) -> &'static str {
    match input {
        KcvInputClass::DeterministicFixtureCandidate => "fixture_responder_untrusted",
        KcvInputClass::ExternallySuppliedCandidate => "external_claimed_responder_untrusted",
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], KrvFault> {
    if !is_lower_hex(value, N * 2) {
        return Err(fault(
            KrvFaultCode::Shape,
            format_args!("{label} shape differs"),
        ));
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

fn domain_digest<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, KrvFault> {
    let canonical = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + canonical.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(sha256_bytes(&bytes))
}

fn empty_digest() -> ContentDigest {
    sha256_bytes(b"")
}
fn predecessor_fault(error: impl fmt::Display) -> KrvFault {
    fault(KrvFaultCode::Predecessor, error)
}
fn machine_fault(error: impl fmt::Display) -> KrvFault {
    fault(KrvFaultCode::MachineForm, error)
}
fn fault(code: KrvFaultCode, message: impl fmt::Display) -> KrvFault {
    KrvFault {
        code,
        message: message.to_string(),
    }
}
