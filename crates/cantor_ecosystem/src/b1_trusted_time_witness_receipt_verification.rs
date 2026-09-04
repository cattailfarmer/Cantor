//! A4 supplied time-witness correspondence, not trusted-current-time authority.
//!
//! The verifier has no clock, provider, signing, persistence or execution capability.
//! It joins exact A3 replay to a request-pinned witness and compares supplied integers.

use crate::{
    B1OaprCandidateOrigin, B1OaprConfidentiality, B1OaprPacket, B1OaprRequest, B1OaprVerification,
    BpvPolicyEnvelope, BpvVerificationReceipt, BpvVerificationRequest, KRV_AUTHORITY, KRV_STATUS,
    KcvCustodyAttestation, KcvInputClass, KcvVerificationReceipt, KcvVerificationRequest,
    KrvVerificationReceipt, KrvVerificationRequest, compile_b1oapr_packet,
    to_b1oapr_packet_machine_form, verify_krv_revocation_snapshot,
};
use cantor_core::{ContentDigest, sha256_bytes};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::fmt;

pub const TWV_WITNESS_PROFILE: &str = "cantor-b1-trusted-time-witness-receipt/0.1";
pub const TWV_REQUEST_PROFILE: &str = "cantor-b1-trusted-time-witness-verification-request/0.1";
pub const TWV_RECEIPT_PROFILE: &str = "cantor-b1-trusted-time-witness-verification-receipt/0.1";
pub const TWV_EVIDENCE_PROFILE: &str = "cantor-b1-trusted-time-witness-verification-evidence/0.1";
pub const TWV_STATUS: &str = "time_witness_signature_and_supplied_interval_correspondence_verified_current_time_and_all_execution_authority_unresolved";
pub const TWV_AUTHORITY: &str = "supplied_time_witness_correspondence_only";
pub const TWV_SIGNING_CONTEXT: &str = "cantor-b1-time-witness-signature/0.1";
pub const TWV_SOURCE_SNAPSHOT_UUID: &str = "3f33fd16-abed-4838-9272-bc3f44aaff54";
pub const TWV_CANONICAL_UUID: &str = "d4bbec0d-b308-4e83-ad80-29cdb61424eb";
pub const TWV_SIGNATURE_UUID: &str = "2e058f81-3eab-49e2-89aa-c677552191a0";
pub const TWV_SOURCE_CUSTODY_COMMIT: &str = "8fc0fe68dd706a13ff57cf7beb32e35e7be6ba56";
pub const TWV_FORMATION_COMMIT: &str = "e06d2f31362a881455883126a3060c6b6e7705c3";
pub const TWV_FORMATION_BOOKEND_COMMIT: &str = "73de513e0ad2a8c98f166015728fb391f19db091";
pub const TWV_A3_IMPLEMENTATION_COMMIT: &str = "508ddddaedee96d97f393244692b17801394f01c";
pub const TWV_A3_BOOKEND_COMMIT: &str = "cb1c608a50bfaad24281c34278ee8fdda2f30f8b";
pub const TWV_A3_PROOF_UUID: &str = "ccecea62-9e48-42ef-ba5b-adadd240ae18";
pub const TWV_MAX_FORM_BYTES: usize = 1_048_576;
pub const TWV_MAX_EVIDENCE_BYTES: u64 = 16_777_216;
pub const TWV_MAX_EVIDENCE_REFERENCES: usize = 48;
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_FIELDS: usize = 4096;
const MAX_TEXT_BYTES: usize = 8192;
const EXACT_SUBJECT: &str = "cantor_b1_cdrive_production_preparation_p0";
const EXACT_BRANCH: &str = "codex/self-hosted-corpus";
const EXACT_REMOTE: &str = "https://github.com/cattailfarmer/Cantor";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TwvIntervalRelation {
    BeforeSnapshotInterval,
    WithinSnapshotInterval,
    AfterSnapshotInterval,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TwvTimeWitness {
    pub profile: String,
    pub witness_uuid: String,
    pub candidate_label: String,
    pub authority_label: String,
    pub subject: String,
    pub branch: String,
    pub canonical_remote: String,
    pub policy_uuid: String,
    pub policy_revision_uuid: String,
    pub a1_receipt_sha256: ContentDigest,
    pub a2_receipt_sha256: ContentDigest,
    pub a3_receipt_sha256: ContentDigest,
    pub a3_authority_packet_sha256: ContentDigest,
    pub a3_snapshot_sha256: ContentDigest,
    pub a3_snapshot_raw_sha256: ContentDigest,
    pub a4_candidate_uuid: String,
    pub target_policy_key_fingerprint_sha256: ContentDigest,
    pub witness_verifying_key_hex: String,
    pub witness_public_key_fingerprint_sha256: ContentDigest,
    pub observed_unix_ms: u64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub sequence: u64,
    pub signing_context: String,
    pub signature_hex: String,
    pub input_class: KcvInputClass,
    pub fixture_only: bool,
    pub production_authority_claimed: bool,
    pub witness_identity_proved: bool,
    pub witness_authority_proved: bool,
    pub witness_freshness_proved: bool,
    pub trusted_current_time_proved: bool,
    pub witness_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TwvVerificationRequest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_custody_commit: String,
    pub formation_commit: String,
    pub formation_bookend_commit: String,
    pub a3_implementation_commit: String,
    pub a3_bookend_commit: String,
    pub a3_proof_uuid: String,
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
    pub authority_packet_request: B1OaprRequest,
    pub authority_packet_request_sha256: ContentDigest,
    pub authority_packet_sha256: ContentDigest,
    pub a4_candidate_uuid: String,
    pub a4_descriptor_sha256: ContentDigest,
    pub time_witness_receipt_bytes: u64,
    pub time_witness_receipt_raw_sha256: ContentDigest,
    pub expected_witness_uuid: String,
    pub expected_witness_authority_label: String,
    pub expected_witness_verifying_key_hex: String,
    pub expected_witness_public_key_fingerprint_sha256: ContentDigest,
    pub expected_sequence: u64,
    pub input_class: KcvInputClass,
    pub evidence_references: Vec<String>,
    pub maximum_attempts: u8,
    pub automatic_retry_count: u8,
    pub automatic_cleanup_count: u8,
    pub request_sha256: ContentDigest,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TwvEffectAccount {
    pub reference_resolution_count: u32,
    pub private_key_read_count: u32,
    pub signing_count: u32,
    pub revocation_service_contact_count: u32,
    pub witness_service_contact_count: u32,
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
pub struct TwvVerificationReceipt {
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
    pub a3_revocation_snapshot_raw_sha256: ContentDigest,
    pub a3_verification_request_sha256: ContentDigest,
    pub a3_receipt_sha256: ContentDigest,
    pub authority_packet_request_sha256: ContentDigest,
    pub authority_packet_sha256: ContentDigest,
    pub request_sha256: ContentDigest,
    pub a4_candidate_uuid: String,
    pub a4_descriptor_sha256: ContentDigest,
    pub time_witness_receipt_bytes: u64,
    pub time_witness_receipt_raw_sha256: ContentDigest,
    pub witness_uuid: String,
    pub authority_label: String,
    pub policy_uuid: String,
    pub policy_revision_uuid: String,
    pub target_policy_key_fingerprint_sha256: ContentDigest,
    pub witness_public_key_fingerprint_sha256: ContentDigest,
    pub observed_unix_ms: u64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub sequence: u64,
    pub a3_snapshot_sha256: ContentDigest,
    pub this_update_unix_ms: u64,
    pub next_update_unix_ms: u64,
    pub comparison_outcome: TwvIntervalRelation,
    pub witness_sha256: ContentDigest,
    pub signature_sha256: ContentDigest,
    pub input_class: KcvInputClass,
    pub fixture_only: bool,
    pub maximum_attempts: u8,
    pub automatic_retry_count: u8,
    pub automatic_cleanup_count: u8,
    pub packet_replayed: bool,
    pub a1_correspondence_receipt_verified: bool,
    pub a2_correspondence_receipt_verified: bool,
    pub a3_correspondence_receipt_verified: bool,
    pub a4_candidate_bytes_matched: bool,
    pub descriptor_correspondence_verified: bool,
    pub subject_lineage_correspondence_verified: bool,
    pub witness_key_correspondence_verified: bool,
    pub witness_structure_verified: bool,
    pub time_bounds_structure_verified: bool,
    pub witness_signature_correspondence_verified: bool,
    pub supplied_interval_comparison_verified: bool,
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
    pub effect_account: TwvEffectAccount,
    pub receipt_sha256: ContentDigest,
}

/// Borrowed predecessor inputs; all are replayed, not treated as trusted receipts.
pub struct TwvPredecessor<'a> {
    pub request: &'a B1OaprRequest,
    pub packet: &'a B1OaprPacket,
    pub verification: &'a B1OaprVerification,
    pub a1_envelope: &'a BpvPolicyEnvelope,
    pub raw_a1_envelope: &'a [u8],
    pub a1_request: &'a BpvVerificationRequest,
    pub a1_receipt: &'a BpvVerificationReceipt,
    pub a2_attestation: &'a KcvCustodyAttestation,
    pub raw_a2_attestation: &'a [u8],
    pub a2_request: &'a KcvVerificationRequest,
    pub a2_receipt: &'a KcvVerificationReceipt,
    pub raw_a3_snapshot: &'a [u8],
    pub a3_request: &'a KrvVerificationRequest,
    pub a3_receipt: &'a KrvVerificationReceipt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TwvFaultCode {
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
    Expectation,
    Sequence,
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
pub struct TwvFault {
    pub code: TwvFaultCode,
    pub message: String,
}
impl fmt::Display for TwvFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}
impl std::error::Error for TwvFault {}

pub fn verify_twv_time_witness(
    request: &TwvVerificationRequest,
    predecessor: &TwvPredecessor<'_>,
    raw_witness: &[u8],
) -> Result<TwvVerificationReceipt, TwvFault> {
    validate_request_shape(request)?;
    let a3 = verify_krv_revocation_snapshot(
        predecessor.a3_request,
        predecessor.request,
        predecessor.packet,
        predecessor.verification,
        predecessor.a1_envelope,
        predecessor.raw_a1_envelope,
        predecessor.a1_request,
        predecessor.a1_receipt,
        predecessor.a2_attestation,
        predecessor.raw_a2_attestation,
        predecessor.a2_request,
        predecessor.a2_receipt,
        predecessor.raw_a3_snapshot,
    )
    .map_err(predecessor_fault)?;
    if a3 != *predecessor.a3_receipt || a3.status != KRV_STATUS || a3.authority != KRV_AUTHORITY {
        return Err(fault(TwvFaultCode::Predecessor, "A3 replay differs"));
    }
    if request.predecessor_request_sha256 != predecessor.request.request_sha256
        || request.predecessor_packet_sha256 != predecessor.packet.packet_sha256
        || request.predecessor_verification_sha256 != predecessor.verification.verification_sha256
        || request.a1_policy_envelope_raw_sha256 != sha256_bytes(predecessor.raw_a1_envelope)
        || request.a1_verification_request_sha256 != predecessor.a1_request.request_sha256
        || request.a1_receipt_sha256 != predecessor.a1_receipt.receipt_sha256
        || request.a2_custody_attestation_raw_sha256 != sha256_bytes(predecessor.raw_a2_attestation)
        || request.a2_verification_request_sha256 != predecessor.a2_request.request_sha256
        || request.a2_receipt_sha256 != predecessor.a2_receipt.receipt_sha256
        || request.a3_revocation_snapshot_raw_sha256 != sha256_bytes(predecessor.raw_a3_snapshot)
        || request.a3_verification_request_sha256 != predecessor.a3_request.request_sha256
        || request.a3_receipt_sha256 != a3.receipt_sha256
    {
        return Err(fault(
            TwvFaultCode::Predecessor,
            "predecessor raw or receipt binding differs",
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
            TwvFaultCode::Digest,
            "current packet reconstruction differs",
        ));
    }
    validate_packet_transition(
        &predecessor.a3_request.authority_packet_request,
        &request.authority_packet_request,
        &a3,
    )?;
    let descriptor = &request.authority_packet_request.descriptors[3];
    if descriptor.ordinal != 4
        || descriptor.authority_name != "current_time"
        || descriptor.artifact_kind != "trusted_time_witness_receipt_candidate"
        || descriptor.required_verifier_profile != "trusted-time-witness-verifier/0.1"
        || descriptor.confidentiality != B1OaprConfidentiality::PublicMetadata
        || descriptor.dependency_ordinal != Some(3)
        || descriptor.candidate_uuid != request.a4_candidate_uuid
        || descriptor.descriptor_sha256 != request.a4_descriptor_sha256
    {
        return Err(fault(TwvFaultCode::Coordinate, "A4 descriptor differs"));
    }
    let fixture = is_fixture(request.input_class);
    let origin = if fixture {
        B1OaprCandidateOrigin::DeterministicFixtureCandidate
    } else {
        B1OaprCandidateOrigin::ExternallySuppliedCandidate
    };
    if descriptor.origin != origin || descriptor.fixture_only != fixture {
        return Err(fault(TwvFaultCode::Identity, "A4 input class differs"));
    }
    if raw_witness.is_empty() || raw_witness.len() > TWV_MAX_FORM_BYTES {
        return Err(fault(TwvFaultCode::Size, "raw witness exceeds bound"));
    }
    if request.time_witness_receipt_bytes != raw_witness.len() as u64
        || descriptor.declared_bytes != raw_witness.len() as u64
        || request.time_witness_receipt_raw_sha256 != sha256_bytes(raw_witness)
        || descriptor.content_sha256 != request.time_witness_receipt_raw_sha256
    {
        return Err(fault(
            TwvFaultCode::RawBytes,
            "A4 raw witness identity differs",
        ));
    }
    let text = std::str::from_utf8(raw_witness).map_err(machine_fault)?;
    let witness = from_twv_witness_machine_form(text)?;
    validate_witness_correspondence(request, &witness, &a3)?;
    let receipt = build_receipt(request, &witness, &a3)?;
    validate_twv_receipt(request, &witness, &a3, &receipt)?;
    Ok(receipt)
}

fn validate_request_shape(request: &TwvVerificationRequest) -> Result<(), TwvFault> {
    bounded_value(request)?;
    if request.profile != TWV_REQUEST_PROFILE {
        return Err(fault(TwvFaultCode::Profile, "request profile differs"));
    }
    if request.source_snapshot_uuid != TWV_SOURCE_SNAPSHOT_UUID
        || request.canonical_uuid != TWV_CANONICAL_UUID
        || request.signature_uuid != TWV_SIGNATURE_UUID
        || request.source_custody_commit != TWV_SOURCE_CUSTODY_COMMIT
        || request.formation_commit != TWV_FORMATION_COMMIT
        || request.formation_bookend_commit != TWV_FORMATION_BOOKEND_COMMIT
        || request.a3_implementation_commit != TWV_A3_IMPLEMENTATION_COMMIT
        || request.a3_bookend_commit != TWV_A3_BOOKEND_COMMIT
        || request.a3_proof_uuid != TWV_A3_PROOF_UUID
    {
        return Err(fault(
            TwvFaultCode::Lineage,
            "request governance lineage differs",
        ));
    }
    if !valid_uuid(&request.a4_candidate_uuid)
        || !valid_uuid(&request.expected_witness_uuid)
        || !safe_text(&request.expected_witness_authority_label)
    {
        return Err(fault(
            TwvFaultCode::Expectation,
            "witness expectation shape differs",
        ));
    }
    if request.expected_sequence == 0 {
        return Err(fault(
            TwvFaultCode::Sequence,
            "expected sequence must be positive",
        ));
    }
    let expected_key = decode_fixed_hex::<32>(
        &request.expected_witness_verifying_key_hex,
        "expected witness key",
    )?;
    if request.expected_witness_public_key_fingerprint_sha256 != sha256_bytes(&expected_key) {
        return Err(fault(TwvFaultCode::Key, "expected key fingerprint differs"));
    }
    if request.evidence_references.is_empty()
        || request.evidence_references.len() > TWV_MAX_EVIDENCE_REFERENCES
        || request.evidence_references.iter().any(|s| !safe_text(s))
        || request
            .evidence_references
            .iter()
            .enumerate()
            .any(|(i, v)| request.evidence_references[..i].contains(v))
    {
        return Err(fault(
            TwvFaultCode::Evidence,
            "opaque evidence-reference bounds differ",
        ));
    }
    if request.maximum_attempts != 1
        || request.automatic_retry_count != 0
        || request.automatic_cleanup_count != 0
    {
        return Err(fault(
            TwvFaultCode::Effect,
            "attempt retry or cleanup policy differs",
        ));
    }
    if request.request_sha256 != twv_request_digest(request)? {
        return Err(fault(TwvFaultCode::Digest, "request digest differs"));
    }
    Ok(())
}

fn validate_packet_transition(
    a3: &B1OaprRequest,
    current: &B1OaprRequest,
    receipt: &KrvVerificationReceipt,
) -> Result<(), TwvFault> {
    if a3.descriptors.len() != 9 || current.descriptors.len() != 9 {
        return Err(fault(
            TwvFaultCode::Coordinate,
            "packet coordinate count differs",
        ));
    }
    if a3.descriptors[..3] != current.descriptors[..3]
        || a3.descriptors[4..] != current.descriptors[4..]
        || current.descriptors[2].candidate_uuid != receipt.a3_candidate_uuid
        || current.descriptors[2].descriptor_sha256 != receipt.a3_descriptor_sha256
        || current.descriptors[2].content_sha256 != receipt.revocation_snapshot_raw_sha256
    {
        return Err(fault(
            TwvFaultCode::Dependency,
            "A4 transition changes an upstream or downstream coordinate",
        ));
    }
    let mut normalized = current.clone();
    normalized.descriptors[3] = a3.descriptors[3].clone();
    normalized.request_sha256 = a3.request_sha256.clone();
    if normalized != *a3 {
        return Err(fault(
            TwvFaultCode::Lineage,
            "A4 transition changes more than selected descriptor",
        ));
    }
    Ok(())
}

pub fn validate_twv_witness(witness: &TwvTimeWitness) -> Result<(), TwvFault> {
    bounded_value(witness)?;
    if witness.profile != TWV_WITNESS_PROFILE {
        return Err(fault(TwvFaultCode::Profile, "witness profile differs"));
    }
    if !valid_uuid(&witness.witness_uuid)
        || !valid_uuid(&witness.policy_uuid)
        || !valid_uuid(&witness.policy_revision_uuid)
        || !valid_uuid(&witness.a4_candidate_uuid)
        || witness.subject != EXACT_SUBJECT
        || witness.branch != EXACT_BRANCH
        || witness.canonical_remote != EXACT_REMOTE
        || !safe_text(&witness.authority_label)
        || witness.candidate_label
            != if is_fixture(witness.input_class) {
                "fixture_a4_time_witness_candidate"
            } else {
                "external_a4_time_witness_candidate"
            }
        || witness.fixture_only != is_fixture(witness.input_class)
    {
        return Err(fault(
            TwvFaultCode::Identity,
            "witness subject or input-class identity differs",
        ));
    }
    if witness.production_authority_claimed
        || witness.witness_identity_proved
        || witness.witness_authority_proved
        || witness.witness_freshness_proved
        || witness.trusted_current_time_proved
    {
        return Err(fault(
            TwvFaultCode::Truth,
            "witness promotes supplied correspondence into authority",
        ));
    }
    if witness.sequence == 0 {
        return Err(fault(TwvFaultCode::Sequence, "witness sequence is zero"));
    }
    if witness.issued_at_unix_ms > witness.observed_unix_ms
        || witness.observed_unix_ms > witness.expires_at_unix_ms
    {
        return Err(fault(
            TwvFaultCode::Interval,
            "witness structural time bounds differ",
        ));
    }
    if witness.signing_context != TWV_SIGNING_CONTEXT {
        return Err(fault(
            TwvFaultCode::Signature,
            "witness signing context differs",
        ));
    }
    let key_bytes = decode_fixed_hex::<32>(&witness.witness_verifying_key_hex, "witness key")?;
    if witness.witness_public_key_fingerprint_sha256 != sha256_bytes(&key_bytes) {
        return Err(fault(TwvFaultCode::Key, "witness key fingerprint differs"));
    }
    if witness.witness_sha256 != twv_witness_digest(witness)? {
        return Err(fault(TwvFaultCode::Digest, "witness self digest differs"));
    }
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| fault(TwvFaultCode::Key, "witness key refused"))?;
    let signature = decode_fixed_hex::<64>(&witness.signature_hex, "witness signature")?;
    key.verify_strict(
        &twv_signature_payload_bytes(witness)?,
        &Signature::from_bytes(&signature),
    )
    .map_err(|_| {
        fault(
            TwvFaultCode::Signature,
            "witness detached signature refused",
        )
    })?;
    Ok(())
}

fn validate_witness_correspondence(
    request: &TwvVerificationRequest,
    witness: &TwvTimeWitness,
    a3: &KrvVerificationReceipt,
) -> Result<(), TwvFault> {
    if witness.witness_uuid != request.expected_witness_uuid
        || witness.authority_label != request.expected_witness_authority_label
        || witness.sequence != request.expected_sequence
    {
        return Err(fault(
            TwvFaultCode::Expectation,
            "witness identity label or sequence does not match request",
        ));
    }
    if witness.witness_verifying_key_hex != request.expected_witness_verifying_key_hex
        || witness.witness_public_key_fingerprint_sha256
            != request.expected_witness_public_key_fingerprint_sha256
    {
        return Err(fault(
            TwvFaultCode::Key,
            "witness key differs from explicit request pin",
        ));
    }
    if witness.a4_candidate_uuid != request.a4_candidate_uuid
        || witness.input_class != request.input_class
        || witness.a1_receipt_sha256 != request.a1_receipt_sha256
        || witness.a2_receipt_sha256 != request.a2_receipt_sha256
        || witness.a3_receipt_sha256 != request.a3_receipt_sha256
        || witness.a3_receipt_sha256 != a3.receipt_sha256
        || witness.a3_authority_packet_sha256 != a3.authority_packet_sha256
        || witness.a3_snapshot_sha256 != a3.snapshot_sha256
        || witness.a3_snapshot_raw_sha256 != a3.revocation_snapshot_raw_sha256
        || witness.a3_snapshot_raw_sha256 != request.a3_revocation_snapshot_raw_sha256
        || witness.policy_uuid != a3.policy_uuid
        || witness.policy_revision_uuid != a3.policy_revision_uuid
        || witness.target_policy_key_fingerprint_sha256 != a3.target_public_key_fingerprint_sha256
    {
        return Err(fault(
            TwvFaultCode::Dependency,
            "witness A3 lineage or A4 input binding differs",
        ));
    }
    Ok(())
}

/// A closed interval comparison of supplied integers; no clock or freshness claim.
pub fn compare_twv_supplied_interval(
    observed: u64,
    this_update: u64,
    next_update: u64,
) -> Result<TwvIntervalRelation, TwvFault> {
    if this_update >= next_update {
        return Err(fault(
            TwvFaultCode::Interval,
            "A3 interval is empty or inverted",
        ));
    }
    Ok(if observed < this_update {
        TwvIntervalRelation::BeforeSnapshotInterval
    } else if observed > next_update {
        TwvIntervalRelation::AfterSnapshotInterval
    } else {
        TwvIntervalRelation::WithinSnapshotInterval
    })
}

fn build_receipt(
    request: &TwvVerificationRequest,
    witness: &TwvTimeWitness,
    a3: &KrvVerificationReceipt,
) -> Result<TwvVerificationReceipt, TwvFault> {
    let mut receipt = TwvVerificationReceipt {
        profile: TWV_RECEIPT_PROFILE.to_owned(),
        status: TWV_STATUS.to_owned(),
        authority: TWV_AUTHORITY.to_owned(),
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
        a3_revocation_snapshot_raw_sha256: request.a3_revocation_snapshot_raw_sha256.clone(),
        a3_verification_request_sha256: request.a3_verification_request_sha256.clone(),
        a3_receipt_sha256: request.a3_receipt_sha256.clone(),
        authority_packet_request_sha256: request.authority_packet_request_sha256.clone(),
        authority_packet_sha256: request.authority_packet_sha256.clone(),
        request_sha256: request.request_sha256.clone(),
        a4_candidate_uuid: request.a4_candidate_uuid.clone(),
        a4_descriptor_sha256: request.a4_descriptor_sha256.clone(),
        time_witness_receipt_bytes: request.time_witness_receipt_bytes,
        time_witness_receipt_raw_sha256: request.time_witness_receipt_raw_sha256.clone(),
        witness_uuid: witness.witness_uuid.clone(),
        authority_label: witness.authority_label.clone(),
        policy_uuid: witness.policy_uuid.clone(),
        policy_revision_uuid: witness.policy_revision_uuid.clone(),
        target_policy_key_fingerprint_sha256: witness.target_policy_key_fingerprint_sha256.clone(),
        witness_public_key_fingerprint_sha256: witness
            .witness_public_key_fingerprint_sha256
            .clone(),
        observed_unix_ms: witness.observed_unix_ms,
        issued_at_unix_ms: witness.issued_at_unix_ms,
        expires_at_unix_ms: witness.expires_at_unix_ms,
        sequence: witness.sequence,
        a3_snapshot_sha256: witness.a3_snapshot_sha256.clone(),
        this_update_unix_ms: a3.this_update_unix_ms,
        next_update_unix_ms: a3.next_update_unix_ms,
        comparison_outcome: compare_twv_supplied_interval(
            witness.observed_unix_ms,
            a3.this_update_unix_ms,
            a3.next_update_unix_ms,
        )?,
        witness_sha256: witness.witness_sha256.clone(),
        signature_sha256: sha256_bytes(&decode_fixed_hex::<64>(
            &witness.signature_hex,
            "witness signature",
        )?),
        input_class: request.input_class,
        fixture_only: witness.fixture_only,
        maximum_attempts: request.maximum_attempts,
        automatic_retry_count: request.automatic_retry_count,
        automatic_cleanup_count: request.automatic_cleanup_count,
        packet_replayed: true,
        a1_correspondence_receipt_verified: true,
        a2_correspondence_receipt_verified: true,
        a3_correspondence_receipt_verified: true,
        a4_candidate_bytes_matched: true,
        descriptor_correspondence_verified: true,
        subject_lineage_correspondence_verified: true,
        witness_key_correspondence_verified: true,
        witness_structure_verified: true,
        time_bounds_structure_verified: true,
        witness_signature_correspondence_verified: true,
        supplied_interval_comparison_verified: true,
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
        effect_account: TwvEffectAccount::default(),
        receipt_sha256: empty_digest(),
    };
    receipt.receipt_sha256 = twv_receipt_digest(&receipt)?;
    Ok(receipt)
}

/// Validates local receipt correspondence; full predecessor correspondence is replayed by verify_twv_time_witness.
pub fn validate_twv_receipt(
    request: &TwvVerificationRequest,
    witness: &TwvTimeWitness,
    a3: &KrvVerificationReceipt,
    receipt: &TwvVerificationReceipt,
) -> Result<(), TwvFault> {
    validate_request_shape(request)?;
    validate_twv_witness(witness)?;
    validate_witness_correspondence(request, witness, a3)?;
    bounded_value(receipt)?;
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
    {
        return Err(fault(
            TwvFaultCode::Truth,
            "receipt promotes an authority claim",
        ));
    }
    if !receipt.packet_replayed
        || !receipt.a1_correspondence_receipt_verified
        || !receipt.a2_correspondence_receipt_verified
        || !receipt.a3_correspondence_receipt_verified
        || !receipt.a4_candidate_bytes_matched
        || !receipt.descriptor_correspondence_verified
        || !receipt.subject_lineage_correspondence_verified
        || !receipt.witness_key_correspondence_verified
        || !receipt.witness_structure_verified
        || !receipt.time_bounds_structure_verified
        || !receipt.witness_signature_correspondence_verified
        || !receipt.supplied_interval_comparison_verified
    {
        return Err(fault(
            TwvFaultCode::Truth,
            "receipt correspondence truth differs",
        ));
    }
    if receipt.effect_account != TwvEffectAccount::default()
        || receipt.maximum_attempts != 1
        || receipt.automatic_retry_count != 0
        || receipt.automatic_cleanup_count != 0
    {
        return Err(fault(
            TwvFaultCode::Effect,
            "receipt effect or attempt account differs",
        ));
    }
    if receipt.receipt_sha256 != twv_receipt_digest(receipt)? {
        return Err(fault(TwvFaultCode::Digest, "receipt digest differs"));
    }
    if *receipt != build_receipt(request, witness, a3)? {
        return Err(fault(
            TwvFaultCode::Receipt,
            "receipt differs from reconstructed correspondence",
        ));
    }
    Ok(())
}

pub fn twv_witness_digest(witness: &TwvTimeWitness) -> Result<ContentDigest, TwvFault> {
    let mut normalized = witness.clone();
    normalized.witness_sha256 = empty_digest();
    domain_digest("cantor.b1.time-witness.digest.v1", &normalized)
}
pub fn twv_request_digest(request: &TwvVerificationRequest) -> Result<ContentDigest, TwvFault> {
    let mut normalized = request.clone();
    normalized.request_sha256 = empty_digest();
    domain_digest("cantor.b1.time-witness.request.v1", &normalized)
}
pub fn twv_receipt_digest(receipt: &TwvVerificationReceipt) -> Result<ContentDigest, TwvFault> {
    let mut normalized = receipt.clone();
    normalized.receipt_sha256 = empty_digest();
    domain_digest("cantor.b1.time-witness.receipt.v1", &normalized)
}
pub fn twv_signature_payload_bytes(witness: &TwvTimeWitness) -> Result<Vec<u8>, TwvFault> {
    let mut normalized = witness.clone();
    normalized.signature_hex.clear();
    normalized.witness_sha256 = empty_digest();
    domain_bytes(TWV_SIGNING_CONTEXT, &normalized)
}
pub fn to_twv_witness_machine_form(witness: &TwvTimeWitness) -> Result<String, TwvFault> {
    validate_twv_witness(witness)?;
    serde_json::to_string(witness).map_err(machine_fault)
}
pub fn from_twv_witness_machine_form(text: &str) -> Result<TwvTimeWitness, TwvFault> {
    let witness = parse_twv_canonical(text)?;
    validate_twv_witness(&witness)?;
    Ok(witness)
}
pub fn to_twv_request_machine_form(request: &TwvVerificationRequest) -> Result<String, TwvFault> {
    validate_request_shape(request)?;
    serde_json::to_string(request).map_err(machine_fault)
}
pub fn from_twv_request_machine_form(text: &str) -> Result<TwvVerificationRequest, TwvFault> {
    let request = parse_twv_canonical(text)?;
    validate_request_shape(&request)?;
    Ok(request)
}
pub fn to_twv_receipt_machine_form(
    request: &TwvVerificationRequest,
    witness: &TwvTimeWitness,
    a3: &KrvVerificationReceipt,
    receipt: &TwvVerificationReceipt,
) -> Result<String, TwvFault> {
    validate_twv_receipt(request, witness, a3, receipt)?;
    serde_json::to_string(receipt).map_err(machine_fault)
}
pub fn from_twv_receipt_machine_form(
    request: &TwvVerificationRequest,
    witness: &TwvTimeWitness,
    a3: &KrvVerificationReceipt,
    text: &str,
) -> Result<TwvVerificationReceipt, TwvFault> {
    let receipt = parse_twv_canonical(text)?;
    validate_twv_receipt(request, witness, a3, &receipt)?;
    Ok(receipt)
}
pub fn expected_twv_downstream_authorities() -> Vec<String> {
    [
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

pub(crate) fn parse_twv_canonical<T: DeserializeOwned + Serialize>(
    text: &str,
) -> Result<T, TwvFault> {
    if text.is_empty()
        || text.len() > TWV_MAX_FORM_BYTES
        || text.starts_with('\u{feff}')
        || text.contains('\r')
        || text.contains('\n')
    {
        return Err(fault(
            TwvFaultCode::MachineForm,
            "machine form framing or size differs",
        ));
    }
    let raw: Value = serde_json::from_str(text).map_err(machine_fault)?;
    let mut fields = 0;
    measure_value(&raw, 1, &mut fields)?;
    let value: T = serde_json::from_value(raw).map_err(machine_fault)?;
    if serde_json::to_string(&value).map_err(machine_fault)? != text {
        return Err(fault(
            TwvFaultCode::MachineForm,
            "machine form is not compact canonical JSON",
        ));
    }
    Ok(value)
}
fn bounded_value<T: Serialize>(value: &T) -> Result<(), TwvFault> {
    let bytes = serde_json::to_vec(value).map_err(machine_fault)?;
    if bytes.len() > TWV_MAX_FORM_BYTES {
        return Err(fault(TwvFaultCode::Size, "typed form exceeds byte limit"));
    }
    let raw = serde_json::to_value(value).map_err(machine_fault)?;
    measure_value(&raw, 1, &mut 0)
}
fn measure_value(value: &Value, depth: usize, fields: &mut usize) -> Result<(), TwvFault> {
    if depth > MAX_JSON_DEPTH {
        return Err(fault(TwvFaultCode::Size, "JSON depth exceeds bound"));
    }
    match value {
        Value::Object(items) => {
            *fields = fields
                .checked_add(items.len())
                .ok_or_else(|| fault(TwvFaultCode::Arithmetic, "JSON field count overflow"))?;
            if *fields > MAX_JSON_FIELDS {
                return Err(fault(TwvFaultCode::Size, "JSON field count exceeds bound"));
            }
            for (key, value) in items {
                if !safe_text(key) {
                    return Err(fault(TwvFaultCode::Shape, "JSON key differs"));
                }
                measure_value(value, depth + 1, fields)?;
            }
        }
        Value::Array(items) => {
            if items.len() > MAX_JSON_FIELDS {
                return Err(fault(TwvFaultCode::Size, "JSON array exceeds bound"));
            }
            for value in items {
                measure_value(value, depth + 1, fields)?;
            }
        }
        Value::String(value)
            if value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) =>
        {
            return Err(fault(TwvFaultCode::Shape, "JSON text exceeds bounds"));
        }
        _ => {}
    }
    Ok(())
}
pub(crate) fn valid_twv_uuid(value: &str) -> bool {
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
fn decode_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], TwvFault> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(fault(
            TwvFaultCode::Shape,
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
fn domain_bytes<T: Serialize>(domain: &str, value: &T) -> Result<Vec<u8>, TwvFault> {
    let canonical = serde_json::to_vec(value).map_err(machine_fault)?;
    let capacity = domain
        .len()
        .checked_add(1)
        .and_then(|v| v.checked_add(canonical.len()))
        .ok_or_else(|| fault(TwvFaultCode::Arithmetic, "domain byte length overflow"))?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}
fn domain_digest<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, TwvFault> {
    Ok(sha256_bytes(&domain_bytes(domain, value)?))
}
fn empty_digest() -> ContentDigest {
    sha256_bytes(b"")
}
fn predecessor_fault(error: impl fmt::Display) -> TwvFault {
    fault(TwvFaultCode::Predecessor, error)
}
fn machine_fault(error: impl fmt::Display) -> TwvFault {
    fault(TwvFaultCode::MachineForm, error)
}
pub(crate) fn twv_fault(code: TwvFaultCode, message: impl fmt::Display) -> TwvFault {
    fault(code, message)
}
fn fault(code: TwvFaultCode, message: impl fmt::Display) -> TwvFault {
    TwvFault {
        code,
        message: message.to_string(),
    }
}
