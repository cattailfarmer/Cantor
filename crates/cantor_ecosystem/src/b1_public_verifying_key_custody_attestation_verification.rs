//! Provider-free verification of one supplied A2 public-key custody attestation.
//!
//! A successful receipt proves only that the A1 verifying key validates a
//! purpose-bound supplied challenge signature. It does not prove challenge
//! freshness, replay prevention, custodian identity, protected storage,
//! nonexportability, exclusive control, current possession, custody authority,
//! policy governance, or execution authority.

use std::fmt;

use cantor_core::{ContentDigest, sha256_bytes};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{
    B1OAPR_AUTHORITY, B1OAPR_STATUS, B1OaprCandidateDescriptor, B1OaprCandidateOrigin,
    B1OaprConfidentiality, B1OaprPacket, B1OaprRequest, B1OaprVerification, BPV_AUTHORITY,
    BPV_STATUS, BpvPolicyEnvelope, BpvVerificationReceipt, BpvVerificationRequest,
    b1oapr_packet_digest, compile_b1oapr_packet, from_bpv_envelope_machine_form,
    to_b1oapr_packet_machine_form, verify_b1oapr_packet, verify_bpv_policy_bundle,
};

pub const KCV_ATTESTATION_PROFILE: &str = "cantor-b1-public-verifying-key-custody-attestation/0.1";
pub const KCV_CHALLENGE_PROFILE: &str = "cantor-b1-key-custody-proof-challenge/0.1";
pub const KCV_REQUEST_PROFILE: &str =
    "cantor-b1-public-verifying-key-custody-verification-request/0.1";
pub const KCV_RECEIPT_PROFILE: &str =
    "cantor-b1-public-verifying-key-custody-verification-receipt/0.1";
pub const KCV_STATUS: &str = "custody_proof_signature_correspondence_verified_live_custody_and_all_execution_authority_unresolved";
pub const KCV_AUTHORITY: &str = "key_custody_proof_correspondence_only";
pub const KCV_SIGNING_CONTEXT: &str = "cantor-b1-key-custody-proof-of-possession/0.1";
pub const KCV_SOURCE_SNAPSHOT_UUID: &str = "957fa5a6-34eb-41da-8c95-2a1dc89cc3bb";
pub const KCV_CANONICAL_UUID: &str = "668ae1a2-e8c9-4f88-9556-a39585817105";
pub const KCV_SIGNATURE_UUID: &str = "fd889970-8468-447c-bf1c-58d22b9c64a1";
pub const KCV_SOURCE_CUSTODY_COMMIT: &str = "c94c2eeb104243fd9e83ee67c4ad6a763f4bdfbc";
pub const KCV_FORMATION_COMMIT: &str = "9fbf9be76184b082690b761bc2b6f67997417727";
pub const KCV_FORMATION_BOOKEND_COMMIT: &str = "1a2743e3c4a44f289b537d6e9e83694e51d21692";
pub const KCV_A1_IMPLEMENTATION_COMMIT: &str = "2456514705bd341098c44688aad048e82b5b5a9e";
pub const KCV_A1_BOOKEND_COMMIT: &str = "d74abf78fdccc4d2891da61dca487ef6ad2dbfe5";
pub const KCV_A1_PROOF_UUID: &str = "8d867069-9bca-4529-869f-e05f7c04f54f";
pub const KCV_MAX_FORM_BYTES: usize = 1_048_576;
pub const KCV_MAX_EVIDENCE_BYTES: u64 = 12_582_912;
pub const KCV_MAX_EVIDENCE_REFERENCES: usize = 32;

const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_FIELDS: usize = 3_072;
const MAX_TEXT_BYTES: usize = 8_192;
const EXACT_BRANCH: &str = "codex/self-hosted-corpus";
const EXACT_REMOTE: &str = "https://github.com/cattailfarmer/Cantor";
const EXACT_SUBJECT: &str = "cantor_b1_cdrive_production_preparation_p0";
const EXACT_CHALLENGE_DOMAIN: &str = "cantor.b1.key-custody-proof.challenge.v1";
const EXACT_CUSTODY_PURPOSE: &str = "prove_correspondence_to_a1_public_verifying_key_only";
const ATTESTATION_DOMAIN: &str = "cantor.b1.key-custody-proof.attestation.v1";
const CHALLENGE_DOMAIN: &str = "cantor.b1.key-custody-proof.challenge-digest.v1";
const REQUEST_DOMAIN: &str = "cantor.b1.key-custody-proof.request.v1";
const RECEIPT_DOMAIN: &str = "cantor.b1.key-custody-proof.receipt.v1";
const SIGNATURE_DOMAIN: &str = "cantor.b1.key-custody-proof.signature.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KcvInputClass {
    DeterministicFixtureCandidate,
    ExternallySuppliedCandidate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KcvChallenge {
    pub profile: String,
    pub challenge_uuid: String,
    pub challenge_domain: String,
    pub subject: String,
    pub branch: String,
    pub canonical_remote: String,
    pub policy_uuid: String,
    pub policy_revision_uuid: String,
    pub a1_receipt_sha256: ContentDigest,
    pub a2_candidate_uuid: String,
    pub custody_proof_uuid: String,
    pub public_key_fingerprint_sha256: ContentDigest,
    pub issuer_class: KcvInputClass,
    pub fixture_only: bool,
    pub nonce_hex: String,
    pub challenge_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KcvCustodyAttestation {
    pub profile: String,
    pub attestation_uuid: String,
    pub custody_proof_uuid: String,
    pub candidate_label: String,
    pub custodian_label: String,
    pub custody_purpose: String,
    pub subject: String,
    pub branch: String,
    pub canonical_remote: String,
    pub policy_uuid: String,
    pub policy_revision_uuid: String,
    pub a1_implementation_commit: String,
    pub a1_bookend_commit: String,
    pub a1_proof_uuid: String,
    pub a1_receipt_sha256: ContentDigest,
    pub verifying_key_hex: String,
    pub public_key_fingerprint_sha256: ContentDigest,
    pub challenge: KcvChallenge,
    pub signing_context: String,
    pub signature_hex: String,
    pub input_class: KcvInputClass,
    pub fixture_only: bool,
    pub production_authority_claimed: bool,
    pub challenge_freshness_proved: bool,
    pub replay_prevention_proved: bool,
    pub custodian_identity_proved: bool,
    pub protected_storage_proved: bool,
    pub private_key_nonexportability_proved: bool,
    pub exclusive_control_proved: bool,
    pub current_possession_proved: bool,
    pub key_custody_proved: bool,
    pub attestation_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KcvVerificationRequest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_custody_commit: String,
    pub formation_commit: String,
    pub formation_bookend_commit: String,
    pub a1_implementation_commit: String,
    pub a1_bookend_commit: String,
    pub a1_proof_uuid: String,
    pub predecessor_request_sha256: ContentDigest,
    pub predecessor_packet_sha256: ContentDigest,
    pub predecessor_verification_sha256: ContentDigest,
    pub a1_policy_envelope_raw_sha256: ContentDigest,
    pub a1_verification_request_sha256: ContentDigest,
    pub a1_receipt_sha256: ContentDigest,
    pub authority_packet_request: B1OaprRequest,
    pub authority_packet_request_sha256: ContentDigest,
    pub authority_packet_sha256: ContentDigest,
    pub a2_candidate_uuid: String,
    pub a2_descriptor_sha256: ContentDigest,
    pub custody_attestation_bytes: u64,
    pub custody_attestation_raw_sha256: ContentDigest,
    pub input_class: KcvInputClass,
    pub evidence_references: Vec<String>,
    pub maximum_attempts: u8,
    pub automatic_retry_count: u8,
    pub automatic_cleanup_count: u8,
    pub request_sha256: ContentDigest,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KcvEffectAccount {
    pub reference_resolution_count: u32,
    pub private_key_read_count: u32,
    pub key_generation_count: u32,
    pub signing_count: u32,
    pub challenge_issuance_count: u32,
    pub replay_store_count: u32,
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
pub struct KcvVerificationReceipt {
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
    pub authority_packet_request_sha256: ContentDigest,
    pub authority_packet_sha256: ContentDigest,
    pub request_sha256: ContentDigest,
    pub a2_candidate_uuid: String,
    pub a2_descriptor_sha256: ContentDigest,
    pub custody_attestation_bytes: u64,
    pub custody_attestation_raw_sha256: ContentDigest,
    pub attestation_uuid: String,
    pub custody_proof_uuid: String,
    pub challenge_uuid: String,
    pub policy_uuid: String,
    pub policy_revision_uuid: String,
    pub public_key_fingerprint_sha256: ContentDigest,
    pub challenge_sha256: ContentDigest,
    pub signature_sha256: ContentDigest,
    pub packet_replayed: bool,
    pub a1_correspondence_receipt_verified: bool,
    pub a2_candidate_bytes_matched: bool,
    pub descriptor_correspondence_verified: bool,
    pub policy_key_correspondence_verified: bool,
    pub challenge_structure_verified: bool,
    pub possession_signature_correspondence_verified: bool,
    pub fixture_only: bool,
    pub production_authority_claimed: bool,
    pub challenge_freshness_proved: bool,
    pub replay_prevention_proved: bool,
    pub custodian_identity_proved: bool,
    pub protected_storage_proved: bool,
    pub private_key_nonexportability_proved: bool,
    pub exclusive_control_proved: bool,
    pub current_possession_proved: bool,
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
    pub effect_account: KcvEffectAccount,
    pub receipt_sha256: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KcvFaultCode {
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
    Challenge,
    Nonce,
    Context,
    Issuer,
    Fixture,
    Claim,
    Signature,
    Receipt,
    Truth,
    Effect,
    Evidence,
    Arithmetic,
    Restart,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KcvFault {
    pub code: KcvFaultCode,
    pub message: String,
}

impl fmt::Display for KcvFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for KcvFault {}

#[allow(clippy::too_many_arguments)]
pub fn verify_kcv_custody_attestation(
    request: &KcvVerificationRequest,
    predecessor_request: &B1OaprRequest,
    predecessor_packet: &B1OaprPacket,
    predecessor_verification: &B1OaprVerification,
    a1_envelope: &BpvPolicyEnvelope,
    raw_a1_envelope: &[u8],
    a1_request: &BpvVerificationRequest,
    a1_receipt: &BpvVerificationReceipt,
    raw_attestation: &[u8],
) -> Result<KcvVerificationReceipt, KcvFault> {
    let (packet, descriptor) = validate_kcv_request(
        request,
        predecessor_request,
        predecessor_packet,
        predecessor_verification,
        a1_envelope,
        raw_a1_envelope,
        a1_request,
        a1_receipt,
        raw_attestation,
    )?;
    let text = std::str::from_utf8(raw_attestation).map_err(|_| {
        fault(
            KcvFaultCode::MachineForm,
            "custody attestation is not UTF-8",
        )
    })?;
    let attestation: KcvCustodyAttestation = parse_canonical(text)?;
    validate_kcv_attestation(&attestation)?;
    validate_attestation_correspondence(
        request,
        descriptor,
        a1_envelope,
        a1_receipt,
        &attestation,
    )?;
    let signature = decode_fixed_hex::<64>(&attestation.signature_hex, "signature")?;
    let mut receipt = KcvVerificationReceipt {
        profile: KCV_RECEIPT_PROFILE.to_owned(),
        status: KCV_STATUS.to_owned(),
        authority: KCV_AUTHORITY.to_owned(),
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
        authority_packet_request_sha256: request.authority_packet_request_sha256.clone(),
        authority_packet_sha256: packet.packet_sha256,
        request_sha256: request.request_sha256.clone(),
        a2_candidate_uuid: descriptor.candidate_uuid.clone(),
        a2_descriptor_sha256: descriptor.descriptor_sha256.clone(),
        custody_attestation_bytes: request.custody_attestation_bytes,
        custody_attestation_raw_sha256: request.custody_attestation_raw_sha256.clone(),
        attestation_uuid: attestation.attestation_uuid.clone(),
        custody_proof_uuid: attestation.custody_proof_uuid.clone(),
        challenge_uuid: attestation.challenge.challenge_uuid.clone(),
        policy_uuid: attestation.policy_uuid.clone(),
        policy_revision_uuid: attestation.policy_revision_uuid.clone(),
        public_key_fingerprint_sha256: attestation.public_key_fingerprint_sha256.clone(),
        challenge_sha256: attestation.challenge.challenge_sha256.clone(),
        signature_sha256: domain_bytes_digest(SIGNATURE_DOMAIN, &signature),
        packet_replayed: true,
        a1_correspondence_receipt_verified: true,
        a2_candidate_bytes_matched: true,
        descriptor_correspondence_verified: true,
        policy_key_correspondence_verified: true,
        challenge_structure_verified: true,
        possession_signature_correspondence_verified: true,
        fixture_only: attestation.fixture_only,
        production_authority_claimed: false,
        challenge_freshness_proved: false,
        replay_prevention_proved: false,
        custodian_identity_proved: false,
        protected_storage_proved: false,
        private_key_nonexportability_proved: false,
        exclusive_control_proved: false,
        current_possession_proved: false,
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
        effect_account: KcvEffectAccount::default(),
        receipt_sha256: empty_digest(),
    };
    receipt.receipt_sha256 = kcv_receipt_digest(&receipt)?;
    validate_kcv_receipt(request, &attestation, &receipt)?;
    Ok(receipt)
}

#[allow(clippy::too_many_arguments)]
pub fn validate_kcv_request<'a>(
    request: &'a KcvVerificationRequest,
    predecessor_request: &B1OaprRequest,
    predecessor_packet: &B1OaprPacket,
    predecessor_verification: &B1OaprVerification,
    a1_envelope: &BpvPolicyEnvelope,
    raw_a1_envelope: &[u8],
    a1_request: &BpvVerificationRequest,
    a1_receipt: &BpvVerificationReceipt,
    raw_attestation: &[u8],
) -> Result<(B1OaprPacket, &'a B1OaprCandidateDescriptor), KcvFault> {
    validate_predecessor(
        predecessor_request,
        predecessor_packet,
        predecessor_verification,
    )?;
    let raw_a1_text = std::str::from_utf8(raw_a1_envelope)
        .map_err(|_| fault(KcvFaultCode::MachineForm, "A1 envelope is not UTF-8"))?;
    if from_bpv_envelope_machine_form(raw_a1_text).map_err(predecessor_fault)? != *a1_envelope {
        return Err(fault(
            KcvFaultCode::Predecessor,
            "typed and raw A1 envelope differ",
        ));
    }
    let reconstructed_a1 = verify_bpv_policy_bundle(
        a1_request,
        predecessor_request,
        predecessor_packet,
        predecessor_verification,
        raw_a1_envelope,
    )
    .map_err(predecessor_fault)?;
    if reconstructed_a1 != *a1_receipt
        || a1_receipt.status != BPV_STATUS
        || a1_receipt.authority != BPV_AUTHORITY
    {
        return Err(fault(
            KcvFaultCode::Predecessor,
            "A1 correspondence receipt replay differs",
        ));
    }
    if request.profile != KCV_REQUEST_PROFILE
        || request.source_snapshot_uuid != KCV_SOURCE_SNAPSHOT_UUID
        || request.canonical_uuid != KCV_CANONICAL_UUID
        || request.signature_uuid != KCV_SIGNATURE_UUID
        || request.source_custody_commit != KCV_SOURCE_CUSTODY_COMMIT
        || request.formation_commit != KCV_FORMATION_COMMIT
        || request.formation_bookend_commit != KCV_FORMATION_BOOKEND_COMMIT
        || request.a1_implementation_commit != KCV_A1_IMPLEMENTATION_COMMIT
        || request.a1_bookend_commit != KCV_A1_BOOKEND_COMMIT
        || request.a1_proof_uuid != KCV_A1_PROOF_UUID
    {
        return Err(fault(KcvFaultCode::Lineage, "request lineage differs"));
    }
    if request.predecessor_request_sha256 != predecessor_request.request_sha256
        || request.predecessor_packet_sha256 != predecessor_packet.packet_sha256
        || request.predecessor_verification_sha256 != predecessor_verification.verification_sha256
        || request.a1_policy_envelope_raw_sha256 != sha256_bytes(raw_a1_envelope)
        || request.a1_verification_request_sha256 != a1_request.request_sha256
        || request.a1_receipt_sha256 != a1_receipt.receipt_sha256
    {
        return Err(fault(
            KcvFaultCode::Predecessor,
            "predecessor or A1 evidence binding differs",
        ));
    }
    let first =
        compile_b1oapr_packet(&request.authority_packet_request).map_err(predecessor_fault)?;
    let second =
        compile_b1oapr_packet(&request.authority_packet_request).map_err(predecessor_fault)?;
    let first_text = to_b1oapr_packet_machine_form(&request.authority_packet_request, &first)
        .map_err(predecessor_fault)?;
    let second_text = to_b1oapr_packet_machine_form(&request.authority_packet_request, &second)
        .map_err(predecessor_fault)?;
    if first != second
        || first_text != second_text
        || request.authority_packet_request_sha256
            != request.authority_packet_request.request_sha256
        || request.authority_packet_sha256 != first.packet_sha256
    {
        return Err(fault(
            KcvFaultCode::Predecessor,
            "A2 authority packet replay differs",
        ));
    }
    validate_packet_transition(
        predecessor_request,
        &request.authority_packet_request,
        a1_receipt,
    )?;
    let descriptor = request
        .authority_packet_request
        .descriptors
        .get(1)
        .ok_or_else(|| fault(KcvFaultCode::Coordinate, "A2 descriptor is absent"))?;
    if descriptor.ordinal != 2
        || descriptor.authority_name != "key_custody"
        || descriptor.artifact_kind != "public_verifying_key_custody_attestation_candidate"
        || descriptor.required_verifier_profile != "public-key-custody-verifier/0.1"
        || descriptor.confidentiality != B1OaprConfidentiality::PublicMetadata
        || descriptor.dependency_ordinal != Some(1)
        || request.a2_candidate_uuid != descriptor.candidate_uuid
        || request.a2_descriptor_sha256 != descriptor.descriptor_sha256
    {
        return Err(fault(KcvFaultCode::Coordinate, "A2 descriptor differs"));
    }
    let raw_len = u64::try_from(raw_attestation.len())
        .map_err(|_| fault(KcvFaultCode::Arithmetic, "attestation length overflow"))?;
    if raw_attestation.is_empty() || raw_attestation.len() > KCV_MAX_FORM_BYTES {
        return Err(fault(
            KcvFaultCode::Size,
            "raw A2 custody-attestation size differs",
        ));
    }
    if request.custody_attestation_bytes != raw_len
        || descriptor.declared_bytes != raw_len
        || request.custody_attestation_raw_sha256 != sha256_bytes(raw_attestation)
        || descriptor.content_sha256 != request.custody_attestation_raw_sha256
    {
        return Err(fault(
            KcvFaultCode::RawBytes,
            "raw A2 custody-attestation byte identity differs",
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
        || request.evidence_references.len() > KCV_MAX_EVIDENCE_REFERENCES
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
            KcvFaultCode::Bound,
            "input class, evidence references, or bounded account differs",
        ));
    }
    if request.request_sha256 != kcv_request_digest(request)? {
        return Err(fault(KcvFaultCode::Digest, "request digest differs"));
    }
    Ok((first, descriptor))
}

pub fn validate_kcv_attestation(attestation: &KcvCustodyAttestation) -> Result<(), KcvFault> {
    let expected_fixture = matches!(
        attestation.input_class,
        KcvInputClass::DeterministicFixtureCandidate
    );
    if attestation.profile != KCV_ATTESTATION_PROFILE {
        return Err(fault(KcvFaultCode::Profile, "attestation profile differs"));
    }
    if !valid_uuid(&attestation.attestation_uuid)
        || !valid_uuid(&attestation.custody_proof_uuid)
        || attestation.attestation_uuid == attestation.custody_proof_uuid
        || attestation.subject != EXACT_SUBJECT
        || attestation.branch != EXACT_BRANCH
        || attestation.canonical_remote != EXACT_REMOTE
        || attestation.a1_implementation_commit != KCV_A1_IMPLEMENTATION_COMMIT
        || attestation.a1_bookend_commit != KCV_A1_BOOKEND_COMMIT
        || attestation.a1_proof_uuid != KCV_A1_PROOF_UUID
        || attestation.custody_purpose != EXACT_CUSTODY_PURPOSE
        || attestation.candidate_label != expected_candidate_label(attestation.input_class)
        || attestation.custodian_label != expected_custodian_label(attestation.input_class)
    {
        return Err(fault(
            KcvFaultCode::Identity,
            "attestation identity differs",
        ));
    }
    if attestation.fixture_only != expected_fixture {
        return Err(fault(
            KcvFaultCode::Fixture,
            "attestation fixture class differs",
        ));
    }
    if attestation.production_authority_claimed
        || attestation.challenge_freshness_proved
        || attestation.replay_prevention_proved
        || attestation.custodian_identity_proved
        || attestation.protected_storage_proved
        || attestation.private_key_nonexportability_proved
        || attestation.exclusive_control_proved
        || attestation.current_possession_proved
        || attestation.key_custody_proved
    {
        return Err(fault(
            KcvFaultCode::Claim,
            "attestation promotes signature correspondence into custody authority",
        ));
    }
    if !is_lower_hex(&attestation.verifying_key_hex, 64) {
        return Err(fault(KcvFaultCode::Shape, "attestation key shape differs"));
    }
    if attestation.signing_context != KCV_SIGNING_CONTEXT {
        return Err(fault(KcvFaultCode::Context, "signing context differs"));
    }
    validate_kcv_challenge(&attestation.challenge)?;
    if attestation.challenge.custody_proof_uuid != attestation.custody_proof_uuid
        || attestation.challenge.subject != attestation.subject
        || attestation.challenge.branch != attestation.branch
        || attestation.challenge.canonical_remote != attestation.canonical_remote
        || attestation.challenge.policy_uuid != attestation.policy_uuid
        || attestation.challenge.policy_revision_uuid != attestation.policy_revision_uuid
        || attestation.challenge.a1_receipt_sha256 != attestation.a1_receipt_sha256
        || attestation.challenge.public_key_fingerprint_sha256
            != attestation.public_key_fingerprint_sha256
        || attestation.challenge.issuer_class != attestation.input_class
        || attestation.challenge.fixture_only != attestation.fixture_only
    {
        return Err(fault(
            KcvFaultCode::Challenge,
            "challenge and attestation correspondence differs",
        ));
    }
    if !is_lower_hex(&attestation.signature_hex, 128) {
        return Err(fault(KcvFaultCode::Shape, "signature shape differs"));
    }
    if attestation.attestation_sha256 != kcv_attestation_digest(attestation)? {
        return Err(fault(KcvFaultCode::Digest, "attestation digest differs"));
    }
    let key_bytes = decode_fixed_hex::<32>(&attestation.verifying_key_hex, "verifying key")?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| fault(KcvFaultCode::Key, "verifying key refused"))?;
    let signature_bytes = decode_fixed_hex::<64>(&attestation.signature_hex, "signature")?;
    key.verify_strict(
        &kcv_signature_payload_bytes(&attestation.challenge)?,
        &Signature::from_bytes(&signature_bytes),
    )
    .map_err(|_| fault(KcvFaultCode::Signature, "possession signature refused"))?;
    Ok(())
}

pub fn validate_kcv_challenge(challenge: &KcvChallenge) -> Result<(), KcvFault> {
    if challenge.profile != KCV_CHALLENGE_PROFILE
        || !valid_uuid(&challenge.challenge_uuid)
        || challenge.challenge_domain != EXACT_CHALLENGE_DOMAIN
        || challenge.subject != EXACT_SUBJECT
        || challenge.branch != EXACT_BRANCH
        || challenge.canonical_remote != EXACT_REMOTE
        || !valid_uuid(&challenge.policy_uuid)
        || !valid_uuid(&challenge.policy_revision_uuid)
        || challenge.policy_uuid == challenge.policy_revision_uuid
        || !valid_uuid(&challenge.a2_candidate_uuid)
        || !valid_uuid(&challenge.custody_proof_uuid)
    {
        return Err(fault(KcvFaultCode::Challenge, "challenge identity differs"));
    }
    if !is_lower_hex(&challenge.nonce_hex, 64) {
        return Err(fault(
            KcvFaultCode::Nonce,
            "challenge nonce is not 32 bytes",
        ));
    }
    if challenge.fixture_only
        != matches!(
            challenge.issuer_class,
            KcvInputClass::DeterministicFixtureCandidate
        )
    {
        return Err(fault(
            KcvFaultCode::Issuer,
            "challenge issuer class differs",
        ));
    }
    if challenge.challenge_sha256 != kcv_challenge_digest(challenge)? {
        return Err(fault(KcvFaultCode::Digest, "challenge digest differs"));
    }
    Ok(())
}

pub fn validate_kcv_receipt(
    request: &KcvVerificationRequest,
    attestation: &KcvCustodyAttestation,
    receipt: &KcvVerificationReceipt,
) -> Result<(), KcvFault> {
    validate_kcv_attestation(attestation)?;
    let signature = decode_fixed_hex::<64>(&attestation.signature_hex, "signature")?;
    if receipt.profile != KCV_RECEIPT_PROFILE
        || receipt.status != KCV_STATUS
        || receipt.authority != KCV_AUTHORITY
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
        || receipt.authority_packet_request_sha256 != request.authority_packet_request_sha256
        || receipt.authority_packet_sha256 != request.authority_packet_sha256
        || receipt.request_sha256 != request.request_sha256
        || receipt.a2_candidate_uuid != request.a2_candidate_uuid
        || receipt.a2_descriptor_sha256 != request.a2_descriptor_sha256
        || receipt.custody_attestation_bytes != request.custody_attestation_bytes
        || receipt.custody_attestation_raw_sha256 != request.custody_attestation_raw_sha256
        || receipt.attestation_uuid != attestation.attestation_uuid
        || receipt.custody_proof_uuid != attestation.custody_proof_uuid
        || receipt.challenge_uuid != attestation.challenge.challenge_uuid
        || receipt.policy_uuid != attestation.policy_uuid
        || receipt.policy_revision_uuid != attestation.policy_revision_uuid
        || receipt.public_key_fingerprint_sha256 != attestation.public_key_fingerprint_sha256
        || receipt.challenge_sha256 != attestation.challenge.challenge_sha256
        || receipt.signature_sha256 != domain_bytes_digest(SIGNATURE_DOMAIN, &signature)
        || receipt.fixture_only != attestation.fixture_only
    {
        return Err(fault(
            KcvFaultCode::Receipt,
            "receipt correspondence differs",
        ));
    }
    if !receipt.packet_replayed
        || !receipt.a1_correspondence_receipt_verified
        || !receipt.a2_candidate_bytes_matched
        || !receipt.descriptor_correspondence_verified
        || !receipt.policy_key_correspondence_verified
        || !receipt.challenge_structure_verified
        || !receipt.possession_signature_correspondence_verified
    {
        return Err(fault(
            KcvFaultCode::Truth,
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
            KcvFaultCode::Truth,
            "receipt promotes an authority truth",
        ));
    }
    if receipt.effect_account != KcvEffectAccount::default() {
        return Err(fault(KcvFaultCode::Effect, "receipt reports an effect"));
    }
    if receipt.receipt_sha256 != kcv_receipt_digest(receipt)? {
        return Err(fault(KcvFaultCode::Digest, "receipt digest differs"));
    }
    Ok(())
}

pub fn kcv_challenge_digest(challenge: &KcvChallenge) -> Result<ContentDigest, KcvFault> {
    let mut normalized = challenge.clone();
    normalized.challenge_sha256 = empty_digest();
    domain_digest(CHALLENGE_DOMAIN, &normalized)
}

pub fn kcv_attestation_digest(
    attestation: &KcvCustodyAttestation,
) -> Result<ContentDigest, KcvFault> {
    let mut normalized = attestation.clone();
    normalized.attestation_sha256 = empty_digest();
    domain_digest(ATTESTATION_DOMAIN, &normalized)
}

pub fn kcv_request_digest(request: &KcvVerificationRequest) -> Result<ContentDigest, KcvFault> {
    let mut normalized = request.clone();
    normalized.request_sha256 = empty_digest();
    domain_digest(REQUEST_DOMAIN, &normalized)
}

pub fn kcv_receipt_digest(receipt: &KcvVerificationReceipt) -> Result<ContentDigest, KcvFault> {
    let mut normalized = receipt.clone();
    normalized.receipt_sha256 = empty_digest();
    domain_digest(RECEIPT_DOMAIN, &normalized)
}

pub fn kcv_signature_payload_bytes(challenge: &KcvChallenge) -> Result<Vec<u8>, KcvFault> {
    if challenge.challenge_sha256 != kcv_challenge_digest(challenge)? {
        return Err(fault(
            KcvFaultCode::Digest,
            "signature challenge digest differs",
        ));
    }
    let canonical = serde_json::to_vec(challenge).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(KCV_SIGNING_CONTEXT.len() + 1 + canonical.len());
    bytes.extend_from_slice(KCV_SIGNING_CONTEXT.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

pub fn to_kcv_attestation_machine_form(value: &KcvCustodyAttestation) -> Result<String, KcvFault> {
    validate_kcv_attestation(value)?;
    serde_json::to_string(value).map_err(machine_fault)
}

pub fn from_kcv_attestation_machine_form(text: &str) -> Result<KcvCustodyAttestation, KcvFault> {
    let value = parse_canonical(text)?;
    validate_kcv_attestation(&value)?;
    Ok(value)
}

pub fn to_kcv_request_machine_form(value: &KcvVerificationRequest) -> Result<String, KcvFault> {
    if value.request_sha256 != kcv_request_digest(value)? {
        return Err(fault(KcvFaultCode::Digest, "request digest differs"));
    }
    serde_json::to_string(value).map_err(machine_fault)
}

pub fn from_kcv_request_machine_form(text: &str) -> Result<KcvVerificationRequest, KcvFault> {
    let value: KcvVerificationRequest = parse_canonical(text)?;
    if value.request_sha256 != kcv_request_digest(&value)? {
        return Err(fault(KcvFaultCode::Digest, "request digest differs"));
    }
    Ok(value)
}

pub fn to_kcv_receipt_machine_form(
    request: &KcvVerificationRequest,
    attestation: &KcvCustodyAttestation,
    receipt: &KcvVerificationReceipt,
) -> Result<String, KcvFault> {
    validate_kcv_receipt(request, attestation, receipt)?;
    serde_json::to_string(receipt).map_err(machine_fault)
}

pub fn from_kcv_receipt_machine_form(
    request: &KcvVerificationRequest,
    attestation: &KcvCustodyAttestation,
    text: &str,
) -> Result<KcvVerificationReceipt, KcvFault> {
    let value = parse_canonical(text)?;
    validate_kcv_receipt(request, attestation, &value)?;
    Ok(value)
}

pub fn expected_kcv_downstream_authorities() -> Vec<String> {
    [
        "revocation_truth",
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

fn validate_predecessor(
    request: &B1OaprRequest,
    packet: &B1OaprPacket,
    verification: &B1OaprVerification,
) -> Result<(), KcvFault> {
    let first = compile_b1oapr_packet(request).map_err(predecessor_fault)?;
    let second = compile_b1oapr_packet(request).map_err(predecessor_fault)?;
    let first_text = to_b1oapr_packet_machine_form(request, &first).map_err(predecessor_fault)?;
    let second_text = to_b1oapr_packet_machine_form(request, &second).map_err(predecessor_fault)?;
    if first != *packet
        || second != *packet
        || first_text != second_text
        || packet.status != B1OAPR_STATUS
        || packet.authority != B1OAPR_AUTHORITY
        || packet.packet_sha256 != b1oapr_packet_digest(packet).map_err(predecessor_fault)?
        || verify_b1oapr_packet(request, packet).map_err(predecessor_fault)? != *verification
    {
        return Err(fault(
            KcvFaultCode::Predecessor,
            "authority-packet predecessor differs",
        ));
    }
    Ok(())
}

fn validate_packet_transition(
    predecessor: &B1OaprRequest,
    current: &B1OaprRequest,
    a1_receipt: &BpvVerificationReceipt,
) -> Result<(), KcvFault> {
    if predecessor.descriptors.len() != 9 || current.descriptors.len() != 9 {
        return Err(fault(
            KcvFaultCode::Coordinate,
            "packet coordinate count differs",
        ));
    }
    let predecessor_a1 = &predecessor.descriptors[0];
    let current_a1 = &current.descriptors[0];
    if predecessor_a1 != current_a1
        || current_a1.ordinal != 1
        || current_a1.authority_name != "policy_governance"
        || current_a1.candidate_uuid != a1_receipt.a1_candidate_uuid
        || current_a1.descriptor_sha256 != a1_receipt.a1_descriptor_sha256
        || current_a1.content_sha256 != a1_receipt.policy_envelope_raw_sha256
    {
        return Err(fault(
            KcvFaultCode::Dependency,
            "A2 dependency does not resolve to A1",
        ));
    }
    if predecessor.descriptors[2..] != current.descriptors[2..] {
        return Err(fault(
            KcvFaultCode::Coordinate,
            "non-A2 packet coordinate changed",
        ));
    }
    let mut normalized = current.clone();
    normalized.descriptors[1] = predecessor.descriptors[1].clone();
    normalized.request_sha256 = predecessor.request_sha256.clone();
    if normalized != *predecessor {
        return Err(fault(
            KcvFaultCode::Lineage,
            "packet transition changes more than A2",
        ));
    }
    Ok(())
}

fn validate_attestation_correspondence(
    request: &KcvVerificationRequest,
    descriptor: &B1OaprCandidateDescriptor,
    a1_envelope: &BpvPolicyEnvelope,
    a1_receipt: &BpvVerificationReceipt,
    attestation: &KcvCustodyAttestation,
) -> Result<(), KcvFault> {
    if attestation.challenge.a2_candidate_uuid != descriptor.candidate_uuid
        || attestation.input_class != request.input_class
        || attestation.fixture_only != descriptor.fixture_only
        || attestation.policy_uuid != a1_receipt.policy_uuid
        || attestation.policy_revision_uuid != a1_receipt.revision_uuid
        || attestation.a1_receipt_sha256 != a1_receipt.receipt_sha256
    {
        return Err(fault(
            KcvFaultCode::Dependency,
            "attestation A1 or A2 binding differs",
        ));
    }
    if attestation.verifying_key_hex != a1_envelope.verifying_key_hex
        || attestation.public_key_fingerprint_sha256 != a1_receipt.public_key_fingerprint_sha256
    {
        return Err(fault(KcvFaultCode::Key, "A2 public key does not equal A1"));
    }
    Ok(())
}

fn parse_canonical<T: DeserializeOwned + Serialize>(text: &str) -> Result<T, KcvFault> {
    if text.is_empty()
        || text.len() > KCV_MAX_FORM_BYTES
        || text.starts_with('\u{feff}')
        || text.contains('\r')
        || text.contains('\n')
    {
        return Err(fault(KcvFaultCode::Shape, "machine-form framing differs"));
    }
    let raw: Value = serde_json::from_str(text).map_err(machine_fault)?;
    let mut fields = 0_usize;
    measure_value(&raw, 1, &mut fields)?;
    let value: T = serde_json::from_value(raw).map_err(machine_fault)?;
    if serde_json::to_string(&value).map_err(machine_fault)? != text {
        return Err(fault(
            KcvFaultCode::MachineForm,
            "machine form is not compact canonical JSON",
        ));
    }
    Ok(value)
}

fn measure_value(value: &Value, depth: usize, fields: &mut usize) -> Result<(), KcvFault> {
    if depth > MAX_JSON_DEPTH {
        return Err(fault(KcvFaultCode::Size, "JSON depth exceeds bound"));
    }
    match value {
        Value::Object(values) => {
            *fields = fields
                .checked_add(values.len())
                .ok_or_else(|| fault(KcvFaultCode::Arithmetic, "JSON field count overflow"))?;
            if *fields > MAX_JSON_FIELDS {
                return Err(fault(KcvFaultCode::Size, "JSON field count exceeds bound"));
            }
            for (key, item) in values {
                if key.len() > MAX_TEXT_BYTES {
                    return Err(fault(KcvFaultCode::Size, "JSON key exceeds text bound"));
                }
                measure_value(item, depth + 1, fields)?;
            }
        }
        Value::Array(values) => {
            for item in values {
                measure_value(item, depth + 1, fields)?;
            }
        }
        Value::String(value) if value.len() > MAX_TEXT_BYTES => {
            return Err(fault(KcvFaultCode::Size, "JSON string exceeds text bound"));
        }
        _ => {}
    }
    Ok(())
}

fn has_duplicates(values: &[String]) -> bool {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.windows(2).any(|pair| pair[0] == pair[1])
}

fn valid_uuid(value: &str) -> bool {
    value != "00000000-0000-0000-0000-000000000000"
        && value.len() == 36
        && value.as_bytes().iter().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
            }
        })
}

fn safe_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && !value.contains(['\0', '\r', '\n'])
        && !value.contains("..")
}

fn expected_candidate_label(input: KcvInputClass) -> &'static str {
    match input {
        KcvInputClass::DeterministicFixtureCandidate => "fixture_a2_public_verifying_key_candidate",
        KcvInputClass::ExternallySuppliedCandidate => "external_a2_public_verifying_key_candidate",
    }
}

fn expected_custodian_label(input: KcvInputClass) -> &'static str {
    match input {
        KcvInputClass::DeterministicFixtureCandidate => "fixture_custodian_untrusted",
        KcvInputClass::ExternallySuppliedCandidate => "external_claimed_custodian_untrusted",
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], KcvFault> {
    if !is_lower_hex(value, N * 2) {
        return Err(fault(KcvFaultCode::Key, format!("{label} hex differs")));
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = (hex_nibble(value.as_bytes()[index * 2]) << 4)
            | hex_nibble(value.as_bytes()[index * 2 + 1]);
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

fn domain_digest<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, KcvFault> {
    let body = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + body.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&body);
    Ok(sha256_bytes(&bytes))
}

fn domain_bytes_digest(domain: &str, value: &[u8]) -> ContentDigest {
    let mut bytes = Vec::with_capacity(domain.len() + 1 + value.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(value);
    sha256_bytes(&bytes)
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn predecessor_fault(error: impl fmt::Display) -> KcvFault {
    fault(KcvFaultCode::Predecessor, error)
}

fn machine_fault(error: impl fmt::Display) -> KcvFault {
    fault(KcvFaultCode::MachineForm, error)
}

fn fault(code: KcvFaultCode, message: impl fmt::Display) -> KcvFault {
    KcvFault {
        code,
        message: message.to_string(),
    }
}
