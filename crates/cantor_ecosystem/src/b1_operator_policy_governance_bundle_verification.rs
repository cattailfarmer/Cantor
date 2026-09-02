//! Provider-free verification of one supplied A1 operator-policy bundle.
//!
//! A successful receipt proves byte, structure, scope, denial, and Ed25519
//! correspondence only. It cannot establish issuer identity, policy governance,
//! key custody, revocation, current time, live consent, or execution authority.

use std::fmt;

use cantor_core::{ContentDigest, sha256_bytes};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{
    B1OAPR_AUTHORITY, B1OAPR_STATUS, B1OaprCandidateDescriptor, B1OaprCandidateOrigin,
    B1OaprConfidentiality, B1OaprPacket, B1OaprRequest, B1OaprVerification, b1oapr_packet_digest,
    compile_b1oapr_packet, to_b1oapr_packet_machine_form, verify_b1oapr_packet,
};

pub const BPV_PAYLOAD_PROFILE: &str = "cantor-b1-operator-policy-governance-payload/0.1";
pub const BPV_ENVELOPE_PROFILE: &str = "cantor-b1-operator-policy-governance-envelope/0.1";
pub const BPV_REQUEST_PROFILE: &str =
    "cantor-b1-operator-policy-governance-verification-request/0.1";
pub const BPV_RECEIPT_PROFILE: &str =
    "cantor-b1-operator-policy-governance-verification-receipt/0.1";
pub const BPV_STATUS: &str = "policy_bundle_signature_correspondence_verified_all_governance_and_execution_authority_unresolved";
pub const BPV_AUTHORITY: &str = "policy_bundle_correspondence_only";
pub const BPV_SOURCE_SNAPSHOT_UUID: &str = "39915a21-c45a-4402-a573-d43346c1edd8";
pub const BPV_CANONICAL_UUID: &str = "4a7ef159-ef62-4a2e-82fb-4010633c6858";
pub const BPV_SIGNATURE_UUID: &str = "a67353a2-6730-4a81-b250-4f9ef9f1e6e7";
pub const BPV_SOURCE_CUSTODY_COMMIT: &str = "142c5a0bcdc861e1effae00b3c34360a9b88ff55";
pub const BPV_FORMATION_COMMIT: &str = "4acabdb2793f041bee8ada28f53765178e8330b2";
pub const BPV_FORMATION_BOOKEND_COMMIT: &str = "ef5c814ee2d872286067286f769646648c4d0403";
pub const BPV_PREDECESSOR_IMPLEMENTATION_COMMIT: &str = "d2c3bae2d12561e31146fcfc8ccb42cce892cfcb";
pub const BPV_PREDECESSOR_BOOKEND_COMMIT: &str = "7bb0b1de3eddb9c69c9f16f15d40aa73f1e2c545";
pub const BPV_PREDECESSOR_PROOF_UUID: &str = "44d24344-544f-4219-bd38-a1ebeb277eb1";
pub const BPV_MAX_FORM_BYTES: usize = 1_048_576;
pub const BPV_MAX_EVIDENCE_BYTES: u64 = 8_388_608;
pub const BPV_MAX_EVIDENCE_REFERENCES: usize = 32;

const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_FIELDS: usize = 2_048;
const MAX_TEXT_BYTES: usize = 8_192;
const EXACT_BRANCH: &str = "codex/self-hosted-corpus";
const EXACT_REMOTE: &str = "https://github.com/cattailfarmer/Cantor";
const EXACT_PRINCIPAL: &str = r"THEBRAIN\enjer";
const EXACT_ROLE: &str = "operator_authorizer";
const EXACT_SUBJECT: &str = "cantor_b1_cdrive_production_preparation_p0";
const EXACT_POLICY_DOMAIN: &str = "cantor.b1.cdrive.production-preparation.operator-policy.v1";
const EXACT_ACTION: &str = "cantor_b1_cdrive_production_preparation_authority_ceremony";
pub const BPV_SIGNING_CONTEXT: &str = "cantor.b1.operator-policy-governance.payload-signature.v1";
const PAYLOAD_DOMAIN: &str = "cantor.b1.operator-policy-governance.payload.v1";
const ENVELOPE_DOMAIN: &str = "cantor.b1.operator-policy-governance.envelope.v1";
const REQUEST_DOMAIN: &str = "cantor.b1.operator-policy-governance.request.v1";
const RECEIPT_DOMAIN: &str = "cantor.b1.operator-policy-governance.receipt.v1";
const KEY_DOMAIN: &str = "cantor.b1.operator-policy-governance.public-key.v1";
const DENIAL_DOMAIN: &str = "cantor.b1.operator-policy-governance.denials.v1";
const PROPOSAL_IMPLEMENTATION_COMMIT: &str = "1844d5d89ac256c31c0b3ece0ee479a5e896698c";
const PROPOSAL_BOOKEND_COMMIT: &str = "98683316ff8735026dded1838c88e84edf7288f5";
const PROPOSAL_SEMANTIC_SHA256: &str =
    "591525df40baaebd800077b3349702687db39d2eac1359f2e15eccce010ae9e8";
const CEREMONY_IMPLEMENTATION_COMMIT: &str = "025de395f0f469ba68eba3f488ac85a0ff0d8480";
const CEREMONY_BOOKEND_COMMIT: &str = "11539da2ebdbd56b328d1408befce91815e38e1b";
const CEREMONY_PLAN_SHA256: &str =
    "ee51d65ddfdc220545a6e58a50fe0109f8ea1ac2c36ab425d1bb4afe670d71d4";
const PACKET_FIXTURE_SHA256: &str =
    "19dd95b0b124c4b24dbff6a01ccfa9b3dba1e7aabcdb8f9490554cc95551f233";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BpvInputClass {
    DeterministicFixtureCandidate,
    ExternallySuppliedCandidate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BpvPolicyPayload {
    pub profile: String,
    pub policy_uuid: String,
    pub revision_uuid: String,
    pub issuer_principal: String,
    pub issuer_role: String,
    pub subject: String,
    pub branch: String,
    pub canonical_remote: String,
    pub policy_domain: String,
    pub policy_sequence: u64,
    pub proposal_implementation_commit: String,
    pub proposal_bookend_commit: String,
    pub proposal_semantic_sha256: ContentDigest,
    pub ceremony_implementation_commit: String,
    pub ceremony_bookend_commit: String,
    pub ceremony_plan_sha256: ContentDigest,
    pub authority_packet_implementation_commit: String,
    pub authority_packet_bookend_commit: String,
    pub authority_packet_fixture_sha256: ContentDigest,
    pub governed_action: String,
    pub permitted_decision_classes: Vec<String>,
    pub maximum_attempts: u8,
    pub automatic_retry_count: u8,
    pub automatic_cleanup_count: u8,
    pub required_downstream_authorities: Vec<String>,
    pub denials: Vec<String>,
    pub fixture_only: bool,
    pub production_authority_claimed: bool,
    pub payload_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BpvPolicyEnvelope {
    pub profile: String,
    pub payload: BpvPolicyPayload,
    pub verifying_key_hex: String,
    pub signature_hex: String,
    pub signing_context: String,
    pub envelope_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BpvVerificationRequest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_custody_commit: String,
    pub formation_commit: String,
    pub formation_bookend_commit: String,
    pub predecessor_implementation_commit: String,
    pub predecessor_bookend_commit: String,
    pub predecessor_proof_uuid: String,
    pub predecessor_request_sha256: ContentDigest,
    pub predecessor_packet_sha256: ContentDigest,
    pub predecessor_verification_sha256: ContentDigest,
    pub a1_candidate_uuid: String,
    pub a1_descriptor_sha256: ContentDigest,
    pub policy_envelope_bytes: u64,
    pub policy_envelope_raw_sha256: ContentDigest,
    pub input_class: BpvInputClass,
    pub evidence_references: Vec<String>,
    pub request_sha256: ContentDigest,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BpvEffectAccount {
    pub reference_resolution_count: u32,
    pub private_key_read_count: u32,
    pub key_generation_count: u32,
    pub signing_count: u32,
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
pub struct BpvVerificationReceipt {
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
    pub request_sha256: ContentDigest,
    pub a1_candidate_uuid: String,
    pub a1_descriptor_sha256: ContentDigest,
    pub policy_envelope_bytes: u64,
    pub policy_envelope_raw_sha256: ContentDigest,
    pub policy_uuid: String,
    pub revision_uuid: String,
    pub payload_sha256: ContentDigest,
    pub envelope_sha256: ContentDigest,
    pub public_key_fingerprint_sha256: ContentDigest,
    pub signature_sha256: ContentDigest,
    pub denials_sha256: ContentDigest,
    pub candidate_bytes_matched: bool,
    pub descriptor_correspondence_verified: bool,
    pub payload_structure_verified: bool,
    pub scope_and_denials_verified: bool,
    pub signature_correspondence_verified: bool,
    pub fixture_only: bool,
    pub production_authority_claimed: bool,
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
    pub effect_account: BpvEffectAccount,
    pub receipt_sha256: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BpvFaultCode {
    Bound,
    MachineForm,
    Lineage,
    Predecessor,
    Coordinate,
    RawBytes,
    Payload,
    Scope,
    Authority,
    Signature,
    Digest,
    Effect,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BpvFault {
    pub code: BpvFaultCode,
    pub message: String,
}

impl fmt::Display for BpvFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for BpvFault {}

pub fn deterministic_bpv_fixture_payload() -> Result<BpvPolicyPayload, BpvFault> {
    let mut payload = BpvPolicyPayload {
        profile: BPV_PAYLOAD_PROFILE.to_owned(),
        policy_uuid: "b1000000-0000-4000-8000-000000000001".to_owned(),
        revision_uuid: "b1000000-0000-4000-8000-000000000002".to_owned(),
        issuer_principal: EXACT_PRINCIPAL.to_owned(),
        issuer_role: EXACT_ROLE.to_owned(),
        subject: EXACT_SUBJECT.to_owned(),
        branch: EXACT_BRANCH.to_owned(),
        canonical_remote: EXACT_REMOTE.to_owned(),
        policy_domain: EXACT_POLICY_DOMAIN.to_owned(),
        policy_sequence: 1,
        proposal_implementation_commit: PROPOSAL_IMPLEMENTATION_COMMIT.to_owned(),
        proposal_bookend_commit: PROPOSAL_BOOKEND_COMMIT.to_owned(),
        proposal_semantic_sha256: digest(PROPOSAL_SEMANTIC_SHA256),
        ceremony_implementation_commit: CEREMONY_IMPLEMENTATION_COMMIT.to_owned(),
        ceremony_bookend_commit: CEREMONY_BOOKEND_COMMIT.to_owned(),
        ceremony_plan_sha256: digest(CEREMONY_PLAN_SHA256),
        authority_packet_implementation_commit: BPV_PREDECESSOR_IMPLEMENTATION_COMMIT.to_owned(),
        authority_packet_bookend_commit: BPV_PREDECESSOR_BOOKEND_COMMIT.to_owned(),
        authority_packet_fixture_sha256: digest(PACKET_FIXTURE_SHA256),
        governed_action: EXACT_ACTION.to_owned(),
        permitted_decision_classes: vec!["authorize_once".to_owned(), "reject".to_owned()],
        maximum_attempts: 1,
        automatic_retry_count: 0,
        automatic_cleanup_count: 0,
        required_downstream_authorities: expected_bpv_downstream_authorities(),
        denials: expected_bpv_denials(),
        fixture_only: true,
        production_authority_claimed: false,
        payload_sha256: empty_digest(),
    };
    payload.payload_sha256 = bpv_payload_digest(&payload)?;
    validate_bpv_payload(&payload)?;
    Ok(payload)
}

pub fn verify_bpv_policy_bundle(
    request: &BpvVerificationRequest,
    predecessor_request: &B1OaprRequest,
    predecessor_packet: &B1OaprPacket,
    predecessor_verification: &B1OaprVerification,
    raw_envelope: &[u8],
) -> Result<BpvVerificationReceipt, BpvFault> {
    let descriptor = validate_bpv_request(
        request,
        predecessor_request,
        predecessor_packet,
        predecessor_verification,
        raw_envelope,
    )?;
    let text = std::str::from_utf8(raw_envelope)
        .map_err(|_| fault(BpvFaultCode::MachineForm, "policy envelope is not UTF-8"))?;
    let envelope: BpvPolicyEnvelope = parse_canonical(text)?;
    validate_bpv_envelope(&envelope)?;
    if descriptor.fixture_only != envelope.payload.fixture_only
        || descriptor.origin
            != match request.input_class {
                BpvInputClass::DeterministicFixtureCandidate => {
                    B1OaprCandidateOrigin::DeterministicFixtureCandidate
                }
                BpvInputClass::ExternallySuppliedCandidate => {
                    B1OaprCandidateOrigin::ExternallySuppliedCandidate
                }
            }
    {
        return Err(fault(
            BpvFaultCode::Coordinate,
            "input class, descriptor origin, and fixture label differ",
        ));
    }
    let key_bytes = decode_fixed_hex::<32>(&envelope.verifying_key_hex, "verifying key")?;
    let signature_bytes = decode_fixed_hex::<64>(&envelope.signature_hex, "signature")?;
    let mut receipt = BpvVerificationReceipt {
        profile: BPV_RECEIPT_PROFILE.to_owned(),
        status: BPV_STATUS.to_owned(),
        authority: BPV_AUTHORITY.to_owned(),
        source_snapshot_uuid: request.source_snapshot_uuid.clone(),
        canonical_uuid: request.canonical_uuid.clone(),
        signature_uuid: request.signature_uuid.clone(),
        formation_commit: request.formation_commit.clone(),
        formation_bookend_commit: request.formation_bookend_commit.clone(),
        predecessor_request_sha256: request.predecessor_request_sha256.clone(),
        predecessor_packet_sha256: request.predecessor_packet_sha256.clone(),
        predecessor_verification_sha256: request.predecessor_verification_sha256.clone(),
        request_sha256: request.request_sha256.clone(),
        a1_candidate_uuid: descriptor.candidate_uuid.clone(),
        a1_descriptor_sha256: descriptor.descriptor_sha256.clone(),
        policy_envelope_bytes: request.policy_envelope_bytes,
        policy_envelope_raw_sha256: request.policy_envelope_raw_sha256.clone(),
        policy_uuid: envelope.payload.policy_uuid.clone(),
        revision_uuid: envelope.payload.revision_uuid.clone(),
        payload_sha256: envelope.payload.payload_sha256.clone(),
        envelope_sha256: envelope.envelope_sha256.clone(),
        public_key_fingerprint_sha256: domain_bytes_digest(KEY_DOMAIN, &key_bytes),
        signature_sha256: sha256_bytes(&signature_bytes),
        denials_sha256: domain_digest(DENIAL_DOMAIN, &envelope.payload.denials)?,
        candidate_bytes_matched: true,
        descriptor_correspondence_verified: true,
        payload_structure_verified: true,
        scope_and_denials_verified: true,
        signature_correspondence_verified: true,
        fixture_only: envelope.payload.fixture_only,
        production_authority_claimed: false,
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
        effect_account: BpvEffectAccount::default(),
        receipt_sha256: empty_digest(),
    };
    receipt.receipt_sha256 = bpv_receipt_digest(&receipt)?;
    validate_bpv_receipt(request, &envelope, &receipt)?;
    Ok(receipt)
}

pub fn validate_bpv_request<'a>(
    request: &BpvVerificationRequest,
    predecessor_request: &'a B1OaprRequest,
    predecessor_packet: &'a B1OaprPacket,
    predecessor_verification: &'a B1OaprVerification,
    raw_envelope: &[u8],
) -> Result<&'a B1OaprCandidateDescriptor, BpvFault> {
    validate_predecessor(
        predecessor_request,
        predecessor_packet,
        predecessor_verification,
    )?;
    if request.profile != BPV_REQUEST_PROFILE
        || request.source_snapshot_uuid != BPV_SOURCE_SNAPSHOT_UUID
        || request.canonical_uuid != BPV_CANONICAL_UUID
        || request.signature_uuid != BPV_SIGNATURE_UUID
        || request.source_custody_commit != BPV_SOURCE_CUSTODY_COMMIT
        || request.formation_commit != BPV_FORMATION_COMMIT
        || request.formation_bookend_commit != BPV_FORMATION_BOOKEND_COMMIT
        || request.predecessor_implementation_commit != BPV_PREDECESSOR_IMPLEMENTATION_COMMIT
        || request.predecessor_bookend_commit != BPV_PREDECESSOR_BOOKEND_COMMIT
        || request.predecessor_proof_uuid != BPV_PREDECESSOR_PROOF_UUID
        || request.predecessor_request_sha256 != predecessor_request.request_sha256
        || request.predecessor_packet_sha256 != predecessor_packet.packet_sha256
        || request.predecessor_verification_sha256 != predecessor_verification.verification_sha256
    {
        return Err(fault(
            BpvFaultCode::Lineage,
            "verification request lineage differs",
        ));
    }
    let descriptor = predecessor_packet
        .descriptors
        .first()
        .ok_or_else(|| fault(BpvFaultCode::Coordinate, "A1 descriptor is absent"))?;
    if descriptor.ordinal != 1
        || descriptor.authority_name != "policy_governance"
        || descriptor.artifact_kind != "operator_policy_governance_bundle_candidate"
        || descriptor.required_verifier_profile != "operator-policy-governance-verifier/0.1"
        || descriptor.confidentiality != B1OaprConfidentiality::PublicMetadata
        || descriptor.dependency_ordinal.is_some()
        || request.a1_candidate_uuid != descriptor.candidate_uuid
        || request.a1_descriptor_sha256 != descriptor.descriptor_sha256
    {
        return Err(fault(BpvFaultCode::Coordinate, "A1 descriptor differs"));
    }
    let raw_len = u64::try_from(raw_envelope.len())
        .map_err(|_| fault(BpvFaultCode::Bound, "policy envelope length overflow"))?;
    if raw_envelope.is_empty()
        || raw_envelope.len() > BPV_MAX_FORM_BYTES
        || request.policy_envelope_bytes != raw_len
        || descriptor.declared_bytes != raw_len
        || request.policy_envelope_raw_sha256 != sha256_bytes(raw_envelope)
        || descriptor.content_sha256 != request.policy_envelope_raw_sha256
    {
        return Err(fault(
            BpvFaultCode::RawBytes,
            "raw policy envelope byte identity differs",
        ));
    }
    let expected_fixture = matches!(
        request.input_class,
        BpvInputClass::DeterministicFixtureCandidate
    );
    if descriptor.fixture_only != expected_fixture
        || request.evidence_references.is_empty()
        || request.evidence_references.len() > BPV_MAX_EVIDENCE_REFERENCES
        || request
            .evidence_references
            .iter()
            .any(|value| !safe_text(value))
        || has_duplicates(&request.evidence_references)
    {
        return Err(fault(
            BpvFaultCode::Bound,
            "input class or evidence references differ",
        ));
    }
    if request.request_sha256 != bpv_request_digest(request)? {
        return Err(fault(BpvFaultCode::Digest, "request digest differs"));
    }
    Ok(descriptor)
}

pub fn validate_bpv_payload(payload: &BpvPolicyPayload) -> Result<(), BpvFault> {
    if payload.profile != BPV_PAYLOAD_PROFILE
        || !valid_uuid(&payload.policy_uuid)
        || !valid_uuid(&payload.revision_uuid)
        || payload.policy_uuid == payload.revision_uuid
        || payload.issuer_principal != EXACT_PRINCIPAL
        || payload.issuer_role != EXACT_ROLE
        || payload.subject != EXACT_SUBJECT
        || payload.branch != EXACT_BRANCH
        || payload.canonical_remote != EXACT_REMOTE
        || payload.policy_domain != EXACT_POLICY_DOMAIN
        || payload.policy_sequence == 0
        || payload.proposal_implementation_commit != PROPOSAL_IMPLEMENTATION_COMMIT
        || payload.proposal_bookend_commit != PROPOSAL_BOOKEND_COMMIT
        || payload.proposal_semantic_sha256 != digest(PROPOSAL_SEMANTIC_SHA256)
        || payload.ceremony_implementation_commit != CEREMONY_IMPLEMENTATION_COMMIT
        || payload.ceremony_bookend_commit != CEREMONY_BOOKEND_COMMIT
        || payload.ceremony_plan_sha256 != digest(CEREMONY_PLAN_SHA256)
        || payload.authority_packet_implementation_commit != BPV_PREDECESSOR_IMPLEMENTATION_COMMIT
        || payload.authority_packet_bookend_commit != BPV_PREDECESSOR_BOOKEND_COMMIT
        || payload.authority_packet_fixture_sha256 != digest(PACKET_FIXTURE_SHA256)
        || payload.governed_action != EXACT_ACTION
        || payload.permitted_decision_classes != ["authorize_once", "reject"]
        || payload.maximum_attempts != 1
        || payload.automatic_retry_count != 0
        || payload.automatic_cleanup_count != 0
        || payload.required_downstream_authorities != expected_bpv_downstream_authorities()
        || payload.denials != expected_bpv_denials()
        || payload.production_authority_claimed
    {
        return Err(fault(
            BpvFaultCode::Scope,
            "policy payload identity, scope, denial, or authority boundary differs",
        ));
    }
    if payload.payload_sha256 != bpv_payload_digest(payload)? {
        return Err(fault(BpvFaultCode::Digest, "policy payload digest differs"));
    }
    Ok(())
}

pub fn validate_bpv_envelope(envelope: &BpvPolicyEnvelope) -> Result<(), BpvFault> {
    validate_bpv_payload(&envelope.payload)?;
    if envelope.profile != BPV_ENVELOPE_PROFILE
        || envelope.signing_context != BPV_SIGNING_CONTEXT
        || !is_lower_hex(&envelope.verifying_key_hex, 64)
        || !is_lower_hex(&envelope.signature_hex, 128)
    {
        return Err(fault(
            BpvFaultCode::Payload,
            "policy envelope profile, key, signature, or context differs",
        ));
    }
    if envelope.envelope_sha256 != bpv_envelope_digest(envelope)? {
        return Err(fault(
            BpvFaultCode::Digest,
            "policy envelope digest differs",
        ));
    }
    let key_bytes = decode_fixed_hex::<32>(&envelope.verifying_key_hex, "verifying key")?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| fault(BpvFaultCode::Signature, "verifying key refused"))?;
    let signature_bytes = decode_fixed_hex::<64>(&envelope.signature_hex, "signature")?;
    key.verify_strict(
        &bpv_signature_payload_bytes(&envelope.payload)?,
        &Signature::from_bytes(&signature_bytes),
    )
    .map_err(|_| fault(BpvFaultCode::Signature, "detached signature refused"))?;
    Ok(())
}

pub fn validate_bpv_receipt(
    request: &BpvVerificationRequest,
    envelope: &BpvPolicyEnvelope,
    receipt: &BpvVerificationReceipt,
) -> Result<(), BpvFault> {
    validate_bpv_envelope(envelope)?;
    let key = decode_fixed_hex::<32>(&envelope.verifying_key_hex, "verifying key")?;
    let signature = decode_fixed_hex::<64>(&envelope.signature_hex, "signature")?;
    if receipt.profile != BPV_RECEIPT_PROFILE
        || receipt.status != BPV_STATUS
        || receipt.authority != BPV_AUTHORITY
        || receipt.source_snapshot_uuid != request.source_snapshot_uuid
        || receipt.canonical_uuid != request.canonical_uuid
        || receipt.signature_uuid != request.signature_uuid
        || receipt.formation_commit != request.formation_commit
        || receipt.formation_bookend_commit != request.formation_bookend_commit
        || receipt.predecessor_request_sha256 != request.predecessor_request_sha256
        || receipt.predecessor_packet_sha256 != request.predecessor_packet_sha256
        || receipt.predecessor_verification_sha256 != request.predecessor_verification_sha256
        || receipt.request_sha256 != request.request_sha256
        || receipt.a1_candidate_uuid != request.a1_candidate_uuid
        || receipt.a1_descriptor_sha256 != request.a1_descriptor_sha256
        || receipt.policy_envelope_bytes != request.policy_envelope_bytes
        || receipt.policy_envelope_raw_sha256 != request.policy_envelope_raw_sha256
        || receipt.policy_uuid != envelope.payload.policy_uuid
        || receipt.revision_uuid != envelope.payload.revision_uuid
        || receipt.payload_sha256 != envelope.payload.payload_sha256
        || receipt.envelope_sha256 != envelope.envelope_sha256
        || receipt.public_key_fingerprint_sha256 != domain_bytes_digest(KEY_DOMAIN, &key)
        || receipt.signature_sha256 != sha256_bytes(&signature)
        || receipt.denials_sha256 != domain_digest(DENIAL_DOMAIN, &envelope.payload.denials)?
        || !receipt.candidate_bytes_matched
        || !receipt.descriptor_correspondence_verified
        || !receipt.payload_structure_verified
        || !receipt.scope_and_denials_verified
        || !receipt.signature_correspondence_verified
        || receipt.fixture_only != envelope.payload.fixture_only
    {
        return Err(fault(
            BpvFaultCode::Payload,
            "verification receipt correspondence differs",
        ));
    }
    if receipt.production_authority_claimed
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
            BpvFaultCode::Authority,
            "receipt promotes correspondence into authority",
        ));
    }
    if receipt.effect_account != BpvEffectAccount::default() {
        return Err(fault(BpvFaultCode::Effect, "receipt reports an effect"));
    }
    if receipt.receipt_sha256 != bpv_receipt_digest(receipt)? {
        return Err(fault(BpvFaultCode::Digest, "receipt digest differs"));
    }
    Ok(())
}

pub fn bpv_payload_digest(payload: &BpvPolicyPayload) -> Result<ContentDigest, BpvFault> {
    let mut normalized = payload.clone();
    normalized.payload_sha256 = empty_digest();
    domain_digest(PAYLOAD_DOMAIN, &normalized)
}

pub fn bpv_envelope_digest(envelope: &BpvPolicyEnvelope) -> Result<ContentDigest, BpvFault> {
    let mut normalized = envelope.clone();
    normalized.envelope_sha256 = empty_digest();
    domain_digest(ENVELOPE_DOMAIN, &normalized)
}

pub fn bpv_request_digest(request: &BpvVerificationRequest) -> Result<ContentDigest, BpvFault> {
    let mut normalized = request.clone();
    normalized.request_sha256 = empty_digest();
    domain_digest(REQUEST_DOMAIN, &normalized)
}

pub fn bpv_receipt_digest(receipt: &BpvVerificationReceipt) -> Result<ContentDigest, BpvFault> {
    let mut normalized = receipt.clone();
    normalized.receipt_sha256 = empty_digest();
    domain_digest(RECEIPT_DOMAIN, &normalized)
}

pub fn bpv_signature_payload_bytes(payload: &BpvPolicyPayload) -> Result<Vec<u8>, BpvFault> {
    if payload.payload_sha256 != bpv_payload_digest(payload)? {
        return Err(fault(
            BpvFaultCode::Digest,
            "signature payload digest differs",
        ));
    }
    let canonical = serde_json::to_vec(payload).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(BPV_SIGNING_CONTEXT.len() + 1 + canonical.len());
    bytes.extend_from_slice(BPV_SIGNING_CONTEXT.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

pub fn to_bpv_envelope_machine_form(envelope: &BpvPolicyEnvelope) -> Result<String, BpvFault> {
    validate_bpv_envelope(envelope)?;
    serde_json::to_string(envelope).map_err(machine_fault)
}

pub fn from_bpv_envelope_machine_form(text: &str) -> Result<BpvPolicyEnvelope, BpvFault> {
    let value = parse_canonical(text)?;
    validate_bpv_envelope(&value)?;
    Ok(value)
}

pub fn to_bpv_request_machine_form(request: &BpvVerificationRequest) -> Result<String, BpvFault> {
    if request.request_sha256 != bpv_request_digest(request)? {
        return Err(fault(BpvFaultCode::Digest, "request digest differs"));
    }
    serde_json::to_string(request).map_err(machine_fault)
}

pub fn from_bpv_request_machine_form(text: &str) -> Result<BpvVerificationRequest, BpvFault> {
    let value: BpvVerificationRequest = parse_canonical(text)?;
    if value.request_sha256 != bpv_request_digest(&value)? {
        return Err(fault(BpvFaultCode::Digest, "request digest differs"));
    }
    Ok(value)
}

pub fn to_bpv_receipt_machine_form(
    request: &BpvVerificationRequest,
    envelope: &BpvPolicyEnvelope,
    receipt: &BpvVerificationReceipt,
) -> Result<String, BpvFault> {
    validate_bpv_receipt(request, envelope, receipt)?;
    serde_json::to_string(receipt).map_err(machine_fault)
}

pub fn from_bpv_receipt_machine_form(
    request: &BpvVerificationRequest,
    envelope: &BpvPolicyEnvelope,
    text: &str,
) -> Result<BpvVerificationReceipt, BpvFault> {
    let value = parse_canonical(text)?;
    validate_bpv_receipt(request, envelope, &value)?;
    Ok(value)
}

pub fn expected_bpv_downstream_authorities() -> Vec<String> {
    [
        "key_custody",
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

pub fn expected_bpv_denials() -> Vec<String> {
    [
        "policy_self_issuance",
        "key_generation",
        "key_custody_proof",
        "revocation_truth",
        "trusted_time",
        "live_decision_issuance",
        "fresh_observation_truth",
        "private_execution_permit_disclosure",
        "production_broker_invocation",
        "workspace_mutation",
        "process_execution",
        "provider_use",
        "model_inference",
        "network_contact",
        "git_mutation",
        "persistence",
        "activation",
        "cleanup",
        "remote_hardware",
        "fpga",
        "minecraft",
        "external_effects",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn validate_predecessor(
    request: &B1OaprRequest,
    packet: &B1OaprPacket,
    verification: &B1OaprVerification,
) -> Result<(), BpvFault> {
    let first = compile_b1oapr_packet(request).map_err(predecessor_fault)?;
    let second = compile_b1oapr_packet(request).map_err(predecessor_fault)?;
    let first_text = to_b1oapr_packet_machine_form(request, &first).map_err(predecessor_fault)?;
    let second_text = to_b1oapr_packet_machine_form(request, &second).map_err(predecessor_fault)?;
    if first != *packet
        || second != *packet
        || first_text != second_text
        || packet.profile.is_empty()
        || packet.status != B1OAPR_STATUS
        || packet.authority != B1OAPR_AUTHORITY
        || packet.packet_sha256 != b1oapr_packet_digest(packet).map_err(predecessor_fault)?
        || verify_b1oapr_packet(request, packet).map_err(predecessor_fault)? != *verification
    {
        return Err(fault(
            BpvFaultCode::Predecessor,
            "authority-packet predecessor replay differs",
        ));
    }
    Ok(())
}

fn parse_canonical<T: DeserializeOwned + Serialize>(text: &str) -> Result<T, BpvFault> {
    if text.is_empty()
        || text.len() > BPV_MAX_FORM_BYTES
        || text.starts_with('\u{feff}')
        || text.contains('\r')
        || text.contains('\n')
    {
        return Err(fault(
            BpvFaultCode::MachineForm,
            "machine form size or framing differs",
        ));
    }
    let value: T = serde_json::from_str(text).map_err(machine_fault)?;
    let tree: Value = serde_json::from_str(text).map_err(machine_fault)?;
    let mut fields = 0_usize;
    measure_value(&tree, 0, &mut fields)?;
    if serde_json::to_string(&value).map_err(machine_fault)? != text {
        return Err(fault(
            BpvFaultCode::MachineForm,
            "machine form is not compact canonical JSON",
        ));
    }
    Ok(value)
}

fn measure_value(value: &Value, depth: usize, fields: &mut usize) -> Result<(), BpvFault> {
    if depth > MAX_JSON_DEPTH {
        return Err(fault(BpvFaultCode::Bound, "JSON depth exceeds bound"));
    }
    match value {
        Value::Object(map) => {
            *fields = fields
                .checked_add(map.len())
                .ok_or_else(|| fault(BpvFaultCode::Bound, "JSON field count overflow"))?;
            if *fields > MAX_JSON_FIELDS {
                return Err(fault(BpvFaultCode::Bound, "JSON field count exceeds bound"));
            }
            for (key, child) in map {
                if !safe_text(key) {
                    return Err(fault(BpvFaultCode::Bound, "JSON key text refused"));
                }
                measure_value(child, depth + 1, fields)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                measure_value(child, depth + 1, fields)?;
            }
        }
        Value::String(text) if !safe_text(text) => {
            return Err(fault(BpvFaultCode::Bound, "JSON string text refused"));
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
    if value == "00000000-0000-0000-0000-000000000000" || value.len() != 36 {
        return false;
    }
    value.as_bytes().iter().enumerate().all(|(index, byte)| {
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
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], BpvFault> {
    if !is_lower_hex(value, N * 2) {
        return Err(fault(
            BpvFaultCode::Signature,
            format!("{label} is not canonical lowercase hex"),
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

fn domain_digest<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, BpvFault> {
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

fn digest(value: &str) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: value.to_owned(),
    }
}

fn empty_digest() -> ContentDigest {
    digest(&"0".repeat(64))
}

fn predecessor_fault(error: impl fmt::Display) -> BpvFault {
    fault(BpvFaultCode::Predecessor, error)
}

fn machine_fault(error: impl fmt::Display) -> BpvFault {
    fault(BpvFaultCode::MachineForm, error)
}

fn fault(code: BpvFaultCode, message: impl fmt::Display) -> BpvFault {
    BpvFault {
        code,
        message: message.to_string(),
    }
}
