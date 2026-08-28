//! Pure verification of a supplied B1 C-drive production-preparation operator decision.
//!
//! A successful receipt proves cryptographic correspondence to one supplied
//! key policy and the exact published proposal. It does not govern the policy,
//! issue a decision, observe current time, admit live authority, or invoke the
//! production broker.

use std::fmt;

use cantor_core::{ContentDigest, sha256_bytes};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{
    B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_AUTHORITY,
    B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_STATUS,
    B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_UUID,
    canonical_b1_cdrive_production_preparation_commission_proposal_request,
    compile_b1_cdrive_production_preparation_commission_proposal,
    from_b1_cdrive_production_preparation_commission_proposal_machine_form,
    to_b1_cdrive_production_preparation_commission_proposal_machine_form,
};

pub const B1_CDRIVE_OPERATOR_DECISION_POLICY_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-decision-policy/0.1";
pub const B1_CDRIVE_OPERATOR_DECISION_REQUEST_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-decision-request/0.1";
pub const B1_CDRIVE_OPERATOR_DECISION_PAYLOAD_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-decision-payload/0.1";
pub const B1_CDRIVE_OPERATOR_DECISION_ENVELOPE_PROFILE: &str = "cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-decision-envelope/0.1";
pub const B1_CDRIVE_OPERATOR_DECISION_VERIFICATION_PROFILE: &str = "cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-decision-verification/0.1";
pub const B1_CDRIVE_OPERATOR_DECISION_AUTHORIZE_STATUS: &str = "operator_decision_signature_correspondence_verified_policy_governance_freshness_and_execution_unresolved";
pub const B1_CDRIVE_OPERATOR_DECISION_REJECT_STATUS: &str =
    "operator_rejection_signature_correspondence_verified_physical_preparation_refused";
pub const B1_CDRIVE_OPERATOR_DECISION_AUTHORITY: &str = "cryptographic_correspondence_only";
pub const B1_CDRIVE_OPERATOR_DECISION_SOURCE_SNAPSHOT_UUID: &str =
    "51099c67-dc74-4692-a267-9ce13c5d0ad4";
pub const B1_CDRIVE_OPERATOR_DECISION_CANONICAL_UUID: &str = "0462098c-289e-440b-b515-c0090f9ecee1";
pub const B1_CDRIVE_OPERATOR_DECISION_SIGNATURE_UUID: &str = "69a95cf0-15d1-418b-9796-1fa5ae506499";
pub const B1_CDRIVE_OPERATOR_DECISION_SOURCE_CUSTODY_COMMIT: &str =
    "eb3a4d2d48a8cf31cd3a9218e1cb1d8a7cd74cb3";
pub const B1_CDRIVE_OPERATOR_DECISION_FORMATION_COMMIT: &str =
    "95511aa3acd20812d0a7ac645c02886877542e3f";
pub const B1_CDRIVE_OPERATOR_DECISION_PROPOSAL_IMPLEMENTATION_COMMIT: &str =
    "1844d5d89ac256c31c0b3ece0ee479a5e896698c";
pub const B1_CDRIVE_OPERATOR_DECISION_PROPOSAL_BOOKEND_COMMIT: &str =
    "98683316ff8735026dded1838c88e84edf7288f5";
pub const B1_CDRIVE_OPERATOR_DECISION_MAX_MACHINE_FORM_BYTES: usize = 1_048_576;

const EXACT_BRANCH: &str = "codex/self-hosted-corpus";
const EXACT_REMOTE: &str = "https://github.com/cattailfarmer/Cantor";
const EXACT_PROJECT: &str = r"C:\Project\Cantor";
const EXACT_PRINCIPAL: &str = r"THEBRAIN\enjer";
const EXACT_ROLE: &str = "operator_authorizer";
const EXACT_SUBJECT: &str = "cantor_b1_cdrive_production_preparation_p0";
const EXACT_PURPOSE: &str = "production_preparation_commission_proposal_decision";
const EXACT_CONVERSATION_UUID: &str = "01a02268-2614-7d80-9737-ea77f4aeacb1";
const EXACT_PROPOSAL_BYTES: u64 = 5_791;
const EXACT_PROPOSAL_RAW_SHA256: &str =
    "1e0b482d41e4d450200e62fa131a0bb1a9d01a2858e7f52fcfd5b2a2dd1e8f9e";
const EXACT_PROPOSAL_SELF_SHA256: &str =
    "591525df40baaebd800077b3349702687db39d2eac1359f2e15eccce010ae9e8";
const POLICY_DOMAIN: &str = "cantor.b1.cdrive.production-preparation.operator-decision.policy.v1";
const REQUEST_DOMAIN: &str = "cantor.b1.cdrive.production-preparation.operator-decision.request.v1";
const PAYLOAD_DOMAIN: &str = "cantor.b1.cdrive.production-preparation.operator-decision.payload.v1";
const ENVELOPE_DOMAIN: &str =
    "cantor.b1.cdrive.production-preparation.operator-decision.envelope.v1";
const VERIFICATION_DOMAIN: &str =
    "cantor.b1.cdrive.production-preparation.operator-decision.verification.v1";
const KEY_FINGERPRINT_DOMAIN: &str = "cantor.self-work.b1.cdrive.operator-key.v1";
const SIGNATURE_DOMAIN: &str =
    "cantor.self-work.b1.cdrive.production-preparation.operator-decision.v1";
const MAX_JSON_DEPTH: usize = 24;
const MAX_JSON_FIELDS: usize = 256;
const MAX_TEXT_BYTES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveOperatorDecisionPolicy {
    pub profile: String,
    pub policy_uuid: String,
    pub principal: String,
    pub role: String,
    pub subject: String,
    pub verifying_key_hex: String,
    pub key_fingerprint_sha256: ContentDigest,
    pub policy_governance_ref: String,
    pub policy_governance_artifact_sha256: ContentDigest,
    pub revocation_list_artifact_sha256: ContentDigest,
    pub fixture_only: bool,
    pub policy_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveOperatorDecisionRequest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_custody_commit: String,
    pub formation_commit: String,
    pub proposal_implementation_commit: String,
    pub proposal_bookend_commit: String,
    pub expected_current_commit: String,
    pub branch: String,
    pub canonical_remote: String,
    pub working_project: String,
    pub proposal_machine_form: String,
    pub proposal_bytes: u64,
    pub proposal_raw_sha256: ContentDigest,
    pub proposal_uuid: String,
    pub proposal_self_sha256: ContentDigest,
    pub policy_sha256: ContentDigest,
    pub request_sha256: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDriveOperatorDecisionKind {
    Authorize,
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveOperatorDecisionPayload {
    pub profile: String,
    pub decision_uuid: String,
    pub request_sha256: ContentDigest,
    pub policy_sha256: ContentDigest,
    pub decision_kind: B1CDriveOperatorDecisionKind,
    pub principal: String,
    pub role: String,
    pub subject: String,
    pub purpose: String,
    pub conversation_uuid: String,
    pub external_decision_identity: String,
    pub issued_at_unix_millis: u64,
    pub expires_at_unix_millis: u64,
    pub maximum_attempts: u8,
    pub retry_count: u8,
    pub automatic_cleanup_count: u8,
    pub fixture_only: bool,
    pub payload_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveOperatorDecisionEnvelope {
    pub profile: String,
    pub payload: B1CDriveOperatorDecisionPayload,
    pub signature_hex: String,
    pub fixture_only: bool,
    pub envelope_sha256: ContentDigest,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveOperatorDecisionEffectAccount {
    pub physical_contact: bool,
    pub process_count: u8,
    pub provider_trial_count: u8,
    pub model_turn_count: u8,
    pub mcp_call_count: u8,
    pub network_contact_count: u8,
    pub writer_run_count: u8,
    pub git_runtime_mutation_count: u8,
    pub filesystem_runtime_mutation_count: u8,
    pub publication_count: u8,
    pub persistence_count: u8,
    pub activation_count: u8,
    pub d_drive_runtime_contact_count: u8,
    pub remote_contact_count: u8,
    pub wsl_compile_count: u8,
    pub cleanup_count: u8,
    pub foreign_effect_count: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveOperatorDecisionVerification {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_custody_commit: String,
    pub formation_commit: String,
    pub proposal_implementation_commit: String,
    pub proposal_bookend_commit: String,
    pub proposal_uuid: String,
    pub proposal_self_sha256: ContentDigest,
    pub proposal_raw_sha256: ContentDigest,
    pub policy_uuid: String,
    pub policy_sha256: ContentDigest,
    pub request_sha256: ContentDigest,
    pub decision_uuid: String,
    pub payload_sha256: ContentDigest,
    pub envelope_sha256: ContentDigest,
    pub decision_kind: B1CDriveOperatorDecisionKind,
    pub status: String,
    pub authority: String,
    pub proposal_correspondence_verified: bool,
    pub cryptographic_signature_verified: bool,
    pub fixture_only: bool,
    pub policy_governance_proved: bool,
    pub current_nonexpired: bool,
    pub live_authorization_admitted: bool,
    pub fresh_observation_proved: bool,
    pub private_execution_permit_present: bool,
    pub physical_preparation_authorized: bool,
    pub production_broker_projection_present: bool,
    pub effect_account: B1CDriveOperatorDecisionEffectAccount,
    pub verification_sha256: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum B1CDriveOperatorDecisionFaultCode {
    Bound,
    MachineForm,
    Identity,
    Proposal,
    Policy,
    Decision,
    Signature,
    Authority,
    Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B1CDriveOperatorDecisionFault {
    pub code: B1CDriveOperatorDecisionFaultCode,
    pub message: String,
}

impl fmt::Display for B1CDriveOperatorDecisionFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for B1CDriveOperatorDecisionFault {}

pub fn canonical_b1_cdrive_operator_decision_request(
    policy: &B1CDriveOperatorDecisionPolicy,
) -> Result<B1CDriveOperatorDecisionRequest, B1CDriveOperatorDecisionFault> {
    validate_b1_cdrive_operator_decision_policy(policy)?;
    let proposal_request = canonical_b1_cdrive_production_preparation_commission_proposal_request()
        .map_err(proposal_fault)?;
    let proposal = compile_b1_cdrive_production_preparation_commission_proposal(&proposal_request)
        .map_err(proposal_fault)?;
    let proposal_machine_form =
        to_b1_cdrive_production_preparation_commission_proposal_machine_form(
            &proposal_request,
            &proposal,
        )
        .map_err(proposal_fault)?;
    let mut request = B1CDriveOperatorDecisionRequest {
        profile: B1_CDRIVE_OPERATOR_DECISION_REQUEST_PROFILE.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_OPERATOR_DECISION_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: B1_CDRIVE_OPERATOR_DECISION_CANONICAL_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_OPERATOR_DECISION_SIGNATURE_UUID.to_owned(),
        source_custody_commit: B1_CDRIVE_OPERATOR_DECISION_SOURCE_CUSTODY_COMMIT.to_owned(),
        formation_commit: B1_CDRIVE_OPERATOR_DECISION_FORMATION_COMMIT.to_owned(),
        proposal_implementation_commit: B1_CDRIVE_OPERATOR_DECISION_PROPOSAL_IMPLEMENTATION_COMMIT
            .to_owned(),
        proposal_bookend_commit: B1_CDRIVE_OPERATOR_DECISION_PROPOSAL_BOOKEND_COMMIT.to_owned(),
        expected_current_commit: B1_CDRIVE_OPERATOR_DECISION_PROPOSAL_BOOKEND_COMMIT.to_owned(),
        branch: EXACT_BRANCH.to_owned(),
        canonical_remote: EXACT_REMOTE.to_owned(),
        working_project: EXACT_PROJECT.to_owned(),
        proposal_bytes: proposal_machine_form.len() as u64,
        proposal_raw_sha256: sha256_bytes(proposal_machine_form.as_bytes()),
        proposal_uuid: proposal.proposal_uuid.clone(),
        proposal_self_sha256: proposal.proposal_sha256.clone(),
        proposal_machine_form,
        policy_sha256: policy.policy_sha256.clone(),
        request_sha256: empty_digest(),
    };
    request.request_sha256 = b1_cdrive_operator_decision_request_digest(&request)?;
    validate_b1_cdrive_operator_decision_request(policy, &request)?;
    Ok(request)
}

pub fn verify_b1_cdrive_operator_decision(
    request: &B1CDriveOperatorDecisionRequest,
    policy: &B1CDriveOperatorDecisionPolicy,
    envelope: &B1CDriveOperatorDecisionEnvelope,
) -> Result<B1CDriveOperatorDecisionVerification, B1CDriveOperatorDecisionFault> {
    validate_b1_cdrive_operator_decision_request(policy, request)?;
    validate_b1_cdrive_operator_decision_envelope(request, policy, envelope)?;
    let payload = &envelope.payload;
    let status = match payload.decision_kind {
        B1CDriveOperatorDecisionKind::Authorize => B1_CDRIVE_OPERATOR_DECISION_AUTHORIZE_STATUS,
        B1CDriveOperatorDecisionKind::Reject => B1_CDRIVE_OPERATOR_DECISION_REJECT_STATUS,
    };
    let mut verification = B1CDriveOperatorDecisionVerification {
        profile: B1_CDRIVE_OPERATOR_DECISION_VERIFICATION_PROFILE.to_owned(),
        source_snapshot_uuid: request.source_snapshot_uuid.clone(),
        canonical_uuid: request.canonical_uuid.clone(),
        signature_uuid: request.signature_uuid.clone(),
        source_custody_commit: request.source_custody_commit.clone(),
        formation_commit: request.formation_commit.clone(),
        proposal_implementation_commit: request.proposal_implementation_commit.clone(),
        proposal_bookend_commit: request.proposal_bookend_commit.clone(),
        proposal_uuid: request.proposal_uuid.clone(),
        proposal_self_sha256: request.proposal_self_sha256.clone(),
        proposal_raw_sha256: request.proposal_raw_sha256.clone(),
        policy_uuid: policy.policy_uuid.clone(),
        policy_sha256: policy.policy_sha256.clone(),
        request_sha256: request.request_sha256.clone(),
        decision_uuid: payload.decision_uuid.clone(),
        payload_sha256: payload.payload_sha256.clone(),
        envelope_sha256: envelope.envelope_sha256.clone(),
        decision_kind: payload.decision_kind,
        status: status.to_owned(),
        authority: B1_CDRIVE_OPERATOR_DECISION_AUTHORITY.to_owned(),
        proposal_correspondence_verified: true,
        cryptographic_signature_verified: true,
        fixture_only: envelope.fixture_only,
        policy_governance_proved: false,
        current_nonexpired: false,
        live_authorization_admitted: false,
        fresh_observation_proved: false,
        private_execution_permit_present: false,
        physical_preparation_authorized: false,
        production_broker_projection_present: false,
        effect_account: B1CDriveOperatorDecisionEffectAccount::default(),
        verification_sha256: empty_digest(),
    };
    verification.verification_sha256 =
        b1_cdrive_operator_decision_verification_digest(&verification)?;
    validate_b1_cdrive_operator_decision_verification(request, policy, envelope, &verification)?;
    Ok(verification)
}

pub fn validate_b1_cdrive_operator_decision_policy(
    policy: &B1CDriveOperatorDecisionPolicy,
) -> Result<(), B1CDriveOperatorDecisionFault> {
    if policy.profile != B1_CDRIVE_OPERATOR_DECISION_POLICY_PROFILE
        || !is_uuid(&policy.policy_uuid)
        || policy.principal != EXACT_PRINCIPAL
        || policy.role != EXACT_ROLE
        || policy.subject != EXACT_SUBJECT
        || !is_lower_hex(&policy.verifying_key_hex, 64)
        || policy.policy_governance_ref.is_empty()
        || policy.policy_governance_ref.len() > MAX_TEXT_BYTES
        || !valid_digest(&policy.policy_governance_artifact_sha256)
        || !valid_digest(&policy.revocation_list_artifact_sha256)
    {
        return Err(fault(
            B1CDriveOperatorDecisionFaultCode::Policy,
            "operator decision policy identity or bound differs",
        ));
    }
    let key = decode_fixed_hex::<32>(&policy.verifying_key_hex, "verifying key")?;
    VerifyingKey::from_bytes(&key).map_err(|_| {
        fault(
            B1CDriveOperatorDecisionFaultCode::Policy,
            "operator decision verifying key refused",
        )
    })?;
    if policy.key_fingerprint_sha256 != b1_cdrive_operator_key_fingerprint(&key)
        || policy.policy_sha256 != b1_cdrive_operator_decision_policy_digest(policy)?
    {
        return Err(fault(
            B1CDriveOperatorDecisionFaultCode::Digest,
            "operator decision policy digest differs",
        ));
    }
    Ok(())
}

pub fn validate_b1_cdrive_operator_decision_request(
    policy: &B1CDriveOperatorDecisionPolicy,
    request: &B1CDriveOperatorDecisionRequest,
) -> Result<(), B1CDriveOperatorDecisionFault> {
    validate_b1_cdrive_operator_decision_policy(policy)?;
    if request.profile != B1_CDRIVE_OPERATOR_DECISION_REQUEST_PROFILE
        || request.source_snapshot_uuid != B1_CDRIVE_OPERATOR_DECISION_SOURCE_SNAPSHOT_UUID
        || request.canonical_uuid != B1_CDRIVE_OPERATOR_DECISION_CANONICAL_UUID
        || request.signature_uuid != B1_CDRIVE_OPERATOR_DECISION_SIGNATURE_UUID
        || request.source_custody_commit != B1_CDRIVE_OPERATOR_DECISION_SOURCE_CUSTODY_COMMIT
        || request.formation_commit != B1_CDRIVE_OPERATOR_DECISION_FORMATION_COMMIT
        || request.proposal_implementation_commit
            != B1_CDRIVE_OPERATOR_DECISION_PROPOSAL_IMPLEMENTATION_COMMIT
        || request.proposal_bookend_commit != B1_CDRIVE_OPERATOR_DECISION_PROPOSAL_BOOKEND_COMMIT
        || request.expected_current_commit != B1_CDRIVE_OPERATOR_DECISION_PROPOSAL_BOOKEND_COMMIT
        || request.branch != EXACT_BRANCH
        || request.canonical_remote != EXACT_REMOTE
        || request.working_project != EXACT_PROJECT
        || request.proposal_bytes != EXACT_PROPOSAL_BYTES
        || request.proposal_machine_form.len() as u64 != request.proposal_bytes
        || request.proposal_raw_sha256 != digest(EXACT_PROPOSAL_RAW_SHA256)
        || sha256_bytes(request.proposal_machine_form.as_bytes()) != request.proposal_raw_sha256
        || request.proposal_uuid != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_UUID
        || request.proposal_self_sha256 != digest(EXACT_PROPOSAL_SELF_SHA256)
        || request.policy_sha256 != policy.policy_sha256
    {
        return Err(fault(
            B1CDriveOperatorDecisionFaultCode::Identity,
            "operator decision request lineage or raw proposal identity differs",
        ));
    }
    let proposal_request = canonical_b1_cdrive_production_preparation_commission_proposal_request()
        .map_err(proposal_fault)?;
    let expected = compile_b1_cdrive_production_preparation_commission_proposal(&proposal_request)
        .map_err(proposal_fault)?;
    let parsed = from_b1_cdrive_production_preparation_commission_proposal_machine_form(
        &proposal_request,
        &request.proposal_machine_form,
    )
    .map_err(proposal_fault)?;
    if parsed != expected
        || parsed.status != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_STATUS
        || parsed.authority != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_AUTHORITY
        || parsed.external_authorization_present
        || parsed.physical_preparation_authorized
    {
        return Err(fault(
            B1CDriveOperatorDecisionFaultCode::Proposal,
            "embedded proposal semantic correspondence differs",
        ));
    }
    if request.request_sha256 != b1_cdrive_operator_decision_request_digest(request)? {
        return Err(fault(
            B1CDriveOperatorDecisionFaultCode::Digest,
            "operator decision request digest differs",
        ));
    }
    Ok(())
}

pub fn validate_b1_cdrive_operator_decision_envelope(
    request: &B1CDriveOperatorDecisionRequest,
    policy: &B1CDriveOperatorDecisionPolicy,
    envelope: &B1CDriveOperatorDecisionEnvelope,
) -> Result<(), B1CDriveOperatorDecisionFault> {
    validate_b1_cdrive_operator_decision_request(policy, request)?;
    let payload = &envelope.payload;
    if envelope.profile != B1_CDRIVE_OPERATOR_DECISION_ENVELOPE_PROFILE
        || payload.profile != B1_CDRIVE_OPERATOR_DECISION_PAYLOAD_PROFILE
        || !is_uuid(&payload.decision_uuid)
        || distinct_uuid_collision(policy, request, &payload.decision_uuid)
        || payload.request_sha256 != request.request_sha256
        || payload.policy_sha256 != policy.policy_sha256
        || payload.principal != policy.principal
        || payload.role != policy.role
        || payload.subject != policy.subject
        || payload.purpose != EXACT_PURPOSE
        || payload.conversation_uuid != EXACT_CONVERSATION_UUID
        || payload.external_decision_identity.is_empty()
        || payload.external_decision_identity.len() > MAX_TEXT_BYTES
        || payload.issued_at_unix_millis >= payload.expires_at_unix_millis
        || payload.maximum_attempts != 1
        || payload.retry_count != 0
        || payload.automatic_cleanup_count != 0
        || payload.fixture_only != policy.fixture_only
        || envelope.fixture_only != policy.fixture_only
        || !is_lower_hex(&envelope.signature_hex, 128)
    {
        return Err(fault(
            B1CDriveOperatorDecisionFaultCode::Decision,
            "operator decision payload or envelope binding differs",
        ));
    }
    if payload.payload_sha256 != b1_cdrive_operator_decision_payload_digest(payload)?
        || envelope.envelope_sha256 != b1_cdrive_operator_decision_envelope_digest(envelope)?
    {
        return Err(fault(
            B1CDriveOperatorDecisionFaultCode::Digest,
            "operator decision payload or envelope digest differs",
        ));
    }
    let key_bytes = decode_fixed_hex::<32>(&policy.verifying_key_hex, "verifying key")?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
        fault(
            B1CDriveOperatorDecisionFaultCode::Policy,
            "operator decision verifying key refused",
        )
    })?;
    let signature_bytes = decode_fixed_hex::<64>(&envelope.signature_hex, "signature")?;
    let signature = Signature::from_bytes(&signature_bytes);
    key.verify_strict(
        &b1_cdrive_operator_decision_signature_payload_bytes(payload)?,
        &signature,
    )
    .map_err(|_| {
        fault(
            B1CDriveOperatorDecisionFaultCode::Signature,
            "operator decision signature refused",
        )
    })?;
    Ok(())
}

pub fn validate_b1_cdrive_operator_decision_verification(
    request: &B1CDriveOperatorDecisionRequest,
    policy: &B1CDriveOperatorDecisionPolicy,
    envelope: &B1CDriveOperatorDecisionEnvelope,
    verification: &B1CDriveOperatorDecisionVerification,
) -> Result<(), B1CDriveOperatorDecisionFault> {
    validate_b1_cdrive_operator_decision_envelope(request, policy, envelope)?;
    let payload = &envelope.payload;
    let expected_status = match payload.decision_kind {
        B1CDriveOperatorDecisionKind::Authorize => B1_CDRIVE_OPERATOR_DECISION_AUTHORIZE_STATUS,
        B1CDriveOperatorDecisionKind::Reject => B1_CDRIVE_OPERATOR_DECISION_REJECT_STATUS,
    };
    if verification.profile != B1_CDRIVE_OPERATOR_DECISION_VERIFICATION_PROFILE
        || verification.source_snapshot_uuid != request.source_snapshot_uuid
        || verification.canonical_uuid != request.canonical_uuid
        || verification.signature_uuid != request.signature_uuid
        || verification.source_custody_commit != request.source_custody_commit
        || verification.formation_commit != request.formation_commit
        || verification.proposal_implementation_commit != request.proposal_implementation_commit
        || verification.proposal_bookend_commit != request.proposal_bookend_commit
        || verification.proposal_uuid != request.proposal_uuid
        || verification.proposal_self_sha256 != request.proposal_self_sha256
        || verification.proposal_raw_sha256 != request.proposal_raw_sha256
        || verification.policy_uuid != policy.policy_uuid
        || verification.policy_sha256 != policy.policy_sha256
        || verification.request_sha256 != request.request_sha256
        || verification.decision_uuid != payload.decision_uuid
        || verification.payload_sha256 != payload.payload_sha256
        || verification.envelope_sha256 != envelope.envelope_sha256
        || verification.decision_kind != payload.decision_kind
        || verification.status != expected_status
        || verification.authority != B1_CDRIVE_OPERATOR_DECISION_AUTHORITY
        || !verification.proposal_correspondence_verified
        || !verification.cryptographic_signature_verified
        || verification.fixture_only != envelope.fixture_only
    {
        return Err(fault(
            B1CDriveOperatorDecisionFaultCode::Identity,
            "operator decision verification identity or status differs",
        ));
    }
    if verification.policy_governance_proved
        || verification.current_nonexpired
        || verification.live_authorization_admitted
        || verification.fresh_observation_proved
        || verification.private_execution_permit_present
        || verification.physical_preparation_authorized
        || verification.production_broker_projection_present
        || verification.effect_account != B1CDriveOperatorDecisionEffectAccount::default()
    {
        return Err(fault(
            B1CDriveOperatorDecisionFaultCode::Authority,
            "operator decision verification nonauthority or zero-effect account differs",
        ));
    }
    if verification.verification_sha256
        != b1_cdrive_operator_decision_verification_digest(verification)?
    {
        return Err(fault(
            B1CDriveOperatorDecisionFaultCode::Digest,
            "operator decision verification digest differs",
        ));
    }
    Ok(())
}

pub fn b1_cdrive_operator_key_fingerprint(key: &[u8; 32]) -> ContentDigest {
    domain_bytes_digest(KEY_FINGERPRINT_DOMAIN, key)
}

pub fn b1_cdrive_operator_decision_policy_digest(
    policy: &B1CDriveOperatorDecisionPolicy,
) -> Result<ContentDigest, B1CDriveOperatorDecisionFault> {
    let mut normalized = policy.clone();
    normalized.policy_sha256 = empty_digest();
    domain_digest(POLICY_DOMAIN, &normalized)
}

pub fn b1_cdrive_operator_decision_request_digest(
    request: &B1CDriveOperatorDecisionRequest,
) -> Result<ContentDigest, B1CDriveOperatorDecisionFault> {
    let mut normalized = request.clone();
    normalized.request_sha256 = empty_digest();
    domain_digest(REQUEST_DOMAIN, &normalized)
}

pub fn b1_cdrive_operator_decision_payload_digest(
    payload: &B1CDriveOperatorDecisionPayload,
) -> Result<ContentDigest, B1CDriveOperatorDecisionFault> {
    let mut normalized = payload.clone();
    normalized.payload_sha256 = empty_digest();
    domain_digest(PAYLOAD_DOMAIN, &normalized)
}

pub fn b1_cdrive_operator_decision_envelope_digest(
    envelope: &B1CDriveOperatorDecisionEnvelope,
) -> Result<ContentDigest, B1CDriveOperatorDecisionFault> {
    let mut normalized = envelope.clone();
    normalized.envelope_sha256 = empty_digest();
    domain_digest(ENVELOPE_DOMAIN, &normalized)
}

pub fn b1_cdrive_operator_decision_verification_digest(
    verification: &B1CDriveOperatorDecisionVerification,
) -> Result<ContentDigest, B1CDriveOperatorDecisionFault> {
    let mut normalized = verification.clone();
    normalized.verification_sha256 = empty_digest();
    domain_digest(VERIFICATION_DOMAIN, &normalized)
}

pub fn b1_cdrive_operator_decision_signature_payload_bytes(
    payload: &B1CDriveOperatorDecisionPayload,
) -> Result<Vec<u8>, B1CDriveOperatorDecisionFault> {
    if payload.payload_sha256 != b1_cdrive_operator_decision_payload_digest(payload)? {
        return Err(fault(
            B1CDriveOperatorDecisionFaultCode::Digest,
            "signature payload digest differs",
        ));
    }
    let canonical = serde_json::to_vec(payload).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 1 + canonical.len());
    bytes.extend_from_slice(SIGNATURE_DOMAIN.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

macro_rules! machine_forms {
    ($to:ident, $from:ident, $ty:ty, $validate:expr) => {
        pub fn $to(value: &$ty) -> Result<String, B1CDriveOperatorDecisionFault> {
            ($validate)(value)?;
            serde_json::to_string(value).map_err(machine_fault)
        }

        pub fn $from(machine_form: &str) -> Result<$ty, B1CDriveOperatorDecisionFault> {
            let value: $ty = parse_canonical(machine_form)?;
            ($validate)(&value)?;
            Ok(value)
        }
    };
}

machine_forms!(
    to_b1_cdrive_operator_decision_policy_machine_form,
    from_b1_cdrive_operator_decision_policy_machine_form,
    B1CDriveOperatorDecisionPolicy,
    validate_b1_cdrive_operator_decision_policy
);

pub fn to_b1_cdrive_operator_decision_request_machine_form(
    policy: &B1CDriveOperatorDecisionPolicy,
    request: &B1CDriveOperatorDecisionRequest,
) -> Result<String, B1CDriveOperatorDecisionFault> {
    validate_b1_cdrive_operator_decision_request(policy, request)?;
    serde_json::to_string(request).map_err(machine_fault)
}

pub fn from_b1_cdrive_operator_decision_request_machine_form(
    policy: &B1CDriveOperatorDecisionPolicy,
    machine_form: &str,
) -> Result<B1CDriveOperatorDecisionRequest, B1CDriveOperatorDecisionFault> {
    let request = parse_canonical(machine_form)?;
    validate_b1_cdrive_operator_decision_request(policy, &request)?;
    Ok(request)
}

pub fn to_b1_cdrive_operator_decision_envelope_machine_form(
    request: &B1CDriveOperatorDecisionRequest,
    policy: &B1CDriveOperatorDecisionPolicy,
    envelope: &B1CDriveOperatorDecisionEnvelope,
) -> Result<String, B1CDriveOperatorDecisionFault> {
    validate_b1_cdrive_operator_decision_envelope(request, policy, envelope)?;
    serde_json::to_string(envelope).map_err(machine_fault)
}

pub fn from_b1_cdrive_operator_decision_envelope_machine_form(
    request: &B1CDriveOperatorDecisionRequest,
    policy: &B1CDriveOperatorDecisionPolicy,
    machine_form: &str,
) -> Result<B1CDriveOperatorDecisionEnvelope, B1CDriveOperatorDecisionFault> {
    let envelope = parse_canonical(machine_form)?;
    validate_b1_cdrive_operator_decision_envelope(request, policy, &envelope)?;
    Ok(envelope)
}

pub fn to_b1_cdrive_operator_decision_verification_machine_form(
    request: &B1CDriveOperatorDecisionRequest,
    policy: &B1CDriveOperatorDecisionPolicy,
    envelope: &B1CDriveOperatorDecisionEnvelope,
    verification: &B1CDriveOperatorDecisionVerification,
) -> Result<String, B1CDriveOperatorDecisionFault> {
    validate_b1_cdrive_operator_decision_verification(request, policy, envelope, verification)?;
    serde_json::to_string(verification).map_err(machine_fault)
}

pub fn from_b1_cdrive_operator_decision_verification_machine_form(
    request: &B1CDriveOperatorDecisionRequest,
    policy: &B1CDriveOperatorDecisionPolicy,
    envelope: &B1CDriveOperatorDecisionEnvelope,
    machine_form: &str,
) -> Result<B1CDriveOperatorDecisionVerification, B1CDriveOperatorDecisionFault> {
    let verification = parse_canonical(machine_form)?;
    validate_b1_cdrive_operator_decision_verification(request, policy, envelope, &verification)?;
    Ok(verification)
}

fn distinct_uuid_collision(
    policy: &B1CDriveOperatorDecisionPolicy,
    request: &B1CDriveOperatorDecisionRequest,
    decision_uuid: &str,
) -> bool {
    [
        policy.policy_uuid.as_str(),
        request.source_snapshot_uuid.as_str(),
        request.canonical_uuid.as_str(),
        request.signature_uuid.as_str(),
        request.proposal_uuid.as_str(),
    ]
    .contains(&decision_uuid)
}

fn parse_canonical<T: DeserializeOwned + Serialize>(
    machine_form: &str,
) -> Result<T, B1CDriveOperatorDecisionFault> {
    if machine_form.is_empty()
        || machine_form.len() > B1_CDRIVE_OPERATOR_DECISION_MAX_MACHINE_FORM_BYTES
    {
        return Err(fault(
            B1CDriveOperatorDecisionFaultCode::Bound,
            "machine form byte bound differs",
        ));
    }
    let value: Value = serde_json::from_str(machine_form).map_err(machine_fault)?;
    let mut fields = 0_usize;
    measure_value(&value, 1, &mut fields)?;
    let parsed: T = serde_json::from_str(machine_form).map_err(machine_fault)?;
    if serde_json::to_string(&parsed).map_err(machine_fault)? != machine_form {
        return Err(fault(
            B1CDriveOperatorDecisionFaultCode::MachineForm,
            "machine form is not canonical duplicate-free JSON",
        ));
    }
    Ok(parsed)
}

fn measure_value(
    value: &Value,
    depth: usize,
    fields: &mut usize,
) -> Result<(), B1CDriveOperatorDecisionFault> {
    if depth > MAX_JSON_DEPTH {
        return Err(fault(
            B1CDriveOperatorDecisionFaultCode::Bound,
            "JSON depth exceeds bound",
        ));
    }
    match value {
        Value::Object(map) => {
            *fields = fields.checked_add(map.len()).ok_or_else(|| {
                fault(
                    B1CDriveOperatorDecisionFaultCode::Bound,
                    "JSON field count overflowed",
                )
            })?;
            if *fields > MAX_JSON_FIELDS {
                return Err(fault(
                    B1CDriveOperatorDecisionFaultCode::Bound,
                    "JSON field count exceeds bound",
                ));
            }
            for child in map.values() {
                measure_value(child, depth + 1, fields)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                measure_value(child, depth + 1, fields)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn domain_digest<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<ContentDigest, B1CDriveOperatorDecisionFault> {
    let payload = serde_json::to_vec(value).map_err(machine_fault)?;
    Ok(domain_bytes_digest(domain, &payload))
}

fn domain_bytes_digest(domain: &str, payload: &[u8]) -> ContentDigest {
    let mut bytes = Vec::with_capacity(domain.len() + 1 + payload.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(payload);
    sha256_bytes(&bytes)
}

fn decode_fixed_hex<const N: usize>(
    value: &str,
    field: &str,
) -> Result<[u8; N], B1CDriveOperatorDecisionFault> {
    if !is_lower_hex(value, N * 2) {
        return Err(fault(
            B1CDriveOperatorDecisionFaultCode::MachineForm,
            format!("{field} must be exact lowercase hex"),
        ));
    }
    let mut output = [0_u8; N];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = (hex_nibble(value.as_bytes()[index * 2]) << 4)
            | hex_nibble(value.as_bytes()[index * 2 + 1]);
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => unreachable!("validated lowercase hex"),
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_digest(value: &ContentDigest) -> bool {
    value.algorithm == "sha256" && is_lower_hex(&value.value, 64)
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value
            .as_bytes()
            .iter()
            .enumerate()
            .all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => *byte == b'-',
                _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
            })
        && value != "00000000-0000-0000-0000-000000000000"
}

fn digest(value: &str) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: value.to_owned(),
    }
}

fn empty_digest() -> ContentDigest {
    digest("")
}

fn proposal_fault(error: impl fmt::Display) -> B1CDriveOperatorDecisionFault {
    fault(
        B1CDriveOperatorDecisionFaultCode::Proposal,
        format!("published proposal replay failed: {error}"),
    )
}

fn fault(
    code: B1CDriveOperatorDecisionFaultCode,
    message: impl Into<String>,
) -> B1CDriveOperatorDecisionFault {
    B1CDriveOperatorDecisionFault {
        code,
        message: message.into(),
    }
}

fn machine_fault(error: impl fmt::Display) -> B1CDriveOperatorDecisionFault {
    fault(
        B1CDriveOperatorDecisionFaultCode::MachineForm,
        error.to_string(),
    )
}
