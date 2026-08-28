//! Pure provider-free compiler for the B1 operator-authority ceremony plan.
//!
//! The plan names the externally governed ceremony. It cannot perform a
//! ceremony stage, manufacture an authority, or project into the broker.

use std::fmt;

use cantor_core::{ContentDigest, sha256_bytes};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

pub const B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_REQUEST_PROFILE: &str = "cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-authority-ceremony-plan-request/0.1";
pub const B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_PLAN_PROFILE: &str = "cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-authority-ceremony-plan/0.1";
pub const B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_VERIFICATION_PROFILE: &str = "cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-authority-ceremony-plan-verification/0.1";
pub const B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_STATUS: &str = "operator_authority_ceremony_plan_verified_awaiting_separately_supplied_governance_and_live_decision";
pub const B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_AUTHORITY: &str = "ceremony_plan_only";
pub const B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_SOURCE_SNAPSHOT_UUID: &str =
    "02bfd1ac-b826-4e4b-9a9c-30e657fc8a80";
pub const B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_CANONICAL_UUID: &str =
    "43ef2537-0fdf-4798-9f5e-8e8a3b5210e9";
pub const B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_SIGNATURE_UUID: &str =
    "6f2d23aa-89d4-4fc1-8724-7aa4d9f04845";
pub const B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_SOURCE_CUSTODY_COMMIT: &str =
    "a271142ce0b8f89f63bc4a9b095a61e416c9bae2";
pub const B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_FORMATION_COMMIT: &str =
    "c12a3bbf14d98feb410a6176231702eb4d9a3e23";
pub const B1_CDRIVE_OPERATOR_DECISION_IMPLEMENTATION_COMMIT: &str =
    "9aaaab269836b8265c74ac9c46c690493c9fe746";
pub const B1_CDRIVE_OPERATOR_DECISION_BOOKEND_COMMIT: &str =
    "bfc068ff93ef781cab3d58e7f3fce0be21ac0ccc";
pub const B1_CDRIVE_OPERATOR_DECISION_PUBLICATION_PROOF_UUID: &str =
    "5e48d1ed-a769-46b1-b7c0-a52fe7db5b2b";
pub const B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_MAX_MACHINE_FORM_BYTES: usize = 1_048_576;

const REQUEST_DOMAIN: &str = "cantor.b1.cdrive.operator-authority-ceremony.request.v1";
const PLAN_DOMAIN: &str = "cantor.b1.cdrive.operator-authority-ceremony.plan.v1";
const VERIFICATION_DOMAIN: &str = "cantor.b1.cdrive.operator-authority-ceremony.verification.v1";
const MAX_JSON_DEPTH: usize = 24;
const MAX_JSON_FIELDS: usize = 512;
const EXACT_BRANCH: &str = "codex/self-hosted-corpus";
const EXACT_REMOTE: &str = "https://github.com/cattailfarmer/Cantor";
const EXACT_PROPOSAL_UUID: &str = "a5822c1d-1613-408e-93b5-34f78bdbd571";
const EXACT_PROPOSAL_SELF_DIGEST: &str =
    "591525df40baaebd800077b3349702687db39d2eac1359f2e15eccce010ae9e8";
const EXACT_PROPOSAL_RAW_SHA256: &str =
    "1e0b482d41e4d450200e62fa131a0bb1a9d01a2858e7f52fcfd5b2a2dd1e8f9e";
const EXACT_PRINCIPAL: &str = r"THEBRAIN\enjer";
const EXACT_ROLE: &str = "operator_authorizer";
const EXACT_SUBJECT: &str = "cantor_b1_cdrive_production_preparation_p0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveOperatorAuthorityCeremonyRequest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_custody_commit: String,
    pub formation_commit: String,
    pub operator_decision_implementation_commit: String,
    pub operator_decision_bookend_commit: String,
    pub operator_decision_publication_proof_uuid: String,
    pub branch: String,
    pub canonical_remote: String,
    pub proposal_uuid: String,
    pub proposal_self_digest: String,
    pub proposal_raw_bytes: u32,
    pub proposal_raw_sha256: String,
    pub principal: String,
    pub role: String,
    pub subject: String,
    pub unresolved_authorities: Vec<String>,
    pub maximum_attempts: u8,
    pub automatic_retry_count: u8,
    pub automatic_cleanup_count: u8,
    pub fixture_only: bool,
    pub request_sha256: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDriveOperatorAuthorityCeremonyRoleKind {
    OperatorPrincipal,
    PolicyGovernor,
    KeyCustodian,
    RevocationAuthority,
    TimeWitness,
    ObservationAcquirer,
    PermitIssuer,
    BrokerExecutor,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveOperatorAuthorityCeremonyRole {
    pub sequence: u8,
    pub kind: B1CDriveOperatorAuthorityCeremonyRoleKind,
    pub responsibility: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDriveOperatorAuthorityCeremonyStageKind {
    PolicyGovernance,
    PublicKeyCustody,
    RevocationTruth,
    CurrentTimeWitness,
    LiveDecision,
    CryptographicCorrespondence,
    FreshObservation,
    PrivateExecutionPermit,
    BrokerProjectionAdmission,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveOperatorAuthorityCeremonyStage {
    pub sequence: u8,
    pub kind: B1CDriveOperatorAuthorityCeremonyStageKind,
    pub predecessor_sequence: Option<u8>,
    pub responsible_role: B1CDriveOperatorAuthorityCeremonyRoleKind,
    pub required_input: String,
    pub expected_output: String,
    pub authority_before: Vec<String>,
    pub authority_required: Vec<String>,
    pub authority_after: Vec<String>,
    pub unresolved_after: Vec<String>,
    pub executed: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveOperatorAuthorityCeremonyEffectAccount {
    pub key_generation_count: u32,
    pub private_key_read_count: u32,
    pub signing_count: u32,
    pub decision_issuance_count: u32,
    pub clock_read_count: u32,
    pub environment_read_count: u32,
    pub host_observation_count: u32,
    pub physical_contact: bool,
    pub process_count: u32,
    pub provider_trial_count: u32,
    pub model_turn_count: u32,
    pub mcp_call_count: u32,
    pub network_contact_count: u32,
    pub writer_run_count: u32,
    pub git_runtime_mutation_count: u32,
    pub filesystem_runtime_mutation_count: u32,
    pub publication_count: u32,
    pub persistence_count: u32,
    pub activation_count: u32,
    pub d_drive_runtime_contact_count: u32,
    pub wsl_compile_count: u32,
    pub cleanup_effect_count: u32,
    pub foreign_effect_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveOperatorAuthorityCeremonyPlan {
    pub profile: String,
    pub status: String,
    pub authority: String,
    pub request_sha256: ContentDigest,
    pub roles: Vec<B1CDriveOperatorAuthorityCeremonyRole>,
    pub stages: Vec<B1CDriveOperatorAuthorityCeremonyStage>,
    pub unresolved_authorities: Vec<String>,
    pub maximum_attempts: u8,
    pub automatic_retry_count: u8,
    pub automatic_cleanup_count: u8,
    pub fixture_only: bool,
    pub policy_governance_proved: bool,
    pub key_custody_proved: bool,
    pub revocation_truth_proved: bool,
    pub current_nonexpired: bool,
    pub live_authorization_admitted: bool,
    pub fresh_observation_proved: bool,
    pub private_execution_permit_present: bool,
    pub production_broker_projection_present: bool,
    pub physical_preparation_authorized: bool,
    pub effect_account: B1CDriveOperatorAuthorityCeremonyEffectAccount,
    pub plan_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveOperatorAuthorityCeremonyVerification {
    pub profile: String,
    pub status: String,
    pub authority: String,
    pub request_sha256: ContentDigest,
    pub plan_sha256: ContentDigest,
    pub role_count: u8,
    pub stage_count: u8,
    pub unresolved_authority_count: u8,
    pub deterministic_replay_count: u8,
    pub byte_identical: bool,
    pub fixture_only: bool,
    pub policy_governance_proved: bool,
    pub key_custody_proved: bool,
    pub revocation_truth_proved: bool,
    pub current_nonexpired: bool,
    pub live_authorization_admitted: bool,
    pub fresh_observation_proved: bool,
    pub private_execution_permit_present: bool,
    pub production_broker_projection_present: bool,
    pub physical_preparation_authorized: bool,
    pub effect_account: B1CDriveOperatorAuthorityCeremonyEffectAccount,
    pub verification_sha256: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum B1CDriveOperatorAuthorityCeremonyFaultCode {
    Bound,
    MachineForm,
    Identity,
    Role,
    Stage,
    Authority,
    Effect,
    Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B1CDriveOperatorAuthorityCeremonyFault {
    pub code: B1CDriveOperatorAuthorityCeremonyFaultCode,
    pub message: String,
}

impl fmt::Display for B1CDriveOperatorAuthorityCeremonyFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for B1CDriveOperatorAuthorityCeremonyFault {}

pub fn canonical_b1_cdrive_operator_authority_ceremony_request()
-> Result<B1CDriveOperatorAuthorityCeremonyRequest, B1CDriveOperatorAuthorityCeremonyFault> {
    let mut request = B1CDriveOperatorAuthorityCeremonyRequest {
        profile: B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_REQUEST_PROFILE.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_CANONICAL_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_SIGNATURE_UUID.to_owned(),
        source_custody_commit: B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_SOURCE_CUSTODY_COMMIT
            .to_owned(),
        formation_commit: B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_FORMATION_COMMIT.to_owned(),
        operator_decision_implementation_commit: B1_CDRIVE_OPERATOR_DECISION_IMPLEMENTATION_COMMIT
            .to_owned(),
        operator_decision_bookend_commit: B1_CDRIVE_OPERATOR_DECISION_BOOKEND_COMMIT.to_owned(),
        operator_decision_publication_proof_uuid:
            B1_CDRIVE_OPERATOR_DECISION_PUBLICATION_PROOF_UUID.to_owned(),
        branch: EXACT_BRANCH.to_owned(),
        canonical_remote: EXACT_REMOTE.to_owned(),
        proposal_uuid: EXACT_PROPOSAL_UUID.to_owned(),
        proposal_self_digest: EXACT_PROPOSAL_SELF_DIGEST.to_owned(),
        proposal_raw_bytes: 5_791,
        proposal_raw_sha256: EXACT_PROPOSAL_RAW_SHA256.to_owned(),
        principal: EXACT_PRINCIPAL.to_owned(),
        role: EXACT_ROLE.to_owned(),
        subject: EXACT_SUBJECT.to_owned(),
        unresolved_authorities: expected_unresolved_authorities(),
        maximum_attempts: 1,
        automatic_retry_count: 0,
        automatic_cleanup_count: 0,
        fixture_only: true,
        request_sha256: empty_digest(),
    };
    request.request_sha256 = b1_cdrive_operator_authority_ceremony_request_digest(&request)?;
    validate_b1_cdrive_operator_authority_ceremony_request(&request)?;
    Ok(request)
}

pub fn compile_b1_cdrive_operator_authority_ceremony_plan(
    request: &B1CDriveOperatorAuthorityCeremonyRequest,
) -> Result<B1CDriveOperatorAuthorityCeremonyPlan, B1CDriveOperatorAuthorityCeremonyFault> {
    validate_b1_cdrive_operator_authority_ceremony_request(request)?;
    let mut plan = B1CDriveOperatorAuthorityCeremonyPlan {
        profile: B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_PLAN_PROFILE.to_owned(),
        status: B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_STATUS.to_owned(),
        authority: B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_AUTHORITY.to_owned(),
        request_sha256: request.request_sha256.clone(),
        roles: expected_roles(),
        stages: expected_stages(),
        unresolved_authorities: expected_unresolved_authorities(),
        maximum_attempts: 1,
        automatic_retry_count: 0,
        automatic_cleanup_count: 0,
        fixture_only: true,
        policy_governance_proved: false,
        key_custody_proved: false,
        revocation_truth_proved: false,
        current_nonexpired: false,
        live_authorization_admitted: false,
        fresh_observation_proved: false,
        private_execution_permit_present: false,
        production_broker_projection_present: false,
        physical_preparation_authorized: false,
        effect_account: B1CDriveOperatorAuthorityCeremonyEffectAccount::default(),
        plan_sha256: empty_digest(),
    };
    plan.plan_sha256 = b1_cdrive_operator_authority_ceremony_plan_digest(&plan)?;
    validate_b1_cdrive_operator_authority_ceremony_plan(request, &plan)?;
    Ok(plan)
}

pub fn verify_b1_cdrive_operator_authority_ceremony_plan(
    request: &B1CDriveOperatorAuthorityCeremonyRequest,
    plan: &B1CDriveOperatorAuthorityCeremonyPlan,
) -> Result<B1CDriveOperatorAuthorityCeremonyVerification, B1CDriveOperatorAuthorityCeremonyFault> {
    validate_b1_cdrive_operator_authority_ceremony_plan(request, plan)?;
    let first = compile_b1_cdrive_operator_authority_ceremony_plan(request)?;
    let second = compile_b1_cdrive_operator_authority_ceremony_plan(request)?;
    let first_bytes = serde_json::to_vec(&first).map_err(machine_fault)?;
    let second_bytes = serde_json::to_vec(&second).map_err(machine_fault)?;
    if &first != plan || &second != plan || first_bytes != second_bytes {
        return Err(fault(
            B1CDriveOperatorAuthorityCeremonyFaultCode::Digest,
            "ceremony plan replay differs",
        ));
    }
    let mut verification = B1CDriveOperatorAuthorityCeremonyVerification {
        profile: B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_VERIFICATION_PROFILE.to_owned(),
        status: B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_STATUS.to_owned(),
        authority: B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_AUTHORITY.to_owned(),
        request_sha256: request.request_sha256.clone(),
        plan_sha256: plan.plan_sha256.clone(),
        role_count: 8,
        stage_count: 9,
        unresolved_authority_count: 9,
        deterministic_replay_count: 2,
        byte_identical: true,
        fixture_only: true,
        policy_governance_proved: false,
        key_custody_proved: false,
        revocation_truth_proved: false,
        current_nonexpired: false,
        live_authorization_admitted: false,
        fresh_observation_proved: false,
        private_execution_permit_present: false,
        production_broker_projection_present: false,
        physical_preparation_authorized: false,
        effect_account: B1CDriveOperatorAuthorityCeremonyEffectAccount::default(),
        verification_sha256: empty_digest(),
    };
    verification.verification_sha256 =
        b1_cdrive_operator_authority_ceremony_verification_digest(&verification)?;
    validate_b1_cdrive_operator_authority_ceremony_verification(request, plan, &verification)?;
    Ok(verification)
}

pub fn validate_b1_cdrive_operator_authority_ceremony_request(
    request: &B1CDriveOperatorAuthorityCeremonyRequest,
) -> Result<(), B1CDriveOperatorAuthorityCeremonyFault> {
    if request.profile != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_REQUEST_PROFILE
        || request.source_snapshot_uuid
            != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_SOURCE_SNAPSHOT_UUID
        || request.canonical_uuid != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_CANONICAL_UUID
        || request.signature_uuid != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_SIGNATURE_UUID
        || request.source_custody_commit
            != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_SOURCE_CUSTODY_COMMIT
        || request.formation_commit != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_FORMATION_COMMIT
        || request.operator_decision_implementation_commit
            != B1_CDRIVE_OPERATOR_DECISION_IMPLEMENTATION_COMMIT
        || request.operator_decision_bookend_commit != B1_CDRIVE_OPERATOR_DECISION_BOOKEND_COMMIT
        || request.operator_decision_publication_proof_uuid
            != B1_CDRIVE_OPERATOR_DECISION_PUBLICATION_PROOF_UUID
        || request.branch != EXACT_BRANCH
        || request.canonical_remote != EXACT_REMOTE
        || request.proposal_uuid != EXACT_PROPOSAL_UUID
        || request.proposal_self_digest != EXACT_PROPOSAL_SELF_DIGEST
        || request.proposal_raw_bytes != 5_791
        || request.proposal_raw_sha256 != EXACT_PROPOSAL_RAW_SHA256
        || request.principal != EXACT_PRINCIPAL
        || request.role != EXACT_ROLE
        || request.subject != EXACT_SUBJECT
        || request.unresolved_authorities != expected_unresolved_authorities()
        || request.maximum_attempts != 1
        || request.automatic_retry_count != 0
        || request.automatic_cleanup_count != 0
        || !request.fixture_only
    {
        return Err(fault(
            B1CDriveOperatorAuthorityCeremonyFaultCode::Identity,
            "ceremony request identity, ceiling, or nonauthority differs",
        ));
    }
    if request.request_sha256 != b1_cdrive_operator_authority_ceremony_request_digest(request)? {
        return Err(fault(
            B1CDriveOperatorAuthorityCeremonyFaultCode::Digest,
            "ceremony request digest differs",
        ));
    }
    Ok(())
}

pub fn validate_b1_cdrive_operator_authority_ceremony_plan(
    request: &B1CDriveOperatorAuthorityCeremonyRequest,
    plan: &B1CDriveOperatorAuthorityCeremonyPlan,
) -> Result<(), B1CDriveOperatorAuthorityCeremonyFault> {
    validate_b1_cdrive_operator_authority_ceremony_request(request)?;
    if plan.profile != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_PLAN_PROFILE
        || plan.status != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_STATUS
        || plan.authority != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_AUTHORITY
        || plan.request_sha256 != request.request_sha256
        || plan.roles != expected_roles()
        || plan.stages != expected_stages()
    {
        return Err(fault(
            B1CDriveOperatorAuthorityCeremonyFaultCode::Stage,
            "ceremony role or stage circuit differs",
        ));
    }
    validate_non_authority(
        &plan.unresolved_authorities,
        plan.maximum_attempts,
        plan.automatic_retry_count,
        plan.automatic_cleanup_count,
        plan.fixture_only,
        plan.policy_governance_proved,
        plan.key_custody_proved,
        plan.revocation_truth_proved,
        plan.current_nonexpired,
        plan.live_authorization_admitted,
        plan.fresh_observation_proved,
        plan.private_execution_permit_present,
        plan.production_broker_projection_present,
        plan.physical_preparation_authorized,
        &plan.effect_account,
    )?;
    if plan.plan_sha256 != b1_cdrive_operator_authority_ceremony_plan_digest(plan)? {
        return Err(fault(
            B1CDriveOperatorAuthorityCeremonyFaultCode::Digest,
            "ceremony plan digest differs",
        ));
    }
    Ok(())
}

pub fn validate_b1_cdrive_operator_authority_ceremony_verification(
    request: &B1CDriveOperatorAuthorityCeremonyRequest,
    plan: &B1CDriveOperatorAuthorityCeremonyPlan,
    verification: &B1CDriveOperatorAuthorityCeremonyVerification,
) -> Result<(), B1CDriveOperatorAuthorityCeremonyFault> {
    validate_b1_cdrive_operator_authority_ceremony_plan(request, plan)?;
    if verification.profile != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_VERIFICATION_PROFILE
        || verification.status != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_STATUS
        || verification.authority != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_AUTHORITY
        || verification.request_sha256 != request.request_sha256
        || verification.plan_sha256 != plan.plan_sha256
        || verification.role_count != 8
        || verification.stage_count != 9
        || verification.unresolved_authority_count != 9
        || verification.deterministic_replay_count != 2
        || !verification.byte_identical
    {
        return Err(fault(
            B1CDriveOperatorAuthorityCeremonyFaultCode::Identity,
            "ceremony verification identity or count differs",
        ));
    }
    validate_non_authority(
        &expected_unresolved_authorities(),
        1,
        0,
        0,
        verification.fixture_only,
        verification.policy_governance_proved,
        verification.key_custody_proved,
        verification.revocation_truth_proved,
        verification.current_nonexpired,
        verification.live_authorization_admitted,
        verification.fresh_observation_proved,
        verification.private_execution_permit_present,
        verification.production_broker_projection_present,
        verification.physical_preparation_authorized,
        &verification.effect_account,
    )?;
    if verification.verification_sha256
        != b1_cdrive_operator_authority_ceremony_verification_digest(verification)?
    {
        return Err(fault(
            B1CDriveOperatorAuthorityCeremonyFaultCode::Digest,
            "ceremony verification digest differs",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_non_authority(
    unresolved: &[String],
    attempts: u8,
    retries: u8,
    cleanup: u8,
    fixture_only: bool,
    policy: bool,
    custody: bool,
    revocation: bool,
    current: bool,
    authorization: bool,
    observation: bool,
    permit: bool,
    projection: bool,
    preparation: bool,
    effects: &B1CDriveOperatorAuthorityCeremonyEffectAccount,
) -> Result<(), B1CDriveOperatorAuthorityCeremonyFault> {
    if unresolved != expected_unresolved_authorities()
        || attempts != 1
        || retries != 0
        || cleanup != 0
        || !fixture_only
        || policy
        || custody
        || revocation
        || current
        || authorization
        || observation
        || permit
        || projection
        || preparation
    {
        return Err(fault(
            B1CDriveOperatorAuthorityCeremonyFaultCode::Authority,
            "ceremony authority conservation differs",
        ));
    }
    if effects != &B1CDriveOperatorAuthorityCeremonyEffectAccount::default() {
        return Err(fault(
            B1CDriveOperatorAuthorityCeremonyFaultCode::Effect,
            "ceremony plan effect account differs",
        ));
    }
    Ok(())
}

pub fn b1_cdrive_operator_authority_ceremony_request_digest(
    request: &B1CDriveOperatorAuthorityCeremonyRequest,
) -> Result<ContentDigest, B1CDriveOperatorAuthorityCeremonyFault> {
    let mut normalized = request.clone();
    normalized.request_sha256 = empty_digest();
    domain_digest(REQUEST_DOMAIN, &normalized)
}

pub fn b1_cdrive_operator_authority_ceremony_plan_digest(
    plan: &B1CDriveOperatorAuthorityCeremonyPlan,
) -> Result<ContentDigest, B1CDriveOperatorAuthorityCeremonyFault> {
    let mut normalized = plan.clone();
    normalized.plan_sha256 = empty_digest();
    domain_digest(PLAN_DOMAIN, &normalized)
}

pub fn b1_cdrive_operator_authority_ceremony_verification_digest(
    verification: &B1CDriveOperatorAuthorityCeremonyVerification,
) -> Result<ContentDigest, B1CDriveOperatorAuthorityCeremonyFault> {
    let mut normalized = verification.clone();
    normalized.verification_sha256 = empty_digest();
    domain_digest(VERIFICATION_DOMAIN, &normalized)
}

pub fn to_b1_cdrive_operator_authority_ceremony_request_machine_form(
    request: &B1CDriveOperatorAuthorityCeremonyRequest,
) -> Result<String, B1CDriveOperatorAuthorityCeremonyFault> {
    validate_b1_cdrive_operator_authority_ceremony_request(request)?;
    serde_json::to_string(request).map_err(machine_fault)
}

pub fn from_b1_cdrive_operator_authority_ceremony_request_machine_form(
    machine_form: &str,
) -> Result<B1CDriveOperatorAuthorityCeremonyRequest, B1CDriveOperatorAuthorityCeremonyFault> {
    let request = parse_canonical(machine_form)?;
    validate_b1_cdrive_operator_authority_ceremony_request(&request)?;
    Ok(request)
}

pub fn to_b1_cdrive_operator_authority_ceremony_plan_machine_form(
    request: &B1CDriveOperatorAuthorityCeremonyRequest,
    plan: &B1CDriveOperatorAuthorityCeremonyPlan,
) -> Result<String, B1CDriveOperatorAuthorityCeremonyFault> {
    validate_b1_cdrive_operator_authority_ceremony_plan(request, plan)?;
    serde_json::to_string(plan).map_err(machine_fault)
}

pub fn from_b1_cdrive_operator_authority_ceremony_plan_machine_form(
    request: &B1CDriveOperatorAuthorityCeremonyRequest,
    machine_form: &str,
) -> Result<B1CDriveOperatorAuthorityCeremonyPlan, B1CDriveOperatorAuthorityCeremonyFault> {
    let plan = parse_canonical(machine_form)?;
    validate_b1_cdrive_operator_authority_ceremony_plan(request, &plan)?;
    Ok(plan)
}

pub fn to_b1_cdrive_operator_authority_ceremony_verification_machine_form(
    request: &B1CDriveOperatorAuthorityCeremonyRequest,
    plan: &B1CDriveOperatorAuthorityCeremonyPlan,
    verification: &B1CDriveOperatorAuthorityCeremonyVerification,
) -> Result<String, B1CDriveOperatorAuthorityCeremonyFault> {
    validate_b1_cdrive_operator_authority_ceremony_verification(request, plan, verification)?;
    serde_json::to_string(verification).map_err(machine_fault)
}

pub fn expected_b1_cdrive_operator_authority_ceremony_roles()
-> Vec<B1CDriveOperatorAuthorityCeremonyRole> {
    expected_roles()
}

pub fn expected_b1_cdrive_operator_authority_ceremony_stages()
-> Vec<B1CDriveOperatorAuthorityCeremonyStage> {
    expected_stages()
}

pub fn expected_b1_cdrive_operator_authority_ceremony_unresolved_authorities() -> Vec<String> {
    expected_unresolved_authorities()
}

fn expected_roles() -> Vec<B1CDriveOperatorAuthorityCeremonyRole> {
    use B1CDriveOperatorAuthorityCeremonyRoleKind as Role;
    [
        (
            Role::OperatorPrincipal,
            "approve_or_reject_without_compiler_substitution",
        ),
        (
            Role::PolicyGovernor,
            "author_and_approve_exact_governance_artifact",
        ),
        (
            Role::KeyCustodian,
            "attest_public_key_provenance_keep_private_material_external",
        ),
        (
            Role::RevocationAuthority,
            "supply_current_revocation_snapshot",
        ),
        (
            Role::TimeWitness,
            "supply_separately_trusted_current_time_receipt",
        ),
        (
            Role::ObservationAcquirer,
            "supply_fresh_expected_current_host_and_workspace_evidence",
        ),
        (
            Role::PermitIssuer,
            "bind_authorization_freshness_attempt_recovery_and_quarantine",
        ),
        (
            Role::BrokerExecutor,
            "receive_only_later_independently_admitted_projection",
        ),
    ]
    .into_iter()
    .enumerate()
    .map(
        |(index, (kind, responsibility))| B1CDriveOperatorAuthorityCeremonyRole {
            sequence: (index + 1) as u8,
            kind,
            responsibility: responsibility.to_owned(),
        },
    )
    .collect()
}

fn expected_stages() -> Vec<B1CDriveOperatorAuthorityCeremonyStage> {
    use B1CDriveOperatorAuthorityCeremonyRoleKind as Role;
    use B1CDriveOperatorAuthorityCeremonyStageKind as Stage;
    let definitions = [
        (
            Stage::PolicyGovernance,
            Role::PolicyGovernor,
            "user_authored_policy_source",
            "approved_policy_governance_receipt",
            "policy_governance",
        ),
        (
            Stage::PublicKeyCustody,
            Role::KeyCustodian,
            "approved_policy_and_public_key",
            "public_key_custody_attestation",
            "key_custody",
        ),
        (
            Stage::RevocationTruth,
            Role::RevocationAuthority,
            "custody_attestation_and_revocation_snapshot",
            "unrevoked_key_observation",
            "revocation_truth",
        ),
        (
            Stage::CurrentTimeWitness,
            Role::TimeWitness,
            "trusted_time_source_contract",
            "current_time_witness_receipt",
            "current_time",
        ),
        (
            Stage::LiveDecision,
            Role::OperatorPrincipal,
            "exact_proposal_and_current_policy",
            "externally_signed_authorize_or_reject_envelope",
            "live_decision",
        ),
        (
            Stage::CryptographicCorrespondence,
            Role::OperatorPrincipal,
            "signed_envelope_and_published_verifier",
            "fixture_false_cryptographic_correspondence_receipt",
            "live_decision",
        ),
        (
            Stage::FreshObservation,
            Role::ObservationAcquirer,
            "expected_current_host_workspace_and_preparation_prerequisites",
            "fresh_expected_current_observation",
            "fresh_observation",
        ),
        (
            Stage::PrivateExecutionPermit,
            Role::PermitIssuer,
            "authorization_time_observation_attempt_and_recovery_receipts",
            "private_execution_permit_candidate",
            "private_execution_permit",
        ),
        (
            Stage::BrokerProjectionAdmission,
            Role::BrokerExecutor,
            "independently_admitted_permit_and_broker_contract",
            "production_broker_projection_candidate",
            "broker_projection",
        ),
    ];
    let unresolved = expected_unresolved_authorities();
    definitions
        .into_iter()
        .enumerate()
        .map(|(index, (kind, role, input, output, required))| {
            B1CDriveOperatorAuthorityCeremonyStage {
                sequence: (index + 1) as u8,
                kind,
                predecessor_sequence: (index != 0).then_some(index as u8),
                responsible_role: role,
                required_input: input.to_owned(),
                expected_output: output.to_owned(),
                authority_before: unresolved.clone(),
                authority_required: vec![required.to_owned()],
                authority_after: unresolved.clone(),
                unresolved_after: unresolved.clone(),
                executed: false,
            }
        })
        .collect()
}

fn expected_unresolved_authorities() -> Vec<String> {
    [
        "policy_governance",
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

fn parse_canonical<T: DeserializeOwned + Serialize>(
    machine_form: &str,
) -> Result<T, B1CDriveOperatorAuthorityCeremonyFault> {
    if machine_form.is_empty()
        || machine_form.len() > B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_MAX_MACHINE_FORM_BYTES
    {
        return Err(fault(
            B1CDriveOperatorAuthorityCeremonyFaultCode::Bound,
            "machine form byte bound differs",
        ));
    }
    let value: Value = serde_json::from_str(machine_form).map_err(machine_fault)?;
    let mut fields = 0_usize;
    measure_value(&value, 1, &mut fields)?;
    let parsed: T = serde_json::from_str(machine_form).map_err(machine_fault)?;
    if serde_json::to_string(&parsed).map_err(machine_fault)? != machine_form {
        return Err(fault(
            B1CDriveOperatorAuthorityCeremonyFaultCode::MachineForm,
            "machine form is not canonical duplicate-free JSON",
        ));
    }
    Ok(parsed)
}

fn measure_value(
    value: &Value,
    depth: usize,
    fields: &mut usize,
) -> Result<(), B1CDriveOperatorAuthorityCeremonyFault> {
    if depth > MAX_JSON_DEPTH {
        return Err(fault(
            B1CDriveOperatorAuthorityCeremonyFaultCode::Bound,
            "JSON depth exceeds bound",
        ));
    }
    match value {
        Value::Object(map) => {
            *fields = fields.checked_add(map.len()).ok_or_else(|| {
                fault(
                    B1CDriveOperatorAuthorityCeremonyFaultCode::Bound,
                    "JSON field count overflowed",
                )
            })?;
            if *fields > MAX_JSON_FIELDS {
                return Err(fault(
                    B1CDriveOperatorAuthorityCeremonyFaultCode::Bound,
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
) -> Result<ContentDigest, B1CDriveOperatorAuthorityCeremonyFault> {
    let payload = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + payload.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&payload);
    Ok(sha256_bytes(&bytes))
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

fn fault(
    code: B1CDriveOperatorAuthorityCeremonyFaultCode,
    message: impl Into<String>,
) -> B1CDriveOperatorAuthorityCeremonyFault {
    B1CDriveOperatorAuthorityCeremonyFault {
        code,
        message: message.into(),
    }
}

fn machine_fault(error: impl fmt::Display) -> B1CDriveOperatorAuthorityCeremonyFault {
    fault(
        B1CDriveOperatorAuthorityCeremonyFaultCode::MachineForm,
        error.to_string(),
    )
}
