//! Pure forms for the EVO-X2 remote-preflight one-shot activation ceremony.
//!
//! This module compiles and verifies an inert proposal and verifies the
//! cryptographic correspondence of a supplied operator decision. It has no
//! clock, filesystem, process, network, provider, permit-mint, or runner entry
//! surface and never promotes correspondence into live authority.

use std::fmt::{self, Write as _};

use cantor_core::{
    Evox2ScratchBuildControllerPlan, Evox2ScratchBuildControllerRequest,
    Evox2ScratchBuildEffectProgram, Evox2ScratchBuildRemotePreflightProducerPlan,
    verify_evox2_scratch_build_remote_preflight_producer_plan,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const EVOX2_REMOTE_PREFLIGHT_ACTIVATION_REQUEST_PROFILE: &str =
    "cantor-evox2-remote-preflight-activation-request/0.1";
pub const EVOX2_REMOTE_PREFLIGHT_ACTIVATION_PROPOSAL_PROFILE: &str =
    "cantor-evox2-remote-preflight-activation-proposal/0.1";
pub const EVOX2_REMOTE_PREFLIGHT_ACTIVATION_PROPOSAL_VERIFICATION_PROFILE: &str =
    "cantor-evox2-remote-preflight-activation-proposal-verification/0.1";
pub const EVOX2_REMOTE_PREFLIGHT_ACTIVATION_DECISION_PROFILE: &str =
    "cantor-evox2-remote-preflight-operator-decision/0.1";
pub const EVOX2_REMOTE_PREFLIGHT_ACTIVATION_DECISION_CORRESPONDENCE_PROFILE: &str =
    "cantor-evox2-remote-preflight-decision-correspondence/0.1";
pub const EVOX2_REMOTE_PREFLIGHT_ACTIVATION_STATUS: &str =
    "proposal_verified_live_authority_absent";
pub const EVOX2_REMOTE_PREFLIGHT_ACTIVATION_AUTHORITY: &str =
    "pure_correspondence_only_permit_bridge_not_authorized";
pub const EVOX2_REMOTE_PREFLIGHT_ACTIVATION_CANONICAL_UUID: &str =
    "d2724a39-56bd-47ae-8787-064a6196dbfb";
pub const EVOX2_REMOTE_PREFLIGHT_ACTIVATION_SOURCE_SNAPSHOT_UUID: &str =
    "e4929ffa-1c10-451e-ad4d-ddbccc992c52";
pub const EVOX2_REMOTE_PREFLIGHT_ACTIVATION_SIGNATURE_UUID: &str =
    "1feeedea-716a-4b47-ac28-d7e5b7045842";
pub const EVOX2_REMOTE_PREFLIGHT_ACTIVATION_FORMATION_COMMIT: &str =
    "7b508b67a7b16c091e4dbea512c691b885e33a2f";
pub const EVOX2_REMOTE_PREFLIGHT_ACTIVATION_FORMATION_BOOKEND: &str =
    "169c7720914b53c7800293f8352e1ede84846013";
pub const EVOX2_REMOTE_PREFLIGHT_RUNNER_IMPLEMENTATION_COMMIT: &str =
    "0eb334670d825ea7123beb445df1a47e1bc81349";
pub const EVOX2_REMOTE_PREFLIGHT_RUNNER_BOOKEND_COMMIT: &str =
    "0674395c78a998ce1c36c714e52bae68d0f83f58";
pub const EVOX2_REMOTE_PREFLIGHT_PRODUCER_IMPLEMENTATION_COMMIT: &str =
    "606588a6dd542b31816d116abf909f50d0881937";
pub const EVOX2_REMOTE_PREFLIGHT_PRODUCER_BOOKEND_COMMIT: &str =
    "b48c4d7ac48e51aaf70f179cc7b1cdd15e9d5bd0";
pub const EVOX2_REMOTE_PREFLIGHT_CONTROLLER_REQUEST_SHA256: &str =
    "e7dffae6d82cda84e9dd13d77d7d95ba2e403561e511dc7bfb9299b25ae79c8d";
pub const EVOX2_REMOTE_PREFLIGHT_CONTROLLER_PLAN_SHA256: &str =
    "975e1dc17d8f0b678f76c5f8d74bb795c3f09b3cff31a57a0c3af29b39981c97";
pub const EVOX2_REMOTE_PREFLIGHT_CONTROLLER_PROGRAM_SHA256: &str =
    "b8a832656aa3739ac87daffa81858b184b2eddf8c849d2a7f439926611521992";
pub const EVOX2_REMOTE_PREFLIGHT_ACTIVATION_MAX_MACHINE_BYTES: usize = 1_048_576;

const REQUEST_DOMAIN: &[u8] = b"cantor-evox2-remote-preflight-activation-request-v1\0";
const PROPOSAL_DOMAIN: &[u8] = b"cantor-evox2-remote-preflight-activation-proposal-v1\0";
const PROPOSAL_VERIFICATION_DOMAIN: &[u8] =
    b"cantor-evox2-remote-preflight-activation-proposal-verification-v1\0";
const DECISION_SIGNING_DOMAIN: &[u8] =
    b"cantor-evox2-remote-preflight-operator-decision-signing-v1\0";
const DECISION_DOMAIN: &[u8] = b"cantor-evox2-remote-preflight-operator-decision-v1\0";
const CORRESPONDENCE_DOMAIN: &[u8] = b"cantor-evox2-remote-preflight-decision-correspondence-v1\0";
const MAX_JSON_DEPTH: usize = 24;
const MAX_JSON_FIELDS: usize = 512;
const EXACT_EXECUTABLE: &str = "C:/Windows/System32/OpenSSH/ssh.exe";
const EXACT_TARGET: &str = "EVO-X2";
const EXACT_SSH_HOST: &str = "evo-x2";
const EXACT_PRINCIPAL: &str = r"THEBRAIN\enjer";
const EXACT_ROLE: &str = "operator_authorizer";
const EXACT_SUBJECT: &str = "cantor_evox2_remote_preflight_one_shot_activation_p0";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2RemotePreflightActivationEffectAccount {
    pub clock_reads: u32,
    pub signature_creations: u32,
    pub permit_mints: u32,
    pub runner_invocations: u32,
    pub process_spawns: u32,
    pub provider_requests: u32,
    pub remote_calls: u32,
    pub effects: u32,
    pub synthetic_trials: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evox2RemotePreflightActivationRoleKind {
    ProposalCompiler,
    PublicationVerifier,
    OperatorPrincipal,
    DecisionVerifier,
    PermitIssuer,
    RunnerExecutor,
    ReceiptVerifier,
    TerminalRecorder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evox2RemotePreflightActivationStageKind {
    CompileProposal,
    VerifyPublication,
    SupplyDecision,
    AdmitDecision,
    MintPermit,
    ConsumeAndInvoke,
    VerifyReceipt,
    CloseTerminal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2RemotePreflightActivationStage {
    pub sequence: u8,
    pub kind: Evox2RemotePreflightActivationStageKind,
    pub predecessor_sequence: Option<u8>,
    pub responsible_role: Evox2RemotePreflightActivationRoleKind,
    pub effectful: bool,
    pub executed: bool,
    pub terminal_on_refusal: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2RemotePreflightActivationRequest {
    pub profile: String,
    pub ceremony_uuid: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub formation_commit: String,
    pub formation_bookend: String,
    pub runner_implementation_commit: String,
    pub runner_bookend_commit: String,
    pub producer_implementation_commit: String,
    pub producer_bookend_commit: String,
    pub operator_principal: String,
    pub operator_role: String,
    pub subject: String,
    pub decision_nonce: String,
    pub decision_not_before_ms: u64,
    pub decision_expires_at_ms: u64,
    pub fixture_only: bool,
    pub request_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2RemotePreflightActivationProposal {
    pub profile: String,
    pub ceremony_uuid: String,
    pub request_sha256: String,
    pub canonical_uuid: String,
    pub formation_commit: String,
    pub formation_bookend: String,
    pub runner_implementation_commit: String,
    pub runner_bookend_commit: String,
    pub producer_implementation_commit: String,
    pub producer_bookend_commit: String,
    pub controller_request_sha256: String,
    pub controller_plan_sha256: String,
    pub controller_program_sha256: String,
    pub producer_plan_sha256: String,
    pub executable_path: String,
    pub executable_sha256: String,
    pub target_host: String,
    pub ssh_host: String,
    pub argument_atoms: Vec<String>,
    pub argument_count: u32,
    pub timeout_millis: u64,
    pub maximum_stdout_bytes: u32,
    pub maximum_stderr_bytes: u32,
    pub maximum_attempts: u8,
    pub maximum_permits: u8,
    pub maximum_active_processes: u8,
    pub maximum_total_processes: u8,
    pub retry_count: u8,
    pub operator_principal: String,
    pub operator_role: String,
    pub subject: String,
    pub decision_nonce: String,
    pub decision_not_before_ms: u64,
    pub decision_expires_at_ms: u64,
    pub roles: Vec<Evox2RemotePreflightActivationRoleKind>,
    pub stages: Vec<Evox2RemotePreflightActivationStage>,
    pub status: String,
    pub authority: String,
    pub live_authorization_admitted: bool,
    pub permit_mint_authorized: bool,
    pub runner_invocation_authorized: bool,
    pub fixture_only: bool,
    pub effect_account: Evox2RemotePreflightActivationEffectAccount,
    pub proposal_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2RemotePreflightActivationProposalVerification {
    pub profile: String,
    pub ceremony_uuid: String,
    pub request_sha256: String,
    pub proposal_sha256: String,
    pub producer_plan_sha256: String,
    pub deterministic_replay_count: u8,
    pub byte_identical: bool,
    pub role_count: u8,
    pub stage_count: u8,
    pub argument_count: u32,
    pub maximum_attempts: u8,
    pub maximum_permits: u8,
    pub maximum_processes: u8,
    pub retry_count: u8,
    pub status: String,
    pub authority: String,
    pub live_authorization_admitted: bool,
    pub permit_mint_authorized: bool,
    pub runner_invocation_authorized: bool,
    pub fixture_only: bool,
    pub effect_account: Evox2RemotePreflightActivationEffectAccount,
    pub proposal_verification_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evox2RemotePreflightOperatorDecisionKind {
    Authorize,
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2RemotePreflightOperatorDecision {
    pub profile: String,
    pub decision_uuid: String,
    pub ceremony_uuid: String,
    pub proposal_sha256: String,
    pub operator_principal: String,
    pub operator_role: String,
    pub subject: String,
    pub decision_nonce: String,
    pub decision: Evox2RemotePreflightOperatorDecisionKind,
    pub issued_at_ms: u64,
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
    pub maximum_attempts: u8,
    pub maximum_permits: u8,
    pub maximum_processes: u8,
    pub retry_count: u8,
    pub verifying_key_hex: String,
    pub signature_hex: String,
    pub fixture_only: bool,
    pub decision_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2RemotePreflightDecisionCorrespondence {
    pub profile: String,
    pub ceremony_uuid: String,
    pub proposal_sha256: String,
    pub decision_sha256: String,
    pub decision: Evox2RemotePreflightOperatorDecisionKind,
    pub observed_time_ms: u64,
    pub signature_correspondence: bool,
    pub within_supplied_interval: bool,
    pub exact_scope: bool,
    pub status: String,
    pub authority: String,
    pub live_authorization_admitted: bool,
    pub permit_mint_authorized: bool,
    pub runner_invocation_authorized: bool,
    pub fixture_only: bool,
    pub effect_account: Evox2RemotePreflightActivationEffectAccount,
    pub correspondence_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evox2RemotePreflightActivationFaultCode {
    Bound,
    MachineForm,
    Identity,
    Lineage,
    Plan,
    Stage,
    Decision,
    Signature,
    Time,
    Authority,
    Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evox2RemotePreflightActivationFault {
    pub code: Evox2RemotePreflightActivationFaultCode,
    pub detail: String,
}

impl fmt::Display for Evox2RemotePreflightActivationFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Evox2RemotePreflightActivationFault {}

pub fn canonical_evox2_remote_preflight_activation_request()
-> Result<Evox2RemotePreflightActivationRequest, Evox2RemotePreflightActivationFault> {
    let mut request = Evox2RemotePreflightActivationRequest {
        profile: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_REQUEST_PROFILE.to_owned(),
        ceremony_uuid: "64b58794-a740-438e-b505-e62584d0050d".to_owned(),
        source_snapshot_uuid: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_CANONICAL_UUID.to_owned(),
        signature_uuid: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_SIGNATURE_UUID.to_owned(),
        formation_commit: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_FORMATION_COMMIT.to_owned(),
        formation_bookend: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_FORMATION_BOOKEND.to_owned(),
        runner_implementation_commit: EVOX2_REMOTE_PREFLIGHT_RUNNER_IMPLEMENTATION_COMMIT
            .to_owned(),
        runner_bookend_commit: EVOX2_REMOTE_PREFLIGHT_RUNNER_BOOKEND_COMMIT.to_owned(),
        producer_implementation_commit: EVOX2_REMOTE_PREFLIGHT_PRODUCER_IMPLEMENTATION_COMMIT
            .to_owned(),
        producer_bookend_commit: EVOX2_REMOTE_PREFLIGHT_PRODUCER_BOOKEND_COMMIT.to_owned(),
        operator_principal: EXACT_PRINCIPAL.to_owned(),
        operator_role: EXACT_ROLE.to_owned(),
        subject: EXACT_SUBJECT.to_owned(),
        decision_nonce: "88d35019-b4b5-4c9e-ac61-d3a4678c13ab".to_owned(),
        decision_not_before_ms: 1_789_156_800_000,
        decision_expires_at_ms: 1_789_160_400_000,
        fixture_only: true,
        request_sha256: String::new(),
    };
    request.request_sha256 = activation_request_digest(&request)?;
    validate_activation_request(&request)?;
    Ok(request)
}

pub fn compile_evox2_remote_preflight_activation_proposal(
    request: &Evox2RemotePreflightActivationRequest,
    controller_request: &Evox2ScratchBuildControllerRequest,
    controller_plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
) -> Result<Evox2RemotePreflightActivationProposal, Evox2RemotePreflightActivationFault> {
    validate_activation_request(request)?;
    verify_upstream(controller_request, controller_plan, program, producer_plan)?;
    let mut proposal = Evox2RemotePreflightActivationProposal {
        profile: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_PROPOSAL_PROFILE.to_owned(),
        ceremony_uuid: request.ceremony_uuid.clone(),
        request_sha256: request.request_sha256.clone(),
        canonical_uuid: request.canonical_uuid.clone(),
        formation_commit: request.formation_commit.clone(),
        formation_bookend: request.formation_bookend.clone(),
        runner_implementation_commit: request.runner_implementation_commit.clone(),
        runner_bookend_commit: request.runner_bookend_commit.clone(),
        producer_implementation_commit: request.producer_implementation_commit.clone(),
        producer_bookend_commit: request.producer_bookend_commit.clone(),
        controller_request_sha256: controller_request.request_sha256.clone(),
        controller_plan_sha256: controller_plan.plan_sha256.clone(),
        controller_program_sha256: program.program_sha256.clone(),
        producer_plan_sha256: producer_plan.producer_plan_sha256.clone(),
        executable_path: producer_plan.executable_path.clone(),
        executable_sha256: producer_plan.executable_sha256.clone(),
        target_host: producer_plan.target_host.clone(),
        ssh_host: producer_plan.ssh_host.clone(),
        argument_atoms: producer_plan.argument_atoms.clone(),
        argument_count: producer_plan.argument_count,
        timeout_millis: producer_plan.timeout_ms,
        maximum_stdout_bytes: producer_plan.stdout_limit_bytes,
        maximum_stderr_bytes: producer_plan.stderr_limit_bytes,
        maximum_attempts: 1,
        maximum_permits: 1,
        maximum_active_processes: 1,
        maximum_total_processes: 1,
        retry_count: 0,
        operator_principal: request.operator_principal.clone(),
        operator_role: request.operator_role.clone(),
        subject: request.subject.clone(),
        decision_nonce: request.decision_nonce.clone(),
        decision_not_before_ms: request.decision_not_before_ms,
        decision_expires_at_ms: request.decision_expires_at_ms,
        roles: expected_roles(),
        stages: expected_stages(),
        status: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_STATUS.to_owned(),
        authority: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_AUTHORITY.to_owned(),
        live_authorization_admitted: false,
        permit_mint_authorized: false,
        runner_invocation_authorized: false,
        fixture_only: request.fixture_only,
        effect_account: Evox2RemotePreflightActivationEffectAccount::default(),
        proposal_sha256: String::new(),
    };
    proposal.proposal_sha256 = activation_proposal_digest(&proposal)?;
    validate_activation_proposal(
        request,
        controller_request,
        controller_plan,
        program,
        producer_plan,
        &proposal,
    )?;
    Ok(proposal)
}

pub fn verify_evox2_remote_preflight_activation_proposal(
    request: &Evox2RemotePreflightActivationRequest,
    controller_request: &Evox2ScratchBuildControllerRequest,
    controller_plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
    proposal: &Evox2RemotePreflightActivationProposal,
) -> Result<Evox2RemotePreflightActivationProposalVerification, Evox2RemotePreflightActivationFault>
{
    validate_activation_proposal(
        request,
        controller_request,
        controller_plan,
        program,
        producer_plan,
        proposal,
    )?;
    let first = compile_evox2_remote_preflight_activation_proposal(
        request,
        controller_request,
        controller_plan,
        program,
        producer_plan,
    )?;
    let second = compile_evox2_remote_preflight_activation_proposal(
        request,
        controller_request,
        controller_plan,
        program,
        producer_plan,
    )?;
    if proposal != &first || first != second {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::Digest,
            "activation proposal deterministic replay differs",
        ));
    }
    let mut verification = Evox2RemotePreflightActivationProposalVerification {
        profile: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_PROPOSAL_VERIFICATION_PROFILE.to_owned(),
        ceremony_uuid: proposal.ceremony_uuid.clone(),
        request_sha256: request.request_sha256.clone(),
        proposal_sha256: proposal.proposal_sha256.clone(),
        producer_plan_sha256: producer_plan.producer_plan_sha256.clone(),
        deterministic_replay_count: 2,
        byte_identical: true,
        role_count: 8,
        stage_count: 8,
        argument_count: 19,
        maximum_attempts: 1,
        maximum_permits: 1,
        maximum_processes: 1,
        retry_count: 0,
        status: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_STATUS.to_owned(),
        authority: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_AUTHORITY.to_owned(),
        live_authorization_admitted: false,
        permit_mint_authorized: false,
        runner_invocation_authorized: false,
        fixture_only: request.fixture_only,
        effect_account: Evox2RemotePreflightActivationEffectAccount::default(),
        proposal_verification_sha256: String::new(),
    };
    verification.proposal_verification_sha256 = proposal_verification_digest(&verification)?;
    validate_proposal_verification(request, proposal, producer_plan, &verification)?;
    Ok(verification)
}

pub fn seal_evox2_remote_preflight_operator_decision_digest(
    mut decision: Evox2RemotePreflightOperatorDecision,
) -> Result<Evox2RemotePreflightOperatorDecision, Evox2RemotePreflightActivationFault> {
    decision.decision_sha256.clear();
    decision.decision_sha256 = operator_decision_digest(&decision)?;
    Ok(decision)
}

pub fn evox2_remote_preflight_operator_decision_signing_bytes(
    decision: &Evox2RemotePreflightOperatorDecision,
) -> Result<Vec<u8>, Evox2RemotePreflightActivationFault> {
    let mut normalized = decision.clone();
    normalized.signature_hex.clear();
    normalized.decision_sha256.clear();
    domain_bytes(DECISION_SIGNING_DOMAIN, &normalized)
}

pub fn verify_evox2_remote_preflight_operator_decision_correspondence(
    proposal: &Evox2RemotePreflightActivationProposal,
    decision: &Evox2RemotePreflightOperatorDecision,
    observed_time_ms: u64,
) -> Result<Evox2RemotePreflightDecisionCorrespondence, Evox2RemotePreflightActivationFault> {
    validate_operator_decision(proposal, decision, observed_time_ms)?;
    let mut correspondence = Evox2RemotePreflightDecisionCorrespondence {
        profile: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_DECISION_CORRESPONDENCE_PROFILE.to_owned(),
        ceremony_uuid: proposal.ceremony_uuid.clone(),
        proposal_sha256: proposal.proposal_sha256.clone(),
        decision_sha256: decision.decision_sha256.clone(),
        decision: decision.decision,
        observed_time_ms,
        signature_correspondence: true,
        within_supplied_interval: true,
        exact_scope: true,
        status: "decision_cryptographic_correspondence_verified_live_authority_external".to_owned(),
        authority: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_AUTHORITY.to_owned(),
        live_authorization_admitted: false,
        permit_mint_authorized: false,
        runner_invocation_authorized: false,
        fixture_only: decision.fixture_only,
        effect_account: Evox2RemotePreflightActivationEffectAccount::default(),
        correspondence_sha256: String::new(),
    };
    correspondence.correspondence_sha256 = decision_correspondence_digest(&correspondence)?;
    validate_decision_correspondence(proposal, decision, &correspondence)?;
    Ok(correspondence)
}

pub fn validate_activation_request(
    request: &Evox2RemotePreflightActivationRequest,
) -> Result<(), Evox2RemotePreflightActivationFault> {
    if request.profile != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_REQUEST_PROFILE
        || request.source_snapshot_uuid != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_SOURCE_SNAPSHOT_UUID
        || request.canonical_uuid != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_CANONICAL_UUID
        || request.signature_uuid != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_SIGNATURE_UUID
        || request.formation_commit != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_FORMATION_COMMIT
        || request.formation_bookend != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_FORMATION_BOOKEND
        || request.runner_implementation_commit
            != EVOX2_REMOTE_PREFLIGHT_RUNNER_IMPLEMENTATION_COMMIT
        || request.runner_bookend_commit != EVOX2_REMOTE_PREFLIGHT_RUNNER_BOOKEND_COMMIT
        || request.producer_implementation_commit
            != EVOX2_REMOTE_PREFLIGHT_PRODUCER_IMPLEMENTATION_COMMIT
        || request.producer_bookend_commit != EVOX2_REMOTE_PREFLIGHT_PRODUCER_BOOKEND_COMMIT
        || request.operator_principal != EXACT_PRINCIPAL
        || request.operator_role != EXACT_ROLE
        || request.subject != EXACT_SUBJECT
        || !is_lower_uuid(&request.ceremony_uuid)
        || !is_lower_uuid(&request.decision_nonce)
        || request.decision_not_before_ms >= request.decision_expires_at_ms
    {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::Identity,
            "activation request identity or decision window differs",
        ));
    }
    if request.request_sha256 != activation_request_digest(request)? {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::Digest,
            "activation request digest differs",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn validate_activation_proposal(
    request: &Evox2RemotePreflightActivationRequest,
    controller_request: &Evox2ScratchBuildControllerRequest,
    controller_plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
    proposal: &Evox2RemotePreflightActivationProposal,
) -> Result<(), Evox2RemotePreflightActivationFault> {
    validate_activation_request(request)?;
    verify_upstream(controller_request, controller_plan, program, producer_plan)?;
    let mut expected = proposal.clone();
    expected.proposal_sha256.clear();
    let rebuilt = compile_proposal_without_validation(
        request,
        controller_request,
        controller_plan,
        program,
        producer_plan,
    );
    let mut rebuilt_normalized = rebuilt.clone();
    rebuilt_normalized.proposal_sha256.clear();
    if expected != rebuilt_normalized
        || proposal.proposal_sha256 != activation_proposal_digest(proposal)?
    {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::Plan,
            "activation proposal correspondence differs",
        ));
    }
    Ok(())
}

fn compile_proposal_without_validation(
    request: &Evox2RemotePreflightActivationRequest,
    controller_request: &Evox2ScratchBuildControllerRequest,
    controller_plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
) -> Evox2RemotePreflightActivationProposal {
    Evox2RemotePreflightActivationProposal {
        profile: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_PROPOSAL_PROFILE.to_owned(),
        ceremony_uuid: request.ceremony_uuid.clone(),
        request_sha256: request.request_sha256.clone(),
        canonical_uuid: request.canonical_uuid.clone(),
        formation_commit: request.formation_commit.clone(),
        formation_bookend: request.formation_bookend.clone(),
        runner_implementation_commit: request.runner_implementation_commit.clone(),
        runner_bookend_commit: request.runner_bookend_commit.clone(),
        producer_implementation_commit: request.producer_implementation_commit.clone(),
        producer_bookend_commit: request.producer_bookend_commit.clone(),
        controller_request_sha256: controller_request.request_sha256.clone(),
        controller_plan_sha256: controller_plan.plan_sha256.clone(),
        controller_program_sha256: program.program_sha256.clone(),
        producer_plan_sha256: producer_plan.producer_plan_sha256.clone(),
        executable_path: producer_plan.executable_path.clone(),
        executable_sha256: producer_plan.executable_sha256.clone(),
        target_host: producer_plan.target_host.clone(),
        ssh_host: producer_plan.ssh_host.clone(),
        argument_atoms: producer_plan.argument_atoms.clone(),
        argument_count: producer_plan.argument_count,
        timeout_millis: producer_plan.timeout_ms,
        maximum_stdout_bytes: producer_plan.stdout_limit_bytes,
        maximum_stderr_bytes: producer_plan.stderr_limit_bytes,
        maximum_attempts: 1,
        maximum_permits: 1,
        maximum_active_processes: 1,
        maximum_total_processes: 1,
        retry_count: 0,
        operator_principal: request.operator_principal.clone(),
        operator_role: request.operator_role.clone(),
        subject: request.subject.clone(),
        decision_nonce: request.decision_nonce.clone(),
        decision_not_before_ms: request.decision_not_before_ms,
        decision_expires_at_ms: request.decision_expires_at_ms,
        roles: expected_roles(),
        stages: expected_stages(),
        status: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_STATUS.to_owned(),
        authority: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_AUTHORITY.to_owned(),
        live_authorization_admitted: false,
        permit_mint_authorized: false,
        runner_invocation_authorized: false,
        fixture_only: request.fixture_only,
        effect_account: Evox2RemotePreflightActivationEffectAccount::default(),
        proposal_sha256: String::new(),
    }
}

fn validate_operator_decision(
    proposal: &Evox2RemotePreflightActivationProposal,
    decision: &Evox2RemotePreflightOperatorDecision,
    observed_time_ms: u64,
) -> Result<(), Evox2RemotePreflightActivationFault> {
    if decision.profile != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_DECISION_PROFILE
        || !is_lower_uuid(&decision.decision_uuid)
        || decision.ceremony_uuid != proposal.ceremony_uuid
        || decision.proposal_sha256 != proposal.proposal_sha256
        || decision.operator_principal != proposal.operator_principal
        || decision.operator_role != proposal.operator_role
        || decision.subject != proposal.subject
        || decision.decision_nonce != proposal.decision_nonce
        || decision.not_before_ms != proposal.decision_not_before_ms
        || decision.expires_at_ms != proposal.decision_expires_at_ms
        || decision.issued_at_ms < decision.not_before_ms
        || decision.issued_at_ms > decision.expires_at_ms
        || decision.maximum_attempts != 1
        || decision.maximum_permits != 1
        || decision.maximum_processes != 1
        || decision.retry_count != 0
        || decision.fixture_only != proposal.fixture_only
    {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::Decision,
            "operator decision scope or ceilings differ",
        ));
    }
    if observed_time_ms < decision.not_before_ms || observed_time_ms > decision.expires_at_ms {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::Time,
            "supplied observation is outside decision interval",
        ));
    }
    if decision.decision_sha256 != operator_decision_digest(decision)? {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::Digest,
            "operator decision digest differs",
        ));
    }
    let key_bytes = parse_exact_hex::<32>(&decision.verifying_key_hex)?;
    let signature_bytes = parse_exact_hex::<64>(&decision.signature_hex)?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
        fault(
            Evox2RemotePreflightActivationFaultCode::Signature,
            "operator decision verifying key refused",
        )
    })?;
    key.verify_strict(
        &evox2_remote_preflight_operator_decision_signing_bytes(decision)?,
        &Signature::from_bytes(&signature_bytes),
    )
    .map_err(|_| {
        fault(
            Evox2RemotePreflightActivationFaultCode::Signature,
            "operator decision signature correspondence refused",
        )
    })?;
    Ok(())
}

fn validate_proposal_verification(
    request: &Evox2RemotePreflightActivationRequest,
    proposal: &Evox2RemotePreflightActivationProposal,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
    verification: &Evox2RemotePreflightActivationProposalVerification,
) -> Result<(), Evox2RemotePreflightActivationFault> {
    if verification.profile != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_PROPOSAL_VERIFICATION_PROFILE
        || verification.ceremony_uuid != proposal.ceremony_uuid
        || verification.request_sha256 != request.request_sha256
        || verification.proposal_sha256 != proposal.proposal_sha256
        || verification.producer_plan_sha256 != producer_plan.producer_plan_sha256
        || verification.deterministic_replay_count != 2
        || !verification.byte_identical
        || verification.role_count != 8
        || verification.stage_count != 8
        || verification.argument_count != 19
        || verification.maximum_attempts != 1
        || verification.maximum_permits != 1
        || verification.maximum_processes != 1
        || verification.retry_count != 0
        || verification.status != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_STATUS
        || verification.authority != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_AUTHORITY
        || verification.live_authorization_admitted
        || verification.permit_mint_authorized
        || verification.runner_invocation_authorized
        || verification.fixture_only != request.fixture_only
        || verification.effect_account != Evox2RemotePreflightActivationEffectAccount::default()
        || verification.proposal_verification_sha256 != proposal_verification_digest(verification)?
    {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::Authority,
            "proposal verification correspondence or nonauthority differs",
        ));
    }
    Ok(())
}

fn validate_decision_correspondence(
    proposal: &Evox2RemotePreflightActivationProposal,
    decision: &Evox2RemotePreflightOperatorDecision,
    correspondence: &Evox2RemotePreflightDecisionCorrespondence,
) -> Result<(), Evox2RemotePreflightActivationFault> {
    if correspondence.profile != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_DECISION_CORRESPONDENCE_PROFILE
        || correspondence.ceremony_uuid != proposal.ceremony_uuid
        || correspondence.proposal_sha256 != proposal.proposal_sha256
        || correspondence.decision_sha256 != decision.decision_sha256
        || correspondence.decision != decision.decision
        || !correspondence.signature_correspondence
        || !correspondence.within_supplied_interval
        || !correspondence.exact_scope
        || correspondence.status
            != "decision_cryptographic_correspondence_verified_live_authority_external"
        || correspondence.authority != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_AUTHORITY
        || correspondence.live_authorization_admitted
        || correspondence.permit_mint_authorized
        || correspondence.runner_invocation_authorized
        || correspondence.fixture_only != decision.fixture_only
        || correspondence.effect_account != Evox2RemotePreflightActivationEffectAccount::default()
        || correspondence.correspondence_sha256 != decision_correspondence_digest(correspondence)?
    {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::Authority,
            "decision correspondence promoted authority or drifted",
        ));
    }
    Ok(())
}

fn verify_upstream(
    controller_request: &Evox2ScratchBuildControllerRequest,
    controller_plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
) -> Result<(), Evox2RemotePreflightActivationFault> {
    verify_evox2_scratch_build_remote_preflight_producer_plan(
        controller_request,
        controller_plan,
        program,
        producer_plan,
    )
    .map_err(|error| {
        fault(
            Evox2RemotePreflightActivationFaultCode::Plan,
            error.to_string(),
        )
    })?;
    if controller_request.request_sha256 != EVOX2_REMOTE_PREFLIGHT_CONTROLLER_REQUEST_SHA256
        || controller_plan.plan_sha256 != EVOX2_REMOTE_PREFLIGHT_CONTROLLER_PLAN_SHA256
        || program.program_sha256 != EVOX2_REMOTE_PREFLIGHT_CONTROLLER_PROGRAM_SHA256
        || producer_plan.executable_path != EXACT_EXECUTABLE
        || producer_plan.target_host != EXACT_TARGET
        || producer_plan.ssh_host != EXACT_SSH_HOST
        || producer_plan.argument_count != 19
        || producer_plan.argument_atoms.len() != 19
        || producer_plan.timeout_ms != 30_000
        || producer_plan.stdout_limit_bytes != 65_536
        || producer_plan.stderr_limit_bytes != 65_536
        || producer_plan.provider_request_limit != 0
        || producer_plan.remote_call_limit != 1
        || producer_plan.effect_limit != 1
        || producer_plan.remote_contact_authorized
    {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::Lineage,
            "published controller or exact process coordinates differ",
        ));
    }
    Ok(())
}

pub fn activation_request_digest(
    request: &Evox2RemotePreflightActivationRequest,
) -> Result<String, Evox2RemotePreflightActivationFault> {
    let mut normalized = request.clone();
    normalized.request_sha256.clear();
    domain_digest(REQUEST_DOMAIN, &normalized)
}

pub fn activation_proposal_digest(
    proposal: &Evox2RemotePreflightActivationProposal,
) -> Result<String, Evox2RemotePreflightActivationFault> {
    let mut normalized = proposal.clone();
    normalized.proposal_sha256.clear();
    domain_digest(PROPOSAL_DOMAIN, &normalized)
}

pub fn proposal_verification_digest(
    verification: &Evox2RemotePreflightActivationProposalVerification,
) -> Result<String, Evox2RemotePreflightActivationFault> {
    let mut normalized = verification.clone();
    normalized.proposal_verification_sha256.clear();
    domain_digest(PROPOSAL_VERIFICATION_DOMAIN, &normalized)
}

pub fn operator_decision_digest(
    decision: &Evox2RemotePreflightOperatorDecision,
) -> Result<String, Evox2RemotePreflightActivationFault> {
    let mut normalized = decision.clone();
    normalized.decision_sha256.clear();
    domain_digest(DECISION_DOMAIN, &normalized)
}

pub fn decision_correspondence_digest(
    correspondence: &Evox2RemotePreflightDecisionCorrespondence,
) -> Result<String, Evox2RemotePreflightActivationFault> {
    let mut normalized = correspondence.clone();
    normalized.correspondence_sha256.clear();
    domain_digest(CORRESPONDENCE_DOMAIN, &normalized)
}

pub fn to_evox2_remote_preflight_activation_request_machine_form(
    request: &Evox2RemotePreflightActivationRequest,
) -> Result<String, Evox2RemotePreflightActivationFault> {
    validate_activation_request(request)?;
    serde_json::to_string(request).map_err(machine_fault)
}

pub fn from_evox2_remote_preflight_activation_request_machine_form(
    machine_form: &str,
) -> Result<Evox2RemotePreflightActivationRequest, Evox2RemotePreflightActivationFault> {
    let request = parse_canonical(machine_form)?;
    validate_activation_request(&request)?;
    Ok(request)
}

pub fn to_evox2_remote_preflight_activation_proposal_machine_form(
    proposal: &Evox2RemotePreflightActivationProposal,
) -> Result<String, Evox2RemotePreflightActivationFault> {
    if proposal.proposal_sha256 != activation_proposal_digest(proposal)? {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::Digest,
            "activation proposal digest differs",
        ));
    }
    serde_json::to_string(proposal).map_err(machine_fault)
}

pub fn from_evox2_remote_preflight_activation_proposal_machine_form(
    machine_form: &str,
) -> Result<Evox2RemotePreflightActivationProposal, Evox2RemotePreflightActivationFault> {
    let proposal: Evox2RemotePreflightActivationProposal = parse_canonical(machine_form)?;
    if proposal.proposal_sha256 != activation_proposal_digest(&proposal)? {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::Digest,
            "activation proposal digest differs",
        ));
    }
    Ok(proposal)
}

pub fn to_evox2_remote_preflight_activation_proposal_verification_machine_form(
    verification: &Evox2RemotePreflightActivationProposalVerification,
) -> Result<String, Evox2RemotePreflightActivationFault> {
    if verification.proposal_verification_sha256 != proposal_verification_digest(verification)? {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::Digest,
            "activation proposal verification digest differs",
        ));
    }
    serde_json::to_string(verification).map_err(machine_fault)
}

pub fn from_evox2_remote_preflight_activation_proposal_verification_machine_form(
    machine_form: &str,
) -> Result<Evox2RemotePreflightActivationProposalVerification, Evox2RemotePreflightActivationFault>
{
    let verification: Evox2RemotePreflightActivationProposalVerification =
        parse_canonical(machine_form)?;
    if verification.proposal_verification_sha256 != proposal_verification_digest(&verification)? {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::Digest,
            "activation proposal verification digest differs",
        ));
    }
    Ok(verification)
}

pub fn to_evox2_remote_preflight_operator_decision_machine_form(
    decision: &Evox2RemotePreflightOperatorDecision,
) -> Result<String, Evox2RemotePreflightActivationFault> {
    if decision.decision_sha256 != operator_decision_digest(decision)? {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::Digest,
            "operator decision digest differs",
        ));
    }
    serde_json::to_string(decision).map_err(machine_fault)
}

pub fn from_evox2_remote_preflight_operator_decision_machine_form(
    machine_form: &str,
) -> Result<Evox2RemotePreflightOperatorDecision, Evox2RemotePreflightActivationFault> {
    let decision: Evox2RemotePreflightOperatorDecision = parse_canonical(machine_form)?;
    if decision.decision_sha256 != operator_decision_digest(&decision)? {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::Digest,
            "operator decision digest differs",
        ));
    }
    Ok(decision)
}

pub fn to_evox2_remote_preflight_decision_correspondence_machine_form(
    correspondence: &Evox2RemotePreflightDecisionCorrespondence,
) -> Result<String, Evox2RemotePreflightActivationFault> {
    if correspondence.correspondence_sha256 != decision_correspondence_digest(correspondence)? {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::Digest,
            "decision correspondence digest differs",
        ));
    }
    serde_json::to_string(correspondence).map_err(machine_fault)
}

fn expected_roles() -> Vec<Evox2RemotePreflightActivationRoleKind> {
    use Evox2RemotePreflightActivationRoleKind as Role;
    vec![
        Role::ProposalCompiler,
        Role::PublicationVerifier,
        Role::OperatorPrincipal,
        Role::DecisionVerifier,
        Role::PermitIssuer,
        Role::RunnerExecutor,
        Role::ReceiptVerifier,
        Role::TerminalRecorder,
    ]
}

fn expected_stages() -> Vec<Evox2RemotePreflightActivationStage> {
    use Evox2RemotePreflightActivationRoleKind as Role;
    use Evox2RemotePreflightActivationStageKind as Stage;
    let values = [
        (Stage::CompileProposal, Role::ProposalCompiler, false),
        (Stage::VerifyPublication, Role::PublicationVerifier, false),
        (Stage::SupplyDecision, Role::OperatorPrincipal, false),
        (Stage::AdmitDecision, Role::DecisionVerifier, false),
        (Stage::MintPermit, Role::PermitIssuer, false),
        (Stage::ConsumeAndInvoke, Role::RunnerExecutor, true),
        (Stage::VerifyReceipt, Role::ReceiptVerifier, false),
        (Stage::CloseTerminal, Role::TerminalRecorder, false),
    ];
    values
        .into_iter()
        .enumerate()
        .map(
            |(index, (kind, responsible_role, effectful))| Evox2RemotePreflightActivationStage {
                sequence: (index + 1) as u8,
                kind,
                predecessor_sequence: (index != 0).then_some(index as u8),
                responsible_role,
                effectful,
                executed: false,
                terminal_on_refusal: true,
            },
        )
        .collect()
}

fn parse_canonical<T: DeserializeOwned + Serialize>(
    machine_form: &str,
) -> Result<T, Evox2RemotePreflightActivationFault> {
    if machine_form.is_empty()
        || machine_form.len() > EVOX2_REMOTE_PREFLIGHT_ACTIVATION_MAX_MACHINE_BYTES
    {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::Bound,
            "machine form byte bound differs",
        ));
    }
    let value: Value = serde_json::from_str(machine_form).map_err(machine_fault)?;
    let mut fields = 0_usize;
    measure_value(&value, 1, &mut fields)?;
    let parsed: T = serde_json::from_str(machine_form).map_err(machine_fault)?;
    if serde_json::to_string(&parsed).map_err(machine_fault)? != machine_form {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::MachineForm,
            "machine form is not canonical duplicate-free JSON",
        ));
    }
    Ok(parsed)
}

fn measure_value(
    value: &Value,
    depth: usize,
    fields: &mut usize,
) -> Result<(), Evox2RemotePreflightActivationFault> {
    if depth > MAX_JSON_DEPTH {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::Bound,
            "JSON depth exceeds bound",
        ));
    }
    match value {
        Value::Object(map) => {
            *fields = fields.checked_add(map.len()).ok_or_else(|| {
                fault(
                    Evox2RemotePreflightActivationFaultCode::Bound,
                    "JSON field count overflowed",
                )
            })?;
            if *fields > MAX_JSON_FIELDS {
                return Err(fault(
                    Evox2RemotePreflightActivationFaultCode::Bound,
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

fn domain_bytes<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<Vec<u8>, Evox2RemotePreflightActivationFault> {
    let payload = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + payload.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn domain_digest<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<String, Evox2RemotePreflightActivationFault> {
    let bytes = domain_bytes(domain, value)?;
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(output)
}

fn parse_exact_hex<const N: usize>(
    value: &str,
) -> Result<[u8; N], Evox2RemotePreflightActivationFault> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(fault(
            Evox2RemotePreflightActivationFaultCode::Signature,
            "lowercase hexadecimal form differs",
        ));
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| {
            fault(
                Evox2RemotePreflightActivationFaultCode::Signature,
                "hexadecimal value refused",
            )
        })?;
    }
    Ok(output)
}

fn is_lower_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
        && value != "00000000-0000-0000-0000-000000000000"
}

fn fault(
    code: Evox2RemotePreflightActivationFaultCode,
    detail: impl Into<String>,
) -> Evox2RemotePreflightActivationFault {
    Evox2RemotePreflightActivationFault {
        code,
        detail: detail.into(),
    }
}

fn machine_fault(error: impl fmt::Display) -> Evox2RemotePreflightActivationFault {
    fault(
        Evox2RemotePreflightActivationFaultCode::MachineForm,
        error.to_string(),
    )
}
