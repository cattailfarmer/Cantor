//! Provider-free, host-free effect-wrapper and live-evidence correspondence.
//!
//! This module compiles the published deployment plan into closed executor
//! roles and verifies supplied preflight, refusal, retrieval, and receipt
//! evidence. It performs no filesystem, process, environment, clock, network,
//! provider, model, SSH, SCP, Cargo, Git, or remote-host operation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    Evox2ScratchBuildCommission, Evox2ScratchBuildControllerPlan,
    Evox2ScratchBuildControllerRequest, Evox2ScratchBuildReceipt,
    Evox2ScratchBuildReceiptVerification, build_evox2_scratch_build_receipt_verification,
    from_evox2_scratch_build_commission_machine_form,
    from_evox2_scratch_build_receipt_machine_form,
    to_evox2_scratch_build_receipt_verification_machine_form,
    verify_evox2_scratch_build_controller_plan,
};

pub const EVOX2_SCRATCH_BUILD_EFFECT_PROGRAM_PROFILE: &str =
    "cantor-evox2-scratch-build-deployment-effect-program/0.1";
pub const EVOX2_SCRATCH_BUILD_PREFLIGHT_PROFILE: &str =
    "cantor-evox2-scratch-build-controller-preflight/0.1";
pub const EVOX2_SCRATCH_BUILD_OPERATIONAL_REFUSAL_PROFILE: &str =
    "cantor-evox2-scratch-build-controller-operational-refusal/0.1";
pub const EVOX2_SCRATCH_BUILD_RETRIEVAL_INVENTORY_PROFILE: &str =
    "cantor-evox2-scratch-build-retrieval-inventory/0.1";
pub const EVOX2_SCRATCH_BUILD_LIVE_EVIDENCE_VERIFICATION_PROFILE: &str =
    "cantor-evox2-scratch-build-live-evidence-verification/0.1";
pub const EVOX2_SCRATCH_BUILD_EFFECT_OBSERVATION_PROFILE: &str =
    "cantor-evox2-scratch-build-effect-observation/0.1";
pub const EVOX2_SCRATCH_BUILD_EFFECT_STATE_PROFILE: &str =
    "cantor-evox2-scratch-build-effect-state/0.1";

const EFFECT_PROGRAM_DIGEST_DOMAIN: &str =
    "cantor-evox2-scratch-build-deployment-effect-program-v1";
const PREFLIGHT_DIGEST_DOMAIN: &str = "cantor-evox2-scratch-build-controller-preflight-v1";
const OPERATIONAL_REFUSAL_DIGEST_DOMAIN: &str =
    "cantor-evox2-scratch-build-controller-operational-refusal-v1";
const RETRIEVAL_INVENTORY_DIGEST_DOMAIN: &str = "cantor-evox2-scratch-build-retrieval-inventory-v1";
const EFFECT_OBSERVATION_DIGEST_DOMAIN: &str = "cantor-evox2-scratch-build-effect-observation-v1";
const EFFECT_STATE_DIGEST_DOMAIN: &str = "cantor-evox2-scratch-build-effect-state-v1";
const MAXIMUM_MACHINE_BYTES: usize = 1_048_576;
const MAXIMUM_RETRIEVED_BYTES: u64 = 4_194_304;
const RETRIEVED_PATHS: [&str; 5] = [
    "commission.json",
    "controller_preflight.json",
    "receipt.json",
    "receipt_verification.json",
    "remote_run.json",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildEffectStage {
    pub ordinal: u32,
    pub kind: String,
    pub executor_role: String,
    pub required_authority: String,
    pub effectful: bool,
    pub stop_on_failure: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildEffectProgram {
    pub profile: String,
    pub run_uuid: String,
    pub canonical_uuid: String,
    pub request_sha256: String,
    pub plan_sha256: String,
    pub controller_implementation_commit: String,
    pub controller_publication_bookend_commit: String,
    pub package_set_sha256: String,
    pub stages: Vec<Evox2ScratchBuildEffectStage>,
    pub stage_count: u32,
    pub authority_disposition: String,
    pub execution_authorized: bool,
    pub remote_contact_authorized: bool,
    pub provider_requests: u32,
    pub remote_calls: u32,
    pub effects: u32,
    pub program_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildEffectObservation {
    pub profile: String,
    pub program_sha256: String,
    pub ordinal: u32,
    pub kind: String,
    pub status: String,
    pub observation_source: String,
    pub effect_performed: bool,
    pub remote_calls: u32,
    pub effects: u32,
    pub evidence_sha256: String,
    pub observation_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildEffectState {
    pub profile: String,
    pub program_sha256: String,
    pub next_stage_ordinal: u32,
    pub completed_stage_count: u32,
    pub observation_sha256s: Vec<String>,
    pub status: String,
    pub disposition: String,
    pub evidence_is_fixture: bool,
    pub remote_calls: u32,
    pub effects: u32,
    pub state_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildRemotePreflight {
    pub profile: String,
    pub run_uuid: String,
    pub request_sha256: String,
    pub plan_sha256: String,
    pub program_sha256: String,
    pub target_host: String,
    pub status: String,
    pub reason: String,
    pub provider_status: String,
    pub observation_source: String,
    pub commission_admitted: bool,
    pub receipt_expected: bool,
    pub remote_contact_made: bool,
    pub provider_requests: u32,
    pub remote_calls: u32,
    pub effects: u32,
    pub preflight_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildOperationalRefusal {
    pub profile: String,
    pub run_uuid: String,
    pub request_sha256: String,
    pub plan_sha256: String,
    pub program_sha256: String,
    pub preflight_sha256: String,
    pub disposition: String,
    pub reason: String,
    pub commission_admitted: bool,
    pub receipt_present: bool,
    pub retrieved_artifact_count: u32,
    pub provider_requests: u32,
    pub remote_calls: u32,
    pub effects: u32,
    pub refusal_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildRetrievedArtifact {
    pub relative_path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildRetrievalInventory {
    pub profile: String,
    pub run_uuid: String,
    pub request_sha256: String,
    pub plan_sha256: String,
    pub program_sha256: String,
    pub preflight_sha256: String,
    pub outcome: String,
    pub artifacts: Vec<Evox2ScratchBuildRetrievedArtifact>,
    pub artifact_count: u32,
    pub aggregate_bytes: u64,
    pub inventory_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildLiveEvidenceVerification {
    pub profile: String,
    pub status: String,
    pub branch: String,
    pub run_uuid: String,
    pub request_sha256: String,
    pub plan_sha256: String,
    pub program_sha256: String,
    pub preflight_sha256: String,
    pub refusal_sha256: String,
    pub inventory_sha256: String,
    pub commission_sha256: String,
    pub receipt_sha256: String,
    pub disposition: String,
    pub operation_record_count: u32,
    pub physical_build_performed: bool,
    pub protected_state_unchanged: bool,
    pub provider_state_unchanged: bool,
    pub persistent_executor_process_count: u32,
    pub retrieved_artifact_count: u32,
    pub observation_source: String,
    pub evidence_is_fixture: bool,
    pub provider_requests: u32,
    pub remote_calls: u32,
    pub effects: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evox2ScratchBuildStoppedRemoteRun {
    profile: String,
    status: String,
    target_host: String,
    operation_record_count: u32,
    physical_build_performed: bool,
    receipt: Evox2ScratchBuildReceipt,
    total_duration_ms: u64,
    persistent_processes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evox2ScratchBuildSuccessfulRemoteRun {
    profile: String,
    status: String,
    target_host: String,
    operation_record_count: u32,
    physical_build_performed: bool,
    receipt_sha256: String,
    package_manifest_sha256: String,
    total_duration_ms: u64,
    protected_state_unchanged: bool,
    provider_state_unchanged: bool,
    persistent_processes: u32,
    denied_effects: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum Evox2ScratchBuildRemoteRun {
    Stopped(Box<Evox2ScratchBuildStoppedRemoteRun>),
    Succeeded(Evox2ScratchBuildSuccessfulRemoteRun),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evox2ScratchBuildDeploymentEffectFaultCode {
    InvalidMachineForm,
    InvalidIdentity,
    InvalidDigest,
    InvalidProgram,
    InvalidPreflight,
    InvalidRefusal,
    InvalidInventory,
    InvalidEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evox2ScratchBuildDeploymentEffectFault {
    pub code: Evox2ScratchBuildDeploymentEffectFaultCode,
    pub detail: &'static str,
}

impl fmt::Display for Evox2ScratchBuildDeploymentEffectFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Evox2ScratchBuildDeploymentEffectFault {}

pub fn compile_evox2_scratch_build_effect_program(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
) -> Result<Evox2ScratchBuildEffectProgram, Evox2ScratchBuildDeploymentEffectFault> {
    verify_evox2_scratch_build_controller_plan(request, plan).map_err(|_| {
        fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidProgram,
            "controller plan refused before effect compilation",
        )
    })?;
    let mut program = expected_program(request, plan);
    program.program_sha256 = program_digest(&program)?;
    verify_evox2_scratch_build_effect_program(request, plan, &program)?;
    Ok(program)
}

pub fn initial_evox2_scratch_build_effect_state(
    program: &Evox2ScratchBuildEffectProgram,
) -> Result<Evox2ScratchBuildEffectState, Evox2ScratchBuildDeploymentEffectFault> {
    validate_program_without_controller(program)?;
    seal_effect_state(Evox2ScratchBuildEffectState {
        profile: EVOX2_SCRATCH_BUILD_EFFECT_STATE_PROFILE.to_owned(),
        program_sha256: program.program_sha256.clone(),
        next_stage_ordinal: 1,
        completed_stage_count: 0,
        observation_sha256s: Vec::new(),
        status: "active".to_owned(),
        disposition: "awaiting_stage".to_owned(),
        evidence_is_fixture: false,
        remote_calls: 0,
        effects: 0,
        state_sha256: String::new(),
    })
}

pub fn seal_evox2_scratch_build_effect_observation(
    program: &Evox2ScratchBuildEffectProgram,
    mut observation: Evox2ScratchBuildEffectObservation,
) -> Result<Evox2ScratchBuildEffectObservation, Evox2ScratchBuildDeploymentEffectFault> {
    observation.observation_sha256.clear();
    validate_effect_observation_body(program, &observation)?;
    observation.observation_sha256 = effect_observation_digest(&observation)?;
    validate_evox2_scratch_build_effect_observation(program, &observation)?;
    Ok(observation)
}

pub fn fixed_evox2_scratch_build_effect_observation_fixture(
    program: &Evox2ScratchBuildEffectProgram,
    ordinal: u32,
    status: &str,
    evidence_sha256: &str,
) -> Result<Evox2ScratchBuildEffectObservation, Evox2ScratchBuildDeploymentEffectFault> {
    let stage = program
        .stages
        .get(ordinal.saturating_sub(1) as usize)
        .ok_or_else(|| {
            fault(
                Evox2ScratchBuildDeploymentEffectFaultCode::InvalidProgram,
                "effect observation ordinal differs",
            )
        })?;
    seal_evox2_scratch_build_effect_observation(
        program,
        Evox2ScratchBuildEffectObservation {
            profile: EVOX2_SCRATCH_BUILD_EFFECT_OBSERVATION_PROFILE.to_owned(),
            program_sha256: program.program_sha256.clone(),
            ordinal,
            kind: stage.kind.clone(),
            status: status.to_owned(),
            observation_source: "supplied_provider_free_fixture".to_owned(),
            effect_performed: false,
            remote_calls: 0,
            effects: 0,
            evidence_sha256: evidence_sha256.to_owned(),
            observation_sha256: String::new(),
        },
    )
}

pub fn validate_evox2_scratch_build_effect_observation(
    program: &Evox2ScratchBuildEffectProgram,
    observation: &Evox2ScratchBuildEffectObservation,
) -> Result<(), Evox2ScratchBuildDeploymentEffectFault> {
    validate_effect_observation_body(program, observation)?;
    if observation.observation_sha256 != effect_observation_digest(observation)? {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidDigest,
            "effect observation digest differs",
        ));
    }
    Ok(())
}

pub fn advance_evox2_scratch_build_effect_state(
    program: &Evox2ScratchBuildEffectProgram,
    state: &Evox2ScratchBuildEffectState,
    observation: &Evox2ScratchBuildEffectObservation,
) -> Result<Evox2ScratchBuildEffectState, Evox2ScratchBuildDeploymentEffectFault> {
    validate_evox2_scratch_build_effect_state(program, state)?;
    validate_evox2_scratch_build_effect_observation(program, observation)?;
    if state.status != "active" || observation.ordinal != state.next_stage_ordinal {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidProgram,
            "effect observation is not the next admitted stage",
        ));
    }
    let mut next = state.clone();
    next.state_sha256.clear();
    next.observation_sha256s
        .push(observation.observation_sha256.clone());
    next.remote_calls = next
        .remote_calls
        .checked_add(observation.remote_calls)
        .ok_or_else(|| {
            fault(
                Evox2ScratchBuildDeploymentEffectFaultCode::InvalidProgram,
                "effect remote call count overflowed",
            )
        })?;
    next.effects = next
        .effects
        .checked_add(observation.effects)
        .ok_or_else(|| {
            fault(
                Evox2ScratchBuildDeploymentEffectFaultCode::InvalidProgram,
                "effect count overflowed",
            )
        })?;
    next.evidence_is_fixture |= observation.observation_source == "supplied_provider_free_fixture";
    match observation.status.as_str() {
        "passed" => {
            next.completed_stage_count += 1;
            if observation.ordinal == program.stage_count {
                next.next_stage_ordinal = 0;
                next.status = "completed".to_owned();
                next.disposition = "all_stages_passed".to_owned();
            } else {
                next.next_stage_ordinal += 1;
                next.disposition = "awaiting_stage".to_owned();
            }
        }
        "failed" | "refused" => {
            next.next_stage_ordinal = 0;
            next.status = "stopped".to_owned();
            next.disposition = format!("stage_{}_{}", observation.ordinal, observation.status);
        }
        _ => unreachable!("validated effect observation status"),
    }
    seal_effect_state(next)
}

pub fn validate_evox2_scratch_build_effect_state(
    program: &Evox2ScratchBuildEffectProgram,
    state: &Evox2ScratchBuildEffectState,
) -> Result<(), Evox2ScratchBuildDeploymentEffectFault> {
    validate_program_without_controller(program)?;
    validate_effect_state_body(program, state)?;
    if state.state_sha256 != effect_state_digest(state)? {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidDigest,
            "effect state digest differs",
        ));
    }
    Ok(())
}

pub fn verify_evox2_scratch_build_effect_program(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
) -> Result<(), Evox2ScratchBuildDeploymentEffectFault> {
    verify_evox2_scratch_build_controller_plan(request, plan).map_err(|_| {
        fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidProgram,
            "controller plan refused before effect verification",
        )
    })?;
    let mut expected = expected_program(request, plan);
    expected.program_sha256 = program_digest(&expected)?;
    if program != &expected || program.program_sha256 != program_digest(program)? {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidProgram,
            "effect program correspondence differs",
        ));
    }
    Ok(())
}

pub fn fixed_evox2_scratch_build_preflight_fixture(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    admitted: bool,
) -> Result<Evox2ScratchBuildRemotePreflight, Evox2ScratchBuildDeploymentEffectFault> {
    seal_evox2_scratch_build_remote_preflight(
        request,
        plan,
        program,
        Evox2ScratchBuildRemotePreflight {
            profile: EVOX2_SCRATCH_BUILD_PREFLIGHT_PROFILE.to_owned(),
            run_uuid: request.run_uuid.clone(),
            request_sha256: request.request_sha256.clone(),
            plan_sha256: plan.plan_sha256.clone(),
            program_sha256: program.program_sha256.clone(),
            target_host: request.target_host.clone(),
            status: if admitted { "admitted" } else { "refused" }.to_owned(),
            reason: if admitted {
                "preflight_satisfied"
            } else {
                "provider_unavailable_before_commission"
            }
            .to_owned(),
            provider_status: if admitted { "available" } else { "unavailable" }.to_owned(),
            observation_source: "supplied_provider_free_fixture".to_owned(),
            commission_admitted: admitted,
            receipt_expected: admitted,
            remote_contact_made: false,
            provider_requests: 0,
            remote_calls: 0,
            effects: 0,
            preflight_sha256: String::new(),
        },
    )
}

pub fn seal_evox2_scratch_build_remote_preflight(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    mut preflight: Evox2ScratchBuildRemotePreflight,
) -> Result<Evox2ScratchBuildRemotePreflight, Evox2ScratchBuildDeploymentEffectFault> {
    preflight.preflight_sha256.clear();
    validate_preflight_body(request, plan, program, &preflight)?;
    preflight.preflight_sha256 = preflight_digest(&preflight)?;
    validate_evox2_scratch_build_remote_preflight(request, plan, program, &preflight)?;
    Ok(preflight)
}

pub fn validate_evox2_scratch_build_remote_preflight(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    preflight: &Evox2ScratchBuildRemotePreflight,
) -> Result<(), Evox2ScratchBuildDeploymentEffectFault> {
    validate_preflight_body(request, plan, program, preflight)?;
    if preflight.preflight_sha256 != preflight_digest(preflight)? {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidDigest,
            "preflight digest differs",
        ));
    }
    Ok(())
}

pub fn fixed_evox2_scratch_build_operational_refusal(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    preflight: &Evox2ScratchBuildRemotePreflight,
) -> Result<Evox2ScratchBuildOperationalRefusal, Evox2ScratchBuildDeploymentEffectFault> {
    let mut refusal = Evox2ScratchBuildOperationalRefusal {
        profile: EVOX2_SCRATCH_BUILD_OPERATIONAL_REFUSAL_PROFILE.to_owned(),
        run_uuid: request.run_uuid.clone(),
        request_sha256: request.request_sha256.clone(),
        plan_sha256: plan.plan_sha256.clone(),
        program_sha256: program.program_sha256.clone(),
        preflight_sha256: preflight.preflight_sha256.clone(),
        disposition: "operational_refusal_before_commission_no_receipt".to_owned(),
        reason: "provider_unavailable_before_commission".to_owned(),
        commission_admitted: false,
        receipt_present: false,
        retrieved_artifact_count: 0,
        provider_requests: preflight.provider_requests,
        remote_calls: preflight.remote_calls,
        effects: preflight.effects,
        refusal_sha256: String::new(),
    };
    validate_refusal_body(request, plan, program, preflight, &refusal)?;
    refusal.refusal_sha256 = refusal_digest(&refusal)?;
    validate_evox2_scratch_build_operational_refusal(request, plan, program, preflight, &refusal)?;
    Ok(refusal)
}

pub fn validate_evox2_scratch_build_operational_refusal(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    preflight: &Evox2ScratchBuildRemotePreflight,
    refusal: &Evox2ScratchBuildOperationalRefusal,
) -> Result<(), Evox2ScratchBuildDeploymentEffectFault> {
    validate_refusal_body(request, plan, program, preflight, refusal)?;
    if refusal.refusal_sha256 != refusal_digest(refusal)? {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidDigest,
            "operational refusal digest differs",
        ));
    }
    Ok(())
}

pub fn seal_evox2_scratch_build_retrieval_inventory(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    preflight: &Evox2ScratchBuildRemotePreflight,
    outcome: &str,
    artifacts: Vec<Evox2ScratchBuildRetrievedArtifact>,
) -> Result<Evox2ScratchBuildRetrievalInventory, Evox2ScratchBuildDeploymentEffectFault> {
    let aggregate_bytes = artifacts.iter().try_fold(0_u64, |total, artifact| {
        total.checked_add(artifact.bytes).ok_or_else(|| {
            fault(
                Evox2ScratchBuildDeploymentEffectFaultCode::InvalidInventory,
                "retrieval aggregate overflowed",
            )
        })
    })?;
    let mut inventory = Evox2ScratchBuildRetrievalInventory {
        profile: EVOX2_SCRATCH_BUILD_RETRIEVAL_INVENTORY_PROFILE.to_owned(),
        run_uuid: request.run_uuid.clone(),
        request_sha256: request.request_sha256.clone(),
        plan_sha256: plan.plan_sha256.clone(),
        program_sha256: program.program_sha256.clone(),
        preflight_sha256: preflight.preflight_sha256.clone(),
        outcome: outcome.to_owned(),
        artifact_count: artifacts.len() as u32,
        aggregate_bytes,
        artifacts,
        inventory_sha256: String::new(),
    };
    validate_inventory_body(request, plan, program, preflight, &inventory)?;
    inventory.inventory_sha256 = inventory_digest(&inventory)?;
    validate_evox2_scratch_build_retrieval_inventory(
        request, plan, program, preflight, &inventory,
    )?;
    Ok(inventory)
}

pub fn validate_evox2_scratch_build_retrieval_inventory(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    preflight: &Evox2ScratchBuildRemotePreflight,
    inventory: &Evox2ScratchBuildRetrievalInventory,
) -> Result<(), Evox2ScratchBuildDeploymentEffectFault> {
    validate_inventory_body(request, plan, program, preflight, inventory)?;
    if inventory.inventory_sha256 != inventory_digest(inventory)? {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidDigest,
            "retrieval inventory digest differs",
        ));
    }
    Ok(())
}

pub fn verify_evox2_scratch_build_operational_refusal_evidence(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    preflight: &Evox2ScratchBuildRemotePreflight,
    refusal: &Evox2ScratchBuildOperationalRefusal,
) -> Result<Evox2ScratchBuildLiveEvidenceVerification, Evox2ScratchBuildDeploymentEffectFault> {
    validate_evox2_scratch_build_operational_refusal(request, plan, program, preflight, refusal)?;
    Ok(Evox2ScratchBuildLiveEvidenceVerification {
        profile: EVOX2_SCRATCH_BUILD_LIVE_EVIDENCE_VERIFICATION_PROFILE.to_owned(),
        status: "passed".to_owned(),
        branch: "operational_refusal_before_commission_no_receipt".to_owned(),
        run_uuid: request.run_uuid.clone(),
        request_sha256: request.request_sha256.clone(),
        plan_sha256: plan.plan_sha256.clone(),
        program_sha256: program.program_sha256.clone(),
        preflight_sha256: preflight.preflight_sha256.clone(),
        refusal_sha256: refusal.refusal_sha256.clone(),
        inventory_sha256: String::new(),
        commission_sha256: String::new(),
        receipt_sha256: String::new(),
        disposition: refusal.disposition.clone(),
        operation_record_count: 0,
        physical_build_performed: false,
        protected_state_unchanged: true,
        provider_state_unchanged: true,
        persistent_executor_process_count: 0,
        retrieved_artifact_count: 0,
        observation_source: preflight.observation_source.clone(),
        evidence_is_fixture: preflight.observation_source == "supplied_provider_free_fixture",
        provider_requests: refusal.provider_requests,
        remote_calls: refusal.remote_calls,
        effects: refusal.effects,
    })
}

pub fn verify_evox2_scratch_build_retrieved_receipt_evidence(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    preflight: &Evox2ScratchBuildRemotePreflight,
    inventory: &Evox2ScratchBuildRetrievalInventory,
    supplied: &[(&str, &[u8])],
) -> Result<Evox2ScratchBuildLiveEvidenceVerification, Evox2ScratchBuildDeploymentEffectFault> {
    validate_evox2_scratch_build_retrieval_inventory(request, plan, program, preflight, inventory)?;
    let supplied = verify_supplied_artifacts(inventory, supplied)?;
    let preflight_raw = utf8_artifact(&supplied, "controller_preflight.json")?;
    let parsed_preflight = from_evox2_scratch_build_remote_preflight_machine_form(
        request,
        plan,
        program,
        preflight_raw,
    )?;
    if &parsed_preflight != preflight {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidEvidence,
            "retrieved preflight differs",
        ));
    }
    let commission_raw = utf8_artifact(&supplied, "commission.json")?;
    let commission =
        from_evox2_scratch_build_commission_machine_form(commission_raw).map_err(|_| {
            fault(
                Evox2ScratchBuildDeploymentEffectFaultCode::InvalidEvidence,
                "retrieved commission refused",
            )
        })?;
    validate_commission_request_correspondence(request, &commission)?;
    let receipt_raw = utf8_artifact(&supplied, "receipt.json")?;
    let receipt =
        from_evox2_scratch_build_receipt_machine_form(&commission, receipt_raw).map_err(|_| {
            fault(
                Evox2ScratchBuildDeploymentEffectFaultCode::InvalidEvidence,
                "retrieved receipt refused",
            )
        })?;
    if receipt.disposition != inventory.outcome {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidEvidence,
            "retrieval outcome differs from receipt",
        ));
    }
    let verification_raw = utf8_artifact(&supplied, "receipt_verification.json")?;
    let supplied_verification: Evox2ScratchBuildReceiptVerification =
        strict_deserialize(verification_raw)?;
    let rebuilt_verification =
        build_evox2_scratch_build_receipt_verification(&commission, &receipt).map_err(|_| {
            fault(
                Evox2ScratchBuildDeploymentEffectFaultCode::InvalidEvidence,
                "receipt verification reconstruction refused",
            )
        })?;
    let rebuilt_raw = to_evox2_scratch_build_receipt_verification_machine_form(
        &rebuilt_verification,
    )
    .map_err(|_| {
        fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidEvidence,
            "receipt verification serialization refused",
        )
    })?;
    if supplied_verification != rebuilt_verification || verification_raw != rebuilt_raw {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidEvidence,
            "receipt verification differs",
        ));
    }
    verify_remote_run(utf8_artifact(&supplied, "remote_run.json")?, &receipt)?;
    Ok(live_verification(
        request,
        program,
        preflight,
        inventory,
        &commission,
        &receipt,
        &rebuilt_verification,
    ))
}

pub fn to_evox2_scratch_build_effect_program_machine_form(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
) -> Result<String, Evox2ScratchBuildDeploymentEffectFault> {
    verify_evox2_scratch_build_effect_program(request, plan, program)?;
    serialize_bounded(program)
}

pub fn from_evox2_scratch_build_effect_program_machine_form(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    value: &str,
) -> Result<Evox2ScratchBuildEffectProgram, Evox2ScratchBuildDeploymentEffectFault> {
    let program = strict_deserialize(value)?;
    verify_evox2_scratch_build_effect_program(request, plan, &program)?;
    Ok(program)
}

pub fn to_evox2_scratch_build_remote_preflight_machine_form(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    preflight: &Evox2ScratchBuildRemotePreflight,
) -> Result<String, Evox2ScratchBuildDeploymentEffectFault> {
    validate_evox2_scratch_build_remote_preflight(request, plan, program, preflight)?;
    serialize_bounded(preflight)
}

pub fn from_evox2_scratch_build_remote_preflight_machine_form(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    value: &str,
) -> Result<Evox2ScratchBuildRemotePreflight, Evox2ScratchBuildDeploymentEffectFault> {
    let preflight = strict_deserialize(value)?;
    validate_evox2_scratch_build_remote_preflight(request, plan, program, &preflight)?;
    Ok(preflight)
}

pub fn to_evox2_scratch_build_operational_refusal_machine_form(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    preflight: &Evox2ScratchBuildRemotePreflight,
    refusal: &Evox2ScratchBuildOperationalRefusal,
) -> Result<String, Evox2ScratchBuildDeploymentEffectFault> {
    validate_evox2_scratch_build_operational_refusal(request, plan, program, preflight, refusal)?;
    serialize_bounded(refusal)
}

pub fn from_evox2_scratch_build_operational_refusal_machine_form(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    preflight: &Evox2ScratchBuildRemotePreflight,
    value: &str,
) -> Result<Evox2ScratchBuildOperationalRefusal, Evox2ScratchBuildDeploymentEffectFault> {
    let refusal = strict_deserialize(value)?;
    validate_evox2_scratch_build_operational_refusal(request, plan, program, preflight, &refusal)?;
    Ok(refusal)
}

pub fn to_evox2_scratch_build_retrieval_inventory_machine_form(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    preflight: &Evox2ScratchBuildRemotePreflight,
    inventory: &Evox2ScratchBuildRetrievalInventory,
) -> Result<String, Evox2ScratchBuildDeploymentEffectFault> {
    validate_evox2_scratch_build_retrieval_inventory(request, plan, program, preflight, inventory)?;
    serialize_bounded(inventory)
}

pub fn from_evox2_scratch_build_retrieval_inventory_machine_form(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    preflight: &Evox2ScratchBuildRemotePreflight,
    value: &str,
) -> Result<Evox2ScratchBuildRetrievalInventory, Evox2ScratchBuildDeploymentEffectFault> {
    let inventory = strict_deserialize(value)?;
    validate_evox2_scratch_build_retrieval_inventory(
        request, plan, program, preflight, &inventory,
    )?;
    Ok(inventory)
}

pub fn to_evox2_scratch_build_live_evidence_verification_machine_form(
    value: &Evox2ScratchBuildLiveEvidenceVerification,
) -> Result<String, Evox2ScratchBuildDeploymentEffectFault> {
    validate_live_verification(value)?;
    serialize_bounded(value)
}

pub fn to_evox2_scratch_build_effect_observation_machine_form(
    program: &Evox2ScratchBuildEffectProgram,
    observation: &Evox2ScratchBuildEffectObservation,
) -> Result<String, Evox2ScratchBuildDeploymentEffectFault> {
    validate_evox2_scratch_build_effect_observation(program, observation)?;
    serialize_bounded(observation)
}

pub fn from_evox2_scratch_build_effect_observation_machine_form(
    program: &Evox2ScratchBuildEffectProgram,
    value: &str,
) -> Result<Evox2ScratchBuildEffectObservation, Evox2ScratchBuildDeploymentEffectFault> {
    let observation = strict_deserialize(value)?;
    validate_evox2_scratch_build_effect_observation(program, &observation)?;
    Ok(observation)
}

pub fn to_evox2_scratch_build_effect_state_machine_form(
    program: &Evox2ScratchBuildEffectProgram,
    state: &Evox2ScratchBuildEffectState,
) -> Result<String, Evox2ScratchBuildDeploymentEffectFault> {
    validate_evox2_scratch_build_effect_state(program, state)?;
    serialize_bounded(state)
}

pub fn from_evox2_scratch_build_effect_state_machine_form(
    program: &Evox2ScratchBuildEffectProgram,
    value: &str,
) -> Result<Evox2ScratchBuildEffectState, Evox2ScratchBuildDeploymentEffectFault> {
    let state = strict_deserialize(value)?;
    validate_evox2_scratch_build_effect_state(program, &state)?;
    Ok(state)
}

fn expected_program(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
) -> Evox2ScratchBuildEffectProgram {
    let roles = [
        "local_package_verifier",
        "publication_lineage_verifier",
        "bounded_remote_preflight",
        "bounded_package_transfer",
        "remote_package_verifier",
        "create_new_atomic_service_installer",
        "fixed_profile_host_harness",
        "immutable_evidence_retriever",
        "independent_live_evidence_verifier",
        "transient_transport_cleaner",
    ];
    Evox2ScratchBuildEffectProgram {
        profile: EVOX2_SCRATCH_BUILD_EFFECT_PROGRAM_PROFILE.to_owned(),
        run_uuid: request.run_uuid.clone(),
        canonical_uuid: request.canonical_uuid.clone(),
        request_sha256: request.request_sha256.clone(),
        plan_sha256: plan.plan_sha256.clone(),
        controller_implementation_commit: request.controller_implementation_commit.clone(),
        controller_publication_bookend_commit: request
            .controller_publication_bookend_commit
            .clone(),
        package_set_sha256: request.package_set_sha256.clone(),
        stages: plan
            .stages
            .iter()
            .zip(roles)
            .map(|(stage, role)| Evox2ScratchBuildEffectStage {
                ordinal: stage.ordinal,
                kind: stage.kind.clone(),
                executor_role: role.to_owned(),
                required_authority: stage.required_authority.clone(),
                effectful: stage.effectful,
                stop_on_failure: stage.stop_on_failure,
            })
            .collect(),
        stage_count: plan.stage_count,
        authority_disposition: "compiled_effect_roles_not_live_authority".to_owned(),
        execution_authorized: false,
        remote_contact_authorized: false,
        provider_requests: 0,
        remote_calls: 0,
        effects: 0,
        program_sha256: String::new(),
    }
}

fn validate_program_without_controller(
    program: &Evox2ScratchBuildEffectProgram,
) -> Result<(), Evox2ScratchBuildDeploymentEffectFault> {
    if program.profile != EVOX2_SCRATCH_BUILD_EFFECT_PROGRAM_PROFILE
        || !is_uuid(&program.run_uuid)
        || !is_uuid(&program.canonical_uuid)
        || !is_lower_hex(&program.request_sha256, 64)
        || !is_lower_hex(&program.plan_sha256, 64)
        || !is_lower_hex(&program.controller_implementation_commit, 40)
        || !is_lower_hex(&program.controller_publication_bookend_commit, 40)
        || program.controller_implementation_commit == program.controller_publication_bookend_commit
        || !is_lower_hex(&program.package_set_sha256, 64)
        || program.stage_count != 10
        || program.stages.len() != 10
        || program.authority_disposition != "compiled_effect_roles_not_live_authority"
        || program.execution_authorized
        || program.remote_contact_authorized
        || program.provider_requests != 0
        || program.remote_calls != 0
        || program.effects != 0
        || !is_lower_hex(&program.program_sha256, 64)
        || program.program_sha256 != program_digest(program)?
    {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidProgram,
            "effect program shape differs",
        ));
    }
    let roles = [
        "local_package_verifier",
        "publication_lineage_verifier",
        "bounded_remote_preflight",
        "bounded_package_transfer",
        "remote_package_verifier",
        "create_new_atomic_service_installer",
        "fixed_profile_host_harness",
        "immutable_evidence_retriever",
        "independent_live_evidence_verifier",
        "transient_transport_cleaner",
    ];
    if program
        .stages
        .iter()
        .zip(roles)
        .enumerate()
        .any(|(index, (stage, role))| {
            stage.ordinal != (index + 1) as u32
                || stage.executor_role != role
                || !stage.stop_on_failure
                || stage.effectful != matches!(stage.ordinal, 3..=8 | 10)
        })
    {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidProgram,
            "effect program stage shape differs",
        ));
    }
    Ok(())
}

fn validate_effect_observation_body(
    program: &Evox2ScratchBuildEffectProgram,
    observation: &Evox2ScratchBuildEffectObservation,
) -> Result<(), Evox2ScratchBuildDeploymentEffectFault> {
    validate_program_without_controller(program)?;
    let stage = program
        .stages
        .get(observation.ordinal.saturating_sub(1) as usize)
        .ok_or_else(|| {
            fault(
                Evox2ScratchBuildDeploymentEffectFaultCode::InvalidProgram,
                "effect observation ordinal differs",
            )
        })?;
    if observation.profile != EVOX2_SCRATCH_BUILD_EFFECT_OBSERVATION_PROFILE
        || observation.program_sha256 != program.program_sha256
        || observation.kind != stage.kind
        || !matches!(observation.status.as_str(), "passed" | "failed" | "refused")
        || !is_lower_hex(&observation.evidence_sha256, 64)
    {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidProgram,
            "effect observation identity differs",
        ));
    }
    let boundary_valid = match observation.observation_source.as_str() {
        "supplied_provider_free_fixture" => {
            !observation.effect_performed
                && observation.remote_calls == 0
                && observation.effects == 0
        }
        "live_wrapper_observation" if !stage.effectful => {
            !observation.effect_performed
                && observation.remote_calls == 0
                && observation.effects == 0
        }
        "live_wrapper_observation" => {
            let no_effect_refusal = observation.status == "refused"
                && !observation.effect_performed
                && observation.remote_calls == 0
                && observation.effects == 0;
            let attempted = observation.effect_performed
                && observation.remote_calls <= 1
                && observation.effects == 1;
            no_effect_refusal || attempted
        }
        _ => false,
    };
    if !boundary_valid {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidProgram,
            "effect observation boundary differs",
        ));
    }
    if !observation.observation_sha256.is_empty()
        && !is_lower_hex(&observation.observation_sha256, 64)
    {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidDigest,
            "effect observation digest form differs",
        ));
    }
    Ok(())
}

fn seal_effect_state(
    mut state: Evox2ScratchBuildEffectState,
) -> Result<Evox2ScratchBuildEffectState, Evox2ScratchBuildDeploymentEffectFault> {
    state.state_sha256.clear();
    state.state_sha256 = effect_state_digest(&state)?;
    Ok(state)
}

fn validate_effect_state_body(
    program: &Evox2ScratchBuildEffectProgram,
    state: &Evox2ScratchBuildEffectState,
) -> Result<(), Evox2ScratchBuildDeploymentEffectFault> {
    let observation_count = state.observation_sha256s.len() as u32;
    let status_valid = match state.status.as_str() {
        "active" => {
            state.disposition == "awaiting_stage"
                && state.completed_stage_count < program.stage_count
                && state.next_stage_ordinal == state.completed_stage_count + 1
                && observation_count == state.completed_stage_count
        }
        "completed" => {
            state.disposition == "all_stages_passed"
                && state.completed_stage_count == program.stage_count
                && state.next_stage_ordinal == 0
                && observation_count == program.stage_count
        }
        "stopped" => {
            state.disposition.starts_with("stage_")
                && (state.disposition.ends_with("_failed")
                    || state.disposition.ends_with("_refused"))
                && state.completed_stage_count < program.stage_count
                && state.next_stage_ordinal == 0
                && observation_count == state.completed_stage_count + 1
        }
        _ => false,
    };
    if state.profile != EVOX2_SCRATCH_BUILD_EFFECT_STATE_PROFILE
        || state.program_sha256 != program.program_sha256
        || !status_valid
        || state.remote_calls > 7
        || state.effects > 7
        || state
            .observation_sha256s
            .iter()
            .any(|digest| !is_lower_hex(digest, 64))
        || !is_lower_hex(&state.state_sha256, 64)
    {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidProgram,
            "effect state differs",
        ));
    }
    Ok(())
}

fn validate_preflight_body(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    preflight: &Evox2ScratchBuildRemotePreflight,
) -> Result<(), Evox2ScratchBuildDeploymentEffectFault> {
    verify_evox2_scratch_build_effect_program(request, plan, program)?;
    if preflight.profile != EVOX2_SCRATCH_BUILD_PREFLIGHT_PROFILE
        || preflight.run_uuid != request.run_uuid
        || preflight.request_sha256 != request.request_sha256
        || preflight.plan_sha256 != plan.plan_sha256
        || preflight.program_sha256 != program.program_sha256
        || preflight.target_host != request.target_host
    {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidIdentity,
            "preflight identity differs",
        ));
    }
    let outcome_valid = match preflight.status.as_str() {
        "admitted" => {
            preflight.reason == "preflight_satisfied"
                && preflight.provider_status == "available"
                && preflight.commission_admitted
                && preflight.receipt_expected
        }
        "refused" => {
            preflight.reason == "provider_unavailable_before_commission"
                && preflight.provider_status == "unavailable"
                && !preflight.commission_admitted
                && !preflight.receipt_expected
        }
        _ => false,
    };
    let source_valid = match preflight.observation_source.as_str() {
        "supplied_provider_free_fixture" => {
            !preflight.remote_contact_made
                && preflight.provider_requests == 0
                && preflight.remote_calls == 0
                && preflight.effects == 0
        }
        "live_remote_preflight" => {
            preflight.remote_contact_made
                && preflight.provider_requests == 0
                && preflight.remote_calls == 1
                && preflight.effects == 1
        }
        _ => false,
    };
    if !outcome_valid || !source_valid {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidPreflight,
            "preflight outcome or observation boundary differs",
        ));
    }
    if !preflight.preflight_sha256.is_empty() && !is_lower_hex(&preflight.preflight_sha256, 64) {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidDigest,
            "preflight digest form differs",
        ));
    }
    Ok(())
}

fn validate_refusal_body(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    preflight: &Evox2ScratchBuildRemotePreflight,
    refusal: &Evox2ScratchBuildOperationalRefusal,
) -> Result<(), Evox2ScratchBuildDeploymentEffectFault> {
    validate_evox2_scratch_build_remote_preflight(request, plan, program, preflight)?;
    if refusal.profile != EVOX2_SCRATCH_BUILD_OPERATIONAL_REFUSAL_PROFILE
        || refusal.run_uuid != request.run_uuid
        || refusal.request_sha256 != request.request_sha256
        || refusal.plan_sha256 != plan.plan_sha256
        || refusal.program_sha256 != program.program_sha256
        || refusal.preflight_sha256 != preflight.preflight_sha256
        || refusal.disposition != "operational_refusal_before_commission_no_receipt"
        || refusal.reason != "provider_unavailable_before_commission"
        || preflight.status != "refused"
        || refusal.commission_admitted
        || refusal.receipt_present
        || refusal.retrieved_artifact_count != 0
        || refusal.provider_requests != preflight.provider_requests
        || refusal.remote_calls != preflight.remote_calls
        || refusal.effects != preflight.effects
    {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidRefusal,
            "operational refusal differs",
        ));
    }
    if !refusal.refusal_sha256.is_empty() && !is_lower_hex(&refusal.refusal_sha256, 64) {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidDigest,
            "operational refusal digest form differs",
        ));
    }
    Ok(())
}

fn validate_inventory_body(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    preflight: &Evox2ScratchBuildRemotePreflight,
    inventory: &Evox2ScratchBuildRetrievalInventory,
) -> Result<(), Evox2ScratchBuildDeploymentEffectFault> {
    validate_evox2_scratch_build_remote_preflight(request, plan, program, preflight)?;
    let aggregate = inventory
        .artifacts
        .iter()
        .try_fold(0_u64, |total, artifact| total.checked_add(artifact.bytes));
    let paths = inventory
        .artifacts
        .iter()
        .map(|artifact| artifact.relative_path.as_str())
        .collect::<Vec<_>>();
    let unique = paths.iter().copied().collect::<BTreeSet<_>>();
    if inventory.profile != EVOX2_SCRATCH_BUILD_RETRIEVAL_INVENTORY_PROFILE
        || inventory.run_uuid != request.run_uuid
        || inventory.request_sha256 != request.request_sha256
        || inventory.plan_sha256 != plan.plan_sha256
        || inventory.program_sha256 != program.program_sha256
        || inventory.preflight_sha256 != preflight.preflight_sha256
        || preflight.status != "admitted"
        || !matches!(
            inventory.outcome.as_str(),
            "succeeded" | "failed" | "refused"
        )
        || paths != RETRIEVED_PATHS
        || unique.len() != RETRIEVED_PATHS.len()
        || inventory.artifact_count != RETRIEVED_PATHS.len() as u32
        || aggregate != Some(inventory.aggregate_bytes)
        || inventory.aggregate_bytes == 0
        || inventory.aggregate_bytes > MAXIMUM_RETRIEVED_BYTES
        || inventory
            .artifacts
            .iter()
            .any(|artifact| artifact.bytes == 0 || !is_lower_hex(&artifact.sha256, 64))
    {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidInventory,
            "retrieval inventory differs",
        ));
    }
    if !inventory.inventory_sha256.is_empty() && !is_lower_hex(&inventory.inventory_sha256, 64) {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidDigest,
            "retrieval inventory digest form differs",
        ));
    }
    Ok(())
}

fn verify_supplied_artifacts<'a>(
    inventory: &Evox2ScratchBuildRetrievalInventory,
    supplied: &'a [(&'a str, &'a [u8])],
) -> Result<BTreeMap<&'a str, &'a [u8]>, Evox2ScratchBuildDeploymentEffectFault> {
    let mut map = BTreeMap::new();
    for (path, bytes) in supplied {
        if map.insert(*path, *bytes).is_some() {
            return Err(fault(
                Evox2ScratchBuildDeploymentEffectFaultCode::InvalidEvidence,
                "duplicate supplied artifact differs",
            ));
        }
    }
    if map.len() != inventory.artifacts.len() {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidEvidence,
            "supplied artifact count differs",
        ));
    }
    for artifact in &inventory.artifacts {
        let bytes = map.get(artifact.relative_path.as_str()).ok_or_else(|| {
            fault(
                Evox2ScratchBuildDeploymentEffectFaultCode::InvalidEvidence,
                "supplied artifact is absent",
            )
        })?;
        if bytes.len() as u64 != artifact.bytes || sha256(bytes) != artifact.sha256 {
            return Err(fault(
                Evox2ScratchBuildDeploymentEffectFaultCode::InvalidEvidence,
                "supplied artifact identity differs",
            ));
        }
    }
    Ok(map)
}

fn validate_commission_request_correspondence(
    request: &Evox2ScratchBuildControllerRequest,
    commission: &Evox2ScratchBuildCommission,
) -> Result<(), Evox2ScratchBuildDeploymentEffectFault> {
    if commission.target_host != request.target_host
        || commission.workspace_root != request.remote_workspace_root
        || commission.target_root != request.remote_target_root
    {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidEvidence,
            "commission controller correspondence differs",
        ));
    }
    Ok(())
}

fn verify_remote_run(
    raw: &str,
    receipt: &Evox2ScratchBuildReceipt,
) -> Result<(), Evox2ScratchBuildDeploymentEffectFault> {
    let remote: Evox2ScratchBuildRemoteRun = strict_deserialize(raw)?;
    match remote {
        Evox2ScratchBuildRemoteRun::Stopped(stopped) => {
            if stopped.profile != "cantor-evox2-scratch-build-host-run/0.1"
                || !matches!(stopped.status.as_str(), "failed" | "refused")
                || stopped.status != receipt.disposition
                || stopped.target_host != receipt.target_host
                || stopped.operation_record_count != receipt.operation_records.len() as u32
                || stopped.physical_build_performed
                || stopped.receipt != *receipt
                || stopped.persistent_processes != 0
            {
                return Err(fault(
                    Evox2ScratchBuildDeploymentEffectFaultCode::InvalidEvidence,
                    "stopped remote run summary differs",
                ));
            }
        }
        Evox2ScratchBuildRemoteRun::Succeeded(succeeded) => {
            if succeeded.profile != "cantor-evox2-scratch-build-host-run/0.1"
                || succeeded.status != "succeeded"
                || receipt.disposition != "succeeded"
                || succeeded.target_host != receipt.target_host
                || succeeded.operation_record_count != 7
                || !succeeded.physical_build_performed
                || succeeded.receipt_sha256 != receipt.receipt_sha256
                || !is_lower_hex(&succeeded.package_manifest_sha256, 64)
                || !succeeded.protected_state_unchanged
                || !succeeded.provider_state_unchanged
                || succeeded.persistent_processes != 0
                || succeeded.denied_effects != 0
            {
                return Err(fault(
                    Evox2ScratchBuildDeploymentEffectFaultCode::InvalidEvidence,
                    "successful remote run summary differs",
                ));
            }
        }
    }
    Ok(())
}

fn live_verification(
    request: &Evox2ScratchBuildControllerRequest,
    program: &Evox2ScratchBuildEffectProgram,
    preflight: &Evox2ScratchBuildRemotePreflight,
    inventory: &Evox2ScratchBuildRetrievalInventory,
    commission: &Evox2ScratchBuildCommission,
    receipt: &Evox2ScratchBuildReceipt,
    verification: &Evox2ScratchBuildReceiptVerification,
) -> Evox2ScratchBuildLiveEvidenceVerification {
    Evox2ScratchBuildLiveEvidenceVerification {
        profile: EVOX2_SCRATCH_BUILD_LIVE_EVIDENCE_VERIFICATION_PROFILE.to_owned(),
        status: "passed".to_owned(),
        branch: "commissioned_receipt_verified".to_owned(),
        run_uuid: request.run_uuid.clone(),
        request_sha256: request.request_sha256.clone(),
        plan_sha256: program.plan_sha256.clone(),
        program_sha256: program.program_sha256.clone(),
        preflight_sha256: preflight.preflight_sha256.clone(),
        refusal_sha256: String::new(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        commission_sha256: commission.commission_sha256.clone(),
        receipt_sha256: receipt.receipt_sha256.clone(),
        disposition: receipt.disposition.clone(),
        operation_record_count: verification.operation_record_count,
        physical_build_performed: verification.physical_build_performed,
        protected_state_unchanged: verification.protected_state_unchanged,
        provider_state_unchanged: verification.provider_state_unchanged,
        persistent_executor_process_count: verification.persistent_executor_process_count,
        retrieved_artifact_count: inventory.artifact_count,
        observation_source: preflight.observation_source.clone(),
        evidence_is_fixture: preflight.observation_source == "supplied_provider_free_fixture",
        provider_requests: preflight.provider_requests,
        remote_calls: preflight.remote_calls,
        effects: preflight.effects,
    }
}

fn validate_live_verification(
    value: &Evox2ScratchBuildLiveEvidenceVerification,
) -> Result<(), Evox2ScratchBuildDeploymentEffectFault> {
    let common = value.profile == EVOX2_SCRATCH_BUILD_LIVE_EVIDENCE_VERIFICATION_PROFILE
        && value.status == "passed"
        && is_uuid(&value.run_uuid)
        && is_lower_hex(&value.request_sha256, 64)
        && is_lower_hex(&value.plan_sha256, 64)
        && is_lower_hex(&value.program_sha256, 64)
        && is_lower_hex(&value.preflight_sha256, 64)
        && value.protected_state_unchanged
        && value.provider_state_unchanged
        && value.persistent_executor_process_count == 0;
    let branch = match value.branch.as_str() {
        "operational_refusal_before_commission_no_receipt" => {
            is_lower_hex(&value.refusal_sha256, 64)
                && value.inventory_sha256.is_empty()
                && value.commission_sha256.is_empty()
                && value.receipt_sha256.is_empty()
                && value.disposition == "operational_refusal_before_commission_no_receipt"
                && value.operation_record_count == 0
                && !value.physical_build_performed
                && value.retrieved_artifact_count == 0
        }
        "commissioned_receipt_verified" => {
            value.refusal_sha256.is_empty()
                && is_lower_hex(&value.inventory_sha256, 64)
                && is_lower_hex(&value.commission_sha256, 64)
                && is_lower_hex(&value.receipt_sha256, 64)
                && matches!(
                    value.disposition.as_str(),
                    "succeeded" | "failed" | "refused"
                )
                && value.operation_record_count <= 7
                && value.retrieved_artifact_count == RETRIEVED_PATHS.len() as u32
                && (value.disposition != "succeeded"
                    || (value.physical_build_performed && value.operation_record_count == 7))
                && (value.disposition == "succeeded" || !value.physical_build_performed)
        }
        _ => false,
    };
    if !common || !branch {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidEvidence,
            "live evidence verification differs",
        ));
    }
    Ok(())
}

fn program_digest(
    value: &Evox2ScratchBuildEffectProgram,
) -> Result<String, Evox2ScratchBuildDeploymentEffectFault> {
    let mut unsigned = value.clone();
    unsigned.program_sha256.clear();
    digest_json(EFFECT_PROGRAM_DIGEST_DOMAIN, &unsigned)
}

fn preflight_digest(
    value: &Evox2ScratchBuildRemotePreflight,
) -> Result<String, Evox2ScratchBuildDeploymentEffectFault> {
    let mut unsigned = value.clone();
    unsigned.preflight_sha256.clear();
    digest_json(PREFLIGHT_DIGEST_DOMAIN, &unsigned)
}

fn refusal_digest(
    value: &Evox2ScratchBuildOperationalRefusal,
) -> Result<String, Evox2ScratchBuildDeploymentEffectFault> {
    let mut unsigned = value.clone();
    unsigned.refusal_sha256.clear();
    digest_json(OPERATIONAL_REFUSAL_DIGEST_DOMAIN, &unsigned)
}

fn inventory_digest(
    value: &Evox2ScratchBuildRetrievalInventory,
) -> Result<String, Evox2ScratchBuildDeploymentEffectFault> {
    let mut unsigned = value.clone();
    unsigned.inventory_sha256.clear();
    digest_json(RETRIEVAL_INVENTORY_DIGEST_DOMAIN, &unsigned)
}

fn effect_observation_digest(
    value: &Evox2ScratchBuildEffectObservation,
) -> Result<String, Evox2ScratchBuildDeploymentEffectFault> {
    let mut unsigned = value.clone();
    unsigned.observation_sha256.clear();
    digest_json(EFFECT_OBSERVATION_DIGEST_DOMAIN, &unsigned)
}

fn effect_state_digest(
    value: &Evox2ScratchBuildEffectState,
) -> Result<String, Evox2ScratchBuildDeploymentEffectFault> {
    let mut unsigned = value.clone();
    unsigned.state_sha256.clear();
    digest_json(EFFECT_STATE_DIGEST_DOMAIN, &unsigned)
}

fn digest_json<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<String, Evox2ScratchBuildDeploymentEffectFault> {
    let encoded = serde_json::to_vec(value).map_err(|_| {
        fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidMachineForm,
            "effect form serialization failed",
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(encoded);
    Ok(hex_digest(hasher.finalize().as_slice()))
}

fn sha256(value: &[u8]) -> String {
    hex_digest(Sha256::digest(value).as_slice())
}

fn hex_digest(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn utf8_artifact<'a>(
    supplied: &BTreeMap<&str, &'a [u8]>,
    path: &str,
) -> Result<&'a str, Evox2ScratchBuildDeploymentEffectFault> {
    std::str::from_utf8(supplied.get(path).copied().ok_or_else(|| {
        fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidEvidence,
            "required artifact is absent",
        )
    })?)
    .map_err(|_| {
        fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidEvidence,
            "retrieved artifact UTF-8 differs",
        )
    })
}

fn strict_deserialize<T>(value: &str) -> Result<T, Evox2ScratchBuildDeploymentEffectFault>
where
    T: DeserializeOwned + Serialize,
{
    if value.is_empty() || value.len() > MAXIMUM_MACHINE_BYTES {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidMachineForm,
            "effect form byte bound differs",
        ));
    }
    let parsed: T = serde_json::from_str(value).map_err(|_| {
        fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidMachineForm,
            "effect form decode failed",
        )
    })?;
    let canonical = serde_json::to_string(&parsed).map_err(|_| {
        fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidMachineForm,
            "effect form encode failed",
        )
    })?;
    if canonical != value {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidMachineForm,
            "effect form is not canonical",
        ));
    }
    Ok(parsed)
}

fn serialize_bounded<T: Serialize>(
    value: &T,
) -> Result<String, Evox2ScratchBuildDeploymentEffectFault> {
    let encoded = serde_json::to_string(value).map_err(|_| {
        fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidMachineForm,
            "effect form encode failed",
        )
    })?;
    if encoded.len() > MAXIMUM_MACHINE_BYTES {
        return Err(fault(
            Evox2ScratchBuildDeploymentEffectFaultCode::InvalidMachineForm,
            "effect form byte bound differs",
        ));
    }
    Ok(encoded)
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn fault(
    code: Evox2ScratchBuildDeploymentEffectFaultCode,
    detail: &'static str,
) -> Evox2ScratchBuildDeploymentEffectFault {
    Evox2ScratchBuildDeploymentEffectFault { code, detail }
}
