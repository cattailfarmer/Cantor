//! Provider-free contract for one bounded native-OpenSSH preflight process.
//!
//! This module fixes the executable and argument boundary, validates a supplied
//! retained process record, and compiles the already-published remote-preflight
//! observation. It performs no filesystem, process, environment, clock,
//! network, provider, model, SSH, SCP, Cargo, Git, or remote-host operation.

use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_OBSERVATION_PROFILE, Evox2ScratchBuildControllerPlan,
    Evox2ScratchBuildControllerRequest, Evox2ScratchBuildEffectProgram,
    Evox2ScratchBuildRemotePreflightObservation, Evox2ScratchBuildRemoteProbeResult,
    from_evox2_scratch_build_remote_probe_result_machine_form,
    seal_evox2_scratch_build_remote_preflight_observation,
    to_evox2_scratch_build_remote_probe_result_machine_form,
    validate_evox2_scratch_build_remote_probe_result, verify_evox2_scratch_build_effect_program,
};

pub const EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_PLAN_PROFILE: &str =
    "cantor-evox2-scratch-build-remote-preflight-producer-plan/0.1";
pub const EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PROCESS_RECORD_PROFILE: &str =
    "cantor-evox2-scratch-build-remote-preflight-process-record/0.1";
pub const EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_VERIFICATION_PROFILE: &str =
    "cantor-evox2-scratch-build-remote-preflight-producer-verification/0.1";

pub const EVOX2_SCRATCH_BUILD_OBSERVATION_COMPILER_IMPLEMENTATION_COMMIT: &str =
    "000fef93cadce29b2e0ce59e668ac72ca2e2a9ad";
pub const EVOX2_SCRATCH_BUILD_OBSERVATION_COMPILER_BOOKEND_COMMIT: &str =
    "047674f26b4f9cb576fd93524d710d91e0e48b51";

const PRODUCER_PLAN_DIGEST_DOMAIN: &str =
    "cantor-evox2-scratch-build-remote-preflight-producer-plan-v1";
const PROCESS_RECORD_DIGEST_DOMAIN: &str =
    "cantor-evox2-scratch-build-remote-preflight-process-record-v1";
const PROBE_DIGEST_DOMAIN: &str = "cantor-evox2-scratch-build-remote-probe-result-v1";
const MAXIMUM_MACHINE_BYTES: usize = 262_144;
const EXECUTABLE_PATH: &str = "C:/Windows/System32/OpenSSH/ssh.exe";
const TRANSPORT: &str = "openssh_native_bounded_single_call";
const TIMEOUT_MS: u64 = 30_000;
const STREAM_LIMIT_BYTES: u32 = 65_536;
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const PROVIDER_LISTENER: &str = "127.0.0.1:8081";
const PROVIDER_MODEL_PATH: &str =
    "C:/AI/models/validation/Qwen3.5-0.8B-GGUF/Qwen3.5-0.8B-Q4_0.gguf";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildRemotePreflightProducerPlan {
    pub profile: String,
    pub run_uuid: String,
    pub request_sha256: String,
    pub plan_sha256: String,
    pub program_sha256: String,
    pub observation_compiler_implementation_commit: String,
    pub observation_compiler_bookend_commit: String,
    pub target_host: String,
    pub ssh_host: String,
    pub transport: String,
    pub executable_path: String,
    pub executable_sha256: String,
    pub argument_atoms: Vec<String>,
    pub argument_count: u32,
    pub timeout_ms: u64,
    pub stdout_limit_bytes: u32,
    pub stderr_limit_bytes: u32,
    pub provider_request_limit: u32,
    pub remote_call_limit: u32,
    pub effect_limit: u32,
    pub authority_disposition: String,
    pub remote_contact_authorized: bool,
    pub producer_plan_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildRemotePreflightProcessRecord {
    pub profile: String,
    pub producer_plan_sha256: String,
    pub executable_path: String,
    pub executable_sha256: String,
    pub argument_atoms: Vec<String>,
    pub argument_count: u32,
    pub evidence_class: String,
    pub started: bool,
    pub completed: bool,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub stdout: String,
    pub stdout_bytes: u32,
    pub stdout_sha256: String,
    pub stdout_truncated: bool,
    pub stderr: String,
    pub stderr_bytes: u32,
    pub stderr_sha256: String,
    pub stderr_truncated: bool,
    pub probe: Evox2ScratchBuildRemoteProbeResult,
    pub remote_contact_made: bool,
    pub provider_requests: u32,
    pub remote_calls: u32,
    pub effects: u32,
    pub process_record_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildRemotePreflightProducerVerification {
    pub profile: String,
    pub status: String,
    pub request_sha256: String,
    pub plan_sha256: String,
    pub program_sha256: String,
    pub producer_plan_sha256: String,
    pub process_record_sha256: String,
    pub observation_sha256: String,
    pub executable_sha256: String,
    pub argument_count: u32,
    pub timeout_ms: u64,
    pub duration_ms: u64,
    pub stdout_bytes: u32,
    pub stderr_bytes: u32,
    pub provider_requests: u32,
    pub remote_calls: u32,
    pub effects: u32,
    pub remote_contact_authorized: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evox2ScratchBuildRemotePreflightProducerFaultCode {
    InvalidMachineForm,
    InvalidIdentity,
    InvalidDigest,
    InvalidPlan,
    InvalidProcessRecord,
    InvalidObservation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evox2ScratchBuildRemotePreflightProducerFault {
    pub code: Evox2ScratchBuildRemotePreflightProducerFaultCode,
    pub detail: &'static str,
}

impl fmt::Display for Evox2ScratchBuildRemotePreflightProducerFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Evox2ScratchBuildRemotePreflightProducerFault {}

pub fn compile_evox2_scratch_build_remote_preflight_producer_plan(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    executable_sha256: &str,
) -> Result<
    Evox2ScratchBuildRemotePreflightProducerPlan,
    Evox2ScratchBuildRemotePreflightProducerFault,
> {
    verify_program(request, plan, program)?;
    if !is_lower_hex(executable_sha256, 64) {
        return Err(fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidIdentity,
            "producer executable digest form differs",
        ));
    }
    let mut producer_plan = expected_producer_plan(request, plan, program, executable_sha256)?;
    producer_plan.producer_plan_sha256 = producer_plan_digest(&producer_plan)?;
    verify_evox2_scratch_build_remote_preflight_producer_plan(
        request,
        plan,
        program,
        &producer_plan,
    )?;
    Ok(producer_plan)
}

pub fn verify_evox2_scratch_build_remote_preflight_producer_plan(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
) -> Result<(), Evox2ScratchBuildRemotePreflightProducerFault> {
    verify_program(request, plan, program)?;
    if !is_lower_hex(&producer_plan.executable_sha256, 64) {
        return Err(fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidIdentity,
            "producer executable digest form differs",
        ));
    }
    let mut expected =
        expected_producer_plan(request, plan, program, &producer_plan.executable_sha256)?;
    expected.producer_plan_sha256 = producer_plan_digest(&expected)?;
    if producer_plan != &expected
        || producer_plan.producer_plan_sha256 != producer_plan_digest(producer_plan)?
    {
        return Err(fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidPlan,
            "remote preflight producer plan correspondence differs",
        ));
    }
    Ok(())
}

pub fn seal_evox2_scratch_build_remote_preflight_process_record(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
    mut record: Evox2ScratchBuildRemotePreflightProcessRecord,
) -> Result<
    Evox2ScratchBuildRemotePreflightProcessRecord,
    Evox2ScratchBuildRemotePreflightProducerFault,
> {
    record.process_record_sha256.clear();
    validate_process_record_body(request, plan, program, producer_plan, &record)?;
    record.process_record_sha256 = process_record_digest(&record)?;
    validate_evox2_scratch_build_remote_preflight_process_record(
        request,
        plan,
        program,
        producer_plan,
        &record,
    )?;
    Ok(record)
}

pub fn validate_evox2_scratch_build_remote_preflight_process_record(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
    record: &Evox2ScratchBuildRemotePreflightProcessRecord,
) -> Result<(), Evox2ScratchBuildRemotePreflightProducerFault> {
    validate_process_record_body(request, plan, program, producer_plan, record)?;
    if record.process_record_sha256 != process_record_digest(record)? {
        return Err(fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidDigest,
            "remote preflight process-record digest differs",
        ));
    }
    Ok(())
}

pub fn compile_evox2_scratch_build_remote_preflight_observation_from_process_record(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
    record: &Evox2ScratchBuildRemotePreflightProcessRecord,
) -> Result<
    Evox2ScratchBuildRemotePreflightObservation,
    Evox2ScratchBuildRemotePreflightProducerFault,
> {
    validate_evox2_scratch_build_remote_preflight_process_record(
        request,
        plan,
        program,
        producer_plan,
        record,
    )?;
    seal_evox2_scratch_build_remote_preflight_observation(
        request,
        plan,
        program,
        Evox2ScratchBuildRemotePreflightObservation {
            profile: EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_OBSERVATION_PROFILE.to_owned(),
            run_uuid: request.run_uuid.clone(),
            request_sha256: request.request_sha256.clone(),
            plan_sha256: plan.plan_sha256.clone(),
            program_sha256: program.program_sha256.clone(),
            target_host: request.target_host.clone(),
            ssh_host: request.ssh_host.clone(),
            transport: producer_plan.transport.clone(),
            status: "completed".to_owned(),
            observation_source: "live_remote_preflight".to_owned(),
            probe: record.probe.clone(),
            remote_contact_made: record.remote_contact_made,
            provider_requests: record.provider_requests,
            remote_calls: record.remote_calls,
            effects: record.effects,
            exit_code: record.exit_code,
            timed_out: record.timed_out,
            stdout_bytes: record.stdout_bytes,
            stdout_sha256: record.stdout_sha256.clone(),
            stdout_truncated: record.stdout_truncated,
            stderr_bytes: record.stderr_bytes,
            stderr_sha256: record.stderr_sha256.clone(),
            stderr_truncated: record.stderr_truncated,
            observation_sha256: String::new(),
        },
    )
    .map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidObservation,
            "compiled remote preflight observation refused",
        )
    })
}

pub fn verify_evox2_scratch_build_remote_preflight_producer(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
    record: &Evox2ScratchBuildRemotePreflightProcessRecord,
    observation: &Evox2ScratchBuildRemotePreflightObservation,
) -> Result<
    Evox2ScratchBuildRemotePreflightProducerVerification,
    Evox2ScratchBuildRemotePreflightProducerFault,
> {
    let expected = compile_evox2_scratch_build_remote_preflight_observation_from_process_record(
        request,
        plan,
        program,
        producer_plan,
        record,
    )?;
    if observation != &expected {
        return Err(fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidObservation,
            "retained observation differs from process-record compilation",
        ));
    }
    Ok(Evox2ScratchBuildRemotePreflightProducerVerification {
        profile: EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_VERIFICATION_PROFILE.to_owned(),
        status: "passed".to_owned(),
        request_sha256: request.request_sha256.clone(),
        plan_sha256: plan.plan_sha256.clone(),
        program_sha256: program.program_sha256.clone(),
        producer_plan_sha256: producer_plan.producer_plan_sha256.clone(),
        process_record_sha256: record.process_record_sha256.clone(),
        observation_sha256: observation.observation_sha256.clone(),
        executable_sha256: producer_plan.executable_sha256.clone(),
        argument_count: producer_plan.argument_count,
        timeout_ms: producer_plan.timeout_ms,
        duration_ms: record.duration_ms,
        stdout_bytes: record.stdout_bytes,
        stderr_bytes: record.stderr_bytes,
        provider_requests: record.provider_requests,
        remote_calls: record.remote_calls,
        effects: record.effects,
        remote_contact_authorized: false,
    })
}

pub fn to_evox2_scratch_build_remote_preflight_producer_plan_machine_form(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
) -> Result<String, Evox2ScratchBuildRemotePreflightProducerFault> {
    verify_evox2_scratch_build_remote_preflight_producer_plan(
        request,
        plan,
        program,
        producer_plan,
    )?;
    serialize_bounded(producer_plan)
}

pub fn from_evox2_scratch_build_remote_preflight_producer_plan_machine_form(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    value: &str,
) -> Result<
    Evox2ScratchBuildRemotePreflightProducerPlan,
    Evox2ScratchBuildRemotePreflightProducerFault,
> {
    let producer_plan = strict_deserialize(value)?;
    verify_evox2_scratch_build_remote_preflight_producer_plan(
        request,
        plan,
        program,
        &producer_plan,
    )?;
    Ok(producer_plan)
}

pub fn to_evox2_scratch_build_remote_preflight_process_record_machine_form(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
    record: &Evox2ScratchBuildRemotePreflightProcessRecord,
) -> Result<String, Evox2ScratchBuildRemotePreflightProducerFault> {
    validate_evox2_scratch_build_remote_preflight_process_record(
        request,
        plan,
        program,
        producer_plan,
        record,
    )?;
    serialize_bounded(record)
}

pub fn from_evox2_scratch_build_remote_preflight_process_record_machine_form(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
    value: &str,
) -> Result<
    Evox2ScratchBuildRemotePreflightProcessRecord,
    Evox2ScratchBuildRemotePreflightProducerFault,
> {
    let record = strict_deserialize(value)?;
    validate_evox2_scratch_build_remote_preflight_process_record(
        request,
        plan,
        program,
        producer_plan,
        &record,
    )?;
    Ok(record)
}

pub fn to_evox2_scratch_build_remote_preflight_producer_verification_machine_form(
    verification: &Evox2ScratchBuildRemotePreflightProducerVerification,
) -> Result<String, Evox2ScratchBuildRemotePreflightProducerFault> {
    if verification.profile != EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_VERIFICATION_PROFILE
        || verification.status != "passed"
        || !is_lower_hex(&verification.request_sha256, 64)
        || !is_lower_hex(&verification.plan_sha256, 64)
        || !is_lower_hex(&verification.program_sha256, 64)
        || !is_lower_hex(&verification.producer_plan_sha256, 64)
        || !is_lower_hex(&verification.process_record_sha256, 64)
        || !is_lower_hex(&verification.observation_sha256, 64)
        || !is_lower_hex(&verification.executable_sha256, 64)
        || verification.argument_count == 0
        || verification.timeout_ms != TIMEOUT_MS
        || verification.duration_ms == 0
        || verification.duration_ms > verification.timeout_ms
        || verification.stdout_bytes == 0
        || verification.stdout_bytes > STREAM_LIMIT_BYTES
        || verification.stderr_bytes != 0
        || verification.provider_requests != 0
        || verification.remote_calls != 1
        || verification.effects != 1
        || verification.remote_contact_authorized
    {
        return Err(fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidObservation,
            "producer verification differs",
        ));
    }
    serialize_bounded(verification)
}

fn expected_producer_plan(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    executable_sha256: &str,
) -> Result<
    Evox2ScratchBuildRemotePreflightProducerPlan,
    Evox2ScratchBuildRemotePreflightProducerFault,
> {
    let argument_atoms = fixed_argument_atoms(request)?;
    let argument_count = u32::try_from(argument_atoms.len()).map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidPlan,
            "producer argument count overflows",
        )
    })?;
    Ok(Evox2ScratchBuildRemotePreflightProducerPlan {
        profile: EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_PLAN_PROFILE.to_owned(),
        run_uuid: request.run_uuid.clone(),
        request_sha256: request.request_sha256.clone(),
        plan_sha256: plan.plan_sha256.clone(),
        program_sha256: program.program_sha256.clone(),
        observation_compiler_implementation_commit:
            EVOX2_SCRATCH_BUILD_OBSERVATION_COMPILER_IMPLEMENTATION_COMMIT.to_owned(),
        observation_compiler_bookend_commit:
            EVOX2_SCRATCH_BUILD_OBSERVATION_COMPILER_BOOKEND_COMMIT.to_owned(),
        target_host: request.target_host.clone(),
        ssh_host: request.ssh_host.clone(),
        transport: TRANSPORT.to_owned(),
        executable_path: EXECUTABLE_PATH.to_owned(),
        executable_sha256: executable_sha256.to_owned(),
        argument_atoms,
        argument_count,
        timeout_ms: TIMEOUT_MS,
        stdout_limit_bytes: STREAM_LIMIT_BYTES,
        stderr_limit_bytes: STREAM_LIMIT_BYTES,
        provider_request_limit: 0,
        remote_call_limit: 1,
        effect_limit: 1,
        authority_disposition: "producer_contract_only_live_invocation_not_authorized".to_owned(),
        remote_contact_authorized: false,
        producer_plan_sha256: String::new(),
    })
}

fn validate_process_record_body(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
    record: &Evox2ScratchBuildRemotePreflightProcessRecord,
) -> Result<(), Evox2ScratchBuildRemotePreflightProducerFault> {
    verify_evox2_scratch_build_remote_preflight_producer_plan(
        request,
        plan,
        program,
        producer_plan,
    )?;
    validate_evox2_scratch_build_remote_probe_result(request, &record.probe).map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidProcessRecord,
            "process-record probe differs",
        )
    })?;
    let stdout_bytes = u32::try_from(record.stdout.len()).map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidProcessRecord,
            "process-record stdout byte count overflows",
        )
    })?;
    let stderr_bytes = u32::try_from(record.stderr.len()).map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidProcessRecord,
            "process-record stderr byte count overflows",
        )
    })?;
    let canonical_probe =
        to_evox2_scratch_build_remote_probe_result_machine_form(request, &record.probe).map_err(
            |_| {
                fault(
                    Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidProcessRecord,
                    "process-record probe machine form differs",
                )
            },
        )?;
    let parsed_probe =
        from_evox2_scratch_build_remote_probe_result_machine_form(request, &record.stdout)
            .map_err(|_| {
                fault(
                    Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidProcessRecord,
                    "process-record stdout is not the canonical embedded probe",
                )
            })?;
    if record.profile != EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PROCESS_RECORD_PROFILE
        || record.producer_plan_sha256 != producer_plan.producer_plan_sha256
        || record.executable_path != producer_plan.executable_path
        || record.executable_sha256 != producer_plan.executable_sha256
        || record.argument_atoms != producer_plan.argument_atoms
        || record.argument_count != producer_plan.argument_count
        || record.evidence_class != "live_process_observation"
        || !record.started
        || !record.completed
        || record.exit_code != 0
        || record.duration_ms == 0
        || record.duration_ms > producer_plan.timeout_ms
        || record.timed_out
        || record.stdout != canonical_probe
        || parsed_probe != record.probe
        || record.stdout_bytes != stdout_bytes
        || record.stdout_bytes == 0
        || record.stdout_bytes > producer_plan.stdout_limit_bytes
        || record.stdout_sha256 != sha256(record.stdout.as_bytes())
        || record.stdout_truncated
        || !record.stderr.is_empty()
        || record.stderr_bytes != stderr_bytes
        || record.stderr_bytes != 0
        || record.stderr_bytes > producer_plan.stderr_limit_bytes
        || record.stderr_sha256 != EMPTY_SHA256
        || record.stderr_truncated
        || !record.remote_contact_made
        || record.provider_requests != producer_plan.provider_request_limit
        || record.remote_calls != producer_plan.remote_call_limit
        || record.effects != producer_plan.effect_limit
    {
        return Err(fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidProcessRecord,
            "remote preflight process-record boundary differs",
        ));
    }
    if !record.process_record_sha256.is_empty() && !is_lower_hex(&record.process_record_sha256, 64)
    {
        return Err(fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidDigest,
            "remote preflight process-record digest form differs",
        ));
    }
    Ok(())
}

fn fixed_argument_atoms(
    request: &Evox2ScratchBuildControllerRequest,
) -> Result<Vec<String>, Evox2ScratchBuildRemotePreflightProducerFault> {
    let encoded_command = base64_encode(&utf16le(remote_probe_script(request)));
    Ok(vec![
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-o".to_owned(),
        "ConnectTimeout=15".to_owned(),
        "-o".to_owned(),
        "ConnectionAttempts=1".to_owned(),
        "-o".to_owned(),
        "ClearAllForwardings=yes".to_owned(),
        "-o".to_owned(),
        "PermitLocalCommand=no".to_owned(),
        request.ssh_host.clone(),
        "powershell.exe".to_owned(),
        "-NoLogo".to_owned(),
        "-NoProfile".to_owned(),
        "-NonInteractive".to_owned(),
        "-ExecutionPolicy".to_owned(),
        "RemoteSigned".to_owned(),
        "-EncodedCommand".to_owned(),
        encoded_command,
    ])
}

fn remote_probe_script(request: &Evox2ScratchBuildControllerRequest) -> String {
    let mut script = String::new();
    script.push_str("if($env:COMPUTERNAME -ne '");
    script.push_str(&request.target_host);
    script.push_str("'){[Console]::Error.Write('target_host_mismatch');exit 86};");
    script.push_str("$listener=[Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()|Where-Object {$_.Address.ToString() -eq '127.0.0.1' -and $_.Port -eq 8081}|Select-Object -First 1;");
    script.push_str("$listenerObserved=$null -ne $listener;");
    script.push_str("$modelObserved=Test-Path -LiteralPath '");
    script.push_str(PROVIDER_MODEL_PATH);
    script.push_str("';$available=$listenerObserved -and $modelObserved;");
    script.push_str("$status=if($available){'available'}else{'unavailable'};");
    script.push_str("$reason=if($available){'preflight_satisfied'}else{'provider_unavailable_before_commission'};");
    script.push_str("$lb=$listenerObserved.ToString().ToLowerInvariant();$mb=$modelObserved.ToString().ToLowerInvariant();");
    script.push_str("$unsigned='{\"profile\":\"cantor-evox2-scratch-build-remote-probe-result/0.1\",\"run_uuid\":\"");
    script.push_str(&request.run_uuid);
    script.push_str("\",\"request_sha256\":\"");
    script.push_str(&request.request_sha256);
    script.push_str("\",\"target_host\":\"");
    script.push_str(&request.target_host);
    script.push_str("\",\"provider_listener\":\"");
    script.push_str(PROVIDER_LISTENER);
    script.push_str("\",\"provider_model_path\":\"");
    script.push_str(PROVIDER_MODEL_PATH);
    script.push_str("\",\"listener_observed\":'+$lb+',\"model_observed\":'+$mb+',\"provider_status\":\"'+$status+'\",\"reason\":\"'+$reason+'\",\"probe_sha256\":\"\"}';");
    script.push_str(
        "$sha=[Security.Cryptography.SHA256]::Create();try{$data=[Text.Encoding]::UTF8.GetBytes('",
    );
    script.push_str(PROBE_DIGEST_DOMAIN);
    script.push_str("'+[char]0+$unsigned);$hash=-join($sha.ComputeHash($data)|ForEach-Object {$_.ToString('x2')})}finally{$sha.Dispose()};");
    script.push_str("[Console]::Out.Write($unsigned.Substring(0,$unsigned.Length-2)+$hash+'\"}')");
    script
}

fn utf16le(value: String) -> Vec<u8> {
    value
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
}

fn base64_encode(value: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(value.len().div_ceil(3) * 4);
    for chunk in value.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        encoded.push(char::from(TABLE[usize::from(first >> 2)]));
        encoded.push(char::from(
            TABLE[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        if chunk.len() > 1 {
            encoded.push(char::from(
                TABLE[usize::from(((second & 0x0f) << 2) | (third >> 6))],
            ));
        } else {
            encoded.push('=');
        }
        if chunk.len() > 2 {
            encoded.push(char::from(TABLE[usize::from(third & 0x3f)]));
        } else {
            encoded.push('=');
        }
    }
    encoded
}

fn verify_program(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
) -> Result<(), Evox2ScratchBuildRemotePreflightProducerFault> {
    verify_evox2_scratch_build_effect_program(request, plan, program).map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidIdentity,
            "published effect-program correspondence refused",
        )
    })
}

fn producer_plan_digest(
    value: &Evox2ScratchBuildRemotePreflightProducerPlan,
) -> Result<String, Evox2ScratchBuildRemotePreflightProducerFault> {
    let mut unsigned = value.clone();
    unsigned.producer_plan_sha256.clear();
    digest_json(PRODUCER_PLAN_DIGEST_DOMAIN, &unsigned)
}

fn process_record_digest(
    value: &Evox2ScratchBuildRemotePreflightProcessRecord,
) -> Result<String, Evox2ScratchBuildRemotePreflightProducerFault> {
    let mut unsigned = value.clone();
    unsigned.process_record_sha256.clear();
    digest_json(PROCESS_RECORD_DIGEST_DOMAIN, &unsigned)
}

fn digest_json<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<String, Evox2ScratchBuildRemotePreflightProducerFault> {
    let encoded = serde_json::to_vec(value).map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidMachineForm,
            "producer form serialization failed",
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

fn strict_deserialize<T>(value: &str) -> Result<T, Evox2ScratchBuildRemotePreflightProducerFault>
where
    T: DeserializeOwned + Serialize,
{
    if value.is_empty() || value.len() > MAXIMUM_MACHINE_BYTES {
        return Err(fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidMachineForm,
            "producer form byte bound differs",
        ));
    }
    let parsed: T = serde_json::from_str(value).map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidMachineForm,
            "producer form decode failed",
        )
    })?;
    let canonical = serde_json::to_string(&parsed).map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidMachineForm,
            "producer form encode failed",
        )
    })?;
    if canonical != value {
        return Err(fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidMachineForm,
            "producer form is not canonical",
        ));
    }
    Ok(parsed)
}

fn serialize_bounded<T: Serialize>(
    value: &T,
) -> Result<String, Evox2ScratchBuildRemotePreflightProducerFault> {
    let encoded = serde_json::to_string(value).map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidMachineForm,
            "producer form encode failed",
        )
    })?;
    if encoded.len() > MAXIMUM_MACHINE_BYTES {
        return Err(fault(
            Evox2ScratchBuildRemotePreflightProducerFaultCode::InvalidMachineForm,
            "producer form byte bound differs",
        ));
    }
    Ok(encoded)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn fault(
    code: Evox2ScratchBuildRemotePreflightProducerFaultCode,
    detail: &'static str,
) -> Evox2ScratchBuildRemotePreflightProducerFault {
    Evox2ScratchBuildRemotePreflightProducerFault { code, detail }
}
