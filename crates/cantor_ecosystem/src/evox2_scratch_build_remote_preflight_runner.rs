//! Sealed physical runner for one governed EVO-X2 remote-preflight process.
//!
//! The runner reuses the audited Windows contained-child substrate and feeds a
//! successful retained observation into the pure `cantor_core` producer.  The
//! production entry point consumes a permit whose sole crate-private issuer
//! requires the bridge's presently unconstructible live admission, so this
//! module still cannot initiate live contact.

use std::fmt;

#[cfg(windows)]
use std::{fs, fs::File, io::Read, path::Path, time::Instant};

#[cfg(any(windows, test))]
use cantor_core::{
    EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PROCESS_RECORD_PROFILE,
    from_evox2_scratch_build_remote_probe_result_machine_form,
    seal_evox2_scratch_build_remote_preflight_process_record,
};
use cantor_core::{
    Evox2ScratchBuildControllerPlan, Evox2ScratchBuildControllerRequest,
    Evox2ScratchBuildEffectProgram, Evox2ScratchBuildRemotePreflightObservation,
    Evox2ScratchBuildRemotePreflightProcessRecord, Evox2ScratchBuildRemotePreflightProducerPlan,
    Evox2ScratchBuildRemotePreflightProducerVerification,
    compile_evox2_scratch_build_remote_preflight_observation_from_process_record,
    validate_evox2_scratch_build_remote_preflight_process_record,
    verify_evox2_scratch_build_remote_preflight_producer,
    verify_evox2_scratch_build_remote_preflight_producer_plan,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_RUNNER_PROFILE: &str =
    "cantor-evox2-scratch-build-remote-preflight-runner/0.1";
pub const EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_RUNNER_IMPLEMENTATION_AUTHORITY: &str =
    "runner_implementation_only_live_invocation_not_authorized";
pub const EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_IMPLEMENTATION_COMMIT: &str =
    "606588a6dd542b31816d116abf909f50d0881937";
pub const EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_BOOKEND_COMMIT: &str =
    "b48c4d7ac48e51aaf70f179cc7b1cdd15e9d5bd0";

const EXECUTABLE_PATH: &str = "C:/Windows/System32/OpenSSH/ssh.exe";
const WORKING_DIRECTORY: &str = "C:/Windows/System32/OpenSSH";
#[cfg(windows)]
const MAXIMUM_EXECUTABLE_BYTES: u64 = 33_554_432;
const MAXIMUM_ACTIVE_PROCESSES: u32 = 1;
const MAXIMUM_TOTAL_PROCESSES: u32 = 1;
const MAXIMUM_MACHINE_BYTES: usize = 262_144;
const RUNNER_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"cantor-evox2-scratch-build-remote-preflight-runner-receipt-v1\0";

#[derive(Debug)]
pub struct Evox2ScratchBuildRemotePreflightSingleUsePermit {
    producer_plan_sha256: String,
    producer_implementation_commit: String,
    producer_bookend_commit: String,
}

pub(crate) fn issue_evox2_scratch_build_remote_preflight_single_use_permit(
    admission: crate::evox2_remote_preflight_private_permit_bridge::Evox2RemotePreflightLiveAdmission,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
) -> Result<
    Evox2ScratchBuildRemotePreflightSingleUsePermit,
    Evox2ScratchBuildRemotePreflightRunnerFault,
> {
    admission
        .consume_for_runner_permit(producer_plan)
        .map_err(|_| {
            fault(
                Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidPermit,
                "live admission correspondence differs",
            )
        })?;
    Ok(Evox2ScratchBuildRemotePreflightSingleUsePermit {
        producer_plan_sha256: producer_plan.producer_plan_sha256.clone(),
        producer_implementation_commit:
            EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_IMPLEMENTATION_COMMIT.to_owned(),
        producer_bookend_commit: EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_BOOKEND_COMMIT
            .to_owned(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evox2ScratchBuildRemotePreflightContainedProcessSpec {
    pub profile: String,
    pub producer_implementation_commit: String,
    pub producer_bookend_commit: String,
    pub producer_plan_sha256: String,
    pub executable: String,
    pub executable_sha256: String,
    pub arguments: Vec<String>,
    pub working_directory: String,
    pub environment: Vec<(String, String)>,
    pub stdin: Vec<u8>,
    pub maximum_stdout_bytes: usize,
    pub maximum_stderr_bytes: usize,
    pub timeout_millis: u32,
    pub maximum_active_processes: u32,
    pub maximum_total_processes: u32,
    pub authority_disposition: String,
    pub live_invocation_authorized: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evox2ScratchBuildRemotePreflightContainedProcessObservation {
    pub exit_code: u32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_observed_bytes: u64,
    pub stderr_observed_bytes: u64,
    pub stdout_over_bound: bool,
    pub stderr_over_bound: bool,
    pub forced_termination: bool,
    pub total_processes: u32,
    pub active_processes_at_terminal: u32,
    pub resume_previous_count: u32,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildRemotePreflightRun {
    pub profile: String,
    pub producer_implementation_commit: String,
    pub producer_bookend_commit: String,
    pub executable_sha256_before: String,
    pub executable_sha256_after: String,
    pub process_record: Evox2ScratchBuildRemotePreflightProcessRecord,
    pub observation: Evox2ScratchBuildRemotePreflightObservation,
    pub verification: Evox2ScratchBuildRemotePreflightProducerVerification,
    pub total_processes: u32,
    pub active_processes_at_terminal: u32,
    pub resume_previous_count: u32,
    pub execution_disposition: String,
    pub single_use_permit_consumed: bool,
    pub provider_requests: u32,
    pub remote_calls: u32,
    pub effects: u32,
    pub runner_receipt_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evox2ScratchBuildRemotePreflightRunnerFaultCode {
    InvalidPermit,
    InvalidPlan,
    ExecutableObservation,
    ExecutableMismatch,
    ProcessFailure,
    ProcessObservation,
    ProducerRefusal,
    InvalidMachineForm,
    InvalidReceipt,
    PlatformUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evox2ScratchBuildRemotePreflightRunnerFault {
    pub code: Evox2ScratchBuildRemotePreflightRunnerFaultCode,
    pub detail: &'static str,
}

impl fmt::Display for Evox2ScratchBuildRemotePreflightRunnerFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Evox2ScratchBuildRemotePreflightRunnerFault {}

impl Evox2ScratchBuildRemotePreflightContainedProcessSpec {
    pub fn validate_against(
        &self,
        producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
    ) -> Result<(), Evox2ScratchBuildRemotePreflightRunnerFault> {
        let timeout_millis = u32::try_from(producer_plan.timeout_ms).map_err(|_| {
            fault(
                Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidPlan,
                "producer timeout does not fit contained process",
            )
        })?;
        if self.profile != EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_RUNNER_PROFILE
            || self.producer_implementation_commit
                != EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_IMPLEMENTATION_COMMIT
            || self.producer_bookend_commit
                != EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_BOOKEND_COMMIT
            || self.producer_plan_sha256 != producer_plan.producer_plan_sha256
            || self.executable != producer_plan.executable_path
            || self.executable != EXECUTABLE_PATH
            || self.executable_sha256 != producer_plan.executable_sha256
            || self.arguments != producer_plan.argument_atoms
            || self.arguments.len() != producer_plan.argument_count as usize
            || self.working_directory != WORKING_DIRECTORY
            || self.environment != fixed_environment()
            || !self.stdin.is_empty()
            || self.maximum_stdout_bytes != producer_plan.stdout_limit_bytes as usize
            || self.maximum_stderr_bytes != producer_plan.stderr_limit_bytes as usize
            || self.timeout_millis != timeout_millis
            || self.maximum_active_processes != MAXIMUM_ACTIVE_PROCESSES
            || self.maximum_total_processes != MAXIMUM_TOTAL_PROCESSES
            || self.authority_disposition
                != EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_RUNNER_IMPLEMENTATION_AUTHORITY
            || self.live_invocation_authorized
        {
            return Err(fault(
                Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidPlan,
                "contained remote-preflight process correspondence differs",
            ));
        }
        Ok(())
    }
}

#[cfg(any(windows, test))]
trait Evox2ScratchBuildRemotePreflightBackend {
    fn observe_executable_sha256(&mut self, path: &str) -> Result<String, ()>;
    fn run_once(
        &mut self,
        spec: &Evox2ScratchBuildRemotePreflightContainedProcessSpec,
    ) -> Result<Evox2ScratchBuildRemotePreflightContainedProcessObservation, ()>;
}

#[cfg(test)]
pub(crate) fn run_evox2_scratch_build_remote_preflight_with_supplied_observation_for_private_bridge_test(
    permit: Evox2ScratchBuildRemotePreflightSingleUsePermit,
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
    observation: Evox2ScratchBuildRemotePreflightContainedProcessObservation,
) -> Result<Evox2ScratchBuildRemotePreflightRun, Evox2ScratchBuildRemotePreflightRunnerFault> {
    struct SuppliedObservationBackend {
        executable_sha256: String,
        observation: Option<Evox2ScratchBuildRemotePreflightContainedProcessObservation>,
    }
    impl Evox2ScratchBuildRemotePreflightBackend for SuppliedObservationBackend {
        fn observe_executable_sha256(&mut self, _path: &str) -> Result<String, ()> {
            Ok(self.executable_sha256.clone())
        }

        fn run_once(
            &mut self,
            _spec: &Evox2ScratchBuildRemotePreflightContainedProcessSpec,
        ) -> Result<Evox2ScratchBuildRemotePreflightContainedProcessObservation, ()> {
            self.observation.take().ok_or(())
        }
    }
    let mut backend = SuppliedObservationBackend {
        executable_sha256: producer_plan.executable_sha256.clone(),
        observation: Some(observation),
    };
    run_with_backend(permit, request, plan, program, producer_plan, &mut backend)
}

#[cfg(windows)]
struct WindowsRemotePreflightBackend;

#[cfg(windows)]
impl Evox2ScratchBuildRemotePreflightBackend for WindowsRemotePreflightBackend {
    fn observe_executable_sha256(&mut self, path: &str) -> Result<String, ()> {
        hash_bounded_regular_file(path)
    }

    fn run_once(
        &mut self,
        spec: &Evox2ScratchBuildRemotePreflightContainedProcessSpec,
    ) -> Result<Evox2ScratchBuildRemotePreflightContainedProcessObservation, ()> {
        let started = Instant::now();
        let mut observation = crate::self_work_update_broker_b1_cdrive_windows_containment::run_evox2_scratch_build_remote_preflight_contained_process(spec)
            .map_err(|_| ())?;
        observation.duration_ms = u64::try_from(started.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        Ok(observation)
    }
}

/// Execute the sealed physical backend once.
///
/// No public constructor exists for `Evox2ScratchBuildRemotePreflightSingleUsePermit`.
/// Its sole crate-private issuer consumes a live-admission type that has no
/// production constructor; until a separately governed live-initiation child
/// supplies one, this entry point remains structurally unreachable.
#[cfg(windows)]
pub fn run_evox2_scratch_build_remote_preflight_once(
    permit: Evox2ScratchBuildRemotePreflightSingleUsePermit,
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
) -> Result<Evox2ScratchBuildRemotePreflightRun, Evox2ScratchBuildRemotePreflightRunnerFault> {
    run_with_backend(
        permit,
        request,
        plan,
        program,
        producer_plan,
        &mut WindowsRemotePreflightBackend,
    )
}

pub fn validate_evox2_scratch_build_remote_preflight_run(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
    run: &Evox2ScratchBuildRemotePreflightRun,
) -> Result<(), Evox2ScratchBuildRemotePreflightRunnerFault> {
    validate_run_body(request, plan, program, producer_plan, run)?;
    if run.runner_receipt_sha256 != runner_receipt_digest(run)? {
        return Err(fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidReceipt,
            "runner receipt digest differs",
        ));
    }
    Ok(())
}

pub fn to_evox2_scratch_build_remote_preflight_run_machine_form(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
    run: &Evox2ScratchBuildRemotePreflightRun,
) -> Result<String, Evox2ScratchBuildRemotePreflightRunnerFault> {
    validate_evox2_scratch_build_remote_preflight_run(request, plan, program, producer_plan, run)?;
    serialize_bounded(run)
}

pub fn from_evox2_scratch_build_remote_preflight_run_machine_form(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
    value: &str,
) -> Result<Evox2ScratchBuildRemotePreflightRun, Evox2ScratchBuildRemotePreflightRunnerFault> {
    let run = strict_deserialize(value)?;
    validate_evox2_scratch_build_remote_preflight_run(request, plan, program, producer_plan, &run)?;
    Ok(run)
}

#[cfg(not(windows))]
pub fn run_evox2_scratch_build_remote_preflight_once(
    permit: Evox2ScratchBuildRemotePreflightSingleUsePermit,
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
) -> Result<Evox2ScratchBuildRemotePreflightRun, Evox2ScratchBuildRemotePreflightRunnerFault> {
    verify_evox2_scratch_build_remote_preflight_producer_plan(
        request,
        plan,
        program,
        producer_plan,
    )
    .map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidPlan,
            "producer plan refused before platform selection",
        )
    })?;
    validate_permit(&permit, producer_plan)?;
    Err(fault(
        Evox2ScratchBuildRemotePreflightRunnerFaultCode::PlatformUnavailable,
        "remote-preflight contained process is available only on Windows",
    ))
}

#[cfg(any(windows, test))]
fn run_with_backend<B: Evox2ScratchBuildRemotePreflightBackend>(
    permit: Evox2ScratchBuildRemotePreflightSingleUsePermit,
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
    backend: &mut B,
) -> Result<Evox2ScratchBuildRemotePreflightRun, Evox2ScratchBuildRemotePreflightRunnerFault> {
    verify_evox2_scratch_build_remote_preflight_producer_plan(
        request,
        plan,
        program,
        producer_plan,
    )
    .map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidPlan,
            "producer plan refused before physical observation",
        )
    })?;
    validate_permit(&permit, producer_plan)?;
    let spec = expected_spec(producer_plan)?;
    spec.validate_against(producer_plan)?;

    let executable_sha256_before = backend
        .observe_executable_sha256(&spec.executable)
        .map_err(|_| {
            fault(
                Evox2ScratchBuildRemotePreflightRunnerFaultCode::ExecutableObservation,
                "pre-run executable observation failed",
            )
        })?;
    if executable_sha256_before != producer_plan.executable_sha256 {
        return Err(fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::ExecutableMismatch,
            "pre-run executable identity differs",
        ));
    }

    let raw = backend.run_once(&spec).map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::ProcessFailure,
            "contained process failed",
        )
    })?;
    let executable_sha256_after = backend
        .observe_executable_sha256(&spec.executable)
        .map_err(|_| {
            fault(
                Evox2ScratchBuildRemotePreflightRunnerFaultCode::ExecutableObservation,
                "post-run executable observation failed",
            )
        })?;
    if executable_sha256_after != executable_sha256_before
        || executable_sha256_after != producer_plan.executable_sha256
    {
        return Err(fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::ExecutableMismatch,
            "post-run executable identity differs",
        ));
    }

    validate_raw_observation(&raw, producer_plan)?;
    let stdout = String::from_utf8(raw.stdout.clone()).map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::ProcessObservation,
            "process stdout is not UTF-8",
        )
    })?;
    let stderr = String::from_utf8(raw.stderr.clone()).map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::ProcessObservation,
            "process stderr is not UTF-8",
        )
    })?;
    let probe = from_evox2_scratch_build_remote_probe_result_machine_form(request, &stdout)
        .map_err(|_| {
            fault(
                Evox2ScratchBuildRemotePreflightRunnerFaultCode::ProcessObservation,
                "process stdout is not the canonical remote probe",
            )
        })?;
    let exit_code = i32::try_from(raw.exit_code).map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::ProcessObservation,
            "process exit code does not fit the producer record",
        )
    })?;
    let stdout_bytes = u32::try_from(raw.stdout.len()).map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::ProcessObservation,
            "process stdout byte count overflows",
        )
    })?;
    let stderr_bytes = u32::try_from(raw.stderr.len()).map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::ProcessObservation,
            "process stderr byte count overflows",
        )
    })?;
    let process_record = seal_evox2_scratch_build_remote_preflight_process_record(
        request,
        plan,
        program,
        producer_plan,
        Evox2ScratchBuildRemotePreflightProcessRecord {
            profile: EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PROCESS_RECORD_PROFILE.to_owned(),
            producer_plan_sha256: producer_plan.producer_plan_sha256.clone(),
            executable_path: producer_plan.executable_path.clone(),
            executable_sha256: producer_plan.executable_sha256.clone(),
            argument_atoms: producer_plan.argument_atoms.clone(),
            argument_count: producer_plan.argument_count,
            evidence_class: "live_process_observation".to_owned(),
            started: true,
            completed: true,
            exit_code,
            duration_ms: raw.duration_ms,
            timed_out: false,
            stdout,
            stdout_bytes,
            stdout_sha256: sha256(&raw.stdout),
            stdout_truncated: false,
            stderr,
            stderr_bytes,
            stderr_sha256: sha256(&raw.stderr),
            stderr_truncated: false,
            probe,
            remote_contact_made: true,
            provider_requests: 0,
            remote_calls: 1,
            effects: 1,
            process_record_sha256: String::new(),
        },
    )
    .map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::ProducerRefusal,
            "producer refused the retained process record",
        )
    })?;
    let observation = compile_evox2_scratch_build_remote_preflight_observation_from_process_record(
        request,
        plan,
        program,
        producer_plan,
        &process_record,
    )
    .map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::ProducerRefusal,
            "producer refused observation compilation",
        )
    })?;
    let verification = verify_evox2_scratch_build_remote_preflight_producer(
        request,
        plan,
        program,
        producer_plan,
        &process_record,
        &observation,
    )
    .map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::ProducerRefusal,
            "producer verification refused the compiled observation",
        )
    })?;

    let mut run = Evox2ScratchBuildRemotePreflightRun {
        profile: EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_RUNNER_PROFILE.to_owned(),
        producer_implementation_commit:
            EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_IMPLEMENTATION_COMMIT.to_owned(),
        producer_bookend_commit: EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_BOOKEND_COMMIT
            .to_owned(),
        executable_sha256_before,
        executable_sha256_after,
        process_record,
        observation,
        verification,
        total_processes: raw.total_processes,
        active_processes_at_terminal: raw.active_processes_at_terminal,
        resume_previous_count: raw.resume_previous_count,
        execution_disposition: "single_use_permit_consumed_after_published_contract_replay"
            .to_owned(),
        single_use_permit_consumed: true,
        provider_requests: 0,
        remote_calls: 1,
        effects: 1,
        runner_receipt_sha256: String::new(),
    };
    validate_run_body(request, plan, program, producer_plan, &run)?;
    run.runner_receipt_sha256 = runner_receipt_digest(&run)?;
    validate_evox2_scratch_build_remote_preflight_run(request, plan, program, producer_plan, &run)?;
    Ok(run)
}

fn validate_permit(
    permit: &Evox2ScratchBuildRemotePreflightSingleUsePermit,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
) -> Result<(), Evox2ScratchBuildRemotePreflightRunnerFault> {
    if permit.producer_plan_sha256 != producer_plan.producer_plan_sha256
        || permit.producer_implementation_commit
            != EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_IMPLEMENTATION_COMMIT
        || permit.producer_bookend_commit
            != EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_BOOKEND_COMMIT
    {
        return Err(fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidPermit,
            "single-use permit correspondence differs",
        ));
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn expected_spec(
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
) -> Result<
    Evox2ScratchBuildRemotePreflightContainedProcessSpec,
    Evox2ScratchBuildRemotePreflightRunnerFault,
> {
    Ok(Evox2ScratchBuildRemotePreflightContainedProcessSpec {
        profile: EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_RUNNER_PROFILE.to_owned(),
        producer_implementation_commit:
            EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_IMPLEMENTATION_COMMIT.to_owned(),
        producer_bookend_commit: EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_BOOKEND_COMMIT
            .to_owned(),
        producer_plan_sha256: producer_plan.producer_plan_sha256.clone(),
        executable: producer_plan.executable_path.clone(),
        executable_sha256: producer_plan.executable_sha256.clone(),
        arguments: producer_plan.argument_atoms.clone(),
        working_directory: WORKING_DIRECTORY.to_owned(),
        environment: fixed_environment(),
        stdin: Vec::new(),
        maximum_stdout_bytes: producer_plan.stdout_limit_bytes as usize,
        maximum_stderr_bytes: producer_plan.stderr_limit_bytes as usize,
        timeout_millis: u32::try_from(producer_plan.timeout_ms).map_err(|_| {
            fault(
                Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidPlan,
                "producer timeout does not fit contained process",
            )
        })?,
        maximum_active_processes: MAXIMUM_ACTIVE_PROCESSES,
        maximum_total_processes: MAXIMUM_TOTAL_PROCESSES,
        authority_disposition: EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_RUNNER_IMPLEMENTATION_AUTHORITY
            .to_owned(),
        live_invocation_authorized: false,
    })
}

#[cfg(any(windows, test))]
fn validate_raw_observation(
    raw: &Evox2ScratchBuildRemotePreflightContainedProcessObservation,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
) -> Result<(), Evox2ScratchBuildRemotePreflightRunnerFault> {
    if raw.exit_code != 0
        || raw.stdout.is_empty()
        || raw.stdout.len() > producer_plan.stdout_limit_bytes as usize
        || !raw.stderr.is_empty()
        || raw.stderr.len() > producer_plan.stderr_limit_bytes as usize
        || raw.stdout_observed_bytes != raw.stdout.len() as u64
        || raw.stderr_observed_bytes != raw.stderr.len() as u64
        || raw.stdout_over_bound
        || raw.stderr_over_bound
        || raw.forced_termination
        || raw.total_processes != MAXIMUM_TOTAL_PROCESSES
        || raw.active_processes_at_terminal != 0
        || raw.resume_previous_count != 1
        || raw.duration_ms == 0
        || raw.duration_ms > producer_plan.timeout_ms
    {
        return Err(fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::ProcessObservation,
            "contained process observation differs",
        ));
    }
    Ok(())
}

fn validate_run_body(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
    run: &Evox2ScratchBuildRemotePreflightRun,
) -> Result<(), Evox2ScratchBuildRemotePreflightRunnerFault> {
    verify_evox2_scratch_build_remote_preflight_producer_plan(
        request,
        plan,
        program,
        producer_plan,
    )
    .map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidReceipt,
            "runner receipt producer plan differs",
        )
    })?;
    validate_evox2_scratch_build_remote_preflight_process_record(
        request,
        plan,
        program,
        producer_plan,
        &run.process_record,
    )
    .map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidReceipt,
            "runner receipt process record differs",
        )
    })?;
    let expected_observation =
        compile_evox2_scratch_build_remote_preflight_observation_from_process_record(
            request,
            plan,
            program,
            producer_plan,
            &run.process_record,
        )
        .map_err(|_| {
            fault(
                Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidReceipt,
                "runner receipt observation cannot be reconstructed",
            )
        })?;
    let expected_verification = verify_evox2_scratch_build_remote_preflight_producer(
        request,
        plan,
        program,
        producer_plan,
        &run.process_record,
        &run.observation,
    )
    .map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidReceipt,
            "runner receipt producer verification differs",
        )
    })?;
    if run.profile != EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_RUNNER_PROFILE
        || run.producer_implementation_commit
            != EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_IMPLEMENTATION_COMMIT
        || run.producer_bookend_commit
            != EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_BOOKEND_COMMIT
        || run.executable_sha256_before != producer_plan.executable_sha256
        || run.executable_sha256_after != producer_plan.executable_sha256
        || run.observation != expected_observation
        || run.verification != expected_verification
        || run.total_processes != MAXIMUM_TOTAL_PROCESSES
        || run.active_processes_at_terminal != 0
        || run.resume_previous_count != 1
        || run.execution_disposition != "single_use_permit_consumed_after_published_contract_replay"
        || !run.single_use_permit_consumed
        || run.provider_requests != 0
        || run.remote_calls != 1
        || run.effects != 1
        || (!run.runner_receipt_sha256.is_empty() && !is_lower_hex(&run.runner_receipt_sha256, 64))
    {
        return Err(fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidReceipt,
            "runner receipt correspondence differs",
        ));
    }
    Ok(())
}

fn fixed_environment() -> Vec<(String, String)> {
    vec![
        (
            "PATH".to_owned(),
            r"C:\Windows\System32\OpenSSH;C:\Windows\System32;C:\Windows".to_owned(),
        ),
        ("PATHEXT".to_owned(), ".COM;.EXE;.BAT;.CMD".to_owned()),
        ("SYSTEMROOT".to_owned(), r"C:\Windows".to_owned()),
        ("TEMP".to_owned(), r"C:\Windows\Temp".to_owned()),
        ("TMP".to_owned(), r"C:\Windows\Temp".to_owned()),
        ("WINDIR".to_owned(), r"C:\Windows".to_owned()),
    ]
}

#[cfg(windows)]
fn hash_bounded_regular_file(path: &str) -> Result<String, ()> {
    if path != EXECUTABLE_PATH {
        return Err(());
    }
    let path = Path::new(path);
    let before = fs::symlink_metadata(path).map_err(|_| ())?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.len() == 0
        || before.len() > MAXIMUM_EXECUTABLE_BYTES
    {
        return Err(());
    }
    let mut file = File::open(path).map_err(|_| ())?;
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; 65_536];
    loop {
        let count = file.read(&mut buffer).map_err(|_| ())?;
        if count == 0 {
            break;
        }
        observed = observed.checked_add(count as u64).ok_or(())?;
        if observed > MAXIMUM_EXECUTABLE_BYTES {
            return Err(());
        }
        hasher.update(&buffer[..count]);
    }
    let after = fs::symlink_metadata(path).map_err(|_| ())?;
    if after.file_type().is_symlink()
        || !after.is_file()
        || observed != before.len()
        || observed != after.len()
    {
        return Err(());
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(any(windows, test))]
fn sha256(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn runner_receipt_digest(
    run: &Evox2ScratchBuildRemotePreflightRun,
) -> Result<String, Evox2ScratchBuildRemotePreflightRunnerFault> {
    let mut unsigned = run.clone();
    unsigned.runner_receipt_sha256.clear();
    let encoded = serde_json::to_vec(&unsigned).map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidMachineForm,
            "runner receipt serialization failed",
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(RUNNER_RECEIPT_DIGEST_DOMAIN);
    hasher.update(encoded);
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn strict_deserialize<T>(value: &str) -> Result<T, Evox2ScratchBuildRemotePreflightRunnerFault>
where
    T: DeserializeOwned + Serialize,
{
    if value.is_empty() || value.len() > MAXIMUM_MACHINE_BYTES {
        return Err(fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidMachineForm,
            "runner machine-form byte bound differs",
        ));
    }
    let parsed: T = serde_json::from_str(value).map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidMachineForm,
            "runner machine-form decode failed",
        )
    })?;
    if serde_json::to_string(&parsed).map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidMachineForm,
            "runner machine-form encode failed",
        )
    })? != value
    {
        return Err(fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidMachineForm,
            "runner machine form is not canonical",
        ));
    }
    Ok(parsed)
}

fn serialize_bounded<T: Serialize>(
    value: &T,
) -> Result<String, Evox2ScratchBuildRemotePreflightRunnerFault> {
    let encoded = serde_json::to_string(value).map_err(|_| {
        fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidMachineForm,
            "runner machine-form encode failed",
        )
    })?;
    if encoded.len() > MAXIMUM_MACHINE_BYTES {
        return Err(fault(
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidMachineForm,
            "runner machine-form byte bound differs",
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
    code: Evox2ScratchBuildRemotePreflightRunnerFaultCode,
    detail: &'static str,
) -> Evox2ScratchBuildRemotePreflightRunnerFault {
    Evox2ScratchBuildRemotePreflightRunnerFault { code, detail }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cantor_core::{
        EVOX2_SCRATCH_BUILD_REMOTE_PROBE_RESULT_PROFILE,
        compile_evox2_scratch_build_controller_plan, compile_evox2_scratch_build_effect_program,
        compile_evox2_scratch_build_remote_preflight_producer_plan,
        fixed_evox2_scratch_build_controller_request, seal_evox2_scratch_build_remote_probe_result,
        to_evox2_scratch_build_remote_probe_result_machine_form,
    };

    struct MockBackend {
        hashes: Vec<String>,
        observation: Option<Evox2ScratchBuildRemotePreflightContainedProcessObservation>,
        observations: usize,
        calls: usize,
        mutate_spec: Option<fn(&mut Evox2ScratchBuildRemotePreflightContainedProcessSpec)>,
    }

    impl Evox2ScratchBuildRemotePreflightBackend for MockBackend {
        fn observe_executable_sha256(&mut self, _path: &str) -> Result<String, ()> {
            let value = self.hashes.get(self.observations).cloned().ok_or(())?;
            self.observations += 1;
            Ok(value)
        }

        fn run_once(
            &mut self,
            spec: &Evox2ScratchBuildRemotePreflightContainedProcessSpec,
        ) -> Result<Evox2ScratchBuildRemotePreflightContainedProcessObservation, ()> {
            self.calls += 1;
            let mut supplied = spec.clone();
            if let Some(mutate) = self.mutate_spec {
                mutate(&mut supplied);
            }
            supplied.validate_against(&fixture().3).map_err(|_| ())?;
            self.observation.take().ok_or(())
        }
    }

    fn fixture() -> (
        Evox2ScratchBuildControllerRequest,
        Evox2ScratchBuildControllerPlan,
        Evox2ScratchBuildEffectProgram,
        Evox2ScratchBuildRemotePreflightProducerPlan,
    ) {
        let request = fixed_evox2_scratch_build_controller_request(
            "be7bbaed-4b3f-4d54-8d7b-8f060f96630d",
            "1111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222",
        )
        .unwrap();
        let plan = compile_evox2_scratch_build_controller_plan(&request).unwrap();
        let program = compile_evox2_scratch_build_effect_program(&request, &plan).unwrap();
        let producer = compile_evox2_scratch_build_remote_preflight_producer_plan(
            &request,
            &plan,
            &program,
            &"a".repeat(64),
        )
        .unwrap();
        (request, plan, program, producer)
    }

    fn permit(
        producer: &Evox2ScratchBuildRemotePreflightProducerPlan,
    ) -> Evox2ScratchBuildRemotePreflightSingleUsePermit {
        Evox2ScratchBuildRemotePreflightSingleUsePermit {
            producer_plan_sha256: producer.producer_plan_sha256.clone(),
            producer_implementation_commit:
                EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_IMPLEMENTATION_COMMIT.to_owned(),
            producer_bookend_commit: EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PRODUCER_BOOKEND_COMMIT
                .to_owned(),
        }
    }

    fn observation(
        request: &Evox2ScratchBuildControllerRequest,
        available: bool,
    ) -> Evox2ScratchBuildRemotePreflightContainedProcessObservation {
        let probe = seal_evox2_scratch_build_remote_probe_result(
            request,
            cantor_core::Evox2ScratchBuildRemoteProbeResult {
                profile: EVOX2_SCRATCH_BUILD_REMOTE_PROBE_RESULT_PROFILE.to_owned(),
                run_uuid: request.run_uuid.clone(),
                request_sha256: request.request_sha256.clone(),
                target_host: request.target_host.clone(),
                provider_listener: "127.0.0.1:8081".to_owned(),
                provider_model_path:
                    "C:/AI/models/validation/Qwen3.5-0.8B-GGUF/Qwen3.5-0.8B-Q4_0.gguf".to_owned(),
                listener_observed: available,
                model_observed: available,
                provider_status: if available {
                    "available"
                } else {
                    "unavailable"
                }
                .to_owned(),
                reason: if available {
                    "preflight_satisfied"
                } else {
                    "provider_unavailable_before_commission"
                }
                .to_owned(),
                probe_sha256: String::new(),
            },
        )
        .unwrap();
        let stdout = to_evox2_scratch_build_remote_probe_result_machine_form(request, &probe)
            .unwrap()
            .into_bytes();
        Evox2ScratchBuildRemotePreflightContainedProcessObservation {
            exit_code: 0,
            stdout_observed_bytes: stdout.len() as u64,
            stderr_observed_bytes: 0,
            stdout,
            stderr: Vec::new(),
            stdout_over_bound: false,
            stderr_over_bound: false,
            forced_termination: false,
            total_processes: 1,
            active_processes_at_terminal: 0,
            resume_previous_count: 1,
            duration_ms: 7,
        }
    }

    fn mock_backend(request: &Evox2ScratchBuildControllerRequest) -> MockBackend {
        MockBackend {
            hashes: vec!["a".repeat(64), "a".repeat(64)],
            observation: Some(observation(request, false)),
            observations: 0,
            calls: 0,
            mutate_spec: None,
        }
    }

    fn available_mock_backend(request: &Evox2ScratchBuildControllerRequest) -> MockBackend {
        MockBackend {
            observation: Some(observation(request, true)),
            ..mock_backend(request)
        }
    }

    #[test]
    fn exact_mock_run_calls_one_process_and_replays_the_published_producer() {
        let (request, plan, program, producer) = fixture();
        let mut backend = mock_backend(&request);
        let result = run_with_backend(
            permit(&producer),
            &request,
            &plan,
            &program,
            &producer,
            &mut backend,
        )
        .unwrap();
        assert_eq!(backend.observations, 2);
        assert_eq!(backend.calls, 1);
        assert_eq!(result.process_record.remote_calls, 1);
        assert_eq!(result.process_record.effects, 1);
        assert_eq!(result.verification.status, "passed");
        assert_eq!(result.observation.probe.provider_status, "unavailable");
        assert!(!result.verification.remote_contact_authorized);
    }

    #[test]
    fn available_mock_probe_replays_without_performing_a_provider_request() {
        let (request, plan, program, producer) = fixture();
        let mut backend = available_mock_backend(&request);
        let result = run_with_backend(
            permit(&producer),
            &request,
            &plan,
            &program,
            &producer,
            &mut backend,
        )
        .unwrap();
        assert_eq!(result.observation.probe.provider_status, "available");
        assert_eq!(result.observation.probe.reason, "preflight_satisfied");
        assert_eq!(result.provider_requests, 0);
        assert_eq!((backend.observations, backend.calls), (2, 1));
    }

    #[test]
    fn canonical_runner_receipt_replays_and_refuses_machine_form_or_digest_tamper() {
        let (request, plan, program, producer) = fixture();
        let mut backend = mock_backend(&request);
        let result = run_with_backend(
            permit(&producer),
            &request,
            &plan,
            &program,
            &producer,
            &mut backend,
        )
        .unwrap();
        let machine = to_evox2_scratch_build_remote_preflight_run_machine_form(
            &request, &plan, &program, &producer, &result,
        )
        .unwrap();
        assert_eq!(
            from_evox2_scratch_build_remote_preflight_run_machine_form(
                &request, &plan, &program, &producer, &machine,
            )
            .unwrap(),
            result
        );
        let unknown = machine.replacen("{", "{\"unknown\":true,", 1);
        assert!(
            from_evox2_scratch_build_remote_preflight_run_machine_form(
                &request, &plan, &program, &producer, &unknown,
            )
            .is_err()
        );
        let mut changed = result.clone();
        changed.runner_receipt_sha256 = "0".repeat(64);
        assert!(
            validate_evox2_scratch_build_remote_preflight_run(
                &request, &plan, &program, &producer, &changed,
            )
            .is_err()
        );
        let noncanonical = serde_json::to_string_pretty(&result).unwrap();
        assert!(
            from_evox2_scratch_build_remote_preflight_run_machine_form(
                &request,
                &plan,
                &program,
                &producer,
                &noncanonical,
            )
            .is_err()
        );
    }

    #[test]
    fn invalid_plan_or_permit_refuses_before_executable_or_process_observation() {
        let (request, plan, program, mut producer) = fixture();
        let valid_permit = permit(&producer);
        producer.argument_atoms.swap(0, 1);
        let mut backend = mock_backend(&request);
        assert_eq!(
            run_with_backend(
                valid_permit,
                &request,
                &plan,
                &program,
                &producer,
                &mut backend
            )
            .unwrap_err()
            .code,
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidPlan
        );
        assert_eq!((backend.observations, backend.calls), (0, 0));

        let (request, plan, program, producer) = fixture();
        let mut invalid_permit = permit(&producer);
        invalid_permit.producer_bookend_commit = "0".repeat(40);
        let mut backend = mock_backend(&request);
        assert_eq!(
            run_with_backend(
                invalid_permit,
                &request,
                &plan,
                &program,
                &producer,
                &mut backend,
            )
            .unwrap_err()
            .code,
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::InvalidPermit
        );
        assert_eq!((backend.observations, backend.calls), (0, 0));
    }

    #[test]
    fn pre_run_executable_mismatch_refuses_before_the_only_process_call() {
        let (request, plan, program, producer) = fixture();
        let mut backend = mock_backend(&request);
        backend.hashes[0] = "b".repeat(64);
        assert_eq!(
            run_with_backend(
                permit(&producer),
                &request,
                &plan,
                &program,
                &producer,
                &mut backend,
            )
            .unwrap_err()
            .code,
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::ExecutableMismatch
        );
        assert_eq!((backend.observations, backend.calls), (1, 0));
    }

    #[test]
    fn post_run_executable_drift_refuses_after_exactly_one_process_call() {
        let (request, plan, program, producer) = fixture();
        let mut backend = mock_backend(&request);
        backend.hashes[1] = "b".repeat(64);
        assert_eq!(
            run_with_backend(
                permit(&producer),
                &request,
                &plan,
                &program,
                &producer,
                &mut backend,
            )
            .unwrap_err()
            .code,
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::ExecutableMismatch
        );
        assert_eq!((backend.observations, backend.calls), (2, 1));
    }

    #[test]
    fn timeout_overflow_exit_stderr_utf8_and_process_accounts_refuse() {
        let mutations: [fn(&mut Evox2ScratchBuildRemotePreflightContainedProcessObservation); 13] = [
            |value| value.forced_termination = true,
            |value| value.stdout_over_bound = true,
            |value| value.stderr_over_bound = true,
            |value| value.exit_code = 1,
            |value| {
                value.stderr = b"fault".to_vec();
                value.stderr_observed_bytes = 5;
            },
            |value| {
                value.stdout = vec![0xff];
                value.stdout_observed_bytes = 1;
            },
            |value| value.stdout_observed_bytes += 1,
            |value| {
                value.stdout.push(b'\n');
                value.stdout_observed_bytes += 1;
            },
            |value| value.total_processes = 2,
            |value| value.active_processes_at_terminal = 1,
            |value| value.resume_previous_count = 0,
            |value| value.duration_ms = 0,
            |value| value.duration_ms = 30_001,
        ];
        for mutate in mutations {
            let (request, plan, program, producer) = fixture();
            let mut backend = mock_backend(&request);
            mutate(backend.observation.as_mut().unwrap());
            assert_eq!(
                run_with_backend(
                    permit(&producer),
                    &request,
                    &plan,
                    &program,
                    &producer,
                    &mut backend,
                )
                .unwrap_err()
                .code,
                Evox2ScratchBuildRemotePreflightRunnerFaultCode::ProcessObservation
            );
            assert_eq!((backend.observations, backend.calls), (2, 1));
        }
    }

    #[test]
    fn every_contained_process_coordinate_is_closed() {
        let (_, _, _, producer) = fixture();
        let base = expected_spec(&producer).unwrap();
        let mutations: [fn(&mut Evox2ScratchBuildRemotePreflightContainedProcessSpec); 15] = [
            |value| value.profile.push('x'),
            |value| value.producer_implementation_commit = "0".repeat(40),
            |value| value.producer_bookend_commit = "0".repeat(40),
            |value| value.producer_plan_sha256 = "0".repeat(64),
            |value| value.executable.push('x'),
            |value| value.executable_sha256 = "b".repeat(64),
            |value| value.arguments.swap(0, 1),
            |value| value.working_directory.push('x'),
            |value| value.environment.swap(0, 1),
            |value| value.stdin.push(0),
            |value| value.maximum_stdout_bytes -= 1,
            |value| value.maximum_stderr_bytes -= 1,
            |value| value.timeout_millis -= 1,
            |value| value.maximum_active_processes += 1,
            |value| value.live_invocation_authorized = true,
        ];
        for mutate in mutations {
            let mut changed = base.clone();
            mutate(&mut changed);
            assert!(changed.validate_against(&producer).is_err());
        }
        let mut changed = base.clone();
        changed.maximum_total_processes += 1;
        assert!(changed.validate_against(&producer).is_err());
        let mut changed = base;
        changed.authority_disposition.push('x');
        assert!(changed.validate_against(&producer).is_err());
    }

    #[test]
    fn backend_spec_drift_is_refused_without_substituting_the_process() {
        let (request, plan, program, producer) = fixture();
        let mut backend = mock_backend(&request);
        backend.mutate_spec = Some(|spec| spec.arguments.swap(0, 1));
        assert_eq!(
            run_with_backend(
                permit(&producer),
                &request,
                &plan,
                &program,
                &producer,
                &mut backend,
            )
            .unwrap_err()
            .code,
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::ProcessFailure
        );
        assert_eq!((backend.observations, backend.calls), (1, 1));
    }

    #[test]
    fn backend_stage_failures_retain_exact_call_boundaries() {
        let (request, plan, program, producer) = fixture();
        let mut before_failure = mock_backend(&request);
        before_failure.hashes.clear();
        assert_eq!(
            run_with_backend(
                permit(&producer),
                &request,
                &plan,
                &program,
                &producer,
                &mut before_failure,
            )
            .unwrap_err()
            .code,
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::ExecutableObservation
        );
        assert_eq!((before_failure.observations, before_failure.calls), (0, 0));

        let mut process_failure = mock_backend(&request);
        process_failure.observation = None;
        assert_eq!(
            run_with_backend(
                permit(&producer),
                &request,
                &plan,
                &program,
                &producer,
                &mut process_failure,
            )
            .unwrap_err()
            .code,
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::ProcessFailure
        );
        assert_eq!(
            (process_failure.observations, process_failure.calls),
            (1, 1)
        );

        let mut after_failure = mock_backend(&request);
        after_failure.hashes.pop();
        assert_eq!(
            run_with_backend(
                permit(&producer),
                &request,
                &plan,
                &program,
                &producer,
                &mut after_failure,
            )
            .unwrap_err()
            .code,
            Evox2ScratchBuildRemotePreflightRunnerFaultCode::ExecutableObservation
        );
        assert_eq!((after_failure.observations, after_failure.calls), (1, 1));
    }
}
