//! Pure, provider-free compilation of an inert EVO-X2 Cantor build plan.
//!
//! The compiler accepts one exact bounded request and returns declarative data.
//! It performs no filesystem, process, environment, clock, network, provider,
//! model, service, workspace, toolchain, Cargo, or Git operation.

use std::collections::BTreeSet;
use std::fmt;

use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const EVOX2_BUILD_PLAN_PROFILE: &str = "cantor-evox2-plan-only-build-job/0.1";
pub const EVOX2_BUILD_PLAN_VERIFICATION_PROFILE: &str =
    "cantor-evox2-plan-only-build-job-verification/0.1";
pub const EVOX2_BUILD_PLAN_CANONICAL_UUID: &str = "3482e2ce-817c-4788-b185-35adaad414f7";
pub const EVOX2_BUILD_PLAN_SIGNATURE_UUID: &str = "58968a69-538e-43ee-85db-3401765d1fd4";
pub const EVOX2_BUILD_PLAN_PREDECESSOR_CANONICAL_UUID: &str =
    "4cf12917-73e8-4505-9228-f94d981143bd";
pub const EVOX2_BUILD_PLAN_PREDECESSOR_BOOKEND_COMMIT: &str =
    "d805681daee0d6846574875e25b6e1e41c9207bc";
pub const EVOX2_BUILD_PLAN_REPOSITORY_REMOTE: &str = "https://github.com/cattailfarmer/Cantor";
pub const EVOX2_BUILD_PLAN_TARGET_HOST: &str = "EVO-X2";
pub const EVOX2_BUILD_PLAN_TARGET_OS: &str = "windows-x86_64";
pub const EVOX2_BUILD_PLAN_CARGO_PROFILE: &str = "locked-offline-serialized/0.1";
pub const EVOX2_BUILD_PLAN_MAX_REQUEST_BYTES: usize = 65_536;
pub const EVOX2_BUILD_PLAN_MAX_PLAN_BYTES: usize = 1_048_576;
pub const EVOX2_BUILD_PLAN_MAX_ARCHIVE_BYTES: u64 = 536_870_912;
pub const EVOX2_BUILD_PLAN_MAX_FILES: u32 = 32_768;
pub const EVOX2_BUILD_PLAN_MAX_TIMEOUT_SECONDS: u32 = 14_400;

const REQUEST_DIGEST_DOMAIN: &[u8] = b"cantor.evox2-plan-only-build-job.request.v1\0";
const PLAN_DIGEST_DOMAIN: &[u8] = b"cantor.evox2-plan-only-build-job.plan.v1\0";
const PLAN_UUID_DOMAIN: &[u8] = b"cantor.evox2-plan-only-build-job.plan-uuid.v1\0";
const MAX_TEXT_BYTES: usize = 512;
const MAX_ARGUMENTS: usize = 32;
const MAX_ARGUMENT_BYTES: usize = 128;

const REQUESTED_CHECKS: [&str; 4] = [
    "workspace_debug",
    "workspace_release",
    "workspace_clippy",
    "workspace_format",
];

const AUTHORITY_DENIALS: [&str; 15] = [
    "source_transfer",
    "source_extract",
    "toolchain_observe",
    "toolchain_install",
    "dependency_fetch",
    "workspace_write",
    "process_execute",
    "git_mutation",
    "commit",
    "push",
    "provider_call",
    "model_inference",
    "service_change",
    "external_network",
    "security_policy_change",
];

const EXPECTED_EVIDENCE: [&str; 7] = [
    "archive_verification",
    "workspace_materialization",
    "debug_results",
    "release_results",
    "clippy_results",
    "format_results",
    "sealed_build_receipt",
];

const UNRESOLVED: [&str; 5] = [
    "source_not_transferred",
    "workspace_not_created",
    "toolchain_not_observed",
    "commands_not_executed",
    "performance_not_measured",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2BuildPlanBounds {
    pub maximum_archive_bytes: u64,
    pub maximum_files: u32,
    pub maximum_stdout_bytes: u32,
    pub maximum_operation_count: u32,
    pub timeout_seconds: u32,
    pub cargo_build_jobs: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2BuildPlanRequest {
    pub profile: String,
    pub request_uuid: String,
    pub predecessor_canonical_uuid: String,
    pub predecessor_bookend_commit: String,
    pub source_commit: String,
    pub source_archive_sha256: String,
    pub repository_remote_ref: String,
    pub target_host: String,
    pub target_os: String,
    pub future_workspace_root: String,
    pub future_target_root: String,
    pub cargo_profile: String,
    pub requested_checks: Vec<String>,
    pub bounds: Evox2BuildPlanBounds,
    pub authority_denials: Vec<String>,
    pub request_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
pub struct Evox2BuildPlanCargoEnvironment {
    pub CARGO_NET_OFFLINE: bool,
    pub CARGO_BUILD_JOBS: u32,
    pub CARGO_INCREMENTAL: u32,
    pub RUST_TEST_THREADS: u32,
    pub RUST_MIN_STACK: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2BuildPlanOperation {
    pub ordinal: u32,
    pub kind: String,
    pub executable_identity: String,
    pub arguments: Vec<String>,
    pub working_directory: String,
    pub input_identities: Vec<String>,
    pub output_identities: Vec<String>,
    pub dependencies: Vec<u32>,
    pub preconditions: Vec<String>,
    pub authority_required: String,
    pub authority_denials: Vec<String>,
    pub expected_evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2BuildPlan {
    pub profile: String,
    pub plan_uuid: String,
    pub request_uuid: String,
    pub predecessor_canonical_uuid: String,
    pub predecessor_bookend_commit: String,
    pub source_commit: String,
    pub source_archive_sha256: String,
    pub target_host: String,
    pub target_os: String,
    pub future_workspace_root: String,
    pub future_target_root: String,
    pub cargo_environment: Evox2BuildPlanCargoEnvironment,
    pub operations: Vec<Evox2BuildPlanOperation>,
    pub operation_count: u32,
    pub expected_evidence: Vec<String>,
    pub authority_grants: Vec<String>,
    pub authority_denials: Vec<String>,
    pub unresolved: Vec<String>,
    pub disposition: String,
    pub plan_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2BuildPlanVerification {
    pub profile: String,
    pub status: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub request_uuid: String,
    pub plan_uuid: String,
    pub request_sha256: String,
    pub plan_sha256: String,
    pub operation_count: u32,
    pub authority_denial_count: u32,
    pub authority_grant_count: u32,
    pub unresolved_count: u32,
    pub byte_identical_recompilation: bool,
    pub effects: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evox2BuildPlanFaultCode {
    InvalidMachineForm,
    InvalidProfile,
    InvalidIdentity,
    InvalidDigest,
    InvalidBound,
    InvalidRequest,
    InvalidPath,
    InvalidOperation,
    InvalidDependency,
    InvalidAuthority,
    InvalidVerification,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evox2BuildPlanFault {
    pub code: Evox2BuildPlanFaultCode,
    pub detail: &'static str,
}

impl fmt::Display for Evox2BuildPlanFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Evox2BuildPlanFault {}

pub fn evox2_build_plan_requested_checks() -> Vec<String> {
    REQUESTED_CHECKS
        .iter()
        .map(|value| (*value).to_owned())
        .collect()
}

pub fn evox2_build_plan_authority_denials() -> Vec<String> {
    AUTHORITY_DENIALS
        .iter()
        .map(|value| (*value).to_owned())
        .collect()
}

pub fn evox2_build_plan_expected_evidence() -> Vec<String> {
    EXPECTED_EVIDENCE
        .iter()
        .map(|value| (*value).to_owned())
        .collect()
}

pub fn evox2_build_plan_unresolved() -> Vec<String> {
    UNRESOLVED.iter().map(|value| (*value).to_owned()).collect()
}

pub fn synthetic_evox2_build_plan_request() -> Evox2BuildPlanRequest {
    seal_evox2_build_plan_request(Evox2BuildPlanRequest {
        profile: EVOX2_BUILD_PLAN_PROFILE.to_owned(),
        request_uuid: "b1f2596f-2db8-40ea-8cb1-7bb85ba7f001".to_owned(),
        predecessor_canonical_uuid: EVOX2_BUILD_PLAN_PREDECESSOR_CANONICAL_UUID.to_owned(),
        predecessor_bookend_commit: EVOX2_BUILD_PLAN_PREDECESSOR_BOOKEND_COMMIT.to_owned(),
        source_commit: "1111111111111111111111111111111111111111".to_owned(),
        source_archive_sha256: "2222222222222222222222222222222222222222222222222222222222222222"
            .to_owned(),
        repository_remote_ref: EVOX2_BUILD_PLAN_REPOSITORY_REMOTE.to_owned(),
        target_host: EVOX2_BUILD_PLAN_TARGET_HOST.to_owned(),
        target_os: EVOX2_BUILD_PLAN_TARGET_OS.to_owned(),
        future_workspace_root: "C:/AI/workspaces/cantor-build-fb8e9ba7".to_owned(),
        future_target_root: "C:/AI/builds/cantor-build-fb8e9ba7".to_owned(),
        cargo_profile: EVOX2_BUILD_PLAN_CARGO_PROFILE.to_owned(),
        requested_checks: evox2_build_plan_requested_checks(),
        bounds: Evox2BuildPlanBounds {
            maximum_archive_bytes: 268_435_456,
            maximum_files: 16_384,
            maximum_stdout_bytes: 262_144,
            maximum_operation_count: 7,
            timeout_seconds: 7_200,
            cargo_build_jobs: 1,
        },
        authority_denials: evox2_build_plan_authority_denials(),
        request_sha256: String::new(),
    })
    .expect("synthetic EVO-X2 build-plan request is valid")
}

pub fn seal_evox2_build_plan_request(
    mut request: Evox2BuildPlanRequest,
) -> Result<Evox2BuildPlanRequest, Evox2BuildPlanFault> {
    request.request_sha256.clear();
    validate_request_body(&request)?;
    request.request_sha256 = evox2_build_plan_request_digest(&request)?;
    validate_evox2_build_plan_request(&request)?;
    Ok(request)
}

pub fn validate_evox2_build_plan_request(
    request: &Evox2BuildPlanRequest,
) -> Result<(), Evox2BuildPlanFault> {
    validate_request_body(request)?;
    if request.request_sha256 != evox2_build_plan_request_digest(request)? {
        return Err(fault(
            Evox2BuildPlanFaultCode::InvalidDigest,
            "request digest differs",
        ));
    }
    Ok(())
}

pub fn evox2_build_plan_request_digest(
    request: &Evox2BuildPlanRequest,
) -> Result<String, Evox2BuildPlanFault> {
    let mut unsigned = request.clone();
    unsigned.request_sha256.clear();
    let bytes = serde_json::to_vec(&unsigned).map_err(|_| machine_fault())?;
    Ok(domain_digest(REQUEST_DIGEST_DOMAIN, &bytes))
}

pub fn compile_evox2_build_plan(
    request: &Evox2BuildPlanRequest,
) -> Result<Evox2BuildPlan, Evox2BuildPlanFault> {
    validate_evox2_build_plan_request(request)?;
    let mut plan = derive_plan(request);
    validate_plan_body(&plan, request)?;
    plan.plan_sha256 = evox2_build_plan_digest(&plan)?;
    validate_evox2_build_plan(&plan, request)?;
    Ok(plan)
}

pub fn validate_evox2_build_plan(
    plan: &Evox2BuildPlan,
    request: &Evox2BuildPlanRequest,
) -> Result<(), Evox2BuildPlanFault> {
    validate_evox2_build_plan_request(request)?;
    validate_plan_body(plan, request)?;
    if plan.plan_sha256 != evox2_build_plan_digest(plan)? {
        return Err(fault(
            Evox2BuildPlanFaultCode::InvalidDigest,
            "plan digest differs",
        ));
    }
    let plan_bytes = serde_json::to_vec(plan).map_err(|_| machine_fault())?;
    if plan_bytes.len() > request.bounds.maximum_stdout_bytes as usize {
        return Err(fault(
            Evox2BuildPlanFaultCode::InvalidBound,
            "plan exceeds request stdout bound",
        ));
    }
    Ok(())
}

pub fn evox2_build_plan_digest(plan: &Evox2BuildPlan) -> Result<String, Evox2BuildPlanFault> {
    let mut unsigned = plan.clone();
    unsigned.plan_sha256.clear();
    let bytes = serde_json::to_vec(&unsigned).map_err(|_| machine_fault())?;
    Ok(domain_digest(PLAN_DIGEST_DOMAIN, &bytes))
}

pub fn verify_evox2_build_plan(
    request: &Evox2BuildPlanRequest,
    plan: &Evox2BuildPlan,
) -> Result<Evox2BuildPlanVerification, Evox2BuildPlanFault> {
    validate_evox2_build_plan_request(request)?;
    validate_evox2_build_plan(plan, request)?;
    let mut expected = independently_derive_plan(request);
    expected.plan_sha256 = evox2_build_plan_digest(&expected)?;
    if &expected != plan {
        return Err(fault(
            Evox2BuildPlanFaultCode::InvalidVerification,
            "plan differs from independent recompilation",
        ));
    }
    let expected_bytes = to_evox2_build_plan_machine_form(&expected)?;
    let actual_bytes = to_evox2_build_plan_machine_form(plan)?;
    if expected_bytes != actual_bytes {
        return Err(fault(
            Evox2BuildPlanFaultCode::InvalidVerification,
            "plan bytes differ from independent recompilation",
        ));
    }
    Ok(Evox2BuildPlanVerification {
        profile: EVOX2_BUILD_PLAN_VERIFICATION_PROFILE.to_owned(),
        status: "passed".to_owned(),
        canonical_uuid: EVOX2_BUILD_PLAN_CANONICAL_UUID.to_owned(),
        signature_uuid: EVOX2_BUILD_PLAN_SIGNATURE_UUID.to_owned(),
        request_uuid: request.request_uuid.clone(),
        plan_uuid: plan.plan_uuid.clone(),
        request_sha256: request.request_sha256.clone(),
        plan_sha256: plan.plan_sha256.clone(),
        operation_count: plan.operation_count,
        authority_denial_count: plan.authority_denials.len() as u32,
        authority_grant_count: plan.authority_grants.len() as u32,
        unresolved_count: plan.unresolved.len() as u32,
        byte_identical_recompilation: true,
        effects: 0,
    })
}

pub fn to_evox2_build_plan_request_machine_form(
    request: &Evox2BuildPlanRequest,
) -> Result<String, Evox2BuildPlanFault> {
    validate_evox2_build_plan_request(request)?;
    serialize_bounded(request, EVOX2_BUILD_PLAN_MAX_REQUEST_BYTES)
}

pub fn from_evox2_build_plan_request_machine_form(
    value: &str,
) -> Result<Evox2BuildPlanRequest, Evox2BuildPlanFault> {
    let request: Evox2BuildPlanRequest =
        strict_deserialize(value, EVOX2_BUILD_PLAN_MAX_REQUEST_BYTES)?;
    validate_evox2_build_plan_request(&request)?;
    Ok(request)
}

pub fn to_evox2_build_plan_machine_form(
    plan: &Evox2BuildPlan,
) -> Result<String, Evox2BuildPlanFault> {
    serialize_bounded(plan, EVOX2_BUILD_PLAN_MAX_PLAN_BYTES)
}

pub fn from_evox2_build_plan_machine_form(
    value: &str,
) -> Result<Evox2BuildPlan, Evox2BuildPlanFault> {
    strict_deserialize(value, EVOX2_BUILD_PLAN_MAX_PLAN_BYTES)
}

pub fn to_evox2_build_plan_verification_machine_form(
    verification: &Evox2BuildPlanVerification,
) -> Result<String, Evox2BuildPlanFault> {
    if verification.profile != EVOX2_BUILD_PLAN_VERIFICATION_PROFILE
        || verification.status != "passed"
        || verification.canonical_uuid != EVOX2_BUILD_PLAN_CANONICAL_UUID
        || verification.signature_uuid != EVOX2_BUILD_PLAN_SIGNATURE_UUID
        || verification.operation_count != 7
        || verification.authority_denial_count != 15
        || verification.authority_grant_count != 0
        || verification.unresolved_count != 5
        || !verification.byte_identical_recompilation
        || verification.effects != 0
    {
        return Err(fault(
            Evox2BuildPlanFaultCode::InvalidVerification,
            "verification record differs",
        ));
    }
    serialize_bounded(verification, EVOX2_BUILD_PLAN_MAX_REQUEST_BYTES)
}

fn validate_request_body(request: &Evox2BuildPlanRequest) -> Result<(), Evox2BuildPlanFault> {
    if request.profile != EVOX2_BUILD_PLAN_PROFILE {
        return Err(fault(
            Evox2BuildPlanFaultCode::InvalidProfile,
            "request profile differs",
        ));
    }
    if !is_uuid(&request.request_uuid)
        || request.predecessor_canonical_uuid != EVOX2_BUILD_PLAN_PREDECESSOR_CANONICAL_UUID
        || request.predecessor_bookend_commit != EVOX2_BUILD_PLAN_PREDECESSOR_BOOKEND_COMMIT
        || !is_lower_hex(&request.source_commit, 40)
        || !is_lower_hex(&request.source_archive_sha256, 64)
    {
        return Err(fault(
            Evox2BuildPlanFaultCode::InvalidIdentity,
            "request identity differs",
        ));
    }
    if request.repository_remote_ref != EVOX2_BUILD_PLAN_REPOSITORY_REMOTE
        || request.target_host != EVOX2_BUILD_PLAN_TARGET_HOST
        || request.target_os != EVOX2_BUILD_PLAN_TARGET_OS
        || request.cargo_profile != EVOX2_BUILD_PLAN_CARGO_PROFILE
    {
        return Err(fault(
            Evox2BuildPlanFaultCode::InvalidRequest,
            "request target differs",
        ));
    }
    validate_root(&request.future_workspace_root)?;
    validate_root(&request.future_target_root)?;
    if request
        .future_workspace_root
        .eq_ignore_ascii_case(&request.future_target_root)
        || is_protected_root(&request.future_workspace_root)
        || is_protected_root(&request.future_target_root)
    {
        return Err(fault(
            Evox2BuildPlanFaultCode::InvalidPath,
            "future root boundary differs",
        ));
    }
    if request.requested_checks != evox2_build_plan_requested_checks()
        || request.authority_denials != evox2_build_plan_authority_denials()
    {
        return Err(fault(
            Evox2BuildPlanFaultCode::InvalidAuthority,
            "request closed set differs",
        ));
    }
    let bounds = &request.bounds;
    if bounds.maximum_archive_bytes == 0
        || bounds.maximum_archive_bytes > EVOX2_BUILD_PLAN_MAX_ARCHIVE_BYTES
        || bounds.maximum_files == 0
        || bounds.maximum_files > EVOX2_BUILD_PLAN_MAX_FILES
        || bounds.maximum_stdout_bytes == 0
        || bounds.maximum_stdout_bytes as usize > EVOX2_BUILD_PLAN_MAX_PLAN_BYTES
        || bounds.maximum_operation_count != 7
        || bounds.timeout_seconds == 0
        || bounds.timeout_seconds > EVOX2_BUILD_PLAN_MAX_TIMEOUT_SECONDS
        || bounds.cargo_build_jobs != 1
    {
        return Err(fault(
            Evox2BuildPlanFaultCode::InvalidBound,
            "request bound differs",
        ));
    }
    if !request.request_sha256.is_empty() && !is_lower_hex(&request.request_sha256, 64) {
        return Err(fault(
            Evox2BuildPlanFaultCode::InvalidDigest,
            "request digest form differs",
        ));
    }
    Ok(())
}

fn validate_plan_body(
    plan: &Evox2BuildPlan,
    request: &Evox2BuildPlanRequest,
) -> Result<(), Evox2BuildPlanFault> {
    if plan.profile != EVOX2_BUILD_PLAN_PROFILE
        || plan.request_uuid != request.request_uuid
        || plan.predecessor_canonical_uuid != request.predecessor_canonical_uuid
        || plan.predecessor_bookend_commit != request.predecessor_bookend_commit
        || plan.source_commit != request.source_commit
        || plan.source_archive_sha256 != request.source_archive_sha256
        || plan.target_host != request.target_host
        || plan.target_os != request.target_os
        || plan.future_workspace_root != request.future_workspace_root
        || plan.future_target_root != request.future_target_root
        || !is_uuid(&plan.plan_uuid)
    {
        return Err(fault(
            Evox2BuildPlanFaultCode::InvalidIdentity,
            "plan identity differs",
        ));
    }
    if plan.cargo_environment != fixed_cargo_environment()
        || plan.operation_count != 7
        || plan.operations.len() != 7
        || plan.expected_evidence != evox2_build_plan_expected_evidence()
        || !plan.authority_grants.is_empty()
        || plan.authority_denials != evox2_build_plan_authority_denials()
        || plan.unresolved != evox2_build_plan_unresolved()
        || plan.disposition != "planned_effectless"
    {
        return Err(fault(
            Evox2BuildPlanFaultCode::InvalidAuthority,
            "plan closed account differs",
        ));
    }
    if plan.plan_uuid != deterministic_plan_uuid(request) {
        return Err(fault(
            Evox2BuildPlanFaultCode::InvalidIdentity,
            "plan UUID differs",
        ));
    }
    for (index, operation) in plan.operations.iter().enumerate() {
        let ordinal = (index + 1) as u32;
        if operation.ordinal != ordinal || operation.authority_required != "not_granted" {
            return Err(fault(
                Evox2BuildPlanFaultCode::InvalidOperation,
                "operation authority differs",
            ));
        }
        if operation
            .dependencies
            .iter()
            .any(|dependency| *dependency >= ordinal)
            || has_duplicates(&operation.dependencies)
        {
            return Err(fault(
                Evox2BuildPlanFaultCode::InvalidDependency,
                "operation dependency differs",
            ));
        }
        validate_root(&operation.working_directory)?;
        if operation.working_directory != request.future_workspace_root
            && operation.working_directory != request.future_target_root
        {
            return Err(fault(
                Evox2BuildPlanFaultCode::InvalidPath,
                "operation root differs",
            ));
        }
        if operation.arguments.len() > MAX_ARGUMENTS
            || operation.arguments.iter().any(|value| !is_safe_atom(value))
            || operation
                .input_identities
                .iter()
                .any(|value| !is_bounded_text(value))
            || operation
                .output_identities
                .iter()
                .any(|value| !is_bounded_text(value))
            || operation
                .preconditions
                .iter()
                .any(|value| !is_bounded_text(value))
            || !is_bounded_text(&operation.executable_identity)
            || !is_bounded_text(&operation.expected_evidence)
        {
            return Err(fault(
                Evox2BuildPlanFaultCode::InvalidOperation,
                "operation atom differs",
            ));
        }
        if operation.authority_denials.is_empty()
            || operation
                .authority_denials
                .iter()
                .any(|denial| !AUTHORITY_DENIALS.contains(&denial.as_str()))
            || has_duplicates(&operation.authority_denials)
        {
            return Err(fault(
                Evox2BuildPlanFaultCode::InvalidAuthority,
                "operation denial differs",
            ));
        }
    }
    if !plan.plan_sha256.is_empty() && !is_lower_hex(&plan.plan_sha256, 64) {
        return Err(fault(
            Evox2BuildPlanFaultCode::InvalidDigest,
            "plan digest form differs",
        ));
    }
    Ok(())
}

fn derive_plan(request: &Evox2BuildPlanRequest) -> Evox2BuildPlan {
    Evox2BuildPlan {
        profile: EVOX2_BUILD_PLAN_PROFILE.to_owned(),
        plan_uuid: deterministic_plan_uuid(request),
        request_uuid: request.request_uuid.clone(),
        predecessor_canonical_uuid: request.predecessor_canonical_uuid.clone(),
        predecessor_bookend_commit: request.predecessor_bookend_commit.clone(),
        source_commit: request.source_commit.clone(),
        source_archive_sha256: request.source_archive_sha256.clone(),
        target_host: request.target_host.clone(),
        target_os: request.target_os.clone(),
        future_workspace_root: request.future_workspace_root.clone(),
        future_target_root: request.future_target_root.clone(),
        cargo_environment: fixed_cargo_environment(),
        operations: compiler_derived_operations(request),
        operation_count: 7,
        expected_evidence: evox2_build_plan_expected_evidence(),
        authority_grants: Vec::new(),
        authority_denials: evox2_build_plan_authority_denials(),
        unresolved: evox2_build_plan_unresolved(),
        disposition: "planned_effectless".to_owned(),
        plan_sha256: String::new(),
    }
}

fn independently_derive_plan(request: &Evox2BuildPlanRequest) -> Evox2BuildPlan {
    Evox2BuildPlan {
        profile: "cantor-evox2-plan-only-build-job/0.1".to_owned(),
        plan_uuid: deterministic_plan_uuid(request),
        request_uuid: request.request_uuid.clone(),
        predecessor_canonical_uuid: request.predecessor_canonical_uuid.clone(),
        predecessor_bookend_commit: request.predecessor_bookend_commit.clone(),
        source_commit: request.source_commit.clone(),
        source_archive_sha256: request.source_archive_sha256.clone(),
        target_host: request.target_host.clone(),
        target_os: request.target_os.clone(),
        future_workspace_root: request.future_workspace_root.clone(),
        future_target_root: request.future_target_root.clone(),
        cargo_environment: Evox2BuildPlanCargoEnvironment {
            CARGO_NET_OFFLINE: true,
            CARGO_BUILD_JOBS: 1,
            CARGO_INCREMENTAL: 0,
            RUST_TEST_THREADS: 1,
            RUST_MIN_STACK: 33_554_432,
        },
        operations: independently_derived_operations(request),
        operation_count: 7,
        expected_evidence: EXPECTED_EVIDENCE
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        authority_grants: Vec::new(),
        authority_denials: AUTHORITY_DENIALS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        unresolved: UNRESOLVED.iter().map(|value| (*value).to_owned()).collect(),
        disposition: "planned_effectless".to_owned(),
        plan_sha256: String::new(),
    }
}

fn fixed_cargo_environment() -> Evox2BuildPlanCargoEnvironment {
    Evox2BuildPlanCargoEnvironment {
        CARGO_NET_OFFLINE: true,
        CARGO_BUILD_JOBS: 1,
        CARGO_INCREMENTAL: 0,
        RUST_TEST_THREADS: 1,
        RUST_MIN_STACK: 33_554_432,
    }
}

fn compiler_derived_operations(request: &Evox2BuildPlanRequest) -> Vec<Evox2BuildPlanOperation> {
    operation_blueprint()
        .into_iter()
        .enumerate()
        .map(|(index, blueprint)| operation_from_blueprint(request, index, blueprint))
        .collect()
}

fn independently_derived_operations(
    request: &Evox2BuildPlanRequest,
) -> Vec<Evox2BuildPlanOperation> {
    let blueprints = [
        (
            "verify_source_archive",
            "future.archive_verifier",
            vec!["verify", "--sha256"],
            "archive_verification",
        ),
        (
            "materialize_absent_workspace",
            "future.archive_materializer",
            vec!["materialize", "--absent-root"],
            "workspace_materialization",
        ),
        (
            "workspace_debug",
            "future.rust_toolchain.cargo",
            vec![
                "test",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--locked",
                "--offline",
            ],
            "debug_results",
        ),
        (
            "workspace_release",
            "future.rust_toolchain.cargo",
            vec![
                "test",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--release",
                "--locked",
                "--offline",
            ],
            "release_results",
        ),
        (
            "workspace_clippy",
            "future.rust_toolchain.cargo",
            vec![
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--locked",
                "--offline",
                "--",
                "-D",
                "warnings",
            ],
            "clippy_results",
        ),
        (
            "workspace_format",
            "future.rust_toolchain.cargo",
            vec!["fmt", "--all", "--", "--check"],
            "format_results",
        ),
        (
            "seal_build_receipt",
            "future.cantor.build_receipt_sealer",
            vec!["seal", "--effect-account", "exact"],
            "sealed_build_receipt",
        ),
    ];
    blueprints
        .into_iter()
        .enumerate()
        .map(|(index, (kind, executable, arguments, evidence))| {
            let ordinal = (index + 1) as u32;
            let input = if ordinal == 1 {
                format!("source-archive-sha256:{}", request.source_archive_sha256)
            } else {
                EXPECTED_EVIDENCE[index - 1].to_owned()
            };
            Evox2BuildPlanOperation {
                ordinal,
                kind: kind.to_owned(),
                executable_identity: executable.to_owned(),
                arguments: arguments.into_iter().map(str::to_owned).collect(),
                working_directory: if ordinal == 7 {
                    request.future_target_root.clone()
                } else {
                    request.future_workspace_root.clone()
                },
                input_identities: vec![input],
                output_identities: vec![evidence.to_owned()],
                dependencies: if ordinal == 1 {
                    Vec::new()
                } else {
                    vec![ordinal - 1]
                },
                preconditions: if ordinal == 1 {
                    vec!["exact_source_archive_supplied_by_future_executor".to_owned()]
                } else {
                    vec![format!("operation_{}_evidence_admitted", ordinal - 1)]
                },
                authority_required: "not_granted".to_owned(),
                authority_denials: AUTHORITY_DENIALS
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                expected_evidence: evidence.to_owned(),
            }
        })
        .collect()
}

fn operation_blueprint() -> [(&'static str, &'static str, Vec<&'static str>, &'static str); 7] {
    [
        (
            "verify_source_archive",
            "future.archive_verifier",
            vec!["verify", "--sha256"],
            "archive_verification",
        ),
        (
            "materialize_absent_workspace",
            "future.archive_materializer",
            vec!["materialize", "--absent-root"],
            "workspace_materialization",
        ),
        (
            "workspace_debug",
            "future.rust_toolchain.cargo",
            vec![
                "test",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--locked",
                "--offline",
            ],
            "debug_results",
        ),
        (
            "workspace_release",
            "future.rust_toolchain.cargo",
            vec![
                "test",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--release",
                "--locked",
                "--offline",
            ],
            "release_results",
        ),
        (
            "workspace_clippy",
            "future.rust_toolchain.cargo",
            vec![
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--locked",
                "--offline",
                "--",
                "-D",
                "warnings",
            ],
            "clippy_results",
        ),
        (
            "workspace_format",
            "future.rust_toolchain.cargo",
            vec!["fmt", "--all", "--", "--check"],
            "format_results",
        ),
        (
            "seal_build_receipt",
            "future.cantor.build_receipt_sealer",
            vec!["seal", "--effect-account", "exact"],
            "sealed_build_receipt",
        ),
    ]
}

fn operation_from_blueprint(
    request: &Evox2BuildPlanRequest,
    index: usize,
    blueprint: (&str, &str, Vec<&str>, &str),
) -> Evox2BuildPlanOperation {
    operation_from_parts(
        request,
        index,
        blueprint.0,
        blueprint.1,
        blueprint.2,
        blueprint.3,
    )
}

fn operation_from_parts(
    request: &Evox2BuildPlanRequest,
    index: usize,
    kind: &str,
    executable: &str,
    arguments: Vec<&str>,
    evidence: &str,
) -> Evox2BuildPlanOperation {
    let ordinal = (index + 1) as u32;
    let working_directory = if ordinal == 7 {
        request.future_target_root.clone()
    } else {
        request.future_workspace_root.clone()
    };
    let input = if ordinal == 1 {
        format!("source-archive-sha256:{}", request.source_archive_sha256)
    } else {
        EXPECTED_EVIDENCE[index - 1].to_owned()
    };
    Evox2BuildPlanOperation {
        ordinal,
        kind: kind.to_owned(),
        executable_identity: executable.to_owned(),
        arguments: arguments.into_iter().map(str::to_owned).collect(),
        working_directory,
        input_identities: vec![input],
        output_identities: vec![evidence.to_owned()],
        dependencies: if ordinal == 1 {
            Vec::new()
        } else {
            vec![ordinal - 1]
        },
        preconditions: if ordinal == 1 {
            vec!["exact_source_archive_supplied_by_future_executor".to_owned()]
        } else {
            vec![format!("operation_{}_evidence_admitted", ordinal - 1)]
        },
        authority_required: "not_granted".to_owned(),
        authority_denials: evox2_build_plan_authority_denials(),
        expected_evidence: evidence.to_owned(),
    }
}

fn deterministic_plan_uuid(request: &Evox2BuildPlanRequest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PLAN_UUID_DOMAIN);
    hasher.update(request.request_sha256.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_root(value: &str) -> Result<(), Evox2BuildPlanFault> {
    if value.len() < 7
        || value.len() > 240
        || !value.starts_with("C:/")
        || value.ends_with('/')
        || !value.is_ascii()
        || value.contains("//")
    {
        return Err(fault(
            Evox2BuildPlanFaultCode::InvalidPath,
            "portable root differs",
        ));
    }
    for segment in value[3..].split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.ends_with('.')
            || segment.ends_with(' ')
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(fault(
                Evox2BuildPlanFaultCode::InvalidPath,
                "portable root segment differs",
            ));
        }
    }
    Ok(())
}

fn is_protected_root(value: &str) -> bool {
    [
        "C:/AI/services/cantor-current-pilot-48479932",
        "C:/AI/services/cantor-attention-mcp",
        "C:/AI/services/cantor-needle-runtime",
        "C:/AI/services/sop-agent",
    ]
    .iter()
    .any(|root| {
        value.eq_ignore_ascii_case(root)
            || value
                .to_ascii_lowercase()
                .starts_with(&format!("{}/", root.to_ascii_lowercase()))
    })
}

fn is_safe_atom(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ARGUMENT_BYTES
        && value.is_ascii()
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        && !value
            .bytes()
            .any(|byte| matches!(byte, b'&' | b'|' | b';' | b'>' | b'<' | b'`'))
}

fn is_bounded_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && value.is_ascii()
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
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

fn has_duplicates<T: Ord + Clone>(values: &[T]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().any(|value| !seen.insert(value.clone()))
}

fn serialize_bounded<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<String, Evox2BuildPlanFault> {
    let output = serde_json::to_string(value).map_err(|_| machine_fault())?;
    if output.len() > maximum {
        return Err(fault(
            Evox2BuildPlanFaultCode::InvalidBound,
            "machine form exceeds bound",
        ));
    }
    Ok(output)
}

fn strict_deserialize<T: DeserializeOwned + Serialize>(
    value: &str,
    maximum: usize,
) -> Result<T, Evox2BuildPlanFault> {
    if value.is_empty() || value.len() > maximum {
        return Err(fault(
            Evox2BuildPlanFaultCode::InvalidBound,
            "machine form byte bound differs",
        ));
    }
    let mut duplicate_check = serde_json::Deserializer::from_str(value);
    NoDuplicateJson::deserialize(&mut duplicate_check).map_err(|_| machine_fault())?;
    duplicate_check.end().map_err(|_| machine_fault())?;
    let parsed: T = serde_json::from_str(value).map_err(|_| machine_fault())?;
    let canonical = serde_json::to_string(&parsed).map_err(|_| machine_fault())?;
    if canonical != value {
        return Err(machine_fault());
    }
    Ok(parsed)
}

struct NoDuplicateJson;

impl<'de> Deserialize<'de> for NoDuplicateJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateJsonVisitor)?;
        Ok(Self)
    }
}

struct NoDuplicateJsonVisitor;

impl<'de> Visitor<'de> for NoDuplicateJsonVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        NoDuplicateJson::deserialize(deserializer).map(|_| ())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<NoDuplicateJson>()?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
            map.next_value::<NoDuplicateJson>()?;
        }
        Ok(())
    }
}

fn fault(code: Evox2BuildPlanFaultCode, detail: &'static str) -> Evox2BuildPlanFault {
    Evox2BuildPlanFault { code, detail }
}

fn machine_fault() -> Evox2BuildPlanFault {
    fault(
        Evox2BuildPlanFaultCode::InvalidMachineForm,
        "machine form refused",
    )
}
