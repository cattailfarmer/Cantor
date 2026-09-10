//! Provider-free, host-free semantic core for the EVO-X2 scratch-build executor.
//!
//! This module validates a one-run commission and stopped-or-successful receipt.
//! It performs no filesystem, process, environment, clock, network, provider,
//! model, service, Cargo, Git, or remote-host operation.

use std::collections::BTreeSet;
use std::fmt;

use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const EVOX2_SCRATCH_BUILD_PROFILE: &str = "cantor-evox2-scratch-build-executor/0.1";
pub const EVOX2_SCRATCH_BUILD_RECEIPT_PROFILE: &str =
    "cantor-evox2-scratch-build-executor-receipt/0.1";
pub const EVOX2_SCRATCH_BUILD_COMMISSION_VERIFICATION_PROFILE: &str =
    "cantor-evox2-scratch-build-commission-verification/0.1";
pub const EVOX2_SCRATCH_BUILD_RECEIPT_VERIFICATION_PROFILE: &str =
    "cantor-evox2-scratch-build-receipt-verification/0.1";
pub const EVOX2_SCRATCH_BUILD_COMMAND_SET_PROFILE: &str =
    "cantor-evox2-scratch-build-command-set/0.1";
pub const EVOX2_SCRATCH_BUILD_IMPLEMENTATION_MANIFEST_PROFILE: &str =
    "cantor-evox2-scratch-build-implementation-manifest/0.1";
pub const EVOX2_SCRATCH_BUILD_DEPLOYMENT_ENVELOPE_PROFILE: &str =
    "cantor-evox2-scratch-build-deployment-envelope/0.1";
pub const EVOX2_SCRATCH_BUILD_PACKAGE_VERIFICATION_PROFILE: &str =
    "cantor-evox2-scratch-build-package-verification/0.1";
pub const EVOX2_SCRATCH_BUILD_CANONICAL_UUID: &str = "935e020f-8c6f-49e4-b355-63eabd3b778b";
pub const EVOX2_SCRATCH_BUILD_SIGNATURE_UUID: &str = "610fe633-34ec-40a5-a95c-170d0cffb3c1";
pub const EVOX2_SCRATCH_BUILD_PREDECESSOR_BOOKEND_COMMIT: &str =
    "a49ff0b6ab8675c7cf374616a2b2f76495bba18b";
pub const EVOX2_SCRATCH_BUILD_SOURCE_COMMIT: &str = "4fdd29cb7e76ddd827bcc7ceb8ca36ab28864271";
pub const EVOX2_SCRATCH_BUILD_SOURCE_ARCHIVE_SHA256: &str =
    "162a82f42619249a11a81ce64c29889eb5cd448a2d3d864ccb5bf26f1b0f325d";
pub const EVOX2_SCRATCH_BUILD_TARGET_HOST: &str = "EVO-X2";
pub const EVOX2_SCRATCH_BUILD_SERVICE_ROOT: &str = "C:/AI/services/cantor-scratch-build-4fdd29cb";
pub const EVOX2_SCRATCH_BUILD_EXECUTOR_PATH: &str =
    "C:/AI/services/cantor-scratch-build-4fdd29cb/bin/cantor-evox2-scratch-build-executor.exe";
pub const EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT: &str = "C:/AI/workspaces/cantor-build-4fdd29cb";
pub const EVOX2_SCRATCH_BUILD_TARGET_ROOT: &str = "C:/AI/builds/cantor-build-4fdd29cb";
pub const EVOX2_SCRATCH_BUILD_LOCAL_CORE_BOOKEND_COMMIT: &str =
    "1edd3a5596660b9789d7bf43eba82d2ee4917744";
pub const EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES: usize = 1_048_576;

const COMMISSION_DIGEST_DOMAIN: &[u8] = b"cantor.evox2-scratch-build.commission.v1\0";
const TOOLCHAIN_DIGEST_DOMAIN: &[u8] = b"cantor.evox2-scratch-build.toolchain.v1\0";
const OPERATION_DIGEST_DOMAIN: &[u8] = b"cantor.evox2-scratch-build.operation.v1\0";
const RECEIPT_DIGEST_DOMAIN: &[u8] = b"cantor.evox2-scratch-build.receipt.v1\0";
const COMMAND_SET_DIGEST_DOMAIN: &[u8] = b"cantor.evox2-scratch-build.command-set.v1\0";
const IMPLEMENTATION_MANIFEST_DIGEST_DOMAIN: &[u8] =
    b"cantor.evox2-scratch-build.implementation-manifest.v1\0";
const DEPLOYMENT_ENVELOPE_DIGEST_DOMAIN: &[u8] =
    b"cantor.evox2-scratch-build.deployment-envelope.v1\0";
const MAX_TEXT_BYTES: usize = 1_024;
const MAX_ARGUMENTS: usize = 32;
const MAX_ARGUMENT_BYTES: usize = 128;

const OPERATION_ORDINALS: [&str; 7] = [
    "verify_source_archive",
    "materialize_absent_workspace",
    "workspace_debug",
    "workspace_release",
    "workspace_clippy",
    "workspace_format",
    "seal_build_receipt",
];

const AUTHORITY_GRANTS: [&str; 5] = [
    "source_transfer",
    "source_extract",
    "toolchain_observe",
    "workspace_write",
    "process_execute",
];

const AUTHORITY_DENIALS: [&str; 14] = [
    "toolchain_install",
    "dependency_fetch",
    "git_mutation",
    "commit",
    "push",
    "provider_call",
    "model_inference",
    "service_change",
    "security_policy_change",
    "persistence",
    "self_update",
    "production_deploy",
    "external_fallback",
    "autonomous_work",
];

const REQUESTED_CHECKS: [&str; 4] = [
    "workspace_debug",
    "workspace_release",
    "workspace_clippy",
    "workspace_format",
];

const PACKAGE_ARTIFACTS: [(&str, &str); 21] = [
    (
        "bin/cantor-evox2-scratch-build-commission.exe",
        "commission_compiler",
    ),
    (
        "bin/cantor-evox2-scratch-build-commission-verify.exe",
        "commission_verifier",
    ),
    (
        "bin/cantor-evox2-scratch-build-receipt-verify.exe",
        "receipt_verifier",
    ),
    (
        "bin/cantor-evox2-scratch-build-package-verify.exe",
        "package_verifier",
    ),
    (
        "bin/cantor-evox2-scratch-build-executor.exe",
        "fixed_profile_executor",
    ),
    (
        "bin/cantor-evox2-scratch-build-operation-runner.exe",
        "contained_operation_runner",
    ),
    (
        "scripts/invoke-cantor-evox2-scratch-build-once.ps1",
        "fixed_profile_harness",
    ),
    ("request.json", "predecessor_request"),
    ("plan.json", "predecessor_plan"),
    ("plan_verification.json", "predecessor_plan_verification"),
    ("command_set.json", "exact_command_set"),
    ("source.tar", "exact_source_archive"),
    ("evidence/specification.sop", "canonical_specification"),
    ("evidence/solution.sop", "solution"),
    ("evidence/plan.sop", "plan"),
    ("evidence/data-design.sop", "formation_data_design"),
    (
        "evidence/acyclic-package-design.sop",
        "acyclic_package_design",
    ),
    (
        "evidence/local-core-implementation-proof.sop",
        "local_core_implementation_proof",
    ),
    (
        "evidence/local-core-publication-proof.sop",
        "local_core_publication_proof",
    ),
    ("evidence/local-core-coverage.sop", "local_core_coverage"),
    (
        "evidence/local-core-evidence-manifest.json",
        "local_core_evidence",
    ),
];

const PACKAGE_EXECUTIONS: [&str; 8] = [
    "commission_compiler_once",
    "package_verifier_preflight",
    "commission_verifier_preflight",
    "contained_operation_runner_sequence",
    "toolchain_probe_once",
    "fixed_profile_executor_once",
    "stopped_receipt_sealer",
    "receipt_verifier_postflight",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildBounds {
    pub maximum_archive_bytes: u64,
    pub maximum_files: u32,
    pub minimum_free_bytes: u64,
    pub maximum_target_bytes: u64,
    pub maximum_stdout_bytes: u32,
    pub maximum_stderr_bytes: u32,
    pub maximum_process_seconds: u32,
    pub maximum_total_seconds: u32,
    pub cargo_build_jobs: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
pub struct Evox2ScratchBuildCargoEnvironment {
    pub CARGO_NET_OFFLINE: bool,
    pub CARGO_BUILD_JOBS: u32,
    pub CARGO_INCREMENTAL: u32,
    pub RUST_TEST_THREADS: u32,
    pub RUST_MIN_STACK: u32,
    pub CARGO_TARGET_DIR: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildCommission {
    pub profile: String,
    pub commission_uuid: String,
    pub canonical_uuid: String,
    pub predecessor_bookend_commit: String,
    pub source_commit: String,
    pub source_archive_sha256: String,
    pub request_sha256: String,
    pub plan_sha256: String,
    pub package_manifest_sha256: String,
    pub command_set_sha256: String,
    pub target_host: String,
    pub workspace_root: String,
    pub target_root: String,
    pub operation_ordinals: Vec<String>,
    pub authority_grants: Vec<String>,
    pub authority_denials: Vec<String>,
    pub bounds: Evox2ScratchBuildBounds,
    pub cargo_environment: Evox2ScratchBuildCargoEnvironment,
    pub requested_checks: Vec<String>,
    pub disposition: String,
    pub commission_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildToolchainObservation {
    pub architecture: String,
    pub cargo_path: String,
    pub cargo_sha256: String,
    pub cargo_version: String,
    pub rustc_path: String,
    pub rustc_sha256: String,
    pub rustc_version: String,
    pub linker_path: String,
    pub linker_sha256: String,
    pub offline_probe_status: String,
    pub observation_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildOperationRecord {
    pub ordinal: u32,
    pub kind: String,
    pub admitted: bool,
    pub started_at: String,
    pub ended_at: String,
    pub duration_ms: u64,
    pub executable_path: String,
    pub executable_sha256: String,
    pub arguments: Vec<String>,
    pub working_directory: String,
    pub environment: Evox2ScratchBuildCargoEnvironment,
    pub exit_code: i32,
    pub stdout_bytes: u32,
    pub stdout_sha256: String,
    pub stdout_truncated: bool,
    pub stderr_bytes: u32,
    pub stderr_sha256: String,
    pub stderr_truncated: bool,
    pub target_bytes_after: u64,
    pub evidence_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildReceipt {
    pub profile: String,
    pub receipt_uuid: String,
    pub canonical_uuid: String,
    pub commission_uuid: String,
    pub commission_sha256: String,
    pub source_archive_sha256: String,
    pub source_commit: String,
    pub target_host: String,
    pub workspace_root: String,
    pub target_root: String,
    pub toolchain_observation: Evox2ScratchBuildToolchainObservation,
    pub operation_records: Vec<Evox2ScratchBuildOperationRecord>,
    pub protected_before: String,
    pub protected_after: String,
    pub provider_before: String,
    pub provider_after: String,
    pub persistent_executor_process_count: u32,
    pub physical_build_performed: bool,
    pub disposition: String,
    pub receipt_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildCommissionVerification {
    pub profile: String,
    pub status: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub commission_uuid: String,
    pub commission_sha256: String,
    pub authority_grant_count: u32,
    pub authority_denial_count: u32,
    pub effects: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildReceiptVerification {
    pub profile: String,
    pub status: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub commission_uuid: String,
    pub commission_sha256: String,
    pub receipt_uuid: String,
    pub receipt_sha256: String,
    pub disposition: String,
    pub operation_record_count: u32,
    pub physical_build_performed: bool,
    pub protected_state_unchanged: bool,
    pub provider_state_unchanged: bool,
    pub persistent_executor_process_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildCommand {
    pub ordinal: u32,
    pub kind: String,
    pub executable_role: String,
    pub arguments: Vec<String>,
    pub working_directory: String,
    pub environment: Evox2ScratchBuildCargoEnvironment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildCommandSet {
    pub profile: String,
    pub canonical_uuid: String,
    pub source_commit: String,
    pub target_host: String,
    pub workspace_root: String,
    pub target_root: String,
    pub commands: Vec<Evox2ScratchBuildCommand>,
    pub command_count: u32,
    pub command_set_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildPackageArtifact {
    pub relative_path: String,
    pub role: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildImplementationManifest {
    pub profile: String,
    pub manifest_uuid: String,
    pub canonical_uuid: String,
    pub local_core_bookend_commit: String,
    pub implementation_commit: String,
    pub source_commit: String,
    pub source_archive_sha256: String,
    pub target_host: String,
    pub workspace_root: String,
    pub target_root: String,
    pub artifact_count: u32,
    pub aggregate_bytes: u64,
    pub artifacts: Vec<Evox2ScratchBuildPackageArtifact>,
    pub allowed_executions: Vec<String>,
    pub authority_grants: Vec<String>,
    pub effects: u32,
    pub manifest_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildDeploymentEnvelope {
    pub profile: String,
    pub envelope_uuid: String,
    pub canonical_uuid: String,
    pub implementation_manifest_sha256: String,
    pub commission_uuid: String,
    pub commission_sha256: String,
    pub command_set_sha256: String,
    pub package_file_count: u32,
    pub package_aggregate_bytes: u64,
    pub disposition: String,
    pub envelope_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildPackageVerification {
    pub profile: String,
    pub status: String,
    pub canonical_uuid: String,
    pub implementation_commit: String,
    pub implementation_manifest_sha256: String,
    pub commission_sha256: String,
    pub command_set_sha256: String,
    pub artifact_count: u32,
    pub package_file_count: u32,
    pub package_aggregate_bytes: u64,
    pub authority_grants: u32,
    pub effects: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evox2ScratchBuildFaultCode {
    InvalidMachineForm,
    InvalidProfile,
    InvalidIdentity,
    InvalidDigest,
    InvalidBound,
    InvalidPath,
    InvalidAuthority,
    InvalidOperation,
    InvalidReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evox2ScratchBuildFault {
    pub code: Evox2ScratchBuildFaultCode,
    pub detail: &'static str,
}

impl fmt::Display for Evox2ScratchBuildFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Evox2ScratchBuildFault {}

pub fn evox2_scratch_build_operation_ordinals() -> Vec<String> {
    strings(&OPERATION_ORDINALS)
}

pub fn evox2_scratch_build_authority_grants() -> Vec<String> {
    strings(&AUTHORITY_GRANTS)
}

pub fn evox2_scratch_build_authority_denials() -> Vec<String> {
    strings(&AUTHORITY_DENIALS)
}

pub fn evox2_scratch_build_requested_checks() -> Vec<String> {
    strings(&REQUESTED_CHECKS)
}

pub fn fixed_evox2_scratch_build_bounds() -> Evox2ScratchBuildBounds {
    Evox2ScratchBuildBounds {
        maximum_archive_bytes: 268_435_456,
        maximum_files: 16_384,
        minimum_free_bytes: 103_079_215_104,
        maximum_target_bytes: 68_719_476_736,
        maximum_stdout_bytes: 16_777_216,
        maximum_stderr_bytes: 16_777_216,
        maximum_process_seconds: 7_200,
        maximum_total_seconds: 36_000,
        cargo_build_jobs: 1,
    }
}

pub fn fixed_evox2_scratch_build_environment() -> Evox2ScratchBuildCargoEnvironment {
    Evox2ScratchBuildCargoEnvironment {
        CARGO_NET_OFFLINE: true,
        CARGO_BUILD_JOBS: 1,
        CARGO_INCREMENTAL: 0,
        RUST_TEST_THREADS: 1,
        RUST_MIN_STACK: 33_554_432,
        CARGO_TARGET_DIR: EVOX2_SCRATCH_BUILD_TARGET_ROOT.to_owned(),
    }
}

pub fn synthetic_evox2_scratch_build_commission() -> Evox2ScratchBuildCommission {
    seal_evox2_scratch_build_commission(Evox2ScratchBuildCommission {
        profile: EVOX2_SCRATCH_BUILD_PROFILE.to_owned(),
        commission_uuid: "106a5a16-6ae7-46f8-a50d-558508579f80".to_owned(),
        canonical_uuid: EVOX2_SCRATCH_BUILD_CANONICAL_UUID.to_owned(),
        predecessor_bookend_commit: EVOX2_SCRATCH_BUILD_PREDECESSOR_BOOKEND_COMMIT.to_owned(),
        source_commit: EVOX2_SCRATCH_BUILD_SOURCE_COMMIT.to_owned(),
        source_archive_sha256: EVOX2_SCRATCH_BUILD_SOURCE_ARCHIVE_SHA256.to_owned(),
        request_sha256: "c886a16d1a4916dcdb796f724fca1bff1ed97b400d985bbd457510091026212e"
            .to_owned(),
        plan_sha256: "4e3cfa2632a860782ae48000be1b0267ecd308ca5ebb3828a62cfa448e9494e2".to_owned(),
        package_manifest_sha256: "1111111111111111111111111111111111111111111111111111111111111111"
            .to_owned(),
        command_set_sha256: "2222222222222222222222222222222222222222222222222222222222222222"
            .to_owned(),
        target_host: EVOX2_SCRATCH_BUILD_TARGET_HOST.to_owned(),
        workspace_root: EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT.to_owned(),
        target_root: EVOX2_SCRATCH_BUILD_TARGET_ROOT.to_owned(),
        operation_ordinals: evox2_scratch_build_operation_ordinals(),
        authority_grants: evox2_scratch_build_authority_grants(),
        authority_denials: evox2_scratch_build_authority_denials(),
        bounds: fixed_evox2_scratch_build_bounds(),
        cargo_environment: fixed_evox2_scratch_build_environment(),
        requested_checks: evox2_scratch_build_requested_checks(),
        disposition: "commissioned_once".to_owned(),
        commission_sha256: String::new(),
    })
    .expect("synthetic scratch-build commission is valid")
}

pub fn seal_evox2_scratch_build_commission(
    mut commission: Evox2ScratchBuildCommission,
) -> Result<Evox2ScratchBuildCommission, Evox2ScratchBuildFault> {
    commission.commission_sha256.clear();
    validate_commission_body(&commission)?;
    commission.commission_sha256 = evox2_scratch_build_commission_digest(&commission)?;
    validate_evox2_scratch_build_commission(&commission)?;
    Ok(commission)
}

pub fn validate_evox2_scratch_build_commission(
    commission: &Evox2ScratchBuildCommission,
) -> Result<(), Evox2ScratchBuildFault> {
    validate_commission_body(commission)?;
    if commission.commission_sha256 != evox2_scratch_build_commission_digest(commission)? {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidDigest,
            "commission digest differs",
        ));
    }
    Ok(())
}

pub fn evox2_scratch_build_commission_digest(
    commission: &Evox2ScratchBuildCommission,
) -> Result<String, Evox2ScratchBuildFault> {
    let mut unsigned = commission.clone();
    unsigned.commission_sha256.clear();
    digest_json(COMMISSION_DIGEST_DOMAIN, &unsigned)
}

pub fn to_evox2_scratch_build_commission_machine_form(
    commission: &Evox2ScratchBuildCommission,
) -> Result<String, Evox2ScratchBuildFault> {
    validate_evox2_scratch_build_commission(commission)?;
    serialize_bounded(commission)
}

pub fn from_evox2_scratch_build_commission_machine_form(
    value: &str,
) -> Result<Evox2ScratchBuildCommission, Evox2ScratchBuildFault> {
    let commission = strict_deserialize(value)?;
    validate_evox2_scratch_build_commission(&commission)?;
    Ok(commission)
}

pub fn verify_evox2_scratch_build_commission(
    commission: &Evox2ScratchBuildCommission,
) -> Result<Evox2ScratchBuildCommissionVerification, Evox2ScratchBuildFault> {
    validate_evox2_scratch_build_commission(commission)?;
    Ok(Evox2ScratchBuildCommissionVerification {
        profile: EVOX2_SCRATCH_BUILD_COMMISSION_VERIFICATION_PROFILE.to_owned(),
        status: "passed".to_owned(),
        canonical_uuid: EVOX2_SCRATCH_BUILD_CANONICAL_UUID.to_owned(),
        signature_uuid: EVOX2_SCRATCH_BUILD_SIGNATURE_UUID.to_owned(),
        commission_uuid: commission.commission_uuid.clone(),
        commission_sha256: commission.commission_sha256.clone(),
        authority_grant_count: commission.authority_grants.len() as u32,
        authority_denial_count: commission.authority_denials.len() as u32,
        effects: 0,
    })
}

pub fn to_evox2_scratch_build_commission_verification_machine_form(
    verification: &Evox2ScratchBuildCommissionVerification,
) -> Result<String, Evox2ScratchBuildFault> {
    if verification.profile != EVOX2_SCRATCH_BUILD_COMMISSION_VERIFICATION_PROFILE
        || verification.status != "passed"
        || verification.canonical_uuid != EVOX2_SCRATCH_BUILD_CANONICAL_UUID
        || verification.signature_uuid != EVOX2_SCRATCH_BUILD_SIGNATURE_UUID
        || !is_uuid(&verification.commission_uuid)
        || !is_lower_hex(&verification.commission_sha256, 64)
        || verification.authority_grant_count != 5
        || verification.authority_denial_count != 14
        || verification.effects != 0
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidAuthority,
            "commission verification differs",
        ));
    }
    serialize_bounded(verification)
}

pub fn seal_evox2_scratch_build_toolchain_observation(
    mut observation: Evox2ScratchBuildToolchainObservation,
) -> Result<Evox2ScratchBuildToolchainObservation, Evox2ScratchBuildFault> {
    observation.observation_sha256.clear();
    validate_toolchain_body(&observation)?;
    observation.observation_sha256 = toolchain_observation_digest(&observation)?;
    validate_toolchain_observation(&observation)?;
    Ok(observation)
}

pub fn unobserved_evox2_scratch_build_toolchain() -> Evox2ScratchBuildToolchainObservation {
    seal_evox2_scratch_build_toolchain_observation(Evox2ScratchBuildToolchainObservation {
        architecture: "not_observed".to_owned(),
        cargo_path: "not_observed".to_owned(),
        cargo_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned(),
        cargo_version: "not_observed".to_owned(),
        rustc_path: "not_observed".to_owned(),
        rustc_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned(),
        rustc_version: "not_observed".to_owned(),
        linker_path: "not_observed".to_owned(),
        linker_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_owned(),
        offline_probe_status: "not_observed_due_to_preflight_refusal".to_owned(),
        observation_sha256: String::new(),
    })
    .expect("unobserved toolchain sentinel is valid")
}

pub fn seal_evox2_scratch_build_operation_record(
    mut record: Evox2ScratchBuildOperationRecord,
    commission: &Evox2ScratchBuildCommission,
) -> Result<Evox2ScratchBuildOperationRecord, Evox2ScratchBuildFault> {
    record.evidence_sha256.clear();
    validate_operation_body(&record, commission)?;
    record.evidence_sha256 = operation_record_digest(&record)?;
    validate_operation_record(&record, commission)?;
    Ok(record)
}

pub fn seal_evox2_scratch_build_receipt(
    mut receipt: Evox2ScratchBuildReceipt,
    commission: &Evox2ScratchBuildCommission,
) -> Result<Evox2ScratchBuildReceipt, Evox2ScratchBuildFault> {
    receipt.receipt_sha256.clear();
    validate_receipt_body(&receipt, commission)?;
    receipt.receipt_sha256 = evox2_scratch_build_receipt_digest(&receipt)?;
    verify_evox2_scratch_build_receipt(commission, &receipt)?;
    Ok(receipt)
}

pub fn evox2_scratch_build_receipt_digest(
    receipt: &Evox2ScratchBuildReceipt,
) -> Result<String, Evox2ScratchBuildFault> {
    let mut unsigned = receipt.clone();
    unsigned.receipt_sha256.clear();
    digest_json(RECEIPT_DIGEST_DOMAIN, &unsigned)
}

pub fn verify_evox2_scratch_build_receipt(
    commission: &Evox2ScratchBuildCommission,
    receipt: &Evox2ScratchBuildReceipt,
) -> Result<(), Evox2ScratchBuildFault> {
    validate_evox2_scratch_build_commission(commission)?;
    validate_receipt_body(receipt, commission)?;
    if receipt.receipt_sha256 != evox2_scratch_build_receipt_digest(receipt)? {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidDigest,
            "receipt digest differs",
        ));
    }
    Ok(())
}

pub fn build_evox2_scratch_build_receipt_verification(
    commission: &Evox2ScratchBuildCommission,
    receipt: &Evox2ScratchBuildReceipt,
) -> Result<Evox2ScratchBuildReceiptVerification, Evox2ScratchBuildFault> {
    verify_evox2_scratch_build_receipt(commission, receipt)?;
    Ok(Evox2ScratchBuildReceiptVerification {
        profile: EVOX2_SCRATCH_BUILD_RECEIPT_VERIFICATION_PROFILE.to_owned(),
        status: "passed".to_owned(),
        canonical_uuid: EVOX2_SCRATCH_BUILD_CANONICAL_UUID.to_owned(),
        signature_uuid: EVOX2_SCRATCH_BUILD_SIGNATURE_UUID.to_owned(),
        commission_uuid: receipt.commission_uuid.clone(),
        commission_sha256: receipt.commission_sha256.clone(),
        receipt_uuid: receipt.receipt_uuid.clone(),
        receipt_sha256: receipt.receipt_sha256.clone(),
        disposition: receipt.disposition.clone(),
        operation_record_count: receipt.operation_records.len() as u32,
        physical_build_performed: receipt.physical_build_performed,
        protected_state_unchanged: receipt.protected_before == receipt.protected_after,
        provider_state_unchanged: receipt.provider_before == receipt.provider_after,
        persistent_executor_process_count: receipt.persistent_executor_process_count,
    })
}

pub fn to_evox2_scratch_build_receipt_verification_machine_form(
    verification: &Evox2ScratchBuildReceiptVerification,
) -> Result<String, Evox2ScratchBuildFault> {
    if verification.profile != EVOX2_SCRATCH_BUILD_RECEIPT_VERIFICATION_PROFILE
        || verification.status != "passed"
        || verification.canonical_uuid != EVOX2_SCRATCH_BUILD_CANONICAL_UUID
        || verification.signature_uuid != EVOX2_SCRATCH_BUILD_SIGNATURE_UUID
        || !is_uuid(&verification.commission_uuid)
        || !is_lower_hex(&verification.commission_sha256, 64)
        || !is_uuid(&verification.receipt_uuid)
        || !is_lower_hex(&verification.receipt_sha256, 64)
        || verification.operation_record_count > 7
        || !verification.protected_state_unchanged
        || !verification.provider_state_unchanged
        || verification.persistent_executor_process_count != 0
        || !matches!(
            verification.disposition.as_str(),
            "succeeded" | "failed" | "refused"
        )
        || (verification.disposition == "succeeded"
            && (!verification.physical_build_performed || verification.operation_record_count != 7))
        || (verification.disposition != "succeeded" && verification.physical_build_performed)
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidReceipt,
            "receipt verification differs",
        ));
    }
    serialize_bounded(verification)
}

pub fn to_evox2_scratch_build_receipt_machine_form(
    commission: &Evox2ScratchBuildCommission,
    receipt: &Evox2ScratchBuildReceipt,
) -> Result<String, Evox2ScratchBuildFault> {
    verify_evox2_scratch_build_receipt(commission, receipt)?;
    serialize_bounded(receipt)
}

pub fn from_evox2_scratch_build_receipt_machine_form(
    commission: &Evox2ScratchBuildCommission,
    value: &str,
) -> Result<Evox2ScratchBuildReceipt, Evox2ScratchBuildFault> {
    let receipt = strict_deserialize(value)?;
    verify_evox2_scratch_build_receipt(commission, &receipt)?;
    Ok(receipt)
}

pub fn seal_evox2_scratch_build_receipt_candidate_machine_form(
    commission: &Evox2ScratchBuildCommission,
    value: &str,
) -> Result<String, Evox2ScratchBuildFault> {
    let mut receipt: Evox2ScratchBuildReceipt = strict_deserialize(value)?;
    if !receipt.receipt_sha256.is_empty()
        || !receipt.toolchain_observation.observation_sha256.is_empty()
        || receipt
            .operation_records
            .iter()
            .any(|record| !record.evidence_sha256.is_empty())
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidDigest,
            "receipt candidate contains presealed digest",
        ));
    }
    receipt.toolchain_observation =
        seal_evox2_scratch_build_toolchain_observation(receipt.toolchain_observation)?;
    receipt.operation_records = receipt
        .operation_records
        .into_iter()
        .map(|record| seal_evox2_scratch_build_operation_record(record, commission))
        .collect::<Result<Vec<_>, _>>()?;
    let receipt = seal_evox2_scratch_build_receipt(receipt, commission)?;
    to_evox2_scratch_build_receipt_machine_form(commission, &receipt)
}

pub fn from_evox2_scratch_build_unsealed_receipt_candidate_machine_form(
    value: &str,
) -> Result<Evox2ScratchBuildReceipt, Evox2ScratchBuildFault> {
    let receipt: Evox2ScratchBuildReceipt = strict_deserialize(value)?;
    if !receipt.receipt_sha256.is_empty()
        || !receipt.toolchain_observation.observation_sha256.is_empty()
        || receipt
            .operation_records
            .iter()
            .any(|record| !record.evidence_sha256.is_empty())
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidDigest,
            "receipt candidate contains presealed digest",
        ));
    }
    Ok(receipt)
}

pub fn fixed_evox2_scratch_build_command_set() -> Evox2ScratchBuildCommandSet {
    let environment = fixed_evox2_scratch_build_environment();
    let commands = (3..=6)
        .map(|ordinal| Evox2ScratchBuildCommand {
            ordinal,
            kind: OPERATION_ORDINALS[(ordinal - 1) as usize].to_owned(),
            executable_role: "observed_cargo".to_owned(),
            arguments: expected_arguments(ordinal),
            working_directory: EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT.to_owned(),
            environment: environment.clone(),
        })
        .collect::<Vec<_>>();
    seal_evox2_scratch_build_command_set(Evox2ScratchBuildCommandSet {
        profile: EVOX2_SCRATCH_BUILD_COMMAND_SET_PROFILE.to_owned(),
        canonical_uuid: EVOX2_SCRATCH_BUILD_CANONICAL_UUID.to_owned(),
        source_commit: EVOX2_SCRATCH_BUILD_SOURCE_COMMIT.to_owned(),
        target_host: EVOX2_SCRATCH_BUILD_TARGET_HOST.to_owned(),
        workspace_root: EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT.to_owned(),
        target_root: EVOX2_SCRATCH_BUILD_TARGET_ROOT.to_owned(),
        command_count: commands.len() as u32,
        commands,
        command_set_sha256: String::new(),
    })
    .expect("fixed command set is valid")
}

pub fn seal_evox2_scratch_build_command_set(
    mut command_set: Evox2ScratchBuildCommandSet,
) -> Result<Evox2ScratchBuildCommandSet, Evox2ScratchBuildFault> {
    command_set.command_set_sha256.clear();
    validate_command_set_body(&command_set)?;
    command_set.command_set_sha256 = evox2_scratch_build_command_set_digest(&command_set)?;
    validate_evox2_scratch_build_command_set(&command_set)?;
    Ok(command_set)
}

pub fn validate_evox2_scratch_build_command_set(
    command_set: &Evox2ScratchBuildCommandSet,
) -> Result<(), Evox2ScratchBuildFault> {
    validate_command_set_body(command_set)?;
    if command_set.command_set_sha256 != evox2_scratch_build_command_set_digest(command_set)? {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidDigest,
            "command-set digest differs",
        ));
    }
    Ok(())
}

pub fn evox2_scratch_build_command_set_digest(
    command_set: &Evox2ScratchBuildCommandSet,
) -> Result<String, Evox2ScratchBuildFault> {
    let mut unsigned = command_set.clone();
    unsigned.command_set_sha256.clear();
    digest_json(COMMAND_SET_DIGEST_DOMAIN, &unsigned)
}

pub fn to_evox2_scratch_build_command_set_machine_form(
    command_set: &Evox2ScratchBuildCommandSet,
) -> Result<String, Evox2ScratchBuildFault> {
    validate_evox2_scratch_build_command_set(command_set)?;
    serialize_bounded(command_set)
}

pub fn from_evox2_scratch_build_command_set_machine_form(
    value: &str,
) -> Result<Evox2ScratchBuildCommandSet, Evox2ScratchBuildFault> {
    let command_set = strict_deserialize(value)?;
    validate_evox2_scratch_build_command_set(&command_set)?;
    Ok(command_set)
}

pub fn evox2_scratch_build_package_artifacts() -> Vec<(String, String)> {
    PACKAGE_ARTIFACTS
        .iter()
        .map(|(path, role)| ((*path).to_owned(), (*role).to_owned()))
        .collect()
}

pub fn evox2_scratch_build_package_executions() -> Vec<String> {
    strings(&PACKAGE_EXECUTIONS)
}

pub fn seal_evox2_scratch_build_implementation_manifest(
    mut manifest: Evox2ScratchBuildImplementationManifest,
) -> Result<Evox2ScratchBuildImplementationManifest, Evox2ScratchBuildFault> {
    manifest.manifest_sha256.clear();
    validate_implementation_manifest_body(&manifest)?;
    manifest.manifest_sha256 = evox2_scratch_build_implementation_manifest_digest(&manifest)?;
    validate_evox2_scratch_build_implementation_manifest(&manifest)?;
    Ok(manifest)
}

pub fn validate_evox2_scratch_build_implementation_manifest(
    manifest: &Evox2ScratchBuildImplementationManifest,
) -> Result<(), Evox2ScratchBuildFault> {
    validate_implementation_manifest_body(manifest)?;
    if manifest.manifest_sha256 != evox2_scratch_build_implementation_manifest_digest(manifest)? {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidDigest,
            "implementation-manifest digest differs",
        ));
    }
    Ok(())
}

pub fn evox2_scratch_build_implementation_manifest_digest(
    manifest: &Evox2ScratchBuildImplementationManifest,
) -> Result<String, Evox2ScratchBuildFault> {
    let mut unsigned = manifest.clone();
    unsigned.manifest_sha256.clear();
    digest_json(IMPLEMENTATION_MANIFEST_DIGEST_DOMAIN, &unsigned)
}

pub fn to_evox2_scratch_build_implementation_manifest_machine_form(
    manifest: &Evox2ScratchBuildImplementationManifest,
) -> Result<String, Evox2ScratchBuildFault> {
    validate_evox2_scratch_build_implementation_manifest(manifest)?;
    serialize_bounded(manifest)
}

pub fn from_evox2_scratch_build_implementation_manifest_machine_form(
    value: &str,
) -> Result<Evox2ScratchBuildImplementationManifest, Evox2ScratchBuildFault> {
    let manifest = strict_deserialize(value)?;
    validate_evox2_scratch_build_implementation_manifest(&manifest)?;
    Ok(manifest)
}

pub fn commissioned_evox2_scratch_build(
    package_manifest_sha256: &str,
    command_set_sha256: &str,
) -> Result<Evox2ScratchBuildCommission, Evox2ScratchBuildFault> {
    seal_evox2_scratch_build_commission(Evox2ScratchBuildCommission {
        profile: EVOX2_SCRATCH_BUILD_PROFILE.to_owned(),
        commission_uuid: "6cf6f2f1-51a1-4a67-a986-5b3388cef5b5".to_owned(),
        canonical_uuid: EVOX2_SCRATCH_BUILD_CANONICAL_UUID.to_owned(),
        predecessor_bookend_commit: EVOX2_SCRATCH_BUILD_PREDECESSOR_BOOKEND_COMMIT.to_owned(),
        source_commit: EVOX2_SCRATCH_BUILD_SOURCE_COMMIT.to_owned(),
        source_archive_sha256: EVOX2_SCRATCH_BUILD_SOURCE_ARCHIVE_SHA256.to_owned(),
        request_sha256: "c886a16d1a4916dcdb796f724fca1bff1ed97b400d985bbd457510091026212e"
            .to_owned(),
        plan_sha256: "4e3cfa2632a860782ae48000be1b0267ecd308ca5ebb3828a62cfa448e9494e2".to_owned(),
        package_manifest_sha256: package_manifest_sha256.to_owned(),
        command_set_sha256: command_set_sha256.to_owned(),
        target_host: EVOX2_SCRATCH_BUILD_TARGET_HOST.to_owned(),
        workspace_root: EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT.to_owned(),
        target_root: EVOX2_SCRATCH_BUILD_TARGET_ROOT.to_owned(),
        operation_ordinals: evox2_scratch_build_operation_ordinals(),
        authority_grants: evox2_scratch_build_authority_grants(),
        authority_denials: evox2_scratch_build_authority_denials(),
        bounds: fixed_evox2_scratch_build_bounds(),
        cargo_environment: fixed_evox2_scratch_build_environment(),
        requested_checks: evox2_scratch_build_requested_checks(),
        disposition: "commissioned_once".to_owned(),
        commission_sha256: String::new(),
    })
}

pub fn seal_evox2_scratch_build_deployment_envelope(
    mut envelope: Evox2ScratchBuildDeploymentEnvelope,
) -> Result<Evox2ScratchBuildDeploymentEnvelope, Evox2ScratchBuildFault> {
    envelope.envelope_sha256.clear();
    validate_deployment_envelope_body(&envelope)?;
    envelope.envelope_sha256 = evox2_scratch_build_deployment_envelope_digest(&envelope)?;
    validate_evox2_scratch_build_deployment_envelope(&envelope)?;
    Ok(envelope)
}

pub fn validate_evox2_scratch_build_deployment_envelope(
    envelope: &Evox2ScratchBuildDeploymentEnvelope,
) -> Result<(), Evox2ScratchBuildFault> {
    validate_deployment_envelope_body(envelope)?;
    if envelope.envelope_sha256 != evox2_scratch_build_deployment_envelope_digest(envelope)? {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidDigest,
            "deployment-envelope digest differs",
        ));
    }
    Ok(())
}

pub fn evox2_scratch_build_deployment_envelope_digest(
    envelope: &Evox2ScratchBuildDeploymentEnvelope,
) -> Result<String, Evox2ScratchBuildFault> {
    let mut unsigned = envelope.clone();
    unsigned.envelope_sha256.clear();
    digest_json(DEPLOYMENT_ENVELOPE_DIGEST_DOMAIN, &unsigned)
}

pub fn to_evox2_scratch_build_deployment_envelope_machine_form(
    envelope: &Evox2ScratchBuildDeploymentEnvelope,
) -> Result<String, Evox2ScratchBuildFault> {
    validate_evox2_scratch_build_deployment_envelope(envelope)?;
    serialize_bounded(envelope)
}

pub fn from_evox2_scratch_build_deployment_envelope_machine_form(
    value: &str,
) -> Result<Evox2ScratchBuildDeploymentEnvelope, Evox2ScratchBuildFault> {
    let envelope = strict_deserialize(value)?;
    validate_evox2_scratch_build_deployment_envelope(&envelope)?;
    Ok(envelope)
}

pub fn verify_evox2_scratch_build_package_correspondence(
    manifest: &Evox2ScratchBuildImplementationManifest,
    command_set: &Evox2ScratchBuildCommandSet,
    commission: &Evox2ScratchBuildCommission,
    envelope: &Evox2ScratchBuildDeploymentEnvelope,
) -> Result<Evox2ScratchBuildPackageVerification, Evox2ScratchBuildFault> {
    validate_evox2_scratch_build_implementation_manifest(manifest)?;
    validate_evox2_scratch_build_command_set(command_set)?;
    validate_evox2_scratch_build_commission(commission)?;
    validate_evox2_scratch_build_deployment_envelope(envelope)?;
    if commission.package_manifest_sha256 != manifest.manifest_sha256
        || commission.command_set_sha256 != command_set.command_set_sha256
        || envelope.implementation_manifest_sha256 != manifest.manifest_sha256
        || envelope.commission_uuid != commission.commission_uuid
        || envelope.commission_sha256 != commission.commission_sha256
        || envelope.command_set_sha256 != command_set.command_set_sha256
        || envelope.package_file_count != manifest.artifact_count + 3
        || envelope.package_aggregate_bytes <= manifest.aggregate_bytes
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidIdentity,
            "acyclic package correspondence differs",
        ));
    }
    Ok(Evox2ScratchBuildPackageVerification {
        profile: EVOX2_SCRATCH_BUILD_PACKAGE_VERIFICATION_PROFILE.to_owned(),
        status: "passed".to_owned(),
        canonical_uuid: EVOX2_SCRATCH_BUILD_CANONICAL_UUID.to_owned(),
        implementation_commit: manifest.implementation_commit.clone(),
        implementation_manifest_sha256: manifest.manifest_sha256.clone(),
        commission_sha256: commission.commission_sha256.clone(),
        command_set_sha256: command_set.command_set_sha256.clone(),
        artifact_count: manifest.artifact_count,
        package_file_count: envelope.package_file_count,
        package_aggregate_bytes: envelope.package_aggregate_bytes,
        authority_grants: commission.authority_grants.len() as u32,
        effects: 0,
    })
}

pub fn to_evox2_scratch_build_package_verification_machine_form(
    verification: &Evox2ScratchBuildPackageVerification,
) -> Result<String, Evox2ScratchBuildFault> {
    if verification.profile != EVOX2_SCRATCH_BUILD_PACKAGE_VERIFICATION_PROFILE
        || verification.status != "passed"
        || verification.canonical_uuid != EVOX2_SCRATCH_BUILD_CANONICAL_UUID
        || !is_lower_hex(&verification.implementation_commit, 40)
        || !is_lower_hex(&verification.implementation_manifest_sha256, 64)
        || !is_lower_hex(&verification.commission_sha256, 64)
        || !is_lower_hex(&verification.command_set_sha256, 64)
        || verification.artifact_count != PACKAGE_ARTIFACTS.len() as u32
        || verification.package_file_count != PACKAGE_ARTIFACTS.len() as u32 + 3
        || verification.package_aggregate_bytes == 0
        || verification.authority_grants != AUTHORITY_GRANTS.len() as u32
        || verification.effects != 0
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidAuthority,
            "package verification differs",
        ));
    }
    serialize_bounded(verification)
}

pub fn evox2_scratch_build_expected_arguments(ordinal: u32) -> Vec<String> {
    expected_arguments(ordinal)
}

fn validate_command_set_body(
    command_set: &Evox2ScratchBuildCommandSet,
) -> Result<(), Evox2ScratchBuildFault> {
    if command_set.profile != EVOX2_SCRATCH_BUILD_COMMAND_SET_PROFILE
        || command_set.canonical_uuid != EVOX2_SCRATCH_BUILD_CANONICAL_UUID
        || command_set.source_commit != EVOX2_SCRATCH_BUILD_SOURCE_COMMIT
        || command_set.target_host != EVOX2_SCRATCH_BUILD_TARGET_HOST
        || command_set.workspace_root != EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT
        || command_set.target_root != EVOX2_SCRATCH_BUILD_TARGET_ROOT
        || command_set.command_count != 4
        || command_set.commands.len() != 4
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidIdentity,
            "command-set identity differs",
        ));
    }
    for (index, command) in command_set.commands.iter().enumerate() {
        let ordinal = (index + 3) as u32;
        if command.ordinal != ordinal
            || command.kind != OPERATION_ORDINALS[(ordinal - 1) as usize]
            || command.executable_role != "observed_cargo"
            || command.arguments != expected_arguments(ordinal)
            || command.working_directory != EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT
            || command.environment != fixed_evox2_scratch_build_environment()
        {
            return Err(fault(
                Evox2ScratchBuildFaultCode::InvalidOperation,
                "command-set operation differs",
            ));
        }
    }
    if !command_set.command_set_sha256.is_empty()
        && !is_lower_hex(&command_set.command_set_sha256, 64)
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidDigest,
            "command-set digest form differs",
        ));
    }
    Ok(())
}

fn validate_implementation_manifest_body(
    manifest: &Evox2ScratchBuildImplementationManifest,
) -> Result<(), Evox2ScratchBuildFault> {
    if manifest.profile != EVOX2_SCRATCH_BUILD_IMPLEMENTATION_MANIFEST_PROFILE
        || !is_uuid(&manifest.manifest_uuid)
        || manifest.canonical_uuid != EVOX2_SCRATCH_BUILD_CANONICAL_UUID
        || manifest.local_core_bookend_commit != EVOX2_SCRATCH_BUILD_LOCAL_CORE_BOOKEND_COMMIT
        || !is_lower_hex(&manifest.implementation_commit, 40)
        || manifest.source_commit != EVOX2_SCRATCH_BUILD_SOURCE_COMMIT
        || manifest.source_archive_sha256 != EVOX2_SCRATCH_BUILD_SOURCE_ARCHIVE_SHA256
        || manifest.target_host != EVOX2_SCRATCH_BUILD_TARGET_HOST
        || manifest.workspace_root != EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT
        || manifest.target_root != EVOX2_SCRATCH_BUILD_TARGET_ROOT
        || manifest.artifact_count != PACKAGE_ARTIFACTS.len() as u32
        || manifest.artifacts.len() != PACKAGE_ARTIFACTS.len()
        || manifest.allowed_executions != evox2_scratch_build_package_executions()
        || !manifest.authority_grants.is_empty()
        || manifest.effects != 0
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidIdentity,
            "implementation-manifest identity differs",
        ));
    }
    let mut aggregate = 0_u64;
    let mut seen = BTreeSet::new();
    for (artifact, (expected_path, expected_role)) in
        manifest.artifacts.iter().zip(PACKAGE_ARTIFACTS.iter())
    {
        if artifact.relative_path != *expected_path
            || artifact.role != *expected_role
            || !valid_relative_package_path(&artifact.relative_path)
            || !seen.insert(artifact.relative_path.to_ascii_lowercase())
            || artifact.bytes == 0
            || !is_lower_hex(&artifact.sha256, 64)
        {
            return Err(fault(
                Evox2ScratchBuildFaultCode::InvalidPath,
                "implementation artifact differs",
            ));
        }
        aggregate = aggregate.checked_add(artifact.bytes).ok_or_else(|| {
            fault(
                Evox2ScratchBuildFaultCode::InvalidBound,
                "implementation aggregate differs",
            )
        })?;
        if artifact.relative_path == "source.tar"
            && (artifact.sha256 != EVOX2_SCRATCH_BUILD_SOURCE_ARCHIVE_SHA256
                || artifact.bytes > fixed_evox2_scratch_build_bounds().maximum_archive_bytes)
        {
            return Err(fault(
                Evox2ScratchBuildFaultCode::InvalidIdentity,
                "source archive artifact differs",
            ));
        }
    }
    if aggregate != manifest.aggregate_bytes || aggregate > 536_870_912 {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidBound,
            "implementation aggregate differs",
        ));
    }
    if !manifest.manifest_sha256.is_empty() && !is_lower_hex(&manifest.manifest_sha256, 64) {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidDigest,
            "implementation-manifest digest form differs",
        ));
    }
    Ok(())
}

fn validate_deployment_envelope_body(
    envelope: &Evox2ScratchBuildDeploymentEnvelope,
) -> Result<(), Evox2ScratchBuildFault> {
    if envelope.profile != EVOX2_SCRATCH_BUILD_DEPLOYMENT_ENVELOPE_PROFILE
        || !is_uuid(&envelope.envelope_uuid)
        || envelope.canonical_uuid != EVOX2_SCRATCH_BUILD_CANONICAL_UUID
        || !is_lower_hex(&envelope.implementation_manifest_sha256, 64)
        || !is_uuid(&envelope.commission_uuid)
        || !is_lower_hex(&envelope.commission_sha256, 64)
        || !is_lower_hex(&envelope.command_set_sha256, 64)
        || envelope.package_file_count != PACKAGE_ARTIFACTS.len() as u32 + 3
        || envelope.package_aggregate_bytes == 0
        || envelope.package_aggregate_bytes > 536_870_912
        || envelope.disposition != "sealed_for_single_commission"
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidIdentity,
            "deployment-envelope identity differs",
        ));
    }
    if !envelope.envelope_sha256.is_empty() && !is_lower_hex(&envelope.envelope_sha256, 64) {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidDigest,
            "deployment-envelope digest form differs",
        ));
    }
    Ok(())
}

fn valid_relative_package_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains('\\')
        && !value.contains(':')
        && !value.chars().any(|character| {
            character.is_control()
                || !character.is_ascii()
                || matches!(character, '*' | '?' | '"' | '<' | '>' | '|')
        })
        && value.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && !segment.ends_with('.')
                && !segment.ends_with(' ')
        })
}

fn validate_commission_body(
    commission: &Evox2ScratchBuildCommission,
) -> Result<(), Evox2ScratchBuildFault> {
    if commission.profile != EVOX2_SCRATCH_BUILD_PROFILE {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidProfile,
            "commission profile differs",
        ));
    }
    if !is_uuid(&commission.commission_uuid)
        || commission.canonical_uuid != EVOX2_SCRATCH_BUILD_CANONICAL_UUID
        || commission.predecessor_bookend_commit != EVOX2_SCRATCH_BUILD_PREDECESSOR_BOOKEND_COMMIT
        || commission.source_commit != EVOX2_SCRATCH_BUILD_SOURCE_COMMIT
        || commission.source_archive_sha256 != EVOX2_SCRATCH_BUILD_SOURCE_ARCHIVE_SHA256
        || !is_lower_hex(&commission.request_sha256, 64)
        || !is_lower_hex(&commission.plan_sha256, 64)
        || !is_lower_hex(&commission.package_manifest_sha256, 64)
        || !is_lower_hex(&commission.command_set_sha256, 64)
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidIdentity,
            "commission identity differs",
        ));
    }
    if commission.target_host != EVOX2_SCRATCH_BUILD_TARGET_HOST
        || commission.workspace_root != EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT
        || commission.target_root != EVOX2_SCRATCH_BUILD_TARGET_ROOT
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidPath,
            "commission host root differs",
        ));
    }
    if commission.operation_ordinals != evox2_scratch_build_operation_ordinals()
        || commission.authority_grants != evox2_scratch_build_authority_grants()
        || commission.authority_denials != evox2_scratch_build_authority_denials()
        || commission.requested_checks != evox2_scratch_build_requested_checks()
        || commission.disposition != "commissioned_once"
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidAuthority,
            "commission closed authority differs",
        ));
    }
    if commission.bounds != fixed_evox2_scratch_build_bounds()
        || commission.cargo_environment != fixed_evox2_scratch_build_environment()
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidBound,
            "commission bounds differ",
        ));
    }
    if !commission.commission_sha256.is_empty() && !is_lower_hex(&commission.commission_sha256, 64)
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidDigest,
            "commission digest form differs",
        ));
    }
    Ok(())
}

fn validate_toolchain_observation(
    observation: &Evox2ScratchBuildToolchainObservation,
) -> Result<(), Evox2ScratchBuildFault> {
    validate_toolchain_body(observation)?;
    if observation.observation_sha256 != toolchain_observation_digest(observation)? {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidDigest,
            "toolchain observation digest differs",
        ));
    }
    Ok(())
}

fn validate_toolchain_body(
    observation: &Evox2ScratchBuildToolchainObservation,
) -> Result<(), Evox2ScratchBuildFault> {
    for value in [
        observation.architecture.as_str(),
        observation.cargo_path.as_str(),
        observation.cargo_version.as_str(),
        observation.rustc_path.as_str(),
        observation.rustc_version.as_str(),
        observation.linker_path.as_str(),
    ] {
        validate_text(value)?;
    }
    let unobserved = observation.architecture == "not_observed"
        && observation.cargo_path == "not_observed"
        && observation.cargo_sha256
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        && observation.cargo_version == "not_observed"
        && observation.rustc_path == "not_observed"
        && observation.rustc_sha256
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        && observation.rustc_version == "not_observed"
        && observation.linker_path == "not_observed"
        && observation.linker_sha256
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        && observation.offline_probe_status == "not_observed_due_to_preflight_refusal";
    let observed = is_lower_hex(&observation.cargo_sha256, 64)
        && is_lower_hex(&observation.rustc_sha256, 64)
        && is_lower_hex(&observation.linker_sha256, 64);
    if !unobserved
        && (!observed || observation.offline_probe_status != "available_without_mutation")
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidIdentity,
            "toolchain observation differs",
        ));
    }
    if !observation.observation_sha256.is_empty()
        && !is_lower_hex(&observation.observation_sha256, 64)
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidDigest,
            "toolchain digest form differs",
        ));
    }
    Ok(())
}

fn validate_operation_record(
    record: &Evox2ScratchBuildOperationRecord,
    commission: &Evox2ScratchBuildCommission,
) -> Result<(), Evox2ScratchBuildFault> {
    validate_operation_body(record, commission)?;
    if record.evidence_sha256 != operation_record_digest(record)? {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidDigest,
            "operation evidence digest differs",
        ));
    }
    Ok(())
}

fn validate_operation_body(
    record: &Evox2ScratchBuildOperationRecord,
    commission: &Evox2ScratchBuildCommission,
) -> Result<(), Evox2ScratchBuildFault> {
    let index = usize::try_from(record.ordinal.saturating_sub(1)).map_err(|_| {
        fault(
            Evox2ScratchBuildFaultCode::InvalidOperation,
            "operation ordinal differs",
        )
    })?;
    if index >= OPERATION_ORDINALS.len()
        || record.kind != OPERATION_ORDINALS[index]
        || !record.admitted
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidOperation,
            "operation coordinate differs",
        ));
    }
    validate_text(&record.started_at)?;
    validate_text(&record.ended_at)?;
    validate_text(&record.executable_path)?;
    if !is_lower_hex(&record.executable_sha256, 64)
        || record.environment != commission.cargo_environment
        || record.duration_ms > u64::from(commission.bounds.maximum_process_seconds) * 1_000
        || record.stdout_bytes > commission.bounds.maximum_stdout_bytes
        || record.stderr_bytes > commission.bounds.maximum_stderr_bytes
        || record.target_bytes_after > commission.bounds.maximum_target_bytes
        || !is_lower_hex(&record.stdout_sha256, 64)
        || !is_lower_hex(&record.stderr_sha256, 64)
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidBound,
            "operation evidence bound differs",
        ));
    }
    let expected_working_directory = match record.ordinal {
        1 => EVOX2_SCRATCH_BUILD_SERVICE_ROOT,
        2 => "C:/AI/workspaces",
        7 => commission.target_root.as_str(),
        _ => commission.workspace_root.as_str(),
    };
    if record.working_directory != expected_working_directory
        || record.arguments != expected_arguments(record.ordinal)
        || record.arguments.len() > MAX_ARGUMENTS
        || record.arguments.iter().any(|argument| {
            argument.is_empty()
                || argument.len() > MAX_ARGUMENT_BYTES
                || argument
                    .chars()
                    .any(|character| character.is_control() || ";|&`$".contains(character))
        })
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidOperation,
            "operation command boundary differs",
        ));
    }
    if matches!(record.ordinal, 1 | 2 | 7)
        && record.executable_path != EVOX2_SCRATCH_BUILD_EXECUTOR_PATH
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidOperation,
            "executor operation path differs",
        ));
    }
    if !record.evidence_sha256.is_empty() && !is_lower_hex(&record.evidence_sha256, 64) {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidDigest,
            "operation evidence digest form differs",
        ));
    }
    Ok(())
}

fn validate_receipt_body(
    receipt: &Evox2ScratchBuildReceipt,
    commission: &Evox2ScratchBuildCommission,
) -> Result<(), Evox2ScratchBuildFault> {
    if receipt.profile != EVOX2_SCRATCH_BUILD_RECEIPT_PROFILE {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidProfile,
            "receipt profile differs",
        ));
    }
    if !is_uuid(&receipt.receipt_uuid)
        || receipt.canonical_uuid != commission.canonical_uuid
        || receipt.commission_uuid != commission.commission_uuid
        || receipt.commission_sha256 != commission.commission_sha256
        || receipt.source_archive_sha256 != commission.source_archive_sha256
        || receipt.source_commit != commission.source_commit
        || receipt.target_host != commission.target_host
        || receipt.workspace_root != commission.workspace_root
        || receipt.target_root != commission.target_root
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidIdentity,
            "receipt identity differs",
        ));
    }
    validate_toolchain_observation(&receipt.toolchain_observation)?;
    if receipt.operation_records.len() > OPERATION_ORDINALS.len() {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidOperation,
            "operation record count differs",
        ));
    }
    let executor_identity = receipt
        .operation_records
        .iter()
        .find(|record| matches!(record.ordinal, 1 | 2 | 7))
        .map(|record| {
            (
                record.executable_path.as_str(),
                record.executable_sha256.as_str(),
            )
        });
    let mut total_duration_ms = 0_u64;
    for (index, record) in receipt.operation_records.iter().enumerate() {
        if record.ordinal != (index + 1) as u32 {
            return Err(fault(
                Evox2ScratchBuildFaultCode::InvalidOperation,
                "operation record sequence differs",
            ));
        }
        validate_operation_record(record, commission)?;
        total_duration_ms = total_duration_ms
            .checked_add(record.duration_ms)
            .ok_or_else(|| {
                fault(
                    Evox2ScratchBuildFaultCode::InvalidBound,
                    "total operation duration differs",
                )
            })?;
        if total_duration_ms > u64::from(commission.bounds.maximum_total_seconds) * 1_000 {
            return Err(fault(
                Evox2ScratchBuildFaultCode::InvalidBound,
                "total operation duration differs",
            ));
        }
        if (3..=6).contains(&record.ordinal)
            && (record.executable_path != receipt.toolchain_observation.cargo_path
                || record.executable_sha256 != receipt.toolchain_observation.cargo_sha256)
        {
            return Err(fault(
                Evox2ScratchBuildFaultCode::InvalidOperation,
                "Cargo operation executable identity differs",
            ));
        }
        if matches!(record.ordinal, 1 | 2 | 7)
            && executor_identity.is_some_and(|identity| {
                record.executable_path != identity.0 || record.executable_sha256 != identity.1
            })
        {
            return Err(fault(
                Evox2ScratchBuildFaultCode::InvalidOperation,
                "executor operation executable identity differs",
            ));
        }
        if index + 1 < receipt.operation_records.len() && !operation_succeeded(record) {
            return Err(fault(
                Evox2ScratchBuildFaultCode::InvalidOperation,
                "later operation follows failure",
            ));
        }
    }
    if !is_lower_hex(&receipt.protected_before, 64)
        || receipt.protected_before != receipt.protected_after
        || !is_lower_hex(&receipt.provider_before, 64)
        || receipt.provider_before != receipt.provider_after
        || receipt.persistent_executor_process_count != 0
    {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidReceipt,
            "receipt conservation differs",
        ));
    }
    match receipt.disposition.as_str() {
        "succeeded" => {
            if receipt.operation_records.len() != 7
                || receipt
                    .operation_records
                    .iter()
                    .any(|record| !operation_succeeded(record))
                || !receipt.physical_build_performed
                || receipt.toolchain_observation.offline_probe_status
                    != "available_without_mutation"
            {
                return Err(fault(
                    Evox2ScratchBuildFaultCode::InvalidReceipt,
                    "successful receipt differs",
                ));
            }
        }
        "failed" => {
            if receipt.operation_records.is_empty()
                || receipt
                    .operation_records
                    .last()
                    .is_none_or(operation_succeeded)
                || receipt.physical_build_performed
            {
                return Err(fault(
                    Evox2ScratchBuildFaultCode::InvalidReceipt,
                    "failed receipt differs",
                ));
            }
        }
        "refused" => {
            if receipt.operation_records.len() >= 7
                || receipt
                    .operation_records
                    .iter()
                    .any(|record| !operation_succeeded(record))
                || receipt.physical_build_performed
            {
                return Err(fault(
                    Evox2ScratchBuildFaultCode::InvalidReceipt,
                    "refused receipt differs",
                ));
            }
        }
        _ => {
            return Err(fault(
                Evox2ScratchBuildFaultCode::InvalidReceipt,
                "receipt disposition differs",
            ));
        }
    }
    if !receipt.receipt_sha256.is_empty() && !is_lower_hex(&receipt.receipt_sha256, 64) {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidDigest,
            "receipt digest form differs",
        ));
    }
    Ok(())
}

fn operation_succeeded(record: &Evox2ScratchBuildOperationRecord) -> bool {
    record.exit_code == 0 && !record.stdout_truncated && !record.stderr_truncated
}

fn toolchain_observation_digest(
    observation: &Evox2ScratchBuildToolchainObservation,
) -> Result<String, Evox2ScratchBuildFault> {
    let mut unsigned = observation.clone();
    unsigned.observation_sha256.clear();
    digest_json(TOOLCHAIN_DIGEST_DOMAIN, &unsigned)
}

fn operation_record_digest(
    record: &Evox2ScratchBuildOperationRecord,
) -> Result<String, Evox2ScratchBuildFault> {
    let mut unsigned = record.clone();
    unsigned.evidence_sha256.clear();
    digest_json(OPERATION_DIGEST_DOMAIN, &unsigned)
}

fn expected_arguments(ordinal: u32) -> Vec<String> {
    let values: &[&str] = match ordinal {
        1 => &["verify", "--sha256"],
        2 => &["materialize", "--absent-root"],
        3 => &[
            "test",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--offline",
        ],
        4 => &[
            "test",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--release",
            "--locked",
            "--offline",
        ],
        5 => &[
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
        6 => &["fmt", "--all", "--", "--check"],
        7 => &["seal", "--effect-account", "exact"],
        _ => &[],
    };
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn serialize_bounded<T: Serialize>(value: &T) -> Result<String, Evox2ScratchBuildFault> {
    let bytes = serde_json::to_vec(value).map_err(|_| machine_fault())?;
    if bytes.is_empty() || bytes.len() > EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES {
        return Err(machine_fault());
    }
    String::from_utf8(bytes).map_err(|_| machine_fault())
}

fn strict_deserialize<T: DeserializeOwned + Serialize>(
    value: &str,
) -> Result<T, Evox2ScratchBuildFault> {
    if value.is_empty() || value.len() > EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES {
        return Err(machine_fault());
    }
    let mut duplicate_check = serde_json::Deserializer::from_str(value);
    NoDuplicateJson::deserialize(&mut duplicate_check).map_err(|_| machine_fault())?;
    duplicate_check.end().map_err(|_| machine_fault())?;
    let parsed: T = serde_json::from_str(value).map_err(|_| machine_fault())?;
    let canonical = serde_json::to_string(&parsed).map_err(|_| machine_fault())?;
    if canonical.as_bytes() != value.as_bytes() {
        return Err(machine_fault());
    }
    Ok(parsed)
}

fn digest_json<T: Serialize>(domain: &[u8], value: &T) -> Result<String, Evox2ScratchBuildFault> {
    let bytes = serde_json::to_vec(value).map_err(|_| machine_fault())?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn strings<const N: usize>(values: &[&str; N]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn validate_text(value: &str) -> Result<(), Evox2ScratchBuildFault> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(fault(
            Evox2ScratchBuildFaultCode::InvalidMachineForm,
            "text boundary differs",
        ));
    }
    Ok(())
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
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

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        let _ = value;
        Ok(())
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        let _ = value;
        Ok(())
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        let _ = value;
        Ok(())
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let _ = value;
        Ok(())
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        let _ = value;
        Ok(())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        let _ = value;
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
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

fn fault(code: Evox2ScratchBuildFaultCode, detail: &'static str) -> Evox2ScratchBuildFault {
    Evox2ScratchBuildFault { code, detail }
}

fn machine_fault() -> Evox2ScratchBuildFault {
    fault(
        Evox2ScratchBuildFaultCode::InvalidMachineForm,
        "machine form refused",
    )
}
