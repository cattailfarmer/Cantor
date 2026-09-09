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
pub const EVOX2_SCRATCH_BUILD_CANONICAL_UUID: &str = "935e020f-8c6f-49e4-b355-63eabd3b778b";
pub const EVOX2_SCRATCH_BUILD_SIGNATURE_UUID: &str = "610fe633-34ec-40a5-a95c-170d0cffb3c1";
pub const EVOX2_SCRATCH_BUILD_PREDECESSOR_BOOKEND_COMMIT: &str =
    "a49ff0b6ab8675c7cf374616a2b2f76495bba18b";
pub const EVOX2_SCRATCH_BUILD_SOURCE_COMMIT: &str = "4fdd29cb7e76ddd827bcc7ceb8ca36ab28864271";
pub const EVOX2_SCRATCH_BUILD_SOURCE_ARCHIVE_SHA256: &str =
    "162a82f42619249a11a81ce64c29889eb5cd448a2d3d864ccb5bf26f1b0f325d";
pub const EVOX2_SCRATCH_BUILD_TARGET_HOST: &str = "EVO-X2";
pub const EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT: &str = "C:/AI/workspaces/cantor-build-4fdd29cb";
pub const EVOX2_SCRATCH_BUILD_TARGET_ROOT: &str = "C:/AI/builds/cantor-build-4fdd29cb";
pub const EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES: usize = 1_048_576;

const COMMISSION_DIGEST_DOMAIN: &[u8] = b"cantor.evox2-scratch-build.commission.v1\0";
const TOOLCHAIN_DIGEST_DOMAIN: &[u8] = b"cantor.evox2-scratch-build.toolchain.v1\0";
const OPERATION_DIGEST_DOMAIN: &[u8] = b"cantor.evox2-scratch-build.operation.v1\0";
const RECEIPT_DIGEST_DOMAIN: &[u8] = b"cantor.evox2-scratch-build.receipt.v1\0";
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
    if !is_lower_hex(&observation.cargo_sha256, 64)
        || !is_lower_hex(&observation.rustc_sha256, 64)
        || !is_lower_hex(&observation.linker_sha256, 64)
        || observation.offline_probe_status != "available_without_mutation"
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
    let expected_working_directory = if record.ordinal == 7 {
        commission.target_root.as_str()
    } else {
        commission.workspace_root.as_str()
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
