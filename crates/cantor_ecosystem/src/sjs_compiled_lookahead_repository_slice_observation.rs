//! Typed request and accounting boundary for exact read-only observation of a
//! supplied compiled-lookahead repository slice.
//!
//! This checkpoint defines and validates the pure request ABI only. It performs
//! no filesystem access and starts no Git process. Physical observation is a
//! later function inside this already-signed module boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

use cantor_core::{
    ContentDigest, SJS_RCX_CANONICAL_UUID, SJS_RCX_SIGNATURE_UUID, SemanticId, SjsRcxEnvelope,
    SjsRcxInputClass, SjsRcxRequest, SjsRcxVerification, sha256_bytes, validate_sjs_rcx_envelope,
    validate_sjs_rcx_request, verify_sjs_rcx,
};
use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SJS_RSO_REQUEST_PROFILE: &str =
    "cantor-sjs-lookahead-repository-slice-observation-request/0.1";
pub const SJS_RSO_RECEIPT_PROFILE: &str =
    "cantor-sjs-lookahead-repository-slice-observation-receipt/0.1";
pub const SJS_RSO_VERIFICATION_PROFILE: &str =
    "cantor-sjs-lookahead-repository-slice-observation-verification/0.1";
pub const SJS_RSO_EVIDENCE_PROFILE: &str =
    "cantor-sjs-lookahead-repository-slice-observation-evidence/0.1";
pub const SJS_RSO_CANONICAL_UUID: &str = "f1fd1689-f290-4be6-ad82-e36d58103e1b";
pub const SJS_RSO_SIGNATURE_UUID: &str = "7966d8e4-4944-4547-ae12-cebbc5f80383";
pub const SJS_RSO_SOURCE_UUID: &str = "e4ca7100-5a6f-4276-8797-e5e79395720c";
pub const SJS_RSO_PARENT_COMPLETION_UUID: &str = "c14b101c-5e52-4ef6-927a-729381f95a2e";
pub const SJS_RSO_MAX_MACHINE_FORM_BYTES: usize = 1_048_576;
pub const SJS_RSO_NON_AUTHORITY: &str = "Request validation only until the separately verified observer executes. A request digest or validation result proves no Git executable identity, repository identity, branch, HEAD, commit bytes, blob bytes, physical contact, parent semantic truth, prompt fit, provider behavior, performance, autonomy, write authority, remote state, or external effect.";

const REQUEST_DOMAIN: &str = "cantor.sjs-rso.request.v1";
const RECEIPT_DOMAIN: &str = "cantor.sjs-rso.receipt.v1";
const VERIFICATION_DOMAIN: &str = "cantor.sjs-rso.verification.v1";
const MAX_DEPTH: usize = 40;
const MAX_FIELDS: usize = 16_384;
const MAX_TEXT_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsRsoInputClass {
    DisposableLocalGitFixture,
    PinnedLocalCommitTree,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRsoLimits {
    pub maximum_git_commands: u32,
    pub maximum_command_milliseconds: u64,
    pub maximum_stdout_bytes: u64,
    pub maximum_stderr_bytes: u64,
    pub maximum_executable_bytes: u64,
    pub maximum_index_bytes: u64,
    pub maximum_commit_bytes: u64,
    pub maximum_blob_bytes: u64,
    pub maximum_total_blob_bytes: u64,
    pub maximum_path_bytes: u32,
    pub maximum_evidence_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRsoRequest {
    pub profile: String,
    pub request_id: SemanticId,
    pub run_id: SemanticId,
    pub receipt_id: SemanticId,
    pub input_class: SjsRsoInputClass,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_snapshot_uuid: String,
    pub parent_canonical_uuid: String,
    pub parent_completion_signature_uuid: String,
    pub parent_request: SjsRcxRequest,
    pub repository_root: String,
    pub git_executable: String,
    pub expected_git_sha256: ContentDigest,
    pub expected_branch_ref: String,
    pub expected_head: String,
    pub object_format: String,
    pub limits: SjsRsoLimits,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub non_authority: String,
    pub request_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsRsoAccountStatus {
    ExactCommittedBlob,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRsoElementAccount {
    pub element_id: SemanticId,
    pub candidate_id: SemanticId,
    pub locator: String,
    pub mode: String,
    pub object_id: String,
    pub raw_bytes: u64,
    pub content_digest: ContentDigest,
    pub status: SjsRsoAccountStatus,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRsoEffectAccount {
    pub read_only_filesystem_observation: bool,
    pub read_only_git_process_observation: bool,
    pub repository_write: bool,
    pub index_write: bool,
    pub worktree_write: bool,
    pub network_contact: bool,
    pub provider_contact: bool,
    pub model_inference: bool,
    pub prompt_stitch: bool,
    pub secret_access: bool,
    pub permission_activation: bool,
    pub remote_hardware_contact: bool,
    pub external_action: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRsoReceipt {
    pub profile: String,
    pub receipt_id: SemanticId,
    pub request_digest: ContentDigest,
    pub git_executable_before_sha256: ContentDigest,
    pub git_executable_after_sha256: ContentDigest,
    pub git_version: String,
    pub git_build_options: String,
    pub repository_root: String,
    pub branch_ref: String,
    pub head: String,
    pub object_format: String,
    pub git_directory: String,
    pub index_path: String,
    pub index_before_sha256: ContentDigest,
    pub index_after_sha256: ContentDigest,
    pub commit_raw_bytes: u64,
    pub unique_blob_count: u32,
    pub total_blob_bytes: u64,
    pub command_count: u32,
    pub accounts: Vec<SjsRsoElementAccount>,
    pub parent_envelope: SjsRcxEnvelope,
    pub parent_verification: SjsRcxVerification,
    pub physical_contact: bool,
    pub effects: SjsRsoEffectAccount,
    pub non_authority: String,
    pub receipt_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRsoVerification {
    pub profile: String,
    pub status: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub request_digest: ContentDigest,
    pub receipt_digest: ContentDigest,
    pub account_count: u32,
    pub unique_blob_count: u32,
    pub total_blob_bytes: u64,
    pub command_count: u32,
    pub physical_contact: bool,
    pub effects: SjsRsoEffectAccount,
    pub parent_verification: SjsRcxVerification,
    pub execution_authorized: bool,
    pub verification_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SjsRsoFaultCode {
    InvalidProfile,
    InvalidIdentity,
    InvalidParent,
    InvalidPath,
    InvalidDigest,
    InvalidGitIdentity,
    InvalidBound,
    InvalidAuthority,
    InvalidMachineForm,
    ArithmeticOverflow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SjsRsoFault {
    pub code: SjsRsoFaultCode,
    pub detail: String,
}

impl fmt::Display for SjsRsoFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}
impl std::error::Error for SjsRsoFault {}

pub fn seal_sjs_rso_request(mut request: SjsRsoRequest) -> Result<SjsRsoRequest, SjsRsoFault> {
    request.request_digest = empty_digest();
    validate_request_body(&request)?;
    request.request_digest = sha256_form(REQUEST_DOMAIN, &request)?;
    validate_sjs_rso_request(&request)?;
    Ok(request)
}

pub fn validate_sjs_rso_request(request: &SjsRsoRequest) -> Result<(), SjsRsoFault> {
    validate_request_body(request)?;
    let expected = digest_without(request, REQUEST_DOMAIN, |value| &mut value.request_digest)?;
    if request.request_digest != expected {
        return Err(fault(
            SjsRsoFaultCode::InvalidDigest,
            "request digest differs",
        ));
    }
    Ok(())
}

pub fn seal_sjs_rso_receipt(
    request: &SjsRsoRequest,
    mut receipt: SjsRsoReceipt,
) -> Result<SjsRsoReceipt, SjsRsoFault> {
    receipt.receipt_digest = empty_digest();
    validate_receipt_body(request, &receipt)?;
    receipt.receipt_digest = sha256_form(RECEIPT_DOMAIN, &receipt)?;
    validate_sjs_rso_receipt(request, &receipt)?;
    Ok(receipt)
}

pub fn validate_sjs_rso_receipt(
    request: &SjsRsoRequest,
    receipt: &SjsRsoReceipt,
) -> Result<(), SjsRsoFault> {
    validate_receipt_body(request, receipt)?;
    let expected = digest_without(receipt, RECEIPT_DOMAIN, |value| &mut value.receipt_digest)?;
    if receipt.receipt_digest != expected {
        return Err(fault(
            SjsRsoFaultCode::InvalidDigest,
            "receipt digest differs",
        ));
    }
    Ok(())
}

pub fn verify_sjs_rso_receipt(
    request: &SjsRsoRequest,
    receipt: &SjsRsoReceipt,
) -> Result<SjsRsoVerification, SjsRsoFault> {
    validate_sjs_rso_receipt(request, receipt)?;
    let mut verification = SjsRsoVerification {
        profile: SJS_RSO_VERIFICATION_PROFILE.to_owned(),
        status: "verified_exact_commit_tree_observation".to_owned(),
        canonical_uuid: SJS_RSO_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_RSO_SIGNATURE_UUID.to_owned(),
        request_digest: request.request_digest.clone(),
        receipt_digest: receipt.receipt_digest.clone(),
        account_count: count_u32(receipt.accounts.len(), "account count")?,
        unique_blob_count: receipt.unique_blob_count,
        total_blob_bytes: receipt.total_blob_bytes,
        command_count: receipt.command_count,
        physical_contact: receipt.physical_contact,
        effects: receipt.effects.clone(),
        parent_verification: receipt.parent_verification.clone(),
        execution_authorized: false,
        verification_digest: empty_digest(),
    };
    verification.verification_digest = sha256_form(VERIFICATION_DOMAIN, &verification)?;
    validate_sjs_rso_verification(request, receipt, &verification)?;
    Ok(verification)
}

pub fn validate_sjs_rso_verification(
    request: &SjsRsoRequest,
    receipt: &SjsRsoReceipt,
    verification: &SjsRsoVerification,
) -> Result<(), SjsRsoFault> {
    validate_sjs_rso_receipt(request, receipt)?;
    if verification.profile != SJS_RSO_VERIFICATION_PROFILE
        || verification.status != "verified_exact_commit_tree_observation"
        || verification.canonical_uuid != SJS_RSO_CANONICAL_UUID
        || verification.signature_uuid != SJS_RSO_SIGNATURE_UUID
        || verification.request_digest != request.request_digest
        || verification.receipt_digest != receipt.receipt_digest
        || verification.account_count != count_u32(receipt.accounts.len(), "account count")?
        || verification.unique_blob_count != receipt.unique_blob_count
        || verification.total_blob_bytes != receipt.total_blob_bytes
        || verification.command_count != receipt.command_count
        || verification.physical_contact != receipt.physical_contact
        || verification.effects != receipt.effects
        || verification.parent_verification != receipt.parent_verification
        || verification.execution_authorized
    {
        return Err(fault(
            SjsRsoFaultCode::InvalidAuthority,
            "verification identity or account differs",
        ));
    }
    let expected = digest_without(verification, VERIFICATION_DOMAIN, |value| {
        &mut value.verification_digest
    })?;
    if verification.verification_digest != expected {
        return Err(fault(
            SjsRsoFaultCode::InvalidDigest,
            "verification digest differs",
        ));
    }
    Ok(())
}

fn validate_receipt_body(
    request: &SjsRsoRequest,
    receipt: &SjsRsoReceipt,
) -> Result<(), SjsRsoFault> {
    validate_sjs_rso_request(request)?;
    if receipt.profile != SJS_RSO_RECEIPT_PROFILE
        || receipt.receipt_id != request.receipt_id
        || receipt.request_digest != request.request_digest
        || receipt.repository_root != request.repository_root
        || receipt.branch_ref != request.expected_branch_ref
        || receipt.head != request.expected_head
        || receipt.object_format != request.object_format
        || receipt.non_authority != SJS_RSO_NON_AUTHORITY
        || !receipt.physical_contact
        || receipt.effects != expected_observation_effects()
    {
        return Err(fault(
            SjsRsoFaultCode::InvalidAuthority,
            "receipt identity authority or effect account differs",
        ));
    }
    for (digest, label) in [
        (
            &receipt.git_executable_before_sha256,
            "Git executable before",
        ),
        (&receipt.git_executable_after_sha256, "Git executable after"),
        (&receipt.index_before_sha256, "index before"),
        (&receipt.index_after_sha256, "index after"),
    ] {
        validate_digest(digest, label)?;
    }
    if receipt.git_executable_before_sha256 != request.expected_git_sha256
        || receipt.git_executable_after_sha256 != request.expected_git_sha256
        || receipt.index_before_sha256 != receipt.index_after_sha256
    {
        return Err(fault(
            SjsRsoFaultCode::InvalidGitIdentity,
            "pre-post executable or index identity differs",
        ));
    }
    validate_text(&receipt.git_version, "Git version")?;
    validate_text(&receipt.git_build_options, "Git build options")?;
    validate_absolute_path(&receipt.git_directory, "Git directory")?;
    validate_absolute_path(&receipt.index_path, "Git index")?;
    if receipt.commit_raw_bytes > request.limits.maximum_commit_bytes
        || receipt.command_count == 0
        || receipt.command_count > request.limits.maximum_git_commands
        || receipt.accounts.len() != request.parent_request.records.len()
        || receipt.accounts.len() > 16
    {
        return Err(fault(
            SjsRsoFaultCode::InvalidBound,
            "receipt count or byte bound differs",
        ));
    }
    let object_width = if request.object_format == "sha1" {
        40
    } else {
        64
    };
    let mut unique_blobs = BTreeMap::new();
    for (account, record) in receipt.accounts.iter().zip(&request.parent_request.records) {
        if account.element_id != record.element_id
            || account.candidate_id != record.candidate.candidate_id
            || account.locator != record.locator
            || account.content_digest != record.content_digest
            || account.status != SjsRsoAccountStatus::ExactCommittedBlob
            || !matches!(account.mode.as_str(), "100644" | "100755")
            || account.object_id.len() != object_width
            || !is_lower_hex(&account.object_id)
            || account.raw_bytes > request.limits.maximum_blob_bytes
        {
            return Err(fault(
                SjsRsoFaultCode::InvalidGitIdentity,
                "element-to-blob account differs",
            ));
        }
        match unique_blobs.get(&account.object_id) {
            Some((raw_bytes, digest))
                if *raw_bytes != account.raw_bytes || *digest != account.content_digest =>
            {
                return Err(fault(
                    SjsRsoFaultCode::InvalidGitIdentity,
                    "one object has conflicting accounts",
                ));
            }
            Some(_) => {}
            None => {
                unique_blobs.insert(
                    account.object_id.clone(),
                    (account.raw_bytes, account.content_digest.clone()),
                );
            }
        }
    }
    let mut total_blob_bytes = 0u64;
    for (raw_bytes, _) in unique_blobs.values() {
        total_blob_bytes = total_blob_bytes
            .checked_add(*raw_bytes)
            .ok_or_else(|| fault(SjsRsoFaultCode::ArithmeticOverflow, "blob bytes overflow"))?;
    }
    if receipt.unique_blob_count != count_u32(unique_blobs.len(), "unique blob count")?
        || receipt.total_blob_bytes != total_blob_bytes
        || receipt.total_blob_bytes > request.limits.maximum_total_blob_bytes
    {
        return Err(fault(
            SjsRsoFaultCode::InvalidBound,
            "unique blob accounting differs",
        ));
    }
    if receipt.parent_envelope.request != request.parent_request {
        return Err(fault(
            SjsRsoFaultCode::InvalidParent,
            "parent request bytes or fields differ",
        ));
    }
    validate_sjs_rcx_envelope(&receipt.parent_envelope).map_err(|error| {
        fault(
            SjsRsoFaultCode::InvalidParent,
            format!("parent envelope refuses: {error}"),
        )
    })?;
    let expected_parent = verify_sjs_rcx(&receipt.parent_envelope).map_err(|error| {
        fault(
            SjsRsoFaultCode::InvalidParent,
            format!("parent verification refuses: {error}"),
        )
    })?;
    if receipt.parent_verification != expected_parent {
        return Err(fault(
            SjsRsoFaultCode::InvalidParent,
            "parent verification differs",
        ));
    }
    Ok(())
}

fn expected_observation_effects() -> SjsRsoEffectAccount {
    SjsRsoEffectAccount {
        read_only_filesystem_observation: true,
        read_only_git_process_observation: true,
        ..SjsRsoEffectAccount::default()
    }
}

fn validate_request_body(request: &SjsRsoRequest) -> Result<(), SjsRsoFault> {
    if request.profile != SJS_RSO_REQUEST_PROFILE {
        return Err(fault(
            SjsRsoFaultCode::InvalidProfile,
            "request profile differs",
        ));
    }
    if request.canonical_uuid != SJS_RSO_CANONICAL_UUID
        || request.signature_uuid != SJS_RSO_SIGNATURE_UUID
        || request.source_snapshot_uuid != SJS_RSO_SOURCE_UUID
        || request.parent_canonical_uuid != SJS_RCX_CANONICAL_UUID
        || request.parent_completion_signature_uuid != SJS_RSO_PARENT_COMPLETION_UUID
        || request.non_authority != SJS_RSO_NON_AUTHORITY
    {
        return Err(fault(
            SjsRsoFaultCode::InvalidAuthority,
            "authority identity differs",
        ));
    }
    for (identity, label) in [
        (&request.request_id, "request"),
        (&request.run_id, "run"),
        (&request.receipt_id, "receipt"),
    ] {
        validate_uuid_id(identity, label)?;
    }
    for evidence_ref in &request.evidence_refs {
        validate_uuid_id(evidence_ref, "evidence reference")?;
    }
    if request.evidence_refs.len() > 64 {
        return Err(fault(
            SjsRsoFaultCode::InvalidBound,
            "evidence references exceed 64",
        ));
    }
    validate_sjs_rcx_request(&request.parent_request).map_err(|error| {
        fault(
            SjsRsoFaultCode::InvalidParent,
            format!("parent request refuses: {error}"),
        )
    })?;
    if request.parent_request.input_class != SjsRcxInputClass::SuppliedUnobservedRepositorySlice
        || request.parent_request.canonical_uuid != SJS_RCX_CANONICAL_UUID
        || request.parent_request.signature_uuid != SJS_RCX_SIGNATURE_UUID
    {
        return Err(fault(
            SjsRsoFaultCode::InvalidParent,
            "parent class or identity differs",
        ));
    }
    validate_absolute_path(&request.repository_root, "repository root")?;
    validate_absolute_path(&request.git_executable, "Git executable")?;
    let normalized_root = request.repository_root.replace('\\', "/");
    if normalized_root != request.parent_request.scope.repository {
        return Err(fault(
            SjsRsoFaultCode::InvalidPath,
            "repository root and parent identity differ",
        ));
    }
    validate_digest(&request.expected_git_sha256, "Git executable SHA256")?;
    validate_text(&request.expected_branch_ref, "branch ref")?;
    let expected_branch = request
        .expected_branch_ref
        .strip_prefix("refs/heads/")
        .ok_or_else(|| {
            fault(
                SjsRsoFaultCode::InvalidGitIdentity,
                "branch ref is not heads",
            )
        })?;
    if expected_branch != request.parent_request.scope.branch {
        return Err(fault(
            SjsRsoFaultCode::InvalidGitIdentity,
            "branch ref and parent branch differ",
        ));
    }
    let head_width = match request.object_format.as_str() {
        "sha1" => 40,
        "sha256" => 64,
        _ => {
            return Err(fault(
                SjsRsoFaultCode::InvalidGitIdentity,
                "object format differs",
            ));
        }
    };
    if request.expected_head.len() != head_width || !is_lower_hex(&request.expected_head) {
        return Err(fault(
            SjsRsoFaultCode::InvalidGitIdentity,
            "HEAD identity differs",
        ));
    }
    validate_limits(&request.limits)?;
    Ok(())
}

fn validate_limits(limits: &SjsRsoLimits) -> Result<(), SjsRsoFault> {
    let valid = (1..=32).contains(&limits.maximum_git_commands)
        && (1..=120_000).contains(&limits.maximum_command_milliseconds)
        && (1..=8_388_608).contains(&limits.maximum_stdout_bytes)
        && (1..=1_048_576).contains(&limits.maximum_stderr_bytes)
        && (1..=67_108_864).contains(&limits.maximum_executable_bytes)
        && (1..=67_108_864).contains(&limits.maximum_index_bytes)
        && (1..=4_194_304).contains(&limits.maximum_commit_bytes)
        && (1..=8_388_608).contains(&limits.maximum_blob_bytes)
        && limits.maximum_total_blob_bytes >= limits.maximum_blob_bytes
        && limits.maximum_total_blob_bytes <= 67_108_864
        && (1..=4_096).contains(&limits.maximum_path_bytes)
        && (1..=8_388_608).contains(&limits.maximum_evidence_bytes);
    if valid {
        Ok(())
    } else {
        Err(fault(
            SjsRsoFaultCode::InvalidBound,
            "observation limits differ",
        ))
    }
}

pub fn to_sjs_rso_request_machine_form(request: &SjsRsoRequest) -> Result<String, SjsRsoFault> {
    to_machine_form(request)
}

pub fn from_sjs_rso_request_machine_form(value: &str) -> Result<SjsRsoRequest, SjsRsoFault> {
    parse_bounded(value)
}

pub fn to_sjs_rso_receipt_machine_form(
    request: &SjsRsoRequest,
    receipt: &SjsRsoReceipt,
) -> Result<String, SjsRsoFault> {
    validate_sjs_rso_receipt(request, receipt)?;
    to_machine_form(receipt)
}

pub fn from_sjs_rso_receipt_machine_form(
    request: &SjsRsoRequest,
    value: &str,
) -> Result<SjsRsoReceipt, SjsRsoFault> {
    let receipt = parse_bounded(value)?;
    validate_sjs_rso_receipt(request, &receipt)?;
    Ok(receipt)
}

pub fn to_sjs_rso_verification_machine_form(
    request: &SjsRsoRequest,
    receipt: &SjsRsoReceipt,
    verification: &SjsRsoVerification,
) -> Result<String, SjsRsoFault> {
    validate_sjs_rso_verification(request, receipt, verification)?;
    to_machine_form(verification)
}

pub fn from_sjs_rso_verification_machine_form(
    request: &SjsRsoRequest,
    receipt: &SjsRsoReceipt,
    value: &str,
) -> Result<SjsRsoVerification, SjsRsoFault> {
    let verification = parse_bounded(value)?;
    validate_sjs_rso_verification(request, receipt, &verification)?;
    Ok(verification)
}

fn validate_absolute_path(value: &str, label: &str) -> Result<(), SjsRsoFault> {
    validate_text(value, label)?;
    if Path::new(value).is_absolute()
        && !value.contains('\0')
        && !value
            .split(['/', '\\'])
            .any(|part| matches!(part, "." | ".."))
    {
        Ok(())
    } else {
        Err(fault(
            SjsRsoFaultCode::InvalidPath,
            format!("{label} is not absolute stable form"),
        ))
    }
}

fn validate_digest(digest: &ContentDigest, label: &str) -> Result<(), SjsRsoFault> {
    if digest.algorithm == "sha256" && digest.value.len() == 64 && is_lower_hex(&digest.value) {
        Ok(())
    } else {
        Err(fault(
            SjsRsoFaultCode::InvalidDigest,
            format!("{label} differs"),
        ))
    }
}

fn count_u32(value: usize, label: &str) -> Result<u32, SjsRsoFault> {
    u32::try_from(value).map_err(|_| {
        fault(
            SjsRsoFaultCode::ArithmeticOverflow,
            format!("{label} exceeds u32"),
        )
    })
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn validate_uuid_id(identity: &SemanticId, label: &str) -> Result<(), SjsRsoFault> {
    let suffix = identity.as_str().rsplit(':').next().unwrap_or_default();
    let bytes = suffix.as_bytes();
    let valid = bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        })
        && suffix != "00000000-0000-0000-0000-000000000000";
    if valid {
        Ok(())
    } else {
        Err(fault(
            SjsRsoFaultCode::InvalidIdentity,
            format!("{label} is not lowercase nonnil UUID-bearing"),
        ))
    }
}

fn validate_text(value: &str, label: &str) -> Result<(), SjsRsoFault> {
    if !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && value.trim() == value
        && value.chars().all(|character| !character.is_control())
    {
        Ok(())
    } else {
        Err(fault(
            SjsRsoFaultCode::InvalidPath,
            format!("{label} text differs"),
        ))
    }
}

fn digest_without<T: Clone + Serialize>(
    value: &T,
    domain: &str,
    field: impl Fn(&mut T) -> &mut ContentDigest,
) -> Result<ContentDigest, SjsRsoFault> {
    let mut copy = value.clone();
    *field(&mut copy) = empty_digest();
    sha256_form(domain, &copy)
}

fn sha256_form<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, SjsRsoFault> {
    let body = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + body.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&body);
    Ok(sha256_bytes(&bytes))
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn to_machine_form<T: Serialize>(value: &T) -> Result<String, SjsRsoFault> {
    serde_json::to_string(value).map_err(machine_fault)
}

fn parse_bounded<T: DeserializeOwned + Serialize>(value: &str) -> Result<T, SjsRsoFault> {
    if value.len() > SJS_RSO_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            SjsRsoFaultCode::InvalidBound,
            "machine form exceeds 1048576 bytes",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_str(value);
    NoDuplicateJson::deserialize(&mut deserializer).map_err(machine_fault)?;
    deserializer.end().map_err(machine_fault)?;
    let shape: Value = serde_json::from_str(value).map_err(machine_fault)?;
    let mut fields = 0;
    validate_shape(&shape, 1, &mut fields)?;
    let parsed: T = serde_json::from_str(value).map_err(machine_fault)?;
    if to_machine_form(&parsed)? != value {
        return Err(fault(
            SjsRsoFaultCode::InvalidMachineForm,
            "machine form is not compact canonical JSON",
        ));
    }
    Ok(parsed)
}

struct NoDuplicateJson;
impl<'de> Deserialize<'de> for NoDuplicateJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NoDuplicateVisitor)?;
        Ok(Self)
    }
}
struct NoDuplicateVisitor;
impl<'de> Visitor<'de> for NoDuplicateVisitor {
    type Value = ();
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON")
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_string<E>(self, _: String) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        while sequence.next_element::<NoDuplicateJson>()?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!("duplicate key {key}")));
            }
            map.next_value::<NoDuplicateJson>()?;
        }
        Ok(())
    }
}

fn validate_shape(value: &Value, depth: usize, fields: &mut usize) -> Result<(), SjsRsoFault> {
    if depth > MAX_DEPTH {
        return Err(fault(
            SjsRsoFaultCode::InvalidMachineForm,
            "depth exceeds 40",
        ));
    }
    match value {
        Value::Object(map) => {
            *fields = fields.checked_add(map.len()).ok_or_else(|| {
                fault(SjsRsoFaultCode::ArithmeticOverflow, "field count overflow")
            })?;
            if *fields > MAX_FIELDS {
                return Err(fault(
                    SjsRsoFaultCode::InvalidMachineForm,
                    "fields exceed 16384",
                ));
            }
            for (key, nested) in map {
                validate_text(key, "field")?;
                validate_shape(nested, depth + 1, fields)?;
            }
        }
        Value::Array(array) => {
            for nested in array {
                validate_shape(nested, depth + 1, fields)?;
            }
        }
        Value::String(text) => validate_text(text, "machine text")?,
        _ => {}
    }
    Ok(())
}

fn machine_fault(error: impl fmt::Display) -> SjsRsoFault {
    fault(SjsRsoFaultCode::InvalidMachineForm, error.to_string())
}
fn fault(code: SjsRsoFaultCode, detail: impl Into<String>) -> SjsRsoFault {
    SjsRsoFault {
        code,
        detail: detail.into(),
    }
}
