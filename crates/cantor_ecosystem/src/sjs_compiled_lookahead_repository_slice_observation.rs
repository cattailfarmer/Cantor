//! Typed request and accounting boundary for exact read-only observation of a
//! supplied compiled-lookahead repository slice.
//!
//! Pure request and receipt validation remain effect-free. The separately
//! prepared, non-clone runner capability performs bounded no-follow filesystem
//! checks and closed Git operations; complete commit-tree receipt composition
//! remains a later function inside this already-signed module boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt as _;

use cantor_core::{
    ContentDigest, SJS_RCX_CANONICAL_UUID, SJS_RCX_SIGNATURE_UUID, SemanticId, SjsRcxEnvelope,
    SjsRcxInputClass, SjsRcxRequest, SjsRcxVerification, compile_sjs_rcx, sha256_bytes,
    validate_sjs_rcx_envelope, validate_sjs_rcx_request, verify_sjs_rcx,
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
pub const SJS_RSO_MAX_EVIDENCE_BUNDLE_BYTES: usize = 8_388_608;
pub const SJS_RSO_NON_AUTHORITY: &str = "Request validation only until the separately verified observer executes. A request digest or validation result proves no Git executable identity, repository identity, branch, HEAD, commit bytes, blob bytes, physical contact, parent semantic truth, prompt fit, provider behavior, performance, autonomy, write authority, remote state, or external effect.";

const REQUEST_DOMAIN: &str = "cantor.sjs-rso.request.v1";
const RECEIPT_DOMAIN: &str = "cantor.sjs-rso.receipt.v1";
const VERIFICATION_DOMAIN: &str = "cantor.sjs-rso.verification.v1";
const REQUEST_FILE: &str = "request.json";
const RECEIPT_FILE: &str = "receipt.json";
const VERIFICATION_FILE: &str = "verification.json";
const MANIFEST_FILE: &str = "evidence_manifest.json";
const MAX_DEPTH: usize = 40;
const MAX_FIELDS: usize = 16_384;
const MAX_TEXT_BYTES: usize = 4_096;
#[cfg(windows)]
const WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRsoEvidenceFile {
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRsoEvidenceManifest {
    pub profile: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub replay_count: u32,
    pub files: BTreeMap<String, SjsRsoEvidenceFile>,
    pub request_digest: ContentDigest,
    pub receipt_digest: ContentDigest,
    pub verification_digest: ContentDigest,
    pub parent_request_digest: ContentDigest,
    pub parent_envelope_digest: ContentDigest,
    pub parent_receipt_digest: ContentDigest,
    pub account_count: u32,
    pub unique_blob_count: u32,
    pub total_blob_bytes: u64,
    pub command_count: u32,
    pub physical_contact: bool,
    pub effects: SjsRsoEffectAccount,
    pub execution_authorized: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRsoEvidenceBundle {
    pub request_file: String,
    pub receipt_file: String,
    pub verification_file: String,
    pub manifest_file: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsRsoGitOperation {
    VersionBuildOptions,
    ShowTopLevel,
    SymbolicFullNameHead,
    Head,
    ObjectFormat,
    GitDirectory,
    IndexPath,
    LsTreeSuppliedLocators,
    CommitHead,
    BlobObject { object_id: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsRsoPathKind {
    RegularFile,
    Directory,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRsoPathIdentity {
    pub canonical_path: String,
    pub kind: SjsRsoPathKind,
    pub byte_length: u64,
    pub file_system_id: Option<u64>,
    pub file_id: Option<u64>,
    pub attributes: u64,
    pub link_count: Option<u64>,
    pub creation_or_change_time: String,
    pub modification_time: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SjsRsoGitCommandObservation {
    pub operation: SjsRsoGitOperation,
    pub command_sequence: u32,
    pub exit_code: u32,
    pub stdout: Vec<u8>,
    pub stdout_observed_bytes: u64,
    pub stderr_observed_bytes: u64,
    pub total_processes: u32,
    pub active_processes_at_terminal: u32,
    pub assigned_before_resume: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRsoRepositoryIdentitySnapshot {
    pub git_version: String,
    pub git_build_options: String,
    pub repository_root: String,
    pub branch_ref: String,
    pub head: String,
    pub object_format: String,
    pub git_directory: SjsRsoPathIdentity,
    pub index_path: SjsRsoPathIdentity,
    pub index_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRsoCommitTreeObservation {
    pub repository_before: SjsRsoRepositoryIdentitySnapshot,
    pub repository_after: SjsRsoRepositoryIdentitySnapshot,
    pub commit_raw_bytes: u64,
    pub unique_blob_count: u32,
    pub total_blob_bytes: u64,
    pub command_count: u32,
    pub accounts: Vec<SjsRsoElementAccount>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SjsRsoTreeEntry {
    mode: String,
    object_id: String,
}

/// Non-clone execution capability formed only from one validated, hash-pinned
/// RSO request. Its private fields prevent arbitrary command or path creation.
#[derive(Debug)]
pub struct SjsRsoGitRunner {
    request: SjsRsoRequest,
    executable_identity: SjsRsoPathIdentity,
    repository_identity: SjsRsoPathIdentity,
    command_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SjsRsoContainedChildSpec {
    pub request_digest: ContentDigest,
    pub operation: SjsRsoGitOperation,
    pub executable: String,
    pub arguments: Vec<String>,
    pub working_directory: String,
    pub environment: Vec<(String, String)>,
    pub stdin: Vec<u8>,
    pub maximum_stdout_bytes: usize,
    pub maximum_stderr_bytes: usize,
    pub timeout_millis: u32,
    pub maximum_active_processes: u32,
    pub maximum_total_processes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SjsRsoContainedChildObservation {
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SjsRsoFaultCode {
    InvalidProfile,
    InvalidIdentity,
    InvalidParent,
    InvalidPath,
    InvalidDigest,
    InvalidGitIdentity,
    InvalidOperation,
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

pub fn sjs_rso_git_arguments(
    request: &SjsRsoRequest,
    operation: &SjsRsoGitOperation,
) -> Result<Vec<String>, SjsRsoFault> {
    validate_sjs_rso_request(request)?;
    let arguments = match operation {
        SjsRsoGitOperation::VersionBuildOptions => vec!["version", "--build-options"],
        SjsRsoGitOperation::ShowTopLevel => vec!["rev-parse", "--show-toplevel"],
        SjsRsoGitOperation::SymbolicFullNameHead => {
            vec!["rev-parse", "--symbolic-full-name", "HEAD"]
        }
        SjsRsoGitOperation::Head => vec!["rev-parse", "HEAD"],
        SjsRsoGitOperation::ObjectFormat => vec!["rev-parse", "--show-object-format"],
        SjsRsoGitOperation::GitDirectory => {
            vec!["rev-parse", "--path-format=absolute", "--git-dir"]
        }
        SjsRsoGitOperation::IndexPath => {
            vec!["rev-parse", "--path-format=absolute", "--git-path", "index"]
        }
        SjsRsoGitOperation::LsTreeSuppliedLocators => {
            let mut values = vec!["ls-tree", "-rz", "--full-tree", "HEAD", "--"]
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            values.extend(
                request
                    .parent_request
                    .records
                    .iter()
                    .map(|record| record.locator.clone()),
            );
            return Ok(values);
        }
        SjsRsoGitOperation::CommitHead => vec!["cat-file", "commit", "HEAD"],
        SjsRsoGitOperation::BlobObject { object_id } => {
            let width = object_identity_width(&request.object_format)?;
            if object_id.len() != width || !is_lower_hex(object_id) {
                return Err(fault(
                    SjsRsoFaultCode::InvalidOperation,
                    "blob object identity differs",
                ));
            }
            return Ok(vec![
                "cat-file".to_owned(),
                "blob".to_owned(),
                object_id.clone(),
            ]);
        }
    };
    Ok(arguments.into_iter().map(str::to_owned).collect())
}

pub fn prepare_sjs_rso_git_runner(request: &SjsRsoRequest) -> Result<SjsRsoGitRunner, SjsRsoFault> {
    validate_sjs_rso_request(request)?;
    let (executable_identity, executable_digest) = hash_sjs_rso_file_stable(
        &request.git_executable,
        request.limits.maximum_executable_bytes,
    )?;
    if executable_digest != request.expected_git_sha256 {
        return Err(fault(
            SjsRsoFaultCode::InvalidGitIdentity,
            "Git executable digest differs",
        ));
    }
    let repository_identity = inspect_sjs_rso_no_follow_path(
        &request.repository_root,
        SjsRsoPathKind::Directory,
        u64::MAX,
    )?;
    Ok(SjsRsoGitRunner {
        request: request.clone(),
        executable_identity,
        repository_identity,
        command_count: 0,
    })
}

pub fn run_sjs_rso_git_operation(
    runner: &mut SjsRsoGitRunner,
    operation: SjsRsoGitOperation,
) -> Result<SjsRsoGitCommandObservation, SjsRsoFault> {
    validate_sjs_rso_request(&runner.request)?;
    runner.command_count = runner.command_count.checked_add(1).ok_or_else(|| {
        fault(
            SjsRsoFaultCode::ArithmeticOverflow,
            "Git command count overflowed",
        )
    })?;
    if runner.command_count > runner.request.limits.maximum_git_commands {
        return Err(fault(
            SjsRsoFaultCode::InvalidBound,
            "Git command count exceeds request bound",
        ));
    }

    let arguments = sjs_rso_git_arguments(&runner.request, &operation)?;
    let maximum_stdout_bytes = usize::try_from(runner.request.limits.maximum_stdout_bytes)
        .map_err(|_| fault(SjsRsoFaultCode::InvalidBound, "stdout bound exceeds usize"))?;
    let maximum_stderr_bytes = usize::try_from(runner.request.limits.maximum_stderr_bytes)
        .map_err(|_| fault(SjsRsoFaultCode::InvalidBound, "stderr bound exceeds usize"))?;
    let timeout_millis = u32::try_from(runner.request.limits.maximum_command_milliseconds)
        .map_err(|_| fault(SjsRsoFaultCode::InvalidBound, "timeout exceeds u32"))?;
    let spec = SjsRsoContainedChildSpec {
        request_digest: runner.request.request_digest.clone(),
        operation: operation.clone(),
        executable: runner.request.git_executable.clone(),
        arguments,
        working_directory: runner.request.repository_root.clone(),
        environment: sjs_rso_git_environment(),
        stdin: Vec::new(),
        maximum_stdout_bytes,
        maximum_stderr_bytes,
        timeout_millis,
        maximum_active_processes: 2,
        maximum_total_processes: 4,
    };
    runner.authorize_contained_spec(&spec)?;
    runner.verify_stable_authority_paths()?;

    #[cfg(windows)]
    let child =
        crate::self_work_update_broker_b1_cdrive_windows_containment::run_sjs_rso_contained_child(
            runner, &spec,
        );
    #[cfg(not(windows))]
    let child: Result<SjsRsoContainedChildObservation, String> =
        Err("RSO process-tree containment is not implemented for this platform".to_owned());

    let postcheck = runner.verify_stable_authority_paths();
    let child = child.map_err(|detail| fault(SjsRsoFaultCode::InvalidOperation, detail));
    postcheck?;
    let child = child?;
    if child.forced_termination {
        return Err(fault(
            SjsRsoFaultCode::InvalidOperation,
            "contained Git command timed out and its job was terminated",
        ));
    }
    if child.stdout_over_bound || child.stderr_over_bound {
        return Err(fault(
            SjsRsoFaultCode::InvalidBound,
            "contained Git output exceeded its bound",
        ));
    }
    if child.exit_code != 0
        || child.stderr_observed_bytes != 0
        || !child.stderr.is_empty()
        || child.active_processes_at_terminal != 0
        || child.resume_previous_count != 1
        || child.stdout_observed_bytes != child.stdout.len() as u64
    {
        return Err(fault(
            SjsRsoFaultCode::InvalidOperation,
            "contained Git command outcome differs",
        ));
    }
    Ok(SjsRsoGitCommandObservation {
        operation,
        command_sequence: runner.command_count,
        exit_code: child.exit_code,
        stdout: child.stdout,
        stdout_observed_bytes: child.stdout_observed_bytes,
        stderr_observed_bytes: child.stderr_observed_bytes,
        total_processes: child.total_processes,
        active_processes_at_terminal: child.active_processes_at_terminal,
        assigned_before_resume: child.resume_previous_count == 1,
    })
}

pub fn observe_sjs_rso_repository_identity(
    runner: &mut SjsRsoGitRunner,
) -> Result<SjsRsoRepositoryIdentitySnapshot, SjsRsoFault> {
    let (git_version, git_build_options) = parse_sjs_rso_git_version(
        run_sjs_rso_git_operation(runner, SjsRsoGitOperation::VersionBuildOptions)?.stdout,
    )?;
    observe_sjs_rso_repository_identity_with_version(runner, git_version, git_build_options)
}

fn observe_sjs_rso_repository_identity_with_version(
    runner: &mut SjsRsoGitRunner,
    git_version: String,
    git_build_options: String,
) -> Result<SjsRsoRepositoryIdentitySnapshot, SjsRsoFault> {
    let repository_root = parse_sjs_rso_git_line(
        run_sjs_rso_git_operation(runner, SjsRsoGitOperation::ShowTopLevel)?.stdout,
        "repository root",
    )?;
    let branch_ref = parse_sjs_rso_git_line(
        run_sjs_rso_git_operation(runner, SjsRsoGitOperation::SymbolicFullNameHead)?.stdout,
        "branch ref",
    )?;
    let head = parse_sjs_rso_git_line(
        run_sjs_rso_git_operation(runner, SjsRsoGitOperation::Head)?.stdout,
        "HEAD",
    )?;
    let object_format = parse_sjs_rso_git_line(
        run_sjs_rso_git_operation(runner, SjsRsoGitOperation::ObjectFormat)?.stdout,
        "object format",
    )?;
    let git_directory_text = parse_sjs_rso_git_line(
        run_sjs_rso_git_operation(runner, SjsRsoGitOperation::GitDirectory)?.stdout,
        "Git directory",
    )?;
    let index_path_text = parse_sjs_rso_git_line(
        run_sjs_rso_git_operation(runner, SjsRsoGitOperation::IndexPath)?.stdout,
        "Git index",
    )?;

    let maximum_path_bytes = usize::try_from(runner.request.limits.maximum_path_bytes)
        .map_err(|_| fault(SjsRsoFaultCode::InvalidBound, "path bound exceeds usize"))?;
    if git_directory_text.len() > maximum_path_bytes || index_path_text.len() > maximum_path_bytes {
        return Err(fault(
            SjsRsoFaultCode::InvalidBound,
            "observed Git path exceeds request bound",
        ));
    }

    let normalized_root = repository_root.replace('\\', "/");
    if normalized_root != runner.request.repository_root.replace('\\', "/")
        || branch_ref != runner.request.expected_branch_ref
        || head != runner.request.expected_head
        || object_format != runner.request.object_format
    {
        return Err(fault(
            SjsRsoFaultCode::InvalidGitIdentity,
            "observed repository identity differs from request",
        ));
    }
    let git_directory =
        inspect_sjs_rso_no_follow_path(&git_directory_text, SjsRsoPathKind::Directory, u64::MAX)?;
    let (index_path, index_sha256) =
        hash_sjs_rso_file_stable(&index_path_text, runner.request.limits.maximum_index_bytes)?;
    if !Path::new(&index_path.canonical_path).starts_with(Path::new(&git_directory.canonical_path))
    {
        return Err(fault(
            SjsRsoFaultCode::InvalidGitIdentity,
            "Git index is outside resolved Git directory",
        ));
    }
    Ok(SjsRsoRepositoryIdentitySnapshot {
        git_version,
        git_build_options,
        repository_root: normalized_root,
        branch_ref,
        head,
        object_format,
        git_directory,
        index_path,
        index_sha256,
    })
}

pub fn observe_sjs_rso_commit_tree(
    runner: &mut SjsRsoGitRunner,
) -> Result<SjsRsoCommitTreeObservation, SjsRsoFault> {
    if runner.command_count != 0 {
        return Err(fault(
            SjsRsoFaultCode::InvalidAuthority,
            "commit-tree observation requires an unused runner",
        ));
    }
    let repository_before = observe_sjs_rso_repository_identity(runner)?;
    let tree_stdout =
        run_sjs_rso_git_operation(runner, SjsRsoGitOperation::LsTreeSuppliedLocators)?.stdout;
    let tree = parse_sjs_rso_supplied_tree(&tree_stdout, &runner.request)?;

    let commit_raw = run_sjs_rso_git_operation(runner, SjsRsoGitOperation::CommitHead)?.stdout;
    let commit_raw_bytes = u64::try_from(commit_raw.len()).map_err(|_| {
        fault(
            SjsRsoFaultCode::ArithmeticOverflow,
            "raw commit byte count exceeds u64",
        )
    })?;
    if commit_raw_bytes > runner.request.limits.maximum_commit_bytes {
        return Err(fault(
            SjsRsoFaultCode::InvalidBound,
            "raw commit exceeds request bound",
        ));
    }
    if sha256_bytes(&commit_raw) != runner.request.parent_request.scope.commit_digest {
        return Err(fault(
            SjsRsoFaultCode::InvalidDigest,
            "raw commit digest differs",
        ));
    }

    let mut unique_blobs = BTreeMap::<String, (u64, ContentDigest)>::new();
    for entry in tree.values() {
        if unique_blobs.contains_key(&entry.object_id) {
            continue;
        }
        let blob = run_sjs_rso_git_operation(
            runner,
            SjsRsoGitOperation::BlobObject {
                object_id: entry.object_id.clone(),
            },
        )?
        .stdout;
        let raw_bytes = u64::try_from(blob.len()).map_err(|_| {
            fault(
                SjsRsoFaultCode::ArithmeticOverflow,
                "raw blob byte count exceeds u64",
            )
        })?;
        if raw_bytes > runner.request.limits.maximum_blob_bytes {
            return Err(fault(
                SjsRsoFaultCode::InvalidBound,
                "raw blob exceeds request bound",
            ));
        }
        unique_blobs.insert(entry.object_id.clone(), (raw_bytes, sha256_bytes(&blob)));
    }

    let mut total_blob_bytes = 0u64;
    for (raw_bytes, _) in unique_blobs.values() {
        total_blob_bytes = total_blob_bytes.checked_add(*raw_bytes).ok_or_else(|| {
            fault(
                SjsRsoFaultCode::ArithmeticOverflow,
                "total raw blob bytes overflowed",
            )
        })?;
    }
    if total_blob_bytes > runner.request.limits.maximum_total_blob_bytes {
        return Err(fault(
            SjsRsoFaultCode::InvalidBound,
            "total unique raw blob bytes exceed request bound",
        ));
    }

    let mut accounts = Vec::with_capacity(runner.request.parent_request.records.len());
    for record in &runner.request.parent_request.records {
        let entry = tree.get(&record.locator).ok_or_else(|| {
            fault(
                SjsRsoFaultCode::InvalidGitIdentity,
                "signed locator is absent from parsed commit tree",
            )
        })?;
        let (raw_bytes, content_digest) = unique_blobs.get(&entry.object_id).ok_or_else(|| {
            fault(
                SjsRsoFaultCode::InvalidGitIdentity,
                "parsed tree object was not read",
            )
        })?;
        if content_digest != &record.content_digest {
            return Err(fault(
                SjsRsoFaultCode::InvalidDigest,
                "committed blob digest differs from signed parent record",
            ));
        }
        accounts.push(SjsRsoElementAccount {
            element_id: record.element_id.clone(),
            candidate_id: record.candidate.candidate_id.clone(),
            locator: record.locator.clone(),
            mode: entry.mode.clone(),
            object_id: entry.object_id.clone(),
            raw_bytes: *raw_bytes,
            content_digest: content_digest.clone(),
            status: SjsRsoAccountStatus::ExactCommittedBlob,
        });
    }

    let repository_after = observe_sjs_rso_repository_identity_with_version(
        runner,
        repository_before.git_version.clone(),
        repository_before.git_build_options.clone(),
    )?;
    verify_sjs_rso_repository_identity_stable(&repository_before, &repository_after)?;
    let unique_blob_count = count_u32(unique_blobs.len(), "unique blob count")?;
    Ok(SjsRsoCommitTreeObservation {
        repository_before,
        repository_after,
        commit_raw_bytes,
        unique_blob_count,
        total_blob_bytes,
        command_count: runner.command_count,
        accounts,
    })
}

pub fn compile_sjs_rso_commit_tree_receipt(
    mut runner: SjsRsoGitRunner,
) -> Result<(SjsRsoReceipt, SjsRsoVerification), SjsRsoFault> {
    let observation = observe_sjs_rso_commit_tree(&mut runner)?;
    let request = runner.request.clone();

    // Parent compilation is deliberately sequenced after the complete physical
    // correspondence and stability observation above. The exact retained parent
    // request is passed unchanged to the existing pure compiler and verifier.
    let parent_envelope = compile_sjs_rcx(&request.parent_request).map_err(|error| {
        fault(
            SjsRsoFaultCode::InvalidParent,
            format!("parent compilation refuses: {error}"),
        )
    })?;
    let parent_verification = verify_sjs_rcx(&parent_envelope).map_err(|error| {
        fault(
            SjsRsoFaultCode::InvalidParent,
            format!("parent verification refuses: {error}"),
        )
    })?;

    let receipt = seal_sjs_rso_receipt(
        &request,
        SjsRsoReceipt {
            profile: SJS_RSO_RECEIPT_PROFILE.to_owned(),
            receipt_id: request.receipt_id.clone(),
            request_digest: request.request_digest.clone(),
            git_executable_before_sha256: request.expected_git_sha256.clone(),
            git_executable_after_sha256: request.expected_git_sha256.clone(),
            git_version: observation.repository_before.git_version.clone(),
            git_build_options: observation.repository_before.git_build_options.clone(),
            repository_root: request.repository_root.clone(),
            branch_ref: observation.repository_before.branch_ref.clone(),
            head: observation.repository_before.head.clone(),
            object_format: observation.repository_before.object_format.clone(),
            git_directory: observation
                .repository_before
                .git_directory
                .canonical_path
                .clone(),
            index_path: observation
                .repository_before
                .index_path
                .canonical_path
                .clone(),
            index_before_sha256: observation.repository_before.index_sha256.clone(),
            index_after_sha256: observation.repository_after.index_sha256.clone(),
            commit_raw_bytes: observation.commit_raw_bytes,
            unique_blob_count: observation.unique_blob_count,
            total_blob_bytes: observation.total_blob_bytes,
            command_count: observation.command_count,
            accounts: observation.accounts,
            parent_envelope,
            parent_verification,
            physical_contact: true,
            effects: expected_observation_effects(),
            non_authority: SJS_RSO_NON_AUTHORITY.to_owned(),
            receipt_digest: empty_digest(),
        },
    )?;
    let verification = verify_sjs_rso_receipt(&request, &receipt)?;
    Ok((receipt, verification))
}

fn parse_sjs_rso_supplied_tree(
    bytes: &[u8],
    request: &SjsRsoRequest,
) -> Result<BTreeMap<String, SjsRsoTreeEntry>, SjsRsoFault> {
    if bytes.is_empty() || !bytes.ends_with(&[0]) {
        return Err(fault(
            SjsRsoFaultCode::InvalidMachineForm,
            "ls-tree output is empty or not NUL-terminated",
        ));
    }
    let object_width = object_identity_width(&request.object_format)?;
    let expected_locators = request
        .parent_request
        .records
        .iter()
        .map(|record| record.locator.as_str())
        .collect::<BTreeSet<_>>();
    if expected_locators.len() != request.parent_request.records.len() {
        return Err(fault(
            SjsRsoFaultCode::InvalidParent,
            "signed parent contains duplicate locators",
        ));
    }

    let mut tree = BTreeMap::new();
    for raw_record in bytes[..bytes.len() - 1].split(|byte| *byte == 0) {
        if raw_record.is_empty() {
            return Err(fault(
                SjsRsoFaultCode::InvalidMachineForm,
                "ls-tree output contains an empty coordinate",
            ));
        }
        let record = std::str::from_utf8(raw_record).map_err(|_| {
            fault(
                SjsRsoFaultCode::InvalidMachineForm,
                "ls-tree coordinate is not UTF-8",
            )
        })?;
        if record.contains('\r') {
            return Err(fault(
                SjsRsoFaultCode::InvalidMachineForm,
                "ls-tree coordinate contains carriage return",
            ));
        }
        let (identity, locator) = record.split_once('\t').ok_or_else(|| {
            fault(
                SjsRsoFaultCode::InvalidMachineForm,
                "ls-tree coordinate lacks path separator",
            )
        })?;
        let fields = identity.split(' ').collect::<Vec<_>>();
        if fields.len() != 3
            || !matches!(fields[0], "100644" | "100755")
            || fields[1] != "blob"
            || fields[2].len() != object_width
            || !is_lower_hex(fields[2])
            || !expected_locators.contains(locator)
        {
            return Err(fault(
                SjsRsoFaultCode::InvalidGitIdentity,
                "ls-tree identity, mode, type, object, or locator differs",
            ));
        }
        let prior = tree.insert(
            locator.to_owned(),
            SjsRsoTreeEntry {
                mode: fields[0].to_owned(),
                object_id: fields[2].to_owned(),
            },
        );
        if prior.is_some() {
            return Err(fault(
                SjsRsoFaultCode::InvalidGitIdentity,
                "ls-tree contains a duplicate locator",
            ));
        }
    }
    if tree.len() != expected_locators.len()
        || tree
            .keys()
            .any(|locator| !expected_locators.contains(locator.as_str()))
    {
        return Err(fault(
            SjsRsoFaultCode::InvalidGitIdentity,
            "ls-tree locator set differs from signed parent",
        ));
    }
    Ok(tree)
}

pub fn verify_sjs_rso_repository_identity_stable(
    before: &SjsRsoRepositoryIdentitySnapshot,
    after: &SjsRsoRepositoryIdentitySnapshot,
) -> Result<(), SjsRsoFault> {
    if before != after {
        return Err(fault(
            SjsRsoFaultCode::InvalidGitIdentity,
            "repository identity snapshot drifted",
        ));
    }
    Ok(())
}

impl SjsRsoGitRunner {
    pub fn command_count(&self) -> u32 {
        self.command_count
    }

    pub(crate) fn authorize_contained_spec(
        &self,
        spec: &SjsRsoContainedChildSpec,
    ) -> Result<(), SjsRsoFault> {
        let expected_arguments = sjs_rso_git_arguments(&self.request, &spec.operation)?;
        let expected_stdout = usize::try_from(self.request.limits.maximum_stdout_bytes)
            .map_err(|_| fault(SjsRsoFaultCode::InvalidBound, "stdout bound exceeds usize"))?;
        let expected_stderr = usize::try_from(self.request.limits.maximum_stderr_bytes)
            .map_err(|_| fault(SjsRsoFaultCode::InvalidBound, "stderr bound exceeds usize"))?;
        let expected_timeout = u32::try_from(self.request.limits.maximum_command_milliseconds)
            .map_err(|_| fault(SjsRsoFaultCode::InvalidBound, "timeout exceeds u32"))?;
        if spec.request_digest != self.request.request_digest
            || spec.executable != self.request.git_executable
            || spec.arguments != expected_arguments
            || spec.working_directory != self.request.repository_root
            || spec.environment != sjs_rso_git_environment()
            || !spec.stdin.is_empty()
            || spec.maximum_stdout_bytes != expected_stdout
            || spec.maximum_stderr_bytes != expected_stderr
            || spec.timeout_millis != expected_timeout
            || spec.maximum_active_processes != 2
            || spec.maximum_total_processes != 4
        {
            return Err(fault(
                SjsRsoFaultCode::InvalidAuthority,
                "contained Git command specification differs",
            ));
        }
        Ok(())
    }

    fn verify_stable_authority_paths(&self) -> Result<(), SjsRsoFault> {
        let (executable_identity, executable_digest) = hash_sjs_rso_file_stable(
            &self.request.git_executable,
            self.request.limits.maximum_executable_bytes,
        )?;
        let repository_identity = inspect_sjs_rso_no_follow_path(
            &self.request.repository_root,
            SjsRsoPathKind::Directory,
            u64::MAX,
        )?;
        if executable_identity != self.executable_identity
            || executable_digest != self.request.expected_git_sha256
            || repository_identity != self.repository_identity
        {
            return Err(fault(
                SjsRsoFaultCode::InvalidGitIdentity,
                "runner authority path identity drifted",
            ));
        }
        Ok(())
    }
}

fn hash_sjs_rso_file_stable(
    value: &str,
    maximum_bytes: u64,
) -> Result<(SjsRsoPathIdentity, ContentDigest), SjsRsoFault> {
    let before = inspect_sjs_rso_no_follow_path(value, SjsRsoPathKind::RegularFile, maximum_bytes)?;
    let retained_limit = maximum_bytes.checked_add(1).ok_or_else(|| {
        fault(
            SjsRsoFaultCode::ArithmeticOverflow,
            "bounded file read limit overflowed",
        )
    })?;
    let mut bytes = Vec::new();
    File::open(value)
        .map_err(|error| path_fault("open bounded file", value, error))?
        .take(retained_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| path_fault("read bounded file", value, error))?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(fault(
            SjsRsoFaultCode::InvalidBound,
            "bounded file read exceeded limit",
        ));
    }
    let digest = sha256_bytes(&bytes);
    let after = inspect_sjs_rso_no_follow_path(value, SjsRsoPathKind::RegularFile, maximum_bytes)?;
    if before != after || before.byte_length != bytes.len() as u64 {
        return Err(fault(
            SjsRsoFaultCode::InvalidPath,
            "bounded file identity drifted during read",
        ));
    }
    Ok((after, digest))
}

fn parse_sjs_rso_git_version(bytes: Vec<u8>) -> Result<(String, String), SjsRsoFault> {
    let lines = parse_sjs_rso_git_lines(bytes, "Git version")?;
    let git_version = lines.first().cloned().ok_or_else(|| {
        fault(
            SjsRsoFaultCode::InvalidGitIdentity,
            "Git version output is empty",
        )
    })?;
    if !git_version.starts_with("git version ") || lines.len() < 2 {
        return Err(fault(
            SjsRsoFaultCode::InvalidGitIdentity,
            "Git version or build options differ",
        ));
    }
    let git_build_options = serde_json::to_string(&lines[1..]).map_err(machine_fault)?;
    Ok((git_version, git_build_options))
}

fn parse_sjs_rso_git_line(bytes: Vec<u8>, label: &str) -> Result<String, SjsRsoFault> {
    let lines = parse_sjs_rso_git_lines(bytes, label)?;
    if lines.len() != 1 {
        return Err(fault(
            SjsRsoFaultCode::InvalidGitIdentity,
            format!("{label} output is not exactly one line"),
        ));
    }
    Ok(lines.into_iter().next().expect("one checked line"))
}

fn parse_sjs_rso_git_lines(bytes: Vec<u8>, label: &str) -> Result<Vec<String>, SjsRsoFault> {
    let text = String::from_utf8(bytes).map_err(|_| {
        fault(
            SjsRsoFaultCode::InvalidGitIdentity,
            format!("{label} output is not UTF-8"),
        )
    })?;
    let body = text.strip_suffix('\n').ok_or_else(|| {
        fault(
            SjsRsoFaultCode::InvalidGitIdentity,
            format!("{label} output lacks one terminal LF"),
        )
    })?;
    if body.is_empty() || body.contains(['\0', '\r']) || body.ends_with('\n') {
        return Err(fault(
            SjsRsoFaultCode::InvalidGitIdentity,
            format!("{label} output contains an invalid line"),
        ));
    }
    let lines = body.split('\n').map(str::to_owned).collect::<Vec<_>>();
    if lines.iter().any(String::is_empty) {
        return Err(fault(
            SjsRsoFaultCode::InvalidGitIdentity,
            format!("{label} output contains an empty line"),
        ));
    }
    Ok(lines)
}

fn sjs_rso_git_environment() -> Vec<(String, String)> {
    [
        ("GCM_INTERACTIVE", "Never"),
        ("GIT_ALLOW_PROTOCOL", "none"),
        ("GIT_ASKPASS", "NUL"),
        ("GIT_ATTR_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "NUL"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_SYSTEM", "NUL"),
        ("GIT_NO_LAZY_FETCH", "1"),
        ("GIT_NO_REPLACE_OBJECTS", "1"),
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("HOME", r"C:\CantorRsoNoHome"),
        ("LANG", "C"),
        ("LC_ALL", "C"),
        ("SSH_ASKPASS", "NUL"),
        ("SYSTEMROOT", r"C:\Windows"),
        ("WINDIR", r"C:\Windows"),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value.to_owned()))
    .collect()
}

pub fn inspect_sjs_rso_no_follow_path(
    value: &str,
    expected_kind: SjsRsoPathKind,
    maximum_bytes: u64,
) -> Result<SjsRsoPathIdentity, SjsRsoFault> {
    validate_absolute_path(value, "observed path")?;
    let supplied = Path::new(value);
    let before = inspect_path_components(supplied)?;
    validate_path_kind_and_bound(&before, expected_kind, maximum_bytes)?;
    let canonical = fs::canonicalize(supplied).map_err(|error| {
        fault(
            SjsRsoFaultCode::InvalidPath,
            format!("unable to canonicalize observed path: {error}"),
        )
    })?;
    let supplied_text = normalized_identity_path(supplied)?;
    if supplied_text != normalized_identity_path(&canonical)? {
        return Err(fault(
            SjsRsoFaultCode::InvalidPath,
            "supplied and canonical path identities differ",
        ));
    }
    let after = inspect_path_components(&canonical)?;
    validate_path_kind_and_bound(&after, expected_kind, maximum_bytes)?;
    let before_identity = platform_path_identity(&supplied_text, expected_kind, &before)?;
    let canonical_text = normalized_identity_path(&canonical)?;
    let after_identity = platform_path_identity(&canonical_text, expected_kind, &after)?;
    if before_identity != after_identity {
        return Err(fault(
            SjsRsoFaultCode::InvalidPath,
            "observed path identity changed during inspection",
        ));
    }
    Ok(after_identity)
}

fn inspect_path_components(path: &Path) -> Result<Metadata, SjsRsoFault> {
    let mut cursor = PathBuf::new();
    let mut rooted = false;
    let mut final_metadata = None;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => cursor.push(prefix.as_os_str()),
            Component::RootDir => {
                cursor.push(component.as_os_str());
                rooted = true;
            }
            Component::Normal(segment) if rooted => cursor.push(segment),
            Component::Normal(_) | Component::CurDir | Component::ParentDir => {
                return Err(fault(
                    SjsRsoFaultCode::InvalidPath,
                    "observed path component is not rooted stable form",
                ));
            }
        }
        if !rooted {
            continue;
        }
        let metadata = fs::symlink_metadata(&cursor).map_err(|error| {
            fault(
                SjsRsoFaultCode::InvalidPath,
                format!("unable to inspect path component: {error}"),
            )
        })?;
        if metadata.file_type().is_symlink() || metadata_is_reparse_point(&metadata) {
            return Err(fault(
                SjsRsoFaultCode::InvalidPath,
                "symbolic-link or reparse-point component refuses",
            ));
        }
        final_metadata = Some(metadata);
    }
    final_metadata.ok_or_else(|| {
        fault(
            SjsRsoFaultCode::InvalidPath,
            "observed path has no inspectable rooted component",
        )
    })
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &Metadata) -> bool {
    sjs_rso_windows_attributes_are_reparse_point(metadata.file_attributes())
}

#[cfg(windows)]
pub fn sjs_rso_windows_attributes_are_reparse_point(attributes: u32) -> bool {
    attributes & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse_point(_: &Metadata) -> bool {
    false
}

fn validate_path_kind_and_bound(
    metadata: &Metadata,
    expected_kind: SjsRsoPathKind,
    maximum_bytes: u64,
) -> Result<(), SjsRsoFault> {
    let kind_matches = match expected_kind {
        SjsRsoPathKind::RegularFile => metadata.is_file(),
        SjsRsoPathKind::Directory => metadata.is_dir(),
    };
    if !kind_matches || metadata.len() > maximum_bytes {
        return Err(fault(
            SjsRsoFaultCode::InvalidPath,
            "observed path kind or byte bound differs",
        ));
    }
    Ok(())
}

fn normalized_identity_path(path: &Path) -> Result<String, SjsRsoFault> {
    let text = path
        .to_str()
        .ok_or_else(|| fault(SjsRsoFaultCode::InvalidPath, "observed path is not UTF-8"))?;
    let normalized = text.replace('\\', "/");
    #[cfg(windows)]
    let normalized = normalized
        .strip_prefix("//?/UNC/")
        .map(|suffix| format!("//{suffix}"))
        .or_else(|| normalized.strip_prefix("//?/").map(str::to_owned))
        .unwrap_or(normalized);
    Ok(normalized)
}

#[cfg(windows)]
fn platform_path_identity(
    canonical_path: &str,
    kind: SjsRsoPathKind,
    metadata: &Metadata,
) -> Result<SjsRsoPathIdentity, SjsRsoFault> {
    Ok(SjsRsoPathIdentity {
        canonical_path: canonical_path.to_owned(),
        kind,
        byte_length: metadata.file_size(),
        file_system_id: None,
        file_id: None,
        attributes: u64::from(metadata.file_attributes()),
        link_count: None,
        creation_or_change_time: metadata.creation_time().to_string(),
        modification_time: metadata.last_write_time().to_string(),
    })
}

#[cfg(unix)]
fn platform_path_identity(
    canonical_path: &str,
    kind: SjsRsoPathKind,
    metadata: &Metadata,
) -> Result<SjsRsoPathIdentity, SjsRsoFault> {
    Ok(SjsRsoPathIdentity {
        canonical_path: canonical_path.to_owned(),
        kind,
        byte_length: metadata.size(),
        file_system_id: Some(metadata.dev()),
        file_id: Some(metadata.ino()),
        attributes: u64::from(metadata.mode()),
        link_count: Some(metadata.nlink()),
        creation_or_change_time: format!("{}:{}", metadata.ctime(), metadata.ctime_nsec()),
        modification_time: format!("{}:{}", metadata.mtime(), metadata.mtime_nsec()),
    })
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
    let head_width = object_identity_width(&request.object_format)?;
    if request.expected_head.len() != head_width || !is_lower_hex(&request.expected_head) {
        return Err(fault(
            SjsRsoFaultCode::InvalidGitIdentity,
            "HEAD identity differs",
        ));
    }
    validate_limits(&request.limits, request.parent_request.records.len())?;
    let maximum_path_bytes = usize::try_from(request.limits.maximum_path_bytes).map_err(|_| {
        fault(
            SjsRsoFaultCode::ArithmeticOverflow,
            "maximum path bytes exceed usize",
        )
    })?;
    if request.repository_root.len() > maximum_path_bytes
        || request.git_executable.len() > maximum_path_bytes
        || request
            .parent_request
            .records
            .iter()
            .any(|record| record.locator.len() > maximum_path_bytes)
    {
        return Err(fault(
            SjsRsoFaultCode::InvalidBound,
            "request path bytes exceed observation limit",
        ));
    }
    Ok(())
}

fn validate_limits(limits: &SjsRsoLimits, record_count: usize) -> Result<(), SjsRsoFault> {
    let record_commands = u32::try_from(record_count).map_err(|_| {
        fault(
            SjsRsoFaultCode::ArithmeticOverflow,
            "record command count exceeds u32",
        )
    })?;
    let minimum_git_commands = 15u32.checked_add(record_commands).ok_or_else(|| {
        fault(
            SjsRsoFaultCode::ArithmeticOverflow,
            "minimum Git command count overflow",
        )
    })?;
    let valid = (minimum_git_commands..=32).contains(&limits.maximum_git_commands)
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

fn object_identity_width(object_format: &str) -> Result<usize, SjsRsoFault> {
    match object_format {
        "sha1" => Ok(40),
        "sha256" => Ok(64),
        _ => Err(fault(
            SjsRsoFaultCode::InvalidGitIdentity,
            "object format differs",
        )),
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

pub fn build_sjs_rso_evidence_bundle(
    request: &SjsRsoRequest,
    receipt: &SjsRsoReceipt,
    verification: &SjsRsoVerification,
    replay_receipt: &SjsRsoReceipt,
    replay_verification: &SjsRsoVerification,
) -> Result<SjsRsoEvidenceBundle, SjsRsoFault> {
    validate_sjs_rso_verification(request, receipt, verification)?;
    validate_sjs_rso_verification(request, replay_receipt, replay_verification)?;
    if receipt != replay_receipt || verification != replay_verification {
        return Err(fault(
            SjsRsoFaultCode::InvalidGitIdentity,
            "second stable physical observation differs from the first",
        ));
    }

    let request_file = canonical_evidence_file(to_sjs_rso_request_machine_form(request)?);
    let receipt_file = canonical_evidence_file(to_sjs_rso_receipt_machine_form(request, receipt)?);
    let verification_file = canonical_evidence_file(to_sjs_rso_verification_machine_form(
        request,
        receipt,
        verification,
    )?);
    let manifest = build_sjs_rso_evidence_manifest(
        &request_file,
        &receipt_file,
        &verification_file,
        receipt,
        verification,
    )?;
    let manifest_file = canonical_evidence_file(to_machine_form(&manifest)?);
    let bundle = SjsRsoEvidenceBundle {
        request_file,
        receipt_file,
        verification_file,
        manifest_file,
    };
    ensure_sjs_rso_evidence_bound(&bundle, request.limits.maximum_evidence_bytes)?;
    Ok(bundle)
}

pub fn verify_sjs_rso_evidence_bundle(
    bundle: &SjsRsoEvidenceBundle,
) -> Result<SjsRsoVerification, SjsRsoFault> {
    ensure_sjs_rso_evidence_bound(bundle, SJS_RSO_MAX_MACHINE_FORM_BYTES as u64)?;
    let request: SjsRsoRequest =
        parse_bounded(canonical_evidence_body(&bundle.request_file, REQUEST_FILE)?)?;
    validate_sjs_rso_request(&request)?;
    ensure_sjs_rso_evidence_bound(bundle, request.limits.maximum_evidence_bytes)?;

    let receipt = from_sjs_rso_receipt_machine_form(
        &request,
        canonical_evidence_body(&bundle.receipt_file, RECEIPT_FILE)?,
    )?;
    let retained_verification = from_sjs_rso_verification_machine_form(
        &request,
        &receipt,
        canonical_evidence_body(&bundle.verification_file, VERIFICATION_FILE)?,
    )?;
    let verification = verify_sjs_rso_receipt(&request, &receipt)?;
    if retained_verification != verification {
        return Err(fault(
            SjsRsoFaultCode::InvalidDigest,
            "retained verification differs from independent replay",
        ));
    }

    let retained_manifest: SjsRsoEvidenceManifest = parse_bounded(canonical_evidence_body(
        &bundle.manifest_file,
        MANIFEST_FILE,
    )?)?;
    let rebuilt_manifest = build_sjs_rso_evidence_manifest(
        &bundle.request_file,
        &bundle.receipt_file,
        &bundle.verification_file,
        &receipt,
        &verification,
    )?;
    if retained_manifest != rebuilt_manifest {
        return Err(fault(
            SjsRsoFaultCode::InvalidDigest,
            "retained evidence manifest differs from independent byte rehash",
        ));
    }
    Ok(verification)
}

pub fn to_sjs_rso_evidence_bundle_machine_form(
    bundle: &SjsRsoEvidenceBundle,
) -> Result<String, SjsRsoFault> {
    to_machine_form(bundle)
}

pub fn from_sjs_rso_evidence_bundle_machine_form(
    value: &str,
) -> Result<SjsRsoEvidenceBundle, SjsRsoFault> {
    if value.len() > SJS_RSO_MAX_EVIDENCE_BUNDLE_BYTES {
        return Err(fault(
            SjsRsoFaultCode::InvalidBound,
            "evidence bundle carrier exceeds 8388608 bytes",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_str(value);
    NoDuplicateJson::deserialize(&mut deserializer).map_err(machine_fault)?;
    deserializer.end().map_err(machine_fault)?;
    let bundle: SjsRsoEvidenceBundle = serde_json::from_str(value).map_err(machine_fault)?;
    if to_sjs_rso_evidence_bundle_machine_form(&bundle)? != value {
        return Err(fault(
            SjsRsoFaultCode::InvalidMachineForm,
            "evidence bundle carrier is not compact canonical JSON",
        ));
    }
    ensure_sjs_rso_evidence_bound(&bundle, SJS_RSO_MAX_MACHINE_FORM_BYTES as u64)?;
    Ok(bundle)
}

fn build_sjs_rso_evidence_manifest(
    request_file: &str,
    receipt_file: &str,
    verification_file: &str,
    receipt: &SjsRsoReceipt,
    verification: &SjsRsoVerification,
) -> Result<SjsRsoEvidenceManifest, SjsRsoFault> {
    let mut files = BTreeMap::new();
    for (path, body) in [
        (REQUEST_FILE, request_file),
        (RECEIPT_FILE, receipt_file),
        (VERIFICATION_FILE, verification_file),
    ] {
        files.insert(
            path.to_owned(),
            SjsRsoEvidenceFile {
                bytes: u64::try_from(body.len()).map_err(|_| {
                    fault(
                        SjsRsoFaultCode::ArithmeticOverflow,
                        "evidence file byte count exceeds u64",
                    )
                })?,
                sha256: sha256_bytes(body.as_bytes()),
            },
        );
    }
    Ok(SjsRsoEvidenceManifest {
        profile: SJS_RSO_EVIDENCE_PROFILE.to_owned(),
        canonical_uuid: SJS_RSO_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_RSO_SIGNATURE_UUID.to_owned(),
        replay_count: 2,
        files,
        request_digest: verification.request_digest.clone(),
        receipt_digest: verification.receipt_digest.clone(),
        verification_digest: verification.verification_digest.clone(),
        parent_request_digest: receipt.parent_envelope.request.request_digest.clone(),
        parent_envelope_digest: receipt.parent_envelope.envelope_digest.clone(),
        parent_receipt_digest: receipt.parent_envelope.receipt.receipt_digest.clone(),
        account_count: verification.account_count,
        unique_blob_count: verification.unique_blob_count,
        total_blob_bytes: verification.total_blob_bytes,
        command_count: verification.command_count,
        physical_contact: true,
        effects: expected_observation_effects(),
        execution_authorized: false,
    })
}

fn canonical_evidence_file(mut value: String) -> String {
    value.push('\n');
    value
}

fn canonical_evidence_body<'a>(value: &'a str, label: &str) -> Result<&'a str, SjsRsoFault> {
    let body = value.strip_suffix('\n').ok_or_else(|| {
        fault(
            SjsRsoFaultCode::InvalidMachineForm,
            format!("{label} lacks one terminal LF"),
        )
    })?;
    if body.is_empty() || body.contains(['\r', '\n']) {
        return Err(fault(
            SjsRsoFaultCode::InvalidMachineForm,
            format!("{label} is not one compact LF-terminated UTF-8 form"),
        ));
    }
    Ok(body)
}

fn ensure_sjs_rso_evidence_bound(
    bundle: &SjsRsoEvidenceBundle,
    maximum_bytes: u64,
) -> Result<(), SjsRsoFault> {
    for (label, value) in [
        (REQUEST_FILE, &bundle.request_file),
        (RECEIPT_FILE, &bundle.receipt_file),
        (VERIFICATION_FILE, &bundle.verification_file),
        (MANIFEST_FILE, &bundle.manifest_file),
    ] {
        let bytes = u64::try_from(value.len()).map_err(|_| {
            fault(
                SjsRsoFaultCode::ArithmeticOverflow,
                "evidence file byte count exceeds u64",
            )
        })?;
        if bytes > maximum_bytes {
            return Err(fault(
                SjsRsoFaultCode::InvalidBound,
                format!("{label} exceeds evidence byte bound"),
            ));
        }
        canonical_evidence_body(value, label)?;
    }
    Ok(())
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

fn path_fault(action: &str, value: &str, error: impl fmt::Display) -> SjsRsoFault {
    fault(
        SjsRsoFaultCode::InvalidPath,
        format!("{action} failed for {value}: {error}"),
    )
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
