//! Read-only physical acquisition of P2 commit-envelope placement evidence.
//!
//! P2 proves a supplied one-head-lag journal. This module first replays that
//! pure proof and only then invokes one exact hash-pinned Git executable to
//! read carrier commit, tree, and blob objects. It compares raw blob bytes to
//! canonical P2 record JSON plus one LF and emits an observation-only receipt.
//! It has no repository mutation or publication surface.

use std::{
    fmt,
    fs::{self, File},
    io::{self, Read},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::sjs_commit_envelope_journal::{
    CommitEnvelopeJournal, CommitEnvelopeRecord, JournalVerificationReceipt,
    compile_commit_envelope_journal_verification, validate_journal_verification_receipt,
};

pub const PLACEMENT_ACQUISITION_PROFILE: &str = "cantor-sjs-commit-placement-acquisition/0.1";
pub const PHYSICAL_PLACEMENT_EVIDENCE_PROFILE: &str = "cantor-sjs-commit-placement-evidence/0.1";
pub const PLACEMENT_ACQUISITION_RECEIPT_PROFILE: &str =
    "cantor-sjs-commit-placement-acquisition-receipt/0.1";
pub const REPOSITORY_IDENTITY_PROFILE: &str = "cantor-sjs-commit-placement-repository-identity/0.1";
pub const MAX_PLACEMENT_REQUEST_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PLACEMENT_RECEIPT_BYTES: usize = 16 * 1024 * 1024;

const REQUEST_DOMAIN: &[u8] = b"cantor:sjs-commit-placement:request:0.1";
const IDENTITY_DOMAIN: &[u8] = b"cantor:sjs-commit-placement:repository-identity:0.1";
const EVIDENCE_DOMAIN: &[u8] = b"cantor:sjs-commit-placement:evidence:0.1";
const RECEIPT_DOMAIN: &[u8] = b"cantor:sjs-commit-placement:receipt:0.1";
const MAX_PATH_BYTES: usize = 4_096;
const MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_GIT_VERSION_BYTES: usize = 65_536;
const NONAUTHORITY: &str = "observation proves raw carrier commit tree path and canonical P2 record blob identity in one hash-pinned local Git repository only; it grants no hook index mutation staging reset commit push publication provider broker operator self-signature or history-rewrite authority";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementAcquisitionLimits {
    pub max_command_stdout_bytes: u64,
    pub max_command_stderr_bytes: u64,
    pub max_record_blob_bytes: u64,
    pub max_total_record_blob_bytes: u64,
    pub max_git_commands: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitPlacementAcquisitionRequest {
    pub profile: String,
    pub repository_id: String,
    pub branch_ref: String,
    pub expected_head: String,
    pub object_format: String,
    pub repository_root: String,
    pub git_executable: String,
    pub expected_git_sha256: String,
    pub journal: CommitEnvelopeJournal,
    pub limits: PlacementAcquisitionLimits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementAcquisitionAuthority {
    ObservationOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementRepositoryIdentity {
    pub profile: String,
    pub repository_root: String,
    pub branch_ref: String,
    pub head: String,
    pub object_format: String,
    pub git_dir: String,
    pub identity_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalCommitPlacementEvidence {
    pub profile: String,
    pub record_sha256: String,
    pub placement_sha256: String,
    pub carrier_parent_commit: String,
    pub carrier_commit: String,
    pub tree_object_id: String,
    pub journal_path: String,
    pub mode: String,
    pub blob_object_id: String,
    pub blob_sha256: String,
    pub blob_bytes: u64,
    pub canonical_record_sha256: String,
    pub evidence_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitPlacementAcquisitionReceipt {
    pub profile: String,
    pub request_sha256: String,
    pub journal_sha256: String,
    pub journal_receipt_sha256: String,
    pub git_executable_sha256: String,
    pub git_version: String,
    pub repository_before: PlacementRepositoryIdentity,
    pub repository_after: PlacementRepositoryIdentity,
    pub observations: Vec<PhysicalCommitPlacementEvidence>,
    pub command_count: u32,
    pub authority: PlacementAcquisitionAuthority,
    pub physical_contact: bool,
    pub nonauthority: String,
    pub result_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementAcquisitionFaultCode {
    Profile,
    Request,
    P2,
    Executable,
    Repository,
    Identity,
    Process,
    Commit,
    Tree,
    Blob,
    Replay,
    Digest,
    Authority,
    Resource,
    Serialization,
    Io,
    Cli,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementAcquisitionFault {
    pub code: PlacementAcquisitionFaultCode,
    pub message: String,
}

impl PlacementAcquisitionFault {
    pub fn new(code: PlacementAcquisitionFaultCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for PlacementAcquisitionFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for PlacementAcquisitionFault {}

#[derive(Debug)]
struct IdentitySnapshot {
    repository_root: PathBuf,
    branch_ref: String,
    head: String,
    object_format: String,
    git_dir: PathBuf,
}

#[derive(Debug)]
struct BoundedOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    success: bool,
    stdout_over_bound: bool,
    stderr_over_bound: bool,
}

struct GitRunner {
    executable: PathBuf,
    repository_root: PathBuf,
    command_count: u32,
    limits: PlacementAcquisitionLimits,
}

impl GitRunner {
    fn new(
        executable: PathBuf,
        repository_root: PathBuf,
        limits: PlacementAcquisitionLimits,
    ) -> Self {
        Self {
            executable,
            repository_root,
            command_count: 0,
            limits,
        }
    }

    fn run(
        &mut self,
        operation: &[&str],
        stdout_limit: u64,
    ) -> Result<Vec<u8>, PlacementAcquisitionFault> {
        if self.command_count >= self.limits.max_git_commands {
            return fault(
                PlacementAcquisitionFaultCode::Resource,
                "Git command count exceeds request limit",
            );
        }
        self.command_count += 1;
        let repository = self.repository_root.to_string_lossy().into_owned();
        let mut arguments = vec![
            "--no-pager",
            "--no-replace-objects",
            "--literal-pathspecs",
            "-c",
            "core.quotepath=false",
            "-c",
            "protocol.file.allow=never",
            "-C",
            repository.as_str(),
        ];
        arguments.extend_from_slice(operation);

        let global_config = if cfg!(windows) { "NUL" } else { "/dev/null" };
        let mut command = Command::new(&self.executable);
        command
            .args(&arguments)
            .env_clear()
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", global_config)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = run_bounded_command(
            &mut command,
            as_usize(stdout_limit, "command stdout limit")?,
            as_usize(self.limits.max_command_stderr_bytes, "command stderr limit")?,
        )?;
        if output.stdout_over_bound || output.stderr_over_bound {
            return fault(
                PlacementAcquisitionFaultCode::Resource,
                "Git command output exceeds request limit",
            );
        }
        if !output.success {
            return fault(
                PlacementAcquisitionFaultCode::Process,
                "Git command exited unsuccessfully",
            );
        }
        if !output.stderr.is_empty() {
            return fault(
                PlacementAcquisitionFaultCode::Process,
                "Git command produced stderr",
            );
        }
        Ok(output.stdout)
    }
}

pub fn placement_acquisition_request_digest(
    request: &CommitPlacementAcquisitionRequest,
) -> Result<String, PlacementAcquisitionFault> {
    digest_form(REQUEST_DOMAIN, request)
}

pub fn repository_identity_digest(
    identity: &PlacementRepositoryIdentity,
) -> Result<String, PlacementAcquisitionFault> {
    let mut body = identity.clone();
    body.identity_sha256.clear();
    digest_form(IDENTITY_DOMAIN, &body)
}

pub fn physical_placement_evidence_digest(
    evidence: &PhysicalCommitPlacementEvidence,
) -> Result<String, PlacementAcquisitionFault> {
    let mut body = evidence.clone();
    body.evidence_sha256.clear();
    digest_form(EVIDENCE_DOMAIN, &body)
}

pub fn placement_acquisition_receipt_digest(
    receipt: &CommitPlacementAcquisitionReceipt,
) -> Result<String, PlacementAcquisitionFault> {
    let mut body = receipt.clone();
    body.result_sha256.clear();
    digest_form(RECEIPT_DOMAIN, &body)
}

pub fn canonical_record_blob(
    record: &CommitEnvelopeRecord,
) -> Result<Vec<u8>, PlacementAcquisitionFault> {
    let mut bytes = serde_json::to_vec(record).map_err(|error| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Serialization,
            format!("record serialization failed: {error}"),
        )
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn validate_placement_acquisition_request(
    request: &CommitPlacementAcquisitionRequest,
) -> Result<JournalVerificationReceipt, PlacementAcquisitionFault> {
    if request.profile != PLACEMENT_ACQUISITION_PROFILE {
        return fault(
            PlacementAcquisitionFaultCode::Profile,
            "request profile differs",
        );
    }
    validate_encoded_bound(request, MAX_PLACEMENT_REQUEST_BYTES, "request")?;
    validate_semantic_id(&request.repository_id, "repository_id")?;
    validate_branch_ref(&request.branch_ref)?;
    validate_lower_hex(&request.expected_head, 40, "expected_head")?;
    if request.object_format != "sha1" {
        return fault(
            PlacementAcquisitionFaultCode::Request,
            "P3 object format must be sha1",
        );
    }
    validate_absolute_path(&request.repository_root, "repository_root")?;
    validate_absolute_path(&request.git_executable, "git_executable")?;
    validate_upper_sha256(&request.expected_git_sha256, "expected_git_sha256")?;
    validate_limits(&request.limits, request.journal.links.len())?;

    let journal_receipt =
        compile_commit_envelope_journal_verification(&request.journal).map_err(|error| {
            PlacementAcquisitionFault::new(
                PlacementAcquisitionFaultCode::P2,
                format!("P2 journal validation failed: {error}"),
            )
        })?;
    validate_journal_verification_receipt(&request.journal, &journal_receipt).map_err(|error| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::P2,
            format!("P2 receipt replay failed: {error}"),
        )
    })?;
    if request.repository_id != request.journal.repository_id
        || request.branch_ref != request.journal.branch_ref
        || request.expected_head != request.journal.open_tip_commit
        || request
            .journal
            .links
            .last()
            .map(|link| link.placement.carrier_commit.as_str())
            != Some(request.expected_head.as_str())
    {
        return fault(
            PlacementAcquisitionFaultCode::P2,
            "request identity does not join the P2 journal open tip",
        );
    }
    let mut total = 0u64;
    for link in &request.journal.links {
        let bytes = canonical_record_blob(&link.record)?;
        let count = u64::try_from(bytes.len()).map_err(|_| {
            PlacementAcquisitionFault::new(
                PlacementAcquisitionFaultCode::Resource,
                "record blob byte count exceeds u64",
            )
        })?;
        if count > request.limits.max_record_blob_bytes {
            return fault(
                PlacementAcquisitionFaultCode::Resource,
                "canonical record blob exceeds per-record limit",
            );
        }
        total = total.checked_add(count).ok_or_else(|| {
            PlacementAcquisitionFault::new(
                PlacementAcquisitionFaultCode::Resource,
                "canonical record blob total overflow",
            )
        })?;
    }
    if total > request.limits.max_total_record_blob_bytes {
        return fault(
            PlacementAcquisitionFaultCode::Resource,
            "canonical record blob total exceeds limit",
        );
    }
    Ok(journal_receipt)
}

pub fn acquire_commit_placements(
    request: &CommitPlacementAcquisitionRequest,
) -> Result<CommitPlacementAcquisitionReceipt, PlacementAcquisitionFault> {
    let journal_receipt = validate_placement_acquisition_request(request)?;
    let executable = canonical_file(&request.git_executable, "Git executable")?;
    let repository_root = canonical_directory(&request.repository_root, "repository root")?;
    if path_text(&executable, "Git executable")? != request.git_executable {
        return fault(
            PlacementAcquisitionFaultCode::Executable,
            "Git executable path is not canonical",
        );
    }
    if path_text(&repository_root, "repository root")? != request.repository_root {
        return fault(
            PlacementAcquisitionFaultCode::Repository,
            "repository root path is not canonical",
        );
    }
    let executable_before =
        sha256_file_bounded(&executable, MAX_EXECUTABLE_BYTES, "Git executable")?;
    if executable_before != request.expected_git_sha256 {
        return fault(
            PlacementAcquisitionFaultCode::Executable,
            "Git executable SHA256 differs",
        );
    }

    let mut runner = GitRunner::new(
        executable.clone(),
        repository_root.clone(),
        request.limits.clone(),
    );
    let git_version = single_text(
        runner.run(&["--version", "--build-options"], 65_536)?,
        "Git version",
    )?;
    let before_snapshot = read_identity_snapshot(&mut runner)?;
    validate_snapshot(&before_snapshot, request, &repository_root)?;
    let repository_before = snapshot_form(&before_snapshot, request)?;

    let mut total_blob_bytes = 0u64;
    let mut observations = Vec::with_capacity(request.journal.links.len());
    for link in &request.journal.links {
        let commit_bytes = runner.run(
            &["cat-file", "commit", &link.placement.carrier_commit],
            request.limits.max_command_stdout_bytes,
        )?;
        let (tree_object_id, parent_commit) = parse_commit_headers(&commit_bytes)?;
        if parent_commit != link.placement.carrier_parent_commit
            || parent_commit != link.record.payload_resulting_commit
        {
            return fault(
                PlacementAcquisitionFaultCode::Commit,
                "carrier commit parent differs from P2 placement",
            );
        }
        let tree_bytes = runner.run(
            &[
                "ls-tree",
                "-z",
                "--full-tree",
                &link.placement.carrier_commit,
                "--",
                &link.record.journal_path,
            ],
            request.limits.max_command_stdout_bytes,
        )?;
        let (mode, blob_object_id) = parse_tree_entry(&tree_bytes, &link.record.journal_path)?;
        let blob_bytes = runner.run(
            &["cat-file", "blob", &blob_object_id],
            request.limits.max_record_blob_bytes,
        )?;
        total_blob_bytes = total_blob_bytes
            .checked_add(blob_bytes.len() as u64)
            .ok_or_else(|| {
                PlacementAcquisitionFault::new(
                    PlacementAcquisitionFaultCode::Resource,
                    "observed record blob total overflow",
                )
            })?;
        if total_blob_bytes > request.limits.max_total_record_blob_bytes {
            return fault(
                PlacementAcquisitionFaultCode::Resource,
                "observed record blob total exceeds limit",
            );
        }
        let canonical = canonical_record_blob(&link.record)?;
        if blob_bytes != canonical {
            return fault(
                PlacementAcquisitionFaultCode::Blob,
                "raw carrier blob differs from canonical P2 record bytes",
            );
        }
        let canonical_sha256 = sha256_bytes(&canonical);
        let mut evidence = PhysicalCommitPlacementEvidence {
            profile: PHYSICAL_PLACEMENT_EVIDENCE_PROFILE.to_owned(),
            record_sha256: link.record.record_sha256.clone(),
            placement_sha256: link.placement.placement_sha256.clone(),
            carrier_parent_commit: parent_commit,
            carrier_commit: link.placement.carrier_commit.clone(),
            tree_object_id,
            journal_path: link.record.journal_path.clone(),
            mode,
            blob_object_id,
            blob_sha256: sha256_bytes(&blob_bytes),
            blob_bytes: blob_bytes.len() as u64,
            canonical_record_sha256: canonical_sha256,
            evidence_sha256: String::new(),
        };
        evidence.evidence_sha256 = physical_placement_evidence_digest(&evidence)?;
        observations.push(evidence);
    }

    let after_snapshot = read_identity_snapshot(&mut runner)?;
    validate_snapshot(&after_snapshot, request, &repository_root)?;
    if before_snapshot.repository_root != after_snapshot.repository_root
        || before_snapshot.branch_ref != after_snapshot.branch_ref
        || before_snapshot.head != after_snapshot.head
        || before_snapshot.object_format != after_snapshot.object_format
        || before_snapshot.git_dir != after_snapshot.git_dir
    {
        return fault(
            PlacementAcquisitionFaultCode::Replay,
            "repository identity changed during placement acquisition",
        );
    }
    let executable_after =
        sha256_file_bounded(&executable, MAX_EXECUTABLE_BYTES, "Git executable")?;
    if executable_before != executable_after {
        return fault(
            PlacementAcquisitionFaultCode::Replay,
            "Git executable changed during placement acquisition",
        );
    }
    let repository_after = snapshot_form(&after_snapshot, request)?;

    let mut receipt = CommitPlacementAcquisitionReceipt {
        profile: PLACEMENT_ACQUISITION_RECEIPT_PROFILE.to_owned(),
        request_sha256: placement_acquisition_request_digest(request)?,
        journal_sha256: request.journal.journal_sha256.clone(),
        journal_receipt_sha256: journal_receipt.result_sha256,
        git_executable_sha256: executable_after,
        git_version,
        repository_before,
        repository_after,
        observations,
        command_count: runner.command_count,
        authority: PlacementAcquisitionAuthority::ObservationOnly,
        physical_contact: true,
        nonauthority: NONAUTHORITY.to_owned(),
        result_sha256: String::new(),
    };
    receipt.result_sha256 = placement_acquisition_receipt_digest(&receipt)?;
    validate_placement_acquisition_receipt(request, &receipt)?;
    Ok(receipt)
}

pub fn validate_placement_acquisition_receipt(
    request: &CommitPlacementAcquisitionRequest,
    receipt: &CommitPlacementAcquisitionReceipt,
) -> Result<(), PlacementAcquisitionFault> {
    let journal_receipt = validate_placement_acquisition_request(request)?;
    validate_encoded_bound(receipt, MAX_PLACEMENT_RECEIPT_BYTES, "receipt")?;
    if receipt.profile != PLACEMENT_ACQUISITION_RECEIPT_PROFILE
        || receipt.request_sha256 != placement_acquisition_request_digest(request)?
        || receipt.journal_sha256 != request.journal.journal_sha256
        || receipt.journal_receipt_sha256 != journal_receipt.result_sha256
        || receipt.git_executable_sha256 != request.expected_git_sha256
        || receipt.authority != PlacementAcquisitionAuthority::ObservationOnly
        || !receipt.physical_contact
        || receipt.nonauthority != NONAUTHORITY
        || receipt.observations.len() != request.journal.links.len()
    {
        return fault(
            PlacementAcquisitionFaultCode::Authority,
            "placement acquisition receipt identity or authority differs",
        );
    }
    validate_upper_sha256(&receipt.request_sha256, "request_sha256")?;
    validate_upper_sha256(&receipt.journal_receipt_sha256, "journal_receipt_sha256")?;
    validate_upper_sha256(&receipt.git_executable_sha256, "git_executable_sha256")?;
    validate_git_version_text(&receipt.git_version)?;
    validate_identity_form(&receipt.repository_before, request)?;
    validate_identity_form(&receipt.repository_after, request)?;
    if receipt.repository_before != receipt.repository_after {
        return fault(
            PlacementAcquisitionFaultCode::Replay,
            "repository before and after identities differ",
        );
    }
    for (evidence, link) in receipt.observations.iter().zip(&request.journal.links) {
        let canonical = canonical_record_blob(&link.record)?;
        let canonical_sha256 = sha256_bytes(&canonical);
        if evidence.profile != PHYSICAL_PLACEMENT_EVIDENCE_PROFILE
            || evidence.record_sha256 != link.record.record_sha256
            || evidence.placement_sha256 != link.placement.placement_sha256
            || evidence.carrier_parent_commit != link.placement.carrier_parent_commit
            || evidence.carrier_commit != link.placement.carrier_commit
            || evidence.journal_path != link.record.journal_path
            || evidence.mode != "100644"
            || evidence.blob_sha256 != canonical_sha256
            || evidence.canonical_record_sha256 != canonical_sha256
            || evidence.blob_bytes != canonical.len() as u64
        {
            return fault(
                PlacementAcquisitionFaultCode::Replay,
                "physical placement evidence differs from P2 link",
            );
        }
        validate_lower_hex(&evidence.tree_object_id, 40, "tree_object_id")?;
        validate_lower_hex(&evidence.blob_object_id, 40, "blob_object_id")?;
        validate_upper_sha256(&evidence.blob_sha256, "blob_sha256")?;
        validate_upper_sha256(&evidence.canonical_record_sha256, "canonical_record_sha256")?;
        validate_upper_sha256(&evidence.evidence_sha256, "evidence_sha256")?;
        if evidence.evidence_sha256 != physical_placement_evidence_digest(evidence)? {
            return fault(
                PlacementAcquisitionFaultCode::Digest,
                "physical placement evidence digest differs",
            );
        }
    }
    let expected_commands = expected_command_count(request.journal.links.len())?;
    if receipt.command_count != expected_commands
        || receipt.command_count > request.limits.max_git_commands
    {
        return fault(
            PlacementAcquisitionFaultCode::Resource,
            "placement acquisition command count differs",
        );
    }
    validate_upper_sha256(&receipt.result_sha256, "result_sha256")?;
    if receipt.result_sha256 != placement_acquisition_receipt_digest(receipt)? {
        return fault(
            PlacementAcquisitionFaultCode::Digest,
            "placement acquisition receipt digest differs",
        );
    }
    Ok(())
}

pub fn from_placement_acquisition_request_machine_form(
    bytes: &[u8],
) -> Result<CommitPlacementAcquisitionRequest, PlacementAcquisitionFault> {
    let request = deserialize_bounded(bytes, MAX_PLACEMENT_REQUEST_BYTES, "request")?;
    validate_placement_acquisition_request(&request)?;
    Ok(request)
}

pub fn to_placement_acquisition_receipt_machine_form(
    request: &CommitPlacementAcquisitionRequest,
    receipt: &CommitPlacementAcquisitionReceipt,
) -> Result<Vec<u8>, PlacementAcquisitionFault> {
    validate_placement_acquisition_receipt(request, receipt)?;
    serialize_bounded(receipt, MAX_PLACEMENT_RECEIPT_BYTES, "receipt")
}

fn expected_command_count(link_count: usize) -> Result<u32, PlacementAcquisitionFault> {
    let links = u32::try_from(link_count).map_err(|_| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Resource,
            "link count exceeds u32",
        )
    })?;
    11u32
        .checked_add(links.checked_mul(3).ok_or_else(|| {
            PlacementAcquisitionFault::new(
                PlacementAcquisitionFaultCode::Resource,
                "command count overflow",
            )
        })?)
        .ok_or_else(|| {
            PlacementAcquisitionFault::new(
                PlacementAcquisitionFaultCode::Resource,
                "command count overflow",
            )
        })
}

fn read_identity_snapshot(
    runner: &mut GitRunner,
) -> Result<IdentitySnapshot, PlacementAcquisitionFault> {
    let repository_root = canonical_directory_path(
        &PathBuf::from(single_line(
            runner.run(&["rev-parse", "--show-toplevel"], 16_384)?,
            "repository root",
        )?),
        "repository root",
    )?;
    let branch_ref = single_line(
        runner.run(&["symbolic-ref", "-q", "HEAD"], 4_096)?,
        "branch ref",
    )?;
    let head = single_line(runner.run(&["rev-parse", "HEAD"], 4_096)?, "HEAD")?;
    let object_format = single_line(
        runner.run(&["rev-parse", "--show-object-format"], 4_096)?,
        "object format",
    )?;
    let git_dir = canonical_directory_path(
        &PathBuf::from(single_line(
            runner.run(
                &["rev-parse", "--path-format=absolute", "--git-dir"],
                16_384,
            )?,
            "Git directory",
        )?),
        "Git directory",
    )?;
    validate_lower_hex(&head, 40, "observed HEAD")?;
    Ok(IdentitySnapshot {
        repository_root,
        branch_ref,
        head,
        object_format,
        git_dir,
    })
}

fn validate_snapshot(
    snapshot: &IdentitySnapshot,
    request: &CommitPlacementAcquisitionRequest,
    repository_root: &Path,
) -> Result<(), PlacementAcquisitionFault> {
    if snapshot.repository_root != repository_root
        || snapshot.branch_ref != request.branch_ref
        || snapshot.head != request.expected_head
        || snapshot.object_format != request.object_format
    {
        return fault(
            PlacementAcquisitionFaultCode::Identity,
            "observed repository identity differs from request",
        );
    }
    Ok(())
}

fn snapshot_form(
    snapshot: &IdentitySnapshot,
    request: &CommitPlacementAcquisitionRequest,
) -> Result<PlacementRepositoryIdentity, PlacementAcquisitionFault> {
    let mut identity = PlacementRepositoryIdentity {
        profile: REPOSITORY_IDENTITY_PROFILE.to_owned(),
        repository_root: request.repository_root.clone(),
        branch_ref: snapshot.branch_ref.clone(),
        head: snapshot.head.clone(),
        object_format: snapshot.object_format.clone(),
        git_dir: path_text(&snapshot.git_dir, "Git directory")?,
        identity_sha256: String::new(),
    };
    identity.identity_sha256 = repository_identity_digest(&identity)?;
    Ok(identity)
}

fn validate_identity_form(
    identity: &PlacementRepositoryIdentity,
    request: &CommitPlacementAcquisitionRequest,
) -> Result<(), PlacementAcquisitionFault> {
    if identity.profile != REPOSITORY_IDENTITY_PROFILE
        || identity.repository_root != request.repository_root
        || identity.branch_ref != request.branch_ref
        || identity.head != request.expected_head
        || identity.object_format != request.object_format
        || !Path::new(&identity.git_dir).is_absolute()
    {
        return fault(
            PlacementAcquisitionFaultCode::Identity,
            "repository identity form differs",
        );
    }
    validate_upper_sha256(&identity.identity_sha256, "identity_sha256")?;
    if identity.identity_sha256 != repository_identity_digest(identity)? {
        return fault(
            PlacementAcquisitionFaultCode::Digest,
            "repository identity digest differs",
        );
    }
    Ok(())
}

fn parse_commit_headers(bytes: &[u8]) -> Result<(String, String), PlacementAcquisitionFault> {
    if bytes.is_empty() || bytes.contains(&b'\r') || bytes.contains(&0) {
        return fault(
            PlacementAcquisitionFaultCode::Commit,
            "raw commit bytes are empty or contain unsupported framing",
        );
    }
    let header_end = bytes
        .windows(2)
        .position(|pair| pair == b"\n\n")
        .ok_or_else(|| {
            PlacementAcquisitionFault::new(
                PlacementAcquisitionFaultCode::Commit,
                "raw commit lacks header terminator",
            )
        })?;
    let header = std::str::from_utf8(&bytes[..header_end]).map_err(|_| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Commit,
            "raw commit header is not UTF-8",
        )
    })?;
    let mut trees = Vec::new();
    let mut parents = Vec::new();
    for line in header.lines() {
        if let Some(value) = line.strip_prefix("tree ") {
            validate_lower_hex(value, 40, "commit tree object")?;
            trees.push(value.to_owned());
        } else if let Some(value) = line.strip_prefix("parent ") {
            validate_lower_hex(value, 40, "commit parent object")?;
            parents.push(value.to_owned());
        }
    }
    if trees.len() != 1 || parents.len() != 1 {
        return fault(
            PlacementAcquisitionFaultCode::Commit,
            "carrier commit must have exactly one tree and one parent",
        );
    }
    Ok((trees.remove(0), parents.remove(0)))
}

fn parse_tree_entry(
    bytes: &[u8],
    expected_path: &str,
) -> Result<(String, String), PlacementAcquisitionFault> {
    if bytes.is_empty() || *bytes.last().unwrap_or(&1) != 0 {
        return fault(
            PlacementAcquisitionFaultCode::Tree,
            "tree entry is absent or lacks terminal NUL",
        );
    }
    let records: Vec<&[u8]> = bytes[..bytes.len() - 1].split(|byte| *byte == 0).collect();
    if records.len() != 1 || records[0].is_empty() {
        return fault(
            PlacementAcquisitionFaultCode::Tree,
            "tree lookup must return exactly one entry",
        );
    }
    let record = std::str::from_utf8(records[0]).map_err(|_| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Tree,
            "tree entry is not UTF-8",
        )
    })?;
    let (metadata, path) = record.split_once('\t').ok_or_else(|| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Tree,
            "tree entry framing differs",
        )
    })?;
    let fields: Vec<&str> = metadata.split(' ').collect();
    if fields.len() != 3 || fields[0] != "100644" || fields[1] != "blob" || path != expected_path {
        return fault(
            PlacementAcquisitionFaultCode::Tree,
            "tree entry mode type or path differs",
        );
    }
    validate_lower_hex(fields[2], 40, "tree blob object")?;
    Ok((fields[0].to_owned(), fields[2].to_owned()))
}

fn validate_limits(
    limits: &PlacementAcquisitionLimits,
    link_count: usize,
) -> Result<(), PlacementAcquisitionFault> {
    if limits.max_command_stdout_bytes == 0
        || limits.max_command_stdout_bytes > 16 * 1024 * 1024
        || limits.max_command_stderr_bytes == 0
        || limits.max_command_stderr_bytes > 1024 * 1024
        || limits.max_record_blob_bytes == 0
        || limits.max_record_blob_bytes > 1024 * 1024
        || limits.max_total_record_blob_bytes == 0
        || limits.max_total_record_blob_bytes > 32 * 1024 * 1024
        || limits.max_total_record_blob_bytes < limits.max_record_blob_bytes
        || limits.max_git_commands < expected_command_count(link_count)?
        || limits.max_git_commands > 256
    {
        return fault(
            PlacementAcquisitionFaultCode::Resource,
            "placement acquisition limits differ",
        );
    }
    Ok(())
}

fn run_bounded_command(
    command: &mut Command,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<BoundedOutput, PlacementAcquisitionFault> {
    let mut child = command.spawn().map_err(|error| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Process,
            format!("unable to launch Git: {error}"),
        )
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Process,
            "Git stdout pipe is absent",
        )
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Process,
            "Git stderr pipe is absent",
        )
    })?;
    let stdout_thread = thread::spawn(move || drain_bounded(stdout, stdout_limit));
    let stderr_thread = thread::spawn(move || drain_bounded(stderr, stderr_limit));
    let status = child.wait().map_err(|error| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Process,
            format!("unable to wait for Git: {error}"),
        )
    })?;
    let (stdout, stdout_over_bound) = join_reader(stdout_thread, "stdout")?;
    let (stderr, stderr_over_bound) = join_reader(stderr_thread, "stderr")?;
    Ok(BoundedOutput {
        stdout,
        stderr,
        success: status.success(),
        stdout_over_bound,
        stderr_over_bound,
    })
}

fn drain_bounded<R: Read>(mut reader: R, limit: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut retained = Vec::with_capacity(limit.min(65_536));
    let mut over_bound = false;
    let mut buffer = [0u8; 8_192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(retained.len());
        let keep = remaining.min(count);
        retained.extend_from_slice(&buffer[..keep]);
        if keep < count {
            over_bound = true;
        }
    }
    Ok((retained, over_bound))
}

fn join_reader(
    handle: thread::JoinHandle<io::Result<(Vec<u8>, bool)>>,
    stream: &str,
) -> Result<(Vec<u8>, bool), PlacementAcquisitionFault> {
    handle
        .join()
        .map_err(|_| {
            PlacementAcquisitionFault::new(
                PlacementAcquisitionFaultCode::Process,
                format!("Git {stream} reader panicked"),
            )
        })?
        .map_err(|error| {
            PlacementAcquisitionFault::new(
                PlacementAcquisitionFaultCode::Process,
                format!("unable to read Git {stream}: {error}"),
            )
        })
}

fn canonical_file(path: &str, label: &str) -> Result<PathBuf, PlacementAcquisitionFault> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Io,
            format!("unable to canonicalize {label}: {error}"),
        )
    })?;
    let metadata = fs::metadata(&canonical).map_err(|error| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Io,
            format!("unable to inspect {label}: {error}"),
        )
    })?;
    if !metadata.is_file() {
        return fault(
            PlacementAcquisitionFaultCode::Executable,
            format!("{label} is not a regular file"),
        );
    }
    Ok(canonical)
}

fn canonical_directory(path: &str, label: &str) -> Result<PathBuf, PlacementAcquisitionFault> {
    canonical_directory_path(Path::new(path), label)
}

fn canonical_directory_path(
    path: &Path,
    label: &str,
) -> Result<PathBuf, PlacementAcquisitionFault> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Io,
            format!("unable to canonicalize {label}: {error}"),
        )
    })?;
    if !fs::metadata(&canonical)
        .map_err(|error| {
            PlacementAcquisitionFault::new(
                PlacementAcquisitionFaultCode::Io,
                format!("unable to inspect {label}: {error}"),
            )
        })?
        .is_dir()
    {
        return fault(
            PlacementAcquisitionFaultCode::Repository,
            format!("{label} is not a directory"),
        );
    }
    Ok(canonical)
}

fn sha256_file_bounded(
    path: &Path,
    limit: u64,
    label: &str,
) -> Result<String, PlacementAcquisitionFault> {
    let mut file = File::open(path).map_err(|error| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Io,
            format!("unable to open {label}: {error}"),
        )
    })?;
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 65_536];
    loop {
        let count = file.read(&mut buffer).map_err(|error| {
            PlacementAcquisitionFault::new(
                PlacementAcquisitionFaultCode::Io,
                format!("unable to read {label}: {error}"),
            )
        })?;
        if count == 0 {
            break;
        }
        total = total.checked_add(count as u64).ok_or_else(|| {
            PlacementAcquisitionFault::new(
                PlacementAcquisitionFaultCode::Resource,
                format!("{label} byte count overflow"),
            )
        })?;
        if total > limit {
            return fault(
                PlacementAcquisitionFaultCode::Resource,
                format!("{label} exceeds byte limit"),
            );
        }
        digest.update(&buffer[..count]);
    }
    Ok(upper_hex(&digest.finalize()))
}

fn validate_absolute_path(path: &str, label: &str) -> Result<(), PlacementAcquisitionFault> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || path.contains('\0')
        || !Path::new(path).is_absolute()
        || Path::new(path)
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return fault(
            PlacementAcquisitionFaultCode::Request,
            format!("{label} is not a bounded absolute path"),
        );
    }
    Ok(())
}

fn validate_git_version_text(value: &str) -> Result<(), PlacementAcquisitionFault> {
    if value.is_empty() || value.len() > MAX_GIT_VERSION_BYTES || value.contains('\0') {
        return fault(
            PlacementAcquisitionFaultCode::Process,
            "Git version output differs",
        );
    }
    Ok(())
}

fn validate_semantic_id(value: &str, label: &str) -> Result<(), PlacementAcquisitionFault> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
    {
        return fault(
            PlacementAcquisitionFaultCode::Request,
            format!("{label} differs"),
        );
    }
    Ok(())
}

fn validate_branch_ref(value: &str) -> Result<(), PlacementAcquisitionFault> {
    if !value.starts_with("refs/heads/")
        || value.len() > 255
        || value.contains("..")
        || value.contains("@{")
        || value.ends_with('/')
        || value.ends_with('.')
        || value.bytes().any(|byte| {
            byte <= 0x20 || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
    {
        return fault(PlacementAcquisitionFaultCode::Request, "branch_ref differs");
    }
    Ok(())
}

fn validate_lower_hex(
    value: &str,
    length: usize,
    label: &str,
) -> Result<(), PlacementAcquisitionFault> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return fault(
            PlacementAcquisitionFaultCode::Identity,
            format!("{label} differs"),
        );
    }
    Ok(())
}

fn validate_upper_sha256(value: &str, label: &str) -> Result<(), PlacementAcquisitionFault> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
    {
        return fault(
            PlacementAcquisitionFaultCode::Digest,
            format!("{label} differs"),
        );
    }
    Ok(())
}

fn single_line(bytes: Vec<u8>, label: &str) -> Result<String, PlacementAcquisitionFault> {
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Process,
            format!("{label} output is not UTF-8"),
        )
    })?;
    let trimmed = text.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() || trimmed.contains(['\r', '\n', '\0']) {
        return fault(
            PlacementAcquisitionFaultCode::Process,
            format!("{label} output is not one line"),
        );
    }
    Ok(trimmed.to_owned())
}

fn single_text(bytes: Vec<u8>, label: &str) -> Result<String, PlacementAcquisitionFault> {
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Process,
            format!("{label} output is not UTF-8"),
        )
    })?;
    let trimmed = text.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() || trimmed.contains('\0') {
        return fault(
            PlacementAcquisitionFaultCode::Process,
            format!("{label} output differs"),
        );
    }
    Ok(trimmed.to_owned())
}

fn path_text(path: &Path, label: &str) -> Result<String, PlacementAcquisitionFault> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Identity,
            format!("{label} is not UTF-8"),
        )
    })
}

fn validate_encoded_bound<T: Serialize>(
    value: &T,
    limit: usize,
    label: &str,
) -> Result<(), PlacementAcquisitionFault> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Serialization,
            format!("{label} serialization failed: {error}"),
        )
    })?;
    if bytes.is_empty() || bytes.len() > limit {
        return fault(
            PlacementAcquisitionFaultCode::Resource,
            format!("{label} is empty or over bound"),
        );
    }
    Ok(())
}

fn deserialize_bounded<T: DeserializeOwned>(
    bytes: &[u8],
    limit: usize,
    label: &str,
) -> Result<T, PlacementAcquisitionFault> {
    if bytes.is_empty() || bytes.len() > limit {
        return fault(
            PlacementAcquisitionFaultCode::Resource,
            format!("{label} JSON is empty or over bound"),
        );
    }
    serde_json::from_slice(bytes).map_err(|error| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Serialization,
            format!("{label} JSON differs: {error}"),
        )
    })
}

fn serialize_bounded<T: Serialize>(
    value: &T,
    limit: usize,
    label: &str,
) -> Result<Vec<u8>, PlacementAcquisitionFault> {
    let mut bytes = serde_json::to_vec(value).map_err(|error| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Serialization,
            format!("{label} serialization failed: {error}"),
        )
    })?;
    if bytes.is_empty() || bytes.len() + 1 > limit {
        return fault(
            PlacementAcquisitionFaultCode::Resource,
            format!("{label} serialization exceeds bound"),
        );
    }
    bytes.push(b'\n');
    Ok(bytes)
}

fn digest_form<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<String, PlacementAcquisitionFault> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Serialization,
            format!("digest serialization failed: {error}"),
        )
    })?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    digest.update(bytes);
    Ok(upper_hex(&digest.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    upper_hex(&Sha256::digest(bytes))
}

fn upper_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn as_usize(value: u64, label: &str) -> Result<usize, PlacementAcquisitionFault> {
    usize::try_from(value).map_err(|_| {
        PlacementAcquisitionFault::new(
            PlacementAcquisitionFaultCode::Resource,
            format!("{label} exceeds platform usize"),
        )
    })
}

fn fault<T>(
    code: PlacementAcquisitionFaultCode,
    message: impl Into<String>,
) -> Result<T, PlacementAcquisitionFault> {
    Err(PlacementAcquisitionFault::new(code, message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sjs_commit_envelope_journal::{
        CommitEnvelopeRecord, JournalPolicy, PlacementAuthority, PlacementObservation,
        commit_envelope_record_digest, placement_observation_digest,
    };
    use crate::sjs_repository_graph::VerificationAuthority;

    fn record() -> CommitEnvelopeRecord {
        let mut record = CommitEnvelopeRecord {
            profile: crate::sjs_commit_envelope_journal::RECORD_PROFILE.to_owned(),
            record_uuid: "11111111-1111-4111-8111-111111111111".to_owned(),
            change_set_uuid: "22222222-2222-4222-8222-222222222222".to_owned(),
            repository_id: "fixture".to_owned(),
            branch_ref: "refs/heads/main".to_owned(),
            payload_predecessor_commit: "1".repeat(40),
            payload_resulting_commit: "2".repeat(40),
            inventory_sha256: "A".repeat(64),
            candidate_change_set_sha256: "B".repeat(64),
            candidate_receipt_sha256: "C".repeat(64),
            published_change_set_sha256: "D".repeat(64),
            published_receipt_sha256: "E".repeat(64),
            journal_path: "narrative/change_sets/record.json".to_owned(),
            policy: JournalPolicy::ImmediateSuccessor,
            authority: VerificationAuthority::VerificationOnly,
            physical_contact: false,
            record_sha256: String::new(),
        };
        record.record_sha256 = commit_envelope_record_digest(&record).unwrap();
        record
    }

    #[test]
    fn canonical_record_has_exact_lf() {
        let bytes = canonical_record_blob(&record()).unwrap();
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert!(!bytes[..bytes.len() - 1].contains(&b'\n'));
    }

    #[test]
    fn commit_parser_accepts_one_parent() {
        let raw = format!(
            "tree {}\nparent {}\nauthor A <a@example.invalid> 1 +0000\ncommitter A <a@example.invalid> 1 +0000\n\nmessage\n",
            "3".repeat(40),
            "2".repeat(40)
        );
        assert_eq!(
            parse_commit_headers(raw.as_bytes()).unwrap(),
            ("3".repeat(40), "2".repeat(40))
        );
    }

    #[test]
    fn commit_parser_refuses_merge() {
        let raw = format!(
            "tree {}\nparent {}\nparent {}\n\nmerge\n",
            "3".repeat(40),
            "2".repeat(40),
            "4".repeat(40)
        );
        assert_eq!(
            parse_commit_headers(raw.as_bytes()).unwrap_err().code,
            PlacementAcquisitionFaultCode::Commit
        );
    }

    #[test]
    fn tree_parser_accepts_exact_regular_blob() {
        let path = "narrative/change_sets/record.json";
        let raw = format!("100644 blob {}\t{}\0", "a".repeat(40), path);
        assert_eq!(
            parse_tree_entry(raw.as_bytes(), path).unwrap(),
            ("100644".to_owned(), "a".repeat(40))
        );
    }

    #[test]
    fn tree_parser_refuses_executable_mode() {
        let path = "narrative/change_sets/record.json";
        let raw = format!("100755 blob {}\t{}\0", "a".repeat(40), path);
        assert_eq!(
            parse_tree_entry(raw.as_bytes(), path).unwrap_err().code,
            PlacementAcquisitionFaultCode::Tree
        );
    }

    #[test]
    fn tree_parser_refuses_duplicate_entries() {
        let path = "narrative/change_sets/record.json";
        let entry = format!("100644 blob {}\t{}\0", "a".repeat(40), path);
        let raw = format!("{entry}{entry}");
        assert_eq!(
            parse_tree_entry(raw.as_bytes(), path).unwrap_err().code,
            PlacementAcquisitionFaultCode::Tree
        );
    }

    #[test]
    fn placement_digest_is_domain_separated() {
        let record = record();
        let mut placement = PlacementObservation {
            profile: crate::sjs_commit_envelope_journal::PLACEMENT_PROFILE.to_owned(),
            record_sha256: record.record_sha256.clone(),
            journal_path: record.journal_path.clone(),
            carrier_parent_commit: record.payload_resulting_commit.clone(),
            carrier_commit: "4".repeat(40),
            authority: PlacementAuthority::SuppliedData,
            physical_contact: false,
            placement_sha256: String::new(),
        };
        placement.placement_sha256 = placement_observation_digest(&placement).unwrap();
        let bytes = canonical_record_blob(&record).unwrap();
        let mut evidence = PhysicalCommitPlacementEvidence {
            profile: PHYSICAL_PLACEMENT_EVIDENCE_PROFILE.to_owned(),
            record_sha256: record.record_sha256,
            placement_sha256: placement.placement_sha256,
            carrier_parent_commit: placement.carrier_parent_commit,
            carrier_commit: placement.carrier_commit,
            tree_object_id: "5".repeat(40),
            journal_path: placement.journal_path,
            mode: "100644".to_owned(),
            blob_object_id: "6".repeat(40),
            blob_sha256: sha256_bytes(&bytes),
            blob_bytes: bytes.len() as u64,
            canonical_record_sha256: sha256_bytes(&bytes),
            evidence_sha256: String::new(),
        };
        evidence.evidence_sha256 = physical_placement_evidence_digest(&evidence).unwrap();
        assert_ne!(evidence.evidence_sha256, evidence.blob_sha256);
    }

    #[test]
    fn request_parser_denies_unknown_fields() {
        let error = from_placement_acquisition_request_machine_form(
            br#"{"profile":"x","unexpected":true}"#,
        )
        .unwrap_err();
        assert_eq!(error.code, PlacementAcquisitionFaultCode::Serialization);
    }

    #[test]
    fn upper_hex_is_stable() {
        assert_eq!(upper_hex(&[0x00, 0xab, 0xff]), "00ABFF");
    }
}
