//! Read-only acquisition of a Git staged-index diff into the published SJS
//! repository-graph `DiffInventory` form.
//!
//! Unlike `sjs_repository_graph`, this module performs physical observation.
//! It invokes one exact hash-pinned Git executable with a cleared environment,
//! reads repository identities, the index, raw cached diff records, and blob
//! bytes, and emits only an observation receipt. It never mutates Git state.

use std::{
    collections::HashSet,
    fmt,
    fmt::Write as _,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::sjs_repository_graph::{
    DIFF_INVENTORY_PROFILE, DiffEntry, DiffInventory, DiffStatus, diff_inventory_digest,
    validate_diff_inventory,
};

pub const ACQUISITION_PROFILE: &str = "cantor-sjs-staged-diff-acquisition/0.1";
pub const ACQUISITION_RECEIPT_PROFILE: &str = "cantor-sjs-staged-diff-acquisition-receipt/0.1";
pub const MAX_REQUEST_BYTES: usize = 65_536;
pub const MAX_RECEIPT_BYTES: usize = 1_048_576;

const REQUEST_DOMAIN: &[u8] = b"cantor:sjs-staged-diff-acquisition:request:0.1";
const RECEIPT_DOMAIN: &[u8] = b"cantor:sjs-staged-diff-acquisition:receipt:0.1";
const NONAUTHORITY: &str = "observation proves one hash-pinned read-only Git index acquisition only; it grants no staging mutation commit push publication hook installation provider activation self-signature or change-set self-inclusion authority";
const ZERO_SHA1: &str = "0000000000000000000000000000000000000000";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionLimits {
    pub max_command_stdout_bytes: u64,
    pub max_command_stderr_bytes: u64,
    pub max_diff_entries: u32,
    pub max_path_bytes: u32,
    pub max_blob_bytes: u64,
    pub max_total_blob_bytes: u64,
    pub max_index_bytes: u64,
    pub max_git_commands: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedDiffAcquisitionRequest {
    pub profile: String,
    pub repository_id: String,
    pub branch_ref: String,
    pub expected_head: String,
    pub object_format: String,
    pub repository_root: String,
    pub git_executable: String,
    pub expected_git_sha256: String,
    pub generated_refresh_paths: Vec<String>,
    pub limits: AcquisitionLimits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionAuthority {
    ObservationOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedDiffAcquisitionReceipt {
    pub profile: String,
    pub request_sha256: String,
    pub git_executable_sha256: String,
    pub git_version: String,
    pub repository_root: String,
    pub branch_ref: String,
    pub head: String,
    pub object_format: String,
    pub index_path: String,
    pub index_before_sha256: String,
    pub index_after_sha256: String,
    pub inventory: DiffInventory,
    pub command_count: u32,
    pub authority: AcquisitionAuthority,
    pub physical_contact: bool,
    pub nonauthority: String,
    pub result_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionFaultCode {
    Profile,
    Request,
    Executable,
    Repository,
    Identity,
    Index,
    Process,
    Parse,
    Object,
    Inventory,
    Digest,
    Authority,
    Resource,
    Serialization,
    Io,
    Cli,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionFault {
    pub code: AcquisitionFaultCode,
    pub message: String,
}

impl fmt::Display for AcquisitionFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for AcquisitionFault {}

#[derive(Debug)]
struct IdentitySnapshot {
    repository_root: PathBuf,
    branch_ref: String,
    head: String,
    object_format: String,
    git_dir: PathBuf,
    index_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RawDiffRecord {
    old_mode: String,
    new_mode: String,
    old_oid: String,
    new_oid: String,
    status: char,
    score: Option<u8>,
    old_path: Option<String>,
    new_path: Option<String>,
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
    limits: AcquisitionLimits,
}

impl GitRunner {
    fn new(executable: PathBuf, repository_root: PathBuf, limits: AcquisitionLimits) -> Self {
        Self {
            executable,
            repository_root,
            command_count: 0,
            limits,
        }
    }

    fn run(&mut self, operation: &[&str], stdout_limit: u64) -> Result<Vec<u8>, AcquisitionFault> {
        if self.command_count >= self.limits.max_git_commands {
            return fault(
                AcquisitionFaultCode::Resource,
                "Git command count exceeds request limit",
            );
        }
        self.command_count += 1;
        let mut arguments = vec![
            "-c",
            "core.quotepath=false",
            "-c",
            "diff.renames=true",
            "-c",
            "diff.algorithm=myers",
            "-c",
            "protocol.file.allow=never",
            "-C",
        ];
        let repository = self.repository_root.to_string_lossy().into_owned();
        arguments.push(&repository);
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
                AcquisitionFaultCode::Resource,
                "Git command output exceeds request limit",
            );
        }
        if !output.success {
            return fault(
                AcquisitionFaultCode::Process,
                "Git command exited unsuccessfully",
            );
        }
        if !output.stderr.is_empty() {
            return fault(AcquisitionFaultCode::Process, "Git command produced stderr");
        }
        Ok(output.stdout)
    }
}

pub fn acquisition_request_digest(
    request: &StagedDiffAcquisitionRequest,
) -> Result<String, AcquisitionFault> {
    digest_form(REQUEST_DOMAIN, request)
}

pub fn acquisition_receipt_digest(
    receipt: &StagedDiffAcquisitionReceipt,
) -> Result<String, AcquisitionFault> {
    let mut body = receipt.clone();
    body.result_sha256.clear();
    digest_form(RECEIPT_DOMAIN, &body)
}

pub fn acquire_staged_diff(
    request: &StagedDiffAcquisitionRequest,
) -> Result<StagedDiffAcquisitionReceipt, AcquisitionFault> {
    validate_request(request)?;
    let executable = canonical_file(&request.git_executable, "Git executable")?;
    let repository_root = canonical_directory(&request.repository_root, "repository root")?;
    let expected_repository = PathBuf::from(&request.repository_root);
    if canonical_directory_path(&expected_repository, "repository root")? != repository_root {
        return fault(
            AcquisitionFaultCode::Repository,
            "repository root canonicalization differs",
        );
    }
    let executable_before = sha256_file_bounded(&executable, 67_108_864, "Git executable")?;
    if executable_before != request.expected_git_sha256 {
        return fault(
            AcquisitionFaultCode::Executable,
            "Git executable SHA256 differs",
        );
    }

    let mut runner = GitRunner::new(
        executable.clone(),
        repository_root.clone(),
        request.limits.clone(),
    );
    let version = single_text(
        runner.run(&["--version", "--build-options"], 65_536)?,
        "Git version",
    )?;
    let before = read_identity_snapshot(&mut runner, request)?;
    validate_snapshot(&before, request, &repository_root)?;
    let index_before = sha256_file_bounded(
        &before.index_path,
        request.limits.max_index_bytes,
        "Git index",
    )?;

    let raw = runner.run(
        &[
            "diff",
            "--cached",
            "--raw",
            "--no-abbrev",
            "--no-ext-diff",
            "--no-textconv",
            "--submodule=short",
            "--find-renames=50%",
            "-z",
            "--",
        ],
        request.limits.max_command_stdout_bytes,
    )?;
    let records = parse_raw_diff(&raw, &request.limits)?;
    if records.is_empty() {
        return fault(
            AcquisitionFaultCode::Inventory,
            "staged diff is empty and cannot form the P0 DiffInventory",
        );
    }
    let entries = build_entries(&records, request, &mut runner)?;
    let mut inventory = DiffInventory {
        profile: DIFF_INVENTORY_PROFILE.to_owned(),
        repository_id: request.repository_id.clone(),
        branch_ref: request.branch_ref.clone(),
        predecessor_commit: request.expected_head.clone(),
        entries,
        inventory_sha256: String::new(),
    };
    inventory.inventory_sha256 = diff_inventory_digest(&inventory).map_err(|error| {
        AcquisitionFault::new(
            AcquisitionFaultCode::Inventory,
            format!("P0 inventory digest failed: {error}"),
        )
    })?;
    validate_diff_inventory(&inventory).map_err(|error| {
        AcquisitionFault::new(
            AcquisitionFaultCode::Inventory,
            format!("P0 inventory validation failed: {error}"),
        )
    })?;

    let after = read_identity_snapshot(&mut runner, request)?;
    validate_snapshot(&after, request, &repository_root)?;
    if before.branch_ref != after.branch_ref
        || before.head != after.head
        || before.object_format != after.object_format
        || before.repository_root != after.repository_root
        || before.git_dir != after.git_dir
        || before.index_path != after.index_path
    {
        return fault(
            AcquisitionFaultCode::Identity,
            "repository identity changed during acquisition",
        );
    }
    let index_after = sha256_file_bounded(
        &after.index_path,
        request.limits.max_index_bytes,
        "Git index",
    )?;
    if index_before != index_after {
        return fault(
            AcquisitionFaultCode::Index,
            "Git index changed during acquisition",
        );
    }
    let executable_after = sha256_file_bounded(&executable, 67_108_864, "Git executable")?;
    if executable_before != executable_after {
        return fault(
            AcquisitionFaultCode::Executable,
            "Git executable changed during acquisition",
        );
    }

    let mut receipt = StagedDiffAcquisitionReceipt {
        profile: ACQUISITION_RECEIPT_PROFILE.to_owned(),
        request_sha256: acquisition_request_digest(request)?,
        git_executable_sha256: executable_after,
        git_version: version,
        repository_root: path_text(&repository_root, "repository root")?,
        branch_ref: after.branch_ref,
        head: after.head,
        object_format: after.object_format,
        index_path: path_text(&after.index_path, "Git index")?,
        index_before_sha256: index_before,
        index_after_sha256: index_after,
        inventory,
        command_count: runner.command_count,
        authority: AcquisitionAuthority::ObservationOnly,
        physical_contact: true,
        nonauthority: NONAUTHORITY.to_owned(),
        result_sha256: String::new(),
    };
    receipt.result_sha256 = acquisition_receipt_digest(&receipt)?;
    validate_receipt(request, &receipt)?;
    Ok(receipt)
}

pub fn validate_request(request: &StagedDiffAcquisitionRequest) -> Result<(), AcquisitionFault> {
    if request.profile != ACQUISITION_PROFILE {
        return fault(AcquisitionFaultCode::Profile, "request profile differs");
    }
    validate_encoded_bound(request, MAX_REQUEST_BYTES, "request")?;
    validate_semantic_id(&request.repository_id, "repository_id")?;
    validate_branch_ref(&request.branch_ref)?;
    validate_lower_hex(&request.expected_head, 40, "expected_head")?;
    if request.object_format != "sha1" {
        return fault(
            AcquisitionFaultCode::Request,
            "P1 object format must be sha1",
        );
    }
    validate_absolute_path(&request.repository_root, "repository_root")?;
    validate_absolute_path(&request.git_executable, "git_executable")?;
    validate_upper_sha256(&request.expected_git_sha256, "expected_git_sha256")?;
    validate_limits(&request.limits)?;
    if request.generated_refresh_paths.len() > request.limits.max_diff_entries as usize {
        return fault(
            AcquisitionFaultCode::Resource,
            "generated refresh path count exceeds entry limit",
        );
    }
    let mut generated = HashSet::new();
    for path in &request.generated_refresh_paths {
        validate_repository_path(path, request.limits.max_path_bytes)?;
        if !generated.insert(path) {
            return fault(
                AcquisitionFaultCode::Request,
                "duplicate generated refresh path",
            );
        }
    }
    Ok(())
}

pub fn validate_receipt(
    request: &StagedDiffAcquisitionRequest,
    receipt: &StagedDiffAcquisitionReceipt,
) -> Result<(), AcquisitionFault> {
    validate_request(request)?;
    validate_encoded_bound(receipt, MAX_RECEIPT_BYTES, "receipt")?;
    if receipt.profile != ACQUISITION_RECEIPT_PROFILE
        || receipt.request_sha256 != acquisition_request_digest(request)?
        || receipt.git_executable_sha256 != request.expected_git_sha256
        || receipt.branch_ref != request.branch_ref
        || receipt.head != request.expected_head
        || receipt.object_format != request.object_format
        || receipt.authority != AcquisitionAuthority::ObservationOnly
        || !receipt.physical_contact
        || receipt.nonauthority != NONAUTHORITY
        || receipt.index_before_sha256 != receipt.index_after_sha256
    {
        return fault(
            AcquisitionFaultCode::Authority,
            "acquisition receipt identity or authority differs",
        );
    }
    validate_upper_sha256(&receipt.request_sha256, "request_sha256")?;
    validate_upper_sha256(&receipt.git_executable_sha256, "git_executable_sha256")?;
    validate_upper_sha256(&receipt.index_before_sha256, "index_before_sha256")?;
    validate_upper_sha256(&receipt.index_after_sha256, "index_after_sha256")?;
    validate_upper_sha256(&receipt.result_sha256, "result_sha256")?;
    validate_diff_inventory(&receipt.inventory).map_err(|error| {
        AcquisitionFault::new(
            AcquisitionFaultCode::Inventory,
            format!("P0 inventory validation failed: {error}"),
        )
    })?;
    if receipt.inventory.repository_id != request.repository_id
        || receipt.inventory.branch_ref != request.branch_ref
        || receipt.inventory.predecessor_commit != request.expected_head
    {
        return fault(
            AcquisitionFaultCode::Inventory,
            "receipt inventory does not join request",
        );
    }
    if receipt.command_count == 0 || receipt.command_count > request.limits.max_git_commands {
        return fault(
            AcquisitionFaultCode::Resource,
            "receipt command count is invalid",
        );
    }
    if receipt.result_sha256 != acquisition_receipt_digest(receipt)? {
        return fault(AcquisitionFaultCode::Digest, "receipt digest differs");
    }
    Ok(())
}

pub fn from_acquisition_request_machine_form(
    bytes: &[u8],
) -> Result<StagedDiffAcquisitionRequest, AcquisitionFault> {
    let request = deserialize_bounded(bytes, MAX_REQUEST_BYTES, "request")?;
    validate_request(&request)?;
    Ok(request)
}

pub fn to_acquisition_receipt_machine_form(
    request: &StagedDiffAcquisitionRequest,
    receipt: &StagedDiffAcquisitionReceipt,
) -> Result<Vec<u8>, AcquisitionFault> {
    validate_receipt(request, receipt)?;
    serialize_bounded(receipt, MAX_RECEIPT_BYTES, "receipt")
}

fn read_identity_snapshot(
    runner: &mut GitRunner,
    request: &StagedDiffAcquisitionRequest,
) -> Result<IdentitySnapshot, AcquisitionFault> {
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
    let index_path = canonical_file_path(
        &PathBuf::from(single_line(
            runner.run(
                &["rev-parse", "--path-format=absolute", "--git-path", "index"],
                16_384,
            )?,
            "Git index",
        )?),
        "Git index",
    )?;
    if !index_path.starts_with(&git_dir) {
        return fault(
            AcquisitionFaultCode::Index,
            "Git index is outside resolved Git directory",
        );
    }
    if request.object_format == "sha1" {
        validate_lower_hex(&head, 40, "observed HEAD")?;
    }
    Ok(IdentitySnapshot {
        repository_root,
        branch_ref,
        head,
        object_format,
        git_dir,
        index_path,
    })
}

fn validate_snapshot(
    snapshot: &IdentitySnapshot,
    request: &StagedDiffAcquisitionRequest,
    repository_root: &Path,
) -> Result<(), AcquisitionFault> {
    if snapshot.repository_root != repository_root
        || snapshot.branch_ref != request.branch_ref
        || snapshot.head != request.expected_head
        || snapshot.object_format != request.object_format
    {
        return fault(
            AcquisitionFaultCode::Identity,
            "observed repository identity differs from request",
        );
    }
    Ok(())
}

fn parse_raw_diff(
    bytes: &[u8],
    limits: &AcquisitionLimits,
) -> Result<Vec<RawDiffRecord>, AcquisitionFault> {
    if bytes.len() as u64 > limits.max_command_stdout_bytes {
        return fault(
            AcquisitionFaultCode::Resource,
            "raw diff exceeds command stdout limit",
        );
    }
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if *bytes.last().unwrap_or(&1) != 0 {
        return fault(AcquisitionFaultCode::Parse, "raw diff lacks terminal NUL");
    }
    let segments: Vec<&[u8]> = bytes.split(|byte| *byte == 0).collect();
    let mut cursor = 0usize;
    let mut records = Vec::new();
    while cursor + 1 < segments.len() {
        let header = segments[cursor];
        cursor += 1;
        if header.is_empty() || header[0] != b':' {
            return fault(AcquisitionFaultCode::Parse, "raw diff header differs");
        }
        let header_text = std::str::from_utf8(&header[1..]).map_err(|_| {
            AcquisitionFault::new(AcquisitionFaultCode::Parse, "raw header is not UTF-8")
        })?;
        let fields: Vec<&str> = header_text
            .split(' ')
            .filter(|field| !field.is_empty())
            .collect();
        if fields.len() != 5 {
            return fault(
                AcquisitionFaultCode::Parse,
                "raw diff header field count differs",
            );
        }
        let (status, score) = parse_status(fields[4])?;
        if cursor >= segments.len() - 1 {
            return fault(AcquisitionFaultCode::Parse, "raw diff path is absent");
        }
        let first_path = parse_path(segments[cursor], limits.max_path_bytes)?;
        cursor += 1;
        let (old_path, new_path) = if status == 'R' {
            if cursor >= segments.len() - 1 {
                return fault(
                    AcquisitionFaultCode::Parse,
                    "raw rename destination is absent",
                );
            }
            let second_path = parse_path(segments[cursor], limits.max_path_bytes)?;
            cursor += 1;
            (Some(first_path), Some(second_path))
        } else if status == 'D' {
            (Some(first_path), None)
        } else {
            (None, Some(first_path))
        };
        let record = RawDiffRecord {
            old_mode: fields[0].to_owned(),
            new_mode: fields[1].to_owned(),
            old_oid: fields[2].to_owned(),
            new_oid: fields[3].to_owned(),
            status,
            score,
            old_path,
            new_path,
        };
        validate_raw_record(&record)?;
        records.push(record);
        if records.len() > limits.max_diff_entries as usize {
            return fault(
                AcquisitionFaultCode::Resource,
                "raw diff entry count exceeds limit",
            );
        }
    }
    if cursor != segments.len() - 1 || !segments[cursor].is_empty() {
        return fault(
            AcquisitionFaultCode::Parse,
            "raw diff segment termination differs",
        );
    }
    Ok(records)
}

fn parse_status(status: &str) -> Result<(char, Option<u8>), AcquisitionFault> {
    let mut characters = status.chars();
    let code = characters
        .next()
        .ok_or_else(|| AcquisitionFault::new(AcquisitionFaultCode::Parse, "status is empty"))?;
    let suffix: String = characters.collect();
    match code {
        'A' | 'M' | 'D' if suffix.is_empty() => Ok((code, None)),
        'R' if !suffix.is_empty() => {
            let score = suffix.parse::<u8>().map_err(|_| {
                AcquisitionFault::new(AcquisitionFaultCode::Parse, "rename score differs")
            })?;
            if score > 100 {
                return fault(AcquisitionFaultCode::Parse, "rename score exceeds 100");
            }
            Ok((code, Some(score)))
        }
        _ => fault(AcquisitionFaultCode::Parse, "unsupported Git diff status"),
    }
}

fn validate_raw_record(record: &RawDiffRecord) -> Result<(), AcquisitionFault> {
    validate_lower_hex(&record.old_oid, 40, "old object ID")?;
    validate_lower_hex(&record.new_oid, 40, "new object ID")?;
    let old_regular = is_regular_mode(&record.old_mode);
    let new_regular = is_regular_mode(&record.new_mode);
    let shape = match record.status {
        'A' => {
            record.old_mode == "000000"
                && new_regular
                && record.old_oid == ZERO_SHA1
                && record.new_oid != ZERO_SHA1
                && record.old_path.is_none()
                && record.new_path.is_some()
                && record.score.is_none()
        }
        'M' => {
            old_regular
                && new_regular
                && record.old_oid != ZERO_SHA1
                && record.new_oid != ZERO_SHA1
                && record.old_path.is_none()
                && record.new_path.is_some()
                && record.score.is_none()
        }
        'D' => {
            old_regular
                && record.new_mode == "000000"
                && record.old_oid != ZERO_SHA1
                && record.new_oid == ZERO_SHA1
                && record.old_path.is_some()
                && record.new_path.is_none()
                && record.score.is_none()
        }
        'R' => {
            old_regular
                && new_regular
                && record.old_oid != ZERO_SHA1
                && record.new_oid != ZERO_SHA1
                && record.old_path.is_some()
                && record.new_path.is_some()
                && record.old_path != record.new_path
                && record.score.is_some()
        }
        _ => false,
    };
    if !shape {
        return fault(
            AcquisitionFaultCode::Parse,
            "raw diff mode object status or path shape differs",
        );
    }
    Ok(())
}

fn build_entries(
    records: &[RawDiffRecord],
    request: &StagedDiffAcquisitionRequest,
    runner: &mut GitRunner,
) -> Result<Vec<DiffEntry>, AcquisitionFault> {
    let generated: HashSet<&str> = request
        .generated_refresh_paths
        .iter()
        .map(String::as_str)
        .collect();
    let modified: HashSet<&str> = records
        .iter()
        .filter(|record| record.status == 'M')
        .filter_map(|record| record.new_path.as_deref())
        .collect();
    if generated.iter().any(|path| !modified.contains(path)) {
        return fault(
            AcquisitionFaultCode::Request,
            "generated refresh path is not an exact modified coordinate",
        );
    }
    let mut total_blob_bytes = 0u64;
    let mut entries = Vec::with_capacity(records.len());
    for record in records {
        let before_sha256 = if record.old_oid == ZERO_SHA1 {
            None
        } else {
            Some(read_blob_sha256(
                runner,
                &record.old_oid,
                &mut total_blob_bytes,
            )?)
        };
        let after_sha256 = if record.new_oid == ZERO_SHA1 {
            None
        } else {
            Some(read_blob_sha256(
                runner,
                &record.new_oid,
                &mut total_blob_bytes,
            )?)
        };
        let status = match record.status {
            'A' => DiffStatus::Added,
            'M' if generated.contains(record.new_path.as_deref().unwrap_or_default()) => {
                DiffStatus::GeneratedRefresh
            }
            'M' => DiffStatus::Modified,
            'D' => DiffStatus::Deleted,
            'R' => DiffStatus::Renamed,
            _ => unreachable!("raw record was validated"),
        };
        entries.push(DiffEntry {
            status,
            old_path: record.old_path.clone(),
            new_path: record.new_path.clone(),
            before_sha256,
            after_sha256,
        });
    }
    entries.sort_by(|left, right| entry_sort_key(left).cmp(&entry_sort_key(right)));
    let mut coordinates = HashSet::new();
    for entry in &entries {
        let coordinate = (
            status_rank(entry.status),
            entry.old_path.as_deref().unwrap_or_default(),
            entry.new_path.as_deref().unwrap_or_default(),
        );
        if !coordinates.insert(coordinate) {
            return fault(
                AcquisitionFaultCode::Inventory,
                "duplicate acquired diff coordinate",
            );
        }
    }
    Ok(entries)
}

fn read_blob_sha256(
    runner: &mut GitRunner,
    object_id: &str,
    total_blob_bytes: &mut u64,
) -> Result<String, AcquisitionFault> {
    let bytes = runner.run(
        &["cat-file", "blob", object_id],
        runner.limits.max_blob_bytes,
    )?;
    *total_blob_bytes = total_blob_bytes
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| {
            AcquisitionFault::new(AcquisitionFaultCode::Resource, "blob byte total overflow")
        })?;
    if *total_blob_bytes > runner.limits.max_total_blob_bytes {
        return fault(
            AcquisitionFaultCode::Resource,
            "aggregate blob bytes exceed request limit",
        );
    }
    Ok(sha256_bytes(&bytes))
}

fn entry_sort_key(entry: &DiffEntry) -> (u8, &str, &str) {
    (
        status_rank(entry.status),
        entry.old_path.as_deref().unwrap_or_default(),
        entry.new_path.as_deref().unwrap_or_default(),
    )
}

fn status_rank(status: DiffStatus) -> u8 {
    match status {
        DiffStatus::Added => 0,
        DiffStatus::Modified => 1,
        DiffStatus::Deleted => 2,
        DiffStatus::Renamed => 3,
        DiffStatus::GeneratedRefresh => 4,
    }
}

fn run_bounded_command(
    command: &mut Command,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<BoundedOutput, AcquisitionFault> {
    let mut child = command.spawn().map_err(|error| {
        AcquisitionFault::new(
            AcquisitionFaultCode::Process,
            format!("unable to launch Git: {error}"),
        )
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        AcquisitionFault::new(AcquisitionFaultCode::Process, "Git stdout pipe is absent")
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        AcquisitionFault::new(AcquisitionFaultCode::Process, "Git stderr pipe is absent")
    })?;
    let stdout_thread = thread::spawn(move || drain_bounded(stdout, stdout_limit));
    let stderr_thread = thread::spawn(move || drain_bounded(stderr, stderr_limit));
    let status = child.wait().map_err(|error| {
        AcquisitionFault::new(
            AcquisitionFaultCode::Process,
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
) -> Result<(Vec<u8>, bool), AcquisitionFault> {
    handle
        .join()
        .map_err(|_| {
            AcquisitionFault::new(
                AcquisitionFaultCode::Process,
                format!("Git {stream} reader panicked"),
            )
        })?
        .map_err(|error| {
            AcquisitionFault::new(
                AcquisitionFaultCode::Io,
                format!("unable to read Git {stream}: {error}"),
            )
        })
}

fn single_line(bytes: Vec<u8>, label: &str) -> Result<String, AcquisitionFault> {
    let text = single_text(bytes, label)?;
    if text.contains('\n') || text.contains('\r') {
        return fault(
            AcquisitionFaultCode::Parse,
            format!("{label} contains multiple lines"),
        );
    }
    Ok(text)
}

fn single_text(bytes: Vec<u8>, label: &str) -> Result<String, AcquisitionFault> {
    let text = String::from_utf8(bytes).map_err(|_| {
        AcquisitionFault::new(AcquisitionFaultCode::Parse, format!("{label} is not UTF-8"))
    })?;
    let trimmed = text.trim_end_matches(['\r', '\n']).to_owned();
    if trimmed.is_empty() {
        return fault(AcquisitionFaultCode::Parse, format!("{label} is empty"));
    }
    Ok(trimmed)
}

fn parse_path(bytes: &[u8], max_path_bytes: u32) -> Result<String, AcquisitionFault> {
    let path = std::str::from_utf8(bytes)
        .map_err(|_| AcquisitionFault::new(AcquisitionFaultCode::Parse, "Git path is not UTF-8"))?
        .to_owned();
    validate_repository_path(&path, max_path_bytes)?;
    Ok(path)
}

fn validate_limits(limits: &AcquisitionLimits) -> Result<(), AcquisitionFault> {
    let valid = (1_024..=16_777_216).contains(&limits.max_command_stdout_bytes)
        && (1..=1_048_576).contains(&limits.max_command_stderr_bytes)
        && (1..=1_024).contains(&limits.max_diff_entries)
        && (1..=1_024).contains(&limits.max_path_bytes)
        && (1..=67_108_864).contains(&limits.max_blob_bytes)
        && limits.max_total_blob_bytes >= limits.max_blob_bytes
        && limits.max_total_blob_bytes <= 536_870_912
        && (1..=67_108_864).contains(&limits.max_index_bytes)
        && (12..=4_096).contains(&limits.max_git_commands);
    if !valid {
        return fault(
            AcquisitionFaultCode::Resource,
            "acquisition limits are outside the governed range",
        );
    }
    Ok(())
}

fn validate_semantic_id(value: &str, label: &str) -> Result<(), AcquisitionFault> {
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'-' | b'_' | b'/')
        })
    {
        return fault(
            AcquisitionFaultCode::Request,
            format!("{label} is not a normalized semantic ID"),
        );
    }
    Ok(())
}

fn validate_branch_ref(value: &str) -> Result<(), AcquisitionFault> {
    if !value.starts_with("refs/heads/")
        || value.len() > 512
        || value.contains("..")
        || value.contains([' ', '~', '^', ':', '?', '*', '[', '\\'])
    {
        return fault(
            AcquisitionFaultCode::Request,
            "branch_ref is not a conservative local branch ref",
        );
    }
    Ok(())
}

fn validate_lower_hex(value: &str, length: usize, label: &str) -> Result<(), AcquisitionFault> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return fault(
            AcquisitionFaultCode::Identity,
            format!("{label} is not lowercase hexadecimal of length {length}"),
        );
    }
    Ok(())
}

fn validate_upper_sha256(value: &str, label: &str) -> Result<(), AcquisitionFault> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
    {
        return fault(
            AcquisitionFaultCode::Digest,
            format!("{label} is not uppercase SHA256"),
        );
    }
    Ok(())
}

fn validate_absolute_path(value: &str, label: &str) -> Result<(), AcquisitionFault> {
    if value.is_empty() || value.len() > 4_096 || !Path::new(value).is_absolute() {
        return fault(
            AcquisitionFaultCode::Request,
            format!("{label} is not a bounded absolute path"),
        );
    }
    Ok(())
}

fn validate_repository_path(value: &str, max_bytes: u32) -> Result<(), AcquisitionFault> {
    if value.len() > max_bytes as usize {
        return fault(
            AcquisitionFaultCode::Resource,
            "repository path exceeds byte bound",
        );
    }
    let valid = !value.is_empty()
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && !value.contains('\\')
        && !value.contains('\0')
        && !value.contains(':')
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..");
    if !valid {
        return fault(
            AcquisitionFaultCode::Parse,
            "repository path is not normalized",
        );
    }
    Ok(())
}

fn is_regular_mode(mode: &str) -> bool {
    matches!(mode, "100644" | "100755")
}

fn canonical_file(value: &str, label: &str) -> Result<PathBuf, AcquisitionFault> {
    canonical_file_path(Path::new(value), label)
}

fn canonical_file_path(value: &Path, label: &str) -> Result<PathBuf, AcquisitionFault> {
    let canonical = fs::canonicalize(value).map_err(|error| {
        AcquisitionFault::new(
            AcquisitionFaultCode::Io,
            format!("unable to resolve {label}: {error}"),
        )
    })?;
    let metadata = fs::metadata(&canonical).map_err(|error| {
        AcquisitionFault::new(
            AcquisitionFaultCode::Io,
            format!("unable to inspect {label}: {error}"),
        )
    })?;
    if !metadata.is_file() {
        return fault(AcquisitionFaultCode::Io, format!("{label} is not a file"));
    }
    Ok(canonical)
}

fn canonical_directory(value: &str, label: &str) -> Result<PathBuf, AcquisitionFault> {
    canonical_directory_path(Path::new(value), label)
}

fn canonical_directory_path(value: &Path, label: &str) -> Result<PathBuf, AcquisitionFault> {
    let canonical = fs::canonicalize(value).map_err(|error| {
        AcquisitionFault::new(
            AcquisitionFaultCode::Io,
            format!("unable to resolve {label}: {error}"),
        )
    })?;
    if !canonical.is_dir() {
        return fault(
            AcquisitionFaultCode::Io,
            format!("{label} is not a directory"),
        );
    }
    Ok(canonical)
}

fn sha256_file_bounded(
    path: &Path,
    max_bytes: u64,
    label: &str,
) -> Result<String, AcquisitionFault> {
    let metadata = fs::metadata(path).map_err(|error| {
        AcquisitionFault::new(
            AcquisitionFaultCode::Io,
            format!("unable to inspect {label}: {error}"),
        )
    })?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return fault(
            AcquisitionFaultCode::Resource,
            format!("{label} is absent non-file or over bound"),
        );
    }
    let bytes = fs::read(path).map_err(|error| {
        AcquisitionFault::new(
            AcquisitionFaultCode::Io,
            format!("unable to read {label}: {error}"),
        )
    })?;
    Ok(sha256_bytes(&bytes))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    upper_hex(&Sha256::digest(bytes))
}

fn path_text(path: &Path, label: &str) -> Result<String, AcquisitionFault> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        AcquisitionFault::new(
            AcquisitionFaultCode::Identity,
            format!("{label} is not UTF-8"),
        )
    })
}

fn digest_form<T: Serialize>(domain: &[u8], value: &T) -> Result<String, AcquisitionFault> {
    let encoded = serde_json::to_vec(value).map_err(|error| {
        AcquisitionFault::new(
            AcquisitionFaultCode::Serialization,
            format!("unable to serialize digest form: {error}"),
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(encoded);
    Ok(upper_hex(&hasher.finalize()))
}

fn upper_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02X}").expect("writing to String cannot fail");
    }
    encoded
}

fn validate_encoded_bound<T: Serialize>(
    value: &T,
    maximum: usize,
    label: &str,
) -> Result<(), AcquisitionFault> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        AcquisitionFault::new(
            AcquisitionFaultCode::Serialization,
            format!("unable to serialize {label}: {error}"),
        )
    })?;
    if bytes.len() > maximum {
        return fault(
            AcquisitionFaultCode::Resource,
            format!("{label} exceeds byte bound"),
        );
    }
    Ok(())
}

fn deserialize_bounded<T: DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
    label: &str,
) -> Result<T, AcquisitionFault> {
    if bytes.len() > maximum {
        return fault(
            AcquisitionFaultCode::Resource,
            format!("{label} exceeds byte bound"),
        );
    }
    serde_json::from_slice(bytes).map_err(|error| {
        AcquisitionFault::new(
            AcquisitionFaultCode::Serialization,
            format!("unable to parse {label}: {error}"),
        )
    })
}

fn serialize_bounded<T: Serialize>(
    value: &T,
    maximum: usize,
    label: &str,
) -> Result<Vec<u8>, AcquisitionFault> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        AcquisitionFault::new(
            AcquisitionFaultCode::Serialization,
            format!("unable to serialize {label}: {error}"),
        )
    })?;
    if bytes.len() > maximum {
        return fault(
            AcquisitionFaultCode::Resource,
            format!("{label} exceeds byte bound"),
        );
    }
    Ok(bytes)
}

fn as_usize(value: u64, label: &str) -> Result<usize, AcquisitionFault> {
    usize::try_from(value).map_err(|_| {
        AcquisitionFault::new(
            AcquisitionFaultCode::Resource,
            format!("{label} exceeds platform size"),
        )
    })
}

fn fault<T>(code: AcquisitionFaultCode, message: impl Into<String>) -> Result<T, AcquisitionFault> {
    Err(AcquisitionFault::new(code, message))
}

impl AcquisitionFault {
    fn new(code: AcquisitionFaultCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn limits() -> AcquisitionLimits {
        AcquisitionLimits {
            max_command_stdout_bytes: 1_048_576,
            max_command_stderr_bytes: 65_536,
            max_diff_entries: 32,
            max_path_bytes: 512,
            max_blob_bytes: 1_048_576,
            max_total_blob_bytes: 8_388_608,
            max_index_bytes: 8_388_608,
            max_git_commands: 128,
        }
    }

    fn request() -> StagedDiffAcquisitionRequest {
        StagedDiffAcquisitionRequest {
            profile: ACQUISITION_PROFILE.to_owned(),
            repository_id: "cattailfarmer/cantor".to_owned(),
            branch_ref: "refs/heads/codex/self-hosted-corpus".to_owned(),
            expected_head: "a".repeat(40),
            object_format: "sha1".to_owned(),
            repository_root: if cfg!(windows) {
                "C:\\Project\\Cantor".to_owned()
            } else {
                "/tmp/cantor".to_owned()
            },
            git_executable: if cfg!(windows) {
                "C:\\Program Files\\Git\\mingw64\\bin\\git.exe".to_owned()
            } else {
                "/usr/bin/git".to_owned()
            },
            expected_git_sha256: "A".repeat(64),
            generated_refresh_paths: Vec::new(),
            limits: limits(),
        }
    }

    #[test]
    fn request_is_strict_and_digest_stable() {
        let request = request();
        validate_request(&request).unwrap();
        assert_eq!(
            acquisition_request_digest(&request).unwrap(),
            acquisition_request_digest(&request).unwrap()
        );
        let mut unknown = serde_json::to_value(&request).unwrap();
        unknown["unknown"] = serde_json::json!(true);
        assert!(
            from_acquisition_request_machine_form(&serde_json::to_vec(&unknown).unwrap()).is_err()
        );
    }

    #[test]
    fn request_refuses_identity_and_limit_drift() {
        let mut candidate = request();
        candidate.object_format = "sha256".to_owned();
        assert_eq!(
            validate_request(&candidate).unwrap_err().code,
            AcquisitionFaultCode::Request
        );
        let mut candidate = request();
        candidate.expected_git_sha256.make_ascii_lowercase();
        assert_eq!(
            validate_request(&candidate).unwrap_err().code,
            AcquisitionFaultCode::Digest
        );
        let mut candidate = request();
        candidate.limits.max_git_commands = 11;
        assert_eq!(
            validate_request(&candidate).unwrap_err().code,
            AcquisitionFaultCode::Resource
        );
    }

    #[test]
    fn generated_paths_are_normalized_unique() {
        let mut candidate = request();
        candidate.generated_refresh_paths = vec!["evidence/a.json".to_owned()];
        validate_request(&candidate).unwrap();
        candidate
            .generated_refresh_paths
            .push("evidence/a.json".to_owned());
        assert_eq!(
            validate_request(&candidate).unwrap_err().code,
            AcquisitionFaultCode::Request
        );
        candidate.generated_refresh_paths = vec!["../escape".to_owned()];
        assert_eq!(
            validate_request(&candidate).unwrap_err().code,
            AcquisitionFaultCode::Parse
        );
    }

    #[test]
    fn parses_added_modified_deleted_and_renamed_records() {
        let raw = format!(
            ":000000 100644 {ZERO_SHA1} {A} A\0add.txt\0:100644 100755 {A} {B} M\0mod.txt\0:100644 000000 {A} {ZERO_SHA1} D\0del.txt\0:100644 100644 {A} {B} R100\0old.txt\0new.txt\0"
        );
        let records = parse_raw_diff(raw.as_bytes(), &limits()).unwrap();
        assert_eq!(records.len(), 4);
        assert_eq!(records[0].status, 'A');
        assert_eq!(records[1].status, 'M');
        assert_eq!(records[2].status, 'D');
        assert_eq!(records[3].score, Some(100));
    }

    #[test]
    fn raw_diff_refuses_missing_terminal_nul() {
        let raw = format!(":000000 100644 {ZERO_SHA1} {A} A\0add.txt");
        assert_eq!(
            parse_raw_diff(raw.as_bytes(), &limits()).unwrap_err().code,
            AcquisitionFaultCode::Parse
        );
    }

    #[test]
    fn raw_diff_refuses_copy_type_unmerged_and_unknown_statuses() {
        for status in ["C100", "T", "U", "X"] {
            let raw = format!(":100644 100644 {A} {B} {status}\0a\0");
            assert_eq!(
                parse_raw_diff(raw.as_bytes(), &limits()).unwrap_err().code,
                AcquisitionFaultCode::Parse
            );
        }
    }

    #[test]
    fn raw_diff_refuses_submodule_and_nonregular_modes() {
        for mode in ["160000", "120000", "040000"] {
            let raw = format!(":{mode} {mode} {A} {B} M\0a\0");
            assert_eq!(
                parse_raw_diff(raw.as_bytes(), &limits()).unwrap_err().code,
                AcquisitionFaultCode::Parse
            );
        }
    }

    #[test]
    fn raw_diff_refuses_object_shape_drift() {
        let bad_add = format!(":000000 100644 {A} {B} A\0a\0");
        assert!(parse_raw_diff(bad_add.as_bytes(), &limits()).is_err());
        let bad_delete = format!(":100644 000000 {A} {B} D\0a\0");
        assert!(parse_raw_diff(bad_delete.as_bytes(), &limits()).is_err());
        let bad_rename = format!(":100644 100644 {A} {B} R101\0a\0b\0");
        assert!(parse_raw_diff(bad_rename.as_bytes(), &limits()).is_err());
    }

    #[test]
    fn raw_diff_refuses_path_and_entry_overbounds() {
        let mut bounded = limits();
        bounded.max_path_bytes = 3;
        let raw = format!(":000000 100644 {ZERO_SHA1} {A} A\0long\0");
        assert_eq!(
            parse_raw_diff(raw.as_bytes(), &bounded).unwrap_err().code,
            AcquisitionFaultCode::Resource
        );
        bounded = limits();
        bounded.max_diff_entries = 1;
        let raw =
            format!(":000000 100644 {ZERO_SHA1} {A} A\0a\0:000000 100644 {ZERO_SHA1} {B} A\0b\0");
        assert_eq!(
            parse_raw_diff(raw.as_bytes(), &bounded).unwrap_err().code,
            AcquisitionFaultCode::Resource
        );
    }

    #[test]
    fn empty_raw_diff_is_explicit() {
        assert!(parse_raw_diff(&[], &limits()).unwrap().is_empty());
    }

    #[test]
    fn bounded_reader_drains_and_reports_overflow() {
        let bytes = vec![7u8; 10_000];
        let (retained, over) = drain_bounded(bytes.as_slice(), 100).unwrap();
        assert_eq!(retained.len(), 100);
        assert!(over);
    }

    #[test]
    fn status_sort_order_is_closed() {
        assert_eq!(status_rank(DiffStatus::Added), 0);
        assert_eq!(status_rank(DiffStatus::Modified), 1);
        assert_eq!(status_rank(DiffStatus::Deleted), 2);
        assert_eq!(status_rank(DiffStatus::Renamed), 3);
        assert_eq!(status_rank(DiffStatus::GeneratedRefresh), 4);
    }

    #[test]
    fn receipt_digest_is_self_excluding() {
        let request = request();
        let mut inventory = DiffInventory {
            profile: DIFF_INVENTORY_PROFILE.to_owned(),
            repository_id: request.repository_id.clone(),
            branch_ref: request.branch_ref.clone(),
            predecessor_commit: request.expected_head.clone(),
            entries: vec![DiffEntry {
                status: DiffStatus::Added,
                old_path: None,
                new_path: Some("a".to_owned()),
                before_sha256: None,
                after_sha256: Some("B".repeat(64)),
            }],
            inventory_sha256: String::new(),
        };
        inventory.inventory_sha256 = diff_inventory_digest(&inventory).unwrap();
        let mut receipt = StagedDiffAcquisitionReceipt {
            profile: ACQUISITION_RECEIPT_PROFILE.to_owned(),
            request_sha256: acquisition_request_digest(&request).unwrap(),
            git_executable_sha256: request.expected_git_sha256.clone(),
            git_version: "git version fixture".to_owned(),
            repository_root: request.repository_root.clone(),
            branch_ref: request.branch_ref.clone(),
            head: request.expected_head.clone(),
            object_format: request.object_format.clone(),
            index_path: if cfg!(windows) {
                "C:\\repo\\.git\\index"
            } else {
                "/repo/.git/index"
            }
            .to_owned(),
            index_before_sha256: "C".repeat(64),
            index_after_sha256: "C".repeat(64),
            inventory,
            command_count: 14,
            authority: AcquisitionAuthority::ObservationOnly,
            physical_contact: true,
            nonauthority: NONAUTHORITY.to_owned(),
            result_sha256: String::new(),
        };
        receipt.result_sha256 = acquisition_receipt_digest(&receipt).unwrap();
        validate_receipt(&request, &receipt).unwrap();
        let encoded = to_acquisition_receipt_machine_form(&request, &receipt).unwrap();
        assert!(encoded.len() < MAX_RECEIPT_BYTES);
    }
}
