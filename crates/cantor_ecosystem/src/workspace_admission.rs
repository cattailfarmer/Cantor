//! Read-only admission of an operator-prepared candidate Git worktree.
//!
//! The module observes and reconciles repository state. It has no API for
//! creating, changing, cleaning, committing, or promoting a worktree, and it
//! never launches a model or shell.

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use cantor_core::{ContentDigest, sha256_digest};
use serde::{Deserialize, Serialize};

mod inventory;
mod process;
mod validation;

use inventory::*;
use process::ProcessObservationRunner;
use validation::*;

pub const CANDIDATE_WORKSPACE_ADMISSION_PROFILE: &str = "cantor-candidate-workspace-admission/0.1";

const MINIMUM_PROCESS_COUNT: u16 = 12;
const HARD_MAX_COMMAND_BYTES: usize = 8 * 1024 * 1024;
const HARD_MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024;
const HARD_MAX_PROCESSES: u16 = 32;
const HARD_MAX_TIMEOUT_MILLIS: u64 = 60_000;
const MAX_SET_ITEMS: usize = 256;
const MAX_TEXT_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionBudget {
    pub maximum_command_bytes: usize,
    pub maximum_total_bytes: usize,
    pub maximum_processes: u16,
    pub timeout_millis: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateWorkspaceRequest {
    pub profile: String,
    pub candidate_uuid: String,
    pub correlation_uuid: String,
    pub admission_nonce: String,
    pub git_executable: PathBuf,
    pub git_executable_sha256: String,
    pub git_version: String,
    pub principal_workspace: PathBuf,
    pub candidate_workspace: PathBuf,
    pub expected_repository_common_dir: PathBuf,
    pub expected_base_commit: String,
    pub expected_branch_ref: String,
    pub protected_branch_refs: Vec<String>,
    pub allowed_relative_paths: Vec<String>,
    pub budget: AdmissionBudget,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionResourceAccount {
    pub process_count: u16,
    pub received_bytes: usize,
    pub configured_timeout_millis: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReceipt {
    pub profile: String,
    pub request_sha256: ContentDigest,
    pub receipt_sha256: ContentDigest,
    pub observation_sha256: ContentDigest,
    pub candidate_uuid: String,
    pub correlation_uuid: String,
    pub admission_nonce: String,
    pub git_executable_sha256: String,
    pub git_version: String,
    pub principal_workspace: PathBuf,
    pub candidate_workspace: PathBuf,
    pub repository_common_dir: PathBuf,
    pub candidate_git_dir: PathBuf,
    pub base_commit: String,
    pub branch_ref: String,
    pub allowed_relative_paths: Vec<String>,
    pub resource_account: AdmissionResourceAccount,
    pub admitted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionFaultCode {
    Request,
    Path,
    Executable,
    Process,
    Protocol,
    Repository,
    Isolation,
    Branch,
    Baseline,
    Budget,
    Freshness,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionFault {
    pub code: AdmissionFaultCode,
    pub operation: String,
    pub message: String,
    pub resource_account: AdmissionResourceAccount,
}

impl std::fmt::Display for AdmissionFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{:?} at {}: {}",
            self.code, self.operation, self.message
        )
    }
}

impl std::error::Error for AdmissionFault {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum ObservationKind {
    Version,
    PrincipalTopLevel,
    CandidateTopLevel,
    PrincipalCommonDir,
    CandidateCommonDir,
    CandidateGitDir,
    CandidateHead,
    CandidateBranch,
    PrincipalBranch,
    CandidateStatus,
    WorktreeInventory,
    SubmoduleInventory,
}

impl ObservationKind {
    const PLAN: [Self; 12] = [
        Self::Version,
        Self::PrincipalTopLevel,
        Self::CandidateTopLevel,
        Self::PrincipalCommonDir,
        Self::CandidateCommonDir,
        Self::CandidateGitDir,
        Self::CandidateHead,
        Self::CandidateBranch,
        Self::PrincipalBranch,
        Self::CandidateStatus,
        Self::WorktreeInventory,
        Self::SubmoduleInventory,
    ];

    fn operation(self) -> &'static str {
        match self {
            Self::Version => "git_version",
            Self::PrincipalTopLevel => "principal_top_level",
            Self::CandidateTopLevel => "candidate_top_level",
            Self::PrincipalCommonDir => "principal_common_dir",
            Self::CandidateCommonDir => "candidate_common_dir",
            Self::CandidateGitDir => "candidate_git_dir",
            Self::CandidateHead => "candidate_head",
            Self::CandidateBranch => "candidate_branch",
            Self::PrincipalBranch => "principal_branch",
            Self::CandidateStatus => "candidate_status",
            Self::WorktreeInventory => "worktree_inventory",
            Self::SubmoduleInventory => "submodule_inventory",
        }
    }

    fn arguments(self, request: &ValidatedRequest) -> Result<Vec<String>, AdmissionFault> {
        let principal = path_text(&request.principal_workspace, "principal_workspace")?;
        let candidate = path_text(&request.candidate_workspace, "candidate_workspace")?;
        let arguments = match self {
            Self::Version => vec!["--version"],
            Self::PrincipalTopLevel => {
                vec!["-C", principal, "rev-parse", "--show-toplevel"]
            }
            Self::CandidateTopLevel => {
                vec!["-C", candidate, "rev-parse", "--show-toplevel"]
            }
            Self::PrincipalCommonDir => vec![
                "-C",
                principal,
                "rev-parse",
                "--path-format=absolute",
                "--git-common-dir",
            ],
            Self::CandidateCommonDir => vec![
                "-C",
                candidate,
                "rev-parse",
                "--path-format=absolute",
                "--git-common-dir",
            ],
            Self::CandidateGitDir => vec![
                "-C",
                candidate,
                "rev-parse",
                "--path-format=absolute",
                "--git-dir",
            ],
            Self::CandidateHead => {
                vec!["-C", candidate, "rev-parse", "--verify", "HEAD"]
            }
            Self::CandidateBranch => {
                vec!["-C", candidate, "symbolic-ref", "--quiet", "HEAD"]
            }
            Self::PrincipalBranch => {
                vec!["-C", principal, "symbolic-ref", "--quiet", "HEAD"]
            }
            Self::CandidateStatus => vec![
                "-C",
                candidate,
                "status",
                "--porcelain=v2",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ],
            Self::WorktreeInventory => {
                vec!["-C", principal, "worktree", "list", "--porcelain", "-z"]
            }
            Self::SubmoduleInventory => {
                vec!["-C", candidate, "submodule", "status", "--recursive"]
            }
        };
        Ok(arguments.into_iter().map(str::to_owned).collect())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct RecordedObservation {
    kind: ObservationKind,
    arguments: Vec<String>,
    exit_code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Clone, Debug)]
struct RawObservation {
    exit_code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    observed_bytes: usize,
}

trait ObservationRunner {
    fn run(
        &mut self,
        kind: ObservationKind,
        arguments: &[String],
        request: &ValidatedRequest,
        deadline: Instant,
    ) -> Result<RawObservation, AdmissionFault>;
}

#[derive(Clone, Debug)]
struct ValidatedRequest {
    source: CandidateWorkspaceRequest,
    git_executable: PathBuf,
    principal_workspace: PathBuf,
    candidate_workspace: PathBuf,
    repository_common_dir: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct ReceiptBody {
    profile: String,
    request_sha256: ContentDigest,
    observation_sha256: ContentDigest,
    candidate_uuid: String,
    correlation_uuid: String,
    admission_nonce: String,
    git_executable_sha256: String,
    git_version: String,
    principal_workspace: PathBuf,
    candidate_workspace: PathBuf,
    repository_common_dir: PathBuf,
    candidate_git_dir: PathBuf,
    base_commit: String,
    branch_ref: String,
    allowed_relative_paths: Vec<String>,
    resource_account: AdmissionResourceAccount,
    admitted: bool,
}

/// Observe and admit an already-prepared candidate worktree.
pub fn admit_candidate_workspace(
    request: &CandidateWorkspaceRequest,
) -> Result<AdmissionReceipt, AdmissionFault> {
    let validated = validate_request(request)?;
    admit_with_runner(&validated, &mut ProcessObservationRunner)
}

/// Rerun admission and require all canonical receipt bytes to remain identical.
pub fn revalidate_candidate_workspace(
    request: &CandidateWorkspaceRequest,
    prior: &AdmissionReceipt,
) -> Result<AdmissionReceipt, AdmissionFault> {
    let current = admit_candidate_workspace(request)?;
    require_same_receipt(prior, current)
}

fn require_same_receipt(
    prior: &AdmissionReceipt,
    current: AdmissionReceipt,
) -> Result<AdmissionReceipt, AdmissionFault> {
    if &current == prior {
        Ok(current)
    } else {
        Err(fault(
            AdmissionFaultCode::Freshness,
            "revalidation",
            "candidate workspace admission facts changed",
            current.resource_account,
        ))
    }
}

fn admit_with_runner(
    request: &ValidatedRequest,
    runner: &mut impl ObservationRunner,
) -> Result<AdmissionReceipt, AdmissionFault> {
    let deadline = Instant::now() + Duration::from_millis(request.source.budget.timeout_millis);
    let mut account = empty_account(request.source.budget.timeout_millis);
    let mut observations = Vec::with_capacity(ObservationKind::PLAN.len());
    for kind in ObservationKind::PLAN {
        if account.process_count >= request.source.budget.maximum_processes
            || Instant::now() >= deadline
        {
            return Err(fault(
                AdmissionFaultCode::Budget,
                kind.operation(),
                "process budget or admission deadline exhausted",
                account,
            ));
        }
        let arguments = kind.arguments(request)?;
        account.process_count += 1;
        let result = runner
            .run(kind, &arguments, request, deadline)
            .map_err(|mut failure| {
                failure.resource_account = account.clone();
                failure
            })?;
        if result.observed_bytes > request.source.budget.maximum_command_bytes {
            return Err(fault(
                AdmissionFaultCode::Budget,
                kind.operation(),
                "command output exceeds the per-command byte budget",
                account,
            ));
        }
        account.received_bytes = account
            .received_bytes
            .checked_add(result.observed_bytes)
            .ok_or_else(|| {
                fault(
                    AdmissionFaultCode::Budget,
                    kind.operation(),
                    "received-byte account overflowed",
                    account.clone(),
                )
            })?;
        if account.received_bytes > request.source.budget.maximum_total_bytes {
            return Err(fault(
                AdmissionFaultCode::Budget,
                kind.operation(),
                "total output exceeds the admission byte budget",
                account,
            ));
        }
        if result.exit_code != 0 || !result.stderr.is_empty() {
            return Err(fault(
                if result.exit_code == 0 {
                    AdmissionFaultCode::Protocol
                } else {
                    AdmissionFaultCode::Process
                },
                kind.operation(),
                "Git observation failed or emitted stderr",
                account,
            ));
        }
        observations.push(RecordedObservation {
            kind,
            arguments,
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
        });
    }
    reconcile_observations(request, observations, account)
}

fn reconcile_observations(
    request: &ValidatedRequest,
    observations: Vec<RecordedObservation>,
    account: AdmissionResourceAccount,
) -> Result<AdmissionReceipt, AdmissionFault> {
    let observed = |kind| {
        observations
            .iter()
            .find(|item| item.kind == kind)
            .map(|item| item.stdout.as_slice())
            .ok_or_else(|| {
                fault(
                    AdmissionFaultCode::Internal,
                    "observation_set",
                    "closed observation plan is incomplete",
                    account.clone(),
                )
            })
    };
    let version = one_line(observed(ObservationKind::Version)?, "git_version", &account)?;
    if version != request.source.git_version {
        return Err(fault(
            AdmissionFaultCode::Executable,
            "git_version",
            "observed Git version differs from the pin",
            account,
        ));
    }
    for (kind, expected) in [
        (
            ObservationKind::PrincipalTopLevel,
            &request.principal_workspace,
        ),
        (
            ObservationKind::CandidateTopLevel,
            &request.candidate_workspace,
        ),
        (
            ObservationKind::PrincipalCommonDir,
            &request.repository_common_dir,
        ),
        (
            ObservationKind::CandidateCommonDir,
            &request.repository_common_dir,
        ),
    ] {
        let actual = observed_path(observed(kind)?, kind.operation(), &account)?;
        reconcile_path(&actual, expected, kind.operation(), &account)?;
    }
    let candidate_git_dir = observed_path(
        observed(ObservationKind::CandidateGitDir)?,
        "candidate_git_dir",
        &account,
    )?;
    if candidate_git_dir == request.repository_common_dir
        || !candidate_git_dir.starts_with(request.repository_common_dir.join("worktrees"))
    {
        return Err(fault(
            AdmissionFaultCode::Isolation,
            "candidate_git_dir",
            "candidate is not an isolated linked worktree",
            account,
        ));
    }
    let candidate_head = one_line(
        observed(ObservationKind::CandidateHead)?,
        "candidate_head",
        &account,
    )?;
    validate_object_id(&candidate_head, "candidate_head", account.clone())?;
    if candidate_head != request.source.expected_base_commit {
        return Err(fault(
            AdmissionFaultCode::Branch,
            "candidate_head",
            "candidate HEAD differs from the expected base",
            account,
        ));
    }
    let candidate_branch = one_line(
        observed(ObservationKind::CandidateBranch)?,
        "candidate_branch",
        &account,
    )?;
    let principal_branch = one_line(
        observed(ObservationKind::PrincipalBranch)?,
        "principal_branch",
        &account,
    )?;
    validate_branch_ref(&candidate_branch, "candidate_branch", account.clone())?;
    validate_branch_ref(&principal_branch, "principal_branch", account.clone())?;
    if candidate_branch != request.source.expected_branch_ref
        || candidate_branch == principal_branch
        || request
            .source
            .protected_branch_refs
            .binary_search(&candidate_branch)
            .is_ok()
    {
        return Err(fault(
            AdmissionFaultCode::Branch,
            "candidate_branch",
            "candidate branch is substituted, principal, or protected",
            account,
        ));
    }
    if !observed(ObservationKind::CandidateStatus)?.is_empty() {
        return Err(fault(
            AdmissionFaultCode::Baseline,
            "candidate_status",
            "candidate worktree is not exactly clean",
            account,
        ));
    }
    if !observed(ObservationKind::SubmoduleInventory)?.is_empty() {
        return Err(fault(
            AdmissionFaultCode::Baseline,
            "submodule_inventory",
            "submodules are outside the initial admission profile",
            account,
        ));
    }
    let inventory =
        parse_worktree_inventory(observed(ObservationKind::WorktreeInventory)?, &account)?;
    reconcile_inventory(
        &inventory,
        request,
        &candidate_head,
        &candidate_branch,
        &account,
    )?;
    form_receipt(
        request,
        observations,
        version,
        candidate_git_dir,
        candidate_head,
        candidate_branch,
        account,
    )
}

fn form_receipt(
    request: &ValidatedRequest,
    observations: Vec<RecordedObservation>,
    git_version: String,
    candidate_git_dir: PathBuf,
    base_commit: String,
    branch_ref: String,
    resource_account: AdmissionResourceAccount,
) -> Result<AdmissionReceipt, AdmissionFault> {
    let request_sha256 = digest_value(&request.source, "request_digest", &resource_account)?;
    let observation_sha256 = digest_value(&observations, "observation_digest", &resource_account)?;
    let body = ReceiptBody {
        profile: CANDIDATE_WORKSPACE_ADMISSION_PROFILE.to_owned(),
        request_sha256,
        observation_sha256,
        candidate_uuid: request.source.candidate_uuid.clone(),
        correlation_uuid: request.source.correlation_uuid.clone(),
        admission_nonce: request.source.admission_nonce.clone(),
        git_executable_sha256: request.source.git_executable_sha256.clone(),
        git_version,
        principal_workspace: request.principal_workspace.clone(),
        candidate_workspace: request.candidate_workspace.clone(),
        repository_common_dir: request.repository_common_dir.clone(),
        candidate_git_dir,
        base_commit,
        branch_ref,
        allowed_relative_paths: request.source.allowed_relative_paths.clone(),
        resource_account,
        admitted: true,
    };
    let receipt_sha256 = digest_value(&body, "receipt_digest", &body.resource_account)?;
    Ok(AdmissionReceipt {
        profile: body.profile,
        request_sha256: body.request_sha256,
        receipt_sha256,
        observation_sha256: body.observation_sha256,
        candidate_uuid: body.candidate_uuid,
        correlation_uuid: body.correlation_uuid,
        admission_nonce: body.admission_nonce,
        git_executable_sha256: body.git_executable_sha256,
        git_version: body.git_version,
        principal_workspace: body.principal_workspace,
        candidate_workspace: body.candidate_workspace,
        repository_common_dir: body.repository_common_dir,
        candidate_git_dir: body.candidate_git_dir,
        base_commit: body.base_commit,
        branch_ref: body.branch_ref,
        allowed_relative_paths: body.allowed_relative_paths,
        resource_account: body.resource_account,
        admitted: body.admitted,
    })
}

fn digest_value(
    value: &impl Serialize,
    operation: &str,
    account: &AdmissionResourceAccount,
) -> Result<ContentDigest, AdmissionFault> {
    sha256_digest(value).map_err(|error| {
        fault(
            AdmissionFaultCode::Internal,
            operation,
            error.to_string(),
            account.clone(),
        )
    })
}

fn empty_account(timeout_millis: u64) -> AdmissionResourceAccount {
    AdmissionResourceAccount {
        process_count: 0,
        received_bytes: 0,
        configured_timeout_millis: timeout_millis,
    }
}

fn fault(
    code: AdmissionFaultCode,
    operation: impl Into<String>,
    message: impl AsRef<str>,
    resource_account: AdmissionResourceAccount,
) -> AdmissionFault {
    AdmissionFault {
        code,
        operation: operation.into(),
        message: message.as_ref().chars().take(512).collect(),
        resource_account,
    }
}

#[cfg(test)]
#[path = "workspace_admission/tests.rs"]
mod tests;
