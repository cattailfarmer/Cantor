use super::*;
use cantor_core::sha256_bytes;
use std::{
    collections::BTreeMap,
    fs,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    root: PathBuf,
    principal: PathBuf,
    candidate: PathBuf,
    common: PathBuf,
    candidate_git: PathBuf,
    executable: PathBuf,
    request: CandidateWorkspaceRequest,
}

impl Fixture {
    fn new() -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "cantor-workspace-admission-{}-{serial}",
            std::process::id()
        ));
        let principal = root.join("principal");
        let candidate = root.join("candidate");
        let common = root.join("common.git");
        let candidate_git = common.join("worktrees").join("candidate");
        fs::create_dir_all(&principal).expect("principal");
        fs::create_dir_all(&candidate).expect("candidate");
        fs::create_dir_all(&candidate_git).expect("candidate git");
        let executable = root.join(if cfg!(windows) { "git.exe" } else { "git" });
        fs::write(&executable, b"fixture git").expect("executable");
        let executable_hash = sha256_bytes(b"fixture git").value;
        let request = CandidateWorkspaceRequest {
            profile: CANDIDATE_WORKSPACE_ADMISSION_PROFILE.to_owned(),
            candidate_uuid: "11111111-1111-4111-8111-111111111111".to_owned(),
            correlation_uuid: "22222222-2222-4222-8222-222222222222".to_owned(),
            admission_nonce: "nonce:fixture:1".to_owned(),
            git_executable: fs::canonicalize(&executable).expect("executable path"),
            git_executable_sha256: executable_hash,
            git_version: "git version fixture".to_owned(),
            principal_workspace: fs::canonicalize(&principal).expect("principal path"),
            candidate_workspace: fs::canonicalize(&candidate).expect("candidate path"),
            expected_repository_common_dir: fs::canonicalize(&common).expect("common path"),
            expected_base_commit: "a".repeat(40),
            expected_branch_ref: "refs/heads/codex/candidate".to_owned(),
            protected_branch_refs: vec![
                "refs/heads/codex/self-hosted-corpus".to_owned(),
                "refs/heads/main".to_owned(),
            ],
            allowed_relative_paths: vec!["crates/cantor_ecosystem".to_owned(), "docs".to_owned()],
            budget: AdmissionBudget {
                maximum_command_bytes: 64 * 1024,
                maximum_total_bytes: 512 * 1024,
                maximum_processes: 12,
                timeout_millis: 10_000,
            },
        };
        Self {
            root,
            principal,
            candidate,
            common,
            candidate_git,
            executable,
            request,
        }
    }

    fn runner(&self) -> FakeRunner {
        let principal = path_text(
            &fs::canonicalize(&self.principal).expect("principal"),
            "test",
        )
        .expect("principal text")
        .replace('\\', "/");
        let candidate = path_text(
            &fs::canonicalize(&self.candidate).expect("candidate"),
            "test",
        )
        .expect("candidate text")
        .replace('\\', "/");
        let common = path_text(&fs::canonicalize(&self.common).expect("common"), "test")
            .expect("common text")
            .replace('\\', "/");
        let candidate_git = path_text(
            &fs::canonicalize(&self.candidate_git).expect("git dir"),
            "test",
        )
        .expect("git text")
        .replace('\\', "/");
        let inventory = format!(
            "worktree {principal}\0HEAD {}\0branch refs/heads/main\0\0worktree {candidate}\0HEAD {}\0branch refs/heads/codex/candidate\0\0",
            "b".repeat(40),
            "a".repeat(40)
        );
        FakeRunner::new(BTreeMap::from([
            (ObservationKind::Version, b"git version fixture\n".to_vec()),
            (
                ObservationKind::PrincipalTopLevel,
                format!("{principal}\n").into_bytes(),
            ),
            (
                ObservationKind::CandidateTopLevel,
                format!("{candidate}\n").into_bytes(),
            ),
            (
                ObservationKind::PrincipalCommonDir,
                format!("{common}\n").into_bytes(),
            ),
            (
                ObservationKind::CandidateCommonDir,
                format!("{common}\n").into_bytes(),
            ),
            (
                ObservationKind::CandidateGitDir,
                format!("{candidate_git}\n").into_bytes(),
            ),
            (
                ObservationKind::CandidateHead,
                format!("{}\n", "a".repeat(40)).into_bytes(),
            ),
            (
                ObservationKind::CandidateBranch,
                b"refs/heads/codex/candidate\n".to_vec(),
            ),
            (
                ObservationKind::PrincipalBranch,
                b"refs/heads/main\n".to_vec(),
            ),
            (ObservationKind::CandidateStatus, Vec::new()),
            (ObservationKind::WorktreeInventory, inventory.into_bytes()),
            (ObservationKind::SubmoduleInventory, Vec::new()),
        ]))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let expected_prefix = std::env::temp_dir();
        if self.root.starts_with(&expected_prefix)
            && self.root.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .starts_with("cantor-workspace-admission-")
            })
        {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

struct FakeRunner {
    outputs: BTreeMap<ObservationKind, Vec<u8>>,
    calls: Vec<ObservationKind>,
    arguments: Vec<Vec<String>>,
}

impl FakeRunner {
    fn new(outputs: BTreeMap<ObservationKind, Vec<u8>>) -> Self {
        Self {
            outputs,
            calls: Vec::new(),
            arguments: Vec::new(),
        }
    }
}

impl ObservationRunner for FakeRunner {
    fn run(
        &mut self,
        kind: ObservationKind,
        arguments: &[String],
        _request: &ValidatedRequest,
        _deadline: Instant,
    ) -> Result<RawObservation, AdmissionFault> {
        self.calls.push(kind);
        self.arguments.push(arguments.to_vec());
        let stdout = self.outputs.get(&kind).cloned().ok_or_else(|| {
            fault(
                AdmissionFaultCode::Internal,
                kind.operation(),
                "missing fake output",
                empty_account(0),
            )
        })?;
        Ok(RawObservation {
            observed_bytes: stdout.len(),
            stdout,
            stderr: Vec::new(),
            exit_code: 0,
        })
    }
}

fn admit_fixture(
    fixture: &Fixture,
    runner: &mut FakeRunner,
) -> Result<AdmissionReceipt, AdmissionFault> {
    let validated = validate_request(&fixture.request)?;
    admit_with_runner(&validated, runner)
}

#[test]
fn exact_fixture_admits_deterministically_with_closed_plan() {
    let fixture = Fixture::new();
    let mut first_runner = fixture.runner();
    let first = admit_fixture(&fixture, &mut first_runner).expect("first admission");
    let mut second_runner = fixture.runner();
    let second = admit_fixture(&fixture, &mut second_runner).expect("second admission");
    assert_eq!(first, second);
    assert_eq!(first_runner.calls, ObservationKind::PLAN);
    assert_eq!(first_runner.arguments[0], vec!["--version"]);
    assert_eq!(
        &first_runner.arguments[9][2..],
        &[
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none"
        ]
    );
    assert_eq!(first.resource_account.process_count, 12);
    assert!(first.admitted);
    assert_eq!(first.receipt_sha256.algorithm, "sha256");
}

#[test]
fn unknown_request_fields_fail_during_strict_deserialization() {
    let fixture = Fixture::new();
    let mut value = serde_json::to_value(&fixture.request).expect("request JSON");
    value["surprise"] = serde_json::json!(true);
    let error = serde_json::from_value::<CandidateWorkspaceRequest>(value)
        .expect_err("unknown field must fail");
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn unsafe_and_overlapping_path_policies_fail_before_a_runner_call() {
    let mut fixture = Fixture::new();
    fixture.request.allowed_relative_paths = vec!["../escape".to_owned()];
    assert_eq!(
        validate_request(&fixture.request)
            .expect_err("path escape")
            .code,
        AdmissionFaultCode::Path
    );
    fixture.request.allowed_relative_paths = vec!["src".to_owned(), "src/lib.rs".to_owned()];
    assert_eq!(
        validate_request(&fixture.request)
            .expect_err("overlapping allowlist")
            .code,
        AdmissionFaultCode::Path
    );
    fixture.request.allowed_relative_paths = vec!["docs".to_owned()];
    fixture.request.candidate_workspace = fixture.request.principal_workspace.clone();
    assert_eq!(
        validate_request(&fixture.request)
            .expect_err("workspace overlap")
            .code,
        AdmissionFaultCode::Isolation
    );
}

#[test]
fn executable_and_branch_substitution_fail_closed() {
    let mut fixture = Fixture::new();
    fixture.request.git_executable_sha256 = "0".repeat(64);
    assert_eq!(
        validate_request(&fixture.request)
            .expect_err("executable substitution")
            .code,
        AdmissionFaultCode::Executable
    );
    fixture.request.git_executable_sha256 = sha256_bytes(b"fixture git").value;
    let mut runner = fixture.runner();
    runner.outputs.insert(
        ObservationKind::CandidateBranch,
        b"refs/heads/main\n".to_vec(),
    );
    assert_eq!(
        admit_fixture(&fixture, &mut runner)
            .expect_err("branch substitution")
            .code,
        AdmissionFaultCode::Branch
    );
}

#[test]
fn dirty_submodule_and_inventory_substitution_are_distinct_faults() {
    let fixture = Fixture::new();
    let mut dirty = fixture.runner();
    dirty.outputs.insert(
        ObservationKind::CandidateStatus,
        b"? untracked.txt\0".to_vec(),
    );
    assert_eq!(
        admit_fixture(&fixture, &mut dirty).expect_err("dirty").code,
        AdmissionFaultCode::Baseline
    );
    let mut submodule = fixture.runner();
    submodule.outputs.insert(
        ObservationKind::SubmoduleInventory,
        b" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa vendor/example\n".to_vec(),
    );
    assert_eq!(
        admit_fixture(&fixture, &mut submodule)
            .expect_err("submodule")
            .code,
        AdmissionFaultCode::Baseline
    );
    let mut missing = fixture.runner();
    let principal = fs::canonicalize(&fixture.principal)
        .expect("principal")
        .to_string_lossy()
        .replace('\\', "/");
    missing.outputs.insert(
        ObservationKind::WorktreeInventory,
        format!(
            "worktree {principal}\0HEAD {}\0branch refs/heads/main\0\0",
            "b".repeat(40)
        )
        .into_bytes(),
    );
    assert_eq!(
        admit_fixture(&fixture, &mut missing)
            .expect_err("missing inventory")
            .code,
        AdmissionFaultCode::Isolation
    );
}

#[test]
fn process_and_byte_budgets_fail_without_partial_receipt() {
    let mut fixture = Fixture::new();
    fixture.request.budget.maximum_command_bytes = 16;
    fixture.request.budget.maximum_total_bytes = 192;
    let mut runner = fixture.runner();
    let fault = admit_fixture(&fixture, &mut runner).expect_err("command byte budget");
    assert_eq!(fault.code, AdmissionFaultCode::Budget);
    assert_eq!(fault.operation, "git_version");
    assert_eq!(fault.resource_account.process_count, 1);
}

#[test]
fn total_byte_budget_stops_before_repository_reconciliation() {
    let mut fixture = Fixture::new();
    fixture.request.budget.maximum_command_bytes = 1_024;
    fixture.request.budget.maximum_total_bytes = 1_024;
    let mut runner = fixture.runner();
    runner
        .outputs
        .insert(ObservationKind::CandidateStatus, vec![b'x'; 900]);
    let fault = admit_fixture(&fixture, &mut runner).expect_err("total byte budget");
    assert_eq!(fault.code, AdmissionFaultCode::Budget);
    assert_eq!(fault.operation, "candidate_status");
    assert!(runner.calls.len() < ObservationKind::PLAN.len());
}

#[test]
fn runner_fault_stops_the_closed_plan_without_a_partial_receipt() {
    struct FailingRunner {
        inner: FakeRunner,
    }
    impl ObservationRunner for FailingRunner {
        fn run(
            &mut self,
            kind: ObservationKind,
            arguments: &[String],
            request: &ValidatedRequest,
            deadline: Instant,
        ) -> Result<RawObservation, AdmissionFault> {
            if kind == ObservationKind::CandidateTopLevel {
                return Err(fault(
                    AdmissionFaultCode::Process,
                    kind.operation(),
                    "injected process failure",
                    empty_account(0),
                ));
            }
            self.inner.run(kind, arguments, request, deadline)
        }
    }
    let fixture = Fixture::new();
    let validated = validate_request(&fixture.request).expect("request");
    let mut runner = FailingRunner {
        inner: fixture.runner(),
    };
    let fault = admit_with_runner(&validated, &mut runner).expect_err("runner failure");
    assert_eq!(fault.code, AdmissionFaultCode::Process);
    assert_eq!(fault.operation, "candidate_top_level");
    assert_eq!(fault.resource_account.process_count, 3);
    assert_eq!(
        runner.inner.calls,
        [ObservationKind::Version, ObservationKind::PrincipalTopLevel]
    );
}

#[test]
fn duplicate_sets_and_nondeterministic_time_are_absent_from_receipt_identity() {
    let mut fixture = Fixture::new();
    fixture.request.protected_branch_refs =
        vec!["refs/heads/main".to_owned(), "refs/heads/main".to_owned()];
    assert_eq!(
        validate_request(&fixture.request)
            .expect_err("duplicate protected ref")
            .code,
        AdmissionFaultCode::Request
    );
    let fixture = Fixture::new();
    let mut runner = fixture.runner();
    let receipt = admit_fixture(&fixture, &mut runner).expect("receipt");
    let json = serde_json::to_string(&receipt).expect("receipt JSON");
    assert!(!json.contains("elapsed"));
    assert!(!json.contains("timestamp"));
}

#[test]
fn malformed_inventory_and_noncanonical_object_id_fail() {
    let fixture = Fixture::new();
    let mut malformed = fixture.runner();
    malformed.outputs.insert(
        ObservationKind::WorktreeInventory,
        b"worktree no-double-nul".to_vec(),
    );
    assert_eq!(
        admit_fixture(&fixture, &mut malformed)
            .expect_err("malformed inventory")
            .code,
        AdmissionFaultCode::Protocol
    );
    let mut request_fixture = Fixture::new();
    request_fixture.request.expected_base_commit = "A".repeat(40);
    assert_eq!(
        validate_request(&request_fixture.request)
            .expect_err("uppercase object")
            .code,
        AdmissionFaultCode::Branch
    );
}

#[test]
fn top_level_and_inventory_disqualifier_substitution_fail_separately() {
    let fixture = Fixture::new();
    let mut top_level = fixture.runner();
    let unrelated = fixture.root.join("unrelated");
    fs::create_dir_all(&unrelated).expect("unrelated");
    top_level.outputs.insert(
        ObservationKind::CandidateTopLevel,
        format!("{}\n", unrelated.to_string_lossy().replace('\\', "/")).into_bytes(),
    );
    assert_eq!(
        admit_fixture(&fixture, &mut top_level)
            .expect_err("top-level substitution")
            .code,
        AdmissionFaultCode::Repository
    );

    let mut disqualified = fixture.runner();
    let principal = fixture
        .request
        .principal_workspace
        .to_string_lossy()
        .replace('\\', "/");
    let candidate = fixture
        .request
        .candidate_workspace
        .to_string_lossy()
        .replace('\\', "/");
    disqualified.outputs.insert(
        ObservationKind::WorktreeInventory,
        format!(
            "worktree {principal}\0HEAD {}\0branch refs/heads/main\0\0worktree {candidate}\0HEAD {}\0branch refs/heads/codex/candidate\0locked\0\0",
            "b".repeat(40),
            "a".repeat(40)
        )
        .into_bytes(),
    );
    assert_eq!(
        admit_fixture(&fixture, &mut disqualified)
            .expect_err("locked candidate")
            .code,
        AdmissionFaultCode::Isolation
    );
}

#[test]
fn revalidation_rejects_any_changed_receipt_fact() {
    let fixture = Fixture::new();
    let mut runner = fixture.runner();
    let prior = admit_fixture(&fixture, &mut runner).expect("prior receipt");
    let mut current = prior.clone();
    current.branch_ref = "refs/heads/codex/other".to_owned();
    let fault = require_same_receipt(&prior, current).expect_err("changed receipt");
    assert_eq!(fault.code, AdmissionFaultCode::Freshness);
    assert_eq!(fault.operation, "revalidation");
}

#[test]
fn receipt_digest_recomputes_from_the_declared_body() {
    let fixture = Fixture::new();
    let mut runner = fixture.runner();
    let receipt = admit_fixture(&fixture, &mut runner).expect("receipt");
    let body = ReceiptBody {
        profile: receipt.profile.clone(),
        request_sha256: receipt.request_sha256.clone(),
        observation_sha256: receipt.observation_sha256.clone(),
        candidate_uuid: receipt.candidate_uuid.clone(),
        correlation_uuid: receipt.correlation_uuid.clone(),
        admission_nonce: receipt.admission_nonce.clone(),
        git_executable_sha256: receipt.git_executable_sha256.clone(),
        git_version: receipt.git_version.clone(),
        principal_workspace: receipt.principal_workspace.clone(),
        candidate_workspace: receipt.candidate_workspace.clone(),
        repository_common_dir: receipt.repository_common_dir.clone(),
        candidate_git_dir: receipt.candidate_git_dir.clone(),
        base_commit: receipt.base_commit.clone(),
        branch_ref: receipt.branch_ref.clone(),
        allowed_relative_paths: receipt.allowed_relative_paths.clone(),
        resource_account: receipt.resource_account.clone(),
        admitted: receipt.admitted,
    };
    assert_eq!(
        receipt.receipt_sha256,
        sha256_digest(&body).expect("body digest")
    );
}

#[test]
fn file_hash_helper_matches_core_sha256() {
    let fixture = Fixture::new();
    assert_eq!(
        hash_file(
            &fixture.executable,
            "test",
            empty_account(fixture.request.budget.timeout_millis)
        )
        .expect("hash"),
        sha256_bytes(b"fixture git").value
    );
}
