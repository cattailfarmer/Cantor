use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use cantor_core::{
    ContentDigest, SemanticId, SjsRcxInputClass, compile_sjs_rcx, seal_sjs_rcx_request,
    sha256_bytes, synthetic_sjs_rcx_request, verify_sjs_rcx,
};
#[cfg(windows)]
use cantor_ecosystem::sjs_compiled_lookahead_repository_slice_observation::sjs_rso_windows_attributes_are_reparse_point;
use cantor_ecosystem::sjs_compiled_lookahead_repository_slice_observation::{
    SJS_RSO_CANONICAL_UUID, SJS_RSO_MAX_EVIDENCE_BUNDLE_BYTES, SJS_RSO_MAX_MACHINE_FORM_BYTES,
    SJS_RSO_NON_AUTHORITY, SJS_RSO_PARENT_COMPLETION_UUID, SJS_RSO_RECEIPT_PROFILE,
    SJS_RSO_REQUEST_PROFILE, SJS_RSO_SIGNATURE_UUID, SJS_RSO_SOURCE_UUID, SjsRsoAccountStatus,
    SjsRsoEffectAccount, SjsRsoElementAccount, SjsRsoFaultCode, SjsRsoGitOperation,
    SjsRsoInputClass, SjsRsoLimits, SjsRsoPathKind, SjsRsoReceipt, SjsRsoRequest,
    build_sjs_rso_evidence_bundle, compile_sjs_rso_commit_tree_receipt,
    from_sjs_rso_evidence_bundle_machine_form, from_sjs_rso_receipt_machine_form,
    from_sjs_rso_request_machine_form, from_sjs_rso_verification_machine_form,
    inspect_sjs_rso_no_follow_path, observe_sjs_rso_commit_tree,
    observe_sjs_rso_repository_identity, prepare_sjs_rso_git_runner, run_sjs_rso_git_operation,
    seal_sjs_rso_receipt, seal_sjs_rso_request, sjs_rso_git_arguments,
    to_sjs_rso_evidence_bundle_machine_form, to_sjs_rso_receipt_machine_form,
    to_sjs_rso_request_machine_form, to_sjs_rso_verification_machine_form,
    validate_sjs_rso_receipt, validate_sjs_rso_request, validate_sjs_rso_verification,
    verify_sjs_rso_evidence_bundle, verify_sjs_rso_receipt,
    verify_sjs_rso_repository_identity_stable,
};

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("test identity")
}

fn request() -> SjsRsoRequest {
    let mut parent = synthetic_sjs_rcx_request().expect("parent fixture");
    parent.input_class = SjsRcxInputClass::SuppliedUnobservedRepositorySlice;
    let parent = seal_sjs_rcx_request(parent).expect("sealed supplied parent");
    seal_sjs_rso_request(SjsRsoRequest {
        profile: SJS_RSO_REQUEST_PROFILE.to_owned(),
        request_id: id("request:85000000-0000-4000-8000-000000000001"),
        run_id: id("run:85000000-0000-4000-8000-000000000002"),
        receipt_id: id("receipt:85000000-0000-4000-8000-000000000003"),
        input_class: SjsRsoInputClass::DisposableLocalGitFixture,
        canonical_uuid: SJS_RSO_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_RSO_SIGNATURE_UUID.to_owned(),
        source_snapshot_uuid: SJS_RSO_SOURCE_UUID.to_owned(),
        parent_canonical_uuid: cantor_core::SJS_RCX_CANONICAL_UUID.to_owned(),
        parent_completion_signature_uuid: SJS_RSO_PARENT_COMPLETION_UUID.to_owned(),
        parent_request: parent,
        repository_root: "C:/Project/Cantor".to_owned(),
        git_executable: "C:/Program Files/Git/cmd/git.exe".to_owned(),
        expected_git_sha256: sha256_bytes(b"pinned Git executable"),
        expected_branch_ref: "refs/heads/codex/self-hosted-corpus".to_owned(),
        expected_head: "a".repeat(40),
        object_format: "sha1".to_owned(),
        limits: SjsRsoLimits {
            maximum_git_commands: 32,
            maximum_command_milliseconds: 120_000,
            maximum_stdout_bytes: 8_388_608,
            maximum_stderr_bytes: 1_048_576,
            maximum_executable_bytes: 67_108_864,
            maximum_index_bytes: 67_108_864,
            maximum_commit_bytes: 4_194_304,
            maximum_blob_bytes: 8_388_608,
            maximum_total_blob_bytes: 67_108_864,
            maximum_path_bytes: 4_096,
            maximum_evidence_bytes: 8_388_608,
        },
        evidence_refs: BTreeSet::new(),
        non_authority: SJS_RSO_NON_AUTHORITY.to_owned(),
        request_digest: ContentDigest {
            algorithm: "sha256".to_owned(),
            value: "0".repeat(64),
        },
    })
    .expect("sealed observation request")
}

fn assert_refused<T>(result: Result<T, impl std::fmt::Debug>) {
    assert!(result.is_err(), "adversary must refuse");
}

struct DisposablePathFixture {
    root: PathBuf,
}

impl DisposablePathFixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "cantor-rso-no-follow-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create disposable path fixture");
        Self { root }
    }

    fn text(&self, path: &Path) -> String {
        assert!(path.starts_with(&self.root));
        path.to_str().expect("UTF-8 fixture path").to_owned()
    }
}

impl Drop for DisposablePathFixture {
    fn drop(&mut self) {
        let temp = std::env::temp_dir();
        if self.root.parent() == Some(temp.as_path()) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn receipt(request: &SjsRsoRequest) -> SjsRsoReceipt {
    let accounts = request
        .parent_request
        .records
        .iter()
        .enumerate()
        .map(|(index, record)| SjsRsoElementAccount {
            element_id: record.element_id.clone(),
            candidate_id: record.candidate.candidate_id.clone(),
            locator: record.locator.clone(),
            mode: if index % 2 == 0 { "100644" } else { "100755" }.to_owned(),
            object_id: format!("{:040x}", index + 1),
            raw_bytes: 10 + index as u64,
            content_digest: record.content_digest.clone(),
            status: SjsRsoAccountStatus::ExactCommittedBlob,
        })
        .collect::<Vec<_>>();
    let parent_envelope = compile_sjs_rcx(&request.parent_request).expect("parent compile");
    let parent_verification = verify_sjs_rcx(&parent_envelope).expect("parent verify");
    seal_sjs_rso_receipt(
        request,
        SjsRsoReceipt {
            profile: SJS_RSO_RECEIPT_PROFILE.to_owned(),
            receipt_id: request.receipt_id.clone(),
            request_digest: request.request_digest.clone(),
            git_executable_before_sha256: request.expected_git_sha256.clone(),
            git_executable_after_sha256: request.expected_git_sha256.clone(),
            git_version: "git version fixture".to_owned(),
            git_build_options: "fixture build options".to_owned(),
            repository_root: request.repository_root.clone(),
            branch_ref: request.expected_branch_ref.clone(),
            head: request.expected_head.clone(),
            object_format: request.object_format.clone(),
            git_directory: "C:/Project/Cantor/.git".to_owned(),
            index_path: "C:/Project/Cantor/.git/index".to_owned(),
            index_before_sha256: sha256_bytes(b"stable fixture index"),
            index_after_sha256: sha256_bytes(b"stable fixture index"),
            commit_raw_bytes: 123,
            unique_blob_count: accounts.len() as u32,
            total_blob_bytes: accounts.iter().map(|account| account.raw_bytes).sum(),
            command_count: 20,
            accounts,
            parent_envelope,
            parent_verification,
            physical_contact: true,
            effects: SjsRsoEffectAccount {
                read_only_filesystem_observation: true,
                read_only_git_process_observation: true,
                ..SjsRsoEffectAccount::default()
            },
            non_authority: SJS_RSO_NON_AUTHORITY.to_owned(),
            receipt_digest: ContentDigest {
                algorithm: "sha256".to_owned(),
                value: "0".repeat(64),
            },
        },
    )
    .expect("sealed receipt")
}

#[cfg(windows)]
fn physical_runner_request(root: &Path, git_executable: &Path) -> SjsRsoRequest {
    let mut value = request();
    let mut parent = value.parent_request.clone();
    parent.scope.repository = root
        .to_str()
        .expect("UTF-8 fixture root")
        .replace('\\', "/");
    parent.scope.branch = "fixture".to_owned();
    value.parent_request = seal_sjs_rcx_request(parent).expect("reseal physical parent");
    value.repository_root = root.to_str().expect("UTF-8 fixture root").to_owned();
    value.git_executable = git_executable
        .to_str()
        .expect("UTF-8 Git executable")
        .replace('\\', "/");
    value.expected_git_sha256 =
        sha256_bytes(&fs::read(git_executable).expect("read Git executable"));
    value.expected_branch_ref = "refs/heads/fixture".to_owned();
    value.limits.maximum_command_milliseconds = 10_000;
    seal_sjs_rso_request(value).expect("seal physical runner request")
}

#[cfg(windows)]
fn run_fixture_git(root: &Path, git_executable: &Path, arguments: &[&str]) -> Vec<u8> {
    let output = Command::new(git_executable)
        .args(arguments)
        .current_dir(root)
        .env_clear()
        .env("GIT_ALLOW_PROTOCOL", "none")
        .env("GIT_CONFIG_GLOBAL", "NUL")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "NUL")
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("HOME", root)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("SYSTEMROOT", r"C:\Windows")
        .env("WINDIR", r"C:\Windows")
        .output()
        .expect("run fixture Git");
    assert!(
        output.status.success(),
        "fixture Git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

#[cfg(windows)]
fn physical_repository_request(
    fixture: &DisposablePathFixture,
    git_executable: &Path,
) -> SjsRsoRequest {
    run_fixture_git(
        &fixture.root,
        git_executable,
        &["init", "--quiet", "--initial-branch=fixture"],
    );
    let mut value = physical_runner_request(&fixture.root, git_executable);
    for (index, record) in value.parent_request.records.iter().enumerate() {
        let path = fixture.root.join(&record.locator);
        fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture path");
        fs::write(
            path,
            format!("supplied fixture content {}", index + 1).as_bytes(),
        )
        .expect("write committed fixture blob");
    }
    run_fixture_git(&fixture.root, git_executable, &["add", "--all"]);
    run_fixture_git(
        &fixture.root,
        git_executable,
        &[
            "-c",
            "user.name=Cantor Fixture",
            "-c",
            "user.email=cantor-fixture@example.invalid",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--quiet",
            "-m",
            "deterministic fixture",
        ],
    );
    let head = String::from_utf8(run_fixture_git(
        &fixture.root,
        git_executable,
        &["rev-parse", "HEAD"],
    ))
    .expect("UTF-8 fixture HEAD")
    .trim()
    .to_owned();
    let commit_raw = run_fixture_git(
        &fixture.root,
        git_executable,
        &["cat-file", "commit", "HEAD"],
    );
    let mut parent = value.parent_request.clone();
    parent.scope.commit_digest = sha256_bytes(&commit_raw);
    value.parent_request = seal_sjs_rcx_request(parent).expect("reseal committed parent");
    value.expected_head = head;
    let dirty_path = fixture.root.join(&value.parent_request.records[0].locator);
    fs::write(dirty_path, b"dirty working tree contrast").expect("write dirty contrast");
    seal_sjs_rso_request(value).expect("seal repository fixture request")
}

#[cfg(windows)]
fn retarget_repository_request(
    mut value: SjsRsoRequest,
    root: &Path,
    git_executable: &Path,
    update_parent_commit_digest: bool,
) -> SjsRsoRequest {
    value.expected_head = String::from_utf8(run_fixture_git(
        root,
        git_executable,
        &["rev-parse", "HEAD"],
    ))
    .expect("UTF-8 retargeted HEAD")
    .trim()
    .to_owned();
    if update_parent_commit_digest {
        let commit_raw = run_fixture_git(root, git_executable, &["cat-file", "commit", "HEAD"]);
        let mut parent = value.parent_request.clone();
        parent.scope.commit_digest = sha256_bytes(&commit_raw);
        value.parent_request = seal_sjs_rcx_request(parent).expect("reseal retargeted parent");
    }
    seal_sjs_rso_request(value).expect("seal retargeted observation request")
}

#[cfg(windows)]
fn commit_fixture(root: &Path, git_executable: &Path, message: &str) {
    run_fixture_git(
        root,
        git_executable,
        &[
            "-c",
            "user.name=Cantor Fixture",
            "-c",
            "user.email=cantor-fixture@example.invalid",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--quiet",
            "-m",
            message,
        ],
    );
}

#[test]
fn supplied_slice_request_seals_and_round_trips_as_strict_canonical_json() {
    let request = request();
    validate_sjs_rso_request(&request).expect("request validates");
    let machine = to_sjs_rso_request_machine_form(&request).expect("machine form");
    assert_eq!(
        from_sjs_rso_request_machine_form(&machine).expect("round trip"),
        request
    );
}

#[test]
fn four_file_evidence_rehashes_and_every_retained_raw_byte_tamper_refuses() {
    let request = request();
    let receipt = receipt(&request);
    let verification = verify_sjs_rso_receipt(&request, &receipt).expect("verification");
    let bundle =
        build_sjs_rso_evidence_bundle(&request, &receipt, &verification, &receipt, &verification)
            .expect("four-file evidence");

    assert_eq!(
        verify_sjs_rso_evidence_bundle(&bundle).expect("independent evidence replay"),
        verification
    );
    for file in [
        &bundle.request_file,
        &bundle.receipt_file,
        &bundle.verification_file,
        &bundle.manifest_file,
    ] {
        assert!(file.ends_with('\n'));
        assert!(!file.contains('\r'));
        assert!(!file[..file.len() - 1].contains('\n'));
    }
    let machine = to_sjs_rso_evidence_bundle_machine_form(&bundle).expect("bundle machine form");
    assert_eq!(
        from_sjs_rso_evidence_bundle_machine_form(&machine).expect("bundle round trip"),
        bundle
    );
    for malformed in [
        format!("{{\"request_file\":\"duplicate\",{}", &machine[1..]),
        format!("{{\"unknown\":0,{}", &machine[1..]),
        format!(" {machine}"),
        format!("{machine}x"),
        "[[]]".repeat(50),
    ] {
        assert_refused(from_sjs_rso_evidence_bundle_machine_form(&malformed));
    }
    let oversized = "x".repeat(SJS_RSO_MAX_EVIDENCE_BUNDLE_BYTES + 1);
    let oversized_error = from_sjs_rso_evidence_bundle_machine_form(&oversized)
        .expect_err("oversized evidence carrier must refuse");
    assert_eq!(oversized_error.code, SjsRsoFaultCode::InvalidBound);

    for file_index in 0..4 {
        let mut tampered = bundle.clone();
        let target = match file_index {
            0 => &mut tampered.request_file,
            1 => &mut tampered.receipt_file,
            2 => &mut tampered.verification_file,
            _ => &mut tampered.manifest_file,
        };
        let profile = target.find("profile").expect("profile field");
        target.replace_range(profile..profile + 1, "x");
        let error = verify_sjs_rso_evidence_bundle(&tampered)
            .expect_err("one retained raw-byte tamper must refuse");
        assert!(matches!(
            error.code,
            SjsRsoFaultCode::InvalidProfile
                | SjsRsoFaultCode::InvalidDigest
                | SjsRsoFaultCode::InvalidMachineForm
        ));
    }

    let mut replay_receipt = receipt.clone();
    replay_receipt.command_count += 1;
    assert_refused(build_sjs_rso_evidence_bundle(
        &request,
        &receipt,
        &verification,
        &replay_receipt,
        &verification,
    ));
}

#[cfg(windows)]
#[test]
fn hash_pinned_closed_git_version_runs_inside_windows_job() {
    let fixture = DisposablePathFixture::new();
    let git_executable = Path::new(r"C:\Program Files\Git\cmd\git.exe");
    assert!(git_executable.is_file(), "pinned local Git is unavailable");
    let request = physical_runner_request(&fixture.root, git_executable);
    let mut runner = prepare_sjs_rso_git_runner(&request).expect("prepare runner");
    let observation =
        run_sjs_rso_git_operation(&mut runner, SjsRsoGitOperation::VersionBuildOptions)
            .expect("contained Git version");

    assert_eq!(observation.command_sequence, 1);
    assert_eq!(runner.command_count(), 1);
    assert_eq!(observation.exit_code, 0);
    assert!(observation.assigned_before_resume);
    assert_eq!(observation.active_processes_at_terminal, 0);
    assert!((1..=4).contains(&observation.total_processes));
    assert!(observation.stderr_observed_bytes == 0);
    assert!(observation.stdout_observed_bytes > 0);
    assert!(observation.stdout.starts_with(b"git version "));
}

#[cfg(windows)]
#[test]
fn wrong_git_digest_and_repository_identity_drift_refuse_runner_authority() {
    let fixture = DisposablePathFixture::new();
    let git_executable = Path::new(r"C:\Program Files\Git\cmd\git.exe");
    assert!(git_executable.is_file(), "pinned local Git is unavailable");

    let mut wrong_digest = physical_runner_request(&fixture.root, git_executable);
    wrong_digest.expected_git_sha256 = sha256_bytes(b"wrong executable");
    let wrong_digest = seal_sjs_rso_request(wrong_digest).expect("reseal wrong digest request");
    let error = prepare_sjs_rso_git_runner(&wrong_digest).expect_err("wrong digest must refuse");
    assert_eq!(error.code, SjsRsoFaultCode::InvalidGitIdentity);

    let request = physical_runner_request(&fixture.root, git_executable);
    let mut runner = prepare_sjs_rso_git_runner(&request).expect("prepare runner");
    fs::write(fixture.root.join("identity-drift"), b"drift").expect("write drift marker");
    let error = run_sjs_rso_git_operation(&mut runner, SjsRsoGitOperation::VersionBuildOptions)
        .expect_err("repository identity drift must refuse");
    assert_eq!(error.code, SjsRsoFaultCode::InvalidGitIdentity);
}

#[cfg(windows)]
#[test]
fn stdout_overflow_timeout_and_unsuccessful_git_each_refuse() {
    let git_executable = Path::new(r"C:\Program Files\Git\cmd\git.exe");
    assert!(git_executable.is_file(), "pinned local Git is unavailable");

    let overflow_fixture = DisposablePathFixture::new();
    let mut overflow = physical_runner_request(&overflow_fixture.root, git_executable);
    overflow.limits.maximum_stdout_bytes = 1;
    let overflow = seal_sjs_rso_request(overflow).expect("seal overflow request");
    let mut overflow_runner = prepare_sjs_rso_git_runner(&overflow).expect("prepare overflow");
    let overflow_error = run_sjs_rso_git_operation(
        &mut overflow_runner,
        SjsRsoGitOperation::VersionBuildOptions,
    )
    .expect_err("stdout overflow must refuse");
    assert!(
        overflow_error.detail.contains("output exceeded"),
        "unexpected overflow refusal: {}",
        overflow_error.detail
    );

    let timeout_fixture = DisposablePathFixture::new();
    let mut timeout = physical_runner_request(&timeout_fixture.root, git_executable);
    timeout.limits.maximum_command_milliseconds = 1;
    let timeout = seal_sjs_rso_request(timeout).expect("seal timeout request");
    let mut timeout_runner = prepare_sjs_rso_git_runner(&timeout).expect("prepare timeout");
    let timeout_error =
        run_sjs_rso_git_operation(&mut timeout_runner, SjsRsoGitOperation::VersionBuildOptions)
            .expect_err("timeout must refuse");
    assert!(timeout_error.detail.contains("timed out"));

    let failure_fixture = DisposablePathFixture::new();
    let failure = physical_runner_request(&failure_fixture.root, git_executable);
    let mut failure_runner = prepare_sjs_rso_git_runner(&failure).expect("prepare failure");
    let failure_error =
        run_sjs_rso_git_operation(&mut failure_runner, SjsRsoGitOperation::ShowTopLevel)
            .expect_err("non-repository Git command must refuse");
    assert_eq!(failure_error.code, SjsRsoFaultCode::InvalidOperation);
}

#[cfg(windows)]
#[test]
fn command_budget_preincrements_and_refuses_the_first_excess_launch() {
    let fixture = DisposablePathFixture::new();
    let git_executable = Path::new(r"C:\Program Files\Git\cmd\git.exe");
    assert!(git_executable.is_file(), "pinned local Git is unavailable");
    let mut request = physical_runner_request(&fixture.root, git_executable);
    request.limits.maximum_git_commands =
        15 + u32::try_from(request.parent_request.records.len()).expect("record count");
    let request = seal_sjs_rso_request(request).expect("seal minimum command budget");
    let maximum = request.limits.maximum_git_commands;
    let mut runner = prepare_sjs_rso_git_runner(&request).expect("prepare runner");

    for sequence in 1..=maximum {
        let observation =
            run_sjs_rso_git_operation(&mut runner, SjsRsoGitOperation::VersionBuildOptions)
                .expect("bounded command");
        assert_eq!(observation.command_sequence, sequence);
    }
    let error = run_sjs_rso_git_operation(&mut runner, SjsRsoGitOperation::VersionBuildOptions)
        .expect_err("first excess command must refuse");
    assert_eq!(error.code, SjsRsoFaultCode::InvalidBound);
    assert_eq!(runner.command_count(), maximum + 1);
}

#[cfg(windows)]
#[test]
fn seven_command_repository_identity_snapshot_is_exact_and_stable() {
    let fixture = DisposablePathFixture::new();
    let git_executable = Path::new(r"C:\Program Files\Git\cmd\git.exe");
    let request = physical_repository_request(&fixture, git_executable);
    let mut runner = prepare_sjs_rso_git_runner(&request).expect("prepare repository runner");

    let before = observe_sjs_rso_repository_identity(&mut runner).expect("before snapshot");
    let after = observe_sjs_rso_repository_identity(&mut runner).expect("after snapshot");
    verify_sjs_rso_repository_identity_stable(&before, &after).expect("stable snapshots");

    assert_eq!(runner.command_count(), 14);
    assert!(before.git_version.starts_with("git version "));
    assert!(!before.git_build_options.is_empty());
    assert_eq!(
        before.repository_root,
        request.repository_root.replace('\\', "/")
    );
    assert_eq!(before.branch_ref, request.expected_branch_ref);
    assert_eq!(before.head, request.expected_head);
    assert_eq!(before.object_format, request.object_format);
    assert_eq!(before.git_directory.kind, SjsRsoPathKind::Directory);
    assert_eq!(before.index_path.kind, SjsRsoPathKind::RegularFile);
    assert!(
        Path::new(&before.index_path.canonical_path)
            .starts_with(Path::new(&before.git_directory.canonical_path))
    );
    assert_eq!(
        fs::read(
            fixture
                .root
                .join(&request.parent_request.records[0].locator)
        )
        .expect("read dirty contrast"),
        b"dirty working tree contrast"
    );

    let replica = DisposablePathFixture::new();
    let replica_request = physical_repository_request(&replica, git_executable);
    assert_eq!(replica_request.expected_head, request.expected_head);
    assert_eq!(
        replica_request.parent_request.scope.commit_digest,
        request.parent_request.scope.commit_digest
    );
}

#[cfg(windows)]
#[test]
fn locator_only_commit_tree_observation_accounts_for_exact_committed_blobs() {
    let fixture = DisposablePathFixture::new();
    let git_executable = Path::new(r"C:\Program Files\Git\cmd\git.exe");
    let request = physical_repository_request(&fixture, git_executable);
    let dirty_bytes = fs::read(
        fixture
            .root
            .join(&request.parent_request.records[0].locator),
    )
    .expect("read dirty worktree contrast");
    let mut runner = prepare_sjs_rso_git_runner(&request).expect("prepare commit-tree runner");

    let observation = observe_sjs_rso_commit_tree(&mut runner).expect("observe commit tree");

    assert_eq!(
        observation.accounts.len(),
        request.parent_request.records.len()
    );
    assert_eq!(observation.unique_blob_count, 8);
    assert_eq!(observation.command_count, 23);
    assert_eq!(runner.command_count(), 23);
    assert_eq!(
        observation.command_count,
        15 + observation.unique_blob_count
    );
    assert_eq!(observation.repository_before, observation.repository_after);
    assert_eq!(dirty_bytes, b"dirty working tree contrast");
    for (account, record) in observation
        .accounts
        .iter()
        .zip(&request.parent_request.records)
    {
        assert_eq!(account.element_id, record.element_id);
        assert_eq!(account.candidate_id, record.candidate.candidate_id);
        assert_eq!(account.locator, record.locator);
        assert_eq!(account.content_digest, record.content_digest);
        assert_eq!(account.status, SjsRsoAccountStatus::ExactCommittedBlob);
        assert!(matches!(account.mode.as_str(), "100644" | "100755"));
        assert_eq!(account.object_id.len(), 40);
        assert!(account.raw_bytes > 0);
    }
    assert_eq!(
        observation.total_blob_bytes,
        observation
            .accounts
            .iter()
            .map(|account| account.raw_bytes)
            .sum::<u64>()
    );
}

#[cfg(windows)]
#[test]
fn exact_physical_receipt_composes_the_unchanged_parent_after_correspondence() {
    let fixture = DisposablePathFixture::new();
    let git_executable = Path::new(r"C:\Program Files\Git\cmd\git.exe");
    let request = physical_repository_request(&fixture, git_executable);
    let runner = prepare_sjs_rso_git_runner(&request).expect("prepare receipt runner");

    let (receipt, verification) =
        compile_sjs_rso_commit_tree_receipt(runner).expect("compile physical receipt");

    validate_sjs_rso_receipt(&request, &receipt).expect("physical receipt validates");
    validate_sjs_rso_verification(&request, &receipt, &verification)
        .expect("physical verification validates");
    assert_eq!(receipt.parent_envelope.request, request.parent_request);
    assert_eq!(receipt.parent_verification.record_count, 8);
    assert_eq!(receipt.parent_verification.obligation_count, 6);
    assert_eq!(receipt.parent_verification.coverage_edge_count, 12);
    assert_eq!(receipt.parent_verification.selected_count, 3);
    assert_eq!(receipt.parent_verification.rejected_count, 5);
    assert_eq!(receipt.parent_verification.dominated_count, 1);
    assert_eq!(receipt.parent_verification.uncovered_count, 0);
    assert_eq!(receipt.parent_verification.admitted_subset_count, 92);
    assert_eq!(receipt.parent_verification.feasible_subset_count, 1);
    assert!(!receipt.parent_envelope.execution_authorized);
    assert_eq!(receipt.parent_envelope.effects, Default::default());
    assert!(receipt.physical_contact);
    assert!(receipt.effects.read_only_filesystem_observation);
    assert!(receipt.effects.read_only_git_process_observation);
    assert!(!receipt.effects.repository_write);
    assert!(!receipt.effects.network_contact);
    assert!(!receipt.effects.provider_contact);
    assert!(!receipt.effects.model_inference);
    assert_eq!(receipt.command_count, 23);
    assert_eq!(receipt.accounts.len(), 8);
    assert_eq!(verification.account_count, 8);
    assert_eq!(
        verification.parent_verification,
        receipt.parent_verification
    );
    assert!(!verification.execution_authorized);
}

#[cfg(windows)]
#[test]
fn identical_committed_object_is_read_once_but_keeps_separate_parent_accounts() {
    let fixture = DisposablePathFixture::new();
    let git_executable = Path::new(r"C:\Program Files\Git\cmd\git.exe");
    let request = physical_repository_request(&fixture, git_executable);
    let first_locator = request.parent_request.records[0].locator.clone();
    let second_locator = request.parent_request.records[1].locator.clone();
    let first_object = String::from_utf8(run_fixture_git(
        &fixture.root,
        git_executable,
        &["rev-parse", &format!("HEAD:{first_locator}")],
    ))
    .expect("UTF-8 first object")
    .trim()
    .to_owned();
    let first_blob = run_fixture_git(
        &fixture.root,
        git_executable,
        &["cat-file", "blob", &first_object],
    );
    fs::write(fixture.root.join(&second_locator), &first_blob).expect("write duplicate blob");
    run_fixture_git(
        &fixture.root,
        git_executable,
        &["add", "--", &second_locator],
    );
    commit_fixture(&fixture.root, git_executable, "duplicate blob object");

    let conflicting = retarget_repository_request(request, &fixture.root, git_executable, true);
    let mut conflicting_runner =
        prepare_sjs_rso_git_runner(&conflicting).expect("prepare conflicting correspondence");
    let conflict_error = observe_sjs_rso_commit_tree(&mut conflicting_runner)
        .expect_err("one object with conflicting signed digests must refuse");
    assert_eq!(conflict_error.code, SjsRsoFaultCode::InvalidDigest);

    let mut admitted = conflicting;
    let mut parent = admitted.parent_request.clone();
    parent.records[1].content_digest = parent.records[0].content_digest.clone();
    admitted.parent_request = seal_sjs_rcx_request(parent).expect("seal duplicate-object parent");
    let admitted = seal_sjs_rso_request(admitted).expect("seal duplicate-object observation");
    let mut admitted_runner =
        prepare_sjs_rso_git_runner(&admitted).expect("prepare duplicate-object runner");
    let observation =
        observe_sjs_rso_commit_tree(&mut admitted_runner).expect("observe duplicate object");

    assert_eq!(observation.accounts.len(), 8);
    assert_eq!(observation.unique_blob_count, 7);
    assert_eq!(observation.command_count, 22);
    assert_eq!(
        observation.accounts[0].object_id,
        observation.accounts[1].object_id
    );
    assert_eq!(
        observation.accounts[0].content_digest,
        observation.accounts[1].content_digest
    );
    assert_eq!(
        observation.accounts[0].raw_bytes,
        observation.accounts[1].raw_bytes
    );
}

#[cfg(windows)]
#[test]
fn commit_blob_mode_missing_locator_and_commit_digest_adversaries_refuse() {
    let git_executable = Path::new(r"C:\Program Files\Git\cmd\git.exe");

    let blob_fixture = DisposablePathFixture::new();
    let blob_request = physical_repository_request(&blob_fixture, git_executable);
    run_fixture_git(&blob_fixture.root, git_executable, &["add", "--all"]);
    commit_fixture(&blob_fixture.root, git_executable, "blob digest drift");
    let blob_request =
        retarget_repository_request(blob_request, &blob_fixture.root, git_executable, true);
    let mut blob_runner = prepare_sjs_rso_git_runner(&blob_request).expect("prepare blob drift");
    let blob_error = observe_sjs_rso_commit_tree(&mut blob_runner)
        .expect_err("committed blob digest drift must refuse");
    assert_eq!(blob_error.code, SjsRsoFaultCode::InvalidDigest);
    assert!(blob_error.detail.contains("committed blob digest"));

    let mode_fixture = DisposablePathFixture::new();
    let mode_request = physical_repository_request(&mode_fixture, git_executable);
    let mode_locator = mode_request.parent_request.records[1].locator.clone();
    let mode_object = String::from_utf8(run_fixture_git(
        &mode_fixture.root,
        git_executable,
        &["rev-parse", &format!("HEAD:{mode_locator}")],
    ))
    .expect("UTF-8 mode object")
    .trim()
    .to_owned();
    run_fixture_git(
        &mode_fixture.root,
        git_executable,
        &[
            "update-index",
            "--cacheinfo",
            &format!("120000,{mode_object},{mode_locator}"),
        ],
    );
    commit_fixture(&mode_fixture.root, git_executable, "unsupported mode");
    let mode_request =
        retarget_repository_request(mode_request, &mode_fixture.root, git_executable, true);
    let mut mode_runner = prepare_sjs_rso_git_runner(&mode_request).expect("prepare mode drift");
    let mode_error = observe_sjs_rso_commit_tree(&mut mode_runner)
        .expect_err("unsupported tree mode must refuse");
    assert_eq!(mode_error.code, SjsRsoFaultCode::InvalidGitIdentity);
    assert!(mode_error.detail.contains("mode"));

    let type_fixture = DisposablePathFixture::new();
    let type_request = physical_repository_request(&type_fixture, git_executable);
    let type_locator = type_request.parent_request.records[1].locator.clone();
    let commit_object = String::from_utf8(run_fixture_git(
        &type_fixture.root,
        git_executable,
        &["rev-parse", "HEAD"],
    ))
    .expect("UTF-8 commit object")
    .trim()
    .to_owned();
    run_fixture_git(
        &type_fixture.root,
        git_executable,
        &[
            "update-index",
            "--cacheinfo",
            &format!("160000,{commit_object},{type_locator}"),
        ],
    );
    commit_fixture(
        &type_fixture.root,
        git_executable,
        "unsupported object type",
    );
    let type_request =
        retarget_repository_request(type_request, &type_fixture.root, git_executable, true);
    let mut type_runner = prepare_sjs_rso_git_runner(&type_request).expect("prepare type drift");
    let type_error = observe_sjs_rso_commit_tree(&mut type_runner)
        .expect_err("unsupported tree object type must refuse");
    assert_eq!(type_error.code, SjsRsoFaultCode::InvalidGitIdentity);
    assert!(type_error.detail.contains("type"));

    let missing_fixture = DisposablePathFixture::new();
    let missing_request = physical_repository_request(&missing_fixture, git_executable);
    let missing_locator = missing_request.parent_request.records[2].locator.clone();
    run_fixture_git(
        &missing_fixture.root,
        git_executable,
        &["rm", "--quiet", "--cached", "--", &missing_locator],
    );
    commit_fixture(&missing_fixture.root, git_executable, "missing locator");
    let missing_request =
        retarget_repository_request(missing_request, &missing_fixture.root, git_executable, true);
    let mut missing_runner =
        prepare_sjs_rso_git_runner(&missing_request).expect("prepare missing locator");
    let missing_error = observe_sjs_rso_commit_tree(&mut missing_runner)
        .expect_err("missing signed locator must refuse");
    assert_eq!(missing_error.code, SjsRsoFaultCode::InvalidGitIdentity);

    let commit_fixture_root = DisposablePathFixture::new();
    let commit_request = physical_repository_request(&commit_fixture_root, git_executable);
    run_fixture_git(
        &commit_fixture_root.root,
        git_executable,
        &[
            "-c",
            "user.name=Cantor Fixture",
            "-c",
            "user.email=cantor-fixture@example.invalid",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "commit digest drift",
        ],
    );
    let commit_request = retarget_repository_request(
        commit_request,
        &commit_fixture_root.root,
        git_executable,
        false,
    );
    let mut commit_runner =
        prepare_sjs_rso_git_runner(&commit_request).expect("prepare commit drift");
    let commit_error = observe_sjs_rso_commit_tree(&mut commit_runner)
        .expect_err("raw commit digest drift must refuse");
    assert_eq!(commit_error.code, SjsRsoFaultCode::InvalidDigest);
    assert!(commit_error.detail.contains("raw commit"));
}

#[cfg(windows)]
#[test]
fn observed_commit_blob_and_total_blob_byte_bounds_refuse_before_receipt() {
    let git_executable = Path::new(r"C:\Program Files\Git\cmd\git.exe");

    let commit_fixture = DisposablePathFixture::new();
    let mut commit_request = physical_repository_request(&commit_fixture, git_executable);
    commit_request.limits.maximum_commit_bytes = 1;
    let commit_request = seal_sjs_rso_request(commit_request).expect("seal commit byte bound");
    let mut commit_runner =
        prepare_sjs_rso_git_runner(&commit_request).expect("prepare commit byte bound");
    let commit_error = observe_sjs_rso_commit_tree(&mut commit_runner)
        .expect_err("raw commit byte overflow must refuse");
    assert_eq!(commit_error.code, SjsRsoFaultCode::InvalidBound);
    assert!(commit_error.detail.contains("raw commit"));

    let blob_fixture = DisposablePathFixture::new();
    let mut blob_request = physical_repository_request(&blob_fixture, git_executable);
    blob_request.limits.maximum_blob_bytes = 1;
    let blob_request = seal_sjs_rso_request(blob_request).expect("seal blob byte bound");
    let mut blob_runner =
        prepare_sjs_rso_git_runner(&blob_request).expect("prepare blob byte bound");
    let blob_error = observe_sjs_rso_commit_tree(&mut blob_runner)
        .expect_err("raw blob byte overflow must refuse");
    assert_eq!(blob_error.code, SjsRsoFaultCode::InvalidBound);
    assert!(blob_error.detail.contains("raw blob"));

    let total_fixture = DisposablePathFixture::new();
    let mut total_request = physical_repository_request(&total_fixture, git_executable);
    total_request.limits.maximum_blob_bytes = 32;
    total_request.limits.maximum_total_blob_bytes = 32;
    let total_request = seal_sjs_rso_request(total_request).expect("seal total blob byte bound");
    let mut total_runner =
        prepare_sjs_rso_git_runner(&total_request).expect("prepare total blob byte bound");
    let total_error = observe_sjs_rso_commit_tree(&mut total_runner)
        .expect_err("total unique blob byte overflow must refuse");
    assert_eq!(total_error.code, SjsRsoFaultCode::InvalidBound);
    assert!(total_error.detail.contains("total unique raw blob"));
}

#[cfg(windows)]
#[test]
fn index_and_head_drift_refuse_repository_identity_stability() {
    let git_executable = Path::new(r"C:\Program Files\Git\cmd\git.exe");

    let index_fixture = DisposablePathFixture::new();
    let index_request = physical_repository_request(&index_fixture, git_executable);
    let mut index_runner =
        prepare_sjs_rso_git_runner(&index_request).expect("prepare index runner");
    let before = observe_sjs_rso_repository_identity(&mut index_runner).expect("before index");
    run_fixture_git(
        &index_fixture.root,
        git_executable,
        &[
            "add",
            "--",
            &index_request.parent_request.records[0].locator,
        ],
    );
    let after = observe_sjs_rso_repository_identity(&mut index_runner).expect("after index");
    let error = verify_sjs_rso_repository_identity_stable(&before, &after)
        .expect_err("index drift must refuse");
    assert_eq!(error.code, SjsRsoFaultCode::InvalidGitIdentity);

    let head_fixture = DisposablePathFixture::new();
    let head_request = physical_repository_request(&head_fixture, git_executable);
    let mut head_runner = prepare_sjs_rso_git_runner(&head_request).expect("prepare head runner");
    run_fixture_git(
        &head_fixture.root,
        git_executable,
        &[
            "-c",
            "user.name=Cantor Fixture",
            "-c",
            "user.email=cantor-fixture@example.invalid",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "head drift",
        ],
    );
    let error =
        observe_sjs_rso_repository_identity(&mut head_runner).expect_err("HEAD drift must refuse");
    assert_eq!(error.code, SjsRsoFaultCode::InvalidGitIdentity);
}

#[cfg(windows)]
#[test]
fn observed_git_directory_and_index_must_fit_request_path_bound() {
    let fixture = DisposablePathFixture::new();
    let git_executable = Path::new(r"C:\Program Files\Git\cmd\git.exe");
    let mut request = physical_repository_request(&fixture, git_executable);
    let supplied_maximum = request
        .parent_request
        .records
        .iter()
        .map(|record| record.locator.len())
        .chain([request.repository_root.len(), request.git_executable.len()])
        .max()
        .expect("supplied paths");
    request.limits.maximum_path_bytes = u32::try_from(supplied_maximum).expect("path bound");
    let request = seal_sjs_rso_request(request).expect("seal tight supplied path bound");
    let mut runner = prepare_sjs_rso_git_runner(&request).expect("prepare tight runner");
    let error = observe_sjs_rso_repository_identity(&mut runner)
        .expect_err("longer observed Git paths must refuse");
    assert_eq!(error.code, SjsRsoFaultCode::InvalidBound);
}

#[test]
fn synthetic_parent_and_parent_scope_drift_refuse() {
    let mut synthetic = request();
    synthetic.parent_request = synthetic_sjs_rcx_request().expect("synthetic parent");
    assert_refused(seal_sjs_rso_request(synthetic));

    let mut drift = request();
    drift.repository_root = "C:/Project/NotCantor".to_owned();
    let error = seal_sjs_rso_request(drift).expect_err("scope drift");
    assert_eq!(error.code, SjsRsoFaultCode::InvalidPath);
}

#[test]
fn relative_or_traversing_repository_and_git_paths_refuse() {
    for mutation in 0..4 {
        let mut value = request();
        match mutation {
            0 => value.repository_root = "Project/Cantor".to_owned(),
            1 => value.repository_root = "C:/Project/../Cantor".to_owned(),
            2 => value.git_executable = "git.exe".to_owned(),
            _ => value.git_executable = "C:/Git/../git.exe".to_owned(),
        }
        assert_refused(seal_sjs_rso_request(value));
    }
}

#[test]
fn branch_head_object_format_and_git_digest_drift_refuse() {
    let mut branch = request();
    branch.expected_branch_ref = "refs/heads/main".to_owned();
    assert_refused(seal_sjs_rso_request(branch));

    let mut head = request();
    head.expected_head = "A".repeat(40);
    assert_refused(seal_sjs_rso_request(head));

    let mut object_format = request();
    object_format.object_format = "md5".to_owned();
    assert_refused(seal_sjs_rso_request(object_format));

    let mut digest = request();
    digest.expected_git_sha256.value.pop();
    assert_refused(seal_sjs_rso_request(digest));
}

#[test]
fn every_zero_observation_limit_refuses() {
    for mutation in 0..11 {
        let mut value = request();
        match mutation {
            0 => value.limits.maximum_git_commands = 0,
            1 => value.limits.maximum_command_milliseconds = 0,
            2 => value.limits.maximum_stdout_bytes = 0,
            3 => value.limits.maximum_stderr_bytes = 0,
            4 => value.limits.maximum_executable_bytes = 0,
            5 => value.limits.maximum_index_bytes = 0,
            6 => value.limits.maximum_commit_bytes = 0,
            7 => value.limits.maximum_blob_bytes = 0,
            8 => value.limits.maximum_total_blob_bytes = 0,
            9 => value.limits.maximum_path_bytes = 0,
            _ => value.limits.maximum_evidence_bytes = 0,
        }
        assert_refused(seal_sjs_rso_request(value));
    }
}

#[test]
fn command_budget_must_cover_worst_case_identity_tree_commit_and_blob_reads() {
    let mut insufficient = request();
    assert_eq!(insufficient.parent_request.records.len(), 8);
    insufficient.limits.maximum_git_commands = 22;
    assert_refused(seal_sjs_rso_request(insufficient));

    let mut exact = request();
    exact.limits.maximum_git_commands = 23;
    seal_sjs_rso_request(exact).expect("fifteen fixed plus eight record commands");
}

#[test]
fn request_path_limit_covers_repository_executable_and_every_parent_locator() {
    let mut bounded = request();
    let required = bounded
        .parent_request
        .records
        .iter()
        .map(|record| record.locator.len())
        .chain([bounded.repository_root.len(), bounded.git_executable.len()])
        .max()
        .expect("bounded paths");
    bounded.limits.maximum_path_bytes = required as u32;
    seal_sjs_rso_request(bounded.clone()).expect("exact path bound");
    bounded.limits.maximum_path_bytes -= 1;
    assert_refused(seal_sjs_rso_request(bounded));
}

#[test]
fn closed_git_operation_vectors_are_exact_and_request_derived() {
    let request = request();
    let cases = [
        (
            SjsRsoGitOperation::VersionBuildOptions,
            vec!["version", "--build-options"],
        ),
        (
            SjsRsoGitOperation::ShowTopLevel,
            vec!["rev-parse", "--show-toplevel"],
        ),
        (
            SjsRsoGitOperation::SymbolicFullNameHead,
            vec!["rev-parse", "--symbolic-full-name", "HEAD"],
        ),
        (SjsRsoGitOperation::Head, vec!["rev-parse", "HEAD"]),
        (
            SjsRsoGitOperation::ObjectFormat,
            vec!["rev-parse", "--show-object-format"],
        ),
        (
            SjsRsoGitOperation::GitDirectory,
            vec!["rev-parse", "--path-format=absolute", "--git-dir"],
        ),
        (
            SjsRsoGitOperation::IndexPath,
            vec!["rev-parse", "--path-format=absolute", "--git-path", "index"],
        ),
        (
            SjsRsoGitOperation::CommitHead,
            vec!["cat-file", "commit", "HEAD"],
        ),
    ];
    for (operation, expected) in cases {
        assert_eq!(
            sjs_rso_git_arguments(&request, &operation).expect("closed operation"),
            expected
        );
    }

    let tree = sjs_rso_git_arguments(&request, &SjsRsoGitOperation::LsTreeSuppliedLocators)
        .expect("tree command");
    assert_eq!(&tree[..5], ["ls-tree", "-rz", "--full-tree", "HEAD", "--"]);
    assert_eq!(
        &tree[5..],
        request
            .parent_request
            .records
            .iter()
            .map(|record| record.locator.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn blob_operation_accepts_only_exact_object_format_identity() {
    let request = request();
    let object_id = "a".repeat(40);
    assert_eq!(
        sjs_rso_git_arguments(
            &request,
            &SjsRsoGitOperation::BlobObject {
                object_id: object_id.clone(),
            },
        )
        .expect("blob command"),
        vec!["cat-file", "blob", &object_id]
    );
    for invalid in ["a".repeat(39), "a".repeat(41), "A".repeat(40)] {
        let error = sjs_rso_git_arguments(
            &request,
            &SjsRsoGitOperation::BlobObject { object_id: invalid },
        )
        .expect_err("invalid blob identity");
        assert_eq!(error.code, SjsRsoFaultCode::InvalidOperation);
    }
}

#[test]
fn no_follow_path_identity_is_stable_bounded_and_kind_exact() {
    let fixture = DisposablePathFixture::new();
    let file = fixture.root.join("regular.bin");
    fs::write(&file, b"alpha").expect("write fixture file");
    let file_text = fixture.text(&file);
    let first = inspect_sjs_rso_no_follow_path(&file_text, SjsRsoPathKind::RegularFile, 5)
        .expect("regular identity");
    let second = inspect_sjs_rso_no_follow_path(&file_text, SjsRsoPathKind::RegularFile, 5)
        .expect("stable regular identity");
    assert_eq!(first, second);
    assert_eq!(first.byte_length, 5);

    assert_refused(inspect_sjs_rso_no_follow_path(
        &file_text,
        SjsRsoPathKind::RegularFile,
        4,
    ));
    assert_refused(inspect_sjs_rso_no_follow_path(
        &file_text,
        SjsRsoPathKind::Directory,
        1024 * 1024,
    ));
    let root_text = fixture.text(&fixture.root);
    inspect_sjs_rso_no_follow_path(&root_text, SjsRsoPathKind::Directory, 1024 * 1024)
        .expect("directory identity");

    fs::write(&file, b"alpha-beta").expect("mutate fixture file");
    let changed = inspect_sjs_rso_no_follow_path(&file_text, SjsRsoPathKind::RegularFile, 10)
        .expect("changed identity");
    assert_ne!(first, changed);
}

#[test]
fn symbolic_link_or_raw_reparse_classifier_and_noncanonical_component_refuse() {
    let fixture = DisposablePathFixture::new();
    let target = fixture.root.join("target.bin");
    let link = fixture.root.join("link.bin");
    fs::write(&target, b"target").expect("write link target");
    match create_file_symlink(&target, &link) {
        Ok(()) => assert_refused(inspect_sjs_rso_no_follow_path(
            &fixture.text(&link),
            SjsRsoPathKind::RegularFile,
            1024,
        )),
        #[cfg(windows)]
        Err(error) if error.raw_os_error() == Some(1314) => {
            // This host lacks symlink-creation privilege. Preserve that refusal
            // and still prove the exact raw attribute predicate used by every
            // real component inspection; do not claim a live reparse fixture.
            assert!(sjs_rso_windows_attributes_are_reparse_point(0x400));
            assert!(!sjs_rso_windows_attributes_are_reparse_point(0));
        }
        Err(error) => panic!("create disposable symbolic link: {error}"),
    }

    let noncanonical = fixture.root.join("child").join("..").join("target.bin");
    assert_refused(inspect_sjs_rso_no_follow_path(
        noncanonical.to_str().expect("UTF-8 path"),
        SjsRsoPathKind::RegularFile,
        1024,
    ));
}

#[cfg(windows)]
fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

#[cfg(windows)]
fn create_directory_junction(target: &Path, junction: &Path) -> std::io::Result<()> {
    let output = Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(junction)
        .arg(target)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "mklink /J failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

#[cfg(windows)]
struct DirectoryJunctionGuard(PathBuf);

#[cfg(windows)]
impl Drop for DirectoryJunctionGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}

#[cfg(windows)]
#[test]
fn actual_directory_junction_component_refuses_no_follow_inspection() {
    let fixture = DisposablePathFixture::new();
    let target = fixture.root.join("junction-target");
    let junction = fixture.root.join("junction");
    fs::create_dir(&target).expect("create junction target");
    create_directory_junction(&target, &junction).expect("create disposable directory junction");
    let guard = DirectoryJunctionGuard(junction.clone());

    let candidate = junction.join("candidate.bin");
    let error = inspect_sjs_rso_no_follow_path(
        candidate.to_str().expect("UTF-8 junction candidate"),
        SjsRsoPathKind::RegularFile,
        1024,
    )
    .expect_err("actual junction component must refuse before leaf contact");
    assert!(error.detail.contains("reparse"), "{}", error.detail);

    drop(guard);
    assert!(!junction.exists());
}

#[cfg(unix)]
fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[test]
fn request_digest_and_authority_tamper_refuse_validation() {
    let mut digest = request();
    digest.request_digest.value.replace_range(0..1, "f");
    assert_refused(validate_sjs_rso_request(&digest));

    let mut authority = request();
    authority.signature_uuid = "00000000-0000-4000-8000-000000000000".to_owned();
    assert_refused(validate_sjs_rso_request(&authority));
}

#[test]
fn duplicate_unknown_noncanonical_trailing_and_oversize_machine_forms_refuse() {
    let machine = to_sjs_rso_request_machine_form(&request()).expect("machine form");
    let duplicate = machine.replacen(
        "{\"profile\":",
        "{\"profile\":\"duplicate\",\"profile\":",
        1,
    );
    assert_refused(from_sjs_rso_request_machine_form(&duplicate));

    let unknown = machine.replacen("{\"profile\":", "{\"unknown\":true,\"profile\":", 1);
    assert_refused(from_sjs_rso_request_machine_form(&unknown));
    assert_refused(from_sjs_rso_request_machine_form(&format!(" {machine}")));
    assert_refused(from_sjs_rso_request_machine_form(&format!("{machine}\n")));

    let oversize = "x".repeat(SJS_RSO_MAX_MACHINE_FORM_BYTES + 1);
    assert_refused(from_sjs_rso_request_machine_form(&oversize));
}

#[test]
fn exact_receipt_and_verification_seal_validate_and_round_trip() {
    let request = request();
    let receipt = receipt(&request);
    validate_sjs_rso_receipt(&request, &receipt).expect("receipt validates");
    let receipt_machine =
        to_sjs_rso_receipt_machine_form(&request, &receipt).expect("receipt machine form");
    assert_eq!(
        from_sjs_rso_receipt_machine_form(&request, &receipt_machine).expect("receipt round trip"),
        receipt
    );

    let verification = verify_sjs_rso_receipt(&request, &receipt).expect("verification");
    validate_sjs_rso_verification(&request, &receipt, &verification)
        .expect("verification validates");
    let verification_machine =
        to_sjs_rso_verification_machine_form(&request, &receipt, &verification)
            .expect("verification machine form");
    assert_eq!(
        from_sjs_rso_verification_machine_form(&request, &receipt, &verification_machine)
            .expect("verification round trip"),
        verification
    );
}

#[test]
fn receipt_effect_blob_parent_and_digest_tamper_refuse() {
    let request = request();

    let mut effect = receipt(&request);
    effect.effects.network_contact = true;
    assert_refused(seal_sjs_rso_receipt(&request, effect));

    let mut raw_bytes = receipt(&request);
    raw_bytes.accounts[0].raw_bytes += 1;
    assert_refused(seal_sjs_rso_receipt(&request, raw_bytes));

    let mut object = receipt(&request);
    object.accounts[1].object_id = object.accounts[0].object_id.clone();
    assert_refused(seal_sjs_rso_receipt(&request, object));

    let mut parent = receipt(&request);
    parent.parent_envelope.receipt.admitted_record_count -= 1;
    assert_refused(seal_sjs_rso_receipt(&request, parent));

    let mut digest = receipt(&request);
    digest.receipt_digest.value.replace_range(0..1, "f");
    assert_refused(validate_sjs_rso_receipt(&request, &digest));
}

#[test]
fn receipt_machine_form_duplicate_unknown_noncanonical_trailing_and_oversize_refuse() {
    let request = request();
    let receipt = receipt(&request);
    let machine =
        to_sjs_rso_receipt_machine_form(&request, &receipt).expect("receipt machine form");
    let duplicate = machine.replacen(
        "{\"profile\":",
        "{\"profile\":\"duplicate\",\"profile\":",
        1,
    );
    assert_refused(from_sjs_rso_receipt_machine_form(&request, &duplicate));
    let unknown = machine.replacen("{\"profile\":", "{\"unknown\":true,\"profile\":", 1);
    assert_refused(from_sjs_rso_receipt_machine_form(&request, &unknown));
    assert_refused(from_sjs_rso_receipt_machine_form(
        &request,
        &format!(" {machine}"),
    ));
    assert_refused(from_sjs_rso_receipt_machine_form(
        &request,
        &format!("{machine}\n"),
    ));
    let oversize = "x".repeat(SJS_RSO_MAX_MACHINE_FORM_BYTES + 1);
    assert_refused(from_sjs_rso_receipt_machine_form(&request, &oversize));
}

#[test]
fn verification_machine_form_and_effect_or_digest_tamper_refuse() {
    let request = request();
    let receipt = receipt(&request);
    let verification = verify_sjs_rso_receipt(&request, &receipt).expect("verification");
    let machine = to_sjs_rso_verification_machine_form(&request, &receipt, &verification)
        .expect("verification machine form");
    let duplicate = machine.replacen(
        "{\"profile\":",
        "{\"profile\":\"duplicate\",\"profile\":",
        1,
    );
    assert_refused(from_sjs_rso_verification_machine_form(
        &request, &receipt, &duplicate,
    ));
    let unknown = machine.replacen("{\"profile\":", "{\"unknown\":true,\"profile\":", 1);
    assert_refused(from_sjs_rso_verification_machine_form(
        &request, &receipt, &unknown,
    ));
    assert_refused(from_sjs_rso_verification_machine_form(
        &request,
        &receipt,
        &format!(" {machine}"),
    ));
    assert_refused(from_sjs_rso_verification_machine_form(
        &request,
        &receipt,
        &format!("{machine}\n"),
    ));

    let mut effect = verification.clone();
    effect.effects.repository_write = true;
    assert_refused(validate_sjs_rso_verification(&request, &receipt, &effect));
    let mut digest = verification;
    digest.verification_digest.value.replace_range(0..1, "f");
    assert_refused(validate_sjs_rso_verification(&request, &receipt, &digest));
}
