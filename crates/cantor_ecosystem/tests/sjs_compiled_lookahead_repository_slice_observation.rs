use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use cantor_core::{
    ContentDigest, SemanticId, SjsRcxInputClass, compile_sjs_rcx, seal_sjs_rcx_request,
    sha256_bytes, synthetic_sjs_rcx_request, verify_sjs_rcx,
};
#[cfg(windows)]
use cantor_ecosystem::sjs_compiled_lookahead_repository_slice_observation::sjs_rso_windows_attributes_are_reparse_point;
use cantor_ecosystem::sjs_compiled_lookahead_repository_slice_observation::{
    SJS_RSO_CANONICAL_UUID, SJS_RSO_MAX_MACHINE_FORM_BYTES, SJS_RSO_NON_AUTHORITY,
    SJS_RSO_PARENT_COMPLETION_UUID, SJS_RSO_RECEIPT_PROFILE, SJS_RSO_REQUEST_PROFILE,
    SJS_RSO_SIGNATURE_UUID, SJS_RSO_SOURCE_UUID, SjsRsoAccountStatus, SjsRsoEffectAccount,
    SjsRsoElementAccount, SjsRsoFaultCode, SjsRsoGitOperation, SjsRsoInputClass, SjsRsoLimits,
    SjsRsoPathKind, SjsRsoReceipt, SjsRsoRequest, from_sjs_rso_receipt_machine_form,
    from_sjs_rso_request_machine_form, from_sjs_rso_verification_machine_form,
    inspect_sjs_rso_no_follow_path, prepare_sjs_rso_git_runner, run_sjs_rso_git_operation,
    seal_sjs_rso_receipt, seal_sjs_rso_request, sjs_rso_git_arguments,
    to_sjs_rso_receipt_machine_form, to_sjs_rso_request_machine_form,
    to_sjs_rso_verification_machine_form, validate_sjs_rso_receipt, validate_sjs_rso_request,
    validate_sjs_rso_verification, verify_sjs_rso_receipt,
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
