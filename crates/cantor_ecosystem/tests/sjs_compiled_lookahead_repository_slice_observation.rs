use std::collections::BTreeSet;

use cantor_core::{
    ContentDigest, SemanticId, SjsRcxInputClass, compile_sjs_rcx, seal_sjs_rcx_request,
    sha256_bytes, synthetic_sjs_rcx_request, verify_sjs_rcx,
};
use cantor_ecosystem::sjs_compiled_lookahead_repository_slice_observation::{
    SJS_RSO_CANONICAL_UUID, SJS_RSO_MAX_MACHINE_FORM_BYTES, SJS_RSO_NON_AUTHORITY,
    SJS_RSO_PARENT_COMPLETION_UUID, SJS_RSO_RECEIPT_PROFILE, SJS_RSO_REQUEST_PROFILE,
    SJS_RSO_SIGNATURE_UUID, SJS_RSO_SOURCE_UUID, SjsRsoAccountStatus, SjsRsoEffectAccount,
    SjsRsoElementAccount, SjsRsoFaultCode, SjsRsoGitOperation, SjsRsoInputClass, SjsRsoLimits,
    SjsRsoReceipt, SjsRsoRequest, from_sjs_rso_receipt_machine_form,
    from_sjs_rso_request_machine_form, from_sjs_rso_verification_machine_form,
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
