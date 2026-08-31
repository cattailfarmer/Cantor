use std::collections::BTreeSet;

use cantor_core::{
    ContentDigest, SemanticId, SjsRcxInputClass, seal_sjs_rcx_request, sha256_bytes,
    synthetic_sjs_rcx_request,
};
use cantor_ecosystem::sjs_compiled_lookahead_repository_slice_observation::{
    SJS_RSO_CANONICAL_UUID, SJS_RSO_MAX_MACHINE_FORM_BYTES, SJS_RSO_NON_AUTHORITY,
    SJS_RSO_PARENT_COMPLETION_UUID, SJS_RSO_REQUEST_PROFILE, SJS_RSO_SIGNATURE_UUID,
    SJS_RSO_SOURCE_UUID, SjsRsoFaultCode, SjsRsoInputClass, SjsRsoLimits, SjsRsoRequest,
    from_sjs_rso_request_machine_form, seal_sjs_rso_request, to_sjs_rso_request_machine_form,
    validate_sjs_rso_request,
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
