use std::{env, fs, path::Path};

use cantor_core::ContentDigest;
use cantor_ecosystem::{
    B1_CDRIVE_PREFLIGHT_PRODUCER_PLAN_REQUEST_PROFILE,
    B1_CDRIVE_PREFLIGHT_PRODUCER_SELECTED_EXECUTABLE, B1_CDRIVE_PREFLIGHT_PRODUCER_SIGNATURE_UUID,
    B1_CDRIVE_PREFLIGHT_PRODUCER_SOURCE_SNAPSHOT_UUID,
    B1_CDRIVE_WORKTREE_PREPARATION_ATTRIBUTE_QUARANTINE, B1_CDRIVE_WORKTREE_PREPARATION_BOOKEND,
    B1_CDRIVE_WORKTREE_PREPARATION_BRANCH, B1_CDRIVE_WORKTREE_PREPARATION_CARRIER,
    B1_CDRIVE_WORKTREE_PREPARATION_FILESYSTEM_PROFILE, B1_CDRIVE_WORKTREE_PREPARATION_GIT,
    B1_CDRIVE_WORKTREE_PREPARATION_GIT_OBSERVATION_PROFILE,
    B1_CDRIVE_WORKTREE_PREPARATION_GIT_SHA256, B1_CDRIVE_WORKTREE_PREPARATION_GIT_VERSION,
    B1_CDRIVE_WORKTREE_PREPARATION_HOOK_QUARANTINE, B1_CDRIVE_WORKTREE_PREPARATION_IMPLEMENTATION,
    B1_CDRIVE_WORKTREE_PREPARATION_INVALIDATION_UUID,
    B1_CDRIVE_WORKTREE_PREPARATION_OUTCOME_PROFILE, B1_CDRIVE_WORKTREE_PREPARATION_REQUEST_PROFILE,
    B1_CDRIVE_WORKTREE_PREPARATION_SCRATCH, B1_CDRIVE_WORKTREE_PREPARATION_SIGNATURE_UUID,
    B1_CDRIVE_WORKTREE_PREPARATION_SOURCE_SNAPSHOT_UUID, B1CDrivePreflightProducerChildKind,
    B1CDrivePreflightProducerEnvironmentValue, B1CDrivePreflightProducerPlanFaultCode,
    B1CDrivePreflightProducerPlanRequest, CDriveWorktreePreparationRequest,
    PreparationArtifactIdentity, PreparationFilesystemObservation, PreparationGitObservation,
    PreparationOutcomeAccount, PreparationOutcomeDisposition,
    b1_cdrive_preflight_producer_plan_request_digest, compile_b1_cdrive_preflight_producer_plan,
    from_b1_cdrive_preflight_producer_plan_machine_form,
    from_b1_cdrive_preflight_producer_plan_request_machine_form,
    to_b1_cdrive_preflight_producer_plan_machine_form,
    to_b1_cdrive_preflight_producer_plan_request_machine_form,
    validate_b1_cdrive_preflight_producer_plan,
};
use serde::Serialize;
use serde_json::json as json_value;
use sha2::{Digest, Sha256};

const TEST_EXPECTED_CURRENT_COMMIT: &str = "b07a273c0b780fc4b08eccf9ea55472616362c9e";
const HISTORICAL_PROOF_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../experiments/self_work_update_broker_b1_cdrive_linked_worktree_preparation_p0_revision_0_3/supervising_publication_proof.json"
));
const COMMISSION_ADMISSION_RECEIPT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../experiments/self_work_update_broker_b1_cdrive_preparation_commission_admission_p0_revision_0_2/provider_independent_evidence/admission_receipt.json"
));

fn preparation_request() -> CDriveWorktreePreparationRequest {
    let scratch = B1_CDRIVE_WORKTREE_PREPARATION_SCRATCH;
    CDriveWorktreePreparationRequest {
        profile: B1_CDRIVE_WORKTREE_PREPARATION_REQUEST_PROFILE.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_WORKTREE_PREPARATION_SOURCE_SNAPSHOT_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_WORKTREE_PREPARATION_SIGNATURE_UUID.to_owned(),
        predecessor_invalidation_uuid: B1_CDRIVE_WORKTREE_PREPARATION_INVALIDATION_UUID.to_owned(),
        carrier_commit: B1_CDRIVE_WORKTREE_PREPARATION_CARRIER.to_owned(),
        implementation_commit: B1_CDRIVE_WORKTREE_PREPARATION_IMPLEMENTATION.to_owned(),
        bookend_commit: B1_CDRIVE_WORKTREE_PREPARATION_BOOKEND.to_owned(),
        expected_current_commit: TEST_EXPECTED_CURRENT_COMMIT.to_owned(),
        publication_proof_artifact: PreparationArtifactIdentity {
            path: "publication_proof.json".to_owned(),
            bytes: HISTORICAL_PROOF_BYTES.len() as u64,
            sha256: sha256_upper(HISTORICAL_PROOF_BYTES),
        },
        physical_commission_uuid: None,
        physical_preparation_authorized: false,
        recovery_owner: "THEBRAIN\\enjer".to_owned(),
        principal_workspace: "C:\\Project\\Cantor".to_owned(),
        repository_common_dir: "C:\\Project\\Cantor\\.git".to_owned(),
        scratch_root: scratch.to_owned(),
        candidate_root: format!("{scratch}\\candidate"),
        evidence_root: format!("{scratch}\\evidence"),
        temp_root: format!("{scratch}\\temp"),
        codex_home: format!("{scratch}\\codex-home"),
        hook_quarantine_root: B1_CDRIVE_WORKTREE_PREPARATION_HOOK_QUARANTINE.to_owned(),
        attribute_quarantine_file: B1_CDRIVE_WORKTREE_PREPARATION_ATTRIBUTE_QUARANTINE.to_owned(),
        branch_ref: B1_CDRIVE_WORKTREE_PREPARATION_BRANCH.to_owned(),
        git_executable: B1_CDRIVE_WORKTREE_PREPARATION_GIT.to_owned(),
        git_executable_bytes: 46_480,
        git_executable_sha256: B1_CDRIVE_WORKTREE_PREPARATION_GIT_SHA256.to_owned(),
        git_version: B1_CDRIVE_WORKTREE_PREPARATION_GIT_VERSION.to_owned(),
        maximum_processes: 12,
        maximum_stream_bytes: 1024 * 1024,
        maximum_total_process_bytes: 4 * 1024 * 1024,
        deadline_millis: 30_000,
        minimum_pre_effect_free_bytes: 15_032_385_536,
        minimum_final_free_bytes: 12_884_901_888,
    }
}

fn filesystem(request: &CDriveWorktreePreparationRequest) -> PreparationFilesystemObservation {
    PreparationFilesystemObservation {
        profile: B1_CDRIVE_WORKTREE_PREPARATION_FILESYSTEM_PROFILE.to_owned(),
        scratch_root: request.scratch_root.clone(),
        candidate_root: request.candidate_root.clone(),
        evidence_root: request.evidence_root.clone(),
        temp_root: request.temp_root.clone(),
        codex_home: request.codex_home.clone(),
        hook_quarantine_root: request.hook_quarantine_root.clone(),
        attribute_quarantine_file: request.attribute_quarantine_file.clone(),
        scratch_present: true,
        candidate_present: true,
        evidence_present: true,
        temp_present: true,
        codex_home_present: true,
        hook_quarantine_present: true,
        hook_quarantine_is_directory: true,
        hook_quarantine_is_reparse_point: false,
        hook_quarantine_entry_count: 0,
        attribute_quarantine_present: true,
        attribute_quarantine_is_regular_file: true,
        attribute_quarantine_is_reparse_point: false,
        attribute_quarantine_bytes: 0,
        attribute_quarantine_sha256:
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855".to_owned(),
        repository_info_attributes_absent: true,
        roles_pairwise_disjoint: true,
        roles_strict_scratch_descendants: true,
        principal_strictly_nonoverlapping: true,
        same_selected_volume: true,
        directory_creation_count: 5,
        regular_file_creation_count: 1,
        other_path_effect_count: 0,
        principal_worktree_file_mutation_count: 0,
        candidate_post_checkout_authorship_count: 0,
        allowed_sentinel_bytes: 31,
        allowed_sentinel_sha256: "BE8C5B7129F046B3B6A3E290DC3E352810E13C40906E98122E99F66DEEE2312C"
            .to_owned(),
        denied_sentinel_bytes: 30,
        denied_sentinel_sha256: "19992D428A24A764DBD744B1C06AFACB7A1379DDAD8CEE0095D5071940E002A3"
            .to_owned(),
        write_canary_present: false,
        cleanup_count: 0,
    }
}

fn git_observation(request: &CDriveWorktreePreparationRequest) -> PreparationGitObservation {
    PreparationGitObservation {
        profile: B1_CDRIVE_WORKTREE_PREPARATION_GIT_OBSERVATION_PROFILE.to_owned(),
        carrier_commit: request.carrier_commit.clone(),
        candidate_head: request.carrier_commit.clone(),
        candidate_branch_ref: request.branch_ref.clone(),
        candidate_top_level: request.candidate_root.clone(),
        candidate_common_dir: request.repository_common_dir.clone(),
        candidate_git_dir: "C:\\Project\\Cantor\\.git\\worktrees\\candidate".to_owned(),
        candidate_git_dir_under_worktree_admin: true,
        candidate_status_bytes: 0,
        recursive_submodule_status_bytes: 0,
        exact_worktree_membership_count: 1,
        branch_ref_mutation_count: 1,
        worktree_metadata_mutation_count: 1,
        checkout_file_count: 4_416,
        protected_ref_mutation_count: 0,
        fetch_count: 0,
        pull_count: 0,
        remote_update_count: 0,
        commit_count: 0,
        push_count: 0,
        retry_count: 0,
        worktree_remove_count: 0,
        branch_delete_count: 0,
        git_version_before: request.git_version.clone(),
        git_version_after: request.git_version.clone(),
    }
}

fn outcome() -> PreparationOutcomeAccount {
    PreparationOutcomeAccount {
        profile: B1_CDRIVE_WORKTREE_PREPARATION_OUTCOME_PROFILE.to_owned(),
        disposition: PreparationOutcomeDisposition::PreparedForPhase3aAcquisition,
        authority: "linked_worktree_preparation_observation_only".to_owned(),
        pre_effect_gate_passed: true,
        post_effect_verification_passed: true,
        physical_contact: true,
        may_have_mutated: true,
        retained_state: true,
        reserved_root_contact: true,
        reserved_ref_contact: true,
        actual_directory_creations: 5,
        actual_regular_file_creations: 1,
        actual_branch_ref_mutations: 1,
        actual_worktree_metadata_mutations: 1,
        actual_checkout_file_count: 4_416,
        final_free_bytes: Some(12_884_901_888),
        success_receipt_emitted: true,
        network_contact_count: 0,
        phase3a_run_count: 0,
        p1_app_server_run_count: 0,
        writer_run_count: 0,
        provider_trial_count: 0,
        model_turn_count: 0,
        mcp_call_count: 0,
        d_drive_contact_count: 0,
        wsl_compile_count: 0,
        cleanup_count: 0,
    }
}

fn environment(
    request: &CDriveWorktreePreparationRequest,
) -> Vec<B1CDrivePreflightProducerEnvironmentValue> {
    [
        ("CODEX_HOME", request.codex_home.as_str()),
        ("PATH", "C:\\Windows\\System32;C:\\Windows"),
        ("PATHEXT", ".COM;.EXE;.BAT;.CMD"),
        ("SYSTEMROOT", "C:\\Windows"),
        ("TEMP", request.temp_root.as_str()),
        ("TMP", request.temp_root.as_str()),
        ("WINDIR", "C:\\Windows"),
    ]
    .into_iter()
    .map(|(name, value)| B1CDrivePreflightProducerEnvironmentValue {
        name: name.to_owned(),
        value: value.to_owned(),
    })
    .collect()
}

fn plan_request() -> B1CDrivePreflightProducerPlanRequest {
    let preparation = preparation_request();
    let mut request = B1CDrivePreflightProducerPlanRequest {
        profile: B1_CDRIVE_PREFLIGHT_PRODUCER_PLAN_REQUEST_PROFILE.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_PREFLIGHT_PRODUCER_SOURCE_SNAPSHOT_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_PREFLIGHT_PRODUCER_SIGNATURE_UUID.to_owned(),
        commission_admission_receipt_machine_form: COMMISSION_ADMISSION_RECEIPT.to_owned(),
        preparation_request_machine_form: json(&preparation),
        preparation_filesystem_machine_form: json(&filesystem(&preparation)),
        preparation_git_machine_form: json(&git_observation(&preparation)),
        preparation_outcome_machine_form: json(&outcome()),
        environment: environment(&preparation),
        request_sha256: empty_digest(),
    };
    request.request_sha256 = b1_cdrive_preflight_producer_plan_request_digest(&request).unwrap();
    request
}

#[test]
fn exact_producer_plan_is_closed_deterministic_and_physically_gated() {
    let request = plan_request();
    let first = compile_b1_cdrive_preflight_producer_plan(&request).unwrap();
    let second = compile_b1_cdrive_preflight_producer_plan(&request).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.children.len(), 4);
    assert_eq!(first.outbound_frames.len(), 6);
    assert_eq!(first.expected_total_transcript_frame_count, 12);
    assert_eq!(first.evidence_artifact_names.len(), 9);
    assert!(!first.physical_execution_authorized);
    assert_eq!(first.physical_run_count, 0);
    assert_eq!(first.provider_trial_count, 0);
    assert_eq!(first.network_contact_count, 0);
    assert_eq!(first.next_required_authorities.len(), 5);
    assert!(first.children.iter().all(|child| {
        child.executable == B1_CDRIVE_PREFLIGHT_PRODUCER_SELECTED_EXECUTABLE
            && child.environment_clear_first
            && child.terminate_on_timeout
            && child.wait_after_terminate
            && child.require_descendant_free
            && child.require_late_output_free
    }));
    assert_eq!(
        first.children[3].kind,
        B1CDrivePreflightProducerChildKind::AppServer
    );
    assert!(first.children[3].stdin_jsonl);
    assert!(first.filesystem_override.contains("':root'='deny'"));
    assert!(first.filesystem_override.contains("':minimal'='read'"));
    assert!(first.filesystem_override.contains("denied.txt'='deny'"));
    let request_machine =
        to_b1_cdrive_preflight_producer_plan_request_machine_form(&request).unwrap();
    assert_eq!(
        from_b1_cdrive_preflight_producer_plan_request_machine_form(&request_machine).unwrap(),
        request
    );
    let plan_machine = to_b1_cdrive_preflight_producer_plan_machine_form(&request, &first).unwrap();
    assert_eq!(
        from_b1_cdrive_preflight_producer_plan_machine_form(&request, &plan_machine).unwrap(),
        first
    );
}

#[test]
fn commission_laundering_and_nonprepared_outcome_refuse() {
    let mut commission = plan_request();
    commission.commission_admission_receipt_machine_form = commission
        .commission_admission_receipt_machine_form
        .replacen(
            "\"commission_issued\":false",
            "\"commission_issued\":true",
            1,
        );
    commission.request_sha256 =
        b1_cdrive_preflight_producer_plan_request_digest(&commission).unwrap();
    assert_eq!(
        compile_b1_cdrive_preflight_producer_plan(&commission)
            .unwrap_err()
            .code,
        B1CDrivePreflightProducerPlanFaultCode::Commission
    );

    let mut not_prepared = plan_request();
    let mut account = outcome();
    account.disposition = PreparationOutcomeDisposition::NotRun;
    not_prepared.preparation_outcome_machine_form = json(&account);
    not_prepared.request_sha256 =
        b1_cdrive_preflight_producer_plan_request_digest(&not_prepared).unwrap();
    assert_eq!(
        compile_b1_cdrive_preflight_producer_plan(&not_prepared)
            .unwrap_err()
            .code,
        B1CDrivePreflightProducerPlanFaultCode::Preparation
    );
}

#[test]
fn preparation_environment_and_path_drift_refuse() {
    let mut canary = plan_request();
    let mut observation: PreparationFilesystemObservation =
        serde_json::from_str(&canary.preparation_filesystem_machine_form).unwrap();
    observation.write_canary_present = true;
    canary.preparation_filesystem_machine_form = json(&observation);
    canary.request_sha256 = b1_cdrive_preflight_producer_plan_request_digest(&canary).unwrap();
    assert_eq!(
        compile_b1_cdrive_preflight_producer_plan(&canary)
            .unwrap_err()
            .code,
        B1CDrivePreflightProducerPlanFaultCode::Preparation
    );

    let mut reordered = plan_request();
    reordered.environment.swap(0, 1);
    reordered.request_sha256 =
        b1_cdrive_preflight_producer_plan_request_digest(&reordered).unwrap();
    assert_eq!(
        compile_b1_cdrive_preflight_producer_plan(&reordered)
            .unwrap_err()
            .code,
        B1CDrivePreflightProducerPlanFaultCode::Environment
    );

    let mut d_drive = plan_request();
    d_drive.environment[1].value = "C:\\Windows;D:\\Tools".to_owned();
    d_drive.request_sha256 = b1_cdrive_preflight_producer_plan_request_digest(&d_drive).unwrap();
    assert_eq!(
        compile_b1_cdrive_preflight_producer_plan(&d_drive)
            .unwrap_err()
            .code,
        B1CDrivePreflightProducerPlanFaultCode::Environment
    );
}

#[test]
fn strict_machine_forms_and_plan_authority_tamper_refuse() {
    let request = plan_request();
    let machine = to_b1_cdrive_preflight_producer_plan_request_machine_form(&request).unwrap();
    let duplicate = machine.replacen("{", "{\"profile\":\"duplicate\",", 1);
    assert_eq!(
        from_b1_cdrive_preflight_producer_plan_request_machine_form(&duplicate)
            .unwrap_err()
            .code,
        B1CDrivePreflightProducerPlanFaultCode::MachineForm
    );
    let unknown = machine.replacen("{", "{\"unknown\":true,", 1);
    assert_eq!(
        from_b1_cdrive_preflight_producer_plan_request_machine_form(&unknown)
            .unwrap_err()
            .code,
        B1CDrivePreflightProducerPlanFaultCode::MachineForm
    );
    assert_eq!(
        from_b1_cdrive_preflight_producer_plan_request_machine_form(
            &"x".repeat(2 * 1024 * 1024 + 1)
        )
        .unwrap_err()
        .code,
        B1CDrivePreflightProducerPlanFaultCode::Bound
    );

    let mut plan = compile_b1_cdrive_preflight_producer_plan(&request).unwrap();
    plan.physical_execution_authorized = true;
    assert_eq!(
        validate_b1_cdrive_preflight_producer_plan(&request, &plan)
            .unwrap_err()
            .code,
        B1CDrivePreflightProducerPlanFaultCode::Plan
    );
}

#[test]
fn static_plan_surface_has_no_process_or_filesystem_effect_route() {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/self_work_update_broker_b1_cdrive_preflight_producer_plan.rs"
    ));
    for forbidden in [
        "std::process",
        "Command::",
        "std::fs",
        "OpenOptions",
        "create_dir",
        "remove_dir",
        "remove_file",
        "unsafe {",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden effect surface: {forbidden}"
        );
    }
}

#[test]
#[ignore = "writes only the explicitly supplied owned evidence root"]
fn write_owned_provider_free_producer_plan_evidence() {
    let root = env::var("CANTOR_B1_PREFLIGHT_PRODUCER_PLAN_EVIDENCE_ROOT")
        .expect("explicit evidence root is required");
    let root = Path::new(&root);
    if root.exists() {
        assert!(root.is_dir());
        assert_eq!(fs::read_dir(root).unwrap().count(), 0);
    } else {
        fs::create_dir_all(root).unwrap();
    }
    let request = plan_request();
    let plan = compile_b1_cdrive_preflight_producer_plan(&request).unwrap();
    let request_bytes = to_b1_cdrive_preflight_producer_plan_request_machine_form(&request)
        .unwrap()
        .into_bytes();
    let plan_bytes = to_b1_cdrive_preflight_producer_plan_machine_form(&request, &plan)
        .unwrap()
        .into_bytes();
    let verification_bytes = serde_json::to_vec(&json_value!({
        "profile": "cantor-self-work-update-broker-b1-cdrive-preflight-producer-plan-verification/0.2",
        "status": plan.status,
        "authority": plan.authority,
        "synthetic_prepared_input_fixture": true,
        "prepared_input_is_live_authority": false,
        "child_count": plan.children.len(),
        "outbound_frame_count": plan.outbound_frames.len(),
        "expected_total_transcript_frame_count": plan.expected_total_transcript_frame_count,
        "environment_entry_count": plan.environment.len(),
        "denied_environment_count": plan.denied_environment.len(),
        "evidence_artifact_name_count": plan.evidence_artifact_names.len(),
        "next_required_authority_count": plan.next_required_authorities.len(),
        "physical_execution_authorized": plan.physical_execution_authorized,
        "physical_run_count": plan.physical_run_count,
        "live_preparation_run_count": 0,
        "app_server_run_count": 0,
        "provider_trial_count": plan.provider_trial_count,
        "model_turn_count": plan.model_turn_count,
        "mcp_call_count": plan.mcp_call_count,
        "network_contact_count": plan.network_contact_count,
        "d_drive_contact_count": plan.d_drive_contact_count,
        "cleanup_count": plan.cleanup_count
    }))
    .unwrap();
    let artifacts = [
        ("plan.json", plan_bytes),
        ("request.json", request_bytes),
        ("verification.json", verification_bytes),
    ];
    for (name, bytes) in &artifacts {
        fs::write(root.join(name), bytes).unwrap();
    }
    let manifest = json_value!({
        "profile": "cantor-self-work-update-broker-b1-cdrive-preflight-producer-plan-evidence/0.2",
        "source_snapshot_uuid": B1_CDRIVE_PREFLIGHT_PRODUCER_SOURCE_SNAPSHOT_UUID,
        "signature_uuid": B1_CDRIVE_PREFLIGHT_PRODUCER_SIGNATURE_UUID,
        "artifacts": artifacts.iter().map(|(name, bytes)| json_value!({
            "path": name,
            "bytes": bytes.len(),
            "sha256": sha256_upper(bytes)
        })).collect::<Vec<_>>(),
        "non_authority_statement": "Synthetic provider-free producer-plan evidence only; no prepared worktree, App Server, provider, model, MCP, network, D-drive, cleanup, or physical authority."
    });
    fs::write(
        root.join("evidence_manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
}

fn json(value: &impl Serialize) -> String {
    serde_json::to_string(value).unwrap()
}

fn sha256_upper(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}
