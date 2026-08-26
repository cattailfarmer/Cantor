use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use cantor_ecosystem::{
    B1_CDRIVE_WORKTREE_PREPARATION_BRANCH, B1_CDRIVE_WORKTREE_PREPARATION_CARRIER,
    B1_CDRIVE_WORKTREE_PREPARATION_EVIDENCE_PROFILE,
    B1_CDRIVE_WORKTREE_PREPARATION_FILESYSTEM_PROFILE, B1_CDRIVE_WORKTREE_PREPARATION_GIT,
    B1_CDRIVE_WORKTREE_PREPARATION_GIT_OBSERVATION_PROFILE,
    B1_CDRIVE_WORKTREE_PREPARATION_GIT_SHA256, B1_CDRIVE_WORKTREE_PREPARATION_GIT_VERSION,
    B1_CDRIVE_WORKTREE_PREPARATION_INVALIDATION_UUID,
    B1_CDRIVE_WORKTREE_PREPARATION_LOCAL_GATE_PROFILE,
    B1_CDRIVE_WORKTREE_PREPARATION_OUTCOME_PROFILE, B1_CDRIVE_WORKTREE_PREPARATION_PROOF_PROFILE,
    B1_CDRIVE_WORKTREE_PREPARATION_REQUEST_PROFILE, B1_CDRIVE_WORKTREE_PREPARATION_SCRATCH,
    B1_CDRIVE_WORKTREE_PREPARATION_SIGNATURE_UUID,
    B1_CDRIVE_WORKTREE_PREPARATION_SOURCE_SNAPSHOT_UUID, CDriveWorktreePreparationFault,
    CDriveWorktreePreparationFaultCode, CDriveWorktreePreparationRequest,
    PreparationArtifactIdentity, PreparationChildSpec, PreparationEvidenceManifest,
    PreparationFailureDisposition, PreparationFilesystemObservation, PreparationGitObservation,
    PreparationLocalGateObservation, PreparationOutcomeAccount, PreparationOutcomeDisposition,
    PreparationProcessObservation, ProviderOnlyPreparationBroker, SupervisingPublicationProof,
    classify_cdrive_worktree_preparation_failure, compile_cdrive_worktree_preparation_plan,
    from_cdrive_worktree_preparation_local_gate_machine_form,
    from_cdrive_worktree_preparation_outcome_machine_form,
    from_cdrive_worktree_preparation_simulation_receipt_machine_form,
    simulate_cdrive_worktree_preparation_plan, to_cdrive_worktree_preparation_outcome_machine_form,
    to_cdrive_worktree_preparation_plan_machine_form,
    to_cdrive_worktree_preparation_simulation_receipt_machine_form,
    validate_cdrive_worktree_preparation_local_gate, validate_cdrive_worktree_preparation_outcome,
    validate_cdrive_worktree_prepared_observations, verify_cdrive_worktree_preparation_evidence,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

struct FakeBroker;

impl ProviderOnlyPreparationBroker for FakeBroker {
    fn simulate(
        &mut self,
        child: &PreparationChildSpec,
    ) -> Result<PreparationProcessObservation, CDriveWorktreePreparationFault> {
        Ok(PreparationProcessObservation {
            sequence: child.sequence,
            operation: child.operation.clone(),
            arguments: child.arguments.clone(),
            exit_code: child.allowed_exit_codes[0],
            stdout: String::new(),
            stderr: String::new(),
            timed_out: false,
            reaped: true,
            descendant_count_after: 0,
            late_output_bytes: 0,
            network_contact_count: 0,
            physical_effect_performed: false,
        })
    }
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "cantor_b1_cdrive_worktree_preparation_provider_only_{}_{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn build(&self) {
        let proof = publication_proof();
        let proof_bytes = json_bytes(&proof);
        let request = request(&proof_bytes);
        let (plan, observations, projection, consequences, receipt) =
            simulate_cdrive_worktree_preparation_plan(&request, &proof, &mut FakeBroker).unwrap();
        let artifacts = vec![
            ("consequences.json", json_bytes(&consequences)),
            ("plan.json", json_bytes(&plan)),
            ("process_observations.json", json_bytes(&observations)),
            ("projection.json", json_bytes(&projection)),
            ("publication_proof.json", proof_bytes),
            ("request.json", json_bytes(&request)),
            ("simulation_receipt.json", json_bytes(&receipt)),
        ];
        for (name, bytes) in &artifacts {
            fs::write(self.root.join(name), bytes).unwrap();
        }
        write_manifest(&self.root, &artifacts);
    }

    fn value(&self, name: &str) -> Value {
        serde_json::from_slice(&fs::read(self.root.join(name)).unwrap()).unwrap()
    }

    fn write_value(&self, name: &str, value: &Value) {
        fs::write(self.root.join(name), json_bytes(value)).unwrap();
        refresh_manifest(&self.root);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn publication_proof() -> SupervisingPublicationProof {
    let implementation = "1".repeat(40);
    let bookend = "2".repeat(40);
    SupervisingPublicationProof {
        profile: B1_CDRIVE_WORKTREE_PREPARATION_PROOF_PROFILE.to_owned(),
        implementation_commit: implementation,
        bookend_commit: bookend.clone(),
        branch_ref: "refs/heads/codex/self-hosted-corpus".to_owned(),
        local_head: bookend.clone(),
        local_tracking: bookend.clone(),
        origin_remote_tracking: bookend.clone(),
        ls_remote: bookend,
        implementation_parent_of_bookend: true,
        carrier_ancestor_of_implementation: true,
        focused_test_count: 10,
        focused_failure_count: 0,
        evidence_manifest_count: 54,
        evidence_reference_count: 1_944,
        evidence_stale_count: 0,
        physical_preparation_run_count: 0,
    }
}

fn request(proof_bytes: &[u8]) -> CDriveWorktreePreparationRequest {
    let scratch = B1_CDRIVE_WORKTREE_PREPARATION_SCRATCH;
    CDriveWorktreePreparationRequest {
        profile: B1_CDRIVE_WORKTREE_PREPARATION_REQUEST_PROFILE.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_WORKTREE_PREPARATION_SOURCE_SNAPSHOT_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_WORKTREE_PREPARATION_SIGNATURE_UUID.to_owned(),
        predecessor_invalidation_uuid: B1_CDRIVE_WORKTREE_PREPARATION_INVALIDATION_UUID.to_owned(),
        carrier_commit: B1_CDRIVE_WORKTREE_PREPARATION_CARRIER.to_owned(),
        implementation_commit: "1".repeat(40),
        bookend_commit: "2".repeat(40),
        publication_proof_artifact: PreparationArtifactIdentity {
            path: "publication_proof.json".to_owned(),
            bytes: proof_bytes.len() as u64,
            sha256: sha256_upper(proof_bytes),
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

fn local_gate(request: &CDriveWorktreePreparationRequest) -> PreparationLocalGateObservation {
    PreparationLocalGateObservation {
        profile: B1_CDRIVE_WORKTREE_PREPARATION_LOCAL_GATE_PROFILE.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_WORKTREE_PREPARATION_SOURCE_SNAPSHOT_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_WORKTREE_PREPARATION_SIGNATURE_UUID.to_owned(),
        recovery_owner: request.recovery_owner.clone(),
        principal_workspace: request.principal_workspace.clone(),
        repository_common_dir: request.repository_common_dir.clone(),
        worktree_parent: "C:\\Project\\CantorWorktrees".to_owned(),
        volume_guid: "\\\\?\\Volume{3ca93d52-bee3-4c52-9c03-263040cc104d}\\".to_owned(),
        volume_filesystem: "NTFS".to_owned(),
        parent_is_canonical_directory: true,
        parent_is_reparse_point: false,
        scratch_root_absent: true,
        branch_ref_absent: true,
        carrier_commit: request.carrier_commit.clone(),
        implementation_commit: request.implementation_commit.clone(),
        bookend_commit: request.bookend_commit.clone(),
        local_head: request.bookend_commit.clone(),
        local_tracking: request.bookend_commit.clone(),
        origin_remote_tracking: request.bookend_commit.clone(),
        carrier_ancestor_of_implementation: true,
        implementation_immediate_parent_of_bookend: true,
        git_executable: request.git_executable.clone(),
        git_executable_bytes: request.git_executable_bytes,
        git_executable_sha256: request.git_executable_sha256.clone(),
        git_version: request.git_version.clone(),
        pre_effect_free_bytes: request.minimum_pre_effect_free_bytes,
        process_count: 5,
        network_contact_count: 0,
        physical_contact: false,
    }
}

fn outcome(disposition: PreparationOutcomeDisposition) -> PreparationOutcomeAccount {
    let mut account = PreparationOutcomeAccount {
        profile: B1_CDRIVE_WORKTREE_PREPARATION_OUTCOME_PROFILE.to_owned(),
        disposition,
        authority: "linked_worktree_preparation_observation_only".to_owned(),
        pre_effect_gate_passed: false,
        post_effect_verification_passed: false,
        physical_contact: false,
        may_have_mutated: false,
        retained_state: false,
        reserved_root_contact: false,
        reserved_ref_contact: false,
        actual_directory_creations: 0,
        actual_branch_ref_mutations: 0,
        actual_worktree_metadata_mutations: 0,
        actual_checkout_file_count: 0,
        final_free_bytes: None,
        success_receipt_emitted: false,
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
    };
    match disposition {
        PreparationOutcomeDisposition::NotRun => {}
        PreparationOutcomeDisposition::Quarantined => {
            account.pre_effect_gate_passed = true;
            account.physical_contact = true;
            account.may_have_mutated = true;
            account.retained_state = true;
            account.reserved_root_contact = true;
        }
        PreparationOutcomeDisposition::PreparedForPhase3aAcquisition => {
            account.pre_effect_gate_passed = true;
            account.post_effect_verification_passed = true;
            account.physical_contact = true;
            account.may_have_mutated = true;
            account.retained_state = true;
            account.reserved_root_contact = true;
            account.reserved_ref_contact = true;
            account.actual_directory_creations = 4;
            account.actual_branch_ref_mutations = 1;
            account.actual_worktree_metadata_mutations = 1;
            account.actual_checkout_file_count = 4_416;
            account.final_free_bytes = Some(12_884_901_888);
            account.success_receipt_emitted = true;
        }
    }
    account
}

fn filesystem(request: &CDriveWorktreePreparationRequest) -> PreparationFilesystemObservation {
    PreparationFilesystemObservation {
        profile: B1_CDRIVE_WORKTREE_PREPARATION_FILESYSTEM_PROFILE.to_owned(),
        scratch_root: request.scratch_root.clone(),
        candidate_root: request.candidate_root.clone(),
        evidence_root: request.evidence_root.clone(),
        temp_root: request.temp_root.clone(),
        codex_home: request.codex_home.clone(),
        scratch_present: true,
        candidate_present: true,
        evidence_present: true,
        temp_present: true,
        codex_home_present: true,
        roles_pairwise_disjoint: true,
        roles_strict_scratch_descendants: true,
        principal_strictly_nonoverlapping: true,
        same_selected_volume: true,
        directory_creation_count: 4,
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

fn json_bytes(value: &impl Serialize) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn sha256_upper(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

fn write_manifest(root: &Path, artifacts: &[(&str, Vec<u8>)]) {
    let manifest = PreparationEvidenceManifest {
        profile: B1_CDRIVE_WORKTREE_PREPARATION_EVIDENCE_PROFILE.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_WORKTREE_PREPARATION_SOURCE_SNAPSHOT_UUID.to_owned(),
        artifacts: artifacts
            .iter()
            .map(|(name, bytes)| PreparationArtifactIdentity {
                path: (*name).to_owned(),
                bytes: bytes.len() as u64,
                sha256: sha256_upper(bytes),
            })
            .collect(),
    };
    fs::write(root.join("evidence_manifest.json"), json_bytes(&manifest)).unwrap();
}

fn refresh_manifest(root: &Path) {
    let names = [
        "consequences.json",
        "plan.json",
        "process_observations.json",
        "projection.json",
        "publication_proof.json",
        "request.json",
        "simulation_receipt.json",
    ];
    let artifacts: Vec<(&str, Vec<u8>)> = names
        .iter()
        .map(|name| (*name, fs::read(root.join(name)).unwrap()))
        .collect();
    write_manifest(root, &artifacts);
}

fn assert_fault(root: &Path, expected: CDriveWorktreePreparationFaultCode) {
    let error = verify_cdrive_worktree_preparation_evidence(root).unwrap_err();
    assert_eq!(error.code, expected);
}

#[test]
fn complete_provider_only_evidence_verifies_twice_and_round_trips() {
    let fixture = Fixture::new();
    fixture.build();
    let first = verify_cdrive_worktree_preparation_evidence(&fixture.root).unwrap();
    let second = verify_cdrive_worktree_preparation_evidence(&fixture.root).unwrap();
    assert_eq!(first, second);
    let machine = to_cdrive_worktree_preparation_simulation_receipt_machine_form(&first).unwrap();
    assert_eq!(
        from_cdrive_worktree_preparation_simulation_receipt_machine_form(&machine).unwrap(),
        first
    );
    assert!(!first.physical_preparation_authorized);
    assert!(!first.physical_contact);
    assert_eq!(first.network_command_count, 0);
}

#[test]
fn exact_plan_has_twelve_local_children_and_one_modeled_effect() {
    let proof = publication_proof();
    let proof_bytes = json_bytes(&proof);
    let plan = compile_cdrive_worktree_preparation_plan(&request(&proof_bytes), &proof).unwrap();
    assert_eq!(plan.children.len(), 12);
    assert_eq!(
        plan.children.iter().filter(|child| child.mutating).count(),
        1
    );
    assert!(plan.children.iter().all(|child| !child.network));
    let expected_environment_names = [
        "GIT_ASKPASS",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_TERMINAL_PROMPT",
        "HOME",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "WINDIR",
    ];
    for child in &plan.children {
        assert_eq!(child.executable, B1_CDRIVE_WORKTREE_PREPARATION_GIT);
        assert!(child.environment_clear_first);
        assert_eq!(
            child
                .environment
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            expected_environment_names
        );
        assert!(child.stdin_closed);
        assert_eq!(child.maximum_stdout_bytes, 1_048_576);
        assert_eq!(child.maximum_stderr_bytes, 1_048_576);
        assert_eq!(child.maximum_total_bytes, 4_194_304);
        assert_eq!(child.deadline_millis, 30_000);
        assert_eq!(child.deadline_scope, "shared_plan_total");
        assert!(child.rehash_executable_before_start);
        assert!(child.terminate_on_timeout);
        assert!(child.wait_after_terminate);
        assert!(child.require_descendant_free);
        assert!(child.require_late_output_free);
    }
    assert_eq!(plan.maximum_processes, 12);
    assert_eq!(plan.maximum_stream_bytes, 1_048_576);
    assert_eq!(plan.maximum_total_process_bytes, 4_194_304);
    assert_eq!(plan.total_deadline_millis, 30_000);
    assert_eq!(plan.children[5].operation, "worktree_add");
    assert!(
        plan.children
            .iter()
            .flat_map(|child| &child.arguments)
            .all(|argument| !argument.eq_ignore_ascii_case("ls-remote"))
    );
    assert!(!plan.physical_execution_authorized);
}

#[test]
fn planner_and_verifier_clis_emit_exact_machine_forms() {
    let fixture = Fixture::new();
    fixture.build();
    let request_bytes = fs::read(fixture.root.join("request.json")).unwrap();
    let proof_bytes = fs::read(fixture.root.join("publication_proof.json")).unwrap();
    let request_value: CDriveWorktreePreparationRequest =
        serde_json::from_slice(&request_bytes).unwrap();
    let proof_value: SupervisingPublicationProof = serde_json::from_slice(&proof_bytes).unwrap();
    let expected_plan = to_cdrive_worktree_preparation_plan_machine_form(
        &compile_cdrive_worktree_preparation_plan(&request_value, &proof_value).unwrap(),
    )
    .unwrap();
    let planner = Command::new(env!(
        "CARGO_BIN_EXE_cantor-self-work-update-broker-b1-cdrive-worktree-prepare"
    ))
    .arg("--plan-only")
    .arg(fixture.root.join("request.json"))
    .arg(fixture.root.join("publication_proof.json"))
    .output()
    .unwrap();
    assert!(planner.status.success());
    assert_eq!(
        String::from_utf8(planner.stdout).unwrap(),
        format!("{expected_plan}\n")
    );
    let receipt = verify_cdrive_worktree_preparation_evidence(&fixture.root).unwrap();
    let expected_receipt =
        to_cdrive_worktree_preparation_simulation_receipt_machine_form(&receipt).unwrap();
    let verifier = Command::new(env!(
        "CARGO_BIN_EXE_cantor-self-work-update-broker-b1-cdrive-worktree-preparation-evidence-verify"
    ))
    .arg(&fixture.root)
    .output()
    .unwrap();
    assert!(verifier.status.success());
    assert_eq!(
        String::from_utf8(verifier.stdout).unwrap(),
        format!("{expected_receipt}\n")
    );
    let physical_refusal = Command::new(env!(
        "CARGO_BIN_EXE_cantor-self-work-update-broker-b1-cdrive-worktree-prepare"
    ))
    .arg("--execute")
    .arg(fixture.root.join("request.json"))
    .arg(fixture.root.join("publication_proof.json"))
    .output()
    .unwrap();
    assert!(!physical_refusal.status.success());
    assert!(!Path::new(B1_CDRIVE_WORKTREE_PREPARATION_SCRATCH).exists());
    let reformatted_proof_path = fixture.root.join("reformatted-publication-proof.json");
    fs::write(
        &reformatted_proof_path,
        serde_json::to_vec_pretty(&proof_value).unwrap(),
    )
    .unwrap();
    let raw_identity_refusal = Command::new(env!(
        "CARGO_BIN_EXE_cantor-self-work-update-broker-b1-cdrive-worktree-prepare"
    ))
    .arg("--plan-only")
    .arg(fixture.root.join("request.json"))
    .arg(&reformatted_proof_path)
    .output()
    .unwrap();
    assert!(!raw_identity_refusal.status.success());
}

#[test]
fn physical_authority_and_publication_proof_mutations_refuse() {
    let proof = publication_proof();
    let proof_bytes = json_bytes(&proof);
    let mut physical_request = request(&proof_bytes);
    physical_request.physical_preparation_authorized = true;
    physical_request.physical_commission_uuid =
        Some("4e763d15-4abf-4a62-9f20-0d9f30c86f11".to_owned());
    let error = compile_cdrive_worktree_preparation_plan(&physical_request, &proof).unwrap_err();
    assert_eq!(error.code, CDriveWorktreePreparationFaultCode::Request);
    let mut proof = proof;
    proof.ls_remote = "3".repeat(40);
    let error = compile_cdrive_worktree_preparation_plan(&request(&json_bytes(&proof)), &proof)
        .unwrap_err();
    assert_eq!(
        error.code,
        CDriveWorktreePreparationFaultCode::PublicationProof
    );
    let proof = publication_proof();
    let mut long_object_id = request(&json_bytes(&proof));
    long_object_id.implementation_commit = "1".repeat(64);
    assert_eq!(
        compile_cdrive_worktree_preparation_plan(&long_object_id, &proof)
            .unwrap_err()
            .code,
        CDriveWorktreePreparationFaultCode::Request
    );
}

#[test]
fn duplicate_request_and_plan_reorder_refuse_after_rehash() {
    let fixture = Fixture::new();
    fixture.build();
    let raw = String::from_utf8(fs::read(fixture.root.join("request.json")).unwrap()).unwrap();
    let duplicate = raw.replacen(
        "{\"profile\":",
        "{\"profile\":\"duplicate\",\"profile\":",
        1,
    );
    fs::write(fixture.root.join("request.json"), duplicate).unwrap();
    refresh_manifest(&fixture.root);
    assert_fault(
        &fixture.root,
        CDriveWorktreePreparationFaultCode::MachineForm,
    );
    fixture.build();
    let mut plan = fixture.value("plan.json");
    plan["children"].as_array_mut().unwrap().swap(0, 1);
    fixture.write_value("plan.json", &plan);
    assert_fault(&fixture.root, CDriveWorktreePreparationFaultCode::Plan);
    fixture.build();
    let mut plan = fixture.value("plan.json");
    plan["children"][0]["environment"][0]["value"] = Value::String("ambient".to_owned());
    fixture.write_value("plan.json", &plan);
    assert_fault(&fixture.root, CDriveWorktreePreparationFaultCode::Plan);
}

#[test]
fn process_projection_and_consequence_mutations_refuse() {
    let fixture = Fixture::new();
    fixture.build();
    let mut processes = fixture.value("process_observations.json");
    processes[0]["sequence"] = Value::from(2);
    fixture.write_value("process_observations.json", &processes);
    assert_fault(&fixture.root, CDriveWorktreePreparationFaultCode::Process);
    fixture.build();
    let mut projection = fixture.value("projection.json");
    projection["reserved_root_contact"] = Value::Bool(true);
    fixture.write_value("projection.json", &projection);
    assert_fault(
        &fixture.root,
        CDriveWorktreePreparationFaultCode::Projection,
    );
    fixture.build();
    let mut consequences = fixture.value("consequences.json");
    consequences["network_contact_count"] = Value::from(1);
    fixture.write_value("consequences.json", &consequences);
    assert_fault(
        &fixture.root,
        CDriveWorktreePreparationFaultCode::Consequence,
    );
    fixture.build();
    let mut processes = fixture.value("process_observations.json");
    processes[0]["arguments"][0] = Value::String("--help".to_owned());
    fixture.write_value("process_observations.json", &processes);
    assert_fault(&fixture.root, CDriveWorktreePreparationFaultCode::Process);
    fixture.build();
    let mut processes = fixture.value("process_observations.json");
    processes[0]["reaped"] = Value::Bool(false);
    fixture.write_value("process_observations.json", &processes);
    assert_fault(&fixture.root, CDriveWorktreePreparationFaultCode::Process);
    fixture.build();
    let mut processes = fixture.value("process_observations.json");
    for process in processes.as_array_mut().unwrap().iter_mut().take(5) {
        process["stdout"] = Value::String("x".repeat(900_000));
    }
    fixture.write_value("process_observations.json", &processes);
    assert_fault(&fixture.root, CDriveWorktreePreparationFaultCode::Bound);
}

#[test]
fn local_gate_strict_form_and_every_current_identity_refuse_drift() {
    let proof = publication_proof();
    let request = request(&json_bytes(&proof));
    let gate = local_gate(&request);
    validate_cdrive_worktree_preparation_local_gate(&request, &proof, &gate).unwrap();
    let machine = serde_json::to_string(&gate).unwrap();
    assert_eq!(
        from_cdrive_worktree_preparation_local_gate_machine_form(&machine).unwrap(),
        gate
    );
    let mutations: [fn(&mut PreparationLocalGateObservation); 5] = [
        |gate: &mut PreparationLocalGateObservation| gate.scratch_root_absent = false,
        |gate: &mut PreparationLocalGateObservation| gate.branch_ref_absent = false,
        |gate: &mut PreparationLocalGateObservation| gate.local_head = "3".repeat(40),
        |gate: &mut PreparationLocalGateObservation| gate.parent_is_reparse_point = true,
        |gate: &mut PreparationLocalGateObservation| gate.network_contact_count = 1,
    ];
    for mutate in mutations {
        let mut changed = gate.clone();
        mutate(&mut changed);
        assert_eq!(
            validate_cdrive_worktree_preparation_local_gate(&request, &proof, &changed)
                .unwrap_err()
                .code,
            CDriveWorktreePreparationFaultCode::Authority
        );
    }
}

#[test]
fn not_run_quarantine_and_prepared_accounts_are_disjoint_and_strict() {
    let proof = publication_proof();
    let request = request(&json_bytes(&proof));
    for disposition in [
        PreparationOutcomeDisposition::NotRun,
        PreparationOutcomeDisposition::Quarantined,
        PreparationOutcomeDisposition::PreparedForPhase3aAcquisition,
    ] {
        let account = outcome(disposition);
        validate_cdrive_worktree_preparation_outcome(&request, &account).unwrap();
        let machine =
            to_cdrive_worktree_preparation_outcome_machine_form(&request, &account).unwrap();
        assert_eq!(
            from_cdrive_worktree_preparation_outcome_machine_form(&request, &machine).unwrap(),
            account
        );
    }
    let prepared = outcome(PreparationOutcomeDisposition::PreparedForPhase3aAcquisition);
    validate_cdrive_worktree_prepared_observations(
        &request,
        &filesystem(&request),
        &git_observation(&request),
        &prepared,
    )
    .unwrap();
    let mut principal_mutation = filesystem(&request);
    principal_mutation.principal_worktree_file_mutation_count = 1;
    assert_eq!(
        validate_cdrive_worktree_prepared_observations(
            &request,
            &principal_mutation,
            &git_observation(&request),
            &prepared,
        )
        .unwrap_err()
        .code,
        CDriveWorktreePreparationFaultCode::Projection
    );
    let mut pushed = git_observation(&request);
    pushed.push_count = 1;
    assert_eq!(
        validate_cdrive_worktree_prepared_observations(
            &request,
            &filesystem(&request),
            &pushed,
            &prepared,
        )
        .unwrap_err()
        .code,
        CDriveWorktreePreparationFaultCode::Projection
    );
    let mut laundered = outcome(PreparationOutcomeDisposition::Quarantined);
    laundered.success_receipt_emitted = true;
    assert_eq!(
        validate_cdrive_worktree_preparation_outcome(&request, &laundered)
            .unwrap_err()
            .code,
        CDriveWorktreePreparationFaultCode::Consequence
    );
    let mut cleaned = prepared.clone();
    cleaned.cleanup_count = 1;
    assert_eq!(
        validate_cdrive_worktree_preparation_outcome(&request, &cleaned)
            .unwrap_err()
            .code,
        CDriveWorktreePreparationFaultCode::Consequence
    );
    let raw = serde_json::to_string(&prepared).unwrap();
    let duplicate = raw.replacen(
        "{\"profile\":",
        "{\"profile\":\"duplicate\",\"profile\":",
        1,
    );
    assert_eq!(
        from_cdrive_worktree_preparation_outcome_machine_form(&request, &duplicate)
            .unwrap_err()
            .code,
        CDriveWorktreePreparationFaultCode::MachineForm
    );
}

#[test]
fn receipt_authority_and_digest_mutations_refuse() {
    let fixture = Fixture::new();
    fixture.build();
    let mut receipt = fixture.value("simulation_receipt.json");
    receipt["physical_contact"] = Value::Bool(true);
    fixture.write_value("simulation_receipt.json", &receipt);
    assert_fault(&fixture.root, CDriveWorktreePreparationFaultCode::Receipt);
    fixture.build();
    let mut receipt = fixture.value("simulation_receipt.json");
    receipt["receipt_sha256"]["value"] = Value::String("0".repeat(64));
    fixture.write_value("simulation_receipt.json", &receipt);
    assert_fault(&fixture.root, CDriveWorktreePreparationFaultCode::Receipt);
}

#[test]
fn failure_classification_preserves_effect_boundary() {
    assert_eq!(
        classify_cdrive_worktree_preparation_failure(false),
        PreparationFailureDisposition::NotRun
    );
    assert_eq!(
        classify_cdrive_worktree_preparation_failure(true),
        PreparationFailureDisposition::Quarantined
    );
}

#[test]
fn provider_only_module_has_no_production_effect_surface() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/self_work_update_broker_b1_cdrive_worktree_preparation.rs"),
    )
    .unwrap();
    for forbidden in [
        "std::process",
        "Command::",
        "TcpStream",
        "UdpSocket",
        "create_dir",
        "remove_dir",
        "remove_file",
        "File::create",
        "OpenOptions",
        "write_all",
        "ls-remote",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }
    assert!(!Path::new(B1_CDRIVE_WORKTREE_PREPARATION_SCRATCH).exists());
}
