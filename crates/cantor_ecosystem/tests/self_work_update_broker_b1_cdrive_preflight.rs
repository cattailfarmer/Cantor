#[path = "self_work_update_handoff.rs"]
mod handoff_fixture;

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use cantor_core::{ContentDigest, sha256_bytes, sha256_digest};
use cantor_ecosystem::workspace_admission::update_broker_protocol::{
    BrokerRoot, CAPABILITY_ACCOUNT_PROFILE, CapabilityAccount, CapabilityKind,
    PROTOCOL_REQUEST_PROFILE, PROTOCOL_RESULT_PROFILE, ProtocolFormationRequest,
    STAGE_PLAN_PROFILE, SYNTHETIC_EVIDENCE_PROFILE, StageDefinition, StageKind, StagePlan,
    SyntheticEvidenceRef, compile_self_work_update_broker_protocol, protocol_request_digest,
    to_protocol_request_machine_form, to_protocol_result_machine_form,
};
use cantor_ecosystem::*;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

const STANDARD_SCHEMA: &str = "experiments/self_work_update_broker_b1_permission_profile_revalidation_p0/artifacts/standard_schema.json";
const EXPERIMENTAL_SCHEMA: &str = "experiments/self_work_update_broker_b1_permission_profile_revalidation_p0/artifacts/experimental_schema.json";

#[derive(Serialize)]
struct ReceiptBodyFixture {
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

fn admission_receipt(request: &CandidateWorkspaceRequest) -> AdmissionReceipt {
    let mut receipt = AdmissionReceipt {
        profile: CANDIDATE_WORKSPACE_ADMISSION_PROFILE.to_owned(),
        request_sha256: sha256_digest(request).unwrap(),
        receipt_sha256: digest('0'),
        observation_sha256: digest('c'),
        candidate_uuid: request.candidate_uuid.clone(),
        correlation_uuid: request.correlation_uuid.clone(),
        admission_nonce: request.admission_nonce.clone(),
        git_executable_sha256: request.git_executable_sha256.clone(),
        git_version: request.git_version.clone(),
        principal_workspace: request.principal_workspace.clone(),
        candidate_workspace: request.candidate_workspace.clone(),
        repository_common_dir: request.expected_repository_common_dir.clone(),
        candidate_git_dir: request
            .expected_repository_common_dir
            .join("worktrees")
            .join("swa05-b1-cdrive-preflight"),
        base_commit: request.expected_base_commit.clone(),
        branch_ref: request.expected_branch_ref.clone(),
        allowed_relative_paths: request.allowed_relative_paths.clone(),
        resource_account: AdmissionResourceAccount {
            process_count: 12,
            received_bytes: 4_096,
            configured_timeout_millis: request.budget.timeout_millis,
        },
        admitted: true,
    };
    let body = ReceiptBodyFixture {
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
    receipt.receipt_sha256 = sha256_digest(&body).unwrap();
    receipt
}

fn digest(symbol: char) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: symbol.to_string().repeat(64),
    }
}

fn workspace_request(scratch: &str) -> CandidateWorkspaceRequest {
    CandidateWorkspaceRequest {
        profile: CANDIDATE_WORKSPACE_ADMISSION_PROFILE.to_owned(),
        candidate_uuid: "2aec5ded-f9d2-4523-8433-d5f53f9b3caf".to_owned(),
        correlation_uuid: "0f9f23b1-7460-4aea-a463-d14e8fef842c".to_owned(),
        admission_nonce: "swa05-b1-cdrive-preflight:001".to_owned(),
        git_executable: PathBuf::from("C:\\Program Files\\Git\\cmd\\git.exe"),
        git_executable_sha256: "a".repeat(64),
        git_version: "git version 2.51.0.windows.1".to_owned(),
        principal_workspace: PathBuf::from("C:\\Project\\Cantor"),
        candidate_workspace: PathBuf::from(format!("{scratch}\\candidate")),
        expected_repository_common_dir: PathBuf::from("C:\\Project\\Cantor\\.git"),
        expected_base_commit: "b".repeat(40),
        expected_branch_ref: "refs/heads/codex/swa05-b1-cdrive-preflight".to_owned(),
        protected_branch_refs: vec!["refs/heads/main".to_owned()],
        allowed_relative_paths: vec![
            "Cargo.toml".to_owned(),
            "crates/cantor_ecosystem/src/lib.rs".to_owned(),
            "docs/old.md".to_owned(),
            "scripts/run.sh".to_owned(),
        ],
        budget: AdmissionBudget {
            maximum_command_bytes: 64 * 1024,
            maximum_total_bytes: 256 * 1024,
            maximum_processes: 12,
            timeout_millis: 5_000,
        },
    }
}

fn handoff_forms(
    scratch: &str,
) -> (
    SelfWorkUpdateHandoffRequest,
    SelfWorkUpdateHandoffProposal,
    Vec<u8>,
    Vec<u8>,
) {
    let mut request = handoff_fixture::handoff_request();
    request.workspace_request = workspace_request(scratch);
    request.prior_admission_receipt = admission_receipt(&request.workspace_request);
    let proposal = compile_self_work_update_handoff(&request).unwrap();
    let request_form = to_self_work_update_handoff_request_machine_form(&request)
        .unwrap()
        .into_bytes();
    let proposal_form = to_self_work_update_handoff_proposal_machine_form(&proposal)
        .unwrap()
        .into_bytes();
    (request, proposal, request_form, proposal_form)
}

fn domain_digest(domain: &[u8], value: &impl Serialize) -> String {
    let bytes = serde_json::to_vec(value).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn all_capabilities() -> Vec<CapabilityKind> {
    use CapabilityKind::*;
    vec![
        ReadObservation,
        EvidenceRootWrite,
        CandidateMutation,
        ProcessLaunch,
        ProcessInterrupt,
        ProcessTerminate,
        SupervisorTest,
        IndependentReview,
        RollbackAttempt,
        Cleanup,
        GitHistory,
        Commit,
        Push,
        Provider,
        SopAuthorship,
        SemanticSignature,
        Activation,
        Persistence,
        Remote,
        Fpga,
        Minecraft,
        PrincipalWorkspaceMutation,
    ]
}

fn stage_plan() -> Vec<StageDefinition> {
    use StageKind::*;
    [
        (
            B0Protocol,
            PROTOCOL_REQUEST_PROFILE,
            PROTOCOL_RESULT_PROFILE,
            false,
        ),
        (
            B1HostPreflight,
            "cantor-self-work-update-broker-b1-preflight-request/0.2",
            "cantor-self-work-update-broker-b1-preflight-record/0.2",
            true,
        ),
        (
            B2BoundedWriter,
            "cantor-self-work-update-broker-b2-writer-request/0.2",
            "cantor-self-work-update-broker-b2-mutation-record/0.2",
            true,
        ),
        (
            B3PostStateEvidence,
            "cantor-self-work-update-broker-b3-observation-request/0.2",
            "cantor-self-work-update-broker-b3-post-state-record/0.2",
            true,
        ),
        (
            B4IndependentReview,
            "cantor-self-work-update-broker-b4-review-request/0.2",
            "cantor-self-work-update-broker-b4-review-record/0.2",
            true,
        ),
        (
            B5RollbackReobservation,
            "cantor-self-work-update-broker-b5-rollback-request/0.2",
            "cantor-self-work-update-broker-b5-rollback-record/0.2",
            true,
        ),
    ]
    .into_iter()
    .enumerate()
    .map(
        |(index, (kind, input_profile, output_profile, physical_contact_expected))| {
            StageDefinition {
                ordinal: (index + 1) as u8,
                kind,
                input_profile: input_profile.to_owned(),
                output_profile: output_profile.to_owned(),
                physical_contact_expected,
                activation_required: true,
            }
        },
    )
    .collect()
}

fn protocol_forms(
    handoff: &SelfWorkUpdateHandoffRequest,
    proposal: &SelfWorkUpdateHandoffProposal,
) -> (Vec<u8>, Vec<u8>) {
    let handoff_digest = self_work_update_handoff_request_digest(handoff).unwrap();
    let proposal_digest = self_work_update_handoff_proposal_digest(proposal).unwrap();
    let mut root = BrokerRoot {
        broker_uuid: "11111111-1111-4111-8111-111111111111".to_owned(),
        correlation_uuid: "22222222-2222-4222-8222-222222222222".to_owned(),
        corrective_source_snapshot_uuid: "82356753-0666-41cd-9b04-cd488b4bb727".to_owned(),
        formation_canonical_uuid: "88753bbf-33a0-450a-a218-d58fcf601d7d".to_owned(),
        formation_signature_uuid: "e588644d-4420-44f6-a622-85430626bd09".to_owned(),
        protocol_canonical_uuid: "459f30e4-6c0d-4731-90b9-bfa6bdca1b61".to_owned(),
        published_predecessor_commit: "e5bee5e2e60dc2df756da8e26385fce048dc29a1".to_owned(),
        lifecycle_request_sha256: "1".repeat(64),
        checkpoint_sha256: "2".repeat(64),
        step_uuid: "33333333-3333-4333-8333-333333333333".to_owned(),
        attempt_uuid: "44444444-4444-4444-8444-444444444444".to_owned(),
        objective_sha256: "3".repeat(64),
        handoff_request_sha256: handoff_digest.value,
        handoff_proposal_sha256: proposal_digest.value,
        workspace_correlation_uuid: handoff.workspace_request.correlation_uuid.clone(),
        base_commit: handoff.workspace_request.expected_base_commit.clone(),
        branch_ref: handoff.workspace_request.expected_branch_ref.clone(),
        git_executable_sha256: handoff.workspace_request.git_executable_sha256.clone(),
        allowed_relative_paths: handoff.workspace_request.allowed_relative_paths.clone(),
        change_set_sha256: "7".repeat(64),
        broker_root_sha256: String::new(),
    };
    root.broker_root_sha256 = domain_digest(b"cantor:self-work-update-broker:root:0.2", &root);
    let mut stages = StagePlan {
        profile: STAGE_PLAN_PROFILE.to_owned(),
        stages: stage_plan(),
        stage_plan_sha256: String::new(),
    };
    stages.stage_plan_sha256 =
        domain_digest(b"cantor:self-work-update-broker:stage-plan:0.2", &stages);
    let mut capabilities = CapabilityAccount {
        profile: CAPABILITY_ACCOUNT_PROFILE.to_owned(),
        granted: vec![],
        explicitly_not_granted: all_capabilities(),
        capability_account_sha256: String::new(),
    };
    capabilities.capability_account_sha256 = domain_digest(
        b"cantor:self-work-update-broker:capability-account:0.2",
        &capabilities,
    );
    let evidence = vec![SyntheticEvidenceRef {
        label: "fixture:complete_plan".to_owned(),
        profile: SYNTHETIC_EVIDENCE_PROFILE.to_owned(),
        sha256: "8".repeat(64),
        bytes: 128,
        physical_contact: false,
    }];
    let evidence_set_sha256 = domain_digest(
        b"cantor:self-work-update-broker:evidence-set:0.2",
        &evidence,
    );
    let unresolved_frontier = [
        "current_interface",
        "target_host_containment",
        "writer",
        "observer",
        "evidence_root",
        "reviewer",
        "rollback_executor",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    let unresolved_frontier_sha256 = domain_digest(
        b"cantor:self-work-update-broker:unresolved:0.2",
        &unresolved_frontier,
    );
    let mut request = ProtocolFormationRequest {
        profile: PROTOCOL_REQUEST_PROFILE.to_owned(),
        root,
        stage_plan: stages,
        capability_account: capabilities,
        evidence,
        evidence_set_sha256,
        unresolved_frontier,
        unresolved_frontier_sha256,
        request_sha256: String::new(),
    };
    request.request_sha256 = protocol_request_digest(&request).unwrap();
    let result = compile_self_work_update_broker_protocol(&request).unwrap();
    (
        to_protocol_request_machine_form(&request).unwrap(),
        to_protocol_result_machine_form(&request, &result).unwrap(),
    )
}

fn topology(scratch: &str) -> B1CDriveTopology {
    let candidate = format!("{scratch}\\candidate");
    let sentinel = format!("{candidate}\\fixtures\\swa05_b1_cdrive_preflight");
    B1CDriveTopology {
        scratch_root: scratch.to_owned(),
        principal_workspace: "C:\\Project\\Cantor".to_owned(),
        candidate_root: candidate,
        repository_common_dir: "C:\\Project\\Cantor\\.git".to_owned(),
        candidate_git_dir: "C:\\Project\\Cantor\\.git\\worktrees\\swa05-b1-cdrive-preflight"
            .to_owned(),
        evidence_root: format!("{scratch}\\evidence"),
        temp_root: format!("{scratch}\\temp"),
        codex_home: format!("{scratch}\\codex-home"),
        allowed_path: format!("{sentinel}\\allowed.txt"),
        denied_path: format!("{sentinel}\\denied.txt"),
        write_canary_path: format!("{sentinel}\\write_canary.txt"),
    }
}

fn environment(topology: &B1CDriveTopology) -> Vec<B1CDriveEnvironmentIdentity> {
    [
        "CODEX_HOME",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "WINDIR",
    ]
    .into_iter()
    .map(|name| B1CDriveEnvironmentIdentity {
        name: name.to_owned(),
        value_sha256: sha256_upper(if name == "CODEX_HOME" {
            topology.codex_home.as_bytes()
        } else {
            name.as_bytes()
        }),
    })
    .collect()
}

fn command_request(id: u64, path: &str, topology: &B1CDriveTopology, write: bool) -> Value {
    let command = if write {
        json!([
            "C:\\Windows\\System32\\cmd.exe",
            "/d",
            "/c",
            "echo",
            "SWA05_B1_DENIED_WRITE_SENTINEL",
            ">",
            path
        ])
    } else {
        json!(["C:\\Windows\\System32\\cmd.exe", "/d", "/c", "type", path])
    };
    json!({
        "method": "command/exec",
        "id": id,
        "params": {
            "command": command,
            "cwd": topology.candidate_root,
            "permissionProfile": "swa05_b1_preflight",
            "timeoutMs": 10000,
            "disableOutputCap": false
        }
    })
}

fn transcript(topology: &B1CDriveTopology) -> Vec<Value> {
    vec![
        json!({
            "method": "initialize",
            "id": 0,
            "params": {
                "clientInfo": {
                    "name": "cantor_swa05_b1_preflight",
                    "title": "Cantor SWA-05 B1 Preflight",
                    "version": "0.2.0"
                },
                "capabilities": {"experimentalApi": true}
            }
        }),
        json!({"id": 0, "result": {
            "userAgent": "Codex Desktop/0.135.0 (Windows 10.0.26200; x86_64) dumb (cantor_swa05_b1_preflight; 0.2.0)",
            "codexHome": topology.codex_home,
            "platformFamily": "windows",
            "platformOs": "windows"
        }}),
        json!({"method": "remoteControl/status/changed", "params": {
            "status": "disabled",
            "serverName": "fixture",
            "installationId": "38940a83-d519-4dfa-b43e-5c05e7acd41a",
            "environmentId": null
        }}),
        json!({"method": "initialized", "params": {}}),
        json!({"method": "permissionProfile/list", "id": 1, "params": {
            "cwd": topology.candidate_root
        }}),
        json!({"id": 1, "result": {
            "data": [
                {"id": ":read-only", "description": null},
                {"id": ":workspace", "description": null},
                {"id": ":danger-full-access", "description": null},
                {"id": "swa05_b1_preflight", "description": null}
            ],
            "nextCursor": null
        }}),
        command_request(2, &topology.allowed_path, topology, false),
        json!({"id": 2, "result": {
            "exitCode": 0,
            "stdout": "SWA05_B1_ALLOWED_READ_SENTINEL\n",
            "stderr": ""
        }}),
        command_request(3, &topology.denied_path, topology, false),
        json!({"id": 3, "result": {
            "exitCode": 1,
            "stdout": "",
            "stderr": "Access is denied.\r\n"
        }}),
        command_request(4, &topology.write_canary_path, topology, true),
        json!({"id": 4, "result": {
            "exitCode": 1,
            "stdout": "",
            "stderr": "Access is denied.\r\n"
        }}),
    ]
}

fn observation(scratch: &str) -> B1CDrivePreflightObservation {
    let topology = topology(scratch);
    let allowed = B1CDriveInventoryEntry {
        relative_path: "fixtures/swa05_b1_cdrive_preflight/allowed.txt".to_owned(),
        kind: "file".to_owned(),
        bytes: b"SWA05_B1_ALLOWED_READ_SENTINEL\n".len() as u64,
        sha256: sha256_upper(b"SWA05_B1_ALLOWED_READ_SENTINEL\n"),
    };
    let denied = B1CDriveInventoryEntry {
        relative_path: "fixtures/swa05_b1_cdrive_preflight/denied.txt".to_owned(),
        kind: "file".to_owned(),
        bytes: b"SWA05_B1_DENIED_READ_SENTINEL\n".len() as u64,
        sha256: sha256_upper(b"SWA05_B1_DENIED_READ_SENTINEL\n"),
    };
    let inventory = vec![allowed, denied];
    B1CDrivePreflightObservation {
        profile: B1_CDRIVE_PREFLIGHT_OBSERVATION_PROFILE.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_PREFLIGHT_SOURCE_SNAPSHOT_UUID.to_owned(),
        predecessor_commit: B1_CDRIVE_PREFLIGHT_PREDECESSOR_COMMIT.to_owned(),
        historical_not_run_record_digest:
            "b7d65c4877932aaf14a32e4e65d04f40e053af39435d56e8dedaad5d021816ad"
                .to_owned(),
        capability_receipt_digest:
            "b0b9d7933fc8cfeb6c7907fb713cd3422c1c6fe157dd3d913636fc77974e83cb"
                .to_owned(),
        selected_executable: B1CDriveSelectedExecutable {
            path: "C:\\Users\\enjer\\AppData\\Roaming\\npm\\node_modules\\@openai\\codex\\node_modules\\@openai\\codex-win32-x64\\vendor\\x86_64-pc-windows-msvc\\bin\\codex.exe".to_owned(),
            bytes: 242_541_872,
            sha256_before:
                "FE12887B4AB4A4E988F0FA5BAAE9E5CB7D8505C26401378628E762DB9A2E798F"
                    .to_owned(),
            sha256_after:
                "FE12887B4AB4A4E988F0FA5BAAE9E5CB7D8505C26401378628E762DB9A2E798F"
                    .to_owned(),
            version_output: "codex-cli 0.135.0".to_owned(),
        },
        schemas: B1CDriveSchemaIdentity {
            standard_file: "standard_schema.json".to_owned(),
            standard_bytes: 505_191,
            standard_sha256:
                "99B3E93A3E5C96554E23A0B9EFB9FA4BDD1B05699CCB72B86A4F6A5CD69350E8"
                    .to_owned(),
            experimental_file: "experimental_schema.json".to_owned(),
            experimental_bytes: 568_621,
            experimental_sha256:
                "3846D4F0D17D301277E9809AE6F69C9E552CEAD5385476E3B9B4F83211DF9AD2"
                    .to_owned(),
        },
        commission: B1CDriveCommission {
            permission_profile_id: "swa05_b1_preflight".to_owned(),
            filesystem_override: format!(
                "permissions.swa05_b1_preflight.filesystem={{':root'='deny',':minimal'='read','{}'='read','{}'='deny'}}",
                topology.candidate_root, topology.denied_path
            ),
            network_enabled: false,
            granted: vec![
                CapabilityKind::ReadObservation,
                CapabilityKind::ProcessLaunch,
                CapabilityKind::ProcessInterrupt,
                CapabilityKind::ProcessTerminate,
            ],
            explicitly_not_granted: vec![
                CapabilityKind::EvidenceRootWrite,
                CapabilityKind::CandidateMutation,
                CapabilityKind::SupervisorTest,
                CapabilityKind::IndependentReview,
                CapabilityKind::RollbackAttempt,
                CapabilityKind::Cleanup,
                CapabilityKind::GitHistory,
                CapabilityKind::Commit,
                CapabilityKind::Push,
                CapabilityKind::Provider,
                CapabilityKind::SopAuthorship,
                CapabilityKind::SemanticSignature,
                CapabilityKind::Activation,
                CapabilityKind::Persistence,
                CapabilityKind::Remote,
                CapabilityKind::Fpga,
                CapabilityKind::Minecraft,
                CapabilityKind::PrincipalWorkspaceMutation,
            ],
            allowed_environment: environment(&topology),
            denied_environment: [
                "ALL_PROXY",
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AZURE_OPENAI_API_KEY",
                "CODEX_API_KEY",
                "EDITOR",
                "GH_TOKEN",
                "GIT_ASKPASS",
                "GIT_CONFIG_GLOBAL",
                "GIT_SSH_COMMAND",
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "NO_PROXY",
                "OPENAI_API_KEY",
                "PAGER",
                "VISUAL",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            topology: topology.clone(),
        },
        transcript: transcript(&topology),
        pre_inventory: inventory.clone(),
        post_inventory: inventory,
        process: B1CDriveProcessAccount {
            app_server_process_count: 1,
            app_server_started: true,
            stdin_closed: true,
            interrupted: false,
            terminated: false,
            reaped: true,
            exit_code: 0,
            descendant_count: 0,
            late_stdout_bytes: 0,
            late_stderr_bytes: 0,
            elapsed_millis: 100,
        },
        resources: B1CDriveResourceAccount {
            phase3_process_count: 12,
            total_process_count: 13,
            transcript_frames: 12,
            inventory_entries: 2,
            observed_bytes: 1_100_000,
            timeout_millis: 10_000,
        },
        boundaries: B1CDriveBoundaryAccount {
            current_revalidation_count: 1,
            allowed_read_count: 1,
            denied_read_count: 1,
            denied_write_count: 1,
            writer_run_count: 0,
            provider_contact_count: 0,
            model_turn_count: 0,
            mcp_call_count: 0,
            git_observation_process_count: 12,
            git_history_count: 0,
            commit_count: 0,
            push_count: 0,
            service_network_observed: false,
            remote_contact_count: 0,
            d_drive_contact_count: 0,
            product_mutation_count: 0,
            cleanup_count: 0,
            sop_authorship_count: 0,
            semantic_signature_count: 0,
            persistence_count: 0,
            activation_count: 0,
            fpga_count: 0,
            minecraft_count: 0,
            principal_workspace_mutation_count: 0,
            physical_contact: true,
            may_have_mutated: false,
            quarantine_required: false,
            scratch_reusable: true,
            write_canary_absent_before: true,
            write_canary_absent_after: true,
        },
    }
}

struct EvidenceFixture {
    scratch: PathBuf,
    evidence: PathBuf,
}

impl EvidenceFixture {
    fn new() -> Self {
        let suffix = format!(
            "test_{}_{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        );
        let scratch = PathBuf::from(format!(
            "C:\\Project\\CantorWorktrees\\swa05_b1_cdrive_preflight_{suffix}"
        ));
        let evidence = scratch.join("evidence");
        fs::create_dir_all(&evidence).unwrap();
        let scratch_text = scratch.to_str().unwrap();
        let (handoff, proposal, handoff_form, proposal_form) = handoff_forms(scratch_text);
        let (protocol_request, protocol_result) = protocol_forms(&handoff, &proposal);
        let prior = serde_json::to_vec(&handoff.prior_admission_receipt).unwrap();
        let current = prior.clone();
        let observation = serde_json::to_vec(&observation(scratch_text)).unwrap();
        let root = repository_root();
        let standard = fs::read(root.join(STANDARD_SCHEMA)).unwrap();
        let experimental = fs::read(root.join(EXPERIMENTAL_SCHEMA)).unwrap();
        let artifacts = vec![
            ("current_admission.json", current),
            ("experimental_schema.json", experimental),
            ("handoff_proposal.json", proposal_form),
            ("handoff_request.json", handoff_form),
            ("observation.json", observation),
            ("prior_admission.json", prior),
            ("protocol_request.json", protocol_request),
            ("protocol_result.json", protocol_result),
            ("standard_schema.json", standard),
        ];
        let identities = artifacts
            .iter()
            .map(|(path, bytes)| B1CDrivePreflightArtifactIdentity {
                path: (*path).to_owned(),
                bytes: bytes.len() as u64,
                sha256: sha256_upper(bytes),
            })
            .collect();
        for (name, bytes) in artifacts {
            fs::write(evidence.join(name), bytes).unwrap();
        }
        let manifest = B1CDrivePreflightEvidenceManifest {
            profile: B1_CDRIVE_PREFLIGHT_MANIFEST_PROFILE.to_owned(),
            source_snapshot_uuid: B1_CDRIVE_PREFLIGHT_SOURCE_SNAPSHOT_UUID.to_owned(),
            predecessor_commit: B1_CDRIVE_PREFLIGHT_PREDECESSOR_COMMIT.to_owned(),
            artifacts: identities,
        };
        fs::write(
            evidence.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        Self { scratch, evidence }
    }

    fn mutate_artifact(&self, name: &str, mutate: impl FnOnce(&mut Value)) {
        let path = self.evidence.join(name);
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        mutate(&mut value);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        self.rehash(name);
    }

    fn replace_artifact_raw(&self, name: &str, replacement: &[u8]) {
        fs::write(self.evidence.join(name), replacement).unwrap();
        self.rehash(name);
    }

    fn rehash(&self, name: &str) {
        let bytes = fs::read(self.evidence.join(name)).unwrap();
        let manifest_path = self.evidence.join("manifest.json");
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        let artifact = manifest["artifacts"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|artifact| artifact["path"] == name)
            .unwrap();
        artifact["bytes"] = Value::from(bytes.len() as u64);
        artifact["sha256"] = Value::from(sha256_upper(&bytes));
        fs::write(manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    }
}

impl Drop for EvidenceFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sha256_upper(bytes: &[u8]) -> String {
    sha256_bytes(bytes).value.to_ascii_uppercase()
}

fn assert_fault(root: &Path, expected: B1CDrivePreflightFaultCode) {
    assert_eq!(
        verify_b1_cdrive_preflight_evidence(root).unwrap_err().code,
        expected
    );
}

#[test]
fn complete_evidence_verifies_twice_and_receipt_round_trips() {
    let fixture = EvidenceFixture::new();
    let first = verify_b1_cdrive_preflight_evidence(&fixture.evidence).unwrap();
    let second = verify_b1_cdrive_preflight_evidence(&fixture.evidence).unwrap();
    let first_form = to_b1_cdrive_preflight_receipt_machine_form(&first).unwrap();
    assert_eq!(
        first_form,
        to_b1_cdrive_preflight_receipt_machine_form(&second).unwrap()
    );
    assert_eq!(
        from_b1_cdrive_preflight_receipt_machine_form(&first_form).unwrap(),
        first
    );
    assert!(first.allowed_read_enforced);
    assert!(first.denied_read_enforced);
    assert!(first.denied_write_enforced);
    assert_eq!(first.writer_run_count, 0);
    assert_eq!(first.provider_contact_count, 0);
    assert!(first.next_b2_formation_supported);
}

#[test]
fn cli_is_bounded_and_emits_the_exact_receipt() {
    let fixture = EvidenceFixture::new();
    let expected = verify_b1_cdrive_preflight_evidence(&fixture.evidence).unwrap();
    let expected = to_b1_cdrive_preflight_receipt_machine_form(&expected).unwrap();
    let binary = env!("CARGO_BIN_EXE_cantor-self-work-update-broker-b1-cdrive-preflight");
    let output = Command::new(binary)
        .arg(&fixture.evidence)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("{expected}\n")
    );
    assert!(output.stderr.is_empty());

    let output = Command::new(binary).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .starts_with("usage:")
    );
}

#[test]
fn duplicate_raw_argument_and_restart_tamper_refuse() {
    let duplicate = EvidenceFixture::new();
    let raw = fs::read_to_string(duplicate.evidence.join("observation.json")).unwrap();
    let raw = raw.replacen('{', "{\"profile\":\"duplicate\",", 1);
    duplicate.replace_artifact_raw("observation.json", raw.as_bytes());
    assert_fault(&duplicate.evidence, B1CDrivePreflightFaultCode::MachineForm);

    let argument = EvidenceFixture::new();
    argument.mutate_artifact("observation.json", |value| {
        value["transcript"][6]["params"]["command"][4] = Value::from("wrong-path")
    });
    assert_fault(&argument.evidence, B1CDrivePreflightFaultCode::Transcript);

    let restart = EvidenceFixture::new();
    restart.mutate_artifact("current_admission.json", |value| {
        value["admission_nonce"] = Value::from("restart-substitution")
    });
    assert_fault(&restart.evidence, B1CDrivePreflightFaultCode::Admission);
}

#[test]
fn environment_transcript_inventory_and_schema_mutations_refuse() {
    let environment = EvidenceFixture::new();
    environment.mutate_artifact("observation.json", |value| {
        value["commission"]["denied_environment"]
            .as_array_mut()
            .unwrap()
            .push(Value::from("EXTRA"));
    });
    assert_fault(
        &environment.evidence,
        B1CDrivePreflightFaultCode::Environment,
    );

    let transcript = EvidenceFixture::new();
    transcript.mutate_artifact("observation.json", |value| {
        value["transcript"].as_array_mut().unwrap().swap(6, 8)
    });
    assert_fault(&transcript.evidence, B1CDrivePreflightFaultCode::Transcript);

    let inventory = EvidenceFixture::new();
    inventory.mutate_artifact("observation.json", |value| {
        value["post_inventory"][0]["sha256"] = Value::from("0".repeat(64))
    });
    assert_fault(&inventory.evidence, B1CDrivePreflightFaultCode::Inventory);

    let schema = EvidenceFixture::new();
    schema.mutate_artifact("standard_schema.json", |value| {
        let variants = value
            .pointer_mut("/definitions/v2/SandboxPolicy/oneOf")
            .unwrap()
            .as_array_mut()
            .unwrap();
        variants.retain(|variant| variant["title"] != "ReadOnlySandboxPolicy");
    });
    assert_fault(&schema.evidence, B1CDrivePreflightFaultCode::Schema);
}

#[test]
fn machine_form_bounds_actual_root_and_status_identity_refuse() {
    let fields = EvidenceFixture::new();
    fields.mutate_artifact("observation.json", |value| {
        let oversized = (0..257)
            .map(|index| (format!("field_{index:03}"), Value::Null))
            .collect();
        value["oversized_object"] = Value::Object(oversized);
    });
    assert_fault(&fields.evidence, B1CDrivePreflightFaultCode::MachineForm);

    let depth = EvidenceFixture::new();
    depth.mutate_artifact("observation.json", |value| {
        let mut nested = Value::Null;
        for _ in 0..34 {
            nested = json!({"child": nested});
        }
        value["oversized_depth"] = nested;
    });
    assert_fault(&depth.evidence, B1CDrivePreflightFaultCode::MachineForm);

    let root = EvidenceFixture::new();
    root.mutate_artifact("observation.json", |value| {
        value["commission"]["topology"]["evidence_root"] =
            Value::from("C:\\Project\\CantorWorktrees\\substituted\\evidence")
    });
    assert_fault(&root.evidence, B1CDrivePreflightFaultCode::Topology);

    let status = EvidenceFixture::new();
    status.mutate_artifact("observation.json", |value| {
        value["transcript"][2]["params"]
            .as_object_mut()
            .unwrap()
            .remove("installationId");
    });
    assert_fault(&status.evidence, B1CDrivePreflightFaultCode::Transcript);
}

#[test]
fn receipt_authority_and_self_digest_mutations_refuse() {
    let fixture = EvidenceFixture::new();
    let receipt = verify_b1_cdrive_preflight_evidence(&fixture.evidence).unwrap();
    let exact = to_b1_cdrive_preflight_receipt_machine_form(&receipt).unwrap();

    let mut authority: Value = serde_json::from_str(&exact).unwrap();
    authority["writer_run_count"] = Value::from(1);
    assert_eq!(
        from_b1_cdrive_preflight_receipt_machine_form(&authority.to_string())
            .unwrap_err()
            .code,
        B1CDrivePreflightFaultCode::Authority
    );

    let mut digest: Value = serde_json::from_str(&exact).unwrap();
    digest["receipt_digest"]["value"] = Value::from("0".repeat(64));
    assert_eq!(
        from_b1_cdrive_preflight_receipt_machine_form(&digest.to_string())
            .unwrap_err()
            .code,
        B1CDrivePreflightFaultCode::Digest
    );
}

#[test]
fn verifier_source_has_no_effectful_runtime_surface() {
    let source = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/self_work_update_broker_b1_cdrive_preflight.rs"),
    )
    .unwrap();
    for forbidden in [
        "std::process::Command",
        "TcpStream",
        "UdpSocket",
        "reqwest",
        "fs::write",
        "File::create",
        "OpenOptions",
        "create_dir",
        "remove_file",
        "remove_dir",
        "set_var",
        "env::var",
        "SystemTime",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }
}
