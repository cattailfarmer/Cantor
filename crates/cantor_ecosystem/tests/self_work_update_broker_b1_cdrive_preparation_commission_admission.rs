use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use cantor_ecosystem::workspace_admission::update_broker_protocol::{
    BrokerRoot, CAPABILITY_ACCOUNT_PROFILE as B0_CAPABILITY_PROFILE,
    CapabilityAccount as B0CapabilityAccount, CapabilityKind, PROTOCOL_REQUEST_PROFILE,
    ProtocolFormationRequest, STAGE_PLAN_PROFILE, SYNTHETIC_EVIDENCE_PROFILE, StageDefinition,
    StageKind, StagePlan, SyntheticEvidenceRef, compile_self_work_update_broker_protocol,
    protocol_request_digest, to_protocol_request_machine_form, to_protocol_result_machine_form,
};
use cantor_ecosystem::{
    B1_CDRIVE_WORKTREE_PREPARATION_ATTRIBUTE_QUARANTINE, B1_CDRIVE_WORKTREE_PREPARATION_BOOKEND,
    B1_CDRIVE_WORKTREE_PREPARATION_BRANCH, B1_CDRIVE_WORKTREE_PREPARATION_CARRIER,
    B1_CDRIVE_WORKTREE_PREPARATION_GIT, B1_CDRIVE_WORKTREE_PREPARATION_GIT_SHA256,
    B1_CDRIVE_WORKTREE_PREPARATION_GIT_VERSION, B1_CDRIVE_WORKTREE_PREPARATION_HOOK_QUARANTINE,
    B1_CDRIVE_WORKTREE_PREPARATION_IMPLEMENTATION,
    B1_CDRIVE_WORKTREE_PREPARATION_INVALIDATION_UUID,
    B1_CDRIVE_WORKTREE_PREPARATION_REQUEST_PROFILE, B1_CDRIVE_WORKTREE_PREPARATION_SCRATCH,
    B1_CDRIVE_WORKTREE_PREPARATION_SIGNATURE_UUID,
    B1_CDRIVE_WORKTREE_PREPARATION_SOURCE_SNAPSHOT_UUID, CDriveWorktreePreparationFault,
    CDriveWorktreePreparationRequest, CommissionArtifactIdentity,
    PREPARATION_COMMISSION_ADMISSION_EVIDENCE_PROFILE,
    PREPARATION_COMMISSION_ADMISSION_REQUEST_PROFILE,
    PREPARATION_COMMISSION_ADMISSION_SIGNATURE_UUID,
    PREPARATION_COMMISSION_ADMISSION_SOURCE_SNAPSHOT_UUID,
    PREPARATION_COMMISSION_CAPABILITY_PROFILE, PREPARATION_COMMISSION_ISSUER,
    PREPARATION_COMMISSION_PROFILE, PREPARATION_COMMISSION_STAGE, PREPARATION_COMMISSION_SUBJECT,
    PREPARATION_FENCE_STEPS, PREPARATION_LEDGER_ROOT, PREPARATION_MUTATION_FENCE_PROFILE,
    PREPARATION_OPERATOR_AUTHORIZATION_PROFILE, PREPARATION_PRINCIPAL_WORKSPACE,
    PREPARATION_PUBLISHED_BOOKEND_COMMIT, PREPARATION_PUBLISHED_IMPLEMENTATION_COMMIT,
    PREPARATION_REPOSITORY_COMMON_DIR, PREPARATION_WORKTREE_PARENT, PreparationArtifactIdentity,
    PreparationChildSpec, PreparationCommissionAdmissionEvidenceManifest,
    PreparationCommissionAdmissionFaultCode, PreparationCommissionAdmissionReceipt,
    PreparationCommissionAdmissionRequest, PreparationCommissionCapabilityAccount,
    PreparationCommissionEnvelope, PreparationCommissionUnresolvedAccount,
    PreparationMutationFencePlan, PreparationOperatorAuthorizationRecord,
    PreparationProcessObservation, PreparationSimulationReceipt, ProviderOnlyPreparationBroker,
    SupervisingPublicationProof, compile_preparation_commission_admission,
    exact_preparation_commission_unresolved_items, exact_preparation_explicit_denials,
    exact_preparation_requested_future_grants, expected_preparation_commission_branch_ref,
    expected_preparation_commission_lease_name, expected_preparation_commission_scratch_root,
    from_preparation_commission_admission_receipt_machine_form,
    from_preparation_commission_admission_request_machine_form,
    preparation_commission_admission_receipt_digest,
    preparation_commission_admission_request_digest,
    preparation_commission_capability_account_digest, preparation_commission_digest,
    preparation_commission_unresolved_digest, preparation_mutation_fence_digest,
    preparation_operator_authorization_digest, simulate_cdrive_worktree_preparation_plan,
    to_cdrive_worktree_preparation_simulation_receipt_machine_form,
    to_preparation_commission_admission_receipt_machine_form,
    to_preparation_commission_admission_request_machine_form,
    verify_preparation_commission_admission_evidence,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

const EXPECTED_CURRENT_COMMIT: &str = "e766d3b94dfd2c72896631057ba9d0655b4fe5b9";
const COMMISSION_UUID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const CORRELATION_UUID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const ATTEMPT_UUID: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const AUTHORIZATION_UUID: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const HISTORICAL_PROOF_BYTES: &[u8] = include_bytes!(
    "../../../experiments/self_work_update_broker_b1_cdrive_linked_worktree_preparation_p0_revision_0_3/supervising_publication_proof.json"
);
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

fn sha256_upper(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

fn domain_digest_lower<T: Serialize + ?Sized>(domain: &[u8], value: &T) -> String {
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

fn identity(path: &str, bytes: &[u8]) -> CommissionArtifactIdentity {
    CommissionArtifactIdentity {
        path: path.to_owned(),
        bytes: bytes.len() as u64,
        sha256: sha256_upper(bytes),
    }
}

fn json_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn write_forms(root: &Path, forms: &Forms) {
    fs::create_dir_all(root).unwrap();
    let artifacts = forms.artifacts();
    for (name, bytes) in &artifacts {
        fs::write(root.join(name), bytes).unwrap();
    }
    let manifest = PreparationCommissionAdmissionEvidenceManifest {
        profile: PREPARATION_COMMISSION_ADMISSION_EVIDENCE_PROFILE.to_owned(),
        source_snapshot_uuid: PREPARATION_COMMISSION_ADMISSION_SOURCE_SNAPSHOT_UUID.to_owned(),
        artifacts: artifacts
            .iter()
            .map(|(name, bytes)| identity(name, bytes))
            .collect(),
    };
    fs::write(root.join("evidence_manifest.json"), json_bytes(&manifest)).unwrap();
}

fn b0_stages() -> Vec<StageDefinition> {
    use StageKind::*;
    [
        (
            B0Protocol,
            PROTOCOL_REQUEST_PROFILE,
            "cantor-self-work-update-broker-formation-validation/0.2",
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
        |(index, (kind, input, output, physical_contact_expected))| StageDefinition {
            ordinal: (index + 1) as u8,
            kind,
            input_profile: input.to_owned(),
            output_profile: output.to_owned(),
            physical_contact_expected,
            activation_required: true,
        },
    )
    .collect()
}

fn all_b0_capabilities() -> Vec<CapabilityKind> {
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

fn protocol_forms() -> (Vec<u8>, Vec<u8>) {
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
        handoff_request_sha256: "4".repeat(64),
        handoff_proposal_sha256: "5".repeat(64),
        workspace_correlation_uuid: "55555555-5555-4555-8555-555555555555".to_owned(),
        base_commit: "6".repeat(40),
        branch_ref: "refs/heads/codex/fixture".to_owned(),
        git_executable_sha256: "7".repeat(64),
        allowed_relative_paths: vec!["fixtures/allowed.txt".to_owned()],
        change_set_sha256: "8".repeat(64),
        broker_root_sha256: String::new(),
    };
    root.broker_root_sha256 =
        domain_digest_lower(b"cantor:self-work-update-broker:root:0.2", &root);
    let mut stage_plan = StagePlan {
        profile: STAGE_PLAN_PROFILE.to_owned(),
        stages: b0_stages(),
        stage_plan_sha256: String::new(),
    };
    stage_plan.stage_plan_sha256 = domain_digest_lower(
        b"cantor:self-work-update-broker:stage-plan:0.2",
        &stage_plan,
    );
    let mut capability_account = B0CapabilityAccount {
        profile: B0_CAPABILITY_PROFILE.to_owned(),
        granted: vec![],
        explicitly_not_granted: all_b0_capabilities(),
        capability_account_sha256: String::new(),
    };
    capability_account.capability_account_sha256 = domain_digest_lower(
        b"cantor:self-work-update-broker:capability-account:0.2",
        &capability_account,
    );
    let evidence = vec![SyntheticEvidenceRef {
        label: "fixture:complete_plan".to_owned(),
        profile: SYNTHETIC_EVIDENCE_PROFILE.to_owned(),
        sha256: "9".repeat(64),
        bytes: 128,
        physical_contact: false,
    }];
    let evidence_set_sha256 = domain_digest_lower(
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
    let unresolved_frontier_sha256 = domain_digest_lower(
        b"cantor:self-work-update-broker:unresolved:0.2",
        &unresolved_frontier,
    );
    let mut request = ProtocolFormationRequest {
        profile: PROTOCOL_REQUEST_PROFILE.to_owned(),
        root,
        stage_plan,
        capability_account,
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
            stdout: if child.expected_stdout_lines.is_empty() {
                String::new()
            } else {
                format!("{}\n", child.expected_stdout_lines.join("\n"))
            },
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

fn preparation_receipt() -> (PreparationSimulationReceipt, Vec<u8>) {
    let proof: SupervisingPublicationProof =
        serde_json::from_slice(HISTORICAL_PROOF_BYTES).unwrap();
    let scratch = B1_CDRIVE_WORKTREE_PREPARATION_SCRATCH;
    let request = CDriveWorktreePreparationRequest {
        profile: B1_CDRIVE_WORKTREE_PREPARATION_REQUEST_PROFILE.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_WORKTREE_PREPARATION_SOURCE_SNAPSHOT_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_WORKTREE_PREPARATION_SIGNATURE_UUID.to_owned(),
        predecessor_invalidation_uuid: B1_CDRIVE_WORKTREE_PREPARATION_INVALIDATION_UUID.to_owned(),
        carrier_commit: B1_CDRIVE_WORKTREE_PREPARATION_CARRIER.to_owned(),
        implementation_commit: B1_CDRIVE_WORKTREE_PREPARATION_IMPLEMENTATION.to_owned(),
        bookend_commit: B1_CDRIVE_WORKTREE_PREPARATION_BOOKEND.to_owned(),
        expected_current_commit: EXPECTED_CURRENT_COMMIT.to_owned(),
        publication_proof_artifact: PreparationArtifactIdentity {
            path: "publication_proof.json".to_owned(),
            bytes: HISTORICAL_PROOF_BYTES.len() as u64,
            sha256: sha256_upper(HISTORICAL_PROOF_BYTES),
        },
        physical_commission_uuid: None,
        physical_preparation_authorized: false,
        recovery_owner: PREPARATION_COMMISSION_ISSUER.to_owned(),
        principal_workspace: PREPARATION_PRINCIPAL_WORKSPACE.to_owned(),
        repository_common_dir: PREPARATION_REPOSITORY_COMMON_DIR.to_owned(),
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
    };
    let (_, _, _, _, receipt) =
        simulate_cdrive_worktree_preparation_plan(&request, &proof, &mut FakeBroker).unwrap();
    let bytes = to_cdrive_worktree_preparation_simulation_receipt_machine_form(&receipt)
        .unwrap()
        .into_bytes();
    (receipt, bytes)
}

#[derive(Clone)]
struct Forms {
    protocol_request_bytes: Vec<u8>,
    protocol_result_bytes: Vec<u8>,
    preparation_receipt_bytes: Vec<u8>,
    request: PreparationCommissionAdmissionRequest,
    commission: PreparationCommissionEnvelope,
    capabilities: PreparationCommissionCapabilityAccount,
    fence: PreparationMutationFencePlan,
    authorization: PreparationOperatorAuthorizationRecord,
    unresolved: PreparationCommissionUnresolvedAccount,
    receipt: PreparationCommissionAdmissionReceipt,
}

impl Forms {
    fn new() -> Self {
        let (protocol_request_bytes, protocol_result_bytes) = protocol_forms();
        let (preparation_receipt, preparation_receipt_bytes) = preparation_receipt();
        let mut authorization = PreparationOperatorAuthorizationRecord {
            profile: PREPARATION_OPERATOR_AUTHORIZATION_PROFILE.to_owned(),
            authorization_uuid: AUTHORIZATION_UUID.to_owned(),
            operator_identity: PREPARATION_COMMISSION_ISSUER.to_owned(),
            subject_identity: PREPARATION_COMMISSION_SUBJECT.to_owned(),
            stage: PREPARATION_COMMISSION_STAGE.to_owned(),
            commission_uuid: COMMISSION_UUID.to_owned(),
            externally_issued: false,
            authorization_authenticated: false,
            operator_consent_observed: false,
            authorization_sha256: String::new(),
        };
        authorization.authorization_sha256 =
            preparation_operator_authorization_digest(&authorization).unwrap();
        let authorization_bytes = json_bytes(&authorization);
        let scratch = expected_preparation_commission_scratch_root(COMMISSION_UUID).unwrap();
        let mut commission = PreparationCommissionEnvelope {
            profile: PREPARATION_COMMISSION_PROFILE.to_owned(),
            commission_uuid: COMMISSION_UUID.to_owned(),
            correlation_uuid: CORRELATION_UUID.to_owned(),
            attempt_uuid: ATTEMPT_UUID.to_owned(),
            issuer_identity: PREPARATION_COMMISSION_ISSUER.to_owned(),
            subject_identity: PREPARATION_COMMISSION_SUBJECT.to_owned(),
            recovery_owner: PREPARATION_COMMISSION_ISSUER.to_owned(),
            stage: PREPARATION_COMMISSION_STAGE.to_owned(),
            operator_authorization_artifact: identity(
                "operator_authorization.json",
                &authorization_bytes,
            ),
            carrier_commit: preparation_receipt.carrier_commit.clone(),
            preparation_implementation_commit: PREPARATION_PUBLISHED_IMPLEMENTATION_COMMIT
                .to_owned(),
            preparation_bookend_commit: PREPARATION_PUBLISHED_BOOKEND_COMMIT.to_owned(),
            expected_current_commit: preparation_receipt.expected_current_commit.clone(),
            provider_only_plan_sha256: preparation_receipt.plan_sha256.value.to_ascii_uppercase(),
            branch_ref: expected_preparation_commission_branch_ref(COMMISSION_UUID).unwrap(),
            principal_workspace: PREPARATION_PRINCIPAL_WORKSPACE.to_owned(),
            repository_common_dir: PREPARATION_REPOSITORY_COMMON_DIR.to_owned(),
            worktree_parent: PREPARATION_WORKTREE_PARENT.to_owned(),
            ledger_root: PREPARATION_LEDGER_ROOT.to_owned(),
            scratch_root: scratch.clone(),
            candidate_root: format!("{scratch}\\candidate"),
            evidence_root: format!("{scratch}\\evidence"),
            temp_root: format!("{scratch}\\temp"),
            codex_home: format!("{scratch}\\codex-home"),
            hook_quarantine_root: format!("{scratch}\\hook-quarantine"),
            attribute_quarantine_file: format!("{scratch}\\attribute-quarantine"),
            maximum_attempts: 1,
            retry_count: 0,
            commission_sha256: String::new(),
        };
        commission.commission_sha256 = preparation_commission_digest(&commission).unwrap();
        let mut capabilities = PreparationCommissionCapabilityAccount {
            profile: PREPARATION_COMMISSION_CAPABILITY_PROFILE.to_owned(),
            requested_future_grants: exact_preparation_requested_future_grants(),
            explicit_denials: exact_preparation_explicit_denials(),
            requested_grant_count: 7,
            explicit_denial_count: 15,
            unique_capability_count: 22,
            overlap_count: 0,
            issued_capability_count: 0,
            capability_account_sha256: String::new(),
        };
        capabilities.capability_account_sha256 =
            preparation_commission_capability_account_digest(&capabilities).unwrap();
        let mut fence = PreparationMutationFencePlan {
            profile: PREPARATION_MUTATION_FENCE_PROFILE.to_owned(),
            steps: PREPARATION_FENCE_STEPS
                .into_iter()
                .map(str::to_owned)
                .collect(),
            declared_step_count: 10,
            maximum_step_count: 10,
            lease_kind: "windows_named_mutex".to_owned(),
            lease_name: expected_preparation_commission_lease_name(COMMISSION_UUID).unwrap(),
            acquisition_wait_millis: 0,
            lease_hold_from_step: "acquire_exclusive_lease".to_owned(),
            lease_hold_through_step: "mark_commission_consumed".to_owned(),
            ledger_claim_path: format!(
                "{PREPARATION_LEDGER_ROOT}\\commissions\\{COMMISSION_UUID}.claimed.json"
            ),
            ledger_consumed_path: format!(
                "{PREPARATION_LEDGER_ROOT}\\commissions\\{COMMISSION_UUID}.consumed.json"
            ),
            ledger_claim_mode: "create_new".to_owned(),
            claim_before_any_effect: true,
            reobserve_after_lease_before_effect: true,
            publish_before_consumption: true,
            consumption_before_release: true,
            no_retry: true,
            no_delete: true,
            no_replace: true,
            no_cleanup: true,
            retain_uncertain_state: true,
            fence_plan_sha256: String::new(),
        };
        fence.fence_plan_sha256 = preparation_mutation_fence_digest(&fence).unwrap();
        let mut unresolved = PreparationCommissionUnresolvedAccount {
            profile: cantor_ecosystem::PREPARATION_COMMISSION_UNRESOLVED_PROFILE.to_owned(),
            items: exact_preparation_commission_unresolved_items(),
            unresolved_sha256: String::new(),
        };
        unresolved.unresolved_sha256 =
            preparation_commission_unresolved_digest(&unresolved).unwrap();
        let request = Self::request_for(
            &protocol_request_bytes,
            &protocol_result_bytes,
            &preparation_receipt_bytes,
            &commission,
            &capabilities,
            &fence,
            &authorization,
            &unresolved,
        );
        let receipt = compile_preparation_commission_admission(
            &protocol_request_bytes,
            &protocol_result_bytes,
            &preparation_receipt_bytes,
            &request,
            &commission,
            &capabilities,
            &fence,
            &authorization,
            &unresolved,
        )
        .unwrap();
        Self {
            protocol_request_bytes,
            protocol_result_bytes,
            preparation_receipt_bytes,
            request,
            commission,
            capabilities,
            fence,
            authorization,
            unresolved,
            receipt,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn request_for(
        protocol_request_bytes: &[u8],
        protocol_result_bytes: &[u8],
        preparation_receipt_bytes: &[u8],
        commission: &PreparationCommissionEnvelope,
        capabilities: &PreparationCommissionCapabilityAccount,
        fence: &PreparationMutationFencePlan,
        authorization: &PreparationOperatorAuthorizationRecord,
        unresolved: &PreparationCommissionUnresolvedAccount,
    ) -> PreparationCommissionAdmissionRequest {
        let commission_bytes = json_bytes(commission);
        let capability_bytes = json_bytes(capabilities);
        let fence_bytes = json_bytes(fence);
        let authorization_bytes = json_bytes(authorization);
        let unresolved_bytes = json_bytes(unresolved);
        let mut request = PreparationCommissionAdmissionRequest {
            profile: PREPARATION_COMMISSION_ADMISSION_REQUEST_PROFILE.to_owned(),
            source_snapshot_uuid: PREPARATION_COMMISSION_ADMISSION_SOURCE_SNAPSHOT_UUID.to_owned(),
            signature_uuid: PREPARATION_COMMISSION_ADMISSION_SIGNATURE_UUID.to_owned(),
            protocol_request_artifact: identity("protocol_request.json", protocol_request_bytes),
            protocol_result_artifact: identity("protocol_result.json", protocol_result_bytes),
            preparation_receipt_artifact: identity(
                "preparation_receipt.json",
                preparation_receipt_bytes,
            ),
            commission_artifact: identity("commission.json", &commission_bytes),
            capability_account_artifact: identity("capability_account.json", &capability_bytes),
            fence_plan_artifact: identity("fence_plan.json", &fence_bytes),
            operator_authorization_artifact: identity(
                "operator_authorization.json",
                &authorization_bytes,
            ),
            unresolved_account_artifact: identity("unresolved_account.json", &unresolved_bytes),
            physical_contact_expected: false,
            request_sha256: String::new(),
        };
        request.request_sha256 = preparation_commission_admission_request_digest(&request).unwrap();
        request
    }

    #[allow(clippy::too_many_arguments)]
    fn compile(
        &self,
        protocol_request_bytes: &[u8],
        protocol_result_bytes: &[u8],
        preparation_receipt_bytes: &[u8],
        commission: &PreparationCommissionEnvelope,
        capabilities: &PreparationCommissionCapabilityAccount,
        fence: &PreparationMutationFencePlan,
        authorization: &PreparationOperatorAuthorizationRecord,
        unresolved: &PreparationCommissionUnresolvedAccount,
    ) -> Result<PreparationCommissionAdmissionReceipt, PreparationCommissionAdmissionFaultCode>
    {
        let request = Self::request_for(
            protocol_request_bytes,
            protocol_result_bytes,
            preparation_receipt_bytes,
            commission,
            capabilities,
            fence,
            authorization,
            unresolved,
        );
        compile_preparation_commission_admission(
            protocol_request_bytes,
            protocol_result_bytes,
            preparation_receipt_bytes,
            &request,
            commission,
            capabilities,
            fence,
            authorization,
            unresolved,
        )
        .map_err(|error| error.code)
    }

    fn artifacts(&self) -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("admission_receipt.json", json_bytes(&self.receipt)),
            ("capability_account.json", json_bytes(&self.capabilities)),
            ("commission.json", json_bytes(&self.commission)),
            ("fence_plan.json", json_bytes(&self.fence)),
            (
                "operator_authorization.json",
                json_bytes(&self.authorization),
            ),
            (
                "preparation_receipt.json",
                self.preparation_receipt_bytes.clone(),
            ),
            ("protocol_request.json", self.protocol_request_bytes.clone()),
            ("protocol_result.json", self.protocol_result_bytes.clone()),
            ("request.json", json_bytes(&self.request)),
            ("unresolved_account.json", json_bytes(&self.unresolved)),
        ]
    }
}

struct Fixture {
    root: PathBuf,
    forms: Forms,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "cantor_b1_cdrive_preparation_commission_admission_{}_{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        fs::create_dir_all(&root).unwrap();
        let forms = Forms::new();
        let fixture = Self { root, forms };
        fixture.write();
        fixture
    }

    fn write(&self) {
        write_forms(&self.root, &self.forms);
    }

    fn value(&self, name: &str) -> Value {
        serde_json::from_slice(&fs::read(self.root.join(name)).unwrap()).unwrap()
    }

    fn write_value_and_refresh(&self, name: &str, value: &Value) {
        fs::write(self.root.join(name), json_bytes(value)).unwrap();
        self.refresh_manifest();
    }

    fn write_raw_and_refresh(&self, name: &str, bytes: &[u8]) {
        fs::write(self.root.join(name), bytes).unwrap();
        self.refresh_manifest();
    }

    fn refresh_manifest(&self) {
        let artifact_names = [
            "admission_receipt.json",
            "capability_account.json",
            "commission.json",
            "fence_plan.json",
            "operator_authorization.json",
            "preparation_receipt.json",
            "protocol_request.json",
            "protocol_result.json",
            "request.json",
            "unresolved_account.json",
        ];
        let manifest = PreparationCommissionAdmissionEvidenceManifest {
            profile: PREPARATION_COMMISSION_ADMISSION_EVIDENCE_PROFILE.to_owned(),
            source_snapshot_uuid: PREPARATION_COMMISSION_ADMISSION_SOURCE_SNAPSHOT_UUID.to_owned(),
            artifacts: artifact_names
                .into_iter()
                .map(|artifact_name| {
                    identity(
                        artifact_name,
                        &fs::read(self.root.join(artifact_name)).unwrap(),
                    )
                })
                .collect(),
        };
        fs::write(
            self.root.join("evidence_manifest.json"),
            json_bytes(&manifest),
        )
        .unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn pure_admission_binds_exact_ten_step_contract_and_machine_forms() {
    let forms = Forms::new();
    assert_eq!(forms.fence.steps.len(), 10);
    assert_eq!(forms.fence.steps, PREPARATION_FENCE_STEPS);
    assert_eq!(forms.receipt.actual_fence_step_count, 10);
    assert_eq!(forms.receipt.declared_fence_step_count, 10);
    assert_eq!(forms.receipt.maximum_fence_step_count, 10);
    assert_eq!(forms.receipt.requested_future_grant_count, 7);
    assert_eq!(forms.receipt.explicit_denial_count, 15);
    assert_eq!(forms.receipt.issued_capability_count, 0);
    assert!(!forms.receipt.commission_issued);
    assert!(!forms.receipt.physical_execution_authorized);
    assert!(!forms.receipt.production_broker_run);
    assert!(!forms.receipt.physical_contact);
    assert_eq!(forms.receipt.process_run_count, 0);
    assert_eq!(forms.receipt.filesystem_write_count, 0);
    assert_eq!(forms.receipt.git_mutation_count, 0);

    let request_machine =
        to_preparation_commission_admission_request_machine_form(&forms.request).unwrap();
    assert_eq!(
        from_preparation_commission_admission_request_machine_form(&request_machine).unwrap(),
        forms.request
    );
    let receipt_machine =
        to_preparation_commission_admission_receipt_machine_form(&forms.receipt).unwrap();
    assert_eq!(
        from_preparation_commission_admission_receipt_machine_form(&receipt_machine).unwrap(),
        forms.receipt
    );
}

#[test]
fn independent_evidence_verifier_replays_byte_identically() {
    let fixture = Fixture::new();
    let first = verify_preparation_commission_admission_evidence(&fixture.root).unwrap();
    let second = verify_preparation_commission_admission_evidence(&fixture.root).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        to_preparation_commission_admission_receipt_machine_form(&first).unwrap(),
        to_preparation_commission_admission_receipt_machine_form(&second).unwrap()
    );
}

#[test]
fn committed_provider_independent_evidence_replays() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../experiments/self_work_update_broker_b1_cdrive_preparation_commission_admission_p0_revision_0_2/provider_independent_evidence",
    );
    let receipt = verify_preparation_commission_admission_evidence(&root).unwrap();
    assert_eq!(receipt.actual_fence_step_count, 10);
    assert!(!receipt.physical_contact);
    assert_eq!(receipt.provider_trial_count, 0);
}

#[test]
#[ignore = "writes only the explicitly supplied owned evidence root"]
fn write_owned_provider_independent_evidence_fixture() {
    let root = PathBuf::from(
        std::env::var("CANTOR_B1CCA2_EVIDENCE_ROOT")
            .expect("CANTOR_B1CCA2_EVIDENCE_ROOT must be explicit"),
    );
    assert!(root.ends_with(
        "experiments/self_work_update_broker_b1_cdrive_preparation_commission_admission_p0_revision_0_2/provider_independent_evidence"
    ));
    write_forms(&root, &Forms::new());
}

#[test]
fn every_fence_omission_reorder_and_cardinality_tamper_refuses() {
    let forms = Forms::new();
    for index in 0..10 {
        let mut fence = forms.fence.clone();
        fence.steps.remove(index);
        fence.fence_plan_sha256 = preparation_mutation_fence_digest(&fence).unwrap();
        assert_eq!(
            forms
                .compile(
                    &forms.protocol_request_bytes,
                    &forms.protocol_result_bytes,
                    &forms.preparation_receipt_bytes,
                    &forms.commission,
                    &forms.capabilities,
                    &fence,
                    &forms.authorization,
                    &forms.unresolved,
                )
                .unwrap_err(),
            PreparationCommissionAdmissionFaultCode::Fence
        );
    }

    let mut reordered = forms.fence.clone();
    reordered.steps.swap(8, 9);
    reordered.fence_plan_sha256 = preparation_mutation_fence_digest(&reordered).unwrap();
    assert_eq!(
        forms
            .compile(
                &forms.protocol_request_bytes,
                &forms.protocol_result_bytes,
                &forms.preparation_receipt_bytes,
                &forms.commission,
                &forms.capabilities,
                &reordered,
                &forms.authorization,
                &forms.unresolved,
            )
            .unwrap_err(),
        PreparationCommissionAdmissionFaultCode::Fence
    );

    for mutate in [
        |fence: &mut PreparationMutationFencePlan| fence.declared_step_count = 9,
        |fence: &mut PreparationMutationFencePlan| fence.maximum_step_count = 9,
    ] {
        let mut changed = forms.fence.clone();
        mutate(&mut changed);
        changed.fence_plan_sha256 = preparation_mutation_fence_digest(&changed).unwrap();
        assert_eq!(
            forms
                .compile(
                    &forms.protocol_request_bytes,
                    &forms.protocol_result_bytes,
                    &forms.preparation_receipt_bytes,
                    &forms.commission,
                    &forms.capabilities,
                    &changed,
                    &forms.authorization,
                    &forms.unresolved,
                )
                .unwrap_err(),
            PreparationCommissionAdmissionFaultCode::Fence
        );
    }
}

#[test]
fn capability_removal_reorder_addition_and_overlap_refuse() {
    let forms = Forms::new();
    let mut variants = Vec::new();

    let mut removed = forms.capabilities.clone();
    removed.requested_future_grants.remove(0);
    removed.requested_grant_count = 6;
    removed.unique_capability_count = 21;
    variants.push(removed);

    let mut reordered = forms.capabilities.clone();
    reordered.requested_future_grants.swap(0, 1);
    variants.push(reordered);

    let mut added = forms.capabilities.clone();
    added
        .requested_future_grants
        .push(CapabilityKind::SupervisorTest);
    added.requested_grant_count = 8;
    added.overlap_count = 1;
    variants.push(added);

    let mut duplicate = forms.capabilities.clone();
    duplicate
        .explicit_denials
        .push(CapabilityKind::PrincipalWorkspaceMutation);
    duplicate.explicit_denial_count = 16;
    variants.push(duplicate);

    for mut changed in variants {
        changed.capability_account_sha256 =
            preparation_commission_capability_account_digest(&changed).unwrap();
        assert_eq!(
            forms
                .compile(
                    &forms.protocol_request_bytes,
                    &forms.protocol_result_bytes,
                    &forms.preparation_receipt_bytes,
                    &forms.commission,
                    &changed,
                    &forms.fence,
                    &forms.authorization,
                    &forms.unresolved,
                )
                .unwrap_err(),
            PreparationCommissionAdmissionFaultCode::Capability
        );
    }
}

#[test]
fn commission_scope_retry_role_and_plan_drift_refuse() {
    let forms = Forms::new();
    let mut variants = Vec::new();

    let mut retry = forms.commission.clone();
    retry.retry_count = 1;
    variants.push(retry);

    let mut principal = forms.commission.clone();
    principal.principal_workspace = "D:\\Cantor".to_owned();
    variants.push(principal);

    let mut collapsed_role = forms.commission.clone();
    collapsed_role.subject_identity = collapsed_role.issuer_identity.clone();
    variants.push(collapsed_role);

    let mut plan = forms.commission.clone();
    plan.provider_only_plan_sha256 = "A".repeat(64);
    variants.push(plan);

    for mut changed in variants {
        changed.commission_sha256 = preparation_commission_digest(&changed).unwrap();
        assert_eq!(
            forms
                .compile(
                    &forms.protocol_request_bytes,
                    &forms.protocol_result_bytes,
                    &forms.preparation_receipt_bytes,
                    &changed,
                    &forms.capabilities,
                    &forms.fence,
                    &forms.authorization,
                    &forms.unresolved,
                )
                .unwrap_err(),
            PreparationCommissionAdmissionFaultCode::Commission
        );
    }
}

#[test]
fn raw_upstream_byte_substitution_refuses_even_when_identity_is_rebound() {
    let forms = Forms::new();
    let mut changed_result = forms.protocol_result_bytes.clone();
    changed_result.push(b' ');
    assert_eq!(
        forms
            .compile(
                &forms.protocol_request_bytes,
                &changed_result,
                &forms.preparation_receipt_bytes,
                &forms.commission,
                &forms.capabilities,
                &forms.fence,
                &forms.authorization,
                &forms.unresolved,
            )
            .unwrap_err(),
        PreparationCommissionAdmissionFaultCode::Upstream
    );

    let mut changed_receipt = forms.preparation_receipt_bytes.clone();
    changed_receipt.push(b'\n');
    assert_eq!(
        forms
            .compile(
                &forms.protocol_request_bytes,
                &forms.protocol_result_bytes,
                &changed_receipt,
                &forms.commission,
                &forms.capabilities,
                &forms.fence,
                &forms.authorization,
                &forms.unresolved,
            )
            .unwrap_err(),
        PreparationCommissionAdmissionFaultCode::Upstream
    );
}

#[test]
fn authorization_unresolved_and_restart_tamper_refuse() {
    let forms = Forms::new();
    for mutate in 0..3 {
        let mut authorization = forms.authorization.clone();
        match mutate {
            0 => authorization.externally_issued = true,
            1 => authorization.authorization_authenticated = true,
            _ => authorization.operator_consent_observed = true,
        }
        authorization.authorization_sha256 =
            preparation_operator_authorization_digest(&authorization).unwrap();
        let mut commission = forms.commission.clone();
        commission.operator_authorization_artifact =
            identity("operator_authorization.json", &json_bytes(&authorization));
        commission.commission_sha256 = preparation_commission_digest(&commission).unwrap();
        assert_eq!(
            forms
                .compile(
                    &forms.protocol_request_bytes,
                    &forms.protocol_result_bytes,
                    &forms.preparation_receipt_bytes,
                    &commission,
                    &forms.capabilities,
                    &forms.fence,
                    &authorization,
                    &forms.unresolved,
                )
                .unwrap_err(),
            PreparationCommissionAdmissionFaultCode::Authority
        );
    }

    let mut unresolved = forms.unresolved.clone();
    unresolved.items.remove(0);
    unresolved.unresolved_sha256 = preparation_commission_unresolved_digest(&unresolved).unwrap();
    assert_eq!(
        forms
            .compile(
                &forms.protocol_request_bytes,
                &forms.protocol_result_bytes,
                &forms.preparation_receipt_bytes,
                &forms.commission,
                &forms.capabilities,
                &forms.fence,
                &forms.authorization,
                &unresolved,
            )
            .unwrap_err(),
        PreparationCommissionAdmissionFaultCode::Authority
    );

    let mut restarted = forms.commission.clone();
    restarted.attempt_uuid = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee".to_owned();
    assert_eq!(
        forms
            .compile(
                &forms.protocol_request_bytes,
                &forms.protocol_result_bytes,
                &forms.preparation_receipt_bytes,
                &restarted,
                &forms.capabilities,
                &forms.fence,
                &forms.authorization,
                &forms.unresolved,
            )
            .unwrap_err(),
        PreparationCommissionAdmissionFaultCode::Commission
    );
}

#[test]
fn lease_ledger_ordering_and_failure_truth_tamper_refuse() {
    let forms = Forms::new();
    let mut variants = Vec::new();
    let mut waiting = forms.fence.clone();
    waiting.acquisition_wait_millis = 1;
    variants.push(waiting);
    let mut gap = forms.fence.clone();
    gap.lease_hold_through_step = "publish_outcome".to_owned();
    variants.push(gap);
    let mut late_claim = forms.fence.clone();
    late_claim.claim_before_any_effect = false;
    variants.push(late_claim);
    let mut early_release = forms.fence.clone();
    early_release.consumption_before_release = false;
    variants.push(early_release);
    let mut cleanup = forms.fence.clone();
    cleanup.no_cleanup = false;
    variants.push(cleanup);
    let mut laundering = forms.fence.clone();
    laundering.retain_uncertain_state = false;
    variants.push(laundering);

    for mut changed in variants {
        changed.fence_plan_sha256 = preparation_mutation_fence_digest(&changed).unwrap();
        assert_eq!(
            forms
                .compile(
                    &forms.protocol_request_bytes,
                    &forms.protocol_result_bytes,
                    &forms.preparation_receipt_bytes,
                    &forms.commission,
                    &forms.capabilities,
                    &changed,
                    &forms.authorization,
                    &forms.unresolved,
                )
                .unwrap_err(),
            PreparationCommissionAdmissionFaultCode::Fence
        );
    }
}

#[test]
fn evidence_overdepth_oversize_and_parent_traversal_refuse() {
    let fixture = Fixture::new();
    let mut nested = "0".to_owned();
    for _ in 0..34 {
        nested = format!("[{nested}]");
    }
    fixture.write_raw_and_refresh("request.json", nested.as_bytes());
    assert_eq!(
        verify_preparation_commission_admission_evidence(&fixture.root)
            .unwrap_err()
            .code,
        PreparationCommissionAdmissionFaultCode::MachineForm
    );

    fixture.write();
    let oversized = vec![b' '; 2 * 1024 * 1024 + 1];
    fixture.write_raw_and_refresh("request.json", &oversized);
    assert_eq!(
        verify_preparation_commission_admission_evidence(&fixture.root)
            .unwrap_err()
            .code,
        PreparationCommissionAdmissionFaultCode::Bound
    );

    fixture.write();
    let manifest_path = fixture.root.join("evidence_manifest.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    manifest["artifacts"][8]["path"] = Value::String("../request.json".to_owned());
    fs::write(&manifest_path, json_bytes(&manifest)).unwrap();
    assert_eq!(
        verify_preparation_commission_admission_evidence(&fixture.root)
            .unwrap_err()
            .code,
        PreparationCommissionAdmissionFaultCode::Manifest
    );
}

#[test]
fn evidence_duplicate_unknown_coordinate_and_receipt_laundering_refuse() {
    let fixture = Fixture::new();
    let request_bytes = fs::read(fixture.root.join("request.json")).unwrap();
    let duplicate = request_bytes
        .strip_prefix(b"{")
        .map(|rest| {
            let mut bytes = b"{\"profile\":\"duplicate\",".to_vec();
            bytes.extend_from_slice(rest);
            bytes
        })
        .unwrap();
    fixture.write_raw_and_refresh("request.json", &duplicate);
    assert_eq!(
        verify_preparation_commission_admission_evidence(&fixture.root)
            .unwrap_err()
            .code,
        PreparationCommissionAdmissionFaultCode::MachineForm
    );

    fixture.write();
    let mut unknown = fixture.value("request.json");
    unknown
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_owned(), Value::Bool(true));
    fixture.write_value_and_refresh("request.json", &unknown);
    assert_eq!(
        verify_preparation_commission_admission_evidence(&fixture.root)
            .unwrap_err()
            .code,
        PreparationCommissionAdmissionFaultCode::MachineForm
    );

    fixture.write();
    let manifest_path = fixture.root.join("evidence_manifest.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let artifacts = manifest["artifacts"].as_array_mut().unwrap();
    artifacts[1]["path"] = artifacts[0]["path"].clone();
    fs::write(&manifest_path, json_bytes(&manifest)).unwrap();
    assert_eq!(
        verify_preparation_commission_admission_evidence(&fixture.root)
            .unwrap_err()
            .code,
        PreparationCommissionAdmissionFaultCode::Manifest
    );

    let forms = Forms::new();
    let mut laundered = forms.receipt.clone();
    laundered.physical_contact = true;
    laundered.receipt_sha256 = preparation_commission_admission_receipt_digest(&laundered).unwrap();
    assert_eq!(
        from_preparation_commission_admission_receipt_machine_form(
            &serde_json::to_string(&laundered).unwrap()
        )
        .unwrap_err()
        .code,
        PreparationCommissionAdmissionFaultCode::Receipt
    );
}

#[test]
fn static_surface_has_no_effect_broker_or_hidden_ninth_step() {
    let source = include_str!(
        "../src/self_work_update_broker_b1_cdrive_preparation_commission_admission.rs"
    );
    for forbidden in [
        "std::process::Command",
        "Command::new",
        "fs::write",
        "File::create",
        "OpenOptions",
        "TcpStream",
        "UdpSocket",
        "remove_dir",
        "remove_file",
        "create_dir",
        "unsafe {",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }
    assert_eq!(PREPARATION_FENCE_STEPS.len(), 10);
    assert!(source.contains("actual_fence_step_count: fence.steps.len() as u8"));
    assert!(source.contains("fence.declared_step_count == 10"));
    assert!(source.contains("fence.maximum_step_count == 10"));
}
