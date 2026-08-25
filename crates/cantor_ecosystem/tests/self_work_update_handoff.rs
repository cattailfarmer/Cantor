#[path = "../../cantor_core/tests/objective_work_plan.rs"]
mod objective_work_plan_fixture;

use std::{collections::BTreeSet, path::PathBuf};

use cantor_core::*;
use cantor_ecosystem::*;
use objective_work_plan_fixture::fixture_request;
use serde::Serialize;
use serde_json::json;

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn digest(symbol: char) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: symbol.to_string().repeat(64),
    }
}

fn lifecycle_request() -> SelfWorkLifecycleRequest {
    SelfWorkLifecycleRequest {
        profile: SELF_WORK_LIFECYCLE_REQUEST_PROFILE.to_owned(),
        lifecycle_id: id("self-work-lifecycle:update-handoff"),
        work_plan_proposal: compile_objective_work_plan(&fixture_request())
            .expect("work plan proposal"),
        maximum_transitions: 32,
        evidence_refs: [id("evidence:update-handoff-lifecycle")]
            .into_iter()
            .collect(),
        unresolved_account: [
            "capabilities_not_granted",
            "physical_work_unobserved",
            "succeeding_sop_not_authored",
            "updates_not_applied",
            "workspace_not_admitted",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        non_authority: SELF_WORK_LIFECYCLE_NON_AUTHORITY.to_owned(),
    }
}

fn fixture_root() -> PathBuf {
    std::env::current_dir()
        .expect("current directory")
        .join("target")
        .join("update-handoff-fixture")
}

fn workspace_request() -> CandidateWorkspaceRequest {
    let root = fixture_root();
    CandidateWorkspaceRequest {
        profile: CANDIDATE_WORKSPACE_ADMISSION_PROFILE.to_owned(),
        candidate_uuid: "2aec5ded-f9d2-4523-8433-d5f53f9b3caf".to_owned(),
        correlation_uuid: "0f9f23b1-7460-4aea-a463-d14e8fef842c".to_owned(),
        admission_nonce: "swa04a-fixture:001".to_owned(),
        git_executable: root.join("pinned-git"),
        git_executable_sha256: "a".repeat(64),
        git_version: "git version 2.51.0".to_owned(),
        principal_workspace: root.join("principal"),
        candidate_workspace: root.join("candidate"),
        expected_repository_common_dir: root.join("repository-common"),
        expected_base_commit: "b".repeat(40),
        expected_branch_ref: "refs/heads/codex/swa04a-fixture".to_owned(),
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

fn receipt_body(receipt: &AdmissionReceipt) -> ReceiptBodyFixture {
    ReceiptBodyFixture {
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
    }
}

fn rehash_receipt(receipt: &mut AdmissionReceipt) {
    receipt.receipt_sha256 = sha256_digest(&receipt_body(receipt)).expect("receipt digest");
}

fn admission_receipt(request: &CandidateWorkspaceRequest) -> AdmissionReceipt {
    let common = request.expected_repository_common_dir.clone();
    let mut receipt = AdmissionReceipt {
        profile: CANDIDATE_WORKSPACE_ADMISSION_PROFILE.to_owned(),
        request_sha256: sha256_digest(request).expect("request digest"),
        receipt_sha256: digest('0'),
        observation_sha256: digest('c'),
        candidate_uuid: request.candidate_uuid.clone(),
        correlation_uuid: request.correlation_uuid.clone(),
        admission_nonce: request.admission_nonce.clone(),
        git_executable_sha256: request.git_executable_sha256.clone(),
        git_version: request.git_version.clone(),
        principal_workspace: request.principal_workspace.clone(),
        candidate_workspace: request.candidate_workspace.clone(),
        repository_common_dir: common.clone(),
        candidate_git_dir: common.join("worktrees").join("candidate"),
        base_commit: request.expected_base_commit.clone(),
        branch_ref: request.expected_branch_ref.clone(),
        allowed_relative_paths: request.allowed_relative_paths.clone(),
        resource_account: AdmissionResourceAccount {
            process_count: 12,
            received_bytes: 1_024,
            configured_timeout_millis: request.budget.timeout_millis,
        },
        admitted: true,
    };
    rehash_receipt(&mut receipt);
    receipt
}

fn proposed_changes() -> Vec<ProposedPathChange> {
    vec![
        ProposedPathChange {
            relative_path: "Cargo.toml".to_owned(),
            change_kind: CandidateChangeKind::Add,
            expected_base_sha256: None,
            desired_content_sha256: Some(digest('1')),
            desired_mode: Some("100644".to_owned()),
        },
        ProposedPathChange {
            relative_path: "crates/cantor_ecosystem/src/lib.rs".to_owned(),
            change_kind: CandidateChangeKind::Modify,
            expected_base_sha256: Some(digest('2')),
            desired_content_sha256: Some(digest('3')),
            desired_mode: Some("100644".to_owned()),
        },
        ProposedPathChange {
            relative_path: "docs/old.md".to_owned(),
            change_kind: CandidateChangeKind::Delete,
            expected_base_sha256: Some(digest('4')),
            desired_content_sha256: None,
            desired_mode: None,
        },
        ProposedPathChange {
            relative_path: "scripts/run.sh".to_owned(),
            change_kind: CandidateChangeKind::ModeChange,
            expected_base_sha256: Some(digest('5')),
            desired_content_sha256: Some(digest('5')),
            desired_mode: Some("100755".to_owned()),
        },
    ]
}

pub(crate) fn handoff_request() -> SelfWorkUpdateHandoffRequest {
    let lifecycle_request = lifecycle_request();
    let lifecycle_checkpoint = compile_self_work_lifecycle(&lifecycle_request)
        .expect("lifecycle")
        .checkpoint;
    let selected_step_ref = lifecycle_request.work_plan_proposal.request.plan.steps[0]
        .step_id
        .clone();
    let selected_attempt_ref = lifecycle_checkpoint.step_states[&selected_step_ref]
        .attempt_ref
        .clone();
    let workspace_request = workspace_request();
    let prior_admission_receipt = admission_receipt(&workspace_request);
    SelfWorkUpdateHandoffRequest {
        profile: SELF_WORK_UPDATE_HANDOFF_REQUEST_PROFILE.to_owned(),
        handoff_id: id("self-work-update-handoff:fixture"),
        phase3_machine_forms_profile: PHASE3_MACHINE_FORMS_PROFILE.to_owned(),
        lifecycle_request,
        lifecycle_checkpoint,
        selected_step_ref,
        selected_attempt_ref,
        workspace_request,
        prior_admission_receipt,
        proposed_changes: proposed_changes(),
        evidence_refs: [id("evidence:self-work-update-handoff")]
            .into_iter()
            .collect(),
        unresolved_account: SELF_WORK_UPDATE_HANDOFF_REQUIRED_UNRESOLVED
            .into_iter()
            .map(str::to_owned)
            .collect(),
        verification_obligations: SELF_WORK_UPDATE_HANDOFF_VERIFICATION_OBLIGATIONS
            .into_iter()
            .map(str::to_owned)
            .collect(),
        non_authority: SELF_WORK_UPDATE_HANDOFF_NON_AUTHORITY.to_owned(),
    }
}

fn refresh_admission(request: &mut SelfWorkUpdateHandoffRequest) {
    request.prior_admission_receipt = admission_receipt(&request.workspace_request);
}

#[test]
fn valid_handoff_is_deterministic_strict_and_awaits_physical_revalidation() {
    let request = handoff_request();
    let proposal = compile_self_work_update_handoff(&request).expect("proposal");
    assert_eq!(
        proposal.disposition,
        SelfWorkUpdateHandoffDisposition::PreparedAwaitingPhysicalRevalidation
    );
    assert_eq!(
        proposal.authority,
        SelfWorkUpdateHandoffAuthority::RepresentationOnly
    );
    assert_eq!(
        proposal.fault_disposition,
        SelfWorkUpdateFaultDisposition::QuarantineWithoutCleanup
    );
    assert_eq!(proposal.proposed_changes.len(), 4);
    assert_eq!(
        proposal,
        compile_self_work_update_handoff(&request).expect("deterministic replay")
    );

    let request_form = to_self_work_update_handoff_request_machine_form(&request).expect("form");
    assert_eq!(
        request,
        from_self_work_update_handoff_request_machine_form(&request_form).expect("round trip")
    );
    let proposal_form = to_self_work_update_handoff_proposal_machine_form(&proposal).expect("form");
    assert_eq!(
        proposal,
        from_self_work_update_handoff_proposal_machine_form(&proposal_form).expect("round trip")
    );
}

#[test]
fn stale_nonready_and_substituted_attempts_refuse_without_changing_input() {
    let mut request = handoff_request();
    request.lifecycle_checkpoint.checkpoint_digest = digest('9');
    assert_eq!(
        validate_self_work_update_handoff_request(&request)
            .expect_err("stale checkpoint")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidLifecycle
    );

    let request = handoff_request();
    let before = request.clone();
    let selected = request.selected_step_ref.clone();
    let state = &request.lifecycle_checkpoint.step_states[&selected];
    let transition = SelfWorkLifecycleTransition {
        profile: SELF_WORK_LIFECYCLE_TRANSITION_PROFILE.to_owned(),
        transition_id: id("self-work-transition:update-handoff-start"),
        lifecycle_ref: request.lifecycle_request.lifecycle_id.clone(),
        sequence: 1,
        predecessor_checkpoint_digest: request.lifecycle_checkpoint.checkpoint_digest.clone(),
        step_ref: selected.clone(),
        attempt_ref: state.attempt_ref.clone(),
        kind: SelfWorkTransitionKind::Start,
        prior_state: SelfWorkLifecycleState::ReadyAwaitingAdmission,
        successor_state: SelfWorkLifecycleState::Active,
        capability_receipt: Some(ExternalReceiptReference {
            receipt_profile: "capability-receipt/fixture".to_owned(),
            receipt_ref: id("capability-receipt:update-handoff"),
            receipt_digest: digest('6'),
        }),
        review_receipt: None,
        evidence_refs: [id("evidence:update-handoff-start")].into_iter().collect(),
    };
    let mut nonready = request.clone();
    nonready.lifecycle_checkpoint = advance_self_work_lifecycle(
        &nonready.lifecycle_request,
        &nonready.lifecycle_checkpoint,
        &transition,
    )
    .expect("valid active checkpoint");
    assert_eq!(
        validate_self_work_update_handoff_request(&nonready)
            .expect_err("nonready")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidState
    );

    let mut substituted = request.clone();
    substituted.selected_attempt_ref = id("self-work-attempt:substituted");
    assert_eq!(
        validate_self_work_update_handoff_request(&substituted)
            .expect_err("attempt")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidState
    );
    assert_eq!(request, before);
}

#[test]
fn workspace_claim_and_supplied_receipt_substitutions_refuse() {
    let mut request = handoff_request();
    request.workspace_request.admission_nonce = "bad nonce".to_owned();
    refresh_admission(&mut request);
    assert_eq!(
        validate_self_work_update_handoff_request(&request)
            .expect_err("workspace claim")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidWorkspaceClaim
    );

    let mut request = handoff_request();
    request.prior_admission_receipt.request_sha256 = digest('d');
    rehash_receipt(&mut request.prior_admission_receipt);
    assert_eq!(
        validate_self_work_update_handoff_request(&request)
            .expect_err("request digest")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidAdmissionReceipt
    );

    let mut request = handoff_request();
    request.prior_admission_receipt.base_commit = "e".repeat(40);
    rehash_receipt(&mut request.prior_admission_receipt);
    assert_eq!(
        validate_self_work_update_handoff_request(&request)
            .expect_err("receipt field")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidAdmissionReceipt
    );

    let mut request = handoff_request();
    request.prior_admission_receipt.receipt_sha256 = digest('f');
    assert_eq!(
        validate_self_work_update_handoff_request(&request)
            .expect_err("receipt digest")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidAdmissionReceipt
    );
}

#[test]
fn self_consistent_observation_substitution_still_has_only_nonfresh_authority() {
    let mut request = handoff_request();
    request.prior_admission_receipt.observation_sha256 = digest('d');
    rehash_receipt(&mut request.prior_admission_receipt);
    let proposal = compile_self_work_update_handoff(&request).expect("self-consistent form");
    assert_eq!(
        proposal.disposition,
        SelfWorkUpdateHandoffDisposition::PreparedAwaitingPhysicalRevalidation
    );
    assert!(proposal.non_authority.contains("not authenticated"));
    assert!(proposal.non_authority.contains("or fresh"));
}

#[test]
fn path_order_widening_and_historical_profile_refuse() {
    let mut request = handoff_request();
    request.proposed_changes.swap(0, 1);
    assert_eq!(
        validate_self_work_update_handoff_request(&request)
            .expect_err("ordering")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidPath
    );

    let mut request = handoff_request();
    request.proposed_changes[0].relative_path = "outside.txt".to_owned();
    assert_eq!(
        validate_self_work_update_handoff_request(&request)
            .expect_err("widening")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidPath
    );

    let mut request = handoff_request();
    request.phase3_machine_forms_profile = "cantor-phase3-machine-forms/0.1".to_owned();
    assert_eq!(
        validate_self_work_update_handoff_request(&request)
            .expect_err("historical profile")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidProfile
    );
}

#[test]
fn every_change_shape_digest_and_mode_substitution_refuses() {
    let mut variants = Vec::new();
    let mut request = handoff_request();
    request.proposed_changes[0].expected_base_sha256 = Some(digest('1'));
    variants.push(request);
    let mut request = handoff_request();
    request.proposed_changes[1].desired_content_sha256 = Some(digest('2'));
    variants.push(request);
    let mut request = handoff_request();
    request.proposed_changes[2].desired_mode = Some("100644".to_owned());
    variants.push(request);
    let mut request = handoff_request();
    request.proposed_changes[3].desired_content_sha256 = Some(digest('6'));
    variants.push(request);
    let mut request = handoff_request();
    request.proposed_changes[0].desired_mode = Some("100777".to_owned());
    variants.push(request);
    let mut request = handoff_request();
    request.proposed_changes[0]
        .desired_content_sha256
        .as_mut()
        .expect("digest")
        .value = "A".repeat(64);
    variants.push(request);
    for variant in variants {
        assert!(matches!(
            validate_self_work_update_handoff_request(&variant)
                .expect_err("change substitution")
                .code,
            SelfWorkUpdateHandoffFaultCode::InvalidChange
                | SelfWorkUpdateHandoffFaultCode::InvalidDigest
        ));
    }
}

#[test]
fn change_evidence_and_machine_bounds_refuse() {
    let mut request = handoff_request();
    request.proposed_changes.clear();
    assert_eq!(
        validate_self_work_update_handoff_request(&request)
            .expect_err("empty changes")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidBound
    );

    let mut request = handoff_request();
    request.evidence_refs.clear();
    assert_eq!(
        validate_self_work_update_handoff_request(&request)
            .expect_err("empty evidence")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidEvidence
    );

    let oversized = " ".repeat(8 * 1024 * 1024 + 1);
    assert_eq!(
        from_self_work_update_handoff_request_machine_form(&oversized)
            .expect_err("machine bound")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidBound
    );
}

#[test]
fn unresolved_authority_unknown_fields_and_trailing_content_refuse() {
    let mut request = handoff_request();
    request
        .unresolved_account
        .remove("physical_freshness_unverified");
    assert_eq!(
        validate_self_work_update_handoff_request(&request)
            .expect_err("unresolved")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidUnresolvedAccount
    );

    let mut request = handoff_request();
    request.non_authority.push_str(" Freshness granted.");
    assert_eq!(
        validate_self_work_update_handoff_request(&request)
            .expect_err("authority")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidAuthority
    );

    let mut value = serde_json::to_value(handoff_request()).expect("value");
    value
        .as_object_mut()
        .expect("object")
        .insert("apply_updates".to_owned(), json!(true));
    assert_eq!(
        from_self_work_update_handoff_request_machine_form(&value.to_string())
            .expect_err("unknown")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidMachineForm
    );

    let form = to_self_work_update_handoff_request_machine_form(&handoff_request()).expect("form");
    assert_eq!(
        from_self_work_update_handoff_request_machine_form(&format!("{form} true"))
            .expect_err("trailing")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidMachineForm
    );
}

#[test]
fn output_field_and_digest_substitutions_refuse() {
    let request = handoff_request();
    let proposal = compile_self_work_update_handoff(&request).expect("proposal");

    let mut changed = proposal.clone();
    changed.workspace_candidate_uuid = "f3e5e01c-3225-43d0-be3e-6f4b1537f838".to_owned();
    assert_eq!(
        validate_self_work_update_handoff_proposal(&request, &changed)
            .expect_err("output field")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidCorrespondence
    );

    let mut changed = proposal.clone();
    changed.authority = SelfWorkUpdateHandoffAuthority::RepresentationOnly;
    changed
        .non_authority
        .push_str(" Physical authority granted.");
    assert_eq!(
        validate_self_work_update_handoff_proposal(&request, &changed)
            .expect_err("output authority")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidCorrespondence
    );

    let mut changed = proposal.clone();
    changed.request_digest = digest('e');
    assert_eq!(
        validate_self_work_update_handoff_proposal(&request, &changed)
            .expect_err("request digest")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidDigest
    );

    let mut changed = proposal;
    changed.proposal_digest = digest('f');
    assert_eq!(
        validate_self_work_update_handoff_proposal(&request, &changed)
            .expect_err("proposal digest")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidDigest
    );
}

#[test]
fn pure_child_source_has_no_effect_route() {
    let source = include_str!("../src/workspace_admission/update_handoff.rs");
    for forbidden in [
        "std::fs",
        "std::process",
        "Command::",
        "File::",
        "SystemTime",
        "TcpStream",
        "unsafe {",
    ] {
        assert!(
            !source.contains(forbidden),
            "effect route entered pure child: {forbidden}"
        );
    }
}

#[test]
fn exact_sixty_four_change_ceiling_is_admitted_and_sixty_five_refuses() {
    let mut request = handoff_request();
    request.workspace_request.allowed_relative_paths = (0..65)
        .map(|index| format!("bounded/path-{index:02}.txt"))
        .collect();
    request.proposed_changes = request
        .workspace_request
        .allowed_relative_paths
        .iter()
        .take(64)
        .map(|path| ProposedPathChange {
            relative_path: path.clone(),
            change_kind: CandidateChangeKind::Add,
            expected_base_sha256: None,
            desired_content_sha256: Some(digest('7')),
            desired_mode: Some("100644".to_owned()),
        })
        .collect();
    refresh_admission(&mut request);
    assert!(validate_self_work_update_handoff_request(&request).is_ok());
    request.proposed_changes.push(ProposedPathChange {
        relative_path: request.workspace_request.allowed_relative_paths[64].clone(),
        change_kind: CandidateChangeKind::Add,
        expected_base_sha256: None,
        desired_content_sha256: Some(digest('8')),
        desired_mode: Some("100644".to_owned()),
    });
    assert_eq!(
        validate_self_work_update_handoff_request(&request)
            .expect_err("sixty five")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidBound
    );
}

#[test]
fn evidence_upper_bound_is_exact() {
    let mut request = handoff_request();
    request.evidence_refs = (0..64)
        .map(|index| id(&format!("evidence:update-handoff:{index}")))
        .collect::<BTreeSet<_>>();
    assert!(validate_self_work_update_handoff_request(&request).is_ok());
    request
        .evidence_refs
        .insert(id("evidence:update-handoff:overflow"));
    assert_eq!(
        validate_self_work_update_handoff_request(&request)
            .expect_err("evidence overflow")
            .code,
        SelfWorkUpdateHandoffFaultCode::InvalidEvidence
    );
}
