#[path = "succeeding_sop_review_admission.rs"]
mod review_fixture;

use std::{
    io::Write,
    process::{Command, Stdio},
};

use cantor_core::*;
use serde_json::Value;

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

pub(crate) fn activation_request(
    status: SucceedingSopActivationPolicyUseStatus,
) -> SucceedingSopActivationTransactionRequest {
    let review_request = review_fixture::admission_request(
        SucceedingSopReviewerPolicyUseStatus::SyntheticFixtureOnly,
    );
    let review_admission = admit_succeeding_sop_review(&review_request).expect("review admission");
    let proposal = &review_admission.request.proposal_verification.proposal;
    let preservation = &review_admission.request.source_preservation;

    let mut activation_policy = SucceedingSopActivationPolicy {
        profile: SUCCEEDING_SOP_ACTIVATION_POLICY_PROFILE.to_owned(),
        use_status: status,
        policy_ref: id("activation-policy:swa-06b2a-fixture"),
        activation_authority_ref: id("activation-authority:independent-fixture"),
        recovery_owner_ref: id("recovery-owner:independent-fixture"),
        registry_ref: id("registry:current-sop-fixture"),
        allowed_review_receipt_profile: SUCCEEDING_SOP_REVIEW_ADMISSION_RECEIPT_PROFILE.to_owned(),
        required_acquisition_mode: SucceedingSopSourceAcquisitionMode::ExactRawBytesReopenNoFollow,
        required_atomicity: SucceedingSopRegistryAtomicity::SameVolumeReplaceRequired,
        required_durability: SucceedingSopRegistryDurability::FileAndParentFlushRequired,
        governance_evidence_refs: [id("evidence:activation-policy-governance")]
            .into_iter()
            .collect(),
        non_authority: SUCCEEDING_SOP_ACTIVATION_TRANSACTION_NON_AUTHORITY.to_owned(),
        policy_digest: empty_digest(),
    };
    activation_policy.policy_digest =
        succeeding_sop_activation_policy_digest(&activation_policy).expect("policy digest");

    let mut source_reacquisition = SucceedingSopSourceReacquisitionPlan {
        profile: SUCCEEDING_SOP_SOURCE_REACQUISITION_PLAN_PROFILE.to_owned(),
        plan_ref: id("source-reacquisition:swa-06b2a-fixture"),
        repository_root_ref: id("repository-root:cantor-fixture"),
        preservation_ref: preservation.preservation_ref.clone(),
        source_snapshot_ref: preservation.source_snapshot_ref.clone(),
        source_path: preservation.source_path.clone(),
        source_subject: preservation.source_subject.clone(),
        source_sha256: preservation.source_sha256.clone(),
        source_bytes: preservation.source_bytes,
        proposal_digest: preservation.proposal_digest.clone(),
        immutable_required: true,
        no_normalization: true,
        acquisition_mode: SucceedingSopSourceAcquisitionMode::ExactRawBytesReopenNoFollow,
        evidence_refs: [id("evidence:source-reacquisition-required")]
            .into_iter()
            .collect(),
        plan_digest: empty_digest(),
    };
    source_reacquisition.plan_digest =
        succeeding_sop_source_reacquisition_plan_digest(&source_reacquisition)
            .expect("source plan digest");

    let mut current_registry = SucceedingSopCurrentRegistrySnapshot {
        profile: SUCCEEDING_SOP_CURRENT_REGISTRY_SNAPSHOT_PROFILE.to_owned(),
        snapshot_ref: id("registry-snapshot:swa-06b2a-fixture"),
        registry_ref: activation_policy.registry_ref.clone(),
        registry_path: "narrative/registries/Cantor_Current_SOP_Fixture.sop".to_owned(),
        generation: 41,
        current_revision_ref: proposal.predecessor_sop_revision_ref.clone(),
        current_revision_digest: proposal.predecessor_sop_revision_digest.clone(),
        current_source_path: "source_documents/current_sop_fixture/Cantor_Current_SOP_Source.sop"
            .to_owned(),
        evidence_refs: [id("evidence:current-registry-supplied")]
            .into_iter()
            .collect(),
        snapshot_digest: empty_digest(),
    };
    current_registry.snapshot_digest =
        succeeding_sop_current_registry_snapshot_digest(&current_registry)
            .expect("registry snapshot digest");

    let mut transition = SucceedingSopRegistryTransitionPlan {
        profile: SUCCEEDING_SOP_REGISTRY_TRANSITION_PLAN_PROFILE.to_owned(),
        transaction_ref: id("activation-transaction:swa-06b2a-fixture"),
        expected_registry_snapshot_digest: current_registry.snapshot_digest.clone(),
        registry_ref: current_registry.registry_ref.clone(),
        registry_final_path: current_registry.registry_path.clone(),
        registry_temp_path: "narrative/registries/Cantor_Current_SOP_Fixture.sop.next.tmp"
            .to_owned(),
        before_generation: current_registry.generation,
        after_generation: current_registry.generation + 1,
        candidate_proposal_ref: proposal.proposal_ref.clone(),
        candidate_proposal_digest: proposal.proposal_digest.clone(),
        candidate_source_path: source_reacquisition.source_path.clone(),
        candidate_source_sha256: source_reacquisition.source_sha256.clone(),
        activation_authority_ref: activation_policy.activation_authority_ref.clone(),
        recovery_owner_ref: activation_policy.recovery_owner_ref.clone(),
        write_protocol: SUCCEEDING_SOP_ACTIVATION_WRITE_PROTOCOL
            .into_iter()
            .map(str::to_owned)
            .collect(),
        atomicity: SucceedingSopRegistryAtomicity::SameVolumeReplaceRequired,
        durability: SucceedingSopRegistryDurability::FileAndParentFlushRequired,
        transition_digest: empty_digest(),
    };
    transition.transition_digest =
        succeeding_sop_registry_transition_plan_digest(&transition).expect("transition digest");

    let mut supersession = SucceedingSopSupersessionPlan {
        profile: SUCCEEDING_SOP_SUPERSESSION_PLAN_PROFILE.to_owned(),
        supersession_ref: id("supersession:swa-06b2a-fixture"),
        predecessor_revision_ref: current_registry.current_revision_ref.clone(),
        predecessor_revision_digest: current_registry.current_revision_digest.clone(),
        predecessor_source_path: current_registry.current_source_path.clone(),
        predecessor_generation: current_registry.generation,
        successor_proposal_ref: proposal.proposal_ref.clone(),
        successor_proposal_digest: proposal.proposal_digest.clone(),
        successor_source_path: source_reacquisition.source_path.clone(),
        reason: "independently reviewed succeeding SOP fixture".to_owned(),
        preserve_predecessor: true,
        evidence_refs: [id("evidence:supersession-planned")].into_iter().collect(),
        supersession_digest: empty_digest(),
    };
    supersession.supersession_digest =
        succeeding_sop_supersession_plan_digest(&supersession).expect("supersession digest");

    let mut rollback = SucceedingSopRollbackPlan {
        profile: SUCCEEDING_SOP_ROLLBACK_PLAN_PROFILE.to_owned(),
        rollback_ref: id("rollback:swa-06b2a-fixture"),
        recovery_owner_ref: activation_policy.recovery_owner_ref.clone(),
        rollback_revision_ref: current_registry.current_revision_ref.clone(),
        rollback_revision_digest: current_registry.current_revision_digest.clone(),
        rollback_source_path: current_registry.current_source_path.clone(),
        failed_candidate_ref: proposal.proposal_ref.clone(),
        failed_candidate_digest: proposal.proposal_digest.clone(),
        expected_registry_generation: transition.after_generation,
        triggers: SUCCEEDING_SOP_ACTIVATION_ROLLBACK_TRIGGERS
            .into_iter()
            .map(str::to_owned)
            .collect(),
        preserve_failed_candidate: true,
        evidence_refs: [id("evidence:rollback-planned")].into_iter().collect(),
        rollback_digest: empty_digest(),
    };
    rollback.rollback_digest =
        succeeding_sop_rollback_plan_digest(&rollback).expect("rollback digest");

    SucceedingSopActivationTransactionRequest {
        profile: SUCCEEDING_SOP_ACTIVATION_TRANSACTION_REQUEST_PROFILE.to_owned(),
        admission_id: id("activation-admission:swa-06b2a-fixture"),
        review_admission,
        activation_policy,
        source_reacquisition,
        current_registry,
        transition,
        supersession,
        rollback,
        activation_obligations: SUCCEEDING_SOP_ACTIVATION_OBLIGATIONS
            .into_iter()
            .map(str::to_owned)
            .collect(),
        non_authority: SUCCEEDING_SOP_ACTIVATION_TRANSACTION_NON_AUTHORITY.to_owned(),
    }
}

fn rehash_policy(request: &mut SucceedingSopActivationTransactionRequest) {
    request.activation_policy.policy_digest = empty_digest();
    request.activation_policy.policy_digest =
        succeeding_sop_activation_policy_digest(&request.activation_policy).expect("policy digest");
}

fn rehash_source(request: &mut SucceedingSopActivationTransactionRequest) {
    request.source_reacquisition.plan_digest = empty_digest();
    request.source_reacquisition.plan_digest =
        succeeding_sop_source_reacquisition_plan_digest(&request.source_reacquisition)
            .expect("source digest");
}

fn rehash_registry(request: &mut SucceedingSopActivationTransactionRequest) {
    request.current_registry.snapshot_digest = empty_digest();
    request.current_registry.snapshot_digest =
        succeeding_sop_current_registry_snapshot_digest(&request.current_registry)
            .expect("registry digest");
}

fn rehash_transition(request: &mut SucceedingSopActivationTransactionRequest) {
    request.transition.transition_digest = empty_digest();
    request.transition.transition_digest =
        succeeding_sop_registry_transition_plan_digest(&request.transition)
            .expect("transition digest");
}

fn rehash_supersession(request: &mut SucceedingSopActivationTransactionRequest) {
    request.supersession.supersession_digest = empty_digest();
    request.supersession.supersession_digest =
        succeeding_sop_supersession_plan_digest(&request.supersession)
            .expect("supersession digest");
}

fn rehash_rollback(request: &mut SucceedingSopActivationTransactionRequest) {
    request.rollback.rollback_digest = empty_digest();
    request.rollback.rollback_digest =
        succeeding_sop_rollback_plan_digest(&request.rollback).expect("rollback digest");
}

#[test]
fn activation_transaction_is_deterministic_complete_and_physically_ineligible() {
    for status in [
        SucceedingSopActivationPolicyUseStatus::ExternallyGoverned,
        SucceedingSopActivationPolicyUseStatus::SyntheticFixtureOnly,
    ] {
        let request = activation_request(status);
        let receipt =
            admit_succeeding_sop_activation_transaction(&request).expect("transaction admission");
        assert_eq!(receipt.policy_use_status, status);
        assert_eq!(
            receipt.status,
            SucceedingSopActivationTransactionStatus::TransactionCorrespondenceVerifiedAwaitingPhysicalExecution
        );
        assert_eq!(
            receipt.authority,
            SucceedingSopActivationTransactionAuthority::SuppliedActivationPlanCorrespondenceOnly
        );
        assert!(receipt.upstream_review_verified);
        assert!(receipt.transaction_correspondence_verified);
        assert!(!receipt.physical_contact);
        assert!(!receipt.source_reacquired);
        assert!(!receipt.registry_observed);
        assert!(!receipt.registry_persisted);
        assert!(!receipt.current_sop_selected);
        assert!(!receipt.boot_activation_verified);
        assert!(!receipt.rollback_executed);
        assert!(!receipt.physical_execution_eligible);
        assert_eq!(receipt.verified_checks.len(), 10);
        assert_eq!(receipt.activation_obligations.len(), 6);
        assert_eq!(
            receipt,
            admit_succeeding_sop_activation_transaction(&request).expect("deterministic replay")
        );

        let request_form = to_succeeding_sop_activation_transaction_request_machine_form(&request)
            .expect("request form");
        assert_eq!(
            request,
            from_succeeding_sop_activation_transaction_request_machine_form(&request_form)
                .expect("request round trip")
        );
        let receipt_form = to_succeeding_sop_activation_transaction_receipt_machine_form(&receipt)
            .expect("receipt form");
        assert_eq!(
            receipt,
            from_succeeding_sop_activation_transaction_receipt_machine_form(&receipt_form)
                .expect("receipt round trip")
        );
    }
}

#[test]
fn upstream_and_policy_laundering_refuse() {
    let request = activation_request(SucceedingSopActivationPolicyUseStatus::SyntheticFixtureOnly);
    let mut upstream = request.clone();
    upstream.review_admission.physical_activation_eligible = true;
    assert_eq!(
        validate_succeeding_sop_activation_transaction_request(&upstream)
            .expect_err("upstream laundering")
            .code,
        SucceedingSopActivationTransactionFaultCode::InvalidUpstream
    );

    let mut policy = request.clone();
    policy.activation_policy.allowed_review_receipt_profile = "wrong/0.1".to_owned();
    rehash_policy(&mut policy);
    assert_eq!(
        validate_succeeding_sop_activation_transaction_request(&policy)
            .expect_err("policy substitution")
            .code,
        SucceedingSopActivationTransactionFaultCode::InvalidPolicy
    );
}

#[test]
fn duty_and_evidence_identity_collisions_refuse() {
    let request = activation_request(SucceedingSopActivationPolicyUseStatus::SyntheticFixtureOnly);
    let mut duty = request.clone();
    duty.activation_policy.recovery_owner_ref =
        duty.activation_policy.activation_authority_ref.clone();
    duty.transition.recovery_owner_ref = duty.activation_policy.recovery_owner_ref.clone();
    duty.rollback.recovery_owner_ref = duty.activation_policy.recovery_owner_ref.clone();
    rehash_policy(&mut duty);
    rehash_transition(&mut duty);
    rehash_rollback(&mut duty);
    assert_eq!(
        validate_succeeding_sop_activation_transaction_request(&duty)
            .expect_err("duty collapse")
            .code,
        SucceedingSopActivationTransactionFaultCode::InvalidIdentity
    );

    let mut evidence = request.clone();
    evidence.source_reacquisition.evidence_refs =
        evidence.activation_policy.governance_evidence_refs.clone();
    rehash_source(&mut evidence);
    assert_eq!(
        validate_succeeding_sop_activation_transaction_request(&evidence)
            .expect_err("evidence collision")
            .code,
        SucceedingSopActivationTransactionFaultCode::InvalidIdentity
    );
}

#[test]
fn source_and_path_substitutions_refuse() {
    let request = activation_request(SucceedingSopActivationPolicyUseStatus::SyntheticFixtureOnly);
    let mut source = request.clone();
    source.source_reacquisition.source_bytes += 1;
    rehash_source(&mut source);
    assert_eq!(
        validate_succeeding_sop_activation_transaction_request(&source)
            .expect_err("source byte substitution")
            .code,
        SucceedingSopActivationTransactionFaultCode::InvalidSource
    );

    let mut path = request.clone();
    path.current_registry.registry_path = "narrative/registries/../escape.sop".to_owned();
    rehash_registry(&mut path);
    assert_eq!(
        validate_succeeding_sop_activation_transaction_request(&path)
            .expect_err("registry path escape")
            .code,
        SucceedingSopActivationTransactionFaultCode::InvalidPath
    );
}

#[test]
fn predecessor_generation_and_snapshot_substitutions_refuse() {
    let request = activation_request(SucceedingSopActivationPolicyUseStatus::SyntheticFixtureOnly);
    let mut predecessor = request.clone();
    predecessor.current_registry.current_revision_ref = id("sop-revision:substituted");
    rehash_registry(&mut predecessor);
    assert_eq!(
        validate_succeeding_sop_activation_transaction_request(&predecessor)
            .expect_err("predecessor substitution")
            .code,
        SucceedingSopActivationTransactionFaultCode::InvalidRegistry
    );

    let mut generation = request.clone();
    generation.transition.after_generation += 1;
    rehash_transition(&mut generation);
    assert_eq!(
        validate_succeeding_sop_activation_transaction_request(&generation)
            .expect_err("generation skip")
            .code,
        SucceedingSopActivationTransactionFaultCode::InvalidTransition
    );

    let mut stale = request.clone();
    stale.transition.expected_registry_snapshot_digest = empty_digest();
    rehash_transition(&mut stale);
    assert_eq!(
        validate_succeeding_sop_activation_transaction_request(&stale)
            .expect_err("stale snapshot")
            .code,
        SucceedingSopActivationTransactionFaultCode::InvalidTransition
    );
}

#[test]
fn temporary_parent_and_write_protocol_substitutions_refuse() {
    let request = activation_request(SucceedingSopActivationPolicyUseStatus::SyntheticFixtureOnly);
    let mut parent = request.clone();
    parent.transition.registry_temp_path =
        "narrative/registries/other/Cantor_Current_SOP.tmp".to_owned();
    rehash_transition(&mut parent);
    assert_eq!(
        validate_succeeding_sop_activation_transaction_request(&parent)
            .expect_err("different temporary parent")
            .code,
        SucceedingSopActivationTransactionFaultCode::InvalidPath
    );

    let mut protocol = request.clone();
    protocol.transition.write_protocol.swap(0, 1);
    rehash_transition(&mut protocol);
    assert_eq!(
        validate_succeeding_sop_activation_transaction_request(&protocol)
            .expect_err("write protocol reorder")
            .code,
        SucceedingSopActivationTransactionFaultCode::InvalidTransition
    );
}

#[test]
fn supersession_and_rollback_substitutions_refuse() {
    let request = activation_request(SucceedingSopActivationPolicyUseStatus::SyntheticFixtureOnly);
    let mut supersession = request.clone();
    supersession.supersession.preserve_predecessor = false;
    rehash_supersession(&mut supersession);
    assert_eq!(
        validate_succeeding_sop_activation_transaction_request(&supersession)
            .expect_err("predecessor deletion")
            .code,
        SucceedingSopActivationTransactionFaultCode::InvalidSupersession
    );

    let mut rollback = request.clone();
    rollback.rollback.triggers.remove("operator_abort");
    rehash_rollback(&mut rollback);
    assert_eq!(
        validate_succeeding_sop_activation_transaction_request(&rollback)
            .expect_err("rollback omission")
            .code,
        SucceedingSopActivationTransactionFaultCode::InvalidRollback
    );
}

#[test]
fn obligations_receipt_authority_and_digest_laundering_refuse() {
    let request = activation_request(SucceedingSopActivationPolicyUseStatus::SyntheticFixtureOnly);
    let mut obligations = request.clone();
    obligations
        .activation_obligations
        .remove("never_self_activate");
    assert_eq!(
        validate_succeeding_sop_activation_transaction_request(&obligations)
            .expect_err("obligation omission")
            .code,
        SucceedingSopActivationTransactionFaultCode::InvalidObligation
    );

    let receipt = admit_succeeding_sop_activation_transaction(&request).expect("receipt");
    let mut authority = receipt.clone();
    authority.physical_execution_eligible = true;
    assert_eq!(
        validate_succeeding_sop_activation_transaction_receipt(&authority)
            .expect_err("authority laundering")
            .code,
        SucceedingSopActivationTransactionFaultCode::InvalidCorrespondence
    );

    let mut digest = receipt;
    let replacement = if digest.receipt_digest.value.starts_with('a') {
        "b"
    } else {
        "a"
    };
    digest.receipt_digest.value.replace_range(0..1, replacement);
    assert_eq!(
        validate_succeeding_sop_activation_transaction_receipt(&digest)
            .expect_err("receipt digest substitution")
            .code,
        SucceedingSopActivationTransactionFaultCode::InvalidDigest
    );
}

#[test]
fn machine_forms_refuse_unknown_fields_and_oversize_input() {
    let request = activation_request(SucceedingSopActivationPolicyUseStatus::SyntheticFixtureOnly);
    let form = to_succeeding_sop_activation_transaction_request_machine_form(&request)
        .expect("request form");
    let mut value: Value = serde_json::from_str(&form).expect("json");
    value["unknown_activation_authority"] = Value::Bool(true);
    assert_eq!(
        from_succeeding_sop_activation_transaction_request_machine_form(
            &serde_json::to_string(&value).expect("unknown form")
        )
        .expect_err("unknown field")
        .code,
        SucceedingSopActivationTransactionFaultCode::InvalidMachineForm
    );

    let oversized = "x".repeat(SUCCEEDING_SOP_ACTIVATION_TRANSACTION_MAX_MACHINE_FORM_BYTES + 1);
    assert_eq!(
        from_succeeding_sop_activation_transaction_request_machine_form(&oversized)
            .expect_err("oversize form")
            .code,
        SucceedingSopActivationTransactionFaultCode::InvalidBound
    );
}

#[test]
fn cli_admit_verify_and_static_effect_boundary_hold() {
    let request = activation_request(SucceedingSopActivationPolicyUseStatus::SyntheticFixtureOnly);
    let request_form = to_succeeding_sop_activation_transaction_request_machine_form(&request)
        .expect("request form");
    let binary = match option_env!("CARGO_BIN_EXE_cantor-succeeding-sop-activation-transaction") {
        Some(binary) => binary,
        None => panic!("succeeding SOP activation-transaction test binary is unavailable"),
    };
    let admitted = run_cli(binary, "admit", &request_form);
    assert!(
        admitted.status.success(),
        "{}",
        String::from_utf8_lossy(&admitted.stderr)
    );
    let receipt_form = String::from_utf8(admitted.stdout)
        .expect("admit stdout")
        .trim()
        .to_owned();
    let receipt = from_succeeding_sop_activation_transaction_receipt_machine_form(&receipt_form)
        .expect("CLI receipt");
    assert!(!receipt.physical_execution_eligible);

    let verified = run_cli(binary, "verify", &receipt_form);
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    assert_eq!(
        receipt_form,
        String::from_utf8(verified.stdout)
            .expect("verify stdout")
            .trim()
    );

    let module = include_str!("../src/succeeding_sop_activation_transaction.rs");
    for forbidden in [
        "std::fs",
        "std::env",
        "std::process",
        "std::net",
        "Command::new",
        "OpenOptions",
        "File::create",
        "unsafe {",
    ] {
        assert!(
            !module.contains(forbidden),
            "forbidden production surface: {forbidden}"
        );
    }
}

fn run_cli(binary: &str, operation: &str, input: &str) -> std::process::Output {
    let mut child = Command::new(binary)
        .arg(operation)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn activation transaction CLI");
    child
        .stdin
        .as_mut()
        .expect("CLI stdin")
        .write_all(input.as_bytes())
        .expect("write CLI input");
    child.wait_with_output().expect("CLI output")
}
