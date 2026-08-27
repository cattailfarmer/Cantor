#[path = "self_work_update_handoff.rs"]
mod handoff_fixture;

use std::{
    collections::BTreeSet,
    io::Write,
    process::{Command, Stdio},
};

use cantor_core::*;
use cantor_ecosystem::*;
use handoff_fixture::handoff_request;
use serde_json::Value;

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn digest(symbol: char) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: symbol.to_string().repeat(64),
    }
}

fn external_receipt(label: &str, symbol: char) -> ExternalReceiptReference {
    ExternalReceiptReference {
        receipt_profile: "future-external-receipt/0.1".to_owned(),
        receipt_ref: id(label),
        receipt_digest: digest(symbol),
    }
}

fn transition(
    checkpoint: &SelfWorkLifecycleCheckpoint,
    step_ref: &SemanticId,
    kind: SelfWorkTransitionKind,
    successor_state: SelfWorkLifecycleState,
    extra_evidence: Option<&SemanticId>,
) -> SelfWorkLifecycleTransition {
    let state = checkpoint.step_states.get(step_ref).expect("step state");
    let sequence = checkpoint.sequence + 1;
    let mut evidence_refs = [id(&format!("evidence:composition-transition:{sequence}"))]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if let Some(evidence_ref) = extra_evidence {
        evidence_refs.insert(evidence_ref.clone());
    }
    SelfWorkLifecycleTransition {
        profile: SELF_WORK_LIFECYCLE_TRANSITION_PROFILE.to_owned(),
        transition_id: id(&format!("composition-transition:{sequence}")),
        lifecycle_ref: checkpoint.lifecycle_ref.clone(),
        sequence,
        predecessor_checkpoint_digest: checkpoint.checkpoint_digest.clone(),
        step_ref: step_ref.clone(),
        attempt_ref: state.attempt_ref.clone(),
        kind,
        prior_state: state.state,
        successor_state,
        capability_receipt: matches!(
            kind,
            SelfWorkTransitionKind::Start | SelfWorkTransitionKind::Resume
        )
        .then(|| external_receipt(&format!("composition-capability:{sequence}"), 'a')),
        review_receipt: (kind == SelfWorkTransitionKind::AcceptReview)
            .then(|| external_receipt(&format!("composition-review:{sequence}"), 'b')),
        evidence_refs,
    }
}

fn advance(
    lifecycle: &SelfWorkLifecycleRequest,
    checkpoint: &mut SelfWorkLifecycleCheckpoint,
    step_ref: &SemanticId,
    path: &[(SelfWorkTransitionKind, SelfWorkLifecycleState)],
    bridge: Option<&SemanticId>,
) {
    for (kind, state) in path {
        let extra = (*kind == SelfWorkTransitionKind::AcceptReview)
            .then_some(bridge)
            .flatten();
        let next = transition(checkpoint, step_ref, *kind, *state, extra);
        *checkpoint = advance_self_work_lifecycle(lifecycle, checkpoint, &next).expect("advance");
    }
}

fn complete_step(
    lifecycle: &SelfWorkLifecycleRequest,
    checkpoint: &mut SelfWorkLifecycleCheckpoint,
    step_ref: &SemanticId,
    bridge: Option<&SemanticId>,
) {
    advance(
        lifecycle,
        checkpoint,
        step_ref,
        &[
            (
                SelfWorkTransitionKind::Start,
                SelfWorkLifecycleState::Active,
            ),
            (
                SelfWorkTransitionKind::SubmitForReview,
                SelfWorkLifecycleState::AwaitingReview,
            ),
            (
                SelfWorkTransitionKind::AcceptReview,
                SelfWorkLifecycleState::Complete,
            ),
        ],
        bridge,
    );
}

fn succeeding_request(
    lifecycle: SelfWorkLifecycleRequest,
    checkpoint: SelfWorkLifecycleCheckpoint,
) -> SucceedingSopRequest {
    let selected = &lifecycle.work_plan_proposal.request.plan.steps[5];
    let selected_step_ref = selected.step_id.clone();
    let selected_attempt_ref = checkpoint.step_states[&selected_step_ref]
        .attempt_ref
        .clone();
    let mut work_evidence_refs = lifecycle.evidence_refs.clone();
    work_evidence_refs.extend(selected.evidence_refs.iter().cloned());
    for dependency in &selected.dependency_refs {
        let dependency_step = lifecycle
            .work_plan_proposal
            .request
            .plan
            .steps
            .iter()
            .find(|step| step.step_id == *dependency)
            .expect("dependency step");
        work_evidence_refs.extend(dependency_step.evidence_refs.iter().cloned());
        for item in checkpoint
            .transitions
            .iter()
            .filter(|item| item.step_ref == *dependency)
        {
            work_evidence_refs.extend(item.evidence_refs.iter().cloned());
        }
    }
    SucceedingSopRequest {
        profile: SUCCEEDING_SOP_REQUEST_PROFILE.to_owned(),
        proposal_id: id("succeeding-sop-proposal:composition"),
        lifecycle_request: lifecycle,
        lifecycle_checkpoint: checkpoint,
        selected_step_ref,
        selected_attempt_ref,
        author_ref: id("cantor-agent:composition"),
        authorship_evidence_refs: [id("evidence:composition-authorship")]
            .into_iter()
            .collect(),
        source_subject: "Cantor Provider-Free Composition Successor".to_owned(),
        source_text: "Subject: Cantor Provider-Free Composition Successor\n\n& [Purpose]\n  + continue the exact supplied-data frontier\n".to_owned(),
        work_evidence_refs,
        unresolved_frontier: [
            "independent semantic review remains pending",
            "physical update and publication remain separate",
            "satisfaction signature and activation remain separate",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        review_obligations: SUCCEEDING_SOP_REVIEW_OBLIGATIONS
            .into_iter()
            .map(str::to_owned)
            .collect(),
        non_authority: SUCCEEDING_SOP_NON_AUTHORITY.to_owned(),
    }
}

fn build_succeeding_request(
    lifecycle: SelfWorkLifecycleRequest,
    bridge: &SemanticId,
    bridge_step_index: usize,
) -> SucceedingSopRequest {
    let mut checkpoint = compile_self_work_lifecycle(&lifecycle)
        .expect("lifecycle")
        .checkpoint;
    let steps = lifecycle.work_plan_proposal.request.plan.steps.clone();
    for (index, step) in steps[..5].iter().enumerate() {
        complete_step(
            &lifecycle,
            &mut checkpoint,
            &step.step_id,
            (index == bridge_step_index).then_some(bridge),
        );
    }
    succeeding_request(lifecycle, checkpoint)
}

fn composition_request_with_bridge_step(
    bridge_step_index: usize,
) -> ProviderFreeSelfWorkCompositionRequest {
    let mut handoff = handoff_request();
    let lifecycle = handoff.lifecycle_request.clone();
    let steps = lifecycle.work_plan_proposal.request.plan.steps.clone();
    let bridge = id("evidence:provider-free-composition-bridge");
    let mut prefix = compile_self_work_lifecycle(&lifecycle)
        .expect("lifecycle")
        .checkpoint;
    for step in &steps[..2] {
        complete_step(&lifecycle, &mut prefix, &step.step_id, None);
    }
    handoff.lifecycle_checkpoint = prefix;
    handoff.selected_step_ref = steps[2].step_id.clone();
    handoff.selected_attempt_ref = handoff.lifecycle_checkpoint.step_states
        [&handoff.selected_step_ref]
        .attempt_ref
        .clone();
    handoff.evidence_refs.insert(bridge.clone());
    let succeeding = build_succeeding_request(lifecycle, &bridge, bridge_step_index);
    ProviderFreeSelfWorkCompositionRequest {
        profile: PROVIDER_FREE_SELF_WORK_COMPOSITION_REQUEST_PROFILE.to_owned(),
        composition_id: id("provider-free-self-work-composition:fixture"),
        update_handoff_request: handoff,
        succeeding_sop_request: succeeding,
        bridge_evidence_ref: bridge,
        non_authority: PROVIDER_FREE_SELF_WORK_COMPOSITION_NON_AUTHORITY.to_owned(),
    }
}

fn composition_request() -> ProviderFreeSelfWorkCompositionRequest {
    composition_request_with_bridge_step(2)
}

#[test]
fn complete_chain_is_deterministic_self_contained_and_strict() {
    let request = composition_request();
    let receipt = compile_provider_free_self_work_composition(&request).expect("receipt");
    assert_eq!(receipt.composition_ref, request.composition_id);
    assert_eq!(
        receipt.update_step_ref,
        request.update_handoff_request.selected_step_ref
    );
    assert_eq!(
        receipt.succeeding_step_ref,
        request.succeeding_sop_request.selected_step_ref
    );
    assert_eq!(
        receipt.status,
        ProviderFreeSelfWorkCompositionStatus::ProviderFreeChainCorrespondenceVerified
    );
    assert_eq!(
        receipt.authority,
        ProviderFreeSelfWorkCompositionAuthority::SuppliedDataCorrespondenceOnly
    );
    assert!(!receipt.physical_contact);
    assert_eq!(receipt.stage_account.len(), 6);
    verify_provider_free_self_work_composition(&receipt).expect("verify");
    assert_eq!(
        receipt,
        compile_provider_free_self_work_composition(&request).expect("deterministic replay")
    );

    let request_form = to_provider_free_self_work_composition_request_machine_form(&request)
        .expect("request form");
    assert_eq!(
        request,
        from_provider_free_self_work_composition_request_machine_form(&request_form)
            .expect("request round trip")
    );
    let receipt_form = to_provider_free_self_work_composition_receipt_machine_form(&receipt)
        .expect("receipt form");
    assert_eq!(
        receipt,
        from_provider_free_self_work_composition_receipt_machine_form(&receipt_form)
            .expect("receipt round trip")
    );
}

#[test]
fn identity_downstream_and_lifecycle_substitutions_refuse() {
    let request = composition_request();
    let mut profile = request.clone();
    profile.profile.push_str("-wrong");
    assert_eq!(
        validate_provider_free_self_work_composition_request(&profile)
            .expect_err("profile")
            .code,
        ProviderFreeSelfWorkCompositionFaultCode::InvalidProfile
    );

    let mut collision = request.clone();
    collision.composition_id = collision.update_handoff_request.handoff_id.clone();
    assert_eq!(
        validate_provider_free_self_work_composition_request(&collision)
            .expect_err("collision")
            .code,
        ProviderFreeSelfWorkCompositionFaultCode::InvalidIdentity
    );

    let mut handoff = request.clone();
    handoff
        .update_handoff_request
        .verification_obligations
        .clear();
    assert_eq!(
        validate_provider_free_self_work_composition_request(&handoff)
            .expect_err("handoff")
            .code,
        ProviderFreeSelfWorkCompositionFaultCode::InvalidHandoff
    );

    let mut succeeding = request.clone();
    succeeding.succeeding_sop_request.review_obligations.clear();
    assert_eq!(
        validate_provider_free_self_work_composition_request(&succeeding)
            .expect_err("succeeding")
            .code,
        ProviderFreeSelfWorkCompositionFaultCode::InvalidSucceedingSop
    );

    let mut lifecycle = request;
    let mut alternate = lifecycle.succeeding_sop_request.lifecycle_request.clone();
    alternate.lifecycle_id = id("self-work-lifecycle:composition-alternate");
    lifecycle.succeeding_sop_request =
        build_succeeding_request(alternate, &lifecycle.bridge_evidence_ref, 2);
    assert_eq!(
        validate_provider_free_self_work_composition_request(&lifecycle)
            .expect_err("lifecycle substitution")
            .code,
        ProviderFreeSelfWorkCompositionFaultCode::InvalidLifecycleJoin
    );
}

#[test]
fn prefix_step_class_attempt_and_bridge_laundering_refuse() {
    let request = composition_request();
    let lifecycle = request.update_handoff_request.lifecycle_request.clone();
    let steps = lifecycle.work_plan_proposal.request.plan.steps.clone();

    let mut divergent = request.clone();
    let mut prefix = compile_self_work_lifecycle(&lifecycle)
        .expect("lifecycle")
        .checkpoint;
    complete_step(&lifecycle, &mut prefix, &steps[0].step_id, None);
    advance(
        &lifecycle,
        &mut prefix,
        &steps[1].step_id,
        &[
            (
                SelfWorkTransitionKind::Start,
                SelfWorkLifecycleState::Active,
            ),
            (
                SelfWorkTransitionKind::Stop,
                SelfWorkLifecycleState::Stopped,
            ),
            (
                SelfWorkTransitionKind::MarkResumable,
                SelfWorkLifecycleState::Resumable,
            ),
            (
                SelfWorkTransitionKind::Resume,
                SelfWorkLifecycleState::Active,
            ),
            (
                SelfWorkTransitionKind::SubmitForReview,
                SelfWorkLifecycleState::AwaitingReview,
            ),
            (
                SelfWorkTransitionKind::AcceptReview,
                SelfWorkLifecycleState::Complete,
            ),
        ],
        None,
    );
    divergent.update_handoff_request.lifecycle_checkpoint = prefix;
    divergent.update_handoff_request.selected_attempt_ref = divergent
        .update_handoff_request
        .lifecycle_checkpoint
        .step_states[&divergent.update_handoff_request.selected_step_ref]
        .attempt_ref
        .clone();
    assert_eq!(
        validate_provider_free_self_work_composition_request(&divergent)
            .expect_err("divergent prefix")
            .code,
        ProviderFreeSelfWorkCompositionFaultCode::InvalidLifecycleJoin
    );

    let mut wrong_class = request.clone();
    wrong_class.update_handoff_request.lifecycle_checkpoint =
        compile_self_work_lifecycle(&lifecycle)
            .expect("initial")
            .checkpoint;
    wrong_class.update_handoff_request.selected_step_ref = steps[0].step_id.clone();
    wrong_class.update_handoff_request.selected_attempt_ref = wrong_class
        .update_handoff_request
        .lifecycle_checkpoint
        .step_states[&steps[0].step_id]
        .attempt_ref
        .clone();
    assert_eq!(
        validate_provider_free_self_work_composition_request(&wrong_class)
            .expect_err("wrong update class")
            .code,
        ProviderFreeSelfWorkCompositionFaultCode::InvalidStepClass
    );

    let mut absent = request.clone();
    absent.bridge_evidence_ref = id("evidence:absent-composition-bridge");
    assert_eq!(
        validate_provider_free_self_work_composition_request(&absent)
            .expect_err("absent bridge")
            .code,
        ProviderFreeSelfWorkCompositionFaultCode::InvalidBridgeEvidence
    );

    let unrelated = composition_request_with_bridge_step(3);
    assert_eq!(
        validate_provider_free_self_work_composition_request(&unrelated)
            .expect_err("unrelated bridge")
            .code,
        ProviderFreeSelfWorkCompositionFaultCode::InvalidBridgeEvidence
    );
}

#[test]
fn receipt_authority_projection_and_digest_tampering_refuse() {
    let receipt =
        compile_provider_free_self_work_composition(&composition_request()).expect("receipt");
    let mut physical = receipt.clone();
    physical.physical_contact = true;
    assert_eq!(
        verify_provider_free_self_work_composition(&physical)
            .expect_err("physical authority")
            .code,
        ProviderFreeSelfWorkCompositionFaultCode::InvalidAuthority
    );

    let mut stage = receipt.clone();
    stage.stage_account.clear();
    assert_eq!(
        verify_provider_free_self_work_composition(&stage)
            .expect_err("stage account")
            .code,
        ProviderFreeSelfWorkCompositionFaultCode::InvalidAuthority
    );

    let mut projection = receipt.clone();
    projection.update_step_ref = id("work-step:substituted");
    projection.receipt_digest =
        provider_free_self_work_composition_receipt_digest(&projection).expect("rehash");
    assert_eq!(
        verify_provider_free_self_work_composition(&projection)
            .expect_err("projection")
            .code,
        ProviderFreeSelfWorkCompositionFaultCode::InvalidCorrespondence
    );

    let mut digest_tamper = receipt;
    digest_tamper.receipt_digest.value = "f".repeat(64);
    assert_eq!(
        verify_provider_free_self_work_composition(&digest_tamper)
            .expect_err("digest")
            .code,
        ProviderFreeSelfWorkCompositionFaultCode::InvalidDigest
    );
}

#[test]
fn unknown_fields_trailing_content_and_oversized_forms_refuse() {
    let request = composition_request();
    let form = to_provider_free_self_work_composition_request_machine_form(&request).expect("form");
    let mut value: Value = serde_json::from_str(&form).expect("json");
    value["unknown"] = Value::Bool(true);
    assert_eq!(
        from_provider_free_self_work_composition_request_machine_form(&value.to_string())
            .expect_err("unknown")
            .code,
        ProviderFreeSelfWorkCompositionFaultCode::InvalidMachineForm
    );
    assert_eq!(
        from_provider_free_self_work_composition_request_machine_form(&format!("{form} true"))
            .expect_err("trailing")
            .code,
        ProviderFreeSelfWorkCompositionFaultCode::InvalidMachineForm
    );
    let oversized = "x".repeat(PROVIDER_FREE_SELF_WORK_COMPOSITION_MAX_MACHINE_FORM_BYTES + 1);
    assert_eq!(
        from_provider_free_self_work_composition_request_machine_form(&oversized)
            .expect_err("oversized")
            .code,
        ProviderFreeSelfWorkCompositionFaultCode::InvalidBound
    );
}

fn run_cli(operation: &str, input: &str, extra: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!(
        "CARGO_BIN_EXE_cantor-provider-free-self-work-composition"
    ));
    command
        .arg(operation)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(value) = extra {
        command.arg(value);
    }
    let mut child = command.spawn().expect("spawn CLI");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write CLI input");
    child.wait_with_output().expect("CLI output")
}

#[test]
fn cli_compiles_verifies_and_refuses_output_argument() {
    let request = composition_request();
    let request_form =
        to_provider_free_self_work_composition_request_machine_form(&request).expect("form");
    let compiled = run_cli("compile", &request_form, None);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let receipt_form = String::from_utf8(compiled.stdout).expect("UTF-8 output");
    let receipt =
        from_provider_free_self_work_composition_receipt_machine_form(receipt_form.trim())
            .expect("receipt");
    let verified = run_cli(
        "verify",
        &to_provider_free_self_work_composition_receipt_machine_form(&receipt).expect("form"),
        None,
    );
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    assert_eq!(
        receipt_form,
        String::from_utf8(verified.stdout).expect("UTF-8")
    );

    let refused = run_cli("compile", &request_form, Some("output.json"));
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
}

#[test]
fn production_surface_contains_no_physical_effect_route() {
    let module = include_str!("../src/provider_free_self_work_composition.rs");
    let cli = include_str!("../src/bin/cantor-provider-free-self-work-composition.rs");
    for forbidden in [
        "unsafe {",
        "std::fs",
        "File::",
        "OpenOptions",
        "Command::",
        "TcpStream",
        "UdpSocket",
        "reqwest",
        "std::env::var",
        "current_dir",
        "SystemTime",
        "Instant",
        "PathBuf",
    ] {
        assert!(!module.contains(forbidden), "module contains {forbidden}");
    }
    for forbidden in [
        "--output",
        "output_path",
        "std::fs",
        "File::",
        "OpenOptions",
    ] {
        assert!(!cli.contains(forbidden), "CLI contains {forbidden}");
    }
}
