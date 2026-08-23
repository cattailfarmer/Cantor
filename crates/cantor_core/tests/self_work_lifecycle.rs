#[path = "objective_work_plan.rs"]
mod objective_work_plan_fixture;

use std::collections::BTreeSet;

use cantor_core::*;
use objective_work_plan_fixture::fixture_request;
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
    let work_plan_proposal =
        compile_objective_work_plan(&fixture_request()).expect("work plan proposal");
    SelfWorkLifecycleRequest {
        profile: SELF_WORK_LIFECYCLE_REQUEST_PROFILE.to_owned(),
        lifecycle_id: id("self-work-lifecycle:fixture"),
        work_plan_proposal,
        maximum_transitions: 32,
        evidence_refs: [id("evidence:self-work-lifecycle")].into_iter().collect(),
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

fn receipt(label: &str, symbol: char) -> ExternalReceiptReference {
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
) -> SelfWorkLifecycleTransition {
    let state = checkpoint.step_states.get(step_ref).expect("step state");
    let sequence = checkpoint.sequence + 1;
    SelfWorkLifecycleTransition {
        profile: SELF_WORK_LIFECYCLE_TRANSITION_PROFILE.to_owned(),
        transition_id: id(&format!("self-work-transition:{sequence}")),
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
        .then(|| receipt(&format!("capability-receipt:{sequence}"), 'a')),
        review_receipt: (kind == SelfWorkTransitionKind::AcceptReview)
            .then(|| receipt(&format!("review-receipt:{sequence}"), 'b')),
        evidence_refs: [id(&format!("evidence:self-work-transition:{sequence}"))]
            .into_iter()
            .collect(),
    }
}

#[test]
fn begin_is_deterministic_strict_and_not_executing() {
    let request = lifecycle_request();
    let proposal = compile_self_work_lifecycle(&request).expect("proposal");
    assert_eq!(
        proposal.disposition,
        SelfWorkLifecycleDisposition::PreparedNotExecuting
    );
    assert_eq!(
        proposal.authority,
        SelfWorkLifecycleAuthority::RepresentationOnly
    );
    assert_eq!(proposal.checkpoint.sequence, 0);
    let states: Vec<_> = proposal
        .checkpoint
        .step_states
        .values()
        .map(|state| state.state)
        .collect();
    assert_eq!(states[0], SelfWorkLifecycleState::ReadyAwaitingAdmission);
    assert!(
        states[1..]
            .iter()
            .all(|state| *state == SelfWorkLifecycleState::PendingDependencies)
    );
    assert_eq!(
        proposal,
        compile_self_work_lifecycle(&request).expect("replay")
    );
    let request_form = to_self_work_lifecycle_request_machine_form(&request).expect("form");
    assert_eq!(
        request,
        from_self_work_lifecycle_request_machine_form(&request_form).expect("round trip")
    );
    let proposal_form = to_self_work_lifecycle_proposal_machine_form(&proposal).expect("form");
    assert_eq!(
        proposal,
        from_self_work_lifecycle_proposal_machine_form(&proposal_form).expect("round trip")
    );
}

#[test]
fn stopped_resumable_review_complete_chain_replays_and_releases_dependency() {
    let request = lifecycle_request();
    let mut checkpoint = compile_self_work_lifecycle(&request)
        .expect("proposal")
        .checkpoint;
    let first = request.work_plan_proposal.request.plan.steps[0]
        .step_id
        .clone();
    let second = request.work_plan_proposal.request.plan.steps[1]
        .step_id
        .clone();
    let path = [
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
    ];
    for (kind, successor) in path {
        let next = transition(&checkpoint, &first, kind, successor);
        checkpoint = advance_self_work_lifecycle(&request, &checkpoint, &next).expect("advance");
    }
    assert_eq!(
        checkpoint.step_states[&first].state,
        SelfWorkLifecycleState::Complete
    );
    assert_eq!(
        checkpoint.step_states[&second].state,
        SelfWorkLifecycleState::ReadyAwaitingAdmission
    );
    validate_self_work_lifecycle_checkpoint(&request, &checkpoint).expect("replay validation");
}

#[test]
fn failed_is_terminal_and_illegal_edges_refuse() {
    let request = lifecycle_request();
    let mut checkpoint = compile_self_work_lifecycle(&request)
        .expect("proposal")
        .checkpoint;
    let step = request.work_plan_proposal.request.plan.steps[0]
        .step_id
        .clone();
    let start = transition(
        &checkpoint,
        &step,
        SelfWorkTransitionKind::Start,
        SelfWorkLifecycleState::Active,
    );
    checkpoint = advance_self_work_lifecycle(&request, &checkpoint, &start).expect("start");
    let fail = transition(
        &checkpoint,
        &step,
        SelfWorkTransitionKind::Fail,
        SelfWorkLifecycleState::Failed,
    );
    checkpoint = advance_self_work_lifecycle(&request, &checkpoint, &fail).expect("fail");
    let illegal = transition(
        &checkpoint,
        &step,
        SelfWorkTransitionKind::Resume,
        SelfWorkLifecycleState::Active,
    );
    assert_eq!(
        advance_self_work_lifecycle(&request, &checkpoint, &illegal)
            .expect_err("terminal resume")
            .code,
        SelfWorkLifecycleFaultCode::InvalidTransition
    );
}

#[test]
fn receipt_predecessor_and_checkpoint_tampering_refuse() {
    let request = lifecycle_request();
    let checkpoint = compile_self_work_lifecycle(&request)
        .expect("proposal")
        .checkpoint;
    let step = request.work_plan_proposal.request.plan.steps[0]
        .step_id
        .clone();
    let mut start = transition(
        &checkpoint,
        &step,
        SelfWorkTransitionKind::Start,
        SelfWorkLifecycleState::Active,
    );
    start.capability_receipt = None;
    assert_eq!(
        advance_self_work_lifecycle(&request, &checkpoint, &start)
            .expect_err("missing receipt")
            .code,
        SelfWorkLifecycleFaultCode::InvalidReceiptReference
    );
    let mut start = transition(
        &checkpoint,
        &step,
        SelfWorkTransitionKind::Start,
        SelfWorkLifecycleState::Active,
    );
    start.predecessor_checkpoint_digest = digest('c');
    assert_eq!(
        advance_self_work_lifecycle(&request, &checkpoint, &start)
            .expect_err("predecessor")
            .code,
        SelfWorkLifecycleFaultCode::InvalidCorrespondence
    );
    let mut checkpoint = checkpoint;
    checkpoint.capability_account.remove(&WorkCapability::Push);
    assert_eq!(
        validate_self_work_lifecycle_checkpoint(&request, &checkpoint)
            .expect_err("account")
            .code,
        SelfWorkLifecycleFaultCode::InvalidState
    );
}

#[test]
fn work_plan_bound_unknown_field_and_nonauthority_tampering_refuse() {
    let mut request = lifecycle_request();
    request.work_plan_proposal.proposal_digest = digest('c');
    assert_eq!(
        validate_self_work_lifecycle_request(&request)
            .expect_err("work plan")
            .code,
        SelfWorkLifecycleFaultCode::InvalidWorkPlan
    );
    let mut request = lifecycle_request();
    request.maximum_transitions = 65;
    assert_eq!(
        validate_self_work_lifecycle_request(&request)
            .expect_err("bound")
            .code,
        SelfWorkLifecycleFaultCode::InvalidBound
    );
    let mut request = lifecycle_request();
    request.non_authority.push_str(" Granted.");
    assert_eq!(
        validate_self_work_lifecycle_request(&request)
            .expect_err("authority")
            .code,
        SelfWorkLifecycleFaultCode::InvalidAuthority
    );
    let mut value = serde_json::to_value(lifecycle_request()).expect("value");
    value
        .as_object_mut()
        .expect("object")
        .insert("execute".to_owned(), json!(true));
    assert_eq!(
        from_self_work_lifecycle_request_machine_form(&value.to_string())
            .expect_err("unknown")
            .code,
        SelfWorkLifecycleFaultCode::InvalidMachineForm
    );
    let empty: BTreeSet<SemanticId> = BTreeSet::new();
    let mut request = lifecycle_request();
    request.evidence_refs = empty;
    assert_eq!(
        validate_self_work_lifecycle_request(&request)
            .expect_err("evidence")
            .code,
        SelfWorkLifecycleFaultCode::InvalidEvidence
    );
}
