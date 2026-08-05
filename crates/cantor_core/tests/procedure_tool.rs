use std::collections::{BTreeMap, BTreeSet};

use cantor_core::*;

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn model_candidate() -> ProcedureCandidate {
    let mut candidate: ProcedureCandidate =
        serde_json::from_str(include_str!("fixtures/cppe_two_process_candidate.json"))
            .expect("checked two-process candidate fixture");
    candidate.candidate_id = sid("tool-candidate:model-shaped");
    candidate.author_ref = sid("model-output:tool-procedure-author");
    candidate.provenance_refs = BTreeSet::from([sid("evidence:model-shaped-tool-output")]);
    candidate.source_digest =
        compute_candidate_source_digest(&candidate).expect("candidate source digest");
    candidate
}

fn model_template() -> AuthorshipLaneTemplate {
    AuthorshipLaneTemplate {
        class: AuthorshipClass::ModelShaped,
        authorship_evidence_refs: BTreeSet::from([sid("evidence:model-shaped-tool-output")]),
        validator_ref: sid("validator:independent-tool-fixture"),
        policy_ref: sid("policy:tool-fixture"),
        aliases: BTreeSet::from(["tool-fixture".to_owned()]),
        permitted_invocation_context: "effectless-tool-controller".to_owned(),
        revocation_conditions: BTreeSet::from(["identity changes".to_owned()]),
        invocation_ref: sid("tool-invocation:model-shaped"),
        caller_ref: sid("caller:fake-model-controller"),
        input: ProcedureValue::Record {
            fields: BTreeMap::from([(
                "subject".to_owned(),
                ProcedureValue::Text {
                    value: "hello".to_owned(),
                },
            )]),
        },
        input_sensitivity: SensitivityClass::ProjectInternal,
        sop_generation_ref: sid("sop-generation:tool-fixture"),
        initial_logical_time: 20,
        budgets: InvocationBudget {
            logical_time_limit: 64,
            step_limit: 64,
            memory_unit_limit: 16_384,
            message_limit: 16,
            trace_event_limit: 128,
        },
        retention_policy_ref: sid("policy:retention"),
        session_generation_ref: sid("tool-session-generation:model-shaped"),
        session_ref: sid("tool-session:model-shaped"),
        session_purpose: "prove a fake provider-neutral controller checkpoint".to_owned(),
        frame_ref: sid("tool-frame:model-shaped"),
        frame_conditions: BTreeSet::from(["effectless".to_owned()]),
        frame_constraints: BTreeSet::from(["provider-neutral".to_owned()]),
        permitted_message_kinds: BTreeSet::from([
            ProcedureMessageKind::Propose,
            ProcedureMessageKind::Support,
            ProcedureMessageKind::Pass,
        ]),
    }
}

fn lane() -> AuthorshipLaneEvidence {
    run_authorship_lane(&model_candidate(), &model_template(), &BTreeMap::new())
        .expect("model-shaped tool lane")
}

fn proposal(schema: &ProviderNeutralToolSchema, lane: &AuthorshipLaneEvidence) -> ToolCallProposal {
    let mut proposal = ToolCallProposal {
        schema_ref: schema.schema_id.clone(),
        schema_digest: schema.schema_digest.clone(),
        call_id: sid("tool-call:reconcile-1"),
        inference_job_ref: sid("inference-job:fake-controller-1"),
        participant_ref: lane.request.caller_ref.clone(),
        pass_index: 3,
        operation: ExchangeOperation::Reconcile,
        invocation: lane.request.clone(),
        session: lane.initial_session.clone(),
        argument_digest: ContentDigest {
            algorithm: "sha256".to_owned(),
            value: String::new(),
        },
    };
    proposal.argument_digest =
        compute_tool_call_argument_digest(&proposal).expect("tool argument digest");
    proposal
}

#[test]
fn provider_neutral_schema_is_closed_complete_and_deterministic() {
    let first = provider_neutral_exchange_schema().expect("schema");
    let second = provider_neutral_exchange_schema().expect("schema replay");
    assert_eq!(first, second);
    assert_eq!(first.tool_name, "cantor.exchange");
    assert_eq!(first.operations.len(), 9);
    assert_eq!(first.required_input_fields.len(), 10);
    assert_eq!(first.required_output_fields.len(), 10);
    assert!(
        first
            .required_output_fields
            .contains("invocation_result_digest")
    );
    assert_eq!(
        first.executable_operations,
        BTreeSet::from([ExchangeOperation::Reconcile])
    );
    assert!(first.input_closed && first.output_closed);
    assert_eq!(
        compute_provider_neutral_tool_schema_digest(&first).expect("schema digest"),
        first.schema_digest
    );
}

#[test]
fn fake_controller_stops_calls_binds_and_resumes_in_exact_order() {
    let schema = provider_neutral_exchange_schema().expect("schema");
    let lane = lane();
    let proposal = proposal(&schema, &lane);
    let first = run_fake_controller_exchange(&schema, &proposal, &lane).expect("exchange");
    let second = run_fake_controller_exchange(&schema, &proposal, &lane).expect("replay");
    assert_eq!(first, second);
    assert_eq!(first.result.disposition, ToolResultDisposition::Completed);
    assert_eq!(first.coordination, Some(lane.coordination.clone()));
    assert_eq!(
        first
            .transcript
            .events
            .iter()
            .map(|event| event.kind)
            .collect::<Vec<_>>(),
        vec![
            ControllerEventKind::GenerationOpened,
            ControllerEventKind::ToolCallProposed,
            ControllerEventKind::GenerationStopped,
            ControllerEventKind::ToolCallValidated,
            ControllerEventKind::CantorInvoked,
            ControllerEventKind::ToolResultReturned,
            ControllerEventKind::ContextBound,
            ControllerEventKind::LaterPassResumed,
            ControllerEventKind::Completed,
        ]
    );
    verify_fake_controller_outcome(&schema, &proposal, &lane, &first).expect("verified transcript");
}

#[test]
fn later_pass_receives_only_explicit_proof_carrying_context() {
    let schema = provider_neutral_exchange_schema().expect("schema");
    let lane = lane();
    let proposal = proposal(&schema, &lane);
    let outcome = run_fake_controller_exchange(&schema, &proposal, &lane).expect("exchange");
    let context = outcome
        .result
        .explicit_context
        .as_ref()
        .expect("later-pass context");
    assert_eq!(context.pass_index, proposal.pass_index + 1);
    assert_eq!(context.tool_result_digest, outcome.result.result_digest);
    assert_eq!(
        context.sensitivity,
        lane.coordination.result.output_sensitivity
    );
    assert_eq!(outcome.transcript.provider_call_count, 0);
    assert_eq!(outcome.transcript.external_effect_count, 0);
    assert!(
        outcome
            .result
            .residuals
            .contains("context is explicit input to a later pass, not hidden-state sharing")
    );
}

#[test]
fn changed_arguments_are_refused_before_cantor_invocation_or_resume() {
    let schema = provider_neutral_exchange_schema().expect("schema");
    let lane = lane();
    let mut proposal = proposal(&schema, &lane);
    proposal.invocation.purpose = "changed after hashing".to_owned();
    let outcome = run_fake_controller_exchange(&schema, &proposal, &lane).expect("refusal");
    assert_eq!(outcome.result.disposition, ToolResultDisposition::Refused);
    assert!(outcome.coordination.is_none());
    assert_eq!(outcome.result.faults[0].code, "argument_digest_mismatch");
    assert!(!outcome.transcript.events.iter().any(|event| matches!(
        event.kind,
        ControllerEventKind::CantorInvoked | ControllerEventKind::LaterPassResumed
    )));
    verify_fake_controller_outcome(&schema, &proposal, &lane, &outcome).expect("verified refusal");
}

#[test]
fn named_but_unimplemented_operation_is_visibly_refused() {
    let schema = provider_neutral_exchange_schema().expect("schema");
    let lane = lane();
    let mut proposal = proposal(&schema, &lane);
    proposal.operation = ExchangeOperation::Challenge;
    proposal.argument_digest =
        compute_tool_call_argument_digest(&proposal).expect("updated argument digest");
    let outcome = run_fake_controller_exchange(&schema, &proposal, &lane).expect("refusal");
    assert_eq!(outcome.result.disposition, ToolResultDisposition::Refused);
    assert_eq!(outcome.result.faults[0].code, "operation_not_executable");
    verify_fake_controller_outcome(&schema, &proposal, &lane, &outcome).expect("verified refusal");
}

#[test]
fn substituted_lane_evidence_cannot_cross_the_tool_boundary() {
    let schema = provider_neutral_exchange_schema().expect("schema");
    let mut lane = lane();
    let proposal = proposal(&schema, &lane);
    lane.coordination.result.consumed_budget.steps += 1;
    let outcome = run_fake_controller_exchange(&schema, &proposal, &lane).expect("refusal");
    assert_eq!(outcome.result.disposition, ToolResultDisposition::Refused);
    assert_eq!(outcome.result.faults[0].code, "evidence_replay_failed");
    assert!(outcome.coordination.is_none());
}

#[test]
fn tampered_event_chain_or_result_is_rejected_by_independent_verification() {
    let schema = provider_neutral_exchange_schema().expect("schema");
    let lane = lane();
    let proposal = proposal(&schema, &lane);
    let outcome = run_fake_controller_exchange(&schema, &proposal, &lane).expect("exchange");

    let mut reordered = outcome.clone();
    reordered.transcript.events.swap(2, 3);
    assert!(verify_fake_controller_outcome(&schema, &proposal, &lane, &reordered).is_err());

    let mut changed = outcome;
    changed.result.residuals.insert("unbound claim".to_owned());
    assert!(verify_fake_controller_outcome(&schema, &proposal, &lane, &changed).is_err());
}

#[test]
fn strict_machine_forms_reject_unknown_fields_and_operations() {
    let schema = provider_neutral_exchange_schema().expect("schema");
    let lane = lane();
    let proposal = proposal(&schema, &lane);
    let mut value = serde_json::to_value(&proposal).expect("proposal JSON");
    value
        .as_object_mut()
        .expect("object")
        .insert("provider_private_state".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<ToolCallProposal>(value).is_err());

    let mut value = serde_json::to_value(&proposal).expect("proposal JSON");
    value["operation"] = serde_json::json!("invented_operation");
    assert!(serde_json::from_value::<ToolCallProposal>(value).is_err());
}
