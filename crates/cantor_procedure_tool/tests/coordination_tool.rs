use std::collections::{BTreeMap, BTreeSet};

use cantor_core::*;
use cantor_procedure_tool::{
    CoordinationToolContext, CoordinationToolOperation, CoordinationToolRequest,
    CoordinationToolResponse, CoordinationToolResult, CoordinationToolStatus,
    execute_coordination_tool_request,
};
use serde_json::json;

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn candidate() -> ProcedureCandidate {
    let mut candidate: ProcedureCandidate = serde_json::from_str(include_str!(
        "../../cantor_core/tests/fixtures/cppe_two_process_candidate.json"
    ))
    .expect("checked two-process candidate fixture");
    candidate.candidate_id = sid("tool-candidate:coordination-adapter");
    candidate.author_ref = sid("model-output:coordination-adapter-author");
    candidate.provenance_refs = BTreeSet::from([sid("evidence:coordination-adapter")]);
    candidate.source_digest =
        compute_candidate_source_digest(&candidate).expect("candidate source digest");
    candidate
}

fn template() -> AuthorshipLaneTemplate {
    AuthorshipLaneTemplate {
        class: AuthorshipClass::ModelShaped,
        authorship_evidence_refs: BTreeSet::from([sid("evidence:coordination-adapter")]),
        validator_ref: sid("validator:coordination-adapter"),
        policy_ref: sid("policy:coordination-adapter"),
        aliases: BTreeSet::from(["coordination-adapter".to_owned()]),
        permitted_invocation_context: "effectless-coordination-adapter".to_owned(),
        revocation_conditions: BTreeSet::from(["identity changes".to_owned()]),
        invocation_ref: sid("invocation:coordination-adapter"),
        caller_ref: sid("caller:coordination-adapter"),
        input: ProcedureValue::Record {
            fields: BTreeMap::from([(
                "subject".to_owned(),
                ProcedureValue::Text {
                    value: "hello".to_owned(),
                },
            )]),
        },
        input_sensitivity: SensitivityClass::ProjectInternal,
        sop_generation_ref: sid("sop-generation:coordination-adapter"),
        initial_logical_time: 20,
        budgets: InvocationBudget {
            logical_time_limit: 64,
            step_limit: 64,
            memory_unit_limit: 16_384,
            message_limit: 16,
            trace_event_limit: 128,
        },
        retention_policy_ref: sid("policy:retention"),
        session_generation_ref: sid("session-generation:coordination-adapter"),
        session_ref: sid("session:coordination-adapter"),
        session_purpose: "prove provider-neutral coordination dispatch".to_owned(),
        frame_ref: sid("frame:coordination-adapter"),
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
    run_authorship_lane(&candidate(), &template(), &BTreeMap::new())
        .expect("coordination adapter lane")
}

fn began(response: &CoordinationToolResponse) -> CoordinationCheckpoint {
    match response.result.as_ref().expect("successful result") {
        CoordinationToolResult::Began { checkpoint } => (**checkpoint).clone(),
        CoordinationToolResult::Advanced { .. } => panic!("expected BEGIN result"),
    }
}

#[test]
fn context_projection_contains_only_the_six_execution_inputs() {
    let context = CoordinationToolContext::from(&lane());
    let value = serde_json::to_value(context).expect("context encodes");
    let object = value.as_object().expect("context object");
    assert_eq!(object.len(), 6);
    for required in [
        "catalogue",
        "procedure",
        "ir",
        "admission",
        "request",
        "initial_session",
    ] {
        assert!(object.contains_key(required), "missing {required}");
    }
    for excluded in ["coordination", "replay", "stable_session", "candidate"] {
        assert!(!object.contains_key(excluded), "unexpected {excluded}");
    }
}

#[test]
fn begin_and_advance_are_exactly_core_equivalent_and_repeatable() {
    let lane = lane();
    let context = CoordinationToolContext::from(&lane);
    let expected_begin = begin_coordination_checkpoint(
        &lane.catalogue,
        &lane.procedure,
        &lane.ir,
        &lane.admission,
        &lane.request,
        &lane.initial_session,
    )
    .expect("direct begin");
    let begin_request = CoordinationToolRequest::Begin {
        context: Box::new(context.clone()),
    };
    let first = execute_coordination_tool_request(begin_request.clone());
    let second = execute_coordination_tool_request(begin_request);
    assert_eq!(first, second);
    assert_eq!(first.status, CoordinationToolStatus::Succeeded);
    assert_eq!(began(&first), expected_begin);

    let expected_advance = advance_coordination_checkpoint(
        &lane.catalogue,
        &lane.procedure,
        &lane.ir,
        &lane.admission,
        &lane.request,
        &lane.initial_session,
        &expected_begin,
        1,
    )
    .expect("direct advance");
    let advanced = execute_coordination_tool_request(CoordinationToolRequest::Advance {
        context: Box::new(context),
        checkpoint: Box::new(expected_begin),
        maximum_steps: 1,
    });
    assert_eq!(advanced.operation, CoordinationToolOperation::Advance);
    match advanced.result.expect("advance result") {
        CoordinationToolResult::Advanced { transition } => {
            assert_eq!(*transition, expected_advance);
        }
        CoordinationToolResult::Began { .. } => panic!("expected ADVANCE result"),
    }
}

#[test]
fn zero_quota_unknown_fields_and_changed_lineage_fail_closed() {
    let lane = lane();
    let context = CoordinationToolContext::from(&lane);
    let checkpoint = began(&execute_coordination_tool_request(
        CoordinationToolRequest::Begin {
            context: Box::new(context.clone()),
        },
    ));
    let zero = execute_coordination_tool_request(CoordinationToolRequest::Advance {
        context: Box::new(context.clone()),
        checkpoint: Box::new(checkpoint.clone()),
        maximum_steps: 0,
    });
    assert_eq!(zero.status, CoordinationToolStatus::InvalidRequest);
    assert!(zero.result.is_none());
    assert_eq!(zero.fault.expect("zero fault").code, "zero_step_quota");

    let mut encoded = serde_json::to_value(CoordinationToolRequest::Begin {
        context: Box::new(context.clone()),
    })
    .expect("request encodes");
    encoded
        .as_object_mut()
        .expect("request object")
        .insert("invented_authority".to_owned(), json!(true));
    assert!(serde_json::from_value::<CoordinationToolRequest>(encoded).is_err());

    let mut changed = context;
    changed.request.invocation_id = sid("invocation:changed-after-checkpoint");
    let refused = execute_coordination_tool_request(CoordinationToolRequest::Advance {
        context: Box::new(changed),
        checkpoint: Box::new(checkpoint),
        maximum_steps: 1,
    });
    assert_eq!(refused.status, CoordinationToolStatus::Refused);
    assert!(refused.result.is_none());
    assert!(refused.fault.is_some());
}

#[cfg(feature = "json-schema")]
#[test]
fn request_and_response_schemas_are_closed_and_stable() {
    let request = serde_json::to_value(schemars::schema_for!(CoordinationToolRequest))
        .expect("request schema encodes");
    let response = serde_json::to_value(schemars::schema_for!(CoordinationToolResponse))
        .expect("response schema encodes");
    let encoded = serde_json::to_string(&(request, response)).expect("schemas encode");
    for required in [
        "begin",
        "advance",
        "maximum_steps",
        "checkpoint",
        "nonclaims",
    ] {
        assert!(encoded.contains(required), "missing {required}");
    }
}
