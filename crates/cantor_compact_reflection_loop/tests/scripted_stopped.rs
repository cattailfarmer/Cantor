use cantor_compact_coordination_mcp::CompactSessionStatus;
use cantor_compact_reflection_loop::{
    BoundSession, IterativeRunState, RunPolicy, ScriptedStoppedRun, StopReason, TOOL_NAME,
    generate_scripted_exhaustion_fixture, generate_scripted_tool_cap_fixture, open_bound_session,
    resume_scripted_stopped, run_scripted_complete_iterative, run_scripted_ready_stopped,
    validate_scripted_stopped_run,
};
use cantor_core::SemanticId;
use serde_json::{Value, json};

fn open(session: &str) -> BoundSession {
    open_bound_session(
        cantor_compact_reflection_loop::experimental_fixture_context_json()
            .expect("fixture context"),
        SemanticId::new("registry:scripted-stopped-test").expect("registry id"),
        SemanticId::new(session).expect("session id"),
    )
    .expect("open session")
}

fn policy(maximum_tool_calls: u32) -> RunPolicy {
    RunPolicy {
        maximum_steps_per_call: 8,
        maximum_tool_calls,
        maximum_provider_calls: maximum_tool_calls + 1,
        timeout_seconds: 120,
    }
}

fn response(call_id: &str) -> Value {
    json!({
        "choices": [{
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": call_id,
                    "type": "function",
                    "function": {
                        "name": TOOL_NAME,
                        "arguments": "{\"maximum_steps\":8}"
                    }
                }]
            }
        }]
    })
}

#[test]
fn tool_cap_fixture_stops_at_an_exact_live_ready_head() {
    let stopped = generate_scripted_tool_cap_fixture().expect("tool-cap fixture");
    validate_scripted_stopped_run(&stopped).expect("valid stopped run");
    assert_eq!(stopped.report.status, IterativeRunState::Stopped);
    assert_eq!(stopped.report.stop_reason, Some(StopReason::ToolCallCap));
    assert_eq!(stopped.report.usage.tool_calls, 1);
    assert_eq!(stopped.report.usage.provider_calls, 1);
    assert_eq!(stopped.report.reentry_available, Some(true));
    assert_eq!(
        stopped
            .report
            .reentry_handle
            .as_ref()
            .expect("reentry")
            .status,
        CompactSessionStatus::Ready
    );
    assert!(stopped.failed_request.is_none());
    assert!(stopped.sanitized_failed_response.is_none());
    assert!(stopped.fault_message.is_none());
    let resumed = resume_scripted_stopped(&stopped).expect("resumable session");
    assert_eq!(resumed.registry, stopped.successor_registry);
    assert_eq!(resumed.handle, stopped.report.reentry_handle.unwrap());
}

#[test]
fn script_exhaustion_distinguishes_absent_response_from_invalid_response() {
    let exhausted = generate_scripted_exhaustion_fixture().expect("exhaustion fixture");
    assert_eq!(
        exhausted.report.stop_reason,
        Some(StopReason::ProviderProtocolFault)
    );
    assert_eq!(exhausted.report.usage.tool_calls, 1);
    assert_eq!(exhausted.report.usage.provider_calls, 1);
    assert!(exhausted.failed_request.is_some());
    assert!(exhausted.sanitized_failed_response.is_none());
    assert!(exhausted.fault_message.is_some());

    let opening = open("session:scripted-invalid-response");
    let invalid = json!({
        "choices": [{
            "finish_reason": "stop",
            "message": {
                "role": "assistant",
                "content": "premature",
                "reasoning_content": "must not be retained"
            }
        }]
    });
    let stopped =
        run_scripted_ready_stopped(&opening, "scripted-model", "Run.", policy(8), &[invalid])
            .expect("invalid response stop");
    assert_eq!(stopped.report.usage.tool_calls, 0);
    assert_eq!(stopped.report.usage.provider_calls, 1);
    assert_eq!(
        stopped.report.reentry_handle.as_ref(),
        Some(&opening.handle)
    );
    let retained = stopped
        .sanitized_failed_response
        .as_ref()
        .expect("retained invalid response");
    assert!(
        retained
            .pointer("/choices/0/message/reasoning_content")
            .is_none()
    );
    validate_scripted_stopped_run(&stopped).expect("valid invalid-response stop");
}

#[test]
fn duplicate_call_stops_before_a_second_advancement() {
    let opening = open("session:scripted-duplicate-call");
    let stopped = run_scripted_ready_stopped(
        &opening,
        "scripted-model",
        "Run.",
        policy(8),
        &[response("call-duplicate"), response("call-duplicate")],
    )
    .expect("duplicate response stop");
    assert_eq!(
        stopped.report.stop_reason,
        Some(StopReason::ProviderProtocolFault)
    );
    assert_eq!(stopped.report.usage.tool_calls, 1);
    assert_eq!(stopped.report.usage.provider_calls, 2);
    assert_eq!(stopped.report.iterations.len(), 1);
    assert_eq!(
        stopped
            .report
            .reentry_handle
            .as_ref()
            .expect("reentry")
            .sequence,
        opening.handle.sequence + 1
    );
}

#[test]
fn explicit_resume_reaches_the_uninterrupted_terminal_outcome() {
    let opening = open("session:scripted-stopped-resume");
    let uninterrupted = run_scripted_complete_iterative(
        &opening,
        "scripted-model",
        "Run.",
        policy(8),
        &["call-0".to_owned(), "call-1".to_owned()],
    )
    .expect("uninterrupted run");
    let stopped = run_scripted_ready_stopped(
        &opening,
        "scripted-model",
        "Run.",
        policy(1),
        &[response("call-0")],
    )
    .expect("stopped run");
    let resumed = resume_scripted_stopped(&stopped).expect("resume session");
    let completed = run_scripted_complete_iterative(
        &resumed,
        "scripted-model",
        "Run.",
        policy(8),
        &["call-resumed".to_owned()],
    )
    .expect("resumed completion");
    assert_eq!(
        completed
            .report
            .terminal_observation
            .expect("resumed terminal")
            .outcome_digest,
        uninterrupted
            .report
            .terminal_observation
            .expect("uninterrupted terminal")
            .outcome_digest
    );
}

#[test]
fn stopped_wrapper_mutations_and_terminal_misclassification_refuse() {
    let stopped = generate_scripted_exhaustion_fixture().expect("exhaustion fixture");
    let encoded = serde_json::to_value(&stopped).expect("stopped JSON");
    let decoded: ScriptedStoppedRun =
        serde_json::from_value(encoded.clone()).expect("closed round trip");
    assert_eq!(decoded, stopped);
    let mut unknown = encoded;
    unknown["terminal_pending"] = Value::Bool(false);
    assert!(serde_json::from_value::<ScriptedStoppedRun>(unknown).is_err());

    let mut claimed = stopped.clone();
    claimed.provider_execution_claimed = true;
    assert!(validate_scripted_stopped_run(&claimed).is_err());

    let mut missing_request = stopped.clone();
    missing_request.failed_request = None;
    assert!(validate_scripted_stopped_run(&missing_request).is_err());

    let mut dead = stopped.clone();
    dead.report.reentry_available = Some(false);
    assert!(validate_scripted_stopped_run(&dead).is_err());

    let mut registry = stopped.clone();
    registry.successor_registry.generation += 1;
    assert!(validate_scripted_stopped_run(&registry).is_err());

    let opening = open("session:scripted-terminal-refusal");
    assert!(
        run_scripted_ready_stopped(
            &opening,
            "scripted-model",
            "Run.",
            policy(8),
            &[response("call-0"), response("call-1")]
        )
        .is_err(),
        "terminal state must not be represented as READY stopped"
    );
    assert!(
        run_scripted_ready_stopped(
            &opening,
            "scripted-model",
            "Run.",
            policy(1),
            &[response("call-0"), response("call-extra")]
        )
        .is_err(),
        "responses after the exact cap must not be ignored"
    );
}
