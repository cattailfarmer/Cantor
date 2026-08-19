use cantor_compact_reflection_loop::*;
use cantor_core::{ContentDigest, SemanticId};
use cantor_procedure_tool::{CoordinationToolContext, CoordinationToolRequest};
use serde_json::{Value, json};

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn context() -> CoordinationToolContext {
    serde_json::from_str(&experimental_fixture_context_json().expect("fixture context"))
        .expect("typed context")
}

fn bound_terminal() -> TerminalObservation {
    let bound = open_bound_session(
        serde_json::to_string(&context()).expect("context JSON"),
        sid("registry:compact-reflection-test"),
        sid("session:compact-reflection-test"),
    )
    .expect("open");
    advance_bound_session_terminal(&bound, 64)
        .expect("terminal")
        .1
}

fn call_response(name: &str, maximum_steps: u64, content: Value) -> Value {
    json!({
        "choices": [{
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant",
                "content": content,
                "tool_calls": [{
                    "id": "call-compact-1",
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": serde_json::to_string(&json!({"maximum_steps": maximum_steps})).unwrap()
                    }
                }]
            }
        }]
    })
}

#[test]
fn compact_host_binding_reaches_the_exact_direct_terminal_outcome() {
    let context = context();
    let bound = open_bound_session(
        serde_json::to_string(&context).expect("context JSON"),
        sid("registry:compact-reflection-equivalence"),
        sid("session:compact-reflection-equivalence"),
    )
    .expect("open");
    let (_, observation) = advance_bound_session_terminal(&bound, 64).expect("terminal");
    let record: cantor_compact_coordination_mcp::CompactCoordinationRecord =
        serde_json::from_str(&observation.record_json).expect("record");
    let compact_outcome = record.outcome.expect("outcome");

    let began =
        cantor_procedure_tool::execute_coordination_tool_request(CoordinationToolRequest::Begin {
            context: Box::new(context.clone()),
        });
    let checkpoint = match began.result.expect("begin result") {
        cantor_procedure_tool::CoordinationToolResult::Began { checkpoint } => checkpoint,
        _ => panic!("expected begin"),
    };
    let advanced = cantor_procedure_tool::execute_coordination_tool_request(
        CoordinationToolRequest::Advance {
            context: Box::new(context),
            checkpoint,
            maximum_steps: 64,
        },
    );
    let direct_outcome = match advanced.result.expect("advance result") {
        cantor_procedure_tool::CoordinationToolResult::Advanced { transition } => {
            transition.outcome.expect("direct outcome")
        }
        _ => panic!("expected advance"),
    };
    assert_eq!(*compact_outcome, direct_outcome);
    assert_eq!(observation.observed_status, "terminal_outcome");
    assert_eq!(
        observation.handle.outcome_digest,
        Some(observation.outcome_digest)
    );
}

#[test]
fn model_tool_model_contract_preserves_terminal_identity() {
    let request = first_request("fixture-model", "Run the bounded procedure.", 64);
    assert_eq!(
        request
            .pointer("/tools/0/function/name")
            .and_then(Value::as_str),
        Some(TOOL_NAME)
    );
    assert_eq!(
        request
            .pointer("/tools/0/function/parameters/properties/maximum_steps/const")
            .and_then(Value::as_u64),
        Some(64)
    );
    let response = call_response(TOOL_NAME, 64, Value::Null);
    let call = extract_advance_call(&response, 64).expect("call");
    let observation = bound_terminal();
    let reflection = reflection_request(
        "fixture-model",
        "Run the bounded procedure.",
        &call,
        &observation,
    );
    assert_eq!(reflection["tool_choice"], "none");
    assert_eq!(
        reflection
            .pointer("/messages/3/tool_call_id")
            .and_then(Value::as_str),
        Some("call-compact-1")
    );
    let expected = FinalOutput {
        observed_status: observation.observed_status.clone(),
        session_id: observation.handle.session_id.clone(),
        outcome_digest: observation.outcome_digest.clone(),
        statement: FINAL_STATEMENT.to_owned(),
    };
    let final_response = json!({
        "choices": [{
            "finish_reason": "stop",
            "message": {
                "role": "assistant",
                "content": serde_json::to_string(&expected).unwrap()
            }
        }]
    });
    assert_eq!(
        extract_final_output(&final_response, &observation).expect("final"),
        expected
    );
}

#[test]
fn malformed_or_identity_changing_model_outputs_fail_closed() {
    assert!(extract_advance_call(&call_response("wrong", 64, Value::Null), 64).is_err());
    assert!(extract_advance_call(&call_response(TOOL_NAME, 63, Value::Null), 64).is_err());
    assert!(extract_advance_call(&call_response(TOOL_NAME, 64, json!("premature")), 64).is_err());

    let observation = bound_terminal();
    let changed = FinalOutput {
        observed_status: observation.observed_status.clone(),
        session_id: observation.handle.session_id.clone(),
        outcome_digest: ContentDigest {
            algorithm: "sha256".to_owned(),
            value: "0".repeat(64),
        },
        statement: FINAL_STATEMENT.to_owned(),
    };
    let response = json!({
        "choices": [{
            "finish_reason": "stop",
            "message": {"role": "assistant", "content": serde_json::to_string(&changed).unwrap()}
        }]
    });
    assert!(extract_final_output(&response, &observation).is_err());
}

#[test]
fn provider_and_trace_boundaries_are_closed() {
    assert_eq!(
        normalize_loopback_base_url("http://127.0.0.1:8081/v1/").unwrap(),
        "http://127.0.0.1:8081/v1"
    );
    assert!(normalize_loopback_base_url("http://192.168.1.19:8081/v1").is_err());
    assert!(normalize_loopback_base_url("https://localhost:8081/v1").is_err());
    let advertised = json!({"data": [{"id": "model-a"}, {"id": "model-b"}]});
    assert_eq!(
        select_advertised_model(&advertised, Some("model-b")).unwrap(),
        "model-b"
    );
    assert!(select_advertised_model(&advertised, None).is_err());
    assert!(select_advertised_model(&advertised, Some("model-c")).is_err());
    let sanitized = sanitize(&json!({
        "choices": [{"message": {"content": "public", "reasoning_content": "private"}}],
        "thinking": "private"
    }));
    assert_eq!(
        sanitized
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str),
        Some("public")
    );
    assert!(
        sanitized
            .pointer("/choices/0/message/reasoning_content")
            .is_none()
    );
    assert!(sanitized.get("thinking").is_none());
}
