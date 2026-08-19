use cantor_compact_reflection_loop::{
    BoundSession, FinalOutput, IterationRecord, IterationSuccessor, IterativeProviderPhase,
    RunPolicy, TOOL_NAME, admit_iterative_provider_iteration, drive_bound_session,
    experimental_fixture_context_json, extract_final_output, iterative_advance_request,
    iterative_terminal_reflection_request, open_bound_session, validate_iterative_provider_prefix,
    validate_provider_prefix_projection,
};
use cantor_core::SemanticId;
use serde_json::{Value, json};

const MODEL: &str = "fixture-iterative-model";
const PROMPT: &str = "Run the bounded iterative attention procedure.";

fn open(session: &str) -> BoundSession {
    open_bound_session(
        experimental_fixture_context_json().expect("fixture context"),
        SemanticId::new("registry:iterative-provider-fixture").expect("registry id"),
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

fn one_advance(opening: &BoundSession) -> cantor_compact_reflection_loop::DeterministicDriveResult {
    drive_bound_session(opening, policy(1)).expect("one deterministic advance")
}

fn response(call_id: &str, maximum_steps: u64) -> Value {
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
                        "arguments": serde_json::to_string(&json!({
                            "maximum_steps": maximum_steps
                        })).expect("arguments")
                    }
                }]
            }
        }]
    })
}

fn first_record(
    opening: &BoundSession,
    selected_policy: &RunPolicy,
) -> (IterationRecord, BoundSession) {
    let first_drive = one_advance(opening);
    let record = admit_iterative_provider_iteration(
        MODEL,
        PROMPT,
        selected_policy,
        &opening.handle,
        &[],
        &response("call-z-first", 8),
        &first_drive,
    )
    .expect("admit first provider iteration");
    let resumed = BoundSession {
        registry: first_drive.successor_registry,
        handle: first_drive.stopped_head.expect("READY head"),
    };
    (record, resumed)
}

fn terminal_records(opening: &BoundSession) -> Vec<IterationRecord> {
    let selected_policy = policy(8);
    let (first, resumed) = first_record(opening, &selected_policy);
    let second_drive = one_advance(&resumed);
    let second = admit_iterative_provider_iteration(
        MODEL,
        PROMPT,
        &selected_policy,
        &opening.handle,
        std::slice::from_ref(&first),
        &response("call-a-second", 8),
        &second_drive,
    )
    .expect("admit terminal provider iteration");
    vec![first, second]
}

#[test]
fn first_ready_terminal_and_reflection_requests_are_exactly_ordered() {
    let opening = open("session:iterative-provider-happy");
    let selected_policy = policy(8);
    let first_request =
        iterative_advance_request(MODEL, PROMPT, &selected_policy, &opening.handle, &[])
            .expect("first request");
    assert_eq!(first_request["tool_choice"], "required");
    assert_eq!(first_request["parallel_tool_calls"], false);
    assert_eq!(
        first_request["messages"]
            .as_array()
            .expect("messages")
            .len(),
        2
    );
    assert_eq!(
        first_request.pointer("/tools/0/function/parameters/properties/maximum_steps/const"),
        Some(&json!(8))
    );

    let (first, resumed) = first_record(&opening, &selected_policy);
    assert_eq!(first.request, first_request);
    let ready_prefix = validate_iterative_provider_prefix(
        MODEL,
        PROMPT,
        &selected_policy,
        &opening.handle,
        std::slice::from_ref(&first),
    )
    .expect("READY prefix");
    assert_eq!(ready_prefix.phase, IterativeProviderPhase::Advance);
    assert_eq!(ready_prefix.head_handle, resumed.handle);
    assert_eq!(ready_prefix.call_ids, vec!["call-z-first"]);

    let continuation = iterative_advance_request(
        MODEL,
        PROMPT,
        &selected_policy,
        &opening.handle,
        std::slice::from_ref(&first),
    )
    .expect("continuation request");
    let messages = continuation["messages"].as_array().expect("messages");
    assert_eq!(messages.len(), 4);
    assert_eq!(messages[2]["role"], "assistant");
    assert_eq!(messages[3]["role"], "tool");
    assert_eq!(messages[3]["tool_call_id"], "call-z-first");
    let ready_tool_value: Value =
        serde_json::from_str(messages[3]["content"].as_str().expect("tool content"))
            .expect("READY projection JSON");
    assert_eq!(ready_tool_value["state_is_terminal"], false);

    let second_drive = one_advance(&resumed);
    let second = admit_iterative_provider_iteration(
        MODEL,
        PROMPT,
        &selected_policy,
        &opening.handle,
        std::slice::from_ref(&first),
        &response("call-a-second", 8),
        &second_drive,
    )
    .expect("terminal iteration");
    assert_eq!(second.request, continuation);
    let records = vec![first, second];
    let terminal_prefix = validate_iterative_provider_prefix(
        MODEL,
        PROMPT,
        &selected_policy,
        &opening.handle,
        &records,
    )
    .expect("terminal prefix");
    assert_eq!(
        terminal_prefix.phase,
        IterativeProviderPhase::ReflectTerminal
    );
    assert_eq!(
        terminal_prefix.call_ids,
        vec!["call-z-first", "call-a-second"]
    );

    let reflection = iterative_terminal_reflection_request(
        MODEL,
        PROMPT,
        &selected_policy,
        &opening.handle,
        &records,
    )
    .expect("reflection request");
    assert_eq!(reflection["tool_choice"], "none");
    assert_eq!(reflection["tools"], json!([]));
    assert_eq!(
        reflection["messages"].as_array().expect("messages").len(),
        7
    );
    assert_eq!(reflection["messages"][5]["tool_call_id"], "call-a-second");
    assert_eq!(
        reflection.pointer("/response_format/schema/additionalProperties"),
        Some(&Value::Bool(false))
    );
    assert!(
        iterative_advance_request(MODEL, PROMPT, &selected_policy, &opening.handle, &records)
            .is_err()
    );
}

#[test]
fn terminal_reflection_output_preserves_the_final_projection() {
    let opening = open("session:iterative-provider-final");
    let records = terminal_records(&opening);
    let projection = match &records.last().expect("last record").successor {
        IterationSuccessor::Terminal { projection } => projection,
        IterationSuccessor::Ready { .. } => panic!("expected terminal"),
    };
    let expected = FinalOutput {
        observed_status: projection.observed_status.clone(),
        session_id: projection.session_id.clone(),
        outcome_digest: projection.outcome_digest.clone(),
        statement: cantor_compact_reflection_loop::FINAL_STATEMENT.to_owned(),
    };
    let provider_response = json!({
        "choices": [{
            "finish_reason": "stop",
            "message": {
                "role": "assistant",
                "content": serde_json::to_string(&expected).expect("final JSON")
            }
        }]
    });
    assert_eq!(
        extract_final_output(&provider_response, projection).expect("final output"),
        expected
    );
}

#[test]
fn provider_evidence_is_sanitized_and_replay_mutations_refuse() {
    let opening = open("session:iterative-provider-replay");
    let selected_policy = policy(8);
    let drive = one_advance(&opening);
    let mut private_response = response("call-private", 8);
    private_response["choices"][0]["message"]["reasoning_content"] = json!("private");
    let record = admit_iterative_provider_iteration(
        MODEL,
        PROMPT,
        &selected_policy,
        &opening.handle,
        &[],
        &private_response,
        &drive,
    )
    .expect("sanitized record");
    assert!(
        record
            .sanitized_response
            .pointer("/choices/0/message/reasoning_content")
            .is_none()
    );
    let valid = vec![record.clone()];
    let projection = validate_iterative_provider_prefix(
        MODEL,
        PROMPT,
        &selected_policy,
        &opening.handle,
        &valid,
    )
    .expect("valid prefix");
    validate_provider_prefix_projection(&projection, MODEL, &opening.handle, &valid)
        .expect("valid projection");

    let mut changed_request = record.clone();
    changed_request.request["max_tokens"] = json!(257);
    assert!(
        validate_iterative_provider_prefix(
            MODEL,
            PROMPT,
            &selected_policy,
            &opening.handle,
            &[changed_request]
        )
        .is_err()
    );

    let mut private_record = record.clone();
    private_record.sanitized_response["thinking"] = json!("retained");
    assert!(
        validate_iterative_provider_prefix(
            MODEL,
            PROMPT,
            &selected_policy,
            &opening.handle,
            &[private_record]
        )
        .is_err()
    );

    let mut forked = record;
    forked.predecessor_handle.sequence += 1;
    assert!(
        validate_iterative_provider_prefix(
            MODEL,
            PROMPT,
            &selected_policy,
            &opening.handle,
            &[forked]
        )
        .is_err()
    );

    let mut changed_projection = projection;
    changed_projection.model = "other-model".to_owned();
    assert!(
        validate_provider_prefix_projection(&changed_projection, MODEL, &opening.handle, &valid)
            .is_err()
    );
}

#[test]
fn wrong_calls_duplicates_and_unjoined_advances_refuse() {
    let opening = open("session:iterative-provider-refusal");
    let selected_policy = policy(8);
    let first_drive = one_advance(&opening);

    assert!(
        admit_iterative_provider_iteration(
            MODEL,
            PROMPT,
            &selected_policy,
            &opening.handle,
            &[],
            &response("call-wrong-quota", 7),
            &first_drive
        )
        .is_err()
    );
    let mut wrong_call_type = response("call-wrong-type", 8);
    wrong_call_type["choices"][0]["message"]["tool_calls"][0]["type"] = json!("custom");
    assert!(
        admit_iterative_provider_iteration(
            MODEL,
            PROMPT,
            &selected_policy,
            &opening.handle,
            &[],
            &wrong_call_type,
            &first_drive
        )
        .is_err()
    );
    let mut wrong_tool = response("call-wrong-tool", 8);
    wrong_tool["choices"][0]["message"]["tool_calls"][0]["function"]["name"] = json!("other_tool");
    assert!(
        admit_iterative_provider_iteration(
            MODEL,
            PROMPT,
            &selected_policy,
            &opening.handle,
            &[],
            &wrong_tool,
            &first_drive
        )
        .is_err()
    );
    let mut premature = response("call-premature", 8);
    premature["choices"][0]["message"]["content"] = json!("answer too early");
    assert!(
        admit_iterative_provider_iteration(
            MODEL,
            PROMPT,
            &selected_policy,
            &opening.handle,
            &[],
            &premature,
            &first_drive
        )
        .is_err()
    );

    let (first, resumed) = first_record(&opening, &selected_policy);
    let second_drive = one_advance(&resumed);
    assert!(
        admit_iterative_provider_iteration(
            MODEL,
            PROMPT,
            &selected_policy,
            &opening.handle,
            std::slice::from_ref(&first),
            &response("call-z-first", 8),
            &second_drive
        )
        .is_err()
    );

    let other = open("session:iterative-provider-other");
    let other_drive = one_advance(&other);
    assert!(
        admit_iterative_provider_iteration(
            MODEL,
            PROMPT,
            &selected_policy,
            &opening.handle,
            &[],
            &response("call-other", 8),
            &other_drive
        )
        .is_err()
    );
    let multi_advance = drive_bound_session(&opening, selected_policy.clone()).expect("full drive");
    assert!(
        admit_iterative_provider_iteration(
            MODEL,
            PROMPT,
            &selected_policy,
            &opening.handle,
            &[],
            &response("call-multi", 8),
            &multi_advance
        )
        .is_err()
    );
}

#[test]
fn caps_terminal_state_and_closed_projection_are_enforced() {
    let opening = open("session:iterative-provider-cap");
    let one_call_policy = policy(1);
    let (record, _) = first_record(&opening, &one_call_policy);
    assert!(
        iterative_advance_request(
            MODEL,
            PROMPT,
            &one_call_policy,
            &opening.handle,
            std::slice::from_ref(&record)
        )
        .is_err()
    );
    assert!(
        iterative_terminal_reflection_request(
            MODEL,
            PROMPT,
            &one_call_policy,
            &opening.handle,
            std::slice::from_ref(&record)
        )
        .is_err()
    );

    let records = terminal_records(&opening);
    let projection =
        validate_iterative_provider_prefix(MODEL, PROMPT, &policy(8), &opening.handle, &records)
            .expect("terminal projection");
    let mut encoded = serde_json::to_value(&projection).expect("projection JSON");
    encoded["unknown"] = Value::Bool(true);
    assert!(
        serde_json::from_value::<
            cantor_compact_reflection_loop::IterativeProviderPrefixProjection,
        >(encoded)
        .is_err()
    );
}
