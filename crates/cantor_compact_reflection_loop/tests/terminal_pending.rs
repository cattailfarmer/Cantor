use cantor_compact_reflection_loop::{
    BoundSession, RunPolicy, ScriptedTerminalPendingRun, admit_scripted_terminal_reflection,
    experimental_fixture_context_json, generate_scripted_terminal_pending_fixture,
    open_bound_session, run_scripted_complete_iterative, run_scripted_terminal_pending,
    scripted_terminal_reflection_response, validate_scripted_terminal_pending_run,
    validate_terminal_reflection_pending_report,
};
use cantor_core::SemanticId;
use serde_json::{Value, json};

fn open(session: &str) -> BoundSession {
    open_bound_session(
        experimental_fixture_context_json().expect("fixture context"),
        SemanticId::new("registry:terminal-pending-test").expect("registry id"),
        SemanticId::new(session).expect("session id"),
    )
    .expect("open session")
}

fn policy(maximum_steps_per_call: u64, maximum_tool_calls: u32) -> RunPolicy {
    RunPolicy {
        maximum_steps_per_call,
        maximum_tool_calls,
        maximum_provider_calls: maximum_tool_calls + 1,
        timeout_seconds: 120,
    }
}

fn ids(values: &[&str]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

#[test]
fn generated_fixture_reaches_terminal_without_claiming_reflection() {
    let pending = generate_scripted_terminal_pending_fixture().expect("pending fixture");
    validate_scripted_terminal_pending_run(&pending).expect("valid pending wrapper");
    validate_terminal_reflection_pending_report(&pending.report, &pending.prompt)
        .expect("valid pending report");

    assert_eq!(pending.report.iterations.len(), 2);
    assert_eq!(pending.report.usage.tool_calls, 2);
    assert_eq!(pending.report.usage.provider_calls, 2);
    assert_eq!(pending.report.usage.elapsed_milliseconds, 0);
    assert!(!pending.provider_execution_claimed);
    assert_eq!(pending.terminal_reflection_request["tool_choice"], "none");
    assert_eq!(
        pending.report.terminal_observation.handle.registry_digest,
        pending.successor_registry.registry_digest
    );
}

#[test]
fn pending_then_admit_is_exactly_the_uninterrupted_complete_run() {
    let opening = open("session:terminal-pending-equivalence");
    let selected_policy = policy(8, 8);
    let call_ids = ids(&["call-equivalent-0", "call-equivalent-1"]);
    let uninterrupted = run_scripted_complete_iterative(
        &opening,
        "scripted-model",
        "Run.",
        selected_policy.clone(),
        &call_ids,
    )
    .expect("uninterrupted complete run");
    let pending = run_scripted_terminal_pending(
        &opening,
        "scripted-model",
        "Run.",
        selected_policy,
        &call_ids,
    )
    .expect("terminal pending run");
    let response = scripted_terminal_reflection_response(&pending.report.terminal_projection);
    let admitted =
        admit_scripted_terminal_reflection(&pending, &response).expect("admitted reflection");

    assert_eq!(admitted, uninterrupted);
    assert_eq!(admitted.report.usage.provider_calls, 3);
}

#[test]
fn pending_form_is_closed_and_mutations_fail_replay() {
    let pending = generate_scripted_terminal_pending_fixture().expect("pending fixture");
    let encoded = serde_json::to_value(&pending).expect("pending JSON");
    let decoded: ScriptedTerminalPendingRun =
        serde_json::from_value(encoded.clone()).expect("closed round trip");
    assert_eq!(decoded, pending);
    let mut unknown = encoded;
    unknown["final_output"] = json!(null);
    assert!(serde_json::from_value::<ScriptedTerminalPendingRun>(unknown).is_err());

    let mut claimed = pending.clone();
    claimed.provider_execution_claimed = true;
    assert!(validate_scripted_terminal_pending_run(&claimed).is_err());

    let mut request = pending.clone();
    request.terminal_reflection_request["max_tokens"] = json!(513);
    assert!(validate_scripted_terminal_pending_run(&request).is_err());

    let mut usage = pending.clone();
    usage.report.usage.provider_calls += 1;
    assert!(validate_scripted_terminal_pending_run(&usage).is_err());

    let mut projection = pending.clone();
    projection.report.terminal_projection.sequence += 1;
    assert!(validate_scripted_terminal_pending_run(&projection).is_err());

    let mut registry = pending;
    registry.successor_registry.generation += 1;
    assert!(validate_scripted_terminal_pending_run(&registry).is_err());
}

#[test]
fn finite_call_identity_boundaries_fail_closed() {
    let opening = open("session:terminal-pending-bounds");
    let selected_policy = policy(8, 8);
    assert!(
        run_scripted_terminal_pending(
            &opening,
            "scripted-model",
            "Run.",
            selected_policy.clone(),
            &[]
        )
        .is_err()
    );
    assert!(
        run_scripted_terminal_pending(
            &opening,
            "scripted-model",
            "Run.",
            selected_policy.clone(),
            &ids(&["call-only-ready"])
        )
        .is_err()
    );
    assert!(
        run_scripted_terminal_pending(
            &opening,
            "scripted-model",
            "Run.",
            selected_policy.clone(),
            &ids(&["call-0", "call-1", "call-after-terminal"])
        )
        .is_err()
    );
    assert!(
        run_scripted_terminal_pending(
            &opening,
            "scripted-model",
            "Run.",
            selected_policy,
            &ids(&["call-duplicate", "call-duplicate"])
        )
        .is_err()
    );
    assert!(
        run_scripted_terminal_pending(
            &opening,
            "scripted-model",
            "Run.",
            policy(8, 1),
            &ids(&["call-0", "call-1"])
        )
        .is_err()
    );
}

#[test]
fn reflection_is_sanitized_validated_and_never_advances_terminal_state() {
    let pending = generate_scripted_terminal_pending_fixture().expect("pending fixture");
    let terminal_registry = pending.successor_registry.clone();
    let mut response = scripted_terminal_reflection_response(&pending.report.terminal_projection);
    response["thinking"] = json!("private fixture field");
    let complete =
        admit_scripted_terminal_reflection(&pending, &response).expect("admitted response");
    assert_eq!(complete.successor_registry, terminal_registry);
    assert!(
        complete
            .sanitized_terminal_reflection_response
            .get("thinking")
            .is_none()
    );

    let mut wrong = scripted_terminal_reflection_response(&pending.report.terminal_projection);
    wrong["choices"][0]["message"]["content"] = Value::String("{}".to_owned());
    assert!(admit_scripted_terminal_reflection(&pending, &wrong).is_err());
}
