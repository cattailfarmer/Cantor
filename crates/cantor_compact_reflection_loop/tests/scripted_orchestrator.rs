use cantor_compact_reflection_loop::{
    BoundSession, IterativeRunState, RunPolicy, ScriptedCompleteRun,
    advance_bound_session_terminal, experimental_fixture_context_json,
    generate_scripted_complete_fixture, open_bound_session, run_scripted_complete_iterative,
    validate_iterative_report, validate_scripted_complete_run,
};
use cantor_core::SemanticId;
use serde_json::{Value, json};

fn open(session: &str) -> BoundSession {
    open_bound_session(
        experimental_fixture_context_json().expect("fixture context"),
        SemanticId::new("registry:scripted-orchestrator-test").expect("registry id"),
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
fn generated_fixture_completes_ready_terminal_and_reflection() {
    let run = generate_scripted_complete_fixture().expect("scripted fixture");
    validate_scripted_complete_run(&run).expect("valid scripted run");
    validate_iterative_report(&run.report).expect("valid iterative report");

    assert_eq!(run.report.status, IterativeRunState::Complete);
    assert_eq!(run.report.iterations.len(), 2);
    assert_eq!(run.report.usage.tool_calls, 2);
    assert_eq!(run.report.usage.provider_calls, 3);
    assert_eq!(run.report.usage.elapsed_milliseconds, 0);
    assert!(!run.provider_execution_claimed);
    assert!(run.report.reentry_handle.is_none());
    assert!(run.report.stop_reason.is_none());
    assert_eq!(run.terminal_reflection_request["tool_choice"], "none");
    assert_eq!(
        run.terminal_reflection_request["messages"]
            .as_array()
            .expect("messages")
            .len(),
        7
    );
    assert_eq!(
        run.report
            .terminal_observation
            .as_ref()
            .expect("terminal observation")
            .handle
            .registry_digest,
        run.successor_registry.registry_digest
    );
}

#[test]
fn scripted_run_is_deterministic_closed_and_replayable() {
    let first = generate_scripted_complete_fixture().expect("first fixture");
    let second = generate_scripted_complete_fixture().expect("second fixture");
    assert_eq!(first, second);

    let encoded = serde_json::to_value(&first).expect("run JSON");
    let decoded: ScriptedCompleteRun =
        serde_json::from_value(encoded.clone()).expect("closed round trip");
    assert_eq!(decoded, first);
    let mut unknown = encoded;
    unknown["provider_socket"] = Value::Bool(false);
    assert!(serde_json::from_value::<ScriptedCompleteRun>(unknown).is_err());
}

#[test]
fn one_call_scripted_path_is_byte_identical_to_p0() {
    let opening = open("session:scripted-one-call");
    let (_, p0_observation) = advance_bound_session_terminal(&opening, 64).expect("P0 terminal");
    let run = run_scripted_complete_iterative(
        &opening,
        "scripted-model",
        "Run the one-call fixture.",
        policy(64, 1),
        &ids(&["call-one"]),
    )
    .expect("scripted one-call run");
    assert_eq!(run.report.iterations.len(), 1);
    assert_eq!(run.report.terminal_observation, Some(p0_observation));
}

#[test]
fn finite_script_and_policy_boundaries_fail_closed() {
    let opening = open("session:scripted-bounds");
    let selected_policy = policy(8, 8);
    assert!(
        run_scripted_complete_iterative(
            &opening,
            "scripted-model",
            "Run.",
            selected_policy.clone(),
            &[]
        )
        .is_err()
    );
    assert!(
        run_scripted_complete_iterative(
            &opening,
            "scripted-model",
            "Run.",
            selected_policy.clone(),
            &ids(&["call-only-ready"])
        )
        .is_err()
    );
    assert!(
        run_scripted_complete_iterative(
            &opening,
            "scripted-model",
            "Run.",
            selected_policy.clone(),
            &ids(&["call-0", "call-1", "call-after-terminal"])
        )
        .is_err()
    );
    assert!(
        run_scripted_complete_iterative(
            &opening,
            "scripted-model",
            "Run.",
            selected_policy,
            &ids(&["call-duplicate", "call-duplicate"])
        )
        .is_err()
    );
    assert!(
        run_scripted_complete_iterative(
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
fn wrapper_report_registry_and_reflection_mutations_refuse() {
    let run = generate_scripted_complete_fixture().expect("scripted fixture");

    let mut claimed = run.clone();
    claimed.provider_execution_claimed = true;
    assert!(validate_scripted_complete_run(&claimed).is_err());

    let mut request = run.clone();
    request.terminal_reflection_request["max_tokens"] = json!(513);
    assert!(validate_scripted_complete_run(&request).is_err());

    let mut response = run.clone();
    response.sanitized_terminal_reflection_response["choices"][0]["message"]["content"] =
        json!("{}");
    assert!(validate_scripted_complete_run(&response).is_err());

    let mut private = run.clone();
    private.sanitized_terminal_reflection_response["thinking"] = json!("retained");
    assert!(validate_scripted_complete_run(&private).is_err());

    let mut registry = run.clone();
    registry.successor_registry.generation += 1;
    assert!(validate_scripted_complete_run(&registry).is_err());

    let mut transcript = run.clone();
    transcript.report.iterations[0].request["temperature"] = json!(1);
    assert!(validate_scripted_complete_run(&transcript).is_err());

    let mut prompt = run;
    prompt.prompt.push_str(" changed");
    assert!(validate_scripted_complete_run(&prompt).is_err());
}
