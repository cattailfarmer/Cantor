use cantor_compact_coordination_mcp::{
    CompactCoordinationHandle, CompactSessionCommand, CompactSessionResponse, CompactSessionResult,
    apply_compact_coordination_command,
};
use cantor_compact_reflection_loop::*;
use cantor_core::SemanticId;
use serde_json::{Value, json};

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn open(session: &str) -> BoundSession {
    open_bound_session(
        experimental_fixture_context_json().expect("fixture context"),
        sid("registry:iterative-forms-test"),
        sid(session),
    )
    .expect("open")
}

fn state_handle(response: &CompactSessionResponse) -> CompactCoordinationHandle {
    match response.result.as_ref().expect("result") {
        CompactSessionResult::State { handle } => handle.clone(),
        CompactSessionResult::Record { .. } => panic!("expected state"),
    }
}

fn advance(bound: &BoundSession, maximum_steps: u64) -> (BoundSession, CompactSessionResponse) {
    let transition = apply_compact_coordination_command(
        &bound.registry,
        CompactSessionCommand::Advance {
            expected_registry_digest: bound.handle.registry_digest.clone(),
            session_id: bound.handle.session_id.clone(),
            expected_sequence: bound.handle.sequence,
            expected_record_digest: bound.handle.record_digest.clone(),
            maximum_steps,
        },
    );
    assert!(!transition.response.is_error());
    let handle = state_handle(&transition.response);
    (
        BoundSession {
            registry: transition.successor,
            handle,
        },
        transition.response,
    )
}

fn terminal_observation(bound: &BoundSession) -> TerminalObservation {
    let transition = apply_compact_coordination_command(
        &bound.registry,
        CompactSessionCommand::Read {
            expected_registry_digest: bound.handle.registry_digest.clone(),
            session_id: bound.handle.session_id.clone(),
        },
    );
    match transition.response.result.expect("read result") {
        CompactSessionResult::Record {
            handle,
            record_json,
            ..
        } => TerminalObservation {
            observed_status: "terminal_outcome".to_owned(),
            outcome_digest: handle.outcome_digest.clone().expect("outcome digest"),
            handle,
            record_json,
        },
        CompactSessionResult::State { .. } => panic!("expected record"),
    }
}

fn request(index: u32) -> Value {
    json!({"checkpoint": index, "tools": [{"name": TOOL_NAME}]})
}

fn response(index: u32) -> Value {
    json!({"choices": [{"message": {"role": "assistant", "tool_call": index}}]})
}

fn nonclaims() -> Vec<String> {
    ITERATIVE_REPORT_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}

#[test]
fn run_policy_is_positive_bounded_and_provider_sufficient() {
    validate_run_policy(&RunPolicy::default()).expect("default policy");
    for invalid in [
        RunPolicy {
            maximum_steps_per_call: 0,
            ..RunPolicy::default()
        },
        RunPolicy {
            maximum_tool_calls: 0,
            ..RunPolicy::default()
        },
        RunPolicy {
            maximum_tool_calls: 8,
            maximum_provider_calls: 7,
            ..RunPolicy::default()
        },
        RunPolicy {
            timeout_seconds: 3_601,
            ..RunPolicy::default()
        },
    ] {
        assert!(validate_run_policy(&invalid).is_err());
    }
    assert!(
        serde_json::from_value::<RunPolicy>(json!({
            "maximum_steps_per_call": 8,
            "maximum_tool_calls": 8,
            "maximum_provider_calls": 17,
            "timeout_seconds": 120,
            "hidden": true
        }))
        .is_err()
    );
}

#[test]
fn ready_projection_is_record_derived_compact_and_nonterminal() {
    let opening = open("session:iterative-ready");
    let (ready, _) = advance(&opening, 8);
    let projection =
        project_ready_record(&ready.registry, &ready.handle).expect("ready projection");
    validate_ready_projection(&projection, &ready.handle).expect("projection validation");
    let encoded = serde_json::to_value(&projection).expect("serialize");
    assert_eq!(encoded["state_is_terminal"], false);
    assert_eq!(encoded["exact_state_under_host_custody"], true);
    assert!(encoded.get("checkpoint").is_none());
    assert!(encoded.get("context").is_none());
    assert!(encoded.get("model_summary").is_none());

    let mut changed_registry = ready.registry.clone();
    changed_registry.generation = changed_registry.generation.saturating_add(1);
    assert!(project_ready_record(&changed_registry, &ready.handle).is_err());

    let mut changed = projection;
    changed.state_is_terminal = true;
    assert!(validate_ready_projection(&changed, &ready.handle).is_err());
}

#[test]
fn stopped_report_preserves_the_exact_ready_head_exclusively() {
    let policy = RunPolicy {
        maximum_tool_calls: 1,
        maximum_provider_calls: 2,
        ..RunPolicy::default()
    };
    let opening = open("session:iterative-stopped");
    let (ready, compact_response) = advance(&opening, policy.maximum_steps_per_call);
    let projection = project_ready_record(&ready.registry, &ready.handle).expect("projection");
    let report = IterativeReport {
        profile: ITERATIVE_REPORT_PROFILE.to_owned(),
        status: IterativeRunState::Stopped,
        policy,
        usage: PolicyUsage {
            tool_calls: 1,
            provider_calls: 1,
            elapsed_milliseconds: 1,
        },
        base_url: "http://127.0.0.1:8081/v1".to_owned(),
        model: "fixture-model".to_owned(),
        session_id: opening.handle.session_id.clone(),
        opening_handle: opening.handle.clone(),
        iterations: vec![IterationRecord {
            iteration_index: 0,
            predecessor_handle: opening.handle,
            request: request(0),
            sanitized_response: response(0),
            call_id: "call-iterative-0".to_owned(),
            maximum_steps: 8,
            compact_response,
            successor: IterationSuccessor::Ready { projection },
        }],
        terminal_observation: None,
        terminal_projection: None,
        final_output: None,
        reentry_handle: Some(ready.handle),
        reentry_available: Some(true),
        stop_reason: Some(StopReason::ToolCallCap),
        private_reasoning_recorded: false,
        nonclaims: nonclaims(),
    };
    validate_iterative_report(&report).expect("stopped report");

    let mut premature_timeout = report.clone();
    premature_timeout.stop_reason = Some(StopReason::Timeout);
    premature_timeout.usage.elapsed_milliseconds = 119_999;
    assert!(validate_iterative_report(&premature_timeout).is_err());
    premature_timeout.usage.elapsed_milliseconds = 120_000;
    validate_iterative_report(&premature_timeout).expect("observed timeout");

    let mut after_restart = report.clone();
    after_restart.stop_reason = Some(StopReason::RestartUnavailable);
    after_restart.reentry_available = Some(false);
    validate_iterative_report(&after_restart).expect("honest restart loss");
    after_restart.stop_reason = Some(StopReason::ToolCallCap);
    assert!(validate_iterative_report(&after_restart).is_err());

    let mut fabricated = report;
    fabricated.status = IterativeRunState::Complete;
    assert!(validate_iterative_report(&fabricated).is_err());
}

#[test]
fn complete_report_requires_one_terminal_head_and_no_reentry() {
    let policy = RunPolicy {
        maximum_steps_per_call: 64,
        ..RunPolicy::default()
    };
    let opening = open("session:iterative-complete");
    let (terminal, compact_response) = advance(&opening, policy.maximum_steps_per_call);
    let observation = terminal_observation(&terminal);
    let projection = project_terminal_observation(&observation).expect("terminal projection");
    let final_output = FinalOutput {
        observed_status: projection.observed_status.clone(),
        session_id: projection.session_id.clone(),
        outcome_digest: projection.outcome_digest.clone(),
        statement: FINAL_STATEMENT.to_owned(),
    };
    let report = IterativeReport {
        profile: ITERATIVE_REPORT_PROFILE.to_owned(),
        status: IterativeRunState::Complete,
        policy,
        usage: PolicyUsage {
            tool_calls: 1,
            provider_calls: 2,
            elapsed_milliseconds: 1,
        },
        base_url: "http://localhost:8081/v1".to_owned(),
        model: "fixture-model".to_owned(),
        session_id: opening.handle.session_id.clone(),
        opening_handle: opening.handle.clone(),
        iterations: vec![IterationRecord {
            iteration_index: 0,
            predecessor_handle: opening.handle,
            request: request(0),
            sanitized_response: response(0),
            call_id: "call-iterative-0".to_owned(),
            maximum_steps: 64,
            compact_response,
            successor: IterationSuccessor::Terminal {
                projection: projection.clone(),
            },
        }],
        terminal_observation: Some(observation),
        terminal_projection: Some(projection),
        final_output: Some(final_output),
        reentry_handle: None,
        reentry_available: None,
        stop_reason: None,
        private_reasoning_recorded: false,
        nonclaims: nonclaims(),
    };
    validate_iterative_report(&report).expect("complete report");

    let mut contradictory = report;
    contradictory.reentry_handle = Some(terminal.handle);
    assert!(validate_iterative_report(&contradictory).is_err());
}

#[test]
fn iteration_chain_rejects_a_predecessor_fork() {
    let policy = RunPolicy {
        maximum_steps_per_call: 8,
        ..RunPolicy::default()
    };
    let opening = open("session:iterative-fork");
    let (first, first_response) = advance(&opening, 8);
    let first_projection =
        project_ready_record(&first.registry, &first.handle).expect("first projection");
    let (terminal, second_response) = advance(&first, 8);
    let observation = terminal_observation(&terminal);
    let terminal_projection =
        project_terminal_observation(&observation).expect("terminal projection");
    let final_output = FinalOutput {
        observed_status: terminal_projection.observed_status.clone(),
        session_id: terminal_projection.session_id.clone(),
        outcome_digest: terminal_projection.outcome_digest.clone(),
        statement: FINAL_STATEMENT.to_owned(),
    };
    let mut report = IterativeReport {
        profile: ITERATIVE_REPORT_PROFILE.to_owned(),
        status: IterativeRunState::Complete,
        policy,
        usage: PolicyUsage {
            tool_calls: 2,
            provider_calls: 3,
            elapsed_milliseconds: 1,
        },
        base_url: "http://127.0.0.1:8081/v1".to_owned(),
        model: "fixture-model".to_owned(),
        session_id: opening.handle.session_id.clone(),
        opening_handle: opening.handle.clone(),
        iterations: vec![
            IterationRecord {
                iteration_index: 0,
                predecessor_handle: opening.handle.clone(),
                request: request(0),
                sanitized_response: response(0),
                call_id: "call-iterative-0".to_owned(),
                maximum_steps: 8,
                compact_response: first_response,
                successor: IterationSuccessor::Ready {
                    projection: first_projection,
                },
            },
            IterationRecord {
                iteration_index: 1,
                predecessor_handle: first.handle,
                request: request(1),
                sanitized_response: response(1),
                call_id: "call-iterative-1".to_owned(),
                maximum_steps: 8,
                compact_response: second_response,
                successor: IterationSuccessor::Terminal {
                    projection: terminal_projection.clone(),
                },
            },
        ],
        terminal_observation: Some(observation),
        terminal_projection: Some(terminal_projection),
        final_output: Some(final_output),
        reentry_handle: None,
        reentry_available: None,
        stop_reason: None,
        private_reasoning_recorded: false,
        nonclaims: nonclaims(),
    };
    validate_iterative_report(&report).expect("two-iteration report");

    report.iterations[1].predecessor_handle = opening.handle;
    assert!(validate_iterative_report(&report).is_err());
}
