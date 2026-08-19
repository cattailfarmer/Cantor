use cantor_compact_coordination_mcp::CompactSessionStatus;
use cantor_compact_reflection_loop::{
    BoundSession, DETERMINISTIC_DRIVE_PROFILE, DeterministicAdvanceSuccessor, IterativeRunState,
    RunPolicy, StopReason, advance_bound_session_terminal, drive_bound_session,
    experimental_fixture_context_json, measure_deterministic_drive_result,
    normalize_deterministic_drive_result_json, open_bound_session,
    validate_deterministic_drive_measurement, validate_deterministic_drive_result,
};
use cantor_core::SemanticId;
use serde_json::{Value, json};

fn open(session: &str) -> BoundSession {
    open_bound_session(
        experimental_fixture_context_json().expect("fixture context"),
        SemanticId::new("registry:deterministic-drive-fixture").expect("registry id"),
        SemanticId::new(session).expect("session id"),
    )
    .expect("open bound session")
}

fn policy(maximum_steps_per_call: u64, maximum_tool_calls: u32) -> RunPolicy {
    RunPolicy {
        maximum_steps_per_call,
        maximum_tool_calls,
        maximum_provider_calls: maximum_tool_calls + 1,
        timeout_seconds: 120,
    }
}

#[test]
fn quota_sixty_four_is_byte_identical_to_the_p0_terminal_path() {
    let opening = open("session:deterministic-one-call");
    let (p0_terminal, p0_observation) =
        advance_bound_session_terminal(&opening, 64).expect("P0 terminal");
    let driven = drive_bound_session(&opening, policy(64, 1)).expect("drive terminal");

    assert_eq!(driven.profile, DETERMINISTIC_DRIVE_PROFILE);
    assert_eq!(driven.status, IterativeRunState::Complete);
    assert_eq!(driven.advances.len(), 1);
    assert!(matches!(
        driven.advances[0].successor,
        DeterministicAdvanceSuccessor::Terminal { .. }
    ));
    assert_eq!(driven.successor_registry, p0_terminal.registry);
    assert_eq!(driven.terminal_observation, Some(p0_observation));
    validate_deterministic_drive_result(&driven).expect("valid complete drive");
}

#[test]
fn quota_eight_yields_exactly_ready_then_terminal() {
    let opening = open("session:deterministic-ready-terminal");
    let driven = drive_bound_session(&opening, policy(8, 8)).expect("drive terminal");

    assert_eq!(driven.status, IterativeRunState::Complete);
    assert_eq!(driven.advances.len(), 2);
    let ready = match &driven.advances[0].successor {
        DeterministicAdvanceSuccessor::Ready { projection } => projection,
        DeterministicAdvanceSuccessor::Terminal { .. } => panic!("first advance was terminal"),
    };
    assert_eq!(ready.sequence, opening.handle.sequence + 1);
    assert!(!ready.state_is_terminal);
    assert!(matches!(
        driven.advances[1].successor,
        DeterministicAdvanceSuccessor::Terminal { .. }
    ));
    assert_eq!(
        driven
            .terminal_observation
            .as_ref()
            .expect("terminal observation")
            .handle
            .sequence,
        opening.handle.sequence + 2
    );
}

#[test]
fn cap_stop_preserves_a_live_head_and_resume_reaches_the_same_outcome() {
    let opening = open("session:deterministic-resume");
    let baseline = drive_bound_session(&opening, policy(64, 1)).expect("baseline terminal");
    let stopped = drive_bound_session(&opening, policy(1, 2)).expect("bounded stop");

    assert_eq!(stopped.status, IterativeRunState::Stopped);
    assert_eq!(stopped.stop_reason, Some(StopReason::ToolCallCap));
    assert_eq!(stopped.reentry_available, Some(true));
    assert_eq!(stopped.advances.len(), 2);
    let stopped_head = stopped.stopped_head.clone().expect("stopped head");
    assert_eq!(stopped_head.status, CompactSessionStatus::Ready);
    assert_eq!(stopped_head.sequence, opening.handle.sequence + 2);
    let resumed_opening = BoundSession {
        registry: stopped.successor_registry.clone(),
        handle: stopped_head,
    };
    let resumed = drive_bound_session(&resumed_opening, policy(1, 64)).expect("resume terminal");

    assert_eq!(resumed.status, IterativeRunState::Complete);
    assert_eq!(
        resumed
            .terminal_observation
            .as_ref()
            .expect("resumed terminal")
            .outcome_digest,
        baseline
            .terminal_observation
            .as_ref()
            .expect("baseline terminal")
            .outcome_digest
    );
    let resumed_record: Value = serde_json::from_str(
        &resumed
            .terminal_observation
            .as_ref()
            .expect("resumed terminal")
            .record_json,
    )
    .expect("resumed record");
    let baseline_record: Value = serde_json::from_str(
        &baseline
            .terminal_observation
            .as_ref()
            .expect("baseline terminal")
            .record_json,
    )
    .expect("baseline record");
    assert_eq!(resumed_record["outcome"], baseline_record["outcome"]);
}

#[test]
fn normalized_replay_is_deterministic_and_closed() {
    let opening = open("session:deterministic-replay");
    let selected_policy = policy(8, 8);
    let first = drive_bound_session(&opening, selected_policy.clone()).expect("first drive");
    let second = drive_bound_session(&opening, selected_policy).expect("second drive");
    assert_eq!(first, second);

    let pretty = serde_json::to_string_pretty(&first).expect("pretty result");
    let normalized = normalize_deterministic_drive_result_json(&pretty).expect("normalize");
    assert_eq!(
        normalized,
        serde_json::to_string(&first).expect("compact result")
    );
    assert_eq!(
        normalize_deterministic_drive_result_json(&normalized).expect("normalize again"),
        normalized
    );

    let mut unknown = serde_json::to_value(&first).expect("result value");
    unknown["hidden_state"] = Value::Bool(true);
    assert!(
        normalize_deterministic_drive_result_json(&unknown.to_string()).is_err(),
        "unknown result fields must fail closed"
    );
}

#[test]
fn measurement_separates_projection_transport_from_exact_retained_state() {
    let opening = open("session:deterministic-measurement");
    let complete = drive_bound_session(&opening, policy(8, 8)).expect("complete drive");
    let measurement = measure_deterministic_drive_result(&complete).expect("measurement");

    assert_eq!(measurement.advance_count, 2);
    assert_eq!(measurement.ready_projection_count, 1);
    assert!(measurement.ready_projection_bytes > 0);
    assert!(measurement.terminal_projection_bytes > 0);
    assert!(measurement.terminal_observation_bytes > measurement.terminal_projection_bytes);
    assert!(measurement.successor_registry_bytes > measurement.model_facing_projection_bytes);
    assert!(measurement.model_facing_share_of_result_basis_points < 10_000);
    validate_deterministic_drive_measurement(&measurement).expect("valid measurement");

    let stopped = drive_bound_session(&opening, policy(1, 2)).expect("stopped drive");
    let stopped_measurement =
        measure_deterministic_drive_result(&stopped).expect("stopped measurement");
    assert_eq!(stopped_measurement.terminal_projection_bytes, 0);
    assert_eq!(stopped_measurement.terminal_observation_bytes, 0);

    let mut invented_terminal = stopped_measurement;
    invented_terminal.terminal_projection_bytes = 1;
    assert!(validate_deterministic_drive_measurement(&invented_terminal).is_err());
}

#[test]
fn stale_forked_terminal_and_faulted_evidence_refuse() {
    let opening = open("session:deterministic-adversarial");
    let valid = drive_bound_session(&opening, policy(8, 8)).expect("valid drive");

    let mut stale = valid.clone();
    stale.opening_handle.sequence += 1;
    assert!(validate_deterministic_drive_result(&stale).is_err());

    let mut forked: Value = serde_json::to_value(&valid).expect("drive value");
    forked["advances"][0]["compact_response"]["result"]["handle"]["record_digest"] = json!({
        "algorithm": "sha256",
        "value": "0000000000000000000000000000000000000000000000000000000000000000"
    });
    let forked = serde_json::from_value(forked).expect("typed forked result");
    assert!(validate_deterministic_drive_result(&forked).is_err());

    let ready_projection = match &valid.advances[0].successor {
        DeterministicAdvanceSuccessor::Ready { projection } => projection.clone(),
        DeterministicAdvanceSuccessor::Terminal { .. } => panic!("expected READY first"),
    };
    let mut terminal_as_ready = valid.clone();
    terminal_as_ready
        .advances
        .last_mut()
        .expect("terminal advance")
        .successor = DeterministicAdvanceSuccessor::Ready {
        projection: ready_projection,
    };
    assert!(validate_deterministic_drive_result(&terminal_as_ready).is_err());

    let mut faulted: Value = serde_json::to_value(&valid).expect("drive value");
    faulted["advances"][0]["compact_response"]["status"] = json!("refused");
    faulted["advances"][0]["compact_response"]["result"] = Value::Null;
    faulted["advances"][0]["compact_response"]["fault"] = json!({
        "code": "fixture_refusal",
        "message": "adversarial response mutation"
    });
    let faulted = serde_json::from_value(faulted).expect("typed faulted result");
    assert!(validate_deterministic_drive_result(&faulted).is_err());

    let mut changed_head = valid;
    changed_head
        .terminal_observation
        .as_mut()
        .expect("terminal observation")
        .handle
        .sequence += 1;
    assert!(validate_deterministic_drive_result(&changed_head).is_err());
}

#[test]
fn cap_stop_cannot_claim_completion_or_a_dead_reentry() {
    let opening = open("session:deterministic-stop-adversarial");
    let stopped = drive_bound_session(&opening, policy(1, 2)).expect("bounded stop");

    let mut premature = stopped.clone();
    premature.status = IterativeRunState::Complete;
    assert!(validate_deterministic_drive_result(&premature).is_err());

    let mut dead = stopped.clone();
    dead.reentry_available = Some(false);
    assert!(validate_deterministic_drive_result(&dead).is_err());

    let mut under_cap = stopped;
    under_cap.advances.pop();
    assert!(validate_deterministic_drive_result(&under_cap).is_err());
}

#[test]
fn terminal_or_tampered_openings_never_advance() {
    let ready = open("session:deterministic-opening-refusal");
    let (terminal, _) = advance_bound_session_terminal(&ready, 64).expect("terminal fixture");
    assert!(drive_bound_session(&terminal, policy(8, 8)).is_err());

    let mut tampered = ready;
    tampered.handle.sequence += 1;
    assert!(drive_bound_session(&tampered, policy(8, 8)).is_err());
}
