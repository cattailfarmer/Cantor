use cantor_compact_reflection_loop::{
    EffectlessDispatchPhase, EffectlessDispatchTrace, ScriptedEffectlessDispatchRun,
    admit_iteration_effectless_dispatch, admit_terminal_effectless_dispatch,
    compile_iteration_transport_envelope, generate_scripted_effectless_dispatch_run,
    generate_scripted_transport_envelope_set, prepare_effectless_dispatch,
    pretty_scripted_effectless_dispatch_run_bytes, record_effectless_fixture_dispatch,
    record_effectless_fixture_response, validate_effectless_dispatch_trace,
    validate_scripted_effectless_dispatch_run,
};
use serde_json::{Value, json};

#[test]
fn pure_lifecycle_exposes_every_intermediate_phase() {
    let set = generate_scripted_transport_envelope_set().expect("envelope set");
    let envelope = &set.iteration_envelopes[0];
    let transport = &set.source_projection.iteration_transports[0];

    let prepared = prepare_effectless_dispatch(envelope).expect("prepared");
    assert_eq!(prepared.phase, EffectlessDispatchPhase::Prepared);
    assert_eq!(prepared.transition_sequence, 0);
    assert!(prepared.fixture_dispatch.is_none());
    validate_effectless_dispatch_trace(&prepared).expect("prepared valid");

    let dispatched = record_effectless_fixture_dispatch(&prepared).expect("dispatched");
    assert_eq!(
        dispatched.phase,
        EffectlessDispatchPhase::FixtureDispatchRecorded
    );
    assert_eq!(dispatched.transition_sequence, 1);
    assert!(dispatched.fixture_dispatch.is_some());
    assert_eq!(dispatched.envelope, prepared.envelope);

    let received = record_effectless_fixture_response(&dispatched, &transport.sanitized_response)
        .expect("response recorded");
    assert_eq!(
        received.phase,
        EffectlessDispatchPhase::FixtureResponseRecorded
    );
    assert_eq!(received.transition_sequence, 2);
    assert!(received.response_digest.is_some());
    assert!(!received.canonical_admission_recorded);

    let admitted = admit_iteration_effectless_dispatch(&received, transport).expect("admitted");
    assert_eq!(admitted.phase, EffectlessDispatchPhase::Admitted);
    assert_eq!(admitted.transition_sequence, 3);
    assert!(admitted.canonical_admission_recorded);
    assert_eq!(admitted.supplied_response, received.supplied_response);
    assert!(!admitted.provider_execution_claimed);
    assert!(!admitted.external_effect_claimed);
    assert!(!admitted.persistence_claimed);
}

#[test]
fn fixture_run_is_complete_deterministic_strict_and_normalized() {
    let first = generate_scripted_effectless_dispatch_run().expect("first run");
    let second = generate_scripted_effectless_dispatch_run().expect("second run");
    assert_eq!(first, second);
    validate_scripted_effectless_dispatch_run(&first).expect("valid run");
    assert!(first.all_admitted);
    assert_eq!(first.admitted_trace_count, first.iteration_traces.len() + 1);
    assert!(
        first
            .iteration_traces
            .iter()
            .all(|trace| trace.phase == EffectlessDispatchPhase::Admitted)
    );
    assert_eq!(
        first.terminal_reflection_trace.phase,
        EffectlessDispatchPhase::Admitted
    );

    let bytes = pretty_scripted_effectless_dispatch_run_bytes(&first).expect("pretty run");
    assert_eq!(bytes.last(), Some(&b'\n'));
    let decoded: ScriptedEffectlessDispatchRun =
        serde_json::from_slice(&bytes).expect("strict JSON");
    assert_eq!(decoded, first);

    let mut unknown = serde_json::to_value(&first).expect("value");
    unknown["provider_connected"] = Value::Bool(false);
    assert!(serde_json::from_value::<ScriptedEffectlessDispatchRun>(unknown).is_err());

    let mut unknown_trace = serde_json::to_value(&first.iteration_traces[0]).expect("trace value");
    unknown_trace["physical_dispatch"] = Value::Bool(false);
    assert!(serde_json::from_value::<EffectlessDispatchTrace>(unknown_trace).is_err());
}

#[test]
fn illegal_transitions_and_trace_mutations_fail_closed() {
    let set = generate_scripted_transport_envelope_set().expect("set");
    let transport = &set.source_projection.iteration_transports[0];
    let prepared = prepare_effectless_dispatch(&set.iteration_envelopes[0]).expect("prepared");
    assert!(record_effectless_fixture_response(&prepared, &transport.sanitized_response).is_err());
    assert!(admit_iteration_effectless_dispatch(&prepared, transport).is_err());

    let dispatched = record_effectless_fixture_dispatch(&prepared).expect("dispatched");
    assert!(record_effectless_fixture_dispatch(&dispatched).is_err());
    assert!(admit_iteration_effectless_dispatch(&dispatched, transport).is_err());
    assert!(record_effectless_fixture_response(&dispatched, &Value::Null).is_err());

    let received = record_effectless_fixture_response(&dispatched, &transport.sanitized_response)
        .expect("received");
    assert!(record_effectless_fixture_dispatch(&received).is_err());
    assert!(record_effectless_fixture_response(&received, &transport.sanitized_response).is_err());

    let admitted = admit_iteration_effectless_dispatch(&received, transport).expect("admitted");
    assert!(admit_iteration_effectless_dispatch(&admitted, transport).is_err());

    let mut sequence = received.clone();
    sequence.transition_sequence = 3;
    assert!(validate_effectless_dispatch_trace(&sequence).is_err());

    let mut envelope_digest = received.clone();
    envelope_digest.envelope_digest.value.push('0');
    assert!(validate_effectless_dispatch_trace(&envelope_digest).is_err());

    let mut response = received.clone();
    response.supplied_response.as_mut().expect("response")["id"] = json!("changed");
    assert!(validate_effectless_dispatch_trace(&response).is_err());

    let mut dispatch = received.clone();
    dispatch
        .fixture_dispatch
        .as_mut()
        .expect("dispatch")
        .provider_execution_claimed = true;
    assert!(validate_effectless_dispatch_trace(&dispatch).is_err());

    let mut claim = received.clone();
    claim.external_effect_claimed = true;
    assert!(validate_effectless_dispatch_trace(&claim).is_err());

    let mut fields = received;
    fields.canonical_admission_recorded = true;
    assert!(validate_effectless_dispatch_trace(&fields).is_err());
}

#[test]
fn coherent_substitution_cannot_cross_canonical_admission() {
    let set = generate_scripted_transport_envelope_set().expect("set");
    let canonical_transport = &set.source_projection.iteration_transports[1];
    let mut substituted_transport = canonical_transport.clone();
    substituted_transport.actual_request["temperature"] = json!(1);
    let substituted_envelope =
        compile_iteration_transport_envelope(&substituted_transport).expect("substitute envelope");
    let prepared = prepare_effectless_dispatch(&substituted_envelope).expect("prepared");
    let dispatched = record_effectless_fixture_dispatch(&prepared).expect("dispatched");
    let received =
        record_effectless_fixture_response(&dispatched, &canonical_transport.sanitized_response)
            .expect("received");
    validate_effectless_dispatch_trace(&received).expect("locally valid");
    assert!(admit_iteration_effectless_dispatch(&received, canonical_transport).is_err());

    let canonical_envelope = &set.iteration_envelopes[1];
    let prepared = prepare_effectless_dispatch(canonical_envelope).expect("prepared canonical");
    let dispatched = record_effectless_fixture_dispatch(&prepared).expect("dispatched canonical");
    let wrong_response = json!({"choices": []});
    let received = record_effectless_fixture_response(&dispatched, &wrong_response)
        .expect("wrong response is locally recordable");
    assert!(admit_iteration_effectless_dispatch(&received, canonical_transport).is_err());
}

#[test]
fn terminal_admission_cannot_be_interchanged_with_iteration_admission() {
    let set = generate_scripted_transport_envelope_set().expect("set");
    let terminal = &set.source_projection.terminal_reflection_transport;
    let prepared =
        prepare_effectless_dispatch(&set.terminal_reflection_envelope).expect("prepared");
    let dispatched = record_effectless_fixture_dispatch(&prepared).expect("dispatched");
    let received = record_effectless_fixture_response(&dispatched, &terminal.sanitized_response)
        .expect("received");
    admit_terminal_effectless_dispatch(&received, terminal).expect("terminal admitted");
    assert!(
        admit_iteration_effectless_dispatch(
            &received,
            &set.source_projection.iteration_transports[0]
        )
        .is_err()
    );

    let mut run = generate_scripted_effectless_dispatch_run().expect("run");
    run.iteration_traces.swap(0, 1);
    assert!(validate_scripted_effectless_dispatch_run(&run).is_err());

    let mut claim = generate_scripted_effectless_dispatch_run().expect("run");
    claim.provider_execution_claimed = true;
    assert!(validate_scripted_effectless_dispatch_run(&claim).is_err());
}
