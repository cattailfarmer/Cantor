use cantor_compact_reflection_loop::{
    DispatchCheckpointNextOperation, DispatchLifecycleCheckpoint, EffectlessDispatchPhase,
    ScriptedDispatchResumeCorpus, compile_dispatch_lifecycle_checkpoint,
    compile_iteration_transport_envelope, generate_scripted_dispatch_resume_corpus,
    generate_scripted_transport_envelope_set, prepare_effectless_dispatch,
    pretty_scripted_dispatch_resume_corpus_bytes, record_effectless_fixture_dispatch,
    record_effectless_fixture_response, resume_iteration_fixture_checkpoint,
    resume_terminal_fixture_checkpoint, validate_dispatch_lifecycle_checkpoint,
    validate_scripted_dispatch_resume_corpus,
};
use serde_json::{Value, json};

#[test]
fn every_fixture_phase_resumes_to_the_uninterrupted_trace() {
    let corpus = generate_scripted_dispatch_resume_corpus().expect("corpus");
    validate_scripted_dispatch_resume_corpus(&corpus).expect("valid corpus");
    assert_eq!(corpus.source_run.iteration_traces.len(), 2);
    assert_eq!(corpus.cases.len(), 12);
    assert_eq!(corpus.case_count, 12);
    assert!(corpus.all_exactly_equivalent);

    let phase_cycle = [
        (
            EffectlessDispatchPhase::Prepared,
            DispatchCheckpointNextOperation::RecordFixtureDispatch,
        ),
        (
            EffectlessDispatchPhase::FixtureDispatchRecorded,
            DispatchCheckpointNextOperation::RecordFixtureResponse,
        ),
        (
            EffectlessDispatchPhase::FixtureResponseRecorded,
            DispatchCheckpointNextOperation::AdmitCanonical,
        ),
        (
            EffectlessDispatchPhase::Admitted,
            DispatchCheckpointNextOperation::Complete,
        ),
    ];
    for (index, case) in corpus.cases.iter().enumerate() {
        let (phase, next) = phase_cycle[index % phase_cycle.len()];
        assert_eq!(case.case_ordinal as usize, index);
        assert_eq!(case.transport_position as usize, index / 4);
        assert_eq!(case.terminal_reflection, index >= 8);
        assert_eq!(case.checkpoint_phase, phase);
        assert_eq!(case.expected_next_operation, next);
        assert_eq!(case.checkpoint.next_operation, next);
        assert_eq!(case.resumed_trace, case.uninterrupted_trace);
        assert!(case.exactly_equivalent);
        validate_dispatch_lifecycle_checkpoint(&case.checkpoint).expect("valid checkpoint");
    }
}

#[test]
fn resume_corpus_is_deterministic_strict_and_normalized() {
    let first = generate_scripted_dispatch_resume_corpus().expect("first");
    let second = generate_scripted_dispatch_resume_corpus().expect("second");
    assert_eq!(first, second);
    let bytes = pretty_scripted_dispatch_resume_corpus_bytes(&first).expect("pretty corpus");
    assert_eq!(bytes.last(), Some(&b'\n'));
    let decoded: ScriptedDispatchResumeCorpus =
        serde_json::from_slice(&bytes).expect("strict JSON");
    assert_eq!(decoded, first);

    let mut unknown = serde_json::to_value(&first).expect("value");
    unknown["checkpoint_saved"] = Value::Bool(false);
    assert!(serde_json::from_value::<ScriptedDispatchResumeCorpus>(unknown).is_err());

    let mut unknown_checkpoint =
        serde_json::to_value(&first.cases[0].checkpoint).expect("checkpoint value");
    unknown_checkpoint["kv_cache"] = Value::Null;
    assert!(serde_json::from_value::<DispatchLifecycleCheckpoint>(unknown_checkpoint).is_err());
}

#[test]
fn checkpoint_and_corpus_mutations_fail_closed() {
    let corpus = generate_scripted_dispatch_resume_corpus().expect("corpus");
    let checkpoint = &corpus.cases[0].checkpoint;

    let mut digest = checkpoint.clone();
    digest.trace_digest.value.push('0');
    assert!(validate_dispatch_lifecycle_checkpoint(&digest).is_err());

    let mut next = checkpoint.clone();
    next.next_operation = DispatchCheckpointNextOperation::Complete;
    assert!(validate_dispatch_lifecycle_checkpoint(&next).is_err());

    let mut state = checkpoint.clone();
    state.serialized_state_only = false;
    assert!(validate_dispatch_lifecycle_checkpoint(&state).is_err());

    let mut persistence = checkpoint.clone();
    persistence.persistence_claimed = true;
    assert!(validate_dispatch_lifecycle_checkpoint(&persistence).is_err());

    let mut process = checkpoint.clone();
    process.process_resume_claimed = true;
    assert!(validate_dispatch_lifecycle_checkpoint(&process).is_err());

    let mut nonclaim = checkpoint.clone();
    nonclaim.nonclaims.pop();
    assert!(validate_dispatch_lifecycle_checkpoint(&nonclaim).is_err());

    let mut reordered = corpus.clone();
    reordered.cases.swap(0, 1);
    assert!(validate_scripted_dispatch_resume_corpus(&reordered).is_err());

    let mut omitted = corpus.clone();
    omitted.cases.pop();
    omitted.case_count -= 1;
    assert!(validate_scripted_dispatch_resume_corpus(&omitted).is_err());

    let mut equivalence = corpus.clone();
    equivalence.cases[0].exactly_equivalent = false;
    assert!(validate_scripted_dispatch_resume_corpus(&equivalence).is_err());

    let mut claim = corpus;
    claim.semantic_equivalence_claimed = true;
    assert!(validate_scripted_dispatch_resume_corpus(&claim).is_err());
}

#[test]
fn locally_valid_substitution_and_cross_kind_resume_fail_canonical_binding() {
    let set = generate_scripted_transport_envelope_set().expect("set");
    let canonical_transport = &set.source_projection.iteration_transports[1];
    let mut substituted_transport = canonical_transport.clone();
    substituted_transport.actual_request["temperature"] = json!(1);
    let substituted_envelope =
        compile_iteration_transport_envelope(&substituted_transport).expect("substitute envelope");
    let trace = prepare_effectless_dispatch(&substituted_envelope).expect("substitute trace");
    let checkpoint = compile_dispatch_lifecycle_checkpoint(&trace).expect("local checkpoint");
    validate_dispatch_lifecycle_checkpoint(&checkpoint).expect("locally valid checkpoint");
    assert!(resume_iteration_fixture_checkpoint(&checkpoint, canonical_transport).is_err());

    let terminal_transport = &set.source_projection.terminal_reflection_transport;
    assert!(resume_terminal_fixture_checkpoint(&checkpoint, terminal_transport).is_err());

    let terminal_prepared =
        prepare_effectless_dispatch(&set.terminal_reflection_envelope).expect("terminal prepared");
    let terminal_dispatched =
        record_effectless_fixture_dispatch(&terminal_prepared).expect("terminal dispatched");
    let terminal_received = record_effectless_fixture_response(
        &terminal_dispatched,
        &terminal_transport.sanitized_response,
    )
    .expect("terminal received");
    let terminal_checkpoint =
        compile_dispatch_lifecycle_checkpoint(&terminal_received).expect("terminal checkpoint");
    assert!(
        resume_iteration_fixture_checkpoint(&terminal_checkpoint, canonical_transport).is_err()
    );
    resume_terminal_fixture_checkpoint(&terminal_checkpoint, terminal_transport)
        .expect("terminal resume");
}
