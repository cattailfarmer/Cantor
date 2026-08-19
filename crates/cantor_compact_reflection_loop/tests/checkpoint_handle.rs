use std::process::Command;

use cantor_compact_reflection_loop::{
    DispatchCheckpointHandle, DispatchCheckpointHandleMeasurement,
    compile_dispatch_checkpoint_handle, generate_dispatch_checkpoint_handle_measurement,
    generate_scripted_dispatch_resume_corpus, pretty_dispatch_checkpoint_handle_measurement_bytes,
    validate_dispatch_checkpoint_handle, validate_dispatch_checkpoint_handle_against,
    validate_dispatch_checkpoint_handle_measurement,
};
use serde_json::Value;

#[test]
fn checkpoint_handles_are_smaller_and_exactly_bound() {
    let measurement = generate_dispatch_checkpoint_handle_measurement().expect("measurement");
    validate_dispatch_checkpoint_handle_measurement(&measurement).expect("valid measurement");
    assert_eq!(measurement.case_count, 12);
    assert_eq!(measurement.cases.len(), 12);
    assert!(measurement.all_handles_smaller);
    assert!(measurement.total_full_checkpoint_bytes > measurement.total_handle_bytes);
    assert!(measurement.total_full_minus_handle_bytes > 0);
    assert!(measurement.handle_to_checkpoint_basis_points < 10_000);
    assert!(measurement.minimum_handle_bytes > 0);
    assert!(measurement.maximum_handle_bytes >= measurement.minimum_handle_bytes);
    assert_eq!(measurement.total_full_checkpoint_bytes, 70_830);
    assert_eq!(measurement.total_handle_bytes, 11_963);
    assert_eq!(measurement.total_full_minus_handle_bytes, 58_867);
    assert_eq!(measurement.minimum_handle_bytes, 947);
    assert_eq!(measurement.maximum_handle_bytes, 1_050);
    assert_eq!(measurement.handle_to_checkpoint_basis_points, 1_688);

    let corpus = generate_scripted_dispatch_resume_corpus().expect("corpus");
    for (measured, source) in measurement.cases.iter().zip(&corpus.cases) {
        validate_dispatch_checkpoint_handle(&measured.handle).expect("local handle");
        validate_dispatch_checkpoint_handle_against(
            &measured.handle,
            &source.checkpoint,
            source.transport_position,
            source.terminal_reflection,
        )
        .expect("exact checkpoint binding");
        assert!(measured.full_checkpoint_bytes > measured.handle_bytes);
        assert_eq!(
            measured.full_minus_handle_bytes,
            i64::try_from(measured.full_checkpoint_bytes).expect("full bytes")
                - i64::try_from(measured.handle_bytes).expect("handle bytes")
        );
    }
}

#[test]
fn checked_in_measurement_artifact_regenerates_byte_identically() {
    let measurement = generate_dispatch_checkpoint_handle_measurement().expect("measurement");
    let regenerated =
        pretty_dispatch_checkpoint_handle_measurement_bytes(&measurement).expect("pretty");
    let checked_in = include_bytes!(
        "../../../experiments/iterative_attention_procedure_loop_p1/artifacts/dispatch_checkpoint_handle_measurement_v1.json"
    );
    assert_eq!(checked_in.as_slice(), regenerated);
}

#[test]
fn measurement_and_cli_output_are_deterministic_strict_and_normalized() {
    let first = generate_dispatch_checkpoint_handle_measurement().expect("first");
    let second = generate_dispatch_checkpoint_handle_measurement().expect("second");
    assert_eq!(first, second);
    let expected = pretty_dispatch_checkpoint_handle_measurement_bytes(&first).expect("pretty");
    assert_eq!(expected.last(), Some(&b'\n'));
    let decoded: DispatchCheckpointHandleMeasurement =
        serde_json::from_slice(&expected).expect("strict JSON");
    assert_eq!(decoded, first);

    let output = Command::new(env!("CARGO_BIN_EXE_cantor-compact-reflection-loop"))
        .arg("measure-dispatch-checkpoint-handles")
        .output()
        .expect("measurement CLI");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, expected);

    let mut unknown = serde_json::to_value(&first).expect("value");
    unknown["tokens_saved"] = Value::Number(0.into());
    assert!(serde_json::from_value::<DispatchCheckpointHandleMeasurement>(unknown).is_err());

    let mut unknown_handle = serde_json::to_value(&first.cases[0].handle).expect("handle value");
    unknown_handle["checkpoint"] = Value::Null;
    assert!(serde_json::from_value::<DispatchCheckpointHandle>(unknown_handle).is_err());
}

#[test]
fn handle_and_measurement_mutations_fail_closed() {
    let measurement = generate_dispatch_checkpoint_handle_measurement().expect("measurement");
    let handle = &measurement.cases[0].handle;

    let mut phase = handle.clone();
    phase.checkpoint_phase = cantor_compact_reflection_loop::EffectlessDispatchPhase::Admitted;
    assert!(validate_dispatch_checkpoint_handle(&phase).is_err());

    let mut operation = handle.clone();
    operation.next_operation =
        cantor_compact_reflection_loop::DispatchCheckpointNextOperation::Complete;
    assert!(validate_dispatch_checkpoint_handle(&operation).is_err());

    let mut digest = handle.clone();
    digest.checkpoint_digest.value.push('0');
    assert!(validate_dispatch_checkpoint_handle(&digest).is_err());

    let mut algorithm = handle.clone();
    algorithm.envelope_digest.algorithm = "crc32".to_owned();
    assert!(validate_dispatch_checkpoint_handle(&algorithm).is_err());

    let mut custody = handle.clone();
    custody.exact_checkpoint_under_host_custody = false;
    assert!(validate_dispatch_checkpoint_handle(&custody).is_err());

    let mut embedded = handle.clone();
    embedded.serialized_checkpoint_embedded = true;
    assert!(validate_dispatch_checkpoint_handle(&embedded).is_err());

    let mut claim = handle.clone();
    claim.persistence_claimed = true;
    assert!(validate_dispatch_checkpoint_handle(&claim).is_err());

    let corpus = generate_scripted_dispatch_resume_corpus().expect("corpus");
    let source = &corpus.cases[0];
    let coherent_wrong_position =
        compile_dispatch_checkpoint_handle(&source.checkpoint, 99, false).expect("coherent handle");
    validate_dispatch_checkpoint_handle(&coherent_wrong_position).expect("locally valid");
    assert!(
        validate_dispatch_checkpoint_handle_against(
            &coherent_wrong_position,
            &source.checkpoint,
            source.transport_position,
            source.terminal_reflection
        )
        .is_err()
    );

    let mut total = measurement.clone();
    total.total_handle_bytes += 1;
    assert!(validate_dispatch_checkpoint_handle_measurement(&total).is_err());

    let mut bytes = measurement.clone();
    bytes.cases[0].handle_bytes += 1;
    assert!(validate_dispatch_checkpoint_handle_measurement(&bytes).is_err());

    let mut source_digest = measurement.clone();
    source_digest.source_resume_corpus_digest.value.push('0');
    assert!(validate_dispatch_checkpoint_handle_measurement(&source_digest).is_err());

    let mut semantic = measurement;
    semantic.semantic_equivalence_claimed = true;
    assert!(validate_dispatch_checkpoint_handle_measurement(&semantic).is_err());
}
