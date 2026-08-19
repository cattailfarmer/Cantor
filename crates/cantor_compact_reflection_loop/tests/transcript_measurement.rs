use cantor_compact_reflection_loop::{
    IterativeProviderPhase, IterativeTranscriptMeasurement,
    generate_iterative_transcript_measurement, pretty_iterative_transcript_measurement_bytes,
    validate_iterative_transcript_measurement,
};

const ARTIFACT: &[u8] = include_bytes!(
    "../../../experiments/iterative_attention_procedure_loop_p1/artifacts/iterative_transcript_measurement_v1.json"
);

#[test]
fn transcript_measurement_is_deterministic_and_strict() {
    let first = generate_iterative_transcript_measurement().expect("first measurement");
    let second = generate_iterative_transcript_measurement().expect("second measurement");
    assert_eq!(first, second);
    validate_iterative_transcript_measurement(&first).expect("valid measurement");
    assert_eq!(first.passes.len(), 3);
    assert_eq!(first.passes[0].phase, IterativeProviderPhase::Advance);
    assert_eq!(first.passes[1].phase, IterativeProviderPhase::Advance);
    assert_eq!(
        first.passes[2].phase,
        IterativeProviderPhase::ReflectTerminal
    );
    assert!(first.passes[2].request_bytes > first.passes[0].request_bytes);
    assert!(first.exact_terminal_custody_bytes > first.unique_projection_bytes);
    assert!(first.complete_run_bytes > first.total_model_facing_exchange_bytes);

    let encoded = serde_json::to_value(&first).expect("measurement JSON");
    let decoded: IterativeTranscriptMeasurement =
        serde_json::from_value(encoded.clone()).expect("closed round trip");
    assert_eq!(decoded, first);
    let mut unknown = encoded;
    unknown["token_count"] = serde_json::json!(0);
    assert!(serde_json::from_value::<IterativeTranscriptMeasurement>(unknown).is_err());

    let mut phase = first.clone();
    phase.passes[1].phase = IterativeProviderPhase::ReflectTerminal;
    assert!(validate_iterative_transcript_measurement(&phase).is_err());

    let mut cumulative = first.clone();
    cumulative.passes[1].cumulative_request_bytes += 1;
    assert!(validate_iterative_transcript_measurement(&cumulative).is_err());

    let mut total = first.clone();
    total.total_response_bytes += 1;
    assert!(validate_iterative_transcript_measurement(&total).is_err());

    let mut ratio = first;
    ratio.unique_projection_share_of_exact_custody_basis_points += 1;
    assert!(validate_iterative_transcript_measurement(&ratio).is_err());
}

#[test]
fn transcript_measurement_pretty_bytes_are_stable() {
    let measurement = generate_iterative_transcript_measurement().expect("measurement");
    let bytes = pretty_iterative_transcript_measurement_bytes(&measurement).expect("pretty JSON");
    let artifact: IterativeTranscriptMeasurement =
        serde_json::from_slice(ARTIFACT).expect("artifact JSON");
    validate_iterative_transcript_measurement(&artifact).expect("valid artifact");
    assert_eq!(artifact, measurement);
    assert_eq!(bytes, ARTIFACT);
    assert_eq!(bytes.last(), Some(&b'\n'));
    let decoded: IterativeTranscriptMeasurement =
        serde_json::from_slice(&bytes).expect("pretty measurement JSON");
    assert_eq!(decoded, measurement);
}
