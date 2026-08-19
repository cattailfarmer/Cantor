use cantor_compact_reflection_loop::{
    DeterministicDriveMeasurement, generate_fixture_deterministic_drive_measurement,
    pretty_deterministic_drive_measurement_bytes, validate_deterministic_drive_measurement,
};

const ARTIFACT: &[u8] = include_bytes!(
    "../../../experiments/iterative_attention_procedure_loop_p1/artifacts/deterministic_drive_measurement_v1.json"
);

#[test]
fn deterministic_drive_measurement_is_reproducible() {
    let expected: DeterministicDriveMeasurement =
        serde_json::from_slice(ARTIFACT).expect("artifact JSON");
    validate_deterministic_drive_measurement(&expected).expect("valid artifact");
    let generated = generate_fixture_deterministic_drive_measurement().expect("measurement");
    assert_eq!(generated, expected);
    assert_eq!(
        pretty_deterministic_drive_measurement_bytes(&generated).expect("pretty measurement"),
        ARTIFACT
    );
    assert_eq!(generated.ready_projection_count, 1);
    assert_eq!(generated.advance_count, 2);
    assert!(generated.terminal_observation_bytes > generated.terminal_projection_bytes * 80);
    assert!(generated.successor_registry_bytes > generated.model_facing_projection_bytes * 40);
    assert!(generated.model_facing_share_of_result_basis_points < 100);
}
