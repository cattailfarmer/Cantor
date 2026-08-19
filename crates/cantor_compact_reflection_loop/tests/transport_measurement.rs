use cantor_compact_reflection_loop::{
    TransportMeasurement, generate_fixture_transport_measurement,
    pretty_transport_measurement_bytes, validate_transport_measurement,
};

const ARTIFACT: &[u8] = include_bytes!(
    "../../../experiments/compact_reflection_transport_measurement/artifacts/compact_reflection_transport_measurement_v1.json"
);

#[test]
fn transport_measurement_is_valid_and_regenerates_exactly() {
    let expected: TransportMeasurement = serde_json::from_slice(ARTIFACT).expect("artifact JSON");
    validate_transport_measurement(&expected).expect("valid artifact");
    let generated = generate_fixture_transport_measurement().expect("generated measurement");
    assert_eq!(generated, expected);
    assert_eq!(
        pretty_transport_measurement_bytes(&generated).unwrap(),
        ARTIFACT
    );
    assert_eq!(generated.tool_arguments_bytes, 20);
    assert!(generated.terminal_handle_bytes * 90 < generated.terminal_record_bytes);
    assert!(generated.terminal_record_share_of_reflection_basis_points > 7_500);
    assert!(generated.terminal_record_share_of_report_basis_points > 4_000);
}
