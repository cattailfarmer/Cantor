use std::process::Command;

use cantor_compact_reflection_loop::{
    CustodyQuerySurfaceMeasurement, generate_custody_query_surface_measurement,
    pretty_custody_query_surface_measurement_bytes, validate_custody_query_surface_measurement,
};

const ARTIFACT: &[u8] = include_bytes!(
    "../../../experiments/iterative_attention_procedure_loop_p1/artifacts/custody_query_surface_measurement_v1.json"
);

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cantor-compact-reflection-loop")
}

fn change_first_hex(value: &mut String) {
    let replacement = if value.starts_with('0') { "1" } else { "0" };
    value.replace_range(0..1, replacement);
}

#[test]
fn all_twelve_inspection_surfaces_are_smaller_and_arithmetic_closes() {
    let measurement = generate_custody_query_surface_measurement().expect("measurement");
    assert_eq!(measurement.case_count, 12);
    assert_eq!(measurement.cases.len(), 12);
    assert!(measurement.all_inspect_responses_smaller);
    assert!(measurement.total_inspect_response_bytes < measurement.total_resolve_response_bytes);
    assert_eq!(
        measurement.total_resolve_minus_inspect_response_bytes,
        measurement.total_resolve_response_bytes as i64
            - measurement.total_inspect_response_bytes as i64
    );
    assert!(
        measurement
            .cases
            .iter()
            .all(|case| case.inspect_response_bytes < case.resolve_response_bytes)
    );
}

#[test]
fn normalized_round_trip_and_mutations_fail_closed() {
    let measurement = generate_custody_query_surface_measurement().expect("measurement");
    let bytes = pretty_custody_query_surface_measurement_bytes(&measurement).expect("bytes");
    let decoded: CustodyQuerySurfaceMeasurement =
        serde_json::from_slice(&bytes).expect("strict JSON");
    assert_eq!(decoded, measurement);

    let mut wrong_total = measurement.clone();
    wrong_total.total_inspect_response_bytes += 1;
    assert!(validate_custody_query_surface_measurement(&wrong_total).is_err());
    let mut wrong_digest = measurement.clone();
    change_first_hex(&mut wrong_digest.source_cases_digest.value);
    assert!(validate_custody_query_surface_measurement(&wrong_digest).is_err());
    let mut wrong_claim = measurement.clone();
    wrong_claim.token_measurement_claimed = true;
    assert!(validate_custody_query_surface_measurement(&wrong_claim).is_err());
    let mut reordered = measurement;
    reordered.cases.swap(0, 1);
    assert!(validate_custody_query_surface_measurement(&reordered).is_err());
}

#[test]
fn cli_stdout_is_typed_deterministic_and_rejects_extra_arguments() {
    let output = Command::new(binary())
        .arg("measure-checkpoint-custody-query-surface")
        .output()
        .expect("run");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let measurement: CustodyQuerySurfaceMeasurement =
        serde_json::from_slice(&output.stdout).expect("typed measurement");
    validate_custody_query_surface_measurement(&measurement).expect("valid measurement");
    assert_eq!(
        output.stdout,
        pretty_custody_query_surface_measurement_bytes(&measurement).expect("pretty")
    );
    assert_eq!(output.stdout, ARTIFACT);

    let extra = Command::new(binary())
        .args(["measure-checkpoint-custody-query-surface", "unexpected"])
        .output()
        .expect("run invalid");
    assert_eq!(extra.status.code(), Some(2));
}
