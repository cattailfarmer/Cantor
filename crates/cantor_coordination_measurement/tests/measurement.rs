use std::{fs, path::PathBuf};

use cantor_coordination_measurement::{
    CoordinationTransportMeasurement, QUOTA_SCHEDULES, generate_measurement,
    pretty_measurement_bytes, validate_measurement,
};

fn artifact_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../experiments/coordination_transport_measurement/artifacts/coordination_transport_measurement_v1.json")
}

#[test]
fn generation_is_byte_deterministic_and_self_validating() {
    let first = generate_measurement().expect("first report");
    let second = generate_measurement().expect("second report");
    assert_eq!(first, second);
    assert_eq!(
        pretty_measurement_bytes(&first).expect("first bytes"),
        pretty_measurement_bytes(&second).expect("second bytes")
    );
    validate_measurement(&first).expect("report validates");
}

#[test]
fn all_schedules_reach_one_exact_terminal_outcome_with_valid_accounts() {
    let report = generate_measurement().expect("measurement report");
    assert_eq!(
        report
            .schedules
            .iter()
            .map(|schedule| schedule.maximum_steps)
            .collect::<Vec<_>>(),
        QUOTA_SCHEDULES
    );
    let digest = report.schedules[0].terminal_outcome_digest.clone();
    let bytes = report.schedules[0].terminal_outcome_bytes;
    for schedule in &report.schedules {
        assert_eq!(schedule.steps_advanced, report.expected_terminal_steps);
        assert_eq!(schedule.terminal_outcome_digest, digest);
        assert_eq!(schedule.terminal_outcome_bytes, bytes);
        assert!(schedule.request_bytes > schedule.repeated_context_bytes);
        assert!(schedule.structured_bytes > schedule.request_bytes);
        assert!(schedule.context_request_share_basis_points < 10_000);
        assert!(schedule.context_total_share_basis_points < 10_000);
    }
}

#[test]
fn corruption_and_scope_escalation_fail_validation() {
    let report = generate_measurement().expect("measurement report");
    let mut corrupt = report.clone();
    corrupt.schedules[0].request_bytes += 1;
    assert!(validate_measurement(&corrupt).is_err());

    let mut escalated = report;
    escalated.decision = "implement_registry".to_owned();
    assert!(validate_measurement(&escalated).is_err());
}

#[test]
fn checked_artifact_equals_fresh_generation_byte_for_byte() {
    let tracked = fs::read(artifact_path()).expect("tracked measurement artifact");
    let parsed: CoordinationTransportMeasurement =
        serde_json::from_slice(&tracked).expect("typed tracked report");
    validate_measurement(&parsed).expect("tracked report validates");
    let fresh = generate_measurement().expect("fresh measurement");
    assert_eq!(
        tracked,
        pretty_measurement_bytes(&fresh).expect("fresh bytes")
    );
}
