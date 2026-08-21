use cantor_lifecycle_tool_loop::verify_provider_independent_probe;
use serde_json::Value;
use std::{fs, process::Command};

const EVIDENCE: &[u8] = include_bytes!(
    "../../../experiments/llama_tool_reflection/artifacts/lifecycle_tool_loop/provider_independent_bridge_probe.json"
);

#[test]
fn committed_provider_independent_evidence_recomputes() {
    let verified = verify_provider_independent_probe(EVIDENCE).expect("evidence must verify");

    assert_eq!(verified.status, "passed");
    assert_eq!(verified.source_bytes, EVIDENCE.len());
    assert_eq!(verified.verified_trial_count, 8);
    assert_eq!(verified.first_call_trial_count, 4);
    assert_eq!(verified.steady_state_trial_count, 4);
    assert_eq!(
        verified.comparison.stateless_transport_argument_bytes,
        124_144
    );
    assert_eq!(verified.comparison.custody_transport_argument_bytes, 1_200);
    assert_eq!(verified.comparison.transport_bytes_saved, 122_944);
    assert_eq!(
        verified
            .comparison
            .custody_to_stateless_argument_basis_points,
        96
    );
}

#[test]
fn tampered_summary_is_refused() {
    let mut evidence = value();
    evidence["comparison"]["transport_bytes_saved"] = Value::from(1);

    assert_fault(evidence, "comparison");
}

#[test]
fn duplicate_trial_coordinate_is_refused() {
    let mut evidence = value();
    let mut duplicate = evidence["trials"][0].clone();
    duplicate["sequence"] = Value::from(1);
    evidence["trials"][1] = duplicate;

    assert_fault(evidence, "trial_coordinate");
}

#[test]
fn tampered_raw_argument_byte_account_is_refused() {
    let mut evidence = value();
    evidence["trials"][0]["observation"]["argument_bytes"] = Value::from(1);

    assert_fault(evidence, "trial_argument_bytes");
}

#[test]
fn tampered_restart_evidence_is_refused() {
    let mut evidence = value();
    evidence["restart_trial"]["response"]["registry"]["root_digest"]["value"] = Value::from("00");

    assert_fault(evidence, "restart_registry_root_digest");
}

#[test]
fn false_exact_response_claim_is_refused() {
    let mut evidence = value();
    evidence["trials"][0]["observation"]["exact_direct_response"] = Value::Bool(false);

    assert_fault(evidence, "trial_exact_direct_response");
}

#[test]
fn provider_contact_is_refused() {
    let mut evidence = value();
    evidence["provider_contacted"] = Value::Bool(true);

    assert_fault(evidence, "provider_contacted");
}

#[test]
fn unknown_report_field_is_refused() {
    let mut evidence = value();
    evidence["unrecognized_claim"] = Value::Bool(true);

    assert_fault(evidence, "source_json");
}

#[test]
fn verifier_cli_accepts_a_bare_output_filename() {
    let scratch = std::env::temp_dir().join(format!(
        "cantor-lifecycle-evidence-cli-{}",
        std::process::id()
    ));
    if scratch.exists() {
        fs::remove_dir_all(&scratch).expect("stale scratch directory must be removable");
    }
    fs::create_dir(&scratch).expect("scratch directory must be creatable");
    let input = scratch.join("probe.json");
    fs::write(&input, EVIDENCE).expect("probe fixture must be writable");

    let output = Command::new(env!("CARGO_BIN_EXE_cantor-lifecycle-evidence-verify"))
        .current_dir(&scratch)
        .args(["--input", "probe.json", "--output", "verification.json"])
        .output()
        .expect("verifier CLI must start");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(scratch.join("verification.json").is_file());
    fs::remove_dir_all(&scratch).expect("scratch directory must be removable");
}

fn value() -> Value {
    serde_json::from_slice(EVIDENCE).expect("committed evidence must decode")
}

fn assert_fault(evidence: Value, expected_field: &str) {
    let encoded = serde_json::to_vec(&evidence).expect("tampered evidence must encode");
    let fault = verify_provider_independent_probe(&encoded).expect_err("tampering must be refused");

    assert_eq!(fault.field, expected_field);
}
