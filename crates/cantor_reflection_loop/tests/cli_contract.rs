use std::{fs, path::PathBuf, process::Command};

use serde_json::{Value, json};

const ACCEPTED_REPORT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../experiments/cantor_reflection_loop_p0/script_acceptance_verified_v15.json"
);

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cantor-reflection-loop")
}

#[test]
fn verify_and_inspect_are_machine_clean() {
    let verified = Command::new(binary())
        .args(["verify", "--report", ACCEPTED_REPORT])
        .output()
        .expect("verification process");
    assert!(verified.status.success());
    assert!(verified.stderr.is_empty());
    let verification: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(verification["status"], "verified");

    let inspected = Command::new(binary())
        .args(["inspect", "--report", ACCEPTED_REPORT])
        .output()
        .expect("inspection process");
    assert!(inspected.status.success());
    assert!(inspected.stderr.is_empty());
    let inspection: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(inspection["status"], "verified_trace_projection");
    assert_eq!(inspection["cases"].as_array().unwrap().len(), 3);
}

#[test]
fn verify_rejects_a_tampered_report_with_semantic_exit_one() {
    let mut report: Value = serde_json::from_slice(&fs::read(ACCEPTED_REPORT).unwrap()).unwrap();
    report["cases"][0]["final_output"]["evidence_reference"] = json!("tampered");
    let path = temporary_path("tampered");
    fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
    let output = Command::new(binary())
        .args(["verify", "--report", path.to_str().unwrap()])
        .output()
        .expect("verification process");
    let _ = fs::remove_file(path);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("verification_fault"));
}

#[test]
fn malformed_cli_is_configuration_exit_two() {
    let output = Command::new(binary())
        .args(["inspect", "--wrong", ACCEPTED_REPORT])
        .output()
        .expect("inspection process");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("configuration_fault"));
}

#[test]
fn contract_is_machine_clean_and_effect_free() {
    let output = Command::new(binary())
        .arg("contract")
        .output()
        .expect("contract process");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let contract: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(contract["profile"], "cantor-reflection-loop-contract/0.1");
    assert_eq!(
        contract["report_profile"],
        "cantor-reflection-loop-report/0.2"
    );
    assert_eq!(contract["tool_name"], "route_attention");
    assert_eq!(contract["model_selection"], "sole_advertised_model");
    assert_eq!(contract["campaign"], "mandatory_positive_refusal_control");
    assert_eq!(contract["cases"].as_array().unwrap().len(), 3);
    assert_eq!(contract["max_tool_calls_per_routed_case"], 1);
}

fn temporary_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "cantor-reflection-loop-{label}-{}.json",
        std::process::id()
    ))
}
