use cantor_reflection_loop::{inspect_report, verify_report};
use serde_json::{Value, json};

fn accepted_report() -> Value {
    serde_json::from_str(include_str!(
        "../../../experiments/cantor_reflection_loop_p0/script_acceptance_verified_v10.json"
    ))
    .expect("preserved live report must be JSON")
}

#[test]
fn live_acceptance_report_is_independently_verifiable() {
    let verification = verify_report(&accepted_report()).expect("live report should verify");
    assert_eq!(verification.case_count, 3);
    assert_eq!(verification.evidence_links_verified, 2);
    assert!(verification.private_reasoning_absent);
}

#[test]
fn changed_positive_evidence_link_is_rejected() {
    let mut report = accepted_report();
    report["cases"][0]["final_output"]["evidence_reference"] = json!("invented");
    assert!(verify_report(&report).is_err());
}

#[test]
fn changed_tool_arguments_are_rejected_even_when_headline_fields_match() {
    let mut report = accepted_report();
    report["cases"][0]["first_response"]["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] =
        json!(r#"{"stimulus":"changed","response_mode":"frame"}"#);
    assert!(verify_report(&report).is_err());
}

#[test]
fn changed_reflection_import_is_rejected() {
    let mut report = accepted_report();
    report["cases"][0]["reflection_request"]["messages"][3]["content"] =
        json!("{\"status\":\"invented\"}");
    assert!(verify_report(&report).is_err());
}

#[test]
fn changed_intermediate_state_is_rejected() {
    let mut report = accepted_report();
    report["cases"][0]["events"][3]["state"] = json!("final_received");
    assert!(verify_report(&report).is_err());
}

#[test]
fn changed_model_content_is_rejected_even_if_recorded_output_is_unchanged() {
    let mut report = accepted_report();
    report["cases"][2]["first_response"]["choices"][0]["message"]["content"] = json!(
        r#"{"case_id":"control_without_cantor","observed_tool_status":"no_tool_control","applied_attention":false,"summary":"mutated","evidence_reference":"invented","procedure_id":null}"#
    );
    assert!(verify_report(&report).is_err());
}

#[test]
fn private_reasoning_key_is_rejected_at_any_depth() {
    let mut report = accepted_report();
    report["cases"][2]["first_response"]["choices"][0]["message"]["reasoning_content"] =
        json!("must not persist");
    assert!(verify_report(&report).is_err());
}

#[test]
fn refusal_with_attention_frame_is_rejected() {
    let mut report = accepted_report();
    report["cases"][1]["tool_result"]["attention_frame"] = json!({});
    assert!(verify_report(&report).is_err());
}

#[test]
fn hardened_dependency_drift_is_rejected() {
    let mut report = accepted_report();
    report["dependency_identity_stable"] = json!(false);
    report["mcp_program_sha256_after"] = report["mcp_program_sha256"].clone();
    report["mcp_config_sha256_after"] = report["mcp_config_sha256"].clone();
    report["runner"] = json!("C:\\fixture\\cantor-reflection-loop.exe");
    report["runner_sha256"] = json!("0".repeat(64));
    assert!(verify_report(&report).is_err());
}

#[test]
fn verified_report_projects_a_compact_walk() {
    let inspection = inspect_report(&accepted_report()).expect("live report should inspect");
    assert_eq!(inspection.cases.len(), 3);
    assert_eq!(inspection.cases[0].observed_tool_status, "route_selected");
    assert!(inspection.cases[0].applied_attention);
    assert_eq!(inspection.cases[1].observed_tool_status, "runtime_refused");
    assert!(!inspection.cases[1].applied_attention);
    assert_eq!(inspection.cases[2].observed_tool_status, "no_tool_control");
    assert_eq!(
        inspection.cases[0].states,
        [
            "created",
            "first_inference_requested",
            "tool_call_received",
            "tool_call_validated",
            "tool_result_received",
            "reflection_requested",
            "final_received",
            "completed"
        ]
    );
}
