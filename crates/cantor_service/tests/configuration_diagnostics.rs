mod common;

use std::{fs, path::Path, process::Command};

use cantor_service::{
    ConfigurationDiagnosticCheckStatus, ConfigurationDiagnosticStatus,
    ConfigurationDiagnosticSubject, ServiceConfigurationDiagnostic, diagnose_service_configuration,
};
use common::{TOKEN, TestWorkspace, write_json};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cantord"))
}

fn assert_privacy(diagnostic: &ServiceConfigurationDiagnostic) {
    let privacy = &diagnostic.privacy;
    assert!(!privacy.authority_paths_recorded);
    assert!(!privacy.token_content_recorded);
    assert!(!privacy.token_hash_recorded);
    assert!(!privacy.config_content_recorded);
    assert!(!privacy.activation_content_recorded);
    assert!(!privacy.environment_content_recorded);
    assert!(!privacy.raw_fault_message_recorded);
    assert!(!privacy.listener_bound);
    assert!(!privacy.service_started);
    assert!(!privacy.provider_contacted);
    assert!(!privacy.remote_accessed);
}

fn assert_redacted(bytes: &[u8], workspace: &TestWorkspace, extra: &[&str]) {
    let text = String::from_utf8(bytes.to_vec()).expect("diagnostic JSON must be UTF-8");
    assert!(!text.contains(workspace.root.to_string_lossy().as_ref()));
    assert!(!text.contains(TOKEN));
    for forbidden in [
        "service.json",
        "activation.json",
        "token.txt",
        "environment.json",
        "a resident semantic coprocessor",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    {
        assert!(
            !text.contains(forbidden),
            "diagnostic disclosed {forbidden:?}"
        );
    }
}

#[test]
fn ready_diagnostic_is_deterministic_and_redacted() {
    let (workspace, _) = TestWorkspace::new(400, 7);
    let _ = workspace.publish(400, 7);
    assert!(workspace.environment_path.is_file());
    let first = diagnose_service_configuration(&workspace.config_path);
    let second = diagnose_service_configuration(&workspace.config_path);
    assert_eq!(first, second);
    assert_eq!(first.status, ConfigurationDiagnosticStatus::Ready);
    assert!(first.config_file_sha256.is_some());
    assert!(first.fault.is_none());
    assert_eq!(first.checks.len(), 3);
    assert_eq!(first.checks[0].ordinal, 0);
    assert_eq!(
        first.checks[0].subject,
        ConfigurationDiagnosticSubject::ServiceConfig
    );
    assert_eq!(
        first.checks[1].subject,
        ConfigurationDiagnosticSubject::AuthenticationToken
    );
    assert_eq!(
        first.checks[2].subject,
        ConfigurationDiagnosticSubject::ActivationEnvironment
    );
    assert!(
        first
            .checks
            .iter()
            .all(|check| check.status == ConfigurationDiagnosticCheckStatus::Passed)
    );
    let summary = first.ready_summary.as_ref().expect("ready summary");
    assert_eq!(summary.service_config_schema, "cantor-service-config/0.1");
    assert_eq!(summary.listen_family, "ipv4_loopback");
    assert_eq!(summary.listen_port, 0);
    assert_eq!(summary.max_frame_bytes, 1_048_576);
    assert_eq!(summary.max_connections, 32);
    assert_eq!(summary.read_timeout_milliseconds, 2_000);
    assert_eq!(summary.write_timeout_milliseconds, 2_000);
    assert_eq!(summary.active_binding.activation_sequence, 7);
    assert_eq!(summary.ordered_package_count, 1);
    assert_eq!(summary.runtime_metrics, Default::default());
    assert_privacy(&first);
    let first_bytes = serde_json::to_vec(&first).expect("first diagnostic JSON");
    let second_bytes = serde_json::to_vec(&second).expect("second diagnostic JSON");
    assert_eq!(first_bytes, second_bytes);
    assert_redacted(&first_bytes, &workspace, &[]);
}

#[test]
fn invalid_json_refuses_at_service_config_without_raw_message() {
    let (workspace, _) = TestWorkspace::new(401, 1);
    fs::write(&workspace.config_path, b"{\"schema\":").expect("invalid config fixture");
    let diagnostic = diagnose_service_configuration(&workspace.config_path);
    assert_eq!(diagnostic.status, ConfigurationDiagnosticStatus::Refused);
    assert!(diagnostic.config_file_sha256.is_some());
    assert!(diagnostic.ready_summary.is_none());
    assert_eq!(diagnostic.checks.len(), 1);
    assert_eq!(
        diagnostic.checks[0].subject,
        ConfigurationDiagnosticSubject::ServiceConfig
    );
    assert_eq!(
        diagnostic.checks[0].status,
        ConfigurationDiagnosticCheckStatus::Refused
    );
    let fault = diagnostic.fault.as_ref().expect("public refusal");
    assert_eq!(fault.code, "invalid_service_config");
    assert_eq!(fault.subject, ConfigurationDiagnosticSubject::ServiceConfig);
    assert_privacy(&diagnostic);
    let bytes = serde_json::to_vec(&diagnostic).expect("refusal JSON");
    assert_redacted(&bytes, &workspace, &["EOF while parsing"]);
}

#[test]
fn nonloopback_configuration_refuses_before_token_validation() {
    let (workspace, _) = TestWorkspace::new(402, 1);
    let mut config: serde_json::Value =
        serde_json::from_slice(&fs::read(&workspace.config_path).expect("config bytes"))
            .expect("config JSON");
    config["listen_address"] = serde_json::json!("0.0.0.0:39841");
    write_json(&workspace.config_path, &config);
    let diagnostic = diagnose_service_configuration(&workspace.config_path);
    assert_eq!(diagnostic.status, ConfigurationDiagnosticStatus::Refused);
    assert_eq!(diagnostic.checks.len(), 1);
    assert_eq!(
        diagnostic.fault.as_ref().expect("fault").code,
        "non_loopback_address"
    );
    assert_privacy(&diagnostic);
}

#[test]
fn invalid_token_refuses_without_serializing_token_or_path() {
    let (workspace, _) = TestWorkspace::new(403, 1);
    let forbidden_token = "not-a-real-secret-but-must-stay-private";
    fs::write(&workspace.token_path, forbidden_token).expect("invalid token fixture");
    let diagnostic = diagnose_service_configuration(&workspace.config_path);
    assert_eq!(diagnostic.status, ConfigurationDiagnosticStatus::Refused);
    assert_eq!(diagnostic.checks.len(), 2);
    assert_eq!(
        diagnostic.checks[1].subject,
        ConfigurationDiagnosticSubject::AuthenticationToken
    );
    assert_eq!(
        diagnostic.fault.as_ref().expect("fault").code,
        "invalid_auth_token"
    );
    assert_privacy(&diagnostic);
    let bytes = serde_json::to_vec(&diagnostic).expect("refusal JSON");
    assert_redacted(&bytes, &workspace, &[forbidden_token]);
}

#[test]
fn activation_digest_and_environment_containment_refuse_at_final_stage() {
    let (workspace, _) = TestWorkspace::new(404, 1);
    let original_activation = fs::read(&workspace.activation_path).expect("activation bytes");
    let mut activation: serde_json::Value =
        serde_json::from_slice(&original_activation).expect("activation JSON");
    activation["environment_file_sha256"] = serde_json::json!("0".repeat(64));
    write_json(&workspace.activation_path, &activation);
    let digest_refusal = diagnose_service_configuration(&workspace.config_path);
    assert_eq!(digest_refusal.checks.len(), 3);
    assert_eq!(
        digest_refusal.checks[2].subject,
        ConfigurationDiagnosticSubject::ActivationEnvironment
    );
    assert_eq!(
        digest_refusal.fault.as_ref().expect("digest fault").code,
        "environment_file_digest_mismatch"
    );

    fs::write(&workspace.activation_path, original_activation).expect("restore activation");
    let allowed = workspace.root.join("allowed-only");
    fs::create_dir(&allowed).expect("allowed subdirectory");
    let mut config: serde_json::Value =
        serde_json::from_slice(&fs::read(&workspace.config_path).expect("config bytes"))
            .expect("config JSON");
    config["allowed_environment_root"] = serde_json::json!(allowed);
    write_json(&workspace.config_path, &config);
    let containment_refusal = diagnose_service_configuration(&workspace.config_path);
    assert_eq!(containment_refusal.checks.len(), 3);
    assert_eq!(
        containment_refusal
            .fault
            .as_ref()
            .expect("containment fault")
            .code,
        "environment_path_escape"
    );
    assert_privacy(&containment_refusal);
}

#[test]
fn missing_config_refuses_without_path_or_raw_os_error() {
    let (workspace, _) = TestWorkspace::new(405, 1);
    let missing = workspace.root.join("operator-private-config-name.json");
    let diagnostic = diagnose_service_configuration(&missing);
    assert_eq!(diagnostic.status, ConfigurationDiagnosticStatus::Refused);
    assert!(diagnostic.config_file_sha256.is_none());
    assert_privacy(&diagnostic);
    let bytes = serde_json::to_vec(&diagnostic).expect("missing-config JSON");
    assert_redacted(&bytes, &workspace, &["operator-private-config-name.json"]);
}

#[test]
fn check_config_cli_has_exact_ready_refused_and_invocation_contract() {
    let (workspace, _) = TestWorkspace::new(406, 9);
    let ready = binary()
        .arg("--check-config")
        .arg(&workspace.config_path)
        .output()
        .expect("ready diagnostic process");
    assert_eq!(ready.status.code(), Some(0));
    assert!(ready.stderr.is_empty());
    assert_eq!(ready.stdout.last(), Some(&b'\n'));
    let ready_report: ServiceConfigurationDiagnostic =
        serde_json::from_slice(&ready.stdout).expect("ready diagnostic JSON");
    assert_eq!(ready_report.status, ConfigurationDiagnosticStatus::Ready);
    assert_redacted(&ready.stdout, &workspace, &[]);

    let forbidden_token = "cli-private-fixture-text";
    fs::write(&workspace.token_path, forbidden_token).expect("invalid token fixture");
    let refused = binary()
        .arg("--check-config")
        .arg(&workspace.config_path)
        .output()
        .expect("refused diagnostic process");
    assert_eq!(refused.status.code(), Some(3));
    assert!(refused.stderr.is_empty());
    let refused_report: ServiceConfigurationDiagnostic =
        serde_json::from_slice(&refused.stdout).expect("refused diagnostic JSON");
    assert_eq!(
        refused_report.status,
        ConfigurationDiagnosticStatus::Refused
    );
    assert_redacted(&refused.stdout, &workspace, &[forbidden_token]);

    let invalid = binary()
        .arg("--check-config")
        .output()
        .expect("invalid invocation");
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    let diagnostic = String::from_utf8(invalid.stderr).expect("usage diagnostic UTF-8");
    assert!(diagnostic.contains("usage: cantord --config"));
    assert!(diagnostic.contains("cantord --check-config"));
}

#[test]
fn config_server_invocation_contract_remains_available() {
    let path = Path::new("relative-config-is-refused-before-bind.json");
    let output = binary()
        .arg("--config")
        .arg(path)
        .output()
        .expect("server invocation process");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let diagnostic = String::from_utf8(output.stderr).expect("server diagnostic UTF-8");
    assert!(diagnostic.contains("relative_config_path"));
}
