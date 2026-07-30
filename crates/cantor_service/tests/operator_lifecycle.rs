#![cfg(windows)]

#[allow(dead_code)]
mod common;

use std::{
    collections::BTreeSet,
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Output, Stdio},
    time::{Duration, Instant},
};

use common::{TOKEN, TestWorkspace, write_json};

#[test]
fn production_binaries_have_pid_safe_supervised_operator_lifecycle() {
    let (workspace, _request) = TestWorkspace::new(120, 1);
    let address = reserve_address();
    set_listen_address(&workspace.config_path, &address);

    let state_path = workspace.root.join("supervisor").join("state.json");
    let start_script = script("start_cantor_service.ps1");
    let health_script = script("get_cantor_service_health.ps1");
    let stop_script = script("stop_cantor_service.ps1");
    let server_path = PathBuf::from(env!("CARGO_BIN_EXE_cantord"));
    let client_path = PathBuf::from(env!("CARGO_BIN_EXE_cantorctl"));

    let start = start_service(
        &start_script,
        &server_path,
        &client_path,
        &workspace.config_path,
        &state_path,
        false,
    );
    assert!(
        start.success(),
        "initial supervised start must pass readiness"
    );
    assert!(state_path.is_file(), "readiness must publish state");

    let state_bytes = fs::read(&state_path).expect("state must read");
    let state_text = String::from_utf8(state_bytes.clone()).expect("state must be UTF-8");
    assert!(!state_bytes.starts_with(&[0xef, 0xbb, 0xbf]));
    assert!(!state_text.contains(TOKEN), "state must exclude capability");
    assert!(!state_text.contains("auth_token"));
    let state: serde_json::Value = serde_json::from_slice(&state_bytes).expect("state must decode");
    assert_exact_state_properties(&state);
    assert_eq!(state["schema"], "cantor-service-supervisor-state/0.1");
    assert_eq!(state["server_path"], path_text(&server_path));
    let pid = state["pid"].as_u64().expect("state PID must be unsigned");

    let health = run_script(
        &health_script,
        &["-StatePath".into(), path_text(&state_path)],
    );
    assert_success(&health, "authenticated health");
    let health_json: serde_json::Value =
        serde_json::from_slice(&health.stdout).expect("health must be machine JSON");
    assert_eq!(
        health_json["schema"],
        "cantor-service-supervisor-health/0.1"
    );
    assert_eq!(health_json["state"], "active");
    assert_eq!(health_json["pid"], pid);
    assert_eq!(health_json["current_generation_id"], state["generation_id"]);
    assert!(!String::from_utf8_lossy(&health.stdout).contains(TOKEN));

    let duplicate = start_service(
        &start_script,
        &server_path,
        &client_path,
        &workspace.config_path,
        &state_path,
        false,
    );
    assert!(
        !duplicate.success(),
        "a live matching state must reject duplicate start"
    );
    assert_eq!(
        fs::read(&state_path).expect("state must remain"),
        state_bytes
    );

    let original_token = fs::read(&workspace.token_path).expect("token must read");
    fs::write(&workspace.token_path, format!("{}\n", "f".repeat(64)))
        .expect("alternate capability must write");
    let unauthenticated_stop = run_script(
        &stop_script,
        &[
            "-StatePath".into(),
            path_text(&state_path),
            "-ExitTimeoutMilliseconds".into(),
            "5000".into(),
        ],
    );
    assert!(
        !unauthenticated_stop.status.success(),
        "shutdown with a changed client capability must fail"
    );
    assert_eq!(
        fs::read(&state_path).expect("state must survive rejected shutdown"),
        state_bytes,
        "rejected shutdown must preserve state byte-for-byte"
    );
    fs::write(&workspace.token_path, original_token).expect("token must restore");
    let restored_health = run_script(
        &health_script,
        &["-StatePath".into(), path_text(&state_path)],
    );
    assert_success(&restored_health, "health after capability restoration");

    let forged_path = workspace.root.join("forged-state.json");
    let mut forged = state.clone();
    forged["process_start_time_utc"] = serde_json::json!("2000-01-01T00:00:00.0000000Z");
    write_json(&forged_path, &forged);
    let forged_health = run_script(
        &health_script,
        &["-StatePath".into(), path_text(&forged_path)],
    );
    assert!(
        !forged_health.status.success(),
        "PID-only health authority must fail"
    );
    let forged_stop = run_script(
        &stop_script,
        &[
            "-StatePath".into(),
            path_text(&forged_path),
            "-ExitTimeoutMilliseconds".into(),
            "5000".into(),
        ],
    );
    assert!(
        !forged_stop.status.success(),
        "PID-only stop authority must fail"
    );
    let still_healthy = run_script(
        &health_script,
        &["-StatePath".into(), path_text(&state_path)],
    );
    assert_success(&still_healthy, "service after rejected forged stop");

    forged["unexpected"] = serde_json::json!(true);
    write_json(&forged_path, &forged);
    let unknown_state = run_script(
        &health_script,
        &["-StatePath".into(), path_text(&forged_path)],
    );
    assert!(
        !unknown_state.status.success(),
        "unknown state fields must fail"
    );

    let stop = run_script(
        &stop_script,
        &[
            "-StatePath".into(),
            path_text(&state_path),
            "-ExitTimeoutMilliseconds".into(),
            "10000".into(),
        ],
    );
    assert_success(&stop, "exact-generation graceful stop");
    let stop_json: serde_json::Value =
        serde_json::from_slice(&stop.stdout).expect("stop must be machine JSON");
    assert_eq!(stop_json["state"], "stopped");
    assert_eq!(stop_json["state_removed"], true);
    assert!(!state_path.exists(), "state must be removed after exit");
    TcpListener::bind(&address).expect("graceful stop must release listener");

    fs::write(&state_path, &state_bytes).expect("stale state must write");
    let stale_default = start_service(
        &start_script,
        &server_path,
        &client_path,
        &workspace.config_path,
        &state_path,
        false,
    );
    assert!(
        !stale_default.success(),
        "stale state requires explicit replacement"
    );
    assert_eq!(
        fs::read(&state_path).expect("stale state must remain"),
        state_bytes
    );

    let stale_replaced = start_service(
        &start_script,
        &server_path,
        &client_path,
        &workspace.config_path,
        &state_path,
        true,
    );
    assert!(
        stale_replaced.success(),
        "explicit stale-state replacement must pass"
    );
    let replacement_health = run_script(
        &health_script,
        &["-StatePath".into(), path_text(&state_path)],
    );
    assert_success(&replacement_health, "replacement health");
    let replacement_stop = run_script(
        &stop_script,
        &[
            "-StatePath".into(),
            path_text(&state_path),
            "-ExitTimeoutMilliseconds".into(),
            "10000".into(),
        ],
    );
    assert_success(&replacement_stop, "replacement graceful stop");

    let mut concurrent_a = start_command(
        &start_script,
        &server_path,
        &client_path,
        &workspace.config_path,
        &state_path,
        false,
    )
    .spawn()
    .expect("first concurrent start must spawn");
    let mut concurrent_b = start_command(
        &start_script,
        &server_path,
        &client_path,
        &workspace.config_path,
        &state_path,
        false,
    )
    .spawn()
    .expect("second concurrent start must spawn");
    let concurrent_statuses = [
        concurrent_a
            .wait()
            .expect("first concurrent start must exit"),
        concurrent_b
            .wait()
            .expect("second concurrent start must exit"),
    ];
    assert_eq!(
        concurrent_statuses
            .iter()
            .filter(|status| status.success())
            .count(),
        1,
        "the StatePath mutex must admit exactly one concurrent start"
    );
    let concurrent_health = run_script(
        &health_script,
        &["-StatePath".into(), path_text(&state_path)],
    );
    assert_success(&concurrent_health, "concurrent-start winner health");
    let concurrent_stop = run_script(
        &stop_script,
        &[
            "-StatePath".into(),
            path_text(&state_path),
            "-ExitTimeoutMilliseconds".into(),
            "10000".into(),
        ],
    );
    assert_success(&concurrent_stop, "concurrent-start winner stop");

    let failed_start_begin = Instant::now();
    let failed_start = start_service(
        &start_script,
        &server_path,
        &PathBuf::from(std::env::var("SystemRoot").expect("SystemRoot is required"))
            .join("System32")
            .join("cmd.exe"),
        &workspace.config_path,
        &state_path,
        false,
    );
    assert!(
        !failed_start.success(),
        "non-client readiness probe must fail"
    );
    assert!(
        failed_start_begin.elapsed() < Duration::from_secs(5),
        "the 1.5 second readiness deadline must cap child probes and retry sleeps"
    );
    assert!(
        !state_path.exists(),
        "failed readiness must not publish state"
    );
    TcpListener::bind(&address).expect("failed start must clean up only its new server");
}

fn reserve_address() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("test port must bind");
    let address = listener
        .local_addr()
        .expect("test port address is required")
        .to_string();
    drop(listener);
    address
}

fn set_listen_address(config_path: &Path, address: &str) {
    let mut config: serde_json::Value =
        serde_json::from_slice(&fs::read(config_path).expect("config must read"))
            .expect("config must decode");
    config["listen_address"] = serde_json::json!(address);
    write_json(config_path, &config);
}

fn script(name: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("scripts")
        .join(name);
    assert!(path.is_file(), "operator script must exist");
    path
}

fn start_service(
    script_path: &Path,
    server_path: &Path,
    client_path: &Path,
    config_path: &Path,
    state_path: &Path,
    replace_stale: bool,
) -> ExitStatus {
    start_command(
        script_path,
        server_path,
        client_path,
        config_path,
        state_path,
        replace_stale,
    )
    .status()
    .expect("PowerShell start script must execute")
}

fn start_command(
    script_path: &Path,
    server_path: &Path,
    client_path: &Path,
    config_path: &Path,
    state_path: &Path,
    replace_stale: bool,
) -> Command {
    let mut arguments = vec![
        "-ServerPath".into(),
        path_text(server_path),
        "-ClientPath".into(),
        path_text(client_path),
        "-ConfigPath".into(),
        path_text(config_path),
        "-StatePath".into(),
        path_text(state_path),
        "-ReadinessTimeoutMilliseconds".into(),
        "1500".into(),
        "-ProbeIntervalMilliseconds".into(),
        "25".into(),
    ];
    if replace_stale {
        arguments.push("-ReplaceStale".into());
    }
    let mut command = Command::new("powershell");
    command
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(script_path)
        .args(&arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn run_script(script_path: &Path, arguments: &[String]) -> Output {
    Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(script_path)
        .args(arguments)
        .output()
        .expect("PowerShell operator script must execute")
}

fn path_text(path: &Path) -> String {
    let text = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_str()
        .expect("test path must be UTF-8")
        .to_owned();
    text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned()
}

fn assert_success(output: &Output, stage: &str) {
    assert!(
        output.status.success(),
        "{stage} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_exact_state_properties(state: &serde_json::Value) {
    let actual: BTreeSet<&str> = state
        .as_object()
        .expect("state must be an object")
        .keys()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = [
        "activation_sequence",
        "client_path",
        "config_path",
        "generation_id",
        "pid",
        "process_start_time_utc",
        "schema",
        "server_path",
        "started_at_utc",
        "stderr_log_path",
        "stdout_log_path",
    ]
    .into_iter()
    .collect();
    assert_eq!(actual, expected);
}
