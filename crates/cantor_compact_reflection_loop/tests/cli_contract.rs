use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cantor-compact-reflection-loop")
}

fn unique_path(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("cantor-{label}-{}-{nonce}", std::process::id()))
}

#[test]
fn help_exposes_the_bounded_live_contract() {
    let output = Command::new(binary()).arg("--help").output().expect("run");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8");
    assert!(stdout.contains("model -> compact Cantor procedure -> model reflection"));
    assert!(stdout.contains("--context PATH"));
    assert!(stdout.contains("--maximum-steps N"));
}

#[test]
fn incomplete_or_remote_configuration_fails_before_provider_contact() {
    let missing = Command::new(binary()).output().expect("run");
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("--context is required"));

    let remote = Command::new(binary())
        .args([
            "--context",
            "not-read-before-config-admission.json",
            "--prompt",
            "bounded",
            "--base-url",
            "http://192.168.1.19:8081/v1",
        ])
        .output()
        .expect("run");
    assert_eq!(remote.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&remote.stderr).contains("loopback"));
}

#[test]
fn context_and_create_new_output_boundaries_fail_closed() {
    let empty_context = unique_path("empty-context");
    fs::write(&empty_context, []).expect("write empty fixture");
    let empty = Command::new(binary())
        .args([
            "--context",
            empty_context.to_str().expect("path"),
            "--prompt",
            "bounded",
        ])
        .output()
        .expect("run");
    assert_eq!(empty.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&empty.stderr).contains("nonempty regular file"));

    let existing_output = unique_path("existing-output");
    fs::write(&existing_output, b"preserve").expect("write existing output");
    let existing = Command::new(binary())
        .args([
            "--context",
            empty_context.to_str().expect("path"),
            "--prompt",
            "bounded",
            "--output",
            existing_output.to_str().expect("path"),
        ])
        .output()
        .expect("run");
    assert_eq!(existing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&existing.stderr).contains("output already exists"));
    assert_eq!(fs::read(&existing_output).expect("preserved"), b"preserve");

    fs::remove_file(empty_context).expect("remove fixture");
    fs::remove_file(existing_output).expect("remove fixture");
}
