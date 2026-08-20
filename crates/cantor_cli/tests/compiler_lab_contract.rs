use std::io::Write;
use std::process::{Command, Stdio};

use cantor_core::{
    NATIVE_LIFECYCLE_MAX_INPUT_BYTES, NATIVE_LIFECYCLE_VALIDATION_NON_AUTHORITY,
    NATIVE_LIFECYCLE_VALIDATION_PROTOCOL, NativeLifecycleValidationFaultKind,
    NativeLifecycleValidationOutcome, NativeLifecycleValidationResponse,
};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cantor-compiler-lab"))
}

fn run_stdin(bytes: &[u8]) -> std::process::Output {
    let mut child = binary()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start compiler lab");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(bytes)
        .expect("write request");
    child.wait_with_output().expect("compiler lab output")
}

#[test]
fn help_and_version_expose_the_bounded_read_only_contract() {
    let help = binary().arg("--help").output().expect("help output");
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).expect("UTF-8 help");
    assert!(help.contains("[--input <path>]"));
    assert!(!help.contains("--output"));

    let version = binary().arg("--version").output().expect("version output");
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout)
            .expect("UTF-8 version")
            .trim(),
        format!("cantor-compiler-lab {NATIVE_LIFECYCLE_VALIDATION_PROTOCOL}")
    );
}

#[test]
fn malformed_unknown_trailing_and_empty_inputs_are_machine_clean() {
    for bytes in [
        b"".as_slice(),
        b"{".as_slice(),
        b"{}".as_slice(),
        b"{} true".as_slice(),
    ] {
        let output = run_stdin(bytes);
        assert_eq!(output.status.code(), Some(2));
        let response: NativeLifecycleValidationResponse =
            serde_json::from_slice(&output.stdout).expect("typed stdout response");
        assert_eq!(
            response.outcome,
            NativeLifecycleValidationOutcome::InputRefused
        );
        assert_eq!(response.faults.len(), 1);
        assert_eq!(
            response.faults[0].kind,
            NativeLifecycleValidationFaultKind::Wire
        );
        assert_eq!(
            response.non_authority,
            NATIVE_LIFECYCLE_VALIDATION_NON_AUTHORITY
        );
        assert_eq!(output.stdout.last(), Some(&b'\n'));
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn oversized_input_and_invalid_invocation_refuse_before_semantic_replay() {
    let output = run_stdin(&vec![b'x'; NATIVE_LIFECYCLE_MAX_INPUT_BYTES + 1]);
    assert_eq!(output.status.code(), Some(2));
    let response: NativeLifecycleValidationResponse =
        serde_json::from_slice(&output.stdout).expect("bounded fault response");
    assert_eq!(
        response.faults[0].kind,
        NativeLifecycleValidationFaultKind::InvalidBound
    );
    assert!(response.stage_account.is_empty());

    let output = binary()
        .args(["--input", "one", "--output", "two"])
        .output()
        .expect("invalid invocation");
    assert_eq!(output.status.code(), Some(2));
    let response: NativeLifecycleValidationResponse =
        serde_json::from_slice(&output.stdout).expect("invocation response");
    assert_eq!(response.faults[0].field, "arguments");
}
