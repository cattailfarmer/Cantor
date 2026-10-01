use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

use cantor_sop_inspect::{InspectionRequest, request as inspection_request};
use cantor_sop_inspect_wire::{
    MAX_WIRE_REQUEST_BYTES, REQUEST_PROFILE, Status, parse_response, request, respond,
};
use cantor_sop_project::{PROJECT_PROFILE, SuppliedFile, SuppliedPackage, SuppliedProject};
use cantor_sop_query::FindRequest;

const SOURCE: &str = "kind [kind:fact] \"Fact\" { meaning \"An observation\" }\ncontext [context:any] { scopes () purposes () perspectives () }\nterm [site:alpha] \"Alpha one\" { kind [kind:fact] context [context:any] meaning \"Alpha\" }\nterm [site:beta] \"Alpha two\" { kind [kind:fact] context [context:any] meaning \"Beta\" }\n";
const PUBLIC_FAULT: &[u8] = b"cantor_stdio_host_refused\n";

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cantor-sop-inspect-stdio")
}

fn project() -> SuppliedProject {
    SuppliedProject {
        profile: PROJECT_PROFILE.to_owned(),
        packages: vec![SuppliedPackage {
            id: "pkg:site".to_owned(),
            version: "1.0.0".to_owned(),
            namespaces: ["site".to_owned()].into_iter().collect(),
            dependencies: Default::default(),
            files: vec![SuppliedFile {
                id: "source:site".to_owned(),
                path: "site/main.sop".to_owned(),
                namespace: "site".to_owned(),
                text: SOURCE.to_owned(),
            }],
        }],
    }
}

fn nested(text: &str) -> InspectionRequest {
    inspection_request(project(), FindRequest::prefix(text)).unwrap()
}

fn encoded(nested_request: InspectionRequest) -> Vec<u8> {
    serde_json::to_vec(&request(nested_request)).unwrap()
}

fn run(input: &[u8], arguments: &[&str]) -> Output {
    let mut child = Command::new(binary())
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(input);
    child.wait_with_output().unwrap()
}

#[test]
fn fresh_process_stdout_is_the_exact_direct_wire_response() {
    let input = encoded(nested("Alp"));
    let expected = respond(&input).unwrap();
    let first = run(&input, &[]);
    let second = run(&input, &[]);
    assert!(first.status.success());
    assert_eq!(first.stdout, expected);
    assert_eq!(first.stdout, second.stdout);
    assert!(first.stderr.is_empty());
    assert!(second.status.success());
}

#[test]
fn nested_refusal_is_a_successfully_transported_wire_response() {
    let mut invalid = nested("Alp");
    invalid.request_digest = "0".repeat(64);
    let input = encoded(invalid);
    let output = run(&input, &[]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, respond(&input).unwrap());
    assert_eq!(
        parse_response(&output.stdout).unwrap().status,
        Status::Refused
    );
}

#[test]
fn invocation_faults_are_fixed_bounded_and_non_echoing() {
    for output in [
        run(&[], &[]),
        run(b"secret malformed input", &[]),
        run(b"{}", &["extra"]),
    ] {
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, PUBLIC_FAULT);
        assert!(!output.stderr.windows(6).any(|bytes| bytes == b"secret"));
    }
}

#[test]
fn strict_outer_and_raw_bound_faults_do_not_dispatch_or_echo() {
    let valid = encoded(nested("Alp"));
    let mut unknown: serde_json::Value = serde_json::from_slice(&valid).unwrap();
    unknown["extra"] = serde_json::json!(false);
    let mut trailing = valid.clone();
    trailing.extend_from_slice(b"{}");
    let duplicate = String::from_utf8(valid)
        .unwrap()
        .replacen(
            &format!("\"profile\":\"{REQUEST_PROFILE}\""),
            &format!("\"profile\":\"{REQUEST_PROFILE}\",\"profile\":\"{REQUEST_PROFILE}\""),
            1,
        )
        .into_bytes();
    let oversized = vec![b'x'; MAX_WIRE_REQUEST_BYTES + 1];
    for input in [
        b"{".to_vec(),
        serde_json::to_vec(&unknown).unwrap(),
        trailing,
        duplicate,
        oversized,
    ] {
        let output = run(&input, &[]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, PUBLIC_FAULT);
        assert!(!output.stderr.windows(5).any(|bytes| bytes == b"extra"));
    }
}

#[test]
fn empty_page_and_pagination_survive_fresh_processes() {
    let empty = run(&encoded(nested("Absent")), &[]);
    assert!(empty.status.success());
    assert!(
        parse_response(&empty.stdout)
            .unwrap()
            .result
            .unwrap()
            .find
            .items
            .is_empty()
    );

    let mut find = FindRequest::prefix("Alp");
    find.limit = 1;
    let first_input = encoded(inspection_request(project(), find.clone()).unwrap());
    let first = parse_response(&run(&first_input, &[]).stdout).unwrap();
    let first_result = first.result.unwrap();
    assert_eq!(first_result.find.items.len(), 1);
    assert!(!first_result.find.complete);
    find.cursor = first_result.find.next;
    let second_input = encoded(inspection_request(project(), find).unwrap());
    let second = parse_response(&run(&second_input, &[]).stdout).unwrap();
    assert!(second.result.unwrap().find.complete);
}

#[test]
fn closed_stdout_returns_failure_without_an_alternate_fault_payload() {
    let input = encoded(nested("Alp"));
    let mut child = Command::new(binary())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    child.stdin.take().unwrap().write_all(&input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}
