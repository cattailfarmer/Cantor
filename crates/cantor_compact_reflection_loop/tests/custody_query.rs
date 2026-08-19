use std::{
    io::Write,
    process::{Command, Stdio},
};

use cantor_compact_reflection_loop::{
    CHECKPOINT_CUSTODY_QUERY_PROFILE, CheckpointCustodyOperation, CheckpointCustodyQuery,
    CheckpointCustodyResponse, CheckpointCustodyResult, compile_dispatch_checkpoint_handle,
    dispatch_checkpoint_custody_query, generate_scripted_checkpoint_custody_registry,
    generate_scripted_dispatch_resume_corpus, pretty_checkpoint_custody_query_bytes,
    resolve_checkpoint_custody, resume_iteration_from_checkpoint_custody,
    resume_terminal_from_checkpoint_custody, validate_checkpoint_custody_response,
};
use serde_json::json;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cantor-compact-reflection-loop")
}

fn query(operation: CheckpointCustodyOperation) -> CheckpointCustodyQuery {
    let registry = generate_scripted_checkpoint_custody_registry().expect("registry");
    CheckpointCustodyQuery {
        profile: CHECKPOINT_CUSTODY_QUERY_PROFILE.to_owned(),
        expected_registry_root: registry.root_digest,
        operation,
    }
}

fn change_first_hex(value: &mut String) {
    let replacement = if value.starts_with('0') { "1" } else { "0" };
    value.replace_range(0..1, replacement);
}

#[test]
fn inspection_is_compact_bound_and_deterministic() {
    let registry = generate_scripted_checkpoint_custody_registry().expect("registry");
    let corpus = generate_scripted_dispatch_resume_corpus().expect("corpus");
    let case = &corpus.cases[0];
    let handle = compile_dispatch_checkpoint_handle(
        &case.checkpoint,
        case.transport_position,
        case.terminal_reflection,
    )
    .expect("handle");
    let request = query(CheckpointCustodyOperation::Inspect { handle });
    let first = dispatch_checkpoint_custody_query(&registry, &request).expect("inspect");
    let second = dispatch_checkpoint_custody_query(&registry, &request).expect("repeat");
    assert_eq!(first, second);
    validate_checkpoint_custody_response(&registry, &request, &first).expect("response");
    let encoded = serde_json::to_string(&first).expect("JSON");
    assert!(!encoded.contains("actual_request"));
    assert!(!encoded.contains("sanitized_response"));
    assert!(!encoded.contains("canonical_iteration"));
    match first.result {
        CheckpointCustodyResult::Inspection { inspection } => {
            assert!(inspection.exact_checkpoint_available);
            assert!(!inspection.full_checkpoint_embedded);
            assert_eq!(inspection.checkpoint_phase, case.checkpoint_phase);
        }
        _ => panic!("wrong result"),
    }
}

#[test]
fn resolve_and_every_resume_equal_direct_custody_functions() {
    let registry = generate_scripted_checkpoint_custody_registry().expect("registry");
    let corpus = generate_scripted_dispatch_resume_corpus().expect("corpus");
    let projection = &corpus.source_run.source_envelopes.source_projection;
    for case in &corpus.cases {
        let handle = compile_dispatch_checkpoint_handle(
            &case.checkpoint,
            case.transport_position,
            case.terminal_reflection,
        )
        .expect("handle");
        let resolved_request = query(CheckpointCustodyOperation::Resolve {
            handle: handle.clone(),
        });
        let resolved = dispatch_checkpoint_custody_query(&registry, &resolved_request)
            .expect("resolve response");
        assert_eq!(
            resolved.result,
            CheckpointCustodyResult::Resolved {
                checkpoint: resolve_checkpoint_custody(&registry, &handle).expect("direct resolve")
            }
        );

        let (request, direct) = if case.terminal_reflection {
            let transport = projection.terminal_reflection_transport.clone();
            (
                query(CheckpointCustodyOperation::ResumeTerminal {
                    handle: handle.clone(),
                    transport: Box::new(transport.clone()),
                }),
                resume_terminal_from_checkpoint_custody(&registry, &handle, &transport)
                    .expect("direct terminal"),
            )
        } else {
            let transport =
                projection.iteration_transports[case.transport_position as usize].clone();
            (
                query(CheckpointCustodyOperation::ResumeIteration {
                    handle: handle.clone(),
                    transport: Box::new(transport.clone()),
                }),
                resume_iteration_from_checkpoint_custody(&registry, &handle, &transport)
                    .expect("direct iteration"),
            )
        };
        let response = dispatch_checkpoint_custody_query(&registry, &request).expect("resume");
        match response.result {
            CheckpointCustodyResult::IterationResumed { trace }
            | CheckpointCustodyResult::TerminalResumed { trace } => assert_eq!(trace, direct),
            _ => panic!("wrong resume result"),
        }
    }
}

#[test]
fn roots_cross_kind_and_response_mutations_fail_closed() {
    let registry = generate_scripted_checkpoint_custody_registry().expect("registry");
    let corpus = generate_scripted_dispatch_resume_corpus().expect("corpus");
    let iteration_case = corpus
        .cases
        .iter()
        .find(|case| !case.terminal_reflection)
        .expect("iteration");
    let terminal_case = corpus
        .cases
        .iter()
        .find(|case| case.terminal_reflection)
        .expect("terminal");
    let iteration_handle = compile_dispatch_checkpoint_handle(
        &iteration_case.checkpoint,
        iteration_case.transport_position,
        false,
    )
    .expect("handle");
    let terminal_handle = compile_dispatch_checkpoint_handle(
        &terminal_case.checkpoint,
        terminal_case.transport_position,
        true,
    )
    .expect("handle");
    let mut wrong_root = query(CheckpointCustodyOperation::Inspect {
        handle: iteration_handle.clone(),
    });
    change_first_hex(&mut wrong_root.expected_registry_root.value);
    assert!(dispatch_checkpoint_custody_query(&registry, &wrong_root).is_err());

    let terminal_transport = corpus
        .source_run
        .source_envelopes
        .source_projection
        .terminal_reflection_transport
        .clone();
    let cross = query(CheckpointCustodyOperation::ResumeTerminal {
        handle: iteration_handle,
        transport: Box::new(terminal_transport),
    });
    assert!(dispatch_checkpoint_custody_query(&registry, &cross).is_err());

    let valid = query(CheckpointCustodyOperation::Inspect {
        handle: terminal_handle,
    });
    let response = dispatch_checkpoint_custody_query(&registry, &valid).expect("response");
    let mut changed = response.clone();
    changed.external_effect_claimed = true;
    assert!(validate_checkpoint_custody_response(&registry, &valid, &changed).is_err());
    let mut changed_digest = response;
    change_first_hex(&mut changed_digest.response_digest.value);
    assert!(validate_checkpoint_custody_response(&registry, &valid, &changed_digest).is_err());
}

#[test]
fn strict_json_rejects_unknown_fields() {
    let registry = generate_scripted_checkpoint_custody_registry().expect("registry");
    let entry = registry.entries.values().next().expect("entry");
    let request = query(CheckpointCustodyOperation::Inspect {
        handle: entry.handle.clone(),
    });
    let mut value = serde_json::to_value(request).expect("value");
    value
        .as_object_mut()
        .expect("object")
        .insert("unknown".to_owned(), json!(true));
    assert!(serde_json::from_value::<CheckpointCustodyQuery>(value).is_err());
}

#[test]
fn cli_accepts_one_bounded_query_on_stdin_and_emits_typed_response() {
    let registry = generate_scripted_checkpoint_custody_registry().expect("registry");
    let entry = registry.entries.values().next().expect("entry");
    let request = query(CheckpointCustodyOperation::Inspect {
        handle: entry.handle.clone(),
    });
    let bytes = pretty_checkpoint_custody_query_bytes(&request).expect("request bytes");
    let mut child = Command::new(binary())
        .arg("query-scripted-checkpoint-custody")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(&bytes)
        .expect("write request");
    let output = child.wait_with_output().expect("output");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let response: CheckpointCustodyResponse =
        serde_json::from_slice(&output.stdout).expect("typed response");
    validate_checkpoint_custody_response(&registry, &request, &response).expect("valid response");

    let extra = Command::new(binary())
        .args(["query-scripted-checkpoint-custody", "unexpected"])
        .output()
        .expect("run invalid");
    assert_eq!(extra.status.code(), Some(2));

    let empty = Command::new(binary())
        .arg("query-scripted-checkpoint-custody")
        .stdin(Stdio::null())
        .output()
        .expect("run empty");
    assert_eq!(empty.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&empty.stderr).contains("stdin is empty"));

    let mut trailing = Command::new(binary())
        .arg("query-scripted-checkpoint-custody")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trailing");
    let mut trailing_bytes = bytes.clone();
    trailing_bytes.extend_from_slice(b"{}\n");
    trailing
        .stdin
        .take()
        .expect("stdin")
        .write_all(&trailing_bytes)
        .expect("write trailing");
    let trailing = trailing.wait_with_output().expect("trailing output");
    assert_eq!(trailing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&trailing.stderr).contains("trailing characters"));

    let mut oversized = Command::new(binary())
        .arg("query-scripted-checkpoint-custody")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn oversized");
    oversized
        .stdin
        .take()
        .expect("stdin")
        .write_all(&vec![b' '; 1024 * 1024 + 1])
        .expect("write oversized");
    let oversized = oversized.wait_with_output().expect("oversized output");
    assert_eq!(oversized.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&oversized.stderr).contains("exceeds 1048576 bytes"));
}
