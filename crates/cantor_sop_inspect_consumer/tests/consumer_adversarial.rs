mod support;

use cantor_sop_inspect_consumer::{
    CONTRACT_PROFILE, MAX_CONTRACT_BYTES, MAX_RECEIPT_BYTES, MAX_STDERR_BYTES, Outcome,
    PUBLIC_HOST_FAULT, RECEIPT_PROFILE, Receipt, Transcript, contract, parse_contract,
    parse_receipt, validate_receipt, verify,
};
use cantor_sop_inspect_wire::{MAX_WIRE_REQUEST_BYTES, MAX_WIRE_RESPONSE_BYTES, respond};
use cantor_sop_semantics::digest;

fn transcript(stdout: &[u8]) -> Transcript<'_> {
    Transcript {
        exit_code: 0,
        stdout,
        stderr: b"",
    }
}

fn reseal(receipt: &mut Receipt) {
    receipt.receipt_digest.clear();
    receipt.receipt_digest = digest::value(RECEIPT_PROFILE, receipt).unwrap();
}

#[test]
fn supported_contract_round_trips_with_exact_seal_and_framing() {
    let supported = contract().unwrap();
    assert_eq!(supported.argument_count, 0);
    assert!(supported.stdin_framing.contains("eof"));
    assert!(!supported.stdin_framing.contains("jsonl"));
    let bytes = serde_json::to_vec(&supported).unwrap();
    assert_eq!(parse_contract(&bytes).unwrap(), supported);
    let mut unsigned = supported.clone();
    unsigned.contract_digest.clear();
    assert_eq!(
        supported.contract_digest,
        digest::value(CONTRACT_PROFILE, &unsigned).unwrap()
    );
}

#[test]
fn every_contract_coordinate_refuses_even_when_resealed() {
    let supported = serde_json::to_value(contract().unwrap()).unwrap();
    for key in supported.as_object().unwrap().keys() {
        let mut changed = supported.clone();
        changed[key] = match &changed[key] {
            serde_json::Value::Number(value) => serde_json::json!(value.as_i64().unwrap() + 1),
            _ => serde_json::json!("unsupported"),
        };
        if key != "contract_digest" {
            changed["contract_digest"] = serde_json::json!("");
            changed["contract_digest"] =
                serde_json::json!(digest::value(CONTRACT_PROFILE, &changed).unwrap());
        }
        assert!(
            parse_contract(&serde_json::to_vec(&changed).unwrap()).is_err(),
            "accepted {key}"
        );
    }
}

#[test]
fn strict_contract_parser_refuses_unknown_duplicate_trailing_and_raw_bound() {
    let bytes = serde_json::to_vec(&contract().unwrap()).unwrap();
    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    unknown["new_service"] = serde_json::json!(true);
    let mut trailing = bytes.clone();
    trailing.extend_from_slice(b"{}");
    let duplicate = String::from_utf8(bytes)
        .unwrap()
        .replacen(
            "\"argument_count\":0",
            "\"argument_count\":0,\"argument_count\":0",
            1,
        )
        .into_bytes();
    for invalid in [
        serde_json::to_vec(&unknown).unwrap(),
        trailing,
        duplicate,
        vec![b' '; MAX_CONTRACT_BYTES + 1],
    ] {
        assert!(parse_contract(&invalid).is_err());
    }
}

#[test]
fn receipt_binds_raw_request_stdout_stderr_and_semantic_outcome() {
    let input = support::success_input();
    let output = respond(&input).unwrap();
    let receipt = verify(&input, transcript(&output)).unwrap();
    assert_eq!(receipt.outcome, Outcome::InspectionSucceeded);
    assert_eq!(receipt.request_sha256, digest::bytes(&input));
    assert_eq!(receipt.stdout_sha256, digest::bytes(&output));
    assert_eq!(receipt.stderr_sha256, digest::bytes(b""));
    assert_eq!(receipt.request_bytes, input.len());
    assert_eq!(receipt.stdout_bytes, output.len());
    validate_receipt(&input, transcript(&output), &receipt).unwrap();
    assert_eq!(
        parse_receipt(&serde_json::to_vec(&receipt).unwrap()).unwrap(),
        receipt
    );
}

#[test]
fn nested_refusal_and_host_refusal_have_distinct_receipts() {
    let fixtures = support::bundle();
    assert_eq!(fixtures.cases[4].receipt.outcome, Outcome::SemanticRefused);
    assert_eq!(fixtures.cases[4].exit_code, 0);
    for fixture in &fixtures.cases[5..] {
        assert_eq!(fixture.receipt.outcome, Outcome::HostRefused);
        assert_eq!(fixture.exit_code, 2);
        assert!(fixture.receipt.wire_response_digest.is_none());
    }
}

#[test]
fn generated_bundle_has_eight_exact_supported_cases() {
    let bytes = support::bundle_bytes();
    let bundle: support::FixtureBundle = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(bundle.profile, support::BUNDLE_PROFILE);
    assert_eq!(bundle.cases.len(), 8);
    assert_eq!(bundle.contract, contract().unwrap());
}

#[test]
fn partial_output_unexplained_exit_and_alternate_payload_never_receive_a_receipt() {
    let input = support::success_input();
    let output = respond(&input).unwrap();
    for invalid in [
        Transcript {
            exit_code: 0,
            stdout: &output[..output.len() - 1],
            stderr: b"",
        },
        Transcript {
            exit_code: 2,
            stdout: &output,
            stderr: b"",
        },
        Transcript {
            exit_code: 2,
            stdout: b"",
            stderr: PUBLIC_HOST_FAULT,
        },
        Transcript {
            exit_code: 0,
            stdout: &output,
            stderr: PUBLIC_HOST_FAULT,
        },
        Transcript {
            exit_code: -1,
            stdout: b"",
            stderr: b"",
        },
        Transcript {
            exit_code: 1,
            stdout: b"",
            stderr: b"",
        },
        Transcript {
            exit_code: 0,
            stdout: b"",
            stderr: b"",
        },
    ] {
        assert!(verify(&input, invalid).is_err());
    }
}

#[test]
fn host_refusal_requires_exact_exit_empty_stdout_and_fixed_stderr() {
    for invalid in [
        Transcript {
            exit_code: 0,
            stdout: b"",
            stderr: PUBLIC_HOST_FAULT,
        },
        Transcript {
            exit_code: 1,
            stdout: b"",
            stderr: PUBLIC_HOST_FAULT,
        },
        Transcript {
            exit_code: 2,
            stdout: b"{}",
            stderr: PUBLIC_HOST_FAULT,
        },
        Transcript {
            exit_code: 2,
            stdout: b"",
            stderr: b"secret OS diagnostics",
        },
        Transcript {
            exit_code: 2,
            stdout: b"",
            stderr: b"",
        },
    ] {
        assert!(verify(b"{", invalid).is_err());
    }
}

#[test]
fn equivalent_json_whitespace_reordering_and_changed_nested_data_are_not_exact_stdout() {
    let input = support::success_input();
    let output = respond(&input).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let mut suffix = output.clone();
    suffix.push(b'\n');
    let reordered = serde_json::to_vec(&value).unwrap();
    assert_ne!(reordered, output);
    let mut changed = value;
    changed["result"]["non_authority"] = serde_json::json!("grants execution");
    changed["response_digest"] = serde_json::json!("");
    changed["response_digest"] = serde_json::json!(
        digest::value("cantor-sop-inspection-wire-response/0.1", &changed).unwrap()
    );
    for invalid in [suffix, reordered, serde_json::to_vec(&changed).unwrap()] {
        assert!(verify(&input, transcript(&invalid)).is_err());
    }
}

#[test]
fn receipt_cannot_be_transplanted_to_equivalent_raw_input() {
    let input = support::success_input();
    let output = respond(&input).unwrap();
    let receipt = verify(&input, transcript(&output)).unwrap();
    let mut padded = input.clone();
    padded.push(b'\n');
    assert_eq!(respond(&padded).unwrap(), output);
    assert!(validate_receipt(&padded, transcript(&output), &receipt).is_err());
}

#[test]
fn resealed_receipt_mutation_can_parse_but_cannot_be_accepted_without_reconstruction() {
    let input = support::success_input();
    let output = respond(&input).unwrap();
    let mut receipt = verify(&input, transcript(&output)).unwrap();
    receipt.request_sha256 = "0".repeat(64);
    reseal(&mut receipt);
    let parsed = parse_receipt(&serde_json::to_vec(&receipt).unwrap()).unwrap();
    assert!(validate_receipt(&input, transcript(&output), &parsed).is_err());
}

#[test]
fn receipt_parser_refuses_incompatible_shape_duplicate_unknown_trailing_and_oversize() {
    let input = support::success_input();
    let output = respond(&input).unwrap();
    let receipt = verify(&input, transcript(&output)).unwrap();
    let bytes = serde_json::to_vec(&receipt).unwrap();
    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    unknown["launch_authority"] = serde_json::json!(true);
    let mut trailing = bytes.clone();
    trailing.extend_from_slice(b"{}");
    let duplicate = String::from_utf8(bytes)
        .unwrap()
        .replacen("\"exit_code\":0", "\"exit_code\":0,\"exit_code\":0", 1)
        .into_bytes();
    let mut incompatible = receipt;
    incompatible.outcome = Outcome::HostRefused;
    reseal(&mut incompatible);
    for invalid in [
        serde_json::to_vec(&unknown).unwrap(),
        trailing,
        duplicate,
        serde_json::to_vec(&incompatible).unwrap(),
        vec![b' '; MAX_RECEIPT_BYTES + 1],
    ] {
        assert!(parse_receipt(&invalid).is_err());
    }
}

#[test]
fn every_receipt_coordinate_mutation_refuses_transcript_reconstruction() {
    let input = support::success_input();
    let output = respond(&input).unwrap();
    let receipt = verify(&input, transcript(&output)).unwrap();
    let value = serde_json::to_value(&receipt).unwrap();
    for key in value.as_object().unwrap().keys() {
        let mut changed = value.clone();
        changed[key] = match &changed[key] {
            serde_json::Value::Number(value) => serde_json::json!(value.as_i64().unwrap() + 1),
            _ => serde_json::json!("unsupported"),
        };
        if let Ok(changed) = serde_json::from_value::<Receipt>(changed) {
            assert!(
                validate_receipt(&input, transcript(&output), &changed).is_err(),
                "accepted {key}"
            );
        }
    }
}

#[test]
fn raw_transcript_limits_are_checked_before_dispatch() {
    let request = vec![b'x'; MAX_WIRE_REQUEST_BYTES + 2];
    assert_eq!(
        verify(
            &request,
            Transcript {
                exit_code: 2,
                stdout: b"",
                stderr: PUBLIC_HOST_FAULT
            }
        )
        .unwrap_err()
        .code,
        "consumer_transcript_limit"
    );
    drop(request);
    let output = vec![b'x'; MAX_WIRE_RESPONSE_BYTES + 1];
    assert_eq!(
        verify(
            b"{",
            Transcript {
                exit_code: 2,
                stdout: &output,
                stderr: PUBLIC_HOST_FAULT
            }
        )
        .unwrap_err()
        .code,
        "consumer_transcript_limit"
    );
    drop(output);
    let stderr = vec![b'x'; MAX_STDERR_BYTES + 1];
    assert_eq!(
        verify(
            b"{",
            Transcript {
                exit_code: 2,
                stdout: b"",
                stderr: &stderr
            }
        )
        .unwrap_err()
        .code,
        "consumer_transcript_limit"
    );
}

#[test]
fn maximum_plus_one_request_retains_only_deterministic_host_refusal() {
    let request = vec![b'x'; MAX_WIRE_REQUEST_BYTES + 1];
    let receipt = verify(
        &request,
        Transcript {
            exit_code: 2,
            stdout: b"",
            stderr: PUBLIC_HOST_FAULT,
        },
    )
    .unwrap();
    assert_eq!(receipt.outcome, Outcome::HostRefused);
    assert_eq!(receipt.request_bytes, MAX_WIRE_REQUEST_BYTES + 1);
}
