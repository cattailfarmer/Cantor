use std::{
    io::Write,
    process::{Command, Stdio},
};

use cantor_compact_reflection_loop::{
    CHECKPOINT_HANDLE_DISCOVERY_SELECTOR_PROFILE, CheckpointHandleDiscoveryResponse,
    CheckpointHandleDiscoverySelector, DispatchCheckpointNextOperation, EffectlessDispatchPhase,
    discover_checkpoint_handles, generate_scripted_checkpoint_custody_registry,
    pretty_checkpoint_handle_discovery_response_bytes,
    validate_checkpoint_handle_discovery_response, validate_checkpoint_handle_discovery_selector,
};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cantor-compact-reflection-loop")
}

fn selector(maximum_results: usize) -> CheckpointHandleDiscoverySelector {
    CheckpointHandleDiscoverySelector {
        profile: CHECKPOINT_HANDLE_DISCOVERY_SELECTOR_PROFILE.to_owned(),
        expected_registry_root: None,
        checkpoint_phase: None,
        next_operation: None,
        transport_position: None,
        terminal_reflection: None,
        checkpoint_digest_prefix: None,
        maximum_results,
    }
}

#[test]
fn bootstrap_discovery_is_bounded_ordered_and_body_free() {
    let registry = generate_scripted_checkpoint_custody_registry().expect("registry");
    let selector = selector(5);
    let response = discover_checkpoint_handles(&registry, &selector).expect("discover");
    assert!(!response.caller_root_pinned);
    assert_eq!(response.available_match_count, 12);
    assert_eq!(response.returned_match_count, 5);
    assert!(response.truncated);
    assert!(!response.checkpoint_bodies_embedded);
    let keys: Vec<_> = response
        .matches
        .iter()
        .map(|value| value.handle.checkpoint_digest.value.as_str())
        .collect();
    assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
    let encoded = serde_json::to_string(&response).expect("JSON");
    assert!(!encoded.contains("actual_request"));
    assert!(!encoded.contains("sanitized_response"));
}

#[test]
fn pinned_filters_intersect_and_zero_matches_are_valid() {
    let registry = generate_scripted_checkpoint_custody_registry().expect("registry");
    let mut terminal = selector(12);
    terminal.expected_registry_root = Some(registry.root_digest.clone());
    terminal.terminal_reflection = Some(true);
    let terminal_response = discover_checkpoint_handles(&registry, &terminal).expect("terminal");
    assert!(terminal_response.caller_root_pinned);
    assert_eq!(terminal_response.available_match_count, 4);
    assert!(
        terminal_response
            .matches
            .iter()
            .all(|value| value.handle.terminal_reflection)
    );

    let mut exact = selector(12);
    exact.expected_registry_root = Some(registry.root_digest.clone());
    exact.transport_position = Some(1);
    exact.checkpoint_phase = Some(EffectlessDispatchPhase::FixtureResponseRecorded);
    exact.next_operation = Some(DispatchCheckpointNextOperation::AdmitCanonical);
    let exact_response = discover_checkpoint_handles(&registry, &exact).expect("exact");
    assert_eq!(exact_response.returned_match_count, 1);
    let digest = &exact_response.matches[0].handle.checkpoint_digest.value;
    exact.checkpoint_digest_prefix = Some(digest[..8].to_owned());
    assert_eq!(
        discover_checkpoint_handles(&registry, &exact)
            .expect("prefix")
            .returned_match_count,
        1
    );

    exact.checkpoint_digest_prefix = Some("00000000".to_owned());
    let none = discover_checkpoint_handles(&registry, &exact).expect("zero match");
    assert_eq!(none.available_match_count, 0);
    assert!(!none.truncated);
}

#[test]
fn invalid_selectors_and_response_mutations_fail_closed() {
    let registry = generate_scripted_checkpoint_custody_registry().expect("registry");
    let mut invalid = selector(0);
    assert!(validate_checkpoint_handle_discovery_selector(&invalid).is_err());
    invalid.maximum_results = 12;
    invalid.checkpoint_digest_prefix = Some("ABCDEF12".to_owned());
    assert!(validate_checkpoint_handle_discovery_selector(&invalid).is_err());
    invalid.checkpoint_digest_prefix = Some("abc".to_owned());
    assert!(validate_checkpoint_handle_discovery_selector(&invalid).is_err());
    let mut wrong_root = selector(12);
    wrong_root.expected_registry_root = Some(registry.root_digest.clone());
    let replacement = if wrong_root
        .expected_registry_root
        .as_ref()
        .expect("root")
        .value
        .starts_with('0')
    {
        "1"
    } else {
        "0"
    };
    wrong_root
        .expected_registry_root
        .as_mut()
        .expect("root")
        .value
        .replace_range(0..1, replacement);
    assert!(discover_checkpoint_handles(&registry, &wrong_root).is_err());
    let mut unknown = serde_json::to_value(selector(12)).expect("selector value");
    unknown
        .as_object_mut()
        .expect("object")
        .insert("unknown".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<CheckpointHandleDiscoverySelector>(unknown).is_err());

    let valid = selector(2);
    let response = discover_checkpoint_handles(&registry, &valid).expect("response");
    let mut wrong_count = response.clone();
    wrong_count.returned_match_count += 1;
    assert!(
        validate_checkpoint_handle_discovery_response(&registry, &valid, &wrong_count).is_err()
    );
    let mut reordered = response.clone();
    reordered.matches.swap(0, 1);
    assert!(validate_checkpoint_handle_discovery_response(&registry, &valid, &reordered).is_err());
    let mut body_claim = response;
    body_claim.checkpoint_bodies_embedded = true;
    assert!(validate_checkpoint_handle_discovery_response(&registry, &valid, &body_claim).is_err());
}

#[test]
fn discovery_cli_accepts_strict_stdin_and_rejects_boundary_faults() {
    let registry = generate_scripted_checkpoint_custody_registry().expect("registry");
    let selector = selector(3);
    let input = serde_json::to_vec_pretty(&selector).expect("selector JSON");
    let mut child = Command::new(binary())
        .arg("discover-scripted-checkpoint-handles")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(&input)
        .expect("write");
    let output = child.wait_with_output().expect("output");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: CheckpointHandleDiscoveryResponse =
        serde_json::from_slice(&output.stdout).expect("response");
    validate_checkpoint_handle_discovery_response(&registry, &selector, &response).expect("valid");
    assert_eq!(
        output.stdout,
        pretty_checkpoint_handle_discovery_response_bytes(&registry, &selector, &response)
            .expect("pretty")
    );

    let empty = Command::new(binary())
        .arg("discover-scripted-checkpoint-handles")
        .stdin(Stdio::null())
        .output()
        .expect("empty");
    assert_eq!(empty.status.code(), Some(1));
    let extra = Command::new(binary())
        .args(["discover-scripted-checkpoint-handles", "unexpected"])
        .output()
        .expect("extra");
    assert_eq!(extra.status.code(), Some(2));

    let mut trailing = Command::new(binary())
        .arg("discover-scripted-checkpoint-handles")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trailing");
    let mut trailing_input = input;
    trailing_input.extend_from_slice(b"{}\n");
    trailing
        .stdin
        .take()
        .expect("stdin")
        .write_all(&trailing_input)
        .expect("write trailing");
    assert_eq!(
        trailing.wait_with_output().expect("trailing").status.code(),
        Some(1)
    );

    let mut oversized = Command::new(binary())
        .arg("discover-scripted-checkpoint-handles")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn oversized");
    oversized
        .stdin
        .take()
        .expect("stdin")
        .write_all(&vec![b' '; 64 * 1024 + 1])
        .expect("write oversized");
    assert_eq!(
        oversized
            .wait_with_output()
            .expect("oversized")
            .status
            .code(),
        Some(1)
    );
}
