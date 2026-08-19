use cantor_compact_reflection_loop::{
    AttentionTransportKind, ScriptedCompactTransportProjection,
    generate_scripted_compact_transport_projection,
    pretty_scripted_compact_transport_projection_bytes,
    validate_scripted_compact_transport_projection,
};
use serde_json::{Value, json};

#[test]
fn projection_keeps_actual_transport_and_canonical_replay_distinct() {
    let projection = generate_scripted_compact_transport_projection().expect("projection");
    validate_scripted_compact_transport_projection(&projection).expect("valid projection");
    assert_eq!(projection.iteration_transports.len(), 2);
    assert_eq!(
        projection.iteration_transports[0].transport_kind,
        AttentionTransportKind::FullPrefix
    );
    assert!(projection.iteration_transports[0].reentry_frame.is_none());
    assert_eq!(
        projection.iteration_transports[0].actual_request,
        projection.iteration_transports[0]
            .canonical_iteration
            .request
    );
    assert_eq!(
        projection.iteration_transports[1].transport_kind,
        AttentionTransportKind::CompactReentry
    );
    assert!(projection.iteration_transports[1].reentry_frame.is_some());
    assert_ne!(
        projection.iteration_transports[1].actual_request,
        projection.iteration_transports[1]
            .canonical_iteration
            .request
    );
    assert_eq!(
        projection.terminal_reflection_transport.transport_kind,
        AttentionTransportKind::CompactReentry
    );
    assert!(!projection.provider_execution_claimed);
    assert!(!projection.semantic_equivalence_claimed);
    assert!(projection.structural_equivalence_only);
    assert!(projection.request_byte_account.canonical_request_bytes > 0);
    assert!(projection.request_byte_account.actual_request_bytes > 0);
    assert_eq!(
        projection.request_byte_account.canonical_minus_actual_bytes,
        i64::try_from(projection.request_byte_account.canonical_request_bytes)
            .expect("canonical bytes fit")
            - i64::try_from(projection.request_byte_account.actual_request_bytes)
                .expect("actual bytes fit")
    );
}

#[test]
fn projection_is_deterministic_closed_and_normalized() {
    let first = generate_scripted_compact_transport_projection().expect("first projection");
    let second = generate_scripted_compact_transport_projection().expect("second projection");
    assert_eq!(first, second);
    let bytes =
        pretty_scripted_compact_transport_projection_bytes(&first).expect("pretty projection");
    assert_eq!(bytes.last(), Some(&b'\n'));
    let decoded: ScriptedCompactTransportProjection =
        serde_json::from_slice(&bytes).expect("projection JSON");
    assert_eq!(decoded, first);

    let encoded = serde_json::to_value(&first).expect("projection value");
    let mut unknown = encoded;
    unknown["provider_connected"] = Value::Bool(false);
    assert!(serde_json::from_value::<ScriptedCompactTransportProjection>(unknown).is_err());
}

#[test]
fn transport_and_canonical_mutations_fail_closed() {
    let projection = generate_scripted_compact_transport_projection().expect("projection");

    let mut kind = projection.clone();
    kind.iteration_transports[0].transport_kind = AttentionTransportKind::CompactReentry;
    assert!(validate_scripted_compact_transport_projection(&kind).is_err());

    let mut frame = projection.clone();
    frame.iteration_transports[1]
        .reentry_frame
        .as_mut()
        .expect("frame")
        .iteration_count += 1;
    assert!(validate_scripted_compact_transport_projection(&frame).is_err());

    let mut actual = projection.clone();
    actual.iteration_transports[1].actual_request["temperature"] = json!(1);
    assert!(validate_scripted_compact_transport_projection(&actual).is_err());

    let mut response = projection.clone();
    response.iteration_transports[1].sanitized_response["choices"][0]["finish_reason"] =
        json!("stop");
    assert!(validate_scripted_compact_transport_projection(&response).is_err());

    let mut canonical = projection.clone();
    canonical.iteration_transports[1]
        .canonical_iteration
        .call_id
        .push_str("-changed");
    assert!(validate_scripted_compact_transport_projection(&canonical).is_err());

    let mut terminal = projection.clone();
    terminal.terminal_reflection_transport.actual_request["max_tokens"] = json!(513);
    assert!(validate_scripted_compact_transport_projection(&terminal).is_err());

    let mut complete = projection.clone();
    complete.canonical_complete.provider_execution_claimed = true;
    assert!(validate_scripted_compact_transport_projection(&complete).is_err());

    let mut claim = projection.clone();
    claim.semantic_equivalence_claimed = true;
    assert!(validate_scripted_compact_transport_projection(&claim).is_err());

    let mut bytes = projection;
    bytes.request_byte_account.actual_request_bytes += 1;
    assert!(validate_scripted_compact_transport_projection(&bytes).is_err());
}
