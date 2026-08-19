use cantor_compact_reflection_loop::{
    AttentionTransportEnvelope, AttentionTransportKind, IterativeProviderPhase,
    ScriptedTransportEnvelopeSet, compile_iteration_transport_envelope,
    generate_scripted_transport_envelope_set, pretty_scripted_transport_envelope_set_bytes,
    validate_attention_transport_envelope, validate_iteration_transport_envelope_against,
    validate_scripted_transport_envelope_set,
};
use serde_json::{Value, json};

#[test]
fn envelopes_separate_local_integrity_from_canonical_reconstruction() {
    let set = generate_scripted_transport_envelope_set().expect("envelope set");
    validate_scripted_transport_envelope_set(&set).expect("valid envelope set");
    assert_eq!(
        set.iteration_envelopes.len(),
        set.source_projection.iteration_transports.len()
    );

    let first = &set.iteration_envelopes[0];
    assert_eq!(first.phase, IterativeProviderPhase::Advance);
    assert_eq!(first.transport_kind, AttentionTransportKind::FullPrefix);
    assert_eq!(first.iteration_index, Some(0));
    assert!(first.reentry_frame.is_none());
    assert!(first.reentry_frame_digest.is_none());
    assert!(first.retained_prefix_digest.is_none());

    let second = &set.iteration_envelopes[1];
    assert_eq!(
        second.transport_kind,
        AttentionTransportKind::CompactReentry
    );
    assert_eq!(second.iteration_index, Some(1));
    assert_eq!(
        second.retained_prefix_digest.as_ref(),
        Some(
            &second
                .reentry_frame
                .as_ref()
                .expect("second frame")
                .retained_prefix_digest
        )
    );

    let terminal = &set.terminal_reflection_envelope;
    assert_eq!(terminal.phase, IterativeProviderPhase::ReflectTerminal);
    assert_eq!(
        terminal.transport_kind,
        AttentionTransportKind::CompactReentry
    );
    assert!(terminal.iteration_index.is_none());
    assert!(terminal.reentry_frame.is_some());
    assert!(terminal.reentry_frame_digest.is_some());
    assert!(terminal.local_integrity_only);
    assert!(!terminal.producer_authentication_claimed);

    for (envelope, transport) in set
        .iteration_envelopes
        .iter()
        .zip(&set.source_projection.iteration_transports)
    {
        validate_attention_transport_envelope(envelope).expect("local integrity");
        validate_iteration_transport_envelope_against(envelope, transport)
            .expect("canonical reconstruction");
    }
}

#[test]
fn envelope_set_is_deterministic_strict_and_normalized() {
    let first = generate_scripted_transport_envelope_set().expect("first");
    let second = generate_scripted_transport_envelope_set().expect("second");
    assert_eq!(first, second);
    let bytes = pretty_scripted_transport_envelope_set_bytes(&first).expect("pretty bytes");
    assert_eq!(bytes.last(), Some(&b'\n'));
    let decoded: ScriptedTransportEnvelopeSet =
        serde_json::from_slice(&bytes).expect("strict JSON");
    assert_eq!(decoded, first);

    let mut unknown = serde_json::to_value(&first).expect("value");
    unknown["authenticated"] = Value::Bool(false);
    assert!(serde_json::from_value::<ScriptedTransportEnvelopeSet>(unknown).is_err());

    let mut unknown_envelope =
        serde_json::to_value(&first.iteration_envelopes[0]).expect("envelope value");
    unknown_envelope["canonical"] = Value::Bool(false);
    assert!(serde_json::from_value::<AttentionTransportEnvelope>(unknown_envelope).is_err());
}

#[test]
fn local_integrity_mutations_fail_closed() {
    let set = generate_scripted_transport_envelope_set().expect("set");

    let mut request = set.iteration_envelopes[0].clone();
    request.actual_request["temperature"] = json!(1);
    assert!(validate_attention_transport_envelope(&request).is_err());

    let mut request_digest = set.iteration_envelopes[0].clone();
    request_digest.request_digest.algorithm = "crc32".to_owned();
    assert!(validate_attention_transport_envelope(&request_digest).is_err());

    let mut full_frame = set.iteration_envelopes[0].clone();
    full_frame.reentry_frame = set.iteration_envelopes[1].reentry_frame.clone();
    assert!(validate_attention_transport_envelope(&full_frame).is_err());

    let compact = &set.iteration_envelopes[1];
    let mut frame = compact.clone();
    frame.reentry_frame.as_mut().expect("frame").iteration_count += 1;
    assert!(validate_attention_transport_envelope(&frame).is_err());

    let mut frame_digest = compact.clone();
    frame_digest
        .reentry_frame_digest
        .as_mut()
        .expect("digest")
        .value
        .push('0');
    assert!(validate_attention_transport_envelope(&frame_digest).is_err());

    let mut retained = compact.clone();
    retained
        .retained_prefix_digest
        .as_mut()
        .expect("retained digest")
        .value
        .push('0');
    assert!(validate_attention_transport_envelope(&retained).is_err());

    let mut no_index = compact.clone();
    no_index.iteration_index = None;
    assert!(validate_attention_transport_envelope(&no_index).is_err());

    let mut wrong_phase = compact.clone();
    wrong_phase.phase = IterativeProviderPhase::ReflectTerminal;
    assert!(validate_attention_transport_envelope(&wrong_phase).is_err());

    let mut terminal_index = set.terminal_reflection_envelope.clone();
    terminal_index.iteration_index = Some(2);
    assert!(validate_attention_transport_envelope(&terminal_index).is_err());

    let mut claim = compact.clone();
    claim.producer_authentication_claimed = true;
    assert!(validate_attention_transport_envelope(&claim).is_err());

    let mut scope = compact.clone();
    scope.local_integrity_only = false;
    assert!(validate_attention_transport_envelope(&scope).is_err());

    let mut nonclaim = compact.clone();
    nonclaim.nonclaims.pop();
    assert!(validate_attention_transport_envelope(&nonclaim).is_err());
}

#[test]
fn locally_coherent_substitutions_still_fail_canonical_binding() {
    let set = generate_scripted_transport_envelope_set().expect("set");
    let canonical_transport = &set.source_projection.iteration_transports[1];
    let mut substituted_transport = canonical_transport.clone();
    substituted_transport.actual_request["temperature"] = json!(1);
    let substituted =
        compile_iteration_transport_envelope(&substituted_transport).expect("coherent substitute");
    validate_attention_transport_envelope(&substituted).expect("local substitute integrity");
    assert!(
        validate_iteration_transport_envelope_against(&substituted, canonical_transport).is_err()
    );

    let mut substituted_set = set.clone();
    substituted_set.iteration_envelopes[1] = substituted;
    assert!(validate_scripted_transport_envelope_set(&substituted_set).is_err());

    let mut reordered = set.clone();
    reordered.iteration_envelopes.swap(0, 1);
    assert!(validate_scripted_transport_envelope_set(&reordered).is_err());

    let mut source = set.clone();
    source.source_projection.iteration_transports[1].actual_request["temperature"] = json!(1);
    assert!(validate_scripted_transport_envelope_set(&source).is_err());

    let mut claim = set;
    claim.producer_authentication_claimed = true;
    assert!(validate_scripted_transport_envelope_set(&claim).is_err());
}
