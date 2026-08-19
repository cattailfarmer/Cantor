use cantor_compact_reflection_loop::{
    AttentionHeadKind, AttentionReentryFrame, IterativeProviderPhase,
    compact_iterative_advance_request, compact_terminal_reflection_request,
    compile_attention_reentry_frame, generate_attention_reentry_measurement,
    generate_scripted_terminal_pending_fixture, pretty_attention_reentry_measurement_bytes,
    validate_attention_reentry_frame, validate_attention_reentry_measurement,
    validate_compact_attention_request,
};
use serde_json::{Value, json};

const ARTIFACT: &[u8] = include_bytes!(
    "../../../experiments/iterative_attention_procedure_loop_p1/artifacts/attention_reentry_measurement_v1.json"
);

#[test]
fn ready_and_terminal_frames_preserve_structural_request_surfaces() {
    let pending = generate_scripted_terminal_pending_fixture().expect("pending fixture");
    let ready_prefix = &pending.report.iterations[..1];
    let ready = compile_attention_reentry_frame(
        &pending.report.model,
        &pending.prompt,
        &pending.report.policy,
        &pending.report.opening_handle,
        ready_prefix,
    )
    .expect("READY frame");
    assert_eq!(ready.phase, IterativeProviderPhase::Advance);
    assert_eq!(ready.head_kind, AttentionHeadKind::Ready);
    validate_attention_reentry_frame(
        &ready,
        &pending.report.model,
        &pending.prompt,
        &pending.report.policy,
        &pending.report.opening_handle,
        ready_prefix,
    )
    .expect("valid READY frame");
    let advance = compact_iterative_advance_request(
        &pending.report.model,
        &pending.prompt,
        &pending.report.policy,
        &pending.report.opening_handle,
        ready_prefix,
    )
    .expect("compact advance");
    validate_compact_attention_request(
        &advance,
        &pending.report.model,
        &pending.prompt,
        &pending.report.policy,
        &pending.report.opening_handle,
        ready_prefix,
    )
    .expect("valid compact advance");

    let terminal = compile_attention_reentry_frame(
        &pending.report.model,
        &pending.prompt,
        &pending.report.policy,
        &pending.report.opening_handle,
        &pending.report.iterations,
    )
    .expect("terminal frame");
    assert_eq!(terminal.phase, IterativeProviderPhase::ReflectTerminal);
    assert_eq!(terminal.head_kind, AttentionHeadKind::Terminal);
    let reflection = compact_terminal_reflection_request(
        &pending.report.model,
        &pending.prompt,
        &pending.report.policy,
        &pending.report.opening_handle,
        &pending.report.iterations,
    )
    .expect("compact reflection");
    validate_compact_attention_request(
        &reflection,
        &pending.report.model,
        &pending.prompt,
        &pending.report.policy,
        &pending.report.opening_handle,
        &pending.report.iterations,
    )
    .expect("valid compact reflection");
    assert_eq!(reflection["tool_choice"], "none");
    assert_eq!(advance["tool_choice"], "required");
}

#[test]
fn empty_cross_phase_and_mutated_frames_fail_closed() {
    let pending = generate_scripted_terminal_pending_fixture().expect("pending fixture");
    assert!(
        compile_attention_reentry_frame(
            &pending.report.model,
            &pending.prompt,
            &pending.report.policy,
            &pending.report.opening_handle,
            &[]
        )
        .is_err()
    );
    assert!(
        compact_iterative_advance_request(
            &pending.report.model,
            &pending.prompt,
            &pending.report.policy,
            &pending.report.opening_handle,
            &pending.report.iterations,
        )
        .is_err()
    );
    assert!(
        compact_terminal_reflection_request(
            &pending.report.model,
            &pending.prompt,
            &pending.report.policy,
            &pending.report.opening_handle,
            &pending.report.iterations[..1],
        )
        .is_err()
    );

    let frame = compile_attention_reentry_frame(
        &pending.report.model,
        &pending.prompt,
        &pending.report.policy,
        &pending.report.opening_handle,
        &pending.report.iterations,
    )
    .expect("frame");
    let encoded = serde_json::to_value(&frame).expect("frame JSON");
    let decoded: AttentionReentryFrame =
        serde_json::from_value(encoded.clone()).expect("closed round trip");
    assert_eq!(decoded, frame);
    let mut unknown = encoded;
    unknown["semantic_summary"] = Value::String("invented".to_owned());
    assert!(serde_json::from_value::<AttentionReentryFrame>(unknown).is_err());

    let mut digest = frame.clone();
    let replacement = if digest.retained_prefix_digest.value.starts_with('0') {
        "1"
    } else {
        "0"
    };
    digest
        .retained_prefix_digest
        .value
        .replace_range(0..1, replacement);
    assert!(
        validate_attention_reentry_frame(
            &digest,
            &pending.report.model,
            &pending.prompt,
            &pending.report.policy,
            &pending.report.opening_handle,
            &pending.report.iterations,
        )
        .is_err()
    );
    assert!(
        validate_attention_reentry_frame(
            &frame,
            &pending.report.model,
            "changed prompt",
            &pending.report.policy,
            &pending.report.opening_handle,
            &pending.report.iterations,
        )
        .is_err()
    );
    let mut changed_policy = pending.report.policy.clone();
    changed_policy.maximum_steps_per_call += 1;
    assert!(
        validate_attention_reentry_frame(
            &frame,
            &pending.report.model,
            &pending.prompt,
            &changed_policy,
            &pending.report.opening_handle,
            &pending.report.iterations,
        )
        .is_err()
    );
    let mut changed_prefix = pending.report.iterations.clone();
    changed_prefix[0].call_id.push_str("-changed");
    assert!(
        validate_attention_reentry_frame(
            &frame,
            &pending.report.model,
            &pending.prompt,
            &pending.report.policy,
            &pending.report.opening_handle,
            &changed_prefix,
        )
        .is_err()
    );
    let request = compact_terminal_reflection_request(
        &pending.report.model,
        &pending.prompt,
        &pending.report.policy,
        &pending.report.opening_handle,
        &pending.report.iterations,
    )
    .expect("request");
    let mut schema = request;
    schema["response_format"]["schema"]["additionalProperties"] = json!(true);
    assert!(
        validate_compact_attention_request(
            &schema,
            &pending.report.model,
            &pending.prompt,
            &pending.report.policy,
            &pending.report.opening_handle,
            &pending.report.iterations,
        )
        .is_err()
    );
}

#[test]
fn quota_one_measurement_is_deterministic_bounded_and_strict() {
    let first = generate_attention_reentry_measurement().expect("first measurement");
    let second = generate_attention_reentry_measurement().expect("second measurement");
    assert_eq!(first, second);
    validate_attention_reentry_measurement(&first).expect("valid measurement");
    assert!(first.frames.len() > 3);
    assert_eq!(first.terminal_frame_count, 1);
    assert_eq!(first.ready_frame_count + 1, first.frames.len());
    assert!(first.full_request_growth_bytes > first.compact_request_growth_bytes);
    assert!(first.total_full_minus_compact_bytes > 0);
    assert!(!first.semantic_equivalence_claimed);
    assert!(!first.provider_compatibility_claimed);

    let mut phase = first.clone();
    phase.frames[0].phase = IterativeProviderPhase::ReflectTerminal;
    assert!(validate_attention_reentry_measurement(&phase).is_err());
    let mut difference = first.clone();
    difference.frames[0].full_minus_compact_bytes += 1;
    assert!(validate_attention_reentry_measurement(&difference).is_err());
    let mut claim = first.clone();
    claim.semantic_equivalence_claimed = true;
    assert!(validate_attention_reentry_measurement(&claim).is_err());

    let bytes = pretty_attention_reentry_measurement_bytes(&first).expect("pretty measurement");
    let artifact = serde_json::from_slice(ARTIFACT).expect("artifact JSON");
    validate_attention_reentry_measurement(&artifact).expect("valid artifact");
    assert_eq!(artifact, first);
    assert_eq!(bytes, ARTIFACT);
}
