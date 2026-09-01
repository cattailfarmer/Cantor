use std::collections::BTreeMap;

use cantor_core::{
    SemanticId, SjsLasBoundaryKind, SjsLasEvidenceBundle, SjsLasFaultCode, SjsLasInputClass,
    SjsLasInvocationCoordinate, SjsLasLifecycleState, SjsLasObservation, SjsLasObservationKind,
    SjsLasSourceBindingClass, compile_sjs_las, seal_sjs_las_request, synthetic_sjs_las_request,
    verify_sjs_las, verify_sjs_las_evidence_bundle,
};

const LEGACY_REQUEST: &str =
    include_str!("../../../experiments/sjs_compiled_lookahead_stitch_p0/artifacts/request.json");
const LEGACY_ENVELOPE: &str =
    include_str!("../../../experiments/sjs_compiled_lookahead_stitch_p0/artifacts/envelope.json");
const LEGACY_VERIFICATION: &str = include_str!(
    "../../../experiments/sjs_compiled_lookahead_stitch_p0/artifacts/verification.json"
);
const LEGACY_MANIFEST: &str = include_str!(
    "../../../experiments/sjs_compiled_lookahead_stitch_p0/artifacts/evidence_manifest.json"
);

fn identity(prefix: &str, ordinal: usize) -> SemanticId {
    SemanticId::new(format!("{prefix}:87000000-0000-4000-8000-{ordinal:012}"))
        .expect("capacity identity")
}

fn capacity_request(count: usize, wide: bool) -> cantor_core::SjsLasRequest {
    let mut request = synthetic_sjs_las_request().expect("published seed");
    request.input_class = SjsLasInputClass::SuppliedUnobservedDeclaration;
    request.request_id = identity("request", 901);
    request.run_id = identity("run", 902);
    request.packet_id = identity("packet", 903);
    request.policy_id = identity("policy", 904);
    request.scope.invocation_start = 1;
    request.scope.invocation_end = 1;

    let template = request.stitches[0].clone();
    let mut source = template.source_bindings[0].clone();
    source.class = SjsLasSourceBindingClass::PlanHint;
    source.locator = "l".to_owned();
    source.authority_identity = None;
    request.stitches = (1..=count)
        .map(|ordinal| {
            let mut stitch = template.clone();
            stitch.stitch_id = identity("stitch", ordinal);
            stitch.predecessor_id = None;
            stitch.subject_anchor = "s".to_owned();
            stitch.semantic_turn.description = "t".to_owned();
            stitch.transform = if wide {
                "x".repeat(1_000)
            } else {
                "x".to_owned()
            };
            stitch.key_hints = vec!["h".to_owned()];
            stitch.source_bindings = vec![source.clone()];
            stitch.completion_cue.field = "c".to_owned();
            stitch.completion_cue.equals = "d".to_owned();
            stitch.invalidators.truncate(1);
            stitch.invalidators[0].field = "i".to_owned();
            stitch.invalidators[0].equals = "j".to_owned();
            stitch
        })
        .collect();
    request.observations = (1..=count)
        .map(|ordinal| SjsLasObservation {
            observation_id: identity("observation", ordinal),
            ordinal: u32::try_from(ordinal).expect("bounded ordinal"),
            kind: SjsLasObservationKind::Activate,
            stitch_id: Some(identity("stitch", ordinal)),
            fields: BTreeMap::new(),
        })
        .collect();
    request.coordinates = vec![SjsLasInvocationCoordinate {
        coordinate_id: identity("coordinate", 905),
        ordinal: 1,
        after_observation_ordinal: u32::try_from(count).expect("bounded count"),
        invocation_ordinal: 1,
        phase: request.scope.phase.clone(),
        objective: request.scope.objective.clone(),
        feature: request.scope.feature.clone(),
        requirement: request.scope.requirement.clone(),
        artifact: request.scope.artifact.clone(),
        model_profile: request.scope.model_profile.clone(),
        provider_profile: request.scope.provider_profile.clone(),
        tool_policy: request.scope.tool_policy.clone(),
        authority_ceiling: request.scope.authority_ceiling.clone(),
        boundary_kind: SjsLasBoundaryKind::Initial,
        last_accepted_receipt_id: Some(identity("receipt", count)),
    }];
    seal_sjs_las_request(request).expect("capacity request seals")
}

#[test]
fn three_stitches_compile_as_one_active_projection() {
    let request = capacity_request(3, false);
    let envelope = compile_sjs_las(&request).expect("three-stitch compile");
    let verification = verify_sjs_las(&envelope).expect("three-stitch verify");
    assert_eq!(verification.stitch_count, 3);
    assert_eq!(verification.activation_count, 3);
    assert_eq!(verification.projection_count, 1);
    assert_eq!(verification.projected_inclusion_count, 3);
    assert_eq!(verification.maximum_projected_bytes, 1_809);
    assert!(
        envelope
            .final_states
            .iter()
            .all(|state| state.state == SjsLasLifecycleState::Active)
    );
    assert!(!verification.execution_authorized);
    assert_eq!(verification.effects, Default::default());
}

#[test]
fn eight_minimal_stitches_compile_within_existing_projection_bound() {
    let request = capacity_request(8, false);
    let envelope = compile_sjs_las(&request).expect("eight-stitch compile");
    let verification = verify_sjs_las(&envelope).expect("eight-stitch verify");
    assert_eq!(verification.stitch_count, 8);
    assert_eq!(verification.projected_inclusion_count, 8);
    assert_eq!(verification.maximum_projected_bytes, 4_824);
    assert!(verification.maximum_projected_bytes <= 8_192);
}

#[test]
fn nine_stitches_refuse_at_request_validation() {
    let mut request = capacity_request(8, false);
    let mut ninth = request.stitches[0].clone();
    ninth.stitch_id = identity("stitch", 9);
    request.stitches.push(ninth);
    request.observations.push(SjsLasObservation {
        observation_id: identity("observation", 9),
        ordinal: 9,
        kind: SjsLasObservationKind::Activate,
        stitch_id: Some(identity("stitch", 9)),
        fields: BTreeMap::new(),
    });
    request.coordinates[0].after_observation_ordinal = 9;
    request.coordinates[0].last_accepted_receipt_id = Some(identity("receipt", 9));
    let error = seal_sjs_las_request(request).expect_err("nine must refuse");
    assert_eq!(error.code, SjsLasFaultCode::InvalidStitch);
}

#[test]
fn eight_wide_stitches_refuse_existing_8192_projection_bound() {
    let request = capacity_request(8, true);
    let error = compile_sjs_las(&request).expect_err("wide projection must refuse");
    assert_eq!(error.code, SjsLasFaultCode::InvalidBound);
    assert!(error.detail.contains("8192"));
}

#[test]
fn published_two_stitch_evidence_replays_without_byte_regeneration() {
    let bundle = SjsLasEvidenceBundle {
        request_file: LEGACY_REQUEST.to_owned(),
        envelope_file: LEGACY_ENVELOPE.to_owned(),
        verification_file: LEGACY_VERIFICATION.to_owned(),
        manifest_file: LEGACY_MANIFEST.to_owned(),
    };
    let verification = verify_sjs_las_evidence_bundle(&bundle).expect("legacy evidence replay");
    assert_eq!(verification.stitch_count, 2);
    assert_eq!(verification.projected_inclusion_count, 5);
    assert!(!verification.execution_authorized);
    assert_eq!(verification.effects, Default::default());
}
