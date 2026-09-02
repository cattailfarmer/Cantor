use std::collections::BTreeSet;

use cantor_core::{
    ContentDigest, SJS_LAS_CANONICAL_UUID, SemanticId, SjsLasBoundaryKind, SjsLasEffectAccount,
    SjsLasLifecycleState,
};
use cantor_ecosystem::sjs_compiled_lookahead_repository_slice_observation::{
    from_sjs_rso_receipt_machine_form, from_sjs_rso_request_machine_form,
    from_sjs_rso_verification_machine_form,
};
use cantor_ecosystem::sjs_compiled_lookahead_repository_stitch_projection::{
    SJS_RSP_CANONICAL_UUID, SJS_RSP_NON_AUTHORITY, SJS_RSP_REQUEST_PROFILE,
    SJS_RSP_RSO_BOOKEND_COMMIT, SJS_RSP_RSO_CLOSURE_COMMIT, SJS_RSP_RSO_COMPLETION_UUID,
    SJS_RSP_RSO_IMPLEMENTATION_COMMIT, SJS_RSP_SIGNATURE_UUID, SJS_RSP_SOURCE_UUID,
    SJS_RSP_STITCH_COMPLETION_UUID, SjsRspFaultCode, SjsRspInputClass, SjsRspRequest,
    build_sjs_rsp_evidence_bundle, compile_sjs_rsp, from_sjs_rsp_envelope_machine_form,
    from_sjs_rsp_evidence_bundle_machine_form, from_sjs_rsp_request_machine_form,
    from_sjs_rsp_verification_machine_form, seal_sjs_rsp_request, synthetic_sjs_rsp_request,
    to_sjs_rsp_envelope_machine_form, to_sjs_rsp_evidence_bundle_machine_form,
    to_sjs_rsp_request_machine_form, to_sjs_rsp_verification_machine_form,
    validate_sjs_rsp_envelope, verify_sjs_rsp, verify_sjs_rsp_evidence_bundle,
};

const RSO_REQUEST: &str = include_str!(
    "../../../experiments/sjs_compiled_lookahead_repository_slice_observation_p0/artifacts/request.json"
);
const RSO_RECEIPT: &str = include_str!(
    "../../../experiments/sjs_compiled_lookahead_repository_slice_observation_p0/artifacts/receipt.json"
);
const RSO_VERIFICATION: &str = include_str!(
    "../../../experiments/sjs_compiled_lookahead_repository_slice_observation_p0/artifacts/verification.json"
);

type RequestMutator = Box<dyn Fn(&mut SjsRspRequest)>;

fn semantic_id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixed semantic identity")
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn tamper_digest(digest: &mut ContentDigest) {
    let replacement = if digest.value.starts_with('0') {
        "1"
    } else {
        "0"
    };
    digest.value.replace_range(0..1, replacement);
}

fn body(value: &'static str) -> &'static str {
    value
        .strip_suffix('\n')
        .expect("retained evidence has one terminal LF")
}

fn fixture_request_unsealed() -> SjsRspRequest {
    let upstream_request =
        from_sjs_rso_request_machine_form(body(RSO_REQUEST)).expect("published RSO request");
    let upstream_receipt = from_sjs_rso_receipt_machine_form(&upstream_request, body(RSO_RECEIPT))
        .expect("published RSO receipt");
    let upstream_verification = from_sjs_rso_verification_machine_form(
        &upstream_request,
        &upstream_receipt,
        body(RSO_VERIFICATION),
    )
    .expect("published RSO verification");
    SjsRspRequest {
        profile: SJS_RSP_REQUEST_PROFILE.to_owned(),
        request_id: semantic_id("request:86000000-0000-4000-8000-000000000001"),
        run_id: semantic_id("run:86000000-0000-4000-8000-000000000002"),
        receipt_id: semantic_id("receipt:86000000-0000-4000-8000-000000000003"),
        downstream_request_id: semantic_id("request:86000000-0000-4000-8000-000000000004"),
        downstream_run_id: semantic_id("run:86000000-0000-4000-8000-000000000005"),
        downstream_packet_id: semantic_id("packet:86000000-0000-4000-8000-000000000006"),
        downstream_policy_id: semantic_id("policy:86000000-0000-4000-8000-000000000007"),
        input_class: SjsRspInputClass::SyntheticProviderFreeFixture,
        canonical_uuid: SJS_RSP_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_RSP_SIGNATURE_UUID.to_owned(),
        source_snapshot_uuid: SJS_RSP_SOURCE_UUID.to_owned(),
        parent_observation_canonical_uuid:
            cantor_ecosystem::sjs_compiled_lookahead_repository_slice_observation::SJS_RSO_CANONICAL_UUID
                .to_owned(),
        parent_observation_completion_signature_uuid: SJS_RSP_RSO_COMPLETION_UUID.to_owned(),
        parent_observation_implementation_commit: SJS_RSP_RSO_IMPLEMENTATION_COMMIT.to_owned(),
        parent_observation_bookend_commit: SJS_RSP_RSO_BOOKEND_COMMIT.to_owned(),
        parent_observation_closure_commit: SJS_RSP_RSO_CLOSURE_COMMIT.to_owned(),
        stitch_canonical_uuid: SJS_LAS_CANONICAL_UUID.to_owned(),
        stitch_completion_signature_uuid: SJS_RSP_STITCH_COMPLETION_UUID.to_owned(),
        upstream_request,
        upstream_receipt,
        upstream_verification,
        provider_profile: "fixture-provider-declaration/0.1".to_owned(),
        invocation_ordinal: 1,
        boundary_kind: SjsLasBoundaryKind::Initial,
        evidence_refs: [semantic_id("evidence:86000000-0000-4000-8000-000000000008")]
            .into_iter()
            .collect(),
        non_authority: SJS_RSP_NON_AUTHORITY.to_owned(),
        request_digest: empty_digest(),
    }
}

fn fixture_request() -> SjsRspRequest {
    let local =
        seal_sjs_rsp_request(fixture_request_unsealed()).expect("sealed projection request");
    let public = synthetic_sjs_rsp_request().expect("public synthetic projection request");
    assert_eq!(public, local);
    public
}

fn correspondence_consistent_selected_nine_request_unsealed() -> SjsRspRequest {
    let mut request = fixture_request_unsealed();
    let template = request
        .upstream_receipt
        .parent_envelope
        .downstream_envelope
        .selected_candidates
        .last()
        .expect("selected fixture candidate")
        .clone();
    for ordinal in 4..=9 {
        let mut candidate = template.clone();
        candidate.candidate_id =
            semantic_id(&format!("candidate:83000000-0000-4000-8001-{ordinal:012}"));
        request
            .upstream_receipt
            .parent_envelope
            .downstream_envelope
            .selected_candidates
            .push(candidate);
    }
    let selected_ids = request
        .upstream_receipt
        .parent_envelope
        .downstream_envelope
        .selected_candidates
        .iter()
        .map(|candidate| candidate.candidate_id.clone())
        .collect::<Vec<_>>();
    let parent = &mut request.upstream_receipt.parent_envelope;
    parent.downstream_envelope.receipt.selected_candidate_ids = selected_ids;
    parent
        .downstream_envelope
        .receipt
        .budget_account
        .selected_count = 9;
    parent
        .downstream_envelope
        .receipt
        .objective_account
        .selected_count = 9;
    parent.downstream_verification.selected_count = 9;
    parent.receipt.downstream_selected_count = 9;
    request.upstream_receipt.parent_verification.selected_count = 9;
    request
        .upstream_verification
        .parent_verification
        .selected_count = 9;
    request
}

#[test]
fn correspondence_consistent_selected_nine_refuses_at_rsp_bound_before_compilation() {
    let error = seal_sjs_rsp_request(correspondence_consistent_selected_nine_request_unsealed())
        .expect_err("nine selected candidates must refuse");
    assert_eq!(error.code, SjsRspFaultCode::InvalidBound);
    assert_eq!(
        error.detail,
        "selected candidate count exceeds one-through-eight bound"
    );
}

#[test]
fn published_rso_fixture_projects_exact_selected_candidates_to_active_stitches() {
    let request = fixture_request();
    let envelope = compile_sjs_rsp(&request).expect("pure projection");
    let verification = verify_sjs_rsp(&envelope).expect("independent projection verification");

    assert_eq!(
        verification.status,
        "verified_repository_selection_projected_to_stitch_only"
    );
    assert_eq!(verification.selected_count, 3);
    assert_eq!(verification.stitch_count, 3);
    assert_eq!(verification.hint_count, 3);
    assert_eq!(verification.source_binding_count, 3);
    assert_eq!(verification.observation_count, 3);
    assert_eq!(verification.coordinate_count, 1);
    assert_eq!(verification.projection_count, 1);
    assert_eq!(verification.projected_inclusion_count, 3);
    assert_eq!(verification.physical_input_account_count, 8);
    assert!(verification.historical_physical_contact);
    assert!(!verification.execution_authorized);
    assert_eq!(verification.effects, SjsLasEffectAccount::default());
    assert_eq!(
        envelope.downstream_envelope.effects,
        SjsLasEffectAccount::default()
    );
    assert!(
        envelope
            .downstream_envelope
            .final_states
            .iter()
            .all(|state| state.state == SjsLasLifecycleState::Active)
    );

    let selected = &request
        .upstream_receipt
        .parent_envelope
        .downstream_envelope
        .selected_candidates;
    let selected_ids = selected
        .iter()
        .map(|candidate| candidate.candidate_id.as_str().rsplit(':').next().unwrap())
        .collect::<BTreeSet<_>>();
    let stitch_ids = envelope
        .downstream_request
        .stitches
        .iter()
        .map(|stitch| stitch.stitch_id.as_str().rsplit(':').next().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(selected_ids, stitch_ids);
    for stitch in &envelope.downstream_request.stitches {
        let candidate = selected
            .iter()
            .find(|candidate| {
                candidate.candidate_id.as_str().rsplit(':').next()
                    == stitch.stitch_id.as_str().rsplit(':').next()
            })
            .expect("selected source candidate");
        assert_eq!(stitch.subject_anchor, candidate.subject_anchor);
        assert_eq!(stitch.semantic_turn, candidate.semantic_turn);
        assert_eq!(stitch.transform, candidate.transform);
        assert_eq!(stitch.scope_id, candidate.scope_id);
        assert_eq!(
            stitch.key_hints.as_slice(),
            std::slice::from_ref(&candidate.projected_surface)
        );
        assert_eq!(
            stitch.source_bindings.as_slice(),
            std::slice::from_ref(&candidate.source_binding)
        );
        assert_eq!(stitch.completion_cue, candidate.completion_cue);
        assert_eq!(stitch.invalidators, candidate.invalidators);
        assert!(stitch.predecessor_id.is_none());
    }
    assert_eq!(
        envelope.downstream_envelope.projection_records[0].active_stitch_ids,
        envelope
            .downstream_request
            .stitches
            .iter()
            .map(|stitch| stitch.stitch_id.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn request_envelope_verification_and_evidence_round_trip_canonically() {
    let request = fixture_request();
    let envelope = compile_sjs_rsp(&request).expect("projection");
    let verification = verify_sjs_rsp(&envelope).expect("verification");
    let replay_envelope = compile_sjs_rsp(&request).expect("replay projection");
    let replay_verification = verify_sjs_rsp(&replay_envelope).expect("replay verification");

    let request_form = to_sjs_rsp_request_machine_form(&request).expect("request form");
    assert_eq!(
        from_sjs_rsp_request_machine_form(&request_form).expect("request parse"),
        request
    );
    let envelope_form = to_sjs_rsp_envelope_machine_form(&envelope).expect("envelope form");
    assert_eq!(
        from_sjs_rsp_envelope_machine_form(&envelope_form).expect("envelope parse"),
        envelope
    );
    let verification_form =
        to_sjs_rsp_verification_machine_form(&envelope, &verification).expect("verification form");
    assert_eq!(
        from_sjs_rsp_verification_machine_form(&envelope, &verification_form)
            .expect("verification parse"),
        verification
    );

    let bundle = build_sjs_rsp_evidence_bundle(
        &request,
        &envelope,
        &verification,
        &replay_envelope,
        &replay_verification,
    )
    .expect("evidence bundle");
    assert!(bundle.request_file.ends_with('\n'));
    assert!(bundle.envelope_file.ends_with('\n'));
    assert!(bundle.verification_file.ends_with('\n'));
    assert!(bundle.manifest_file.ends_with('\n'));
    assert_eq!(
        verify_sjs_rsp_evidence_bundle(&bundle).expect("independent evidence replay"),
        verification
    );
    let carrier = to_sjs_rsp_evidence_bundle_machine_form(&bundle).expect("bundle carrier");
    assert_eq!(
        from_sjs_rsp_evidence_bundle_machine_form(&carrier).expect("bundle parse"),
        bundle
    );
}

#[test]
fn upstream_request_receipt_verification_and_physical_truth_tamper_refuse() {
    let cases: Vec<RequestMutator> = vec![
        Box::new(|request| {
            request
                .upstream_request
                .expected_head
                .replace_range(0..1, "f")
        }),
        Box::new(|request| request.upstream_receipt.accounts[0].raw_bytes += 1),
        Box::new(|request| request.upstream_receipt.physical_contact = false),
        Box::new(|request| request.upstream_receipt.effects.provider_contact = true),
        Box::new(|request| request.upstream_verification.account_count += 1),
        Box::new(|request| request.upstream_verification.execution_authorized = true),
        Box::new(|request| {
            request
                .upstream_receipt
                .parent_envelope
                .receipt
                .downstream_selected_count -= 1
        }),
        Box::new(|request| {
            request
                .upstream_receipt
                .parent_envelope
                .downstream_envelope
                .selected_candidates[0]
                .projected_surface
                .push_str(" tamper")
        }),
    ];
    for mutate in cases {
        let mut request = fixture_request_unsealed();
        mutate(&mut request);
        let error = seal_sjs_rsp_request(request).expect_err("upstream tamper must refuse");
        assert!(matches!(
            error.code,
            SjsRspFaultCode::InvalidUpstream | SjsRspFaultCode::InvalidMapping
        ));
    }
}

#[test]
fn projection_identity_provider_ordinal_boundary_and_authority_tamper_refuse() {
    let cases: Vec<RequestMutator> = vec![
        Box::new(|request| {
            request.downstream_run_id = semantic_id("run:86000000-0000-4000-8000-000000000002")
        }),
        Box::new(|request| request.provider_profile.clear()),
        Box::new(|request| request.invocation_ordinal = 0),
        Box::new(|request| request.boundary_kind = SjsLasBoundaryKind::Reentry),
        Box::new(|request| request.evidence_refs.clear()),
        Box::new(|request| {
            request
                .parent_observation_closure_commit
                .replace_range(0..1, "f")
        }),
        Box::new(|request| request.non_authority.push_str(" widened")),
        Box::new(|request| request.input_class = SjsRspInputClass::VerifiedRepositorySelection),
    ];
    for mutate in cases {
        let mut request = fixture_request_unsealed();
        mutate(&mut request);
        assert!(seal_sjs_rsp_request(request).is_err());
    }
}

#[test]
fn downstream_field_digest_authority_count_and_effect_tamper_refuse() {
    let request = fixture_request();
    let original = compile_sjs_rsp(&request).expect("projection");
    type Mutator = Box<
        dyn Fn(
            &mut cantor_ecosystem::sjs_compiled_lookahead_repository_stitch_projection::SjsRspEnvelope,
        ),
    >;
    let cases: Vec<(&str, Mutator)> = vec![
        (
            "downstream request field",
            Box::new(|envelope| {
                envelope.downstream_request.stitches[0]
                    .subject_anchor
                    .push_str(" drift")
            }),
        ),
        (
            "downstream packet field",
            Box::new(|envelope| {
                envelope.downstream_envelope.packet.stitch_declarations[0].key_hints[0]
                    .push_str(" drift")
            }),
        ),
        (
            "downstream execution authority",
            Box::new(|envelope| envelope.downstream_envelope.execution_authorized = true),
        ),
        (
            "downstream effect",
            Box::new(|envelope| envelope.downstream_envelope.effects.provider_effect_count = 1),
        ),
        (
            "receipt count",
            Box::new(|envelope| envelope.receipt.selected_count += 1),
        ),
        (
            "receipt downstream verification digest",
            Box::new(|envelope| {
                tamper_digest(&mut envelope.receipt.downstream_verification_digest)
            }),
        ),
        (
            "envelope digest",
            Box::new(|envelope| tamper_digest(&mut envelope.envelope_digest)),
        ),
    ];
    for (label, mutate) in cases {
        let mut envelope = original.clone();
        mutate(&mut envelope);
        assert!(
            validate_sjs_rsp_envelope(&envelope).is_err(),
            "accepted {label} tamper"
        );
    }
}

#[test]
fn strict_machine_forms_refuse_unknown_duplicate_noncanonical_trailing_and_oversized() {
    let request = fixture_request();
    let form = to_sjs_rsp_request_machine_form(&request).expect("request form");

    let unknown = form.replacen("{\"profile\"", "{\"unknown\":true,\"profile\"", 1);
    assert!(from_sjs_rsp_request_machine_form(&unknown).is_err());
    let duplicate = form.replacen(
        "{\"profile\":",
        "{\"profile\":\"duplicate\",\"profile\":",
        1,
    );
    assert!(from_sjs_rsp_request_machine_form(&duplicate).is_err());
    assert!(from_sjs_rsp_request_machine_form(&format!("{form}x")).is_err());
    assert!(from_sjs_rsp_request_machine_form(&format!(" {form}")).is_err());
    assert!(from_sjs_rsp_request_machine_form(&"x".repeat(1_048_577)).is_err());

    let deep = format!("{}0{}", "[".repeat(41), "]".repeat(41));
    let error = from_sjs_rsp_request_machine_form(&deep).expect_err("depth must refuse");
    assert_eq!(error.code, SjsRspFaultCode::InvalidMachineForm);
}

#[test]
fn retained_raw_byte_manifest_and_lf_substitution_refuse() {
    let request = fixture_request();
    let envelope = compile_sjs_rsp(&request).expect("projection");
    let verification = verify_sjs_rsp(&envelope).expect("verification");
    let bundle =
        build_sjs_rsp_evidence_bundle(&request, &envelope, &verification, &envelope, &verification)
            .expect("bundle");

    let mut request_tamper = bundle.clone();
    request_tamper.request_file = request_tamper.request_file.replacen(
        "fixture-provider-declaration",
        "fixture-provider-declaratioN",
        1,
    );
    assert!(verify_sjs_rsp_evidence_bundle(&request_tamper).is_err());

    let mut envelope_tamper = bundle.clone();
    envelope_tamper.envelope_file =
        envelope_tamper
            .envelope_file
            .replacen("projected_surface", "projected_surfacE", 1);
    assert!(verify_sjs_rsp_evidence_bundle(&envelope_tamper).is_err());

    let mut manifest_tamper = bundle.clone();
    manifest_tamper.manifest_file =
        manifest_tamper
            .manifest_file
            .replacen("\"replay_count\":2", "\"replay_count\":1", 1);
    assert!(verify_sjs_rsp_evidence_bundle(&manifest_tamper).is_err());

    let mut lf_tamper = bundle.clone();
    lf_tamper.verification_file.pop();
    assert!(verify_sjs_rsp_evidence_bundle(&lf_tamper).is_err());

    let carrier = to_sjs_rsp_evidence_bundle_machine_form(&bundle).expect("carrier");
    assert!(from_sjs_rsp_evidence_bundle_machine_form(&format!(" {carrier}")).is_err());
    let duplicate = carrier.replacen(
        "{\"request_file\":",
        "{\"request_file\":\"duplicate\",\"request_file\":",
        1,
    );
    assert!(from_sjs_rsp_evidence_bundle_machine_form(&duplicate).is_err());
}
