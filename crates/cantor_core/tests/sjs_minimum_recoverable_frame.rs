use std::collections::BTreeSet;

use cantor_core::{
    ContentDigest, SemanticId, SjsMrfCompilationDisposition, SjsMrfFaultCode, SjsMrfHint,
    SjsMrfHintClass, SjsMrfInputClass, SjsMrfRecoverySource, SjsMrfRecoverySourceKind,
    SjsMrfWitnessDisposition, build_sjs_mrf_evidence_bundle, compile_sjs_mrf,
    from_sjs_mrf_request_machine_form, seal_sjs_mrf_request, sjs_mrf_envelope_digest,
    synthetic_sjs_mrf_request, to_sjs_mrf_envelope_machine_form, to_sjs_mrf_request_machine_form,
    validate_sjs_mrf_envelope, verify_sjs_mrf, verify_sjs_mrf_evidence_bundle,
};

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("valid test identity")
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn supplied_request() -> cantor_core::SjsMrfRequest {
    let mut request = synthetic_sjs_mrf_request().expect("synthetic request");
    request.input_class = SjsMrfInputClass::SuppliedUnobservedDeclaration;
    request.request_id = id("request:82000000-0000-4000-8000-000000000001");
    request.run_id = id("run:82000000-0000-4000-8000-000000000002");
    seal_sjs_mrf_request(request).expect("supplied request")
}

#[test]
fn synthetic_fixture_compiles_to_exact_local_minimum() {
    let request = synthetic_sjs_mrf_request().expect("request");
    let envelope = compile_sjs_mrf(&request).expect("compile");
    let verification = verify_sjs_mrf(&envelope).expect("verify");
    assert_eq!(verification.job_count, 2);
    assert_eq!(verification.hint_count, 8);
    assert_eq!(verification.mandatory_hint_count, 3);
    assert_eq!(verification.recovery_source_count, 2);
    assert_eq!(verification.initial_basis_count, 8);
    assert_eq!(verification.final_basis_count, 4);
    assert_eq!(verification.admitted_release_count, 4);
    assert_eq!(verification.drift_refusal_count, 1);
    assert_eq!(verification.underdetermined_refusal_count, 1);
    assert_eq!(verification.attempt_count, 6);
    assert!(verification.locally_irreducible);
    assert!(!verification.pass_budget_exhausted);
    assert!(!verification.execution_authorized);
    assert_eq!(envelope.effects, Default::default());
    assert_eq!(
        envelope.disposition,
        SjsMrfCompilationDisposition::LocallyIrreducible
    );
    assert!(
        envelope.witnesses.iter().any(|witness| {
            witness.disposition == SjsMrfWitnessDisposition::ReleaseRefusedDrifted
        })
    );
    assert!(envelope.witnesses.iter().any(|witness| {
        witness.disposition == SjsMrfWitnessDisposition::ReleaseRefusedUnderdetermined
    }));
}

#[test]
fn compilation_and_machine_forms_are_byte_deterministic() {
    let request = synthetic_sjs_mrf_request().expect("request");
    let first = compile_sjs_mrf(&request).expect("first");
    let second = compile_sjs_mrf(&request).expect("second");
    assert_eq!(first, second);
    assert_eq!(
        to_sjs_mrf_envelope_machine_form(&first).expect("first form"),
        to_sjs_mrf_envelope_machine_form(&second).expect("second form")
    );
}

#[test]
fn evidence_bundle_independently_replays() {
    let request = synthetic_sjs_mrf_request().expect("request");
    let bundle = build_sjs_mrf_evidence_bundle(&request).expect("bundle");
    let verification = verify_sjs_mrf_evidence_bundle(&bundle).expect("bundle verify");
    assert_eq!(verification.attempt_count, 6);
    assert_eq!(verification.final_basis_count, 4);
}

#[test]
fn known_fixture_cannot_be_relabelled_as_supplied() {
    let mut request = synthetic_sjs_mrf_request().expect("request");
    request.input_class = SjsMrfInputClass::SuppliedUnobservedDeclaration;
    let fault = seal_sjs_mrf_request(request).expect_err("relabel must fail");
    assert_eq!(fault.code, SjsMrfFaultCode::InvalidInputClass);
}

#[test]
fn fully_redigested_synthetic_frontier_change_refuses() {
    let mut request = synthetic_sjs_mrf_request().expect("request");
    request.operative_frame.unresolved_frontier = ["live projection declared complete".to_owned()]
        .into_iter()
        .collect();
    request.recovery_sources[0].frame = request.operative_frame.clone();
    let fault = seal_sjs_mrf_request(request).expect_err("fixture change must fail");
    assert_eq!(fault.code, SjsMrfFaultCode::InvalidInputClass);
}

#[test]
fn mandatory_hint_omission_refuses() {
    let mut request = supplied_request();
    request.initial_basis.remove(0);
    let fault = seal_sjs_mrf_request(request).expect_err("mandatory omission must fail");
    assert_eq!(fault.code, SjsMrfFaultCode::InvalidBasis);
}

#[test]
fn mandatory_floor_laundering_refuses() {
    let mut request = supplied_request();
    request.covenant.hints[0].release_eligible = true;
    request.covenant.hints[0].retention_floor = 0;
    let fault = seal_sjs_mrf_request(request).expect_err("floor laundering must fail");
    assert_eq!(fault.code, SjsMrfFaultCode::InvalidHint);
}

#[test]
fn stale_nested_digest_refuses() {
    let mut request = supplied_request();
    request.covenant.hints[5].term.push_str(" changed");
    let fault = compile_sjs_mrf(&request).expect_err("stale digest must fail");
    assert_eq!(fault.code, SjsMrfFaultCode::InvalidDigest);
}

#[test]
fn budget_exhaustion_makes_no_minimum_claim() {
    let mut request = supplied_request();
    request.policy.pass_budget = 1;
    request = seal_sjs_mrf_request(request).expect("resealed budget request");
    let envelope = compile_sjs_mrf(&request).expect("compile");
    assert_eq!(
        envelope.disposition,
        SjsMrfCompilationDisposition::BoundedPassBudgetExhausted
    );
    assert!(!envelope.locally_irreducible);
    assert!(envelope.pass_budget_exhausted);
    assert_eq!(envelope.witnesses.len(), 1);
}

#[test]
fn grouped_release_can_resolve_conflicting_recovery_routes() {
    let mut request = supplied_request();
    let source_id = id("recovery:82000000-0000-4000-8000-000000000032");
    let route_hint = request.covenant.hints[5].hint_id.clone();
    request.covenant.hints[5]
        .recovery_source_ids
        .insert(source_id.clone());
    let mut second_drift = request.operative_frame.clone();
    second_drift.unresolved_frontier = ["a second conflicting reconstruction".to_owned()]
        .into_iter()
        .collect();
    request.recovery_sources.push(SjsMrfRecoverySource {
        source_id,
        kind: SjsMrfRecoverySourceKind::ExactSourceArtifact,
        route_hint_ids: [route_hint].into_iter().collect(),
        frame: second_drift,
        source_digest: empty_digest(),
    });
    request = seal_sjs_mrf_request(request).expect("grouped request");
    let envelope = compile_sjs_mrf(&request).expect("grouped compile");
    assert!(envelope.witnesses.iter().any(|witness| {
        witness.disposition == SjsMrfWitnessDisposition::ReleaseAdmitted
            && witness.released_hint_ids.len() == 2
    }));
}

#[test]
fn all_seven_hint_classes_are_admitted_as_typed_data() {
    let mut request = supplied_request();
    let template = request.covenant.hints[7].clone();
    request.covenant.hints.push(SjsMrfHint {
        hint_id: id("hint:82000000-0000-4000-8000-000000000025"),
        scope_id: template.scope_id,
        class: SjsMrfHintClass::ExpiredItem,
        term: "completed historical cue".to_owned(),
        intended_transform: template.intended_transform,
        applicability: template.applicability,
        completion: template.completion,
        invalidation: template.invalidation,
        restoration_role: template.restoration_role,
        source_refs: template.source_refs,
        recovery_source_ids: BTreeSet::new(),
        release_eligible: false,
        retention_floor: 0,
        hint_digest: empty_digest(),
    });
    request = seal_sjs_mrf_request(request).expect("all classes request");
    let envelope = compile_sjs_mrf(&request).expect("all classes compile");
    assert_eq!(envelope.request.covenant.hints.len(), 9);
}

#[test]
fn noncanonical_whitespace_and_trailing_content_refuse() {
    let request = supplied_request();
    let machine = to_sjs_mrf_request_machine_form(&request).expect("machine form");
    let spaced = format!(" {machine}");
    assert!(from_sjs_mrf_request_machine_form(&spaced).is_err());
    let trailing = format!("{machine}\n");
    assert!(from_sjs_mrf_request_machine_form(&trailing).is_err());
}

#[test]
fn duplicate_and_unknown_json_fields_refuse() {
    let request = supplied_request();
    let machine = to_sjs_mrf_request_machine_form(&request).expect("machine form");
    let duplicate = machine.replacen(
        "{\"profile\":",
        "{\"profile\":\"duplicate\",\"profile\":",
        1,
    );
    assert!(from_sjs_mrf_request_machine_form(&duplicate).is_err());
    let unknown = machine.replacen("{\"profile\":", "{\"unexpected\":false,\"profile\":", 1);
    assert!(from_sjs_mrf_request_machine_form(&unknown).is_err());
}

#[test]
fn raw_argument_byte_mutation_refuses() {
    let request = supplied_request();
    let machine = to_sjs_mrf_request_machine_form(&request).expect("machine form");
    let mutated = machine.replacen(
        "retain the exact governed work frame",
        "retain an altered governed work frame",
        1,
    );
    let fault = from_sjs_mrf_request_machine_form(&mutated).expect_err("raw mutation must fail");
    assert_eq!(fault.code, SjsMrfFaultCode::InvalidDigest);
}

#[test]
fn reordered_witnesses_refuse_even_when_envelope_is_redigested() {
    let request = supplied_request();
    let mut envelope = compile_sjs_mrf(&request).expect("envelope");
    envelope.witnesses.swap(0, 1);
    envelope.envelope_digest = sjs_mrf_envelope_digest(&envelope).expect("redigest");
    let fault = validate_sjs_mrf_envelope(&envelope).expect_err("witness order must fail");
    assert_eq!(fault.code, SjsMrfFaultCode::InvalidWitness);
}

#[test]
fn narrative_cannot_assert_authority_even_when_redigested() {
    let request = supplied_request();
    let mut envelope = compile_sjs_mrf(&request).expect("envelope");
    envelope.narrative_projection[0].authority_asserted = true;
    envelope.envelope_digest = sjs_mrf_envelope_digest(&envelope).expect("redigest");
    let fault = validate_sjs_mrf_envelope(&envelope).expect_err("narrative authority must fail");
    assert_eq!(fault.code, SjsMrfFaultCode::InvalidWitness);
}

#[test]
fn retained_evidence_raw_byte_mutation_refuses() {
    let request = synthetic_sjs_mrf_request().expect("request");
    let mut bundle = build_sjs_mrf_evidence_bundle(&request).expect("bundle");
    bundle.request_file = bundle.request_file.replacen(
        "compiled minimum recoverable frame",
        "compiled altered recoverable frame",
        1,
    );
    assert!(verify_sjs_mrf_evidence_bundle(&bundle).is_err());
}

#[test]
fn machine_form_round_trip_preserves_exact_request() {
    let request = supplied_request();
    let machine = to_sjs_mrf_request_machine_form(&request).expect("machine");
    let reparsed = from_sjs_mrf_request_machine_form(&machine).expect("parse");
    assert_eq!(reparsed, request);
}
