use std::collections::BTreeSet;

use cantor_core::{
    ContentDigest, InnerCantorKind, InnerCantorProcessBinding, InnerProcessBindingState,
    InnerProcessLineageCapabilityDenial, InnerProcessLineageRelationship,
    NESTED_INNER_PROCESS_LINEAGE_NON_AUTHORITY, NESTED_INNER_PROCESS_LINEAGE_REQUEST_PROFILE,
    NESTED_OUTER_HOST_IDENTITY_NON_AUTHORITY, NESTED_OUTER_HOST_IDENTITY_REQUEST_PROFILE,
    NestedHostSessionBounds, NestedInnerProcessLineageFaultCode, NestedInnerProcessLineageRequest,
    NestedOuterHostIdentityRequest, OuterHostKind, OuterHostModelBinding, OuterHostProcessBinding,
    OuterModelBindingState, OuterModelRole, OuterProcessBindingState, SemanticId,
    build_nested_inner_process_lineage_evidence_bundle, compile_nested_inner_process_lineage,
    compile_nested_outer_host_identity, from_nested_inner_process_lineage_envelope_machine_form,
    from_nested_inner_process_lineage_evidence_bundle_machine_form,
    from_nested_inner_process_lineage_request_machine_form,
    from_nested_inner_process_lineage_verification_machine_form,
    nested_inner_process_lineage_envelope_digest, seal_nested_inner_process_lineage_request,
    to_nested_inner_process_lineage_envelope_machine_form,
    to_nested_inner_process_lineage_evidence_bundle_machine_form,
    to_nested_inner_process_lineage_request_machine_form,
    to_nested_inner_process_lineage_verification_machine_form,
    validate_nested_inner_process_lineage_envelope, validate_nested_inner_process_lineage_request,
    validate_nested_inner_process_lineage_verification, verify_nested_inner_process_lineage,
    verify_nested_inner_process_lineage_evidence_bundle,
};
use serde_json::{Value, json};

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn digest(symbol: char) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: symbol.to_string().repeat(64),
    }
}

fn parent_request() -> NestedOuterHostIdentityRequest {
    NestedOuterHostIdentityRequest {
        profile: NESTED_OUTER_HOST_IDENTITY_REQUEST_PROFILE.to_owned(),
        session_id: id("outer-session:11111111-1111-4111-8111-111111111111"),
        outer_host_id: id("outer-host:22222222-2222-4222-8222-222222222222"),
        authority_ref: id("specification:nested-outer-host-identity-p0"),
        authority_digest: digest('a'),
        process: OuterHostProcessBinding {
            process_id: id("outer-process:33333333-3333-4333-8333-333333333333"),
            host_kind: OuterHostKind::SlimCantor,
            binding_state: OuterProcessBindingState::DeclaredUnobserved,
            implementation_digest: digest('b'),
            configuration_digest: digest('c'),
            supervisor_profile: "cantor-service-supervisor-state/0.1".to_owned(),
        },
        model: OuterHostModelBinding {
            model_id: id("outer-model:44444444-4444-4444-8444-444444444444"),
            role: OuterModelRole::SopSelector,
            binding_state: OuterModelBindingState::DeclaredUnloaded,
            provider_family: "cactus-needle".to_owned(),
            model_selector: "needle-2-fixture".to_owned(),
            artifact_digest: digest('d'),
            runtime_digest: digest('e'),
            configuration_digest: digest('f'),
        },
        bounds: NestedHostSessionBounds {
            maximum_inner_processes: 1,
            maximum_model_instances: 2,
            maximum_attention_frame_bytes: 1_048_576,
            maximum_iterations: 16,
            session_timeout_seconds: 900,
        },
        evidence_refs: BTreeSet::from([id("evidence:nested-outer-host-source")]),
        unresolved_account: BTreeSet::from([
            "model_not_loaded".to_owned(),
            "physical_process_not_observed".to_owned(),
            "provider_not_contacted".to_owned(),
        ]),
        non_authority: NESTED_OUTER_HOST_IDENTITY_NON_AUTHORITY.to_owned(),
    }
}

fn request() -> NestedInnerProcessLineageRequest {
    let parent = compile_nested_outer_host_identity(&parent_request()).expect("parent envelope");
    seal_nested_inner_process_lineage_request(NestedInnerProcessLineageRequest {
        profile: NESTED_INNER_PROCESS_LINEAGE_REQUEST_PROFILE.to_owned(),
        request_id: id("request:55555555-5555-4555-8555-555555555555"),
        lineage_id: id("lineage:66666666-6666-4666-8666-666666666666"),
        parent_session_id: parent.request.session_id.clone(),
        parent_outer_host_id: parent.request.outer_host_id.clone(),
        parent_outer_process_id: parent.request.process.process_id.clone(),
        parent_envelope_digest: parent.envelope_digest.clone(),
        parent,
        inner: InnerCantorProcessBinding {
            inner_session_id: id("inner-session:77777777-7777-4777-8777-777777777777"),
            inner_cantor_id: id("inner-cantor:88888888-8888-4888-8888-888888888888"),
            inner_process_id: id("inner-process:99999999-9999-4999-8999-999999999999"),
            kind: InnerCantorKind::InnerCantor,
            binding_state: InnerProcessBindingState::DeclaredUnobserved,
            implementation_digest: digest('1'),
            configuration_digest: digest('2'),
        },
        relationship: InnerProcessLineageRelationship::ProposedParentChildUnobserved,
        lineage_depth: 1,
        child_ordinal: 1,
        evidence_refs: BTreeSet::from([id("evidence:nested-inner-lineage-source")]),
        unresolved_account: BTreeSet::from([
            "parent_process_not_observed".to_owned(),
            "child_process_not_observed".to_owned(),
            "child_not_launched".to_owned(),
            "lineage_not_observed".to_owned(),
            "model_not_admitted".to_owned(),
            "provider_not_contacted".to_owned(),
        ]),
        non_authority: NESTED_INNER_PROCESS_LINEAGE_NON_AUTHORITY.to_owned(),
        request_digest: digest('0'),
    })
    .expect("sealed request")
}

#[test]
fn valid_lineage_round_trips_and_reports_exact_zero_effect_account() {
    let request = request();
    validate_nested_inner_process_lineage_request(&request).expect("request");
    let envelope = compile_nested_inner_process_lineage(&request).expect("compile");
    validate_nested_inner_process_lineage_envelope(&request, &envelope).expect("envelope");
    assert_eq!(envelope.capability_denials.len(), 10);
    let verification = verify_nested_inner_process_lineage(&envelope).expect("verify");
    assert_eq!(verification.operational_identity_count, 7);
    assert_eq!(verification.capability_denial_count, 10);
    assert_eq!(verification.unresolved_truth_count, 6);
    assert!(!verification.effects.physical_parenthood_proved);
    assert!(!verification.effects.child_launched);
    assert_eq!(verification.effects.process_count, 0);
    assert_eq!(verification.effects.workspace_mutation_count, 0);
    assert_eq!(verification.effects.foreign_effect_count, 0);

    let request_form =
        to_nested_inner_process_lineage_request_machine_form(&request).expect("request form");
    assert_eq!(
        from_nested_inner_process_lineage_request_machine_form(&request_form)
            .expect("request restore"),
        request
    );
    let envelope_form =
        to_nested_inner_process_lineage_envelope_machine_form(&envelope).expect("envelope form");
    assert_eq!(
        from_nested_inner_process_lineage_envelope_machine_form(&envelope_form)
            .expect("envelope restore"),
        envelope
    );
    let verification_form =
        to_nested_inner_process_lineage_verification_machine_form(&verification)
            .expect("verification form");
    assert_eq!(
        from_nested_inner_process_lineage_verification_machine_form(&verification_form)
            .expect("verification restore"),
        verification
    );
}

#[test]
fn equal_requests_compile_and_replay_byte_identically() {
    let request = request();
    let first = compile_nested_inner_process_lineage(&request).expect("first");
    let second = compile_nested_inner_process_lineage(&request).expect("second");
    assert_eq!(first, second);
    assert_eq!(
        to_nested_inner_process_lineage_envelope_machine_form(&first).expect("first form"),
        to_nested_inner_process_lineage_envelope_machine_form(&second).expect("second form")
    );

    let bundle = build_nested_inner_process_lineage_evidence_bundle(&request).expect("bundle");
    let first_receipt =
        verify_nested_inner_process_lineage_evidence_bundle(&bundle).expect("first replay");
    let second_receipt =
        verify_nested_inner_process_lineage_evidence_bundle(&bundle).expect("second replay");
    assert_eq!(first_receipt, second_receipt);
    let bundle_form =
        to_nested_inner_process_lineage_evidence_bundle_machine_form(&bundle).expect("bundle form");
    assert_eq!(
        from_nested_inner_process_lineage_evidence_bundle_machine_form(&bundle_form)
            .expect("bundle restore"),
        bundle
    );
}

#[test]
fn all_seven_operational_identities_must_be_distinct() {
    for coordinate in 0..4 {
        let mut candidate = request();
        let colliding_id = candidate.inner.inner_session_id.clone();
        let mut parent = parent_request();
        match coordinate {
            0 => parent.session_id = colliding_id,
            1 => parent.outer_host_id = colliding_id,
            2 => parent.process.process_id = colliding_id,
            3 => parent.model.model_id = colliding_id,
            _ => unreachable!(),
        }
        candidate.parent = compile_nested_outer_host_identity(&parent).expect("colliding parent");
        candidate.parent_session_id = candidate.parent.request.session_id.clone();
        candidate.parent_outer_host_id = candidate.parent.request.outer_host_id.clone();
        candidate.parent_outer_process_id = candidate.parent.request.process.process_id.clone();
        candidate.parent_envelope_digest = candidate.parent.envelope_digest.clone();
        let fault = seal_nested_inner_process_lineage_request(candidate)
            .expect_err("outer-inner collision must refuse");
        assert_eq!(
            fault.code,
            NestedInnerProcessLineageFaultCode::IdentityCollision,
            "coordinate {coordinate} is refused before any result"
        );
    }

    let mut candidate = request();
    candidate.inner.inner_process_id = candidate.inner.inner_cantor_id.clone();
    let fault = seal_nested_inner_process_lineage_request(candidate)
        .expect_err("inner prefix substitution must refuse");
    assert_eq!(
        fault.code,
        NestedInnerProcessLineageFaultCode::InvalidIdentity
    );
}

#[test]
fn malformed_uppercase_or_nil_inner_uuid_refuses() {
    for value in [
        "inner-process:AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
        "inner-process:00000000-0000-0000-0000-000000000000",
        "inner-process:not-a-uuid",
    ] {
        let mut candidate = request();
        candidate.inner.inner_process_id = id(value);
        let fault = seal_nested_inner_process_lineage_request(candidate)
            .expect_err("malformed identity must refuse");
        assert_eq!(
            fault.code,
            NestedInnerProcessLineageFaultCode::InvalidIdentity
        );
    }
}

#[test]
fn invalid_parent_or_parent_anchor_substitution_refuses() {
    let mut invalid_parent = request();
    invalid_parent.parent.envelope_digest = digest('3');
    assert_eq!(
        seal_nested_inner_process_lineage_request(invalid_parent)
            .expect_err("invalid parent")
            .code,
        NestedInnerProcessLineageFaultCode::InvalidParent
    );

    let mut substituted_anchor = request();
    substituted_anchor.parent_outer_host_id = id("outer-host:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    assert_eq!(
        seal_nested_inner_process_lineage_request(substituted_anchor)
            .expect_err("substituted anchor")
            .code,
        NestedInnerProcessLineageFaultCode::InvalidParent
    );
}

#[test]
fn state_relationship_depth_ordinal_evidence_unresolved_and_authority_refuse() {
    let mut state: Value = serde_json::to_value(request()).expect("value");
    state["inner"]["binding_state"] = json!("observed");
    assert!(serde_json::from_value::<NestedInnerProcessLineageRequest>(state).is_err());

    let mut relationship: Value = serde_json::to_value(request()).expect("value");
    relationship["relationship"] = json!("physical_parent_child");
    assert!(serde_json::from_value::<NestedInnerProcessLineageRequest>(relationship).is_err());

    let mut depth = request();
    depth.lineage_depth = 2;
    assert_eq!(
        seal_nested_inner_process_lineage_request(depth)
            .expect_err("depth")
            .code,
        NestedInnerProcessLineageFaultCode::InvalidBounds
    );
    let mut ordinal = request();
    ordinal.child_ordinal = 2;
    assert_eq!(
        seal_nested_inner_process_lineage_request(ordinal)
            .expect_err("ordinal")
            .code,
        NestedInnerProcessLineageFaultCode::InvalidBounds
    );
    let mut evidence = request();
    evidence.evidence_refs.clear();
    assert_eq!(
        seal_nested_inner_process_lineage_request(evidence)
            .expect_err("evidence")
            .code,
        NestedInnerProcessLineageFaultCode::InvalidEvidence
    );
    let mut unresolved = request();
    unresolved
        .unresolved_account
        .remove("provider_not_contacted");
    assert_eq!(
        seal_nested_inner_process_lineage_request(unresolved)
            .expect_err("unresolved")
            .code,
        NestedInnerProcessLineageFaultCode::InvalidUnresolvedAccount
    );
    let mut authority = request();
    authority.non_authority = "process launch authorized".to_owned();
    assert_eq!(
        seal_nested_inner_process_lineage_request(authority)
            .expect_err("authority")
            .code,
        NestedInnerProcessLineageFaultCode::InvalidAuthority
    );
}

#[test]
fn unknown_duplicate_trailing_and_oversize_machine_forms_refuse() {
    let form = to_nested_inner_process_lineage_request_machine_form(&request()).expect("form");
    let mut unknown: Value = serde_json::from_str(&form).expect("value");
    unknown["unexpected"] = json!(true);
    assert!(from_nested_inner_process_lineage_request_machine_form(&unknown.to_string()).is_err());

    let duplicated = form.replacen(
        "{\"profile\":",
        "{\"profile\":\"duplicate\",\"profile\":",
        1,
    );
    assert!(from_nested_inner_process_lineage_request_machine_form(&duplicated).is_err());
    assert!(
        from_nested_inner_process_lineage_request_machine_form(&format!("{form} trailing"))
            .is_err()
    );
    assert!(
        from_nested_inner_process_lineage_request_machine_form(&"x".repeat(1_048_577)).is_err()
    );
}

#[test]
fn duplicate_set_member_and_excessive_depth_or_fields_refuse() {
    let form = to_nested_inner_process_lineage_request_machine_form(&request()).expect("form");
    let duplicate_evidence = form.replace(
        "[\"evidence:nested-inner-lineage-source\"]",
        "[\"evidence:nested-inner-lineage-source\",\"evidence:nested-inner-lineage-source\"]",
    );
    assert!(from_nested_inner_process_lineage_request_machine_form(&duplicate_evidence).is_err());

    let mut deep_value: Value = serde_json::from_str(&form).expect("value");
    let mut nested = Value::Null;
    for _ in 0..25 {
        nested = json!([nested]);
    }
    deep_value["unexpected"] = nested;
    assert!(
        from_nested_inner_process_lineage_request_machine_form(&deep_value.to_string()).is_err()
    );

    let mut value: Value = serde_json::from_str(&form).expect("value");
    let object = value.as_object_mut().expect("object");
    for index in 0..257 {
        object.insert(format!("field_{index}"), json!(index));
    }
    assert!(from_nested_inner_process_lineage_request_machine_form(&value.to_string()).is_err());
}

#[test]
fn request_envelope_denial_and_verification_tampering_refuse() {
    let request = request();
    let mut request_digest = request.clone();
    request_digest.request_digest = digest('4');
    assert_eq!(
        validate_nested_inner_process_lineage_request(&request_digest)
            .expect_err("request digest")
            .code,
        NestedInnerProcessLineageFaultCode::InvalidDigest
    );

    let envelope = compile_nested_inner_process_lineage(&request).expect("envelope");
    let mut denial = envelope.clone();
    denial
        .capability_denials
        .remove(&InnerProcessLineageCapabilityDenial::ProviderCall);
    denial.envelope_digest =
        nested_inner_process_lineage_envelope_digest(&denial).expect("adversarial digest");
    assert_eq!(
        validate_nested_inner_process_lineage_envelope(&request, &denial)
            .expect_err("denial removal")
            .code,
        NestedInnerProcessLineageFaultCode::InvalidAuthority
    );

    let mut verification = verify_nested_inner_process_lineage(&envelope).expect("verification");
    verification.operational_identity_count = 6;
    assert_eq!(
        validate_nested_inner_process_lineage_verification(&verification)
            .expect_err("identity count")
            .code,
        NestedInnerProcessLineageFaultCode::InvalidVerification
    );
}

#[test]
fn every_retained_evidence_coordinate_is_hash_and_replay_bound() {
    for coordinate in 0..4 {
        let mut bundle =
            build_nested_inner_process_lineage_evidence_bundle(&request()).expect("bundle");
        match coordinate {
            0 => bundle.request_file.push(' '),
            1 => bundle.envelope_file.push(' '),
            2 => bundle.verification_file.push(' '),
            3 => bundle.manifest_file.push(' '),
            _ => unreachable!(),
        }
        assert!(verify_nested_inner_process_lineage_evidence_bundle(&bundle).is_err());
    }
}
