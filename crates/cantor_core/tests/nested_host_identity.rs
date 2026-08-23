use std::collections::BTreeSet;

use cantor_core::{
    ContentDigest, NESTED_OUTER_HOST_IDENTITY_ENVELOPE_PROFILE,
    NESTED_OUTER_HOST_IDENTITY_NON_AUTHORITY, NESTED_OUTER_HOST_IDENTITY_REQUEST_PROFILE,
    NestedHostIdentityFaultCode, NestedHostSessionBounds, NestedOuterHostIdentityRequest,
    OuterHostCapabilityDenial, OuterHostKind, OuterHostModelBinding, OuterHostProcessBinding,
    OuterModelBindingState, OuterModelRole, OuterProcessBindingState, SemanticId,
    compile_nested_outer_host_identity, from_nested_outer_host_identity_envelope_machine_form,
    from_nested_outer_host_identity_request_machine_form,
    nested_outer_host_identity_envelope_digest,
    to_nested_outer_host_identity_envelope_machine_form,
    to_nested_outer_host_identity_request_machine_form,
    validate_nested_outer_host_identity_envelope, validate_nested_outer_host_identity_request,
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

fn request() -> NestedOuterHostIdentityRequest {
    NestedOuterHostIdentityRequest {
        profile: NESTED_OUTER_HOST_IDENTITY_REQUEST_PROFILE.to_owned(),
        session_id: id("nested-session:fixture"),
        outer_host_id: id("outer-host:fixture"),
        authority_ref: id("specification:nested-outer-host-identity-p0"),
        authority_digest: digest('a'),
        process: OuterHostProcessBinding {
            process_id: id("outer-process:fixture"),
            host_kind: OuterHostKind::SlimCantor,
            binding_state: OuterProcessBindingState::DeclaredUnobserved,
            implementation_digest: digest('b'),
            configuration_digest: digest('c'),
            supervisor_profile: "cantor-service-supervisor-state/0.1".to_owned(),
        },
        model: OuterHostModelBinding {
            model_id: id("outer-model:fixture"),
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
        evidence_refs: BTreeSet::from([id("evidence:nested-host-source")]),
        unresolved_account: BTreeSet::from([
            "model_not_loaded".to_owned(),
            "physical_process_not_observed".to_owned(),
            "provider_not_contacted".to_owned(),
        ]),
        non_authority: NESTED_OUTER_HOST_IDENTITY_NON_AUTHORITY.to_owned(),
    }
}

#[test]
fn valid_identity_envelope_round_trips_and_validates() {
    let request = request();
    let envelope = compile_nested_outer_host_identity(&request).expect("compile");
    assert_eq!(
        envelope.profile,
        NESTED_OUTER_HOST_IDENTITY_ENVELOPE_PROFILE
    );
    assert_eq!(envelope.request, request);
    assert_eq!(envelope.capability_denials.len(), 6);
    validate_nested_outer_host_identity_envelope(&request, &envelope).expect("validate");

    let request_form =
        to_nested_outer_host_identity_request_machine_form(&request).expect("request form");
    assert_eq!(
        from_nested_outer_host_identity_request_machine_form(&request_form)
            .expect("request restore"),
        request
    );
    let envelope_form =
        to_nested_outer_host_identity_envelope_machine_form(&envelope).expect("envelope form");
    assert_eq!(
        from_nested_outer_host_identity_envelope_machine_form(&envelope_form)
            .expect("envelope restore"),
        envelope
    );
}

#[test]
fn equal_requests_compile_byte_identically() {
    let request = request();
    let first = compile_nested_outer_host_identity(&request).expect("first");
    let second = compile_nested_outer_host_identity(&request).expect("second");
    assert_eq!(first, second);
    assert_eq!(
        to_nested_outer_host_identity_envelope_machine_form(&first).expect("first bytes"),
        to_nested_outer_host_identity_envelope_machine_form(&second).expect("second bytes")
    );
}

#[test]
fn all_four_operational_identities_must_be_distinct() {
    for coordinate in 0..4 {
        let mut candidate = request();
        match coordinate {
            0 => candidate.outer_host_id = candidate.session_id.clone(),
            1 => candidate.process.process_id = candidate.outer_host_id.clone(),
            2 => candidate.model.model_id = candidate.process.process_id.clone(),
            3 => candidate.model.model_id = candidate.session_id.clone(),
            _ => unreachable!(),
        }
        let fault = validate_nested_outer_host_identity_request(&candidate)
            .expect_err("identity collision must refuse");
        assert_eq!(fault.code, NestedHostIdentityFaultCode::IdentityCollision);
    }
}

#[test]
fn request_and_nested_unknown_fields_refuse() {
    let mut value = serde_json::to_value(request()).expect("value");
    value["unexpected"] = json!(true);
    assert!(serde_json::from_value::<NestedOuterHostIdentityRequest>(value).is_err());

    let mut value = serde_json::to_value(request()).expect("value");
    value["model"]["unexpected"] = json!(true);
    assert!(serde_json::from_value::<NestedOuterHostIdentityRequest>(value).is_err());
}

#[test]
fn observed_or_loaded_state_fabrication_refuses() {
    let mut process_value = serde_json::to_value(request()).expect("value");
    process_value["process"]["binding_state"] = json!("observed");
    assert!(serde_json::from_value::<NestedOuterHostIdentityRequest>(process_value).is_err());

    let mut model_value = serde_json::to_value(request()).expect("value");
    model_value["model"]["binding_state"] = json!("loaded");
    assert!(serde_json::from_value::<NestedOuterHostIdentityRequest>(model_value).is_err());
}

#[test]
fn malformed_or_non_sha256_digests_refuse() {
    for coordinate in 0..5 {
        let mut candidate = request();
        let target = match coordinate {
            0 => &mut candidate.authority_digest,
            1 => &mut candidate.process.implementation_digest,
            2 => &mut candidate.model.artifact_digest,
            3 => &mut candidate.model.runtime_digest,
            4 => &mut candidate.model.configuration_digest,
            _ => unreachable!(),
        };
        if coordinate % 2 == 0 {
            target.algorithm = "fnv1a64-fixture-only".to_owned();
        } else {
            target.value = "A".repeat(64);
        }
        let fault = validate_nested_outer_host_identity_request(&candidate)
            .expect_err("invalid digest must refuse");
        assert_eq!(fault.code, NestedHostIdentityFaultCode::InvalidDigest);
    }
}

#[test]
fn every_session_bound_is_closed() {
    let mut variants = Vec::new();
    let mut candidate = request();
    candidate.bounds.maximum_inner_processes = 2;
    variants.push(candidate);
    let mut candidate = request();
    candidate.bounds.maximum_model_instances = 1;
    variants.push(candidate);
    let mut candidate = request();
    candidate.bounds.maximum_attention_frame_bytes = 0;
    variants.push(candidate);
    let mut candidate = request();
    candidate.bounds.maximum_iterations = 65;
    variants.push(candidate);
    let mut candidate = request();
    candidate.bounds.session_timeout_seconds = 86_401;
    variants.push(candidate);

    for candidate in variants {
        let fault = validate_nested_outer_host_identity_request(&candidate)
            .expect_err("bound substitution must refuse");
        assert_eq!(fault.code, NestedHostIdentityFaultCode::InvalidBounds);
    }
}

#[test]
fn evidence_unresolved_and_nonauthority_are_exact() {
    let mut candidate = request();
    candidate.evidence_refs.clear();
    assert_eq!(
        validate_nested_outer_host_identity_request(&candidate)
            .expect_err("empty evidence")
            .code,
        NestedHostIdentityFaultCode::InvalidEvidence
    );

    let mut candidate = request();
    candidate
        .unresolved_account
        .remove("provider_not_contacted");
    assert_eq!(
        validate_nested_outer_host_identity_request(&candidate)
            .expect_err("missing unresolved truth")
            .code,
        NestedHostIdentityFaultCode::InvalidUnresolvedAccount
    );

    let mut candidate = request();
    candidate.non_authority = "process launch authorized".to_owned();
    assert_eq!(
        validate_nested_outer_host_identity_request(&candidate)
            .expect_err("authority widening")
            .code,
        NestedHostIdentityFaultCode::InvalidAuthority
    );
}

#[test]
fn envelope_request_digest_and_profile_tampering_refuse() {
    let request = request();
    let envelope = compile_nested_outer_host_identity(&request).expect("compile");

    let mut candidate = envelope.clone();
    candidate.profile = "production-agent/1".to_owned();
    assert!(validate_nested_outer_host_identity_envelope(&request, &candidate).is_err());

    let mut candidate = envelope.clone();
    candidate.request_digest = digest('1');
    assert!(validate_nested_outer_host_identity_envelope(&request, &candidate).is_err());

    let mut candidate = envelope;
    candidate.envelope_digest = digest('2');
    assert!(validate_nested_outer_host_identity_envelope(&request, &candidate).is_err());
}

#[test]
fn request_substitution_refuses_even_when_each_request_is_valid() {
    let first_request = request();
    let envelope = compile_nested_outer_host_identity(&first_request).expect("compile");
    let mut second_request = request();
    second_request.session_id = id("nested-session:other");
    validate_nested_outer_host_identity_request(&second_request).expect("second request valid");
    let fault = validate_nested_outer_host_identity_envelope(&second_request, &envelope)
        .expect_err("request substitution must refuse");
    assert_eq!(
        fault.code,
        NestedHostIdentityFaultCode::InvalidCorrespondence
    );
}

#[test]
fn denial_removal_refuses_after_digest_recomputation() {
    let request = request();
    let mut envelope = compile_nested_outer_host_identity(&request).expect("compile");
    envelope
        .capability_denials
        .remove(&OuterHostCapabilityDenial::ProviderCall);
    envelope.envelope_digest = nested_outer_host_identity_envelope_digest(&envelope)
        .expect("recompute adversarial digest");
    let fault = validate_nested_outer_host_identity_envelope(&request, &envelope)
        .expect_err("missing denial must refuse");
    assert_eq!(fault.code, NestedHostIdentityFaultCode::InvalidAuthority);
}

#[test]
fn machine_form_wrong_state_and_trailing_content_refuse() {
    let request = request();
    let form = to_nested_outer_host_identity_request_machine_form(&request).expect("form");
    assert!(
        from_nested_outer_host_identity_request_machine_form(&format!("{form} trailing")).is_err()
    );

    let mut value: Value = serde_json::from_str(&form).expect("value");
    value["process"]["host_kind"] = json!("inner_cantor");
    assert!(from_nested_outer_host_identity_request_machine_form(&value.to_string()).is_err());
}
