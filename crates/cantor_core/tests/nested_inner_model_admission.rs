use std::collections::BTreeSet;

use cantor_core::*;

const UPSTREAM_REQUEST: &str =
    include_str!("../../../experiments/nested_inner_process_lineage_p0/artifacts/request.json");
const UPSTREAM_ENVELOPE: &str =
    include_str!("../../../experiments/nested_inner_process_lineage_p0/artifacts/envelope.json");
const UPSTREAM_VERIFICATION: &str = include_str!(
    "../../../experiments/nested_inner_process_lineage_p0/artifacts/verification.json"
);
const FIXTURE_VERIFYING_KEY: &str =
    "31debe55d37c722768b137131caa6087080b2e0b60b94bd785d14575cfa498bc";
const FIXTURE_SIGNATURE: &str = "5e49a0a59c99d3708f22caa98ef8b44a6d094e559d085bfe97d2793ef1ea0fbed09e7ae695deebe61e1df23466ccd30b7467ad71af223dc70d6cb5086e0cca0f";

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn digest(seed: &str) -> ContentDigest {
    sha256_bytes(seed.as_bytes())
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn upstream() -> (
    NestedInnerProcessLineageRequest,
    NestedInnerProcessLineageEnvelope,
    NestedInnerProcessLineageVerification,
) {
    (
        from_nested_inner_process_lineage_request_machine_form(UPSTREAM_REQUEST.trim_end())
            .expect("upstream request"),
        from_nested_inner_process_lineage_envelope_machine_form(UPSTREAM_ENVELOPE.trim_end())
            .expect("upstream envelope"),
        from_nested_inner_process_lineage_verification_machine_form(
            UPSTREAM_VERIFICATION.trim_end(),
        )
        .expect("upstream verification"),
    )
}

fn unsigned_request() -> NestedInnerModelAdmissionRequest {
    let (upstream_request, upstream_envelope, upstream_verification) = upstream();
    let descriptor = seal_inner_model_artifact_descriptor(InnerModelArtifactDescriptor {
        artifact_id: id("model-artifact:3bb85008-05c2-43cf-9818-f0fcb70a2d31"),
        state: InnerModelArtifactState::SuppliedDescriptorUnobserved,
        content_digest: digest("supplied-unobserved-needle-2-gguf"),
        bytes: 12_884_901_888,
        format: "gguf".to_owned(),
        family_selector: "needle-2-opaque-candidate".to_owned(),
        architecture_selector: "opaque-architecture".to_owned(),
        quantization_selector: "opaque-quantization".to_owned(),
        provenance_ref: id("provenance:fixture-only"),
        license_policy_ref: id("policy:license-unverified"),
        safety_policy_ref: id("policy:safety-unverified"),
        descriptor_digest: empty_digest(),
    })
    .expect("descriptor");
    let inner_cantor_id = upstream_request.inner.inner_cantor_id.clone();
    NestedInnerModelAdmissionRequest {
        profile: NESTED_INNER_MODEL_ADMISSION_REQUEST_PROFILE.to_owned(),
        request_id: id("model-admission-request:5dcc595c-c80d-463c-a142-2ed7842c74d9"),
        upstream_request,
        upstream_envelope,
        upstream_verification,
        upstream_bundle_digest: empty_digest(),
        descriptor: descriptor.clone(),
        instance: ProposedInnerModelInstance {
            model_instance_id: id("inner-model-instance:9c04a08a-079f-49d5-9917-71564530f43c"),
            state: InnerModelInstanceState::ProposedUnloaded,
            configuration_digest: digest("bounded-llama-cpp-config"),
            context_token_ceiling: 16_384,
            memory_byte_ceiling: 96 * 1024 * 1024 * 1024,
            thread_ceiling: 64,
            gpu_layer_ceiling: 256,
            backend_selector: "llama.cpp-opaque-provider-free-plan".to_owned(),
        },
        authorization: InnerModelLoadAuthorization {
            authorization_id: id("model-load-authorization:2fb14059-b20e-44b8-aa41-0db40d93ff04"),
            issuer_ref: id("authorization-issuer:fixture-only"),
            subject_inner_cantor_id: inner_cantor_id,
            artifact_id: descriptor.artifact_id,
            model_instance_id: id("inner-model-instance:9c04a08a-079f-49d5-9917-71564530f43c"),
            action: ModelLoadAction::ModelLoad,
            policy_digest: digest("fixture-only-load-policy"),
            nonce_digest: digest("single-use-nonce"),
            sequence_lower_bound: 41,
            sequence_upper_bound: 41,
            attempt_limit: 1,
            retry_limit: 0,
            disposition: ModelLoadAuthorizationDisposition::AuthorizedForLaterSingleAttempt,
            consumption_state: ModelLoadAuthorizationConsumptionState::Unconsumed,
            verifying_key_hex: FIXTURE_VERIFYING_KEY.to_owned(),
            signature_hex: "0".repeat(128),
        },
        evidence_refs: [id("evidence:nhma-fixture")].into_iter().collect(),
        unresolved_account: [
            "artifact_file_presence_not_observed",
            "artifact_bytes_not_reacquired",
            "artifact_digest_not_physically_recomputed",
            "license_status_not_verified",
            "safety_status_not_verified",
            "provider_compatibility_not_verified",
            "resource_fit_not_verified",
            "signer_policy_governance_not_verified",
            "key_custody_revocation_freshness_not_verified",
            "model_not_loaded",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        non_authority: NESTED_INNER_MODEL_ADMISSION_NON_AUTHORITY.to_owned(),
        request_digest: empty_digest(),
    }
}

fn seal_fixture_request(
    mut request: NestedInnerModelAdmissionRequest,
) -> NestedInnerModelAdmissionRequest {
    request.upstream_bundle_digest = nested_inner_model_upstream_bundle_digest(
        &request.upstream_request,
        &request.upstream_envelope,
        &request.upstream_verification,
    )
    .expect("upstream digest");
    request.request_digest = empty_digest();
    request.authorization.signature_hex = FIXTURE_SIGNATURE.to_owned();
    seal_nested_inner_model_admission_request(request).expect("sealed request")
}

fn valid_request() -> NestedInnerModelAdmissionRequest {
    seal_fixture_request(unsigned_request())
}

#[test]
fn valid_admission_round_trips_and_reports_exact_zero_effect_account() {
    let request = valid_request();
    let first = compile_nested_inner_model_admission(&request).expect("compile");
    let second = compile_nested_inner_model_admission(&request).expect("repeat");
    assert_eq!(first, second);
    let verification = verify_nested_inner_model_admission(&first).expect("verify");
    assert_eq!(verification.upstream_operational_identity_count, 7);
    assert_eq!(verification.operational_identity_count, 8);
    assert_eq!(verification.bound_identity_count, 10);
    assert_eq!(verification.capability_denial_count, 15);
    assert_eq!(verification.unresolved_truth_count, 10);
    assert!(verification.signature_correspondence_verified);
    assert_eq!(verification.effects.model_load_attempt_count, 0);
    assert_eq!(verification.effects.model_load_completion_count, 0);
    assert!(!verification.effects.artifact_file_observed);
    assert!(!verification.effects.artifact_bytes_reacquired);
    assert!(!verification.effects.runtime_model_observed);

    let request_form = to_nested_inner_model_admission_request_machine_form(&request).unwrap();
    assert_eq!(
        from_nested_inner_model_admission_request_machine_form(&request_form).unwrap(),
        request
    );
    let envelope_form = to_nested_inner_model_admission_envelope_machine_form(&first).unwrap();
    assert_eq!(
        from_nested_inner_model_admission_envelope_machine_form(&envelope_form).unwrap(),
        first
    );
    let verification_form =
        to_nested_inner_model_admission_verification_machine_form(&verification).unwrap();
    assert_eq!(
        from_nested_inner_model_admission_verification_machine_form(&verification_form).unwrap(),
        verification
    );
}

#[test]
fn signature_and_verifying_key_mutations_refuse() {
    let request = valid_request();
    let mut signature = request.clone();
    signature
        .authorization
        .signature_hex
        .replace_range(0..2, "00");
    assert_eq!(
        validate_nested_inner_model_admission_request(&signature)
            .expect_err("signature mutation")
            .code,
        NestedInnerModelAdmissionFaultCode::InvalidSignature
    );

    let mut key = request;
    key.authorization.verifying_key_hex = "00".repeat(32);
    assert_eq!(
        validate_nested_inner_model_admission_request(&key)
            .expect_err("key mutation")
            .code,
        NestedInnerModelAdmissionFaultCode::InvalidSignature
    );
}

#[test]
fn complete_upstream_substitution_refuses_even_after_outer_redigest() {
    let mut request = unsigned_request();
    request.upstream_verification.status = "fabricated-but-redigested".to_owned();
    request.upstream_bundle_digest = nested_inner_model_upstream_bundle_digest(
        &request.upstream_request,
        &request.upstream_envelope,
        &request.upstream_verification,
    )
    .unwrap();
    assert_eq!(
        seal_nested_inner_model_admission_request(request)
            .expect_err("mutated upstream")
            .code,
        NestedInnerModelAdmissionFaultCode::InvalidUpstream
    );
}

#[test]
fn descriptor_state_format_bounds_and_digest_mutations_refuse() {
    let mut descriptor = unsigned_request().descriptor;
    descriptor.format = "safetensors".to_owned();
    assert_eq!(
        seal_inner_model_artifact_descriptor(descriptor)
            .expect_err("format")
            .code,
        NestedInnerModelAdmissionFaultCode::InvalidDescriptor
    );

    let mut request = valid_request();
    request.descriptor.bytes = 0;
    assert_eq!(
        validate_nested_inner_model_admission_request(&request)
            .expect_err("zero bytes")
            .code,
        NestedInnerModelAdmissionFaultCode::InvalidDescriptor
    );

    let mut request = valid_request();
    request
        .descriptor
        .descriptor_digest
        .value
        .replace_range(0..2, "00");
    assert_eq!(
        validate_nested_inner_model_admission_request(&request)
            .expect_err("descriptor digest")
            .code,
        NestedInnerModelAdmissionFaultCode::InvalidDigest
    );
}

#[test]
fn all_ten_bound_identities_must_be_distinct() {
    let mut request = unsigned_request();
    let duplicate_uuid = request
        .upstream_request
        .inner
        .inner_process_id
        .as_str()
        .rsplit_once(':')
        .unwrap()
        .1;
    request.descriptor.artifact_id = id(&format!("model-artifact:{duplicate_uuid}"));
    request.descriptor = seal_inner_model_artifact_descriptor(request.descriptor).unwrap();
    request.authorization.artifact_id = request.descriptor.artifact_id.clone();
    request.upstream_bundle_digest = nested_inner_model_upstream_bundle_digest(
        &request.upstream_request,
        &request.upstream_envelope,
        &request.upstream_verification,
    )
    .unwrap();
    assert_eq!(
        seal_nested_inner_model_admission_request(request)
            .expect_err("identity collision")
            .code,
        NestedInnerModelAdmissionFaultCode::IdentityCollision
    );
}

#[test]
fn authorization_tuple_attempt_retry_and_range_mutations_refuse() {
    for mutation in 0..4 {
        let mut request = unsigned_request();
        match mutation {
            0 => {
                request.authorization.artifact_id =
                    id("model-artifact:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
            }
            1 => request.authorization.attempt_limit = 2,
            2 => request.authorization.retry_limit = 1,
            _ => {
                request.authorization.sequence_lower_bound = 42;
                request.authorization.sequence_upper_bound = 41;
            }
        }
        request.upstream_bundle_digest = nested_inner_model_upstream_bundle_digest(
            &request.upstream_request,
            &request.upstream_envelope,
            &request.upstream_verification,
        )
        .unwrap();
        assert_eq!(
            seal_nested_inner_model_admission_request(request)
                .expect_err("authorization mutation")
                .code,
            NestedInnerModelAdmissionFaultCode::InvalidAuthorization
        );
    }
}

#[test]
fn unresolved_evidence_envelope_and_verification_mutations_refuse() {
    let mut unresolved = valid_request();
    unresolved.unresolved_account.remove("model_not_loaded");
    assert_eq!(
        validate_nested_inner_model_admission_request(&unresolved)
            .expect_err("unresolved")
            .code,
        NestedInnerModelAdmissionFaultCode::InvalidUnresolvedAccount
    );

    let mut evidence = valid_request();
    evidence.evidence_refs = BTreeSet::new();
    assert_eq!(
        validate_nested_inner_model_admission_request(&evidence)
            .expect_err("evidence")
            .code,
        NestedInnerModelAdmissionFaultCode::InvalidEvidence
    );

    let request = valid_request();
    let mut envelope = compile_nested_inner_model_admission(&request).unwrap();
    envelope
        .capability_denials
        .remove(&NestedInnerModelAdmissionCapabilityDenial::ModelLoadAttempt);
    envelope.envelope_digest = nested_inner_model_admission_envelope_digest(&envelope).unwrap();
    assert_eq!(
        validate_nested_inner_model_admission_envelope(&request, &envelope)
            .expect_err("denial")
            .code,
        NestedInnerModelAdmissionFaultCode::InvalidAuthority
    );

    let envelope = compile_nested_inner_model_admission(&request).unwrap();
    let mut verification = verify_nested_inner_model_admission(&envelope).unwrap();
    verification.effects.model_load_attempt_count = 1;
    assert_eq!(
        validate_nested_inner_model_admission_verification(&verification)
            .expect_err("verification")
            .code,
        NestedInnerModelAdmissionFaultCode::InvalidVerification
    );
}

#[test]
fn unknown_duplicate_trailing_and_oversize_machine_forms_refuse() {
    let request = valid_request();
    let form = to_nested_inner_model_admission_request_machine_form(&request).unwrap();
    let unknown = form.replacen("{", "{\"unknown\":true,", 1);
    assert!(from_nested_inner_model_admission_request_machine_form(&unknown).is_err());
    let duplicate = form.replacen("{", &format!("{{\"profile\":\"{}\",", request.profile), 1);
    assert!(from_nested_inner_model_admission_request_machine_form(&duplicate).is_err());
    assert!(from_nested_inner_model_admission_request_machine_form(&(form.clone() + "x")).is_err());
    let oversize = format!(
        "{{\"padding\":\"{}\"}}",
        "x".repeat(NESTED_INNER_MODEL_ADMISSION_MAX_MACHINE_FORM_BYTES)
    );
    assert_eq!(
        from_nested_inner_model_admission_request_machine_form(&oversize)
            .expect_err("oversize")
            .code,
        NestedInnerModelAdmissionFaultCode::InvalidMachineForm
    );
}

#[test]
fn retained_evidence_double_replays_and_raw_or_semantic_tamper_refuses() {
    let request = valid_request();
    let bundle = build_nested_inner_model_admission_evidence_bundle(&request).unwrap();
    let verification = verify_nested_inner_model_admission_evidence_bundle(&bundle).unwrap();
    assert_eq!(verification.bound_identity_count, 10);
    assert_eq!(
        from_nested_inner_model_admission_evidence_bundle_machine_form(
            &to_nested_inner_model_admission_evidence_bundle_machine_form(&bundle).unwrap()
        )
        .unwrap(),
        bundle
    );

    let mut raw = bundle.clone();
    raw.request_file.push(' ');
    assert_eq!(
        verify_nested_inner_model_admission_evidence_bundle(&raw)
            .expect_err("raw request byte")
            .code,
        NestedInnerModelAdmissionFaultCode::InvalidEvidence
    );

    let mut semantic = bundle;
    let mut envelope: NestedInnerModelAdmissionEnvelope =
        serde_json::from_str(semantic.envelope_file.trim_end()).unwrap();
    envelope
        .capability_denials
        .remove(&NestedInnerModelAdmissionCapabilityDenial::ExternalEffect);
    envelope.envelope_digest = nested_inner_model_admission_envelope_digest(&envelope).unwrap();
    semantic.envelope_file = format!("{}\n", serde_json::to_string(&envelope).unwrap());
    assert!(verify_nested_inner_model_admission_evidence_bundle(&semantic).is_err());
}
