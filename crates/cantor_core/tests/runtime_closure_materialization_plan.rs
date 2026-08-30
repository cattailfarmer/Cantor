use std::collections::BTreeSet;

use cantor_core::*;

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).expect("test semantic identity")
}

fn digest(character: char) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: character.to_string().repeat(64),
    }
}

fn empty_digest() -> ContentDigest {
    digest('0')
}

fn fixture() -> RuntimeClosureMaterializationRequest {
    synthetic_runtime_closure_materialization_request().expect("materialization fixture")
}

fn request_for_upstream(
    upstream: &RuntimeClosureEnvelope,
    input_class: RuntimeClosureMaterializationInputClass,
) -> RuntimeClosureMaterializationRequest {
    let upstream_envelope =
        to_runtime_closure_envelope_machine_form(upstream).expect("upstream machine form");
    let expected_receipt = expected_installation_receipt_digest(&upstream.plan.expected_receipt)
        .expect("expected receipt digest");
    seal_runtime_closure_materialization_request(RuntimeClosureMaterializationRequest {
        profile: RUNTIME_CLOSURE_MATERIALIZATION_REQUEST_PROFILE.to_owned(),
        request_id: sid("materialization-request:73000000-0000-4000-8000-000000000001"),
        materialization_id: sid("materialization:73000000-0000-4000-8000-000000000002"),
        input_class,
        upstream_canonical_uuid: RUNTIME_CLOSURE_CANONICAL_UUID.to_owned(),
        upstream_signature_uuid: RUNTIME_CLOSURE_SIGNATURE_UUID.to_owned(),
        upstream_envelope_bytes: upstream_envelope.len() as u64,
        upstream_envelope_sha256: sha256_bytes(upstream_envelope.as_bytes()),
        upstream_envelope,
        upstream_request_digest: upstream.request.request_digest.clone(),
        upstream_plan_digest: upstream.plan.plan_digest.clone(),
        upstream_envelope_digest: upstream.envelope_digest.clone(),
        upstream_expected_receipt_digest: expected_receipt,
        evidence_refs: [sid("evidence:73000000-0000-4000-8000-000000000003")]
            .into_iter()
            .collect(),
        non_authority: RUNTIME_CLOSURE_MATERIALIZATION_NON_AUTHORITY.to_owned(),
        request_digest: empty_digest(),
    })
    .expect("materialization request for upstream")
}

fn new_material(
    suffix: u32,
    kind: RuntimeClosureMaterialKind,
    target: &str,
    character: char,
) -> RuntimeClosureMaterialNode {
    RuntimeClosureMaterialNode {
        node_id: sid(&format!("material:74000000-0000-4000-8000-{suffix:012x}")),
        kind,
        expected_sha256: digest(character),
        expected_bytes: 512,
        provenance_ref: sid("provenance:materialization-extension"),
        compatibility_refs: BTreeSet::new(),
        target: target.to_owned(),
        verifier_profile: "sha256-exact/0.2".to_owned(),
        executable: RuntimeClosureExecutableDisposition::NonExecutable,
    }
}

fn new_edge(
    suffix: u32,
    input: SemanticId,
    output: &RuntimeClosureMaterialNode,
    source_kind: RuntimeClosureSourceKind,
    prefix: &str,
) -> RuntimeClosureProducerEdge {
    RuntimeClosureProducerEdge {
        edge_id: sid(&format!("producer:75000000-0000-4000-8000-{suffix:012x}")),
        inputs: [input].into_iter().collect(),
        output: output.node_id.clone(),
        source: RuntimeClosureSourceDescriptor {
            source_id: sid(&format!("source:76000000-0000-4000-8000-{suffix:012x}")),
            kind: source_kind,
            immutable_ref: sid(&format!("{prefix}:sha256:{}", "d".repeat(64))),
            expected_sha256: output.expected_sha256.clone(),
            expected_bytes: output.expected_bytes,
        },
        transform_profile: "materialization-test-transform/0.2".to_owned(),
        expected_sha256: output.expected_sha256.clone(),
        expected_bytes: output.expected_bytes,
    }
}

#[test]
fn synthetic_plan_compiles_deterministically_with_formula_and_zero_state() {
    let request = fixture();
    let first = compile_runtime_closure_materialization_plan(&request).unwrap();
    let second = compile_runtime_closure_materialization_plan(&request).unwrap();
    assert_eq!(first, second);
    let upstream = from_runtime_closure_envelope_machine_form(&request.upstream_envelope).unwrap();
    assert_eq!(
        first.plan.operations.len(),
        upstream.plan.material_nodes.len() * 4 + upstream.plan.prerequisites.len() + 3
    );
    assert_eq!(first.plan.operations.len(), 25);
    assert_eq!(first.plan.phases, runtime_closure_materialization_phases());
    assert_eq!(runtime_closure_materialization_operation_kinds().len(), 13);
    assert_eq!(first.plan.capability_denials.len(), 25);
    assert!(!first.plan.execution_authorized);
    assert_eq!(first.plan.receipt_candidate.observation_count, 0);
    assert_eq!(first.plan.receipt_candidate.executed_operation_count, 0);
    assert!(!first.plan.receipt_candidate.rollback_ready_asserted);
}

#[test]
fn operation_order_dependencies_and_denials_are_closed() {
    let envelope = compile_runtime_closure_materialization_plan(&fixture()).unwrap();
    let all_denials = runtime_closure_required_capability_denials();
    let mut prior = BTreeSet::new();
    for (index, operation) in envelope.plan.operations.iter().enumerate() {
        assert_eq!(operation.ordinal as usize, index + 1);
        assert!(
            operation
                .dependencies
                .iter()
                .all(|item| prior.contains(item))
        );
        assert!(!operation.required_denied_capabilities.is_empty());
        assert!(
            operation
                .required_denied_capabilities
                .is_subset(&all_denials)
        );
        assert!(!operation.execution_authorized);
        assert!(!operation.observed);
        assert!(!operation.executed);
        prior.insert(operation.operation_id.clone());
    }
    assert_eq!(prior.len(), envelope.plan.operations.len());
}

#[test]
fn all_five_nonroot_production_kinds_project_exactly() {
    let mut upstream_request = synthetic_runtime_closure_request().unwrap();
    let root = upstream_request.installation_sop.node_id.clone();
    let acquired = new_material(
        1,
        RuntimeClosureMaterialKind::Acquired,
        "lib/acquired.dat",
        '6',
    );
    let supplied = new_material(
        2,
        RuntimeClosureMaterialKind::ExplicitlySupplied,
        "share/supplied.dat",
        '7',
    );
    upstream_request.producer_edges.push(new_edge(
        1,
        root.clone(),
        &acquired,
        RuntimeClosureSourceKind::ContentAddressedArtifact,
        "artifact",
    ));
    upstream_request.producer_edges.push(new_edge(
        2,
        root,
        &supplied,
        RuntimeClosureSourceKind::SuppliedDescriptor,
        "supplied",
    ));
    upstream_request.material_nodes.extend([acquired, supplied]);
    upstream_request.request_digest = empty_digest();
    let sealed = seal_runtime_closure_request(upstream_request).unwrap();
    let upstream = compile_runtime_closure(&sealed).unwrap();
    let request = request_for_upstream(
        &upstream,
        RuntimeClosureMaterializationInputClass::SuppliedUnobservedDeclaration,
    );
    let envelope = compile_runtime_closure_materialization_plan(&request).unwrap();
    let kinds = envelope
        .plan
        .operations
        .iter()
        .map(|operation| operation.kind)
        .collect::<BTreeSet<_>>();
    for kind in [
        RuntimeClosureMaterializationOperationKind::ApplyDeterministicTransform,
        RuntimeClosureMaterializationOperationKind::RunSourceBuild,
        RuntimeClosureMaterializationOperationKind::AcquireContentAddressedArtifact,
        RuntimeClosureMaterializationOperationKind::AcceptExplicitlySuppliedMaterial,
        RuntimeClosureMaterializationOperationKind::GenerateConfiguration,
    ] {
        assert!(kinds.contains(&kind));
    }
    assert_eq!(envelope.plan.operations.len(), 4 * 7 + 2 + 3);
}

#[test]
fn upstream_semantic_permutation_reseals_to_identical_plan() {
    let canonical = synthetic_runtime_closure_request().unwrap();
    let canonical_envelope = compile_runtime_closure(&canonical).unwrap();
    let mut permuted = canonical;
    permuted.material_nodes.reverse();
    permuted.prerequisites.reverse();
    permuted.producer_edges.reverse();
    permuted.request_digest = empty_digest();
    let normalized = seal_runtime_closure_request(permuted).unwrap();
    let normalized_envelope = compile_runtime_closure(&normalized).unwrap();
    assert_eq!(normalized_envelope, canonical_envelope);
    let canonical_request = request_for_upstream(
        &canonical_envelope,
        RuntimeClosureMaterializationInputClass::SyntheticProviderFreeFixture,
    );
    let normalized_request = request_for_upstream(
        &normalized_envelope,
        RuntimeClosureMaterializationInputClass::SyntheticProviderFreeFixture,
    );
    assert_eq!(canonical_request, normalized_request);
    assert_eq!(
        compile_runtime_closure_materialization_plan(&canonical_request).unwrap(),
        compile_runtime_closure_materialization_plan(&normalized_request).unwrap()
    );
}

#[test]
fn supplied_unobserved_variant_is_accepted_without_observation() {
    let mut upstream_request = synthetic_runtime_closure_request().unwrap();
    upstream_request
        .evidence_refs
        .insert(sid("evidence:77000000-0000-4000-8000-000000000001"));
    upstream_request.request_digest = empty_digest();
    let upstream =
        compile_runtime_closure(&seal_runtime_closure_request(upstream_request).unwrap()).unwrap();
    let request = request_for_upstream(
        &upstream,
        RuntimeClosureMaterializationInputClass::SuppliedUnobservedDeclaration,
    );
    let verification = verify_runtime_closure_materialization_plan(
        &compile_runtime_closure_materialization_plan(&request).unwrap(),
    )
    .unwrap();
    assert_eq!(
        verification.input_class,
        RuntimeClosureMaterializationInputClass::SuppliedUnobservedDeclaration
    );
    assert!(!verification.execution_authorized);
    assert_eq!(verification.effects, RuntimeClosureEffectAccount::default());
}

#[test]
fn synthetic_fixture_relabel_refuses() {
    let mut request = fixture();
    request.input_class = RuntimeClosureMaterializationInputClass::SuppliedUnobservedDeclaration;
    request.request_digest = empty_digest();
    assert_eq!(
        seal_runtime_closure_materialization_request(request)
            .unwrap_err()
            .code,
        RuntimeClosureMaterializationFaultCode::InvalidInputClass
    );
}

#[test]
fn raw_upstream_argument_byte_tamper_refuses() {
    let mut request = fixture();
    request.upstream_envelope.push(' ');
    request.upstream_envelope_bytes = request.upstream_envelope.len() as u64;
    request.upstream_envelope_sha256 = sha256_bytes(request.upstream_envelope.as_bytes());
    request.request_digest = empty_digest();
    assert_eq!(
        seal_runtime_closure_materialization_request(request)
            .unwrap_err()
            .code,
        RuntimeClosureMaterializationFaultCode::InvalidUpstream
    );
}

#[test]
fn stale_upstream_semantic_digest_refuses() {
    let mut request = fixture();
    request.upstream_plan_digest = digest('f');
    request.request_digest = empty_digest();
    assert_eq!(
        seal_runtime_closure_materialization_request(request)
            .unwrap_err()
            .code,
        RuntimeClosureMaterializationFaultCode::InvalidDigest
    );
}

#[test]
fn strict_request_machine_form_refuses_unknown_duplicate_whitespace_and_trailing() {
    let machine = to_runtime_closure_materialization_request_machine_form(&fixture()).unwrap();
    let unknown = format!("{{\"unknown\":0,{}", &machine[1..]);
    assert!(from_runtime_closure_materialization_request_machine_form(&unknown).is_err());
    let duplicate = format!(
        "{{\"profile\":\"{}\",{}",
        RUNTIME_CLOSURE_MATERIALIZATION_REQUEST_PROFILE,
        &machine[1..]
    );
    assert_eq!(
        from_runtime_closure_materialization_request_machine_form(&duplicate)
            .unwrap_err()
            .code,
        RuntimeClosureMaterializationFaultCode::InvalidMachineForm
    );
    assert!(
        from_runtime_closure_materialization_request_machine_form(&format!(" {machine}")).is_err()
    );
    assert!(
        from_runtime_closure_materialization_request_machine_form(&format!("{machine}\n")).is_err()
    );
}

#[test]
fn outer_machine_form_byte_bound_refuses() {
    let overbound = "x".repeat(RUNTIME_CLOSURE_MATERIALIZATION_MAX_MACHINE_FORM_BYTES + 1);
    assert_eq!(
        from_runtime_closure_materialization_request_machine_form(&overbound)
            .unwrap_err()
            .code,
        RuntimeClosureMaterializationFaultCode::InvalidBound
    );
}

#[test]
fn fully_redigested_execution_authority_tamper_refuses() {
    let mut envelope = compile_runtime_closure_materialization_plan(&fixture()).unwrap();
    envelope.plan.execution_authorized = true;
    envelope.plan.plan_digest =
        runtime_closure_materialization_plan_digest(&envelope.plan).unwrap();
    envelope.envelope_digest = runtime_closure_materialization_envelope_digest(&envelope).unwrap();
    assert_eq!(
        validate_runtime_closure_materialization_envelope(&envelope)
            .unwrap_err()
            .code,
        RuntimeClosureMaterializationFaultCode::InvalidAuthority
    );
}

#[test]
fn fully_redigested_denial_removal_refuses() {
    let mut envelope = compile_runtime_closure_materialization_plan(&fixture()).unwrap();
    envelope
        .plan
        .capability_denials
        .remove(&RuntimeClosureCapabilityDenial::FilesystemRead);
    envelope.plan.plan_digest =
        runtime_closure_materialization_plan_digest(&envelope.plan).unwrap();
    envelope.envelope_digest = runtime_closure_materialization_envelope_digest(&envelope).unwrap();
    assert_eq!(
        validate_runtime_closure_materialization_envelope(&envelope)
            .unwrap_err()
            .code,
        RuntimeClosureMaterializationFaultCode::InvalidDenial
    );
}

#[test]
fn fully_redigested_receipt_assertion_refuses() {
    let mut envelope = compile_runtime_closure_materialization_plan(&fixture()).unwrap();
    envelope.plan.receipt_candidate.rollback_ready_asserted = true;
    envelope.plan.receipt_candidate.receipt_candidate_digest =
        runtime_closure_materialization_receipt_candidate_digest(&envelope.plan.receipt_candidate)
            .unwrap();
    envelope.plan.plan_digest =
        runtime_closure_materialization_plan_digest(&envelope.plan).unwrap();
    envelope.envelope_digest = runtime_closure_materialization_envelope_digest(&envelope).unwrap();
    assert_eq!(
        validate_runtime_closure_materialization_envelope(&envelope)
            .unwrap_err()
            .code,
        RuntimeClosureMaterializationFaultCode::InvalidReceipt
    );
}

#[test]
fn redigested_operation_execution_state_refuses() {
    let mut envelope = compile_runtime_closure_materialization_plan(&fixture()).unwrap();
    envelope.plan.operations[0].executed = true;
    envelope.plan.operations[0].operation_digest =
        runtime_closure_materialization_operation_digest(&envelope.plan.operations[0]).unwrap();
    envelope.plan.unresolved_operation_digests[0] =
        envelope.plan.operations[0].operation_digest.clone();
    envelope.plan.plan_digest =
        runtime_closure_materialization_plan_digest(&envelope.plan).unwrap();
    envelope.envelope_digest = runtime_closure_materialization_envelope_digest(&envelope).unwrap();
    assert_eq!(
        validate_runtime_closure_materialization_envelope(&envelope)
            .unwrap_err()
            .code,
        RuntimeClosureMaterializationFaultCode::InvalidAuthority
    );
}

#[test]
fn dependency_removal_and_operation_identity_collision_refuse() {
    let canonical = compile_runtime_closure_materialization_plan(&fixture()).unwrap();
    let mut dependency = canonical.clone();
    let index = dependency
        .plan
        .operations
        .iter()
        .position(|operation| !operation.dependencies.is_empty())
        .unwrap();
    dependency.plan.operations[index].dependencies.clear();
    dependency.plan.operations[index].operation_digest =
        runtime_closure_materialization_operation_digest(&dependency.plan.operations[index])
            .unwrap();
    dependency.plan.unresolved_operation_digests[index] =
        dependency.plan.operations[index].operation_digest.clone();
    dependency.plan.receipt_candidate.ordered_operation_digest =
        runtime_closure_materialization_ordered_operation_digest(&dependency.plan.operations)
            .unwrap();
    dependency.plan.receipt_candidate.receipt_candidate_digest =
        runtime_closure_materialization_receipt_candidate_digest(
            &dependency.plan.receipt_candidate,
        )
        .unwrap();
    dependency.plan.plan_digest =
        runtime_closure_materialization_plan_digest(&dependency.plan).unwrap();
    dependency.envelope_digest =
        runtime_closure_materialization_envelope_digest(&dependency).unwrap();
    assert!(validate_runtime_closure_materialization_envelope(&dependency).is_err());

    let mut collision = canonical;
    collision.plan.operations[1].operation_id = collision.plan.operations[0].operation_id.clone();
    collision.plan.operations[1].operation_digest =
        runtime_closure_materialization_operation_digest(&collision.plan.operations[1]).unwrap();
    collision.plan.unresolved_operation_digests[1] =
        collision.plan.operations[1].operation_digest.clone();
    collision.plan.plan_digest =
        runtime_closure_materialization_plan_digest(&collision.plan).unwrap();
    collision.envelope_digest =
        runtime_closure_materialization_envelope_digest(&collision).unwrap();
    assert_eq!(
        validate_runtime_closure_materialization_envelope(&collision)
            .unwrap_err()
            .code,
        RuntimeClosureMaterializationFaultCode::InvalidIdentity
    );
}

#[test]
fn fully_redigested_phase_kind_and_target_mutations_refuse() {
    for mutation in 0..3 {
        let mut envelope = compile_runtime_closure_materialization_plan(&fixture()).unwrap();
        let index = 4;
        match mutation {
            0 => {
                envelope.plan.operations[index].phase =
                    RuntimeClosureMaterializationPhase::ClosureVerification;
            }
            1 => {
                envelope.plan.operations[index].kind =
                    RuntimeClosureMaterializationOperationKind::VerifyClosure;
            }
            _ => {
                envelope.plan.operations[index].target = Some("wrong/target.bin".to_owned());
            }
        }
        envelope.plan.operations[index].operation_digest =
            runtime_closure_materialization_operation_digest(&envelope.plan.operations[index])
                .unwrap();
        envelope.plan.unresolved_operation_digests[index] =
            envelope.plan.operations[index].operation_digest.clone();
        envelope.plan.receipt_candidate.ordered_operation_digest =
            runtime_closure_materialization_ordered_operation_digest(&envelope.plan.operations)
                .unwrap();
        envelope.plan.receipt_candidate.receipt_candidate_digest =
            runtime_closure_materialization_receipt_candidate_digest(
                &envelope.plan.receipt_candidate,
            )
            .unwrap();
        envelope.plan.plan_digest =
            runtime_closure_materialization_plan_digest(&envelope.plan).unwrap();
        envelope.envelope_digest =
            runtime_closure_materialization_envelope_digest(&envelope).unwrap();
        assert_eq!(
            validate_runtime_closure_materialization_envelope(&envelope)
                .unwrap_err()
                .code,
            RuntimeClosureMaterializationFaultCode::InvalidOperation
        );
    }
}

#[test]
fn evidence_round_trip_independently_replays() {
    let bundle = build_runtime_closure_materialization_evidence_bundle(&fixture()).unwrap();
    let machine = to_runtime_closure_materialization_evidence_bundle_machine_form(&bundle).unwrap();
    let restored =
        from_runtime_closure_materialization_evidence_bundle_machine_form(&machine).unwrap();
    let verification = verify_runtime_closure_materialization_evidence_bundle(&restored).unwrap();
    assert_eq!(verification.phase_count, 9);
    assert_eq!(verification.operation_kind_count, 13);
    assert_eq!(verification.operation_count, 25);
    assert_eq!(verification.unresolved_operation_count, 25);
    assert_eq!(verification.receipt_zero_field_count, 10);
    assert_eq!(verification.effects, RuntimeClosureEffectAccount::default());
}

#[test]
fn evidence_manifest_and_raw_request_tamper_refuse() {
    let mut manifest = build_runtime_closure_materialization_evidence_bundle(&fixture()).unwrap();
    manifest.manifest_file = manifest.manifest_file.replace(
        "\"execution_authorized\":false",
        "\"execution_authorized\":true",
    );
    assert!(verify_runtime_closure_materialization_evidence_bundle(&manifest).is_err());

    let mut raw = build_runtime_closure_materialization_evidence_bundle(&fixture()).unwrap();
    raw.request_file.insert(raw.request_file.len() - 1, ' ');
    assert!(verify_runtime_closure_materialization_evidence_bundle(&raw).is_err());
}

#[test]
fn verification_semantic_mutation_refuses() {
    let envelope = compile_runtime_closure_materialization_plan(&fixture()).unwrap();
    let mut verification = verify_runtime_closure_materialization_plan(&envelope).unwrap();
    verification.operation_kind_count = 12;
    assert_eq!(
        validate_runtime_closure_materialization_verification(&verification, &envelope)
            .unwrap_err()
            .code,
        RuntimeClosureMaterializationFaultCode::InvalidVerification
    );
}
