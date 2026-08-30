use std::collections::BTreeSet;

use cantor_core::{
    ContentDigest, RUNTIME_CLOSURE_MAX_MACHINE_FORM_BYTES, RuntimeClosureCapabilityDenial,
    RuntimeClosureExecutableDisposition, RuntimeClosureFaultCode, RuntimeClosureMaterialKind,
    RuntimeClosureMaterialNode, RuntimeClosurePrerequisite, RuntimeClosurePrerequisiteDisposition,
    RuntimeClosurePrerequisiteKind, RuntimeClosureProducerEdge, RuntimeClosureSourceDescriptor,
    RuntimeClosureSourceKind, SemanticId, build_runtime_closure_evidence_bundle,
    compile_runtime_closure, expected_installation_receipt_digest,
    from_runtime_closure_evidence_bundle_machine_form, from_runtime_closure_request_machine_form,
    runtime_closure_envelope_digest, runtime_closure_plan_digest,
    runtime_closure_required_capability_denials, seal_runtime_closure_request,
    synthetic_runtime_closure_request, to_runtime_closure_evidence_bundle_machine_form,
    to_runtime_closure_request_machine_form, validate_runtime_closure_envelope,
    verify_runtime_closure, verify_runtime_closure_evidence_bundle,
};

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).expect("test semantic identity")
}

fn digest(character: char) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: character.to_string().repeat(64),
    }
}

fn fixture() -> cantor_core::RuntimeClosureRequest {
    synthetic_runtime_closure_request().expect("synthetic request")
}

fn new_material(
    suffix: u32,
    kind: RuntimeClosureMaterialKind,
    target: &str,
    character: char,
) -> RuntimeClosureMaterialNode {
    RuntimeClosureMaterialNode {
        node_id: sid(&format!("material:70000000-0000-4000-8000-{suffix:012x}")),
        kind,
        expected_sha256: digest(character),
        expected_bytes: 512,
        provenance_ref: sid("provenance:test-extension"),
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
        edge_id: sid(&format!("producer:71000000-0000-4000-8000-{suffix:012x}")),
        inputs: [input].into_iter().collect(),
        output: output.node_id.clone(),
        source: RuntimeClosureSourceDescriptor {
            source_id: sid(&format!("source:72000000-0000-4000-8000-{suffix:012x}")),
            kind: source_kind,
            immutable_ref: sid(&format!("{prefix}:sha256:{}", "d".repeat(64))),
            expected_sha256: output.expected_sha256.clone(),
            expected_bytes: output.expected_bytes,
        },
        transform_profile: "test-transform/0.2".to_owned(),
        expected_sha256: output.expected_sha256.clone(),
        expected_bytes: output.expected_bytes,
    }
}

#[test]
fn synthetic_closure_compiles_deterministically_with_zero_effects() {
    let request = fixture();
    let first = compile_runtime_closure(&request).expect("first compile");
    let second = compile_runtime_closure(&request).expect("second compile");
    assert_eq!(first, second);
    let verification = verify_runtime_closure(&first).expect("verification");
    assert_eq!(verification.root_count, 2);
    assert_eq!(verification.material_node_count, 5);
    assert_eq!(verification.producer_edge_count, 3);
    assert_eq!(verification.prerequisite_count, 2);
    assert_eq!(verification.prerequisite_kind_count, 11);
    assert_eq!(verification.material_kind_count, 7);
    assert_eq!(verification.source_kind_count, 5);
    assert_eq!(verification.capability_denial_count, 25);
    assert_eq!(verification.effects, Default::default());
    assert!(!verification.expected_receipt_has_observations);
    assert_eq!(first.plan.expected_receipt.observation_count, 0);
    assert!(!first.plan.expected_receipt.installation_state_asserted);
    assert!(!first.plan.expected_receipt.activation_state_asserted);
    assert!(!first.plan.expected_receipt.successor_recognition_authority);
}

#[test]
fn semantic_permutations_seal_and_compile_byte_identically() {
    let canonical = fixture();
    let canonical_envelope = compile_runtime_closure(&canonical).unwrap();
    let mut permuted = canonical.clone();
    permuted.material_nodes.reverse();
    permuted.prerequisites.reverse();
    permuted.producer_edges.reverse();
    permuted.request_digest = digest('0');
    let resealed = seal_runtime_closure_request(permuted).expect("permutation reseal");
    assert_eq!(resealed, canonical);
    assert_eq!(
        compile_runtime_closure(&resealed).unwrap(),
        canonical_envelope
    );
}

#[test]
fn revision_0_2_has_exact_eleven_prerequisite_kinds() {
    let kinds = [
        RuntimeClosurePrerequisiteKind::HostOperatingSystem,
        RuntimeClosurePrerequisiteKind::Architecture,
        RuntimeClosurePrerequisiteKind::Hardware,
        RuntimeClosurePrerequisiteKind::Driver,
        RuntimeClosurePrerequisiteKind::Firmware,
        RuntimeClosurePrerequisiteKind::Toolchain,
        RuntimeClosurePrerequisiteKind::Transport,
        RuntimeClosurePrerequisiteKind::Network,
        RuntimeClosurePrerequisiteKind::ArtifactReservoir,
        RuntimeClosurePrerequisiteKind::ExternalCustody,
        RuntimeClosurePrerequisiteKind::OperatorAcceptance,
    ];
    assert_eq!(kinds.len(), 11);
    assert_eq!(
        serde_json::to_string(&kinds).unwrap(),
        "[\"host_operating_system\",\"architecture\",\"hardware\",\"driver\",\"firmware\",\"toolchain\",\"transport\",\"network\",\"artifact_reservoir\",\"external_custody\",\"operator_acceptance\"]"
    );
}

#[test]
fn strict_machine_form_refuses_revision_0_1_unknown_duplicate_whitespace_and_trailing() {
    let machine = to_runtime_closure_request_machine_form(&fixture()).unwrap();
    assert_eq!(
        from_runtime_closure_request_machine_form(&machine).unwrap(),
        fixture()
    );

    let revision = machine.replacen(
        "cantor-runtime-closure-request/0.2",
        "cantor-runtime-closure-request/0.1",
        1,
    );
    assert_eq!(
        from_runtime_closure_request_machine_form(&revision)
            .unwrap_err()
            .code,
        RuntimeClosureFaultCode::InvalidProfile
    );
    let unknown = machine.replacen('{', "{\"unknown\":true,", 1);
    assert_eq!(
        from_runtime_closure_request_machine_form(&unknown)
            .unwrap_err()
            .code,
        RuntimeClosureFaultCode::InvalidMachineForm
    );
    let duplicate = machine.replacen(
        '{',
        "{\"profile\":\"cantor-runtime-closure-request/0.2\",",
        1,
    );
    assert_eq!(
        from_runtime_closure_request_machine_form(&duplicate)
            .unwrap_err()
            .code,
        RuntimeClosureFaultCode::InvalidMachineForm
    );
    let duplicate_input = machine.replacen(
        "\"inputs\":[\"material:10000000-0000-4000-8000-000000000001\",",
        "\"inputs\":[\"material:10000000-0000-4000-8000-000000000001\",\"material:10000000-0000-4000-8000-000000000001\",",
        1,
    );
    assert_eq!(
        from_runtime_closure_request_machine_form(&duplicate_input)
            .unwrap_err()
            .code,
        RuntimeClosureFaultCode::InvalidMachineForm
    );
    let unknown_prerequisite_kind =
        machine.replacen("\"host_operating_system\"", "\"unknown_kind\"", 1);
    assert_eq!(
        from_runtime_closure_request_machine_form(&unknown_prerequisite_kind)
            .unwrap_err()
            .code,
        RuntimeClosureFaultCode::InvalidMachineForm
    );
    let whitespace = machine.replacen('{', "{ ", 1);
    assert_eq!(
        from_runtime_closure_request_machine_form(&whitespace)
            .unwrap_err()
            .code,
        RuntimeClosureFaultCode::InvalidMachineForm
    );
    assert_eq!(
        from_runtime_closure_request_machine_form(&(machine + "\n"))
            .unwrap_err()
            .code,
        RuntimeClosureFaultCode::InvalidMachineForm
    );
}

#[test]
fn logical_targets_refuse_traversal_device_case_drive_backslash_and_collision() {
    for target in [
        "../escape",
        "bin/../escape",
        "bin/Con.exe",
        "bin/con.exe",
        "c:/cantor.exe",
        "bin\\cantor.exe",
        "/bin/cantor.exe",
        "bin/cantor.exe/",
    ] {
        let mut request = fixture();
        request.material_nodes[0].target = target.to_owned();
        assert_eq!(
            seal_runtime_closure_request(request).unwrap_err().code,
            RuntimeClosureFaultCode::InvalidTarget,
            "target {target:?}"
        );
    }
    let mut collision = fixture();
    collision.material_nodes[1].target = collision.material_nodes[0].target.clone();
    assert_eq!(
        seal_runtime_closure_request(collision).unwrap_err().code,
        RuntimeClosureFaultCode::InvalidTarget
    );
}

#[test]
fn graph_refuses_missing_duplicate_cycle_root_and_output_mismatch() {
    let mut missing = fixture();
    missing.producer_edges.pop();
    assert_eq!(
        seal_runtime_closure_request(missing).unwrap_err().code,
        RuntimeClosureFaultCode::InvalidBound
    );

    let mut duplicate = fixture();
    duplicate.producer_edges[1].output = duplicate.producer_edges[0].output.clone();
    assert_eq!(
        seal_runtime_closure_request(duplicate).unwrap_err().code,
        RuntimeClosureFaultCode::InvalidProducer
    );

    let mut cycle = fixture();
    let launcher = cycle.producer_edges[2].output.clone();
    cycle.producer_edges[0].inputs = [launcher].into_iter().collect();
    assert_eq!(
        seal_runtime_closure_request(cycle).unwrap_err().code,
        RuntimeClosureFaultCode::InvalidGraph
    );

    let mut root = fixture();
    root.producer_edges[0].output = root.bootstrap_runtime.node_id.clone();
    assert_eq!(
        seal_runtime_closure_request(root).unwrap_err().code,
        RuntimeClosureFaultCode::InvalidProducer
    );

    let mut mismatch = fixture();
    mismatch.producer_edges[0].expected_bytes += 1;
    assert_eq!(
        seal_runtime_closure_request(mismatch).unwrap_err().code,
        RuntimeClosureFaultCode::InvalidProducer
    );
}

#[test]
fn ambient_source_mutable_locator_and_secret_material_refuse() {
    for reference in [
        "source:latest",
        "ambient:path-lookup",
        "cache:sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    ] {
        let mut request = fixture();
        request.producer_edges[0].source.immutable_ref = sid(reference);
        assert_eq!(
            seal_runtime_closure_request(request).unwrap_err().code,
            RuntimeClosureFaultCode::InvalidSource
        );
    }
    let mut secret = fixture();
    secret.prerequisites[0].reference = sid("secret-value:embedded-material");
    assert_eq!(
        seal_runtime_closure_request(secret).unwrap_err().code,
        RuntimeClosureFaultCode::InvalidPrerequisite
    );
}

#[test]
fn acquired_and_explicitly_supplied_material_preserve_distinct_source_kinds() {
    let mut request = fixture();
    let root = request.installation_sop.node_id.clone();
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
    request.producer_edges.push(new_edge(
        1,
        root.clone(),
        &acquired,
        RuntimeClosureSourceKind::ContentAddressedArtifact,
        "artifact",
    ));
    request.producer_edges.push(new_edge(
        2,
        root,
        &supplied,
        RuntimeClosureSourceKind::SuppliedDescriptor,
        "supplied",
    ));
    request.material_nodes.extend([acquired, supplied]);
    request.request_digest = digest('0');
    let sealed = seal_runtime_closure_request(request).expect("extended material graph");
    assert_eq!(
        compile_runtime_closure(&sealed)
            .unwrap()
            .plan
            .material_nodes
            .len(),
        7
    );
}

#[test]
fn source_kind_laundering_refuses() {
    let mut request = fixture();
    request.producer_edges[0].source.kind = RuntimeClosureSourceKind::ContentAddressedArtifact;
    assert_eq!(
        seal_runtime_closure_request(request).unwrap_err().code,
        RuntimeClosureFaultCode::InvalidSource
    );
}

#[test]
fn collection_and_byte_bounds_refuse_without_overflow() {
    let mut prerequisites = fixture();
    prerequisites.prerequisites.clear();
    for index in 0..129_u32 {
        prerequisites
            .prerequisites
            .push(RuntimeClosurePrerequisite {
                prerequisite_id: sid(&format!(
                    "prerequisite:80000000-0000-4000-8000-{index:012x}"
                )),
                kind: RuntimeClosurePrerequisiteKind::Architecture,
                reference: sid("architecture:synthetic"),
                disposition: RuntimeClosurePrerequisiteDisposition::RequiredUnresolved,
                unresolved_reason: "bounded refusal fixture".to_owned(),
            });
    }
    assert_eq!(
        seal_runtime_closure_request(prerequisites)
            .unwrap_err()
            .code,
        RuntimeClosureFaultCode::InvalidBound
    );

    let mut compatibility = fixture();
    compatibility.material_nodes[0].compatibility_refs = (0..33_u32)
        .map(|index| sid(&format!("compatibility:profile-{index:02}")))
        .collect();
    assert_eq!(
        seal_runtime_closure_request(compatibility)
            .unwrap_err()
            .code,
        RuntimeClosureFaultCode::InvalidBound
    );

    let mut bytes = fixture();
    bytes.bootstrap_runtime.expected_bytes = 1_099_511_627_776;
    let bootstrap = bytes.bootstrap_runtime.node_id.clone();
    bytes
        .material_nodes
        .iter_mut()
        .find(|node| node.node_id == bootstrap)
        .unwrap()
        .expected_bytes = 1_099_511_627_776;
    assert_eq!(
        seal_runtime_closure_request(bytes).unwrap_err().code,
        RuntimeClosureFaultCode::InvalidBound
    );

    let overbound = " ".repeat(RUNTIME_CLOSURE_MAX_MACHINE_FORM_BYTES + 1);
    assert_eq!(
        from_runtime_closure_request_machine_form(&overbound)
            .unwrap_err()
            .code,
        RuntimeClosureFaultCode::InvalidMachineForm
    );
}

#[test]
fn identity_collision_and_root_correspondence_refuse() {
    let mut collision = fixture();
    collision.closure_id = collision.request_id.clone();
    assert_eq!(
        seal_runtime_closure_request(collision).unwrap_err().code,
        RuntimeClosureFaultCode::IdentityCollision
    );

    let mut root = fixture();
    root.bootstrap_runtime.expected_bytes += 1;
    assert_eq!(
        seal_runtime_closure_request(root).unwrap_err().code,
        RuntimeClosureFaultCode::InvalidRoot
    );
}

#[test]
fn exact_capability_denials_are_complete_and_nonoverlapping() {
    let denials = runtime_closure_required_capability_denials();
    assert_eq!(denials.len(), 25);
    for denial in [
        RuntimeClosureCapabilityDenial::FilesystemRead,
        RuntimeClosureCapabilityDenial::ProcessSpawn,
        RuntimeClosureCapabilityDenial::ArtifactDownload,
        RuntimeClosureCapabilityDenial::ProviderContact,
        RuntimeClosureCapabilityDenial::ModelLoad,
        RuntimeClosureCapabilityDenial::SecretAccess,
        RuntimeClosureCapabilityDenial::ServiceActivation,
        RuntimeClosureCapabilityDenial::RemoteAccess,
        RuntimeClosureCapabilityDenial::HardwareEffect,
        RuntimeClosureCapabilityDenial::ExternalEffect,
    ] {
        assert!(denials.contains(&denial));
    }
}

#[test]
fn evidence_bundle_double_replays_and_raw_argument_tamper_refuses() {
    let request = fixture();
    let bundle = build_runtime_closure_evidence_bundle(&request).expect("evidence bundle");
    let machine = to_runtime_closure_evidence_bundle_machine_form(&bundle).unwrap();
    let restored = from_runtime_closure_evidence_bundle_machine_form(&machine).unwrap();
    let verification = verify_runtime_closure_evidence_bundle(&restored).unwrap();
    assert_eq!(verification.material_node_count, 5);
    assert_eq!(verification.effects, Default::default());

    let mut tampered = bundle;
    tampered.request_file =
        tampered
            .request_file
            .replacen(&request.request_digest.value, &"f".repeat(64), 1);
    assert!(verify_runtime_closure_evidence_bundle(&tampered).is_err());
}

#[test]
fn fully_redigested_receipt_and_authority_tamper_refuse() {
    let request = fixture();
    let mut receipt_tamper = compile_runtime_closure(&request).unwrap();
    receipt_tamper
        .plan
        .expected_receipt
        .installation_state_asserted = true;
    receipt_tamper.plan.expected_receipt.receipt_template_digest =
        expected_installation_receipt_digest(&receipt_tamper.plan.expected_receipt).unwrap();
    receipt_tamper.plan.plan_digest = runtime_closure_plan_digest(&receipt_tamper.plan).unwrap();
    receipt_tamper.envelope_digest = runtime_closure_envelope_digest(&receipt_tamper).unwrap();
    assert_eq!(
        validate_runtime_closure_envelope(&receipt_tamper)
            .unwrap_err()
            .code,
        RuntimeClosureFaultCode::InvalidReceipt
    );

    let mut authority_tamper = compile_runtime_closure(&request).unwrap();
    authority_tamper
        .plan
        .capability_denials
        .remove(&RuntimeClosureCapabilityDenial::FilesystemWrite);
    authority_tamper.plan.plan_digest =
        runtime_closure_plan_digest(&authority_tamper.plan).unwrap();
    authority_tamper.envelope_digest = runtime_closure_envelope_digest(&authority_tamper).unwrap();
    assert_eq!(
        validate_runtime_closure_envelope(&authority_tamper)
            .unwrap_err()
            .code,
        RuntimeClosureFaultCode::InvalidAuthority
    );
}

#[test]
fn evidence_manifest_semantic_and_raw_tamper_refuse() {
    let mut bundle = build_runtime_closure_evidence_bundle(&fixture()).unwrap();
    bundle.manifest_file = bundle.manifest_file.replacen(
        "\"prerequisite_kind_count\":11",
        "\"prerequisite_kind_count\":9",
        1,
    );
    assert!(verify_runtime_closure_evidence_bundle(&bundle).is_err());

    let mut raw = build_runtime_closure_evidence_bundle(&fixture()).unwrap();
    raw.envelope_file.insert(0, ' ');
    assert!(verify_runtime_closure_evidence_bundle(&raw).is_err());
}
