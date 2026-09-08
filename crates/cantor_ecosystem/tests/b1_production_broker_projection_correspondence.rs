//! Full A8 retained replay over the published A7 evidence; no broker contact or effects.
use cantor_core::{ContentDigest, sha256_bytes};
use cantor_ecosystem::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

const CLI: &str = env!("CARGO_BIN_EXE_cantor-b1-production-broker-projection-verify");
const EVIDENCE_CLI: &str =
    env!("CARGO_BIN_EXE_cantor-b1-production-broker-projection-evidence-verify");
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn empty() -> ContentDigest {
    sha256_bytes(b"")
}

fn retained<T: DeserializeOwned>(path: &Path) -> T {
    let bytes = fs::read(path).unwrap();
    serde_json::from_slice(bytes.strip_suffix(b"\n").unwrap()).unwrap()
}

fn line<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}

fn alter_scalar(value: &Value) -> Value {
    match value {
        Value::Bool(inner) => json!(!inner),
        Value::Number(number) => json!(number.as_u64().unwrap() + 1),
        Value::String(text) => json!(format!("{text}_tampered")),
        Value::Array(values) if values.is_empty() => json!(["packet_mismatch"]),
        Value::Array(_) => json!([]),
        Value::Object(object) if object.contains_key("algorithm") => {
            json!(sha256_bytes(b"changed-digest"))
        }
        _ => panic!("explicit structured mutation required"),
    }
}

fn write_json_value(path: &Path, value: &Value) {
    fs::write(path, line(value)).unwrap();
}

fn temporary(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "cantor-pbpc-{label}-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}

fn a7_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence",
    )
}

fn explicit_paths(root: &Path) -> Vec<PathBuf> {
    const INDICES: [usize; 30] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        26, 27, 28, 30, 31,
    ];
    INDICES
        .into_iter()
        .map(|index| root.join(PBPC_EVIDENCE_FILES[index]))
        .collect()
}

fn fixture_forms(
    root: &Path,
    input_class: KcvInputClass,
) -> (PbpcProjectionDeclaration, PbpcVerificationRequest) {
    let a6_request: EocvVerificationRequest = retained(&root.join("a6_verification_request.json"));
    let a7_request: PercVerificationRequest = retained(&root.join("a7_verification_request.json"));
    let a7_receipt: PercVerificationReceipt = retained(&root.join("a7_receipt.json"));
    let mut a7_descriptor = B1OaprCandidateDescriptor {
        ordinal: 7,
        candidate_uuid: a7_request.expected_candidate_uuid.clone(),
        authority_name: a7_request.expected_authority_name.clone(),
        artifact_kind: a7_request.expected_artifact_kind.clone(),
        origin: B1OaprCandidateOrigin::DeterministicFixtureCandidate,
        opaque_reference: a7_request.expected_opaque_reference.clone(),
        content_sha256: a7_request.expected_content_sha256.clone(),
        declared_bytes: a7_request.expected_declared_bytes,
        confidentiality: a7_request.expected_confidentiality,
        required_verifier_profile: a7_request.expected_verifier_profile.clone(),
        fixture_only: a7_request.expected_fixture_only,
        dependency_ordinal: Some(a7_request.expected_dependency_ordinal),
        descriptor_sha256: empty(),
    };
    a7_descriptor.descriptor_sha256 = b1oapr_descriptor_digest(&a7_descriptor).unwrap();
    assert_eq!(
        a7_descriptor.descriptor_sha256,
        a7_request.expected_descriptor_sha256
    );
    let mut packet_request = a6_request.authority_packet_request.clone();
    packet_request.descriptors[6] = a7_descriptor;
    packet_request.request_sha256 = b1oapr_request_digest(&packet_request).unwrap();
    assert_eq!(
        packet_request.request_sha256,
        a7_request.authority_packet_request_sha256
    );

    let selected = packet_request.descriptors[7].clone();
    let mut projection = PbpcProjectionDeclaration {
        profile: PBPC_DECLARATION_PROFILE.to_owned(),
        projection_uuid: "a8000000-0000-4000-8000-000000000001".to_owned(),
        a7_receipt_sha256: a7_receipt.receipt_sha256.clone(),
        preparation_plan_sha256: a6_request.preparation_plan_sha256.clone(),
        candidate_uuid: selected.candidate_uuid.clone(),
        authority_name: selected.authority_name.clone(),
        artifact_kind: selected.artifact_kind.clone(),
        opaque_reference: selected.opaque_reference.clone(),
        content_sha256: selected.content_sha256.clone(),
        declared_bytes: selected.declared_bytes,
        confidentiality: selected.confidentiality,
        required_verifier_profile: selected.required_verifier_profile.clone(),
        fixture_only: input_class == KcvInputClass::DeterministicFixtureCandidate,
        dependency_ordinal: selected.dependency_ordinal.unwrap(),
        input_class,
        broker_adapter_profile: "cantor-production-broker-adapter/0.1".to_owned(),
        broker_operation_kind: "project_preparation_contract".to_owned(),
        broker_subject: "cantor_b1_cdrive_production_preparation_p0".to_owned(),
        required_input_receipt_profile: PERC_RECEIPT_PROFILE.to_owned(),
        expected_output_receipt_profile: PBPC_RECEIPT_PROFILE.to_owned(),
        requires_private_permit: true,
        activation_requested: false,
        evidence_references: vec!["a8_fixture_evidence".to_owned()],
        projection_sha256: empty(),
    };
    projection.projection_sha256 = pbpc_declaration_digest(&projection).unwrap();
    let raw_projection = serde_json::to_vec(&projection).unwrap();

    let mut a8_descriptor = selected;
    a8_descriptor.origin = if input_class == KcvInputClass::DeterministicFixtureCandidate {
        B1OaprCandidateOrigin::DeterministicFixtureCandidate
    } else {
        B1OaprCandidateOrigin::ExternallySuppliedCandidate
    };
    a8_descriptor.fixture_only = projection.fixture_only;
    a8_descriptor.descriptor_sha256 = empty();
    a8_descriptor.descriptor_sha256 = b1oapr_descriptor_digest(&a8_descriptor).unwrap();
    packet_request.descriptors[7] = a8_descriptor.clone();
    packet_request.request_sha256 = b1oapr_request_digest(&packet_request).unwrap();
    let packet = compile_b1oapr_packet(&packet_request).unwrap();

    let mut request = PbpcVerificationRequest {
        profile: PBPC_REQUEST_PROFILE.to_owned(),
        source_snapshot_uuid: PBPC_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: PBPC_CANONICAL_UUID.to_owned(),
        signature_uuid: PBPC_SIGNATURE_UUID.to_owned(),
        source_custody_commit: PBPC_SOURCE_CUSTODY_COMMIT.to_owned(),
        source_bookend_commit: PBPC_SOURCE_BOOKEND_COMMIT.to_owned(),
        formation_commit: PBPC_FORMATION_COMMIT.to_owned(),
        formation_bookend_commit: PBPC_FORMATION_BOOKEND_COMMIT.to_owned(),
        a7_implementation_commit: PBPC_A7_IMPLEMENTATION_COMMIT.to_owned(),
        a7_bookend_commit: PBPC_A7_BOOKEND_COMMIT.to_owned(),
        a7_proof_uuid: PBPC_A7_PROOF_UUID.to_owned(),
        a7_verification_request_sha256: a7_request.request_sha256.clone(),
        expected_a7_receipt_sha256: a7_receipt.receipt_sha256.clone(),
        authority_packet_request_sha256: packet_request.request_sha256.clone(),
        expected_authority_packet_sha256: packet.packet_sha256,
        expected_candidate_uuid: projection.candidate_uuid.clone(),
        expected_descriptor_sha256: a8_descriptor.descriptor_sha256,
        expected_projection_uuid: projection.projection_uuid.clone(),
        expected_projection_bytes: raw_projection.len() as u64,
        expected_projection_raw_sha256: sha256_bytes(&raw_projection),
        expected_projection_sha256: projection.projection_sha256.clone(),
        expected_authority_name: projection.authority_name.clone(),
        expected_artifact_kind: projection.artifact_kind.clone(),
        expected_opaque_reference: projection.opaque_reference.clone(),
        expected_content_sha256: projection.content_sha256.clone(),
        expected_declared_bytes: projection.declared_bytes,
        expected_confidentiality: projection.confidentiality,
        expected_verifier_profile: projection.required_verifier_profile.clone(),
        expected_fixture_only: projection.fixture_only,
        expected_dependency_ordinal: projection.dependency_ordinal,
        input_class: projection.input_class,
        expected_preparation_plan_sha256: projection.preparation_plan_sha256.clone(),
        expected_broker_adapter_profile: projection.broker_adapter_profile.clone(),
        expected_broker_operation_kind: projection.broker_operation_kind.clone(),
        expected_broker_subject: projection.broker_subject.clone(),
        expected_input_receipt_profile: projection.required_input_receipt_profile.clone(),
        expected_output_receipt_profile: projection.expected_output_receipt_profile.clone(),
        expected_requires_private_permit: true,
        expected_activation_requested: false,
        evidence_references: projection.evidence_references.clone(),
        maximum_attempts: 1,
        automatic_retry_count: 0,
        automatic_cleanup_count: 0,
        request_sha256: empty(),
    };
    request.request_sha256 = pbpc_request_digest(&request).unwrap();
    (projection, request)
}

fn write_evidence(root: &Path, input_class: KcvInputClass) {
    write_evidence_with_a7_status(root, input_class, false);
}

fn write_evidence_with_a7_status(root: &Path, input_class: KcvInputClass, mismatched_a7: bool) {
    fs::create_dir(root).expect("fresh caller-owned A8 evidence root");
    let source = a7_root();
    for name in PERC_EVIDENCE_FILES {
        let destination = match name {
            "verification_request.json" => "a7_verification_request.json",
            "receipt.json" => "a7_receipt.json",
            "evidence_manifest.json" => "a7_evidence_manifest.json",
            other => other,
        };
        fs::copy(source.join(name), root.join(destination)).unwrap();
    }
    if mismatched_a7 {
        rebind_a7_as_mismatch(root);
    }
    let (projection, request) = fixture_forms(root, input_class);
    fs::write(
        root.join("broker_projection_declaration.json"),
        line(&projection),
    )
    .unwrap();
    fs::write(root.join("verification_request.json"), line(&request)).unwrap();
    let receipt_text = verify_pbpc_payload_paths(&explicit_paths(root)).unwrap();
    let receipt: PbpcVerificationReceipt = serde_json::from_str(&receipt_text).unwrap();
    fs::write(root.join("receipt.json"), line(&receipt)).unwrap();
    let artifacts = PBPC_EVIDENCE_FILES[..33]
        .iter()
        .map(|name| {
            let bytes = fs::read(root.join(name)).unwrap();
            PbpcEvidenceArtifact {
                path: (*name).to_owned(),
                bytes: bytes.len() as u64,
                sha256: sha256_bytes(&bytes),
            }
        })
        .collect::<Vec<_>>();
    let mut manifest = PbpcEvidenceManifest {
        profile: PBPC_EVIDENCE_PROFILE.to_owned(),
        manifest_uuid: "a8000000-0000-4000-8000-000000000002".to_owned(),
        source_snapshot_uuid: PBPC_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: PBPC_CANONICAL_UUID.to_owned(),
        total_artifact_bytes: artifacts.iter().map(|artifact| artifact.bytes).sum(),
        artifacts,
        artifact_count: 33,
        retained_authority_packet_sha256: receipt.authority_packet_sha256.clone(),
        retained_a7_receipt_sha256: receipt.a7_receipt_sha256.clone(),
        retained_projection_declaration_sha256: receipt.projection_declaration_sha256.clone(),
        retained_receipt_sha256: receipt.receipt_sha256.clone(),
        deterministic_replay_count: 2,
        required_fresh_process_replay_count: 2,
        byte_identical: true,
        effect_count: 0,
        manifest_sha256: empty(),
    };
    manifest.manifest_sha256 = pbpc_evidence_manifest_digest(&manifest).unwrap();
    fs::write(root.join("evidence_manifest.json"), line(&manifest)).unwrap();
}

fn rebind_a7_as_mismatch(root: &Path) {
    let a6_request: EocvVerificationRequest = retained(&root.join("a6_verification_request.json"));
    let mut a7_request: PercVerificationRequest =
        retained(&root.join("a7_verification_request.json"));
    a7_request.expected_opaque_reference = "alternate_a7_reference".to_owned();
    let fixture = a7_request.input_class == KcvInputClass::DeterministicFixtureCandidate;
    let mut descriptor = B1OaprCandidateDescriptor {
        ordinal: 7,
        candidate_uuid: a7_request.expected_candidate_uuid.clone(),
        authority_name: a7_request.expected_authority_name.clone(),
        artifact_kind: a7_request.expected_artifact_kind.clone(),
        origin: if fixture {
            B1OaprCandidateOrigin::DeterministicFixtureCandidate
        } else {
            B1OaprCandidateOrigin::ExternallySuppliedCandidate
        },
        opaque_reference: a7_request.expected_opaque_reference.clone(),
        content_sha256: a7_request.expected_content_sha256.clone(),
        declared_bytes: a7_request.expected_declared_bytes,
        confidentiality: a7_request.expected_confidentiality,
        required_verifier_profile: a7_request.expected_verifier_profile.clone(),
        fixture_only: a7_request.expected_fixture_only,
        dependency_ordinal: Some(a7_request.expected_dependency_ordinal),
        descriptor_sha256: empty(),
    };
    descriptor.descriptor_sha256 = b1oapr_descriptor_digest(&descriptor).unwrap();
    a7_request.expected_descriptor_sha256 = descriptor.descriptor_sha256.clone();
    let mut packet_request = a6_request.authority_packet_request.clone();
    packet_request.descriptors[6] = descriptor;
    packet_request.request_sha256 = b1oapr_request_digest(&packet_request).unwrap();
    a7_request.authority_packet_request_sha256 = packet_request.request_sha256.clone();
    a7_request.expected_authority_packet_sha256 = compile_b1oapr_packet(&packet_request)
        .unwrap()
        .packet_sha256;
    a7_request.request_sha256 = perc_request_digest(&a7_request).unwrap();
    fs::write(root.join("a7_verification_request.json"), line(&a7_request)).unwrap();

    let a7_paths = [&PERC_EVIDENCE_FILES[..25], &PERC_EVIDENCE_FILES[26..28]]
        .concat()
        .into_iter()
        .map(|name| {
            let renamed = match name {
                "verification_request.json" => "a7_verification_request.json",
                "receipt.json" => "a7_receipt.json",
                "evidence_manifest.json" => "a7_evidence_manifest.json",
                other => other,
            };
            root.join(renamed)
        })
        .collect::<Vec<_>>();
    let receipt_text = verify_perc_payload_paths(&a7_paths).unwrap();
    let receipt: PercVerificationReceipt = serde_json::from_str(&receipt_text).unwrap();
    assert_eq!(receipt.status, PERC_MISMATCHED_STATUS);
    fs::write(root.join("a7_receipt.json"), line(&receipt)).unwrap();
}

fn rehash_manifest(root: &Path) {
    let mut manifest: PbpcEvidenceManifest = retained(&root.join("evidence_manifest.json"));
    for artifact in &mut manifest.artifacts {
        let bytes = fs::read(root.join(&artifact.path)).unwrap();
        artifact.bytes = bytes.len() as u64;
        artifact.sha256 = sha256_bytes(&bytes);
    }
    manifest.total_artifact_bytes = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.bytes)
        .sum();
    manifest.manifest_sha256 = pbpc_evidence_manifest_digest(&manifest).unwrap();
    fs::write(root.join("evidence_manifest.json"), line(&manifest)).unwrap();
}

fn rehash_manifest_with_receipt(root: &Path, receipt_sha256: Option<ContentDigest>) {
    let mut manifest: PbpcEvidenceManifest = retained(&root.join("evidence_manifest.json"));
    for artifact in &mut manifest.artifacts {
        let bytes = fs::read(root.join(&artifact.path)).unwrap();
        artifact.bytes = bytes.len() as u64;
        artifact.sha256 = sha256_bytes(&bytes);
    }
    manifest.total_artifact_bytes = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.bytes)
        .sum();
    if let Some(digest) = receipt_sha256 {
        manifest.retained_receipt_sha256 = digest;
    }
    manifest.manifest_sha256 = pbpc_evidence_manifest_digest(&manifest).unwrap();
    fs::write(root.join("evidence_manifest.json"), line(&manifest)).unwrap();
}

fn rehash_manifest_with_a7_receipt(root: &Path, a7_receipt_sha256: ContentDigest) {
    let mut manifest: PbpcEvidenceManifest = retained(&root.join("evidence_manifest.json"));
    for artifact in &mut manifest.artifacts {
        let bytes = fs::read(root.join(&artifact.path)).unwrap();
        artifact.bytes = bytes.len() as u64;
        artifact.sha256 = sha256_bytes(&bytes);
    }
    manifest.total_artifact_bytes = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.bytes)
        .sum();
    manifest.retained_a7_receipt_sha256 = a7_receipt_sha256;
    manifest.manifest_sha256 = pbpc_evidence_manifest_digest(&manifest).unwrap();
    fs::write(root.join("evidence_manifest.json"), line(&manifest)).unwrap();
}

#[test]
fn independent_directory_and_explicit_clis_replay_exact_nonauthorizing_receipt() {
    let root = temporary("replay");
    write_evidence(&root, KcvInputClass::DeterministicFixtureCandidate);
    let replay = verify_pbpc_evidence_directory(&root).unwrap();
    assert_eq!(replay.manifest.artifacts.len(), 33);
    assert_eq!(replay.manifest.artifact_count, 33);
    assert_eq!(replay.deterministic_replay_count, 2);
    assert!(replay.byte_identical);
    assert!(
        replay
            .receipt
            .production_broker_projection_correspondence_proved
    );
    assert!(!replay.receipt.private_execution_permit_present);
    assert!(!replay.receipt.broker_endpoint_resolved);
    assert!(!replay.receipt.execution_authorized);
    assert_eq!(replay.receipt.effect_account, TwvEffectAccount::default());

    let directory_output = Command::new(EVIDENCE_CLI).arg(&root).output().unwrap();
    assert!(
        directory_output.status.success(),
        "{:?}",
        directory_output.stderr
    );
    assert!(directory_output.stderr.is_empty());
    assert_eq!(directory_output.stdout, line(&replay.receipt));

    let paths = explicit_paths(&root);
    assert_eq!(
        verify_pbpc_payload_paths(&paths).unwrap(),
        replay.receipt_machine_form
    );
    let explicit_output = Command::new(CLI).args(&paths).output().unwrap();
    assert!(
        explicit_output.status.success(),
        "{:?}",
        explicit_output.stderr
    );
    assert!(explicit_output.stderr.is_empty());
    assert_eq!(explicit_output.stdout, line(&replay.receipt));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn both_a7_statuses_are_preserved_without_a8_authority_promotion() {
    let root = temporary("a7-mismatch");
    write_evidence_with_a7_status(&root, KcvInputClass::DeterministicFixtureCandidate, true);
    let replay = verify_pbpc_evidence_directory(&root).unwrap();
    assert_eq!(replay.receipt.a7_receipt.status, PERC_MISMATCHED_STATUS);
    assert!(
        !replay
            .receipt
            .a7_receipt
            .correspondence_account
            .all_correspondence_matches
    );
    assert!(
        replay
            .receipt
            .production_broker_projection_correspondence_proved
    );
    assert!(!replay.receipt.production_authority_claimed);
    assert!(!replay.receipt.private_execution_permit_present);
    assert!(!replay.receipt.permit_material_authenticated);
    assert!(!replay.receipt.permit_dependency_satisfied);
    assert!(!replay.receipt.broker_endpoint_resolved);
    assert!(!replay.receipt.broker_reachable);
    assert!(!replay.receipt.broker_identity_proved);
    assert!(!replay.receipt.broker_authority_proved);
    assert!(!replay.receipt.broker_session_authenticated);
    assert!(!replay.receipt.broker_activation_authorized);
    assert!(!replay.receipt.production_broker_projection_present);
    assert!(!replay.receipt.live_authorization_admitted);
    assert!(!replay.receipt.physical_preparation_authorized);
    assert!(!replay.receipt.ready_for_physical_execution);
    assert!(!replay.receipt.execution_authorized);
    assert_eq!(replay.receipt.effect_account, TwvEffectAccount::default());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn evidence_membership_and_explicit_arity_refuse() {
    let extra = temporary("extra");
    write_evidence(&extra, KcvInputClass::DeterministicFixtureCandidate);
    fs::write(extra.join("extra.json"), b"{}\n").unwrap();
    assert_eq!(
        verify_pbpc_evidence_directory(&extra).unwrap_err().code,
        EocvFaultCode::Evidence
    );
    fs::remove_dir_all(extra).unwrap();

    let missing = temporary("missing");
    write_evidence(&missing, KcvInputClass::DeterministicFixtureCandidate);
    fs::remove_file(missing.join("a7_receipt.json")).unwrap();
    assert_eq!(
        verify_pbpc_evidence_directory(&missing).unwrap_err().code,
        EocvFaultCode::Evidence
    );
    let mut paths = explicit_paths(&missing);
    paths.pop();
    assert_eq!(
        verify_pbpc_payload_paths(&paths).unwrap_err().code,
        EocvFaultCode::Path
    );
    fs::remove_dir_all(missing).unwrap();
}

#[test]
fn external_class_and_rehashed_false_retained_identity_remain_nonauthorizing() {
    let external = temporary("external");
    write_evidence(&external, KcvInputClass::ExternallySuppliedCandidate);
    let replay = verify_pbpc_evidence_directory(&external).unwrap();
    assert_eq!(
        replay.receipt.input_class,
        KcvInputClass::ExternallySuppliedCandidate
    );
    assert!(!replay.receipt.fixture_only);
    assert!(!replay.receipt.production_authority_claimed);
    assert!(!replay.receipt.execution_authorized);
    fs::remove_dir_all(external).unwrap();

    let restart = temporary("restart");
    write_evidence(&restart, KcvInputClass::DeterministicFixtureCandidate);
    let mut receipt: PbpcVerificationReceipt = retained(&restart.join("receipt.json"));
    receipt.broker_activation_authorized = true;
    receipt.receipt_sha256 = pbpc_receipt_digest(&receipt).unwrap();
    fs::write(restart.join("receipt.json"), line(&receipt)).unwrap();
    let mut manifest: PbpcEvidenceManifest = retained(&restart.join("evidence_manifest.json"));
    manifest.retained_receipt_sha256 = receipt.receipt_sha256.clone();
    manifest.manifest_sha256 = pbpc_evidence_manifest_digest(&manifest).unwrap();
    fs::write(restart.join("evidence_manifest.json"), line(&manifest)).unwrap();
    rehash_manifest(&restart);
    assert!(matches!(
        verify_pbpc_evidence_directory(&restart).unwrap_err().code,
        EocvFaultCode::Truth | EocvFaultCode::Restart
    ));
    fs::remove_dir_all(restart).unwrap();
}

#[test]
fn every_a8_declaration_request_and_receipt_field_tamper_refuses_after_outer_rehash() {
    let root = temporary("every-field");
    write_evidence(&root, KcvInputClass::DeterministicFixtureCandidate);

    let declaration_path = root.join("broker_projection_declaration.json");
    let original_declaration = fs::read(&declaration_path).unwrap();
    let declaration_value: Value = serde_json::from_slice(&original_declaration).unwrap();
    let declaration_fields = declaration_value
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(declaration_fields.len(), 24);
    for field in &declaration_fields {
        let mut changed = declaration_value.clone();
        changed[field] = alter_scalar(&changed[field]);
        if let Ok(mut typed) = serde_json::from_value::<PbpcProjectionDeclaration>(changed.clone())
        {
            if field != "projection_sha256" {
                typed.projection_sha256 = pbpc_declaration_digest(&typed).unwrap();
            }
            changed = serde_json::to_value(typed).unwrap();
        }
        write_json_value(&declaration_path, &changed);
        rehash_manifest(&root);
        assert!(
            verify_pbpc_evidence_directory(&root).is_err(),
            "declaration {field}"
        );
        fs::write(&declaration_path, &original_declaration).unwrap();
        rehash_manifest(&root);
    }

    let request_path = root.join("verification_request.json");
    let original_request = fs::read(&request_path).unwrap();
    let request_value: Value = serde_json::from_slice(&original_request).unwrap();
    let request_fields = request_value
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(request_fields.len(), 44);
    for field in &request_fields {
        let mut changed = request_value.clone();
        changed[field] = alter_scalar(&changed[field]);
        if let Ok(mut typed) = serde_json::from_value::<PbpcVerificationRequest>(changed.clone()) {
            if field != "request_sha256" {
                typed.request_sha256 = pbpc_request_digest(&typed).unwrap();
            }
            changed = serde_json::to_value(typed).unwrap();
        }
        write_json_value(&request_path, &changed);
        rehash_manifest(&root);
        assert!(
            verify_pbpc_evidence_directory(&root).is_err(),
            "request {field}"
        );
        fs::write(&request_path, &original_request).unwrap();
        rehash_manifest(&root);
    }

    let receipt_path = root.join("receipt.json");
    let original_receipt = fs::read(&receipt_path).unwrap();
    let receipt_value: Value = serde_json::from_slice(&original_receipt).unwrap();
    let receipt_fields = receipt_value
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(receipt_fields.len(), 68);
    for field in &receipt_fields {
        let mut changed = receipt_value.clone();
        match field.as_str() {
            "a7_receipt" => changed[field]["execution_authorized"] = json!(true),
            "comparison_account" => changed[field]["all_correspondence_matches"] = json!(false),
            "effect_account" => changed[field]["process_count"] = json!(1),
            _ => changed[field] = alter_scalar(&changed[field]),
        }
        let mut rebound = None;
        if let Ok(mut typed) = serde_json::from_value::<PbpcVerificationReceipt>(changed.clone()) {
            if field != "receipt_sha256" {
                typed.receipt_sha256 = pbpc_receipt_digest(&typed).unwrap();
            }
            rebound = Some(typed.receipt_sha256.clone());
            changed = serde_json::to_value(typed).unwrap();
        }
        write_json_value(&receipt_path, &changed);
        rehash_manifest_with_receipt(&root, rebound);
        assert!(
            verify_pbpc_evidence_directory(&root).is_err(),
            "receipt {field}"
        );
        fs::write(&receipt_path, &original_receipt).unwrap();
        let original: PbpcVerificationReceipt = serde_json::from_slice(&original_receipt).unwrap();
        rehash_manifest_with_receipt(&root, Some(original.receipt_sha256));
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn every_comparison_effect_and_explicit_a7_payload_tamper_refuses() {
    let root = temporary("nested-fields");
    write_evidence(&root, KcvInputClass::DeterministicFixtureCandidate);
    let receipt_path = root.join("receipt.json");
    let original_receipt = fs::read(&receipt_path).unwrap();
    let receipt_value: Value = serde_json::from_slice(&original_receipt).unwrap();

    let comparison_fields = receipt_value["comparison_account"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(comparison_fields.len(), 28);
    for field in &comparison_fields {
        let mut changed = receipt_value.clone();
        changed["comparison_account"][field] = alter_scalar(&changed["comparison_account"][field]);
        let mut typed: PbpcVerificationReceipt = serde_json::from_value(changed).unwrap();
        typed.receipt_sha256 = pbpc_receipt_digest(&typed).unwrap();
        fs::write(&receipt_path, line(&typed)).unwrap();
        rehash_manifest_with_receipt(&root, Some(typed.receipt_sha256));
        assert!(
            verify_pbpc_evidence_directory(&root).is_err(),
            "comparison {field}"
        );
        fs::write(&receipt_path, &original_receipt).unwrap();
        let original: PbpcVerificationReceipt = serde_json::from_slice(&original_receipt).unwrap();
        rehash_manifest_with_receipt(&root, Some(original.receipt_sha256));
    }

    let effect_fields = receipt_value["effect_account"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(effect_fields.len(), 22);
    for field in &effect_fields {
        let mut changed = receipt_value.clone();
        changed["effect_account"][field] = alter_scalar(&changed["effect_account"][field]);
        let mut typed: PbpcVerificationReceipt = serde_json::from_value(changed).unwrap();
        typed.receipt_sha256 = pbpc_receipt_digest(&typed).unwrap();
        fs::write(&receipt_path, line(&typed)).unwrap();
        rehash_manifest_with_receipt(&root, Some(typed.receipt_sha256));
        assert!(
            verify_pbpc_evidence_directory(&root).is_err(),
            "effect {field}"
        );
        fs::write(&receipt_path, &original_receipt).unwrap();
        let original: PbpcVerificationReceipt = serde_json::from_slice(&original_receipt).unwrap();
        rehash_manifest_with_receipt(&root, Some(original.receipt_sha256));
    }

    const A7_EXPLICIT_INDICES: [usize; 28] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        26, 27, 28,
    ];
    for index in A7_EXPLICIT_INDICES {
        let path = root.join(PBPC_EVIDENCE_FILES[index]);
        let original = fs::read(&path).unwrap();
        let mut changed = original.clone();
        changed[0] = b'[';
        fs::write(&path, changed).unwrap();
        rehash_manifest(&root);
        assert!(
            verify_pbpc_evidence_directory(&root).is_err(),
            "A7 payload {}",
            PBPC_EVIDENCE_FILES[index]
        );
        fs::write(&path, original).unwrap();
        rehash_manifest(&root);
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn every_a7_receipt_comparison_and_effect_field_tamper_refuses_through_a8() {
    let root = temporary("every-a7-field");
    write_evidence(&root, KcvInputClass::DeterministicFixtureCandidate);
    let receipt_path = root.join("a7_receipt.json");
    let original_bytes = fs::read(&receipt_path).unwrap();
    let original_value: Value = serde_json::from_slice(&original_bytes).unwrap();
    let original_typed: PercVerificationReceipt = serde_json::from_slice(&original_bytes).unwrap();
    let fields = original_value
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(fields.len(), 63);
    for field in &fields {
        let mut changed = original_value.clone();
        match field.as_str() {
            "a6_receipt" => changed[field]["execution_authorized"] = json!(true),
            "correspondence_account" => changed[field]["all_correspondence_matches"] = json!(false),
            "effect_account" => changed[field]["process_count"] = json!(1),
            _ => changed[field] = alter_scalar(&changed[field]),
        }
        let mut rebound = original_typed.receipt_sha256.clone();
        if let Ok(mut typed) = serde_json::from_value::<PercVerificationReceipt>(changed.clone()) {
            if field != "receipt_sha256" {
                typed.receipt_sha256 = perc_receipt_digest(&typed).unwrap();
            }
            rebound = typed.receipt_sha256.clone();
            changed = serde_json::to_value(typed).unwrap();
        }
        write_json_value(&receipt_path, &changed);
        rehash_manifest_with_a7_receipt(&root, rebound);
        assert!(
            verify_pbpc_evidence_directory(&root).is_err(),
            "A7 receipt {field}"
        );
        fs::write(&receipt_path, &original_bytes).unwrap();
        rehash_manifest_with_a7_receipt(&root, original_typed.receipt_sha256.clone());
    }

    let comparison_fields = original_value["correspondence_account"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(comparison_fields.len(), 19);
    for field in &comparison_fields {
        let mut changed = original_value.clone();
        changed["correspondence_account"][field] =
            alter_scalar(&changed["correspondence_account"][field]);
        let mut typed: PercVerificationReceipt = serde_json::from_value(changed).unwrap();
        typed.receipt_sha256 = perc_receipt_digest(&typed).unwrap();
        fs::write(&receipt_path, line(&typed)).unwrap();
        rehash_manifest_with_a7_receipt(&root, typed.receipt_sha256);
        assert!(
            verify_pbpc_evidence_directory(&root).is_err(),
            "A7 comparison {field}"
        );
        fs::write(&receipt_path, &original_bytes).unwrap();
        rehash_manifest_with_a7_receipt(&root, original_typed.receipt_sha256.clone());
    }

    let effect_fields = original_value["effect_account"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(effect_fields.len(), 22);
    for field in &effect_fields {
        let mut changed = original_value.clone();
        changed["effect_account"][field] = alter_scalar(&changed["effect_account"][field]);
        let mut typed: PercVerificationReceipt = serde_json::from_value(changed).unwrap();
        typed.receipt_sha256 = perc_receipt_digest(&typed).unwrap();
        fs::write(&receipt_path, line(&typed)).unwrap();
        rehash_manifest_with_a7_receipt(&root, typed.receipt_sha256);
        assert!(
            verify_pbpc_evidence_directory(&root).is_err(),
            "A7 effect {field}"
        );
        fs::write(&receipt_path, &original_bytes).unwrap();
        rehash_manifest_with_a7_receipt(&root, original_typed.receipt_sha256.clone());
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn production_surfaces_have_no_effect_or_fixture_producer_capability() {
    let core = include_str!("../src/b1_production_broker_projection_correspondence.rs");
    let evidence =
        include_str!("../src/b1_production_broker_projection_correspondence_evidence.rs");
    for forbidden in [
        "unsafe {",
        "SigningKey",
        "std::process",
        "std::env",
        "SystemTime::now",
        "TcpStream",
        "UdpSocket",
        ".write(true)",
        ".create(true)",
        "fs::write",
        "remove_file(",
        "remove_dir(",
        "Command::new",
        "reqwest",
        "git2",
        "rmcp",
        "llama",
        "produce_provider_free_evidence",
    ] {
        assert!(!core.contains(forbidden), "core {forbidden}");
        assert!(!evidence.contains(forbidden), "evidence {forbidden}");
    }
    assert!(core.contains("verify_perc_reference_correspondence("));
    assert!(evidence.contains("FILE_FLAG_OPEN_REPARSE_POINT"));
    assert!(evidence.contains("options.read(true)"));
}

#[test]
fn every_manifest_and_artifact_field_tamper_refuses() {
    let root = temporary("manifest-fields");
    write_evidence(&root, KcvInputClass::DeterministicFixtureCandidate);
    let path = root.join("evidence_manifest.json");
    let original_bytes = fs::read(&path).unwrap();
    let original_value: Value = serde_json::from_slice(&original_bytes).unwrap();
    let fields = original_value
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(fields.len(), 16);
    for field in &fields {
        let mut changed = original_value.clone();
        if field == "artifacts" {
            changed[field][0]["bytes"] = json!(2);
        } else {
            changed[field] = alter_scalar(&changed[field]);
        }
        if let Ok(mut typed) = serde_json::from_value::<PbpcEvidenceManifest>(changed.clone()) {
            if field != "manifest_sha256" {
                typed.manifest_sha256 = pbpc_evidence_manifest_digest(&typed).unwrap();
            }
            changed = serde_json::to_value(typed).unwrap();
        }
        write_json_value(&path, &changed);
        assert!(
            verify_pbpc_evidence_directory(&root).is_err(),
            "manifest {field}"
        );
        fs::write(&path, &original_bytes).unwrap();
    }

    for field in ["path", "bytes", "sha256"] {
        let mut changed = original_value.clone();
        changed["artifacts"][0][field] = alter_scalar(&changed["artifacts"][0][field]);
        let mut typed: PbpcEvidenceManifest = serde_json::from_value(changed).unwrap();
        typed.manifest_sha256 = pbpc_evidence_manifest_digest(&typed).unwrap();
        fs::write(&path, line(&typed)).unwrap();
        assert!(
            verify_pbpc_evidence_directory(&root).is_err(),
            "artifact {field}"
        );
        fs::write(&path, &original_bytes).unwrap();
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn framing_and_file_resource_excess_refuse_before_semantic_admission() {
    let root = temporary("resource");
    write_evidence(&root, KcvInputClass::DeterministicFixtureCandidate);
    let declaration = root.join("broker_projection_declaration.json");
    let original = fs::read(&declaration).unwrap();

    fs::write(&declaration, original.strip_suffix(b"\n").unwrap()).unwrap();
    rehash_manifest(&root);
    assert_eq!(
        verify_pbpc_evidence_directory(&root).unwrap_err().code,
        EocvFaultCode::MachineForm
    );

    fs::write(&declaration, vec![b'x'; PBPC_MAX_FORM_BYTES + 2]).unwrap();
    assert_eq!(
        verify_pbpc_evidence_directory(&root).unwrap_err().code,
        EocvFaultCode::Size
    );
    fs::write(&declaration, original).unwrap();
    rehash_manifest(&root);
    verify_pbpc_evidence_directory(&root).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_arity_duplicate_paths_relative_paths_and_aggregate_bounds_are_exact() {
    for args in [vec![], vec!["x"; 29], vec!["x"; 31], vec!["x"; 32]] {
        let output = Command::new(CLI).args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    for args in [vec![], vec!["x", "y"], vec!["x", "y", "z"]] {
        let output = Command::new(EVIDENCE_CLI).args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }

    let root = temporary("cli-resource");
    write_evidence(&root, KcvInputClass::DeterministicFixtureCandidate);
    let relative_names = explicit_paths(Path::new(""));
    let output = Command::new(CLI)
        .current_dir(&root)
        .args(&relative_names)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    let retained_receipt = fs::read(root.join("receipt.json")).unwrap();
    assert_eq!(output.stdout, retained_receipt);

    let paths = explicit_paths(&root);
    let mut duplicate = paths.clone();
    duplicate[1] = duplicate[0].clone();
    assert!(verify_pbpc_payload_paths(&duplicate).is_err());
    fs::write(
        root.join("observation_bundle.json"),
        vec![b'x'; PBPC_MAX_FORM_BYTES + 2],
    )
    .unwrap();
    assert_eq!(
        verify_pbpc_payload_paths(&paths).unwrap_err().code,
        EocvFaultCode::Size
    );
    fs::remove_dir_all(root).unwrap();

    let aggregate_root = temporary("aggregate");
    write_evidence(
        &aggregate_root,
        KcvInputClass::DeterministicFixtureCandidate,
    );
    let aggregate_file_bytes = (PBPC_MAX_EVIDENCE_BYTES / 30 + 1) as usize;
    let aggregate = vec![b'x'; aggregate_file_bytes];
    for path in explicit_paths(&aggregate_root) {
        fs::write(path, &aggregate).unwrap();
    }
    assert_eq!(
        verify_pbpc_payload_paths(&explicit_paths(&aggregate_root))
            .unwrap_err()
            .code,
        EocvFaultCode::Size
    );
    fs::remove_dir_all(aggregate_root).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_junction_root_refuses_without_changing_target() {
    let root = temporary("junction");
    write_evidence(&root, KcvInputClass::DeterministicFixtureCandidate);
    let junction = root.with_extension("junction");
    let result = Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&root)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        verify_pbpc_evidence_directory(&junction).unwrap_err().code,
        EocvFaultCode::Path
    );
    assert_eq!(
        verify_pbpc_payload_paths(&explicit_paths(&junction))
            .unwrap_err()
            .code,
        EocvFaultCode::Path
    );
    fs::remove_dir(&junction).expect("unlink only the test-owned junction");
    assert_eq!(fs::read_dir(&root).unwrap().count(), 34);
    verify_pbpc_evidence_directory(&root).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "test-owned fixture producer: explicit fresh D-drive output directory required"]
fn produce_provider_free_evidence() {
    let root = std::env::var_os("CANTOR_PBPC_EVIDENCE_OUTPUT").expect("explicit test output");
    write_evidence(
        Path::new(&root),
        KcvInputClass::DeterministicFixtureCandidate,
    );
}
