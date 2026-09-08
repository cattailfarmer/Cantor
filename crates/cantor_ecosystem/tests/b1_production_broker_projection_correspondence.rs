//! Full A8 retained replay over the published A7 evidence; no broker contact or effects.
use cantor_core::{ContentDigest, sha256_bytes};
use cantor_ecosystem::*;
use serde::{Serialize, de::DeserializeOwned};
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
    input_class: KcvInputClass,
) -> (PbpcProjectionDeclaration, PbpcVerificationRequest) {
    let root = a7_root();
    let a6_request: EocvVerificationRequest = retained(&root.join("a6_verification_request.json"));
    let a7_request: PercVerificationRequest = retained(&root.join("verification_request.json"));
    let a7_receipt: PercVerificationReceipt = retained(&root.join("receipt.json"));
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
    let (projection, request) = fixture_forms(input_class);
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
#[ignore = "test-owned fixture producer: explicit fresh D-drive output directory required"]
fn produce_provider_free_evidence() {
    let root = std::env::var_os("CANTOR_PBPC_EVIDENCE_OUTPUT").expect("explicit test output");
    write_evidence(
        Path::new(&root),
        KcvInputClass::DeterministicFixtureCandidate,
    );
}
