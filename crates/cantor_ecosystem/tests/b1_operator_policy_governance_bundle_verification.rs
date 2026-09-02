use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use cantor_core::{ContentDigest, sha256_bytes};
use cantor_ecosystem::*;
use ed25519_dalek::{Signer, SigningKey};

struct Fixture {
    request: BpvVerificationRequest,
    predecessor_request: B1OaprRequest,
    predecessor_packet: B1OaprPacket,
    predecessor_verification: B1OaprVerification,
    envelope: BpvPolicyEnvelope,
    raw_envelope: Vec<u8>,
}

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TempEvidence(PathBuf);

impl Drop for TempEvidence {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut value, "{byte:02x}").expect("hex write");
    }
    value
}

fn signed_envelope(fixture_only: bool) -> BpvPolicyEnvelope {
    let mut payload = deterministic_bpv_fixture_payload().expect("fixture payload");
    payload.fixture_only = fixture_only;
    payload.payload_sha256 = bpv_payload_digest(&payload).expect("payload digest");
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let signature =
        signing_key.sign(&bpv_signature_payload_bytes(&payload).expect("signature payload"));
    let mut envelope = BpvPolicyEnvelope {
        profile: BPV_ENVELOPE_PROFILE.to_owned(),
        payload,
        verifying_key_hex: lower_hex(signing_key.verifying_key().as_bytes()),
        signature_hex: lower_hex(&signature.to_bytes()),
        signing_context: BPV_SIGNING_CONTEXT.to_owned(),
        envelope_sha256: empty_digest(),
    };
    envelope.envelope_sha256 = bpv_envelope_digest(&envelope).expect("envelope digest");
    envelope
}

fn bind_envelope(envelope: BpvPolicyEnvelope, input_class: BpvInputClass) -> Fixture {
    let raw_envelope = serde_json::to_vec(&envelope).expect("raw envelope");
    let mut predecessor_request = canonical_b1oapr_request().expect("predecessor request");
    {
        let descriptor = predecessor_request
            .descriptors
            .first_mut()
            .expect("A1 descriptor");
        descriptor.origin = match input_class {
            BpvInputClass::DeterministicFixtureCandidate => {
                B1OaprCandidateOrigin::DeterministicFixtureCandidate
            }
            BpvInputClass::ExternallySuppliedCandidate => {
                B1OaprCandidateOrigin::ExternallySuppliedCandidate
            }
        };
        descriptor.fixture_only =
            matches!(input_class, BpvInputClass::DeterministicFixtureCandidate);
        descriptor.opaque_reference = if descriptor.fixture_only {
            "fixture_candidate_a1_policy_bundle".to_owned()
        } else {
            "externally_supplied_candidate_a1_policy_bundle".to_owned()
        };
        descriptor.declared_bytes = raw_envelope.len() as u64;
        descriptor.content_sha256 = sha256_bytes(&raw_envelope);
        descriptor.descriptor_sha256 = b1oapr_descriptor_digest(descriptor).expect("descriptor");
    }
    predecessor_request.request_sha256 =
        b1oapr_request_digest(&predecessor_request).expect("predecessor request digest");
    let predecessor_packet =
        compile_b1oapr_packet(&predecessor_request).expect("predecessor packet");
    let predecessor_verification = verify_b1oapr_packet(&predecessor_request, &predecessor_packet)
        .expect("predecessor verification");
    let a1 = predecessor_packet.descriptors.first().expect("packet A1");
    let mut request = BpvVerificationRequest {
        profile: BPV_REQUEST_PROFILE.to_owned(),
        source_snapshot_uuid: BPV_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: BPV_CANONICAL_UUID.to_owned(),
        signature_uuid: BPV_SIGNATURE_UUID.to_owned(),
        source_custody_commit: BPV_SOURCE_CUSTODY_COMMIT.to_owned(),
        formation_commit: BPV_FORMATION_COMMIT.to_owned(),
        formation_bookend_commit: BPV_FORMATION_BOOKEND_COMMIT.to_owned(),
        predecessor_implementation_commit: BPV_PREDECESSOR_IMPLEMENTATION_COMMIT.to_owned(),
        predecessor_bookend_commit: BPV_PREDECESSOR_BOOKEND_COMMIT.to_owned(),
        predecessor_proof_uuid: BPV_PREDECESSOR_PROOF_UUID.to_owned(),
        predecessor_request_sha256: predecessor_request.request_sha256.clone(),
        predecessor_packet_sha256: predecessor_packet.packet_sha256.clone(),
        predecessor_verification_sha256: predecessor_verification.verification_sha256.clone(),
        a1_candidate_uuid: a1.candidate_uuid.clone(),
        a1_descriptor_sha256: a1.descriptor_sha256.clone(),
        policy_envelope_bytes: raw_envelope.len() as u64,
        policy_envelope_raw_sha256: sha256_bytes(&raw_envelope),
        input_class,
        evidence_references: vec![
            "predecessor_request.json".to_owned(),
            "predecessor_packet.json".to_owned(),
            "predecessor_verification.json".to_owned(),
            "policy_envelope.json".to_owned(),
        ],
        request_sha256: empty_digest(),
    };
    request.request_sha256 = bpv_request_digest(&request).expect("request digest");
    Fixture {
        request,
        predecessor_request,
        predecessor_packet,
        predecessor_verification,
        envelope,
        raw_envelope,
    }
}

fn fixture() -> Fixture {
    bind_envelope(
        signed_envelope(true),
        BpvInputClass::DeterministicFixtureCandidate,
    )
}

fn verify(value: &Fixture) -> Result<BpvVerificationReceipt, BpvFault> {
    verify_bpv_policy_bundle(
        &value.request,
        &value.predecessor_request,
        &value.predecessor_packet,
        &value.predecessor_verification,
        &value.raw_envelope,
    )
}

fn retained(text: String) -> Vec<u8> {
    let mut bytes = text.into_bytes();
    bytes.push(b'\n');
    bytes
}

fn write_evidence(root: &Path, value: &Fixture) {
    fs::create_dir(root).expect("fresh evidence directory");
    let receipt = verify(value).expect("receipt");
    let artifacts = [
        (
            BPV_PREDECESSOR_REQUEST_FILE,
            retained(
                to_b1oapr_request_machine_form(&value.predecessor_request)
                    .expect("predecessor request form"),
            ),
        ),
        (
            BPV_PREDECESSOR_PACKET_FILE,
            retained(
                to_b1oapr_packet_machine_form(
                    &value.predecessor_request,
                    &value.predecessor_packet,
                )
                .expect("predecessor packet form"),
            ),
        ),
        (
            BPV_PREDECESSOR_VERIFICATION_FILE,
            retained(
                to_b1oapr_verification_machine_form(
                    &value.predecessor_request,
                    &value.predecessor_packet,
                    &value.predecessor_verification,
                )
                .expect("predecessor verification form"),
            ),
        ),
        (
            BPV_POLICY_ENVELOPE_FILE,
            retained(to_bpv_envelope_machine_form(&value.envelope).expect("envelope form")),
        ),
        (
            BPV_VERIFICATION_REQUEST_FILE,
            retained(to_bpv_request_machine_form(&value.request).expect("request form")),
        ),
        (
            BPV_RECEIPT_FILE,
            retained(
                to_bpv_receipt_machine_form(&value.request, &value.envelope, &receipt)
                    .expect("receipt form"),
            ),
        ),
    ];
    let mut bindings = Vec::new();
    let mut total = 0_u64;
    for (name, bytes) in artifacts {
        fs::write(root.join(name), &bytes).expect("write artifact");
        total += bytes.len() as u64;
        bindings.push(BpvEvidenceArtifact {
            path: name.to_owned(),
            bytes: bytes.len() as u64,
            sha256: sha256_bytes(&bytes),
        });
    }
    let mut manifest = BpvEvidenceManifest {
        profile: BPV_EVIDENCE_PROFILE.to_owned(),
        manifest_uuid: "b1000000-0000-4000-8000-000000000003".to_owned(),
        fixture_only: value.envelope.payload.fixture_only,
        artifacts: bindings,
        artifact_count: 6,
        total_artifact_bytes: total,
        retained_receipt_sha256: receipt.receipt_sha256,
        deterministic_replay_count: 2,
        byte_identical: true,
        effect_count: 0,
        manifest_sha256: empty_digest(),
    };
    manifest.manifest_sha256 = bpv_evidence_manifest_digest(&manifest).expect("manifest digest");
    fs::write(
        root.join(BPV_EVIDENCE_MANIFEST_FILE),
        retained(to_bpv_evidence_manifest_machine_form(&manifest).expect("evidence manifest form")),
    )
    .expect("write manifest");
}

fn temporary_evidence(value: &Fixture) -> TempEvidence {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "cantor_bpv_evidence_{}_{}",
        std::process::id(),
        sequence
    ));
    assert!(!root.exists(), "temporary path must be fresh");
    write_evidence(&root, value);
    TempEvidence(root)
}

#[test]
fn fixture_proves_correspondence_without_authority_or_effects() {
    let value = fixture();
    let receipt = verify(&value).expect("valid fixture");
    assert!(receipt.candidate_bytes_matched);
    assert!(receipt.descriptor_correspondence_verified);
    assert!(receipt.payload_structure_verified);
    assert!(receipt.scope_and_denials_verified);
    assert!(receipt.signature_correspondence_verified);
    assert!(receipt.fixture_only);
    assert!(!receipt.production_authority_claimed);
    assert!(!receipt.policy_governance_proved);
    assert!(!receipt.key_custody_proved);
    assert!(!receipt.revocation_truth_proved);
    assert!(!receipt.current_nonexpired);
    assert!(!receipt.live_authorization_admitted);
    assert!(!receipt.fresh_observation_proved);
    assert!(!receipt.private_execution_permit_present);
    assert!(!receipt.production_broker_projection_present);
    assert!(!receipt.physical_preparation_authorized);
    assert!(!receipt.ready_for_physical_execution);
    assert!(!receipt.execution_authorized);
    assert_eq!(receipt.effect_account, BpvEffectAccount::default());
}

#[test]
fn replay_and_machine_forms_are_byte_identical() {
    let value = fixture();
    let first = verify(&value).expect("first replay");
    let second = verify(&value).expect("second replay");
    assert_eq!(first, second);
    let envelope_text = to_bpv_envelope_machine_form(&value.envelope).expect("envelope form");
    assert_eq!(
        from_bpv_envelope_machine_form(&envelope_text).expect("parse envelope"),
        value.envelope
    );
    let request_text = to_bpv_request_machine_form(&value.request).expect("request form");
    assert_eq!(
        from_bpv_request_machine_form(&request_text).expect("parse request"),
        value.request
    );
    let receipt_text =
        to_bpv_receipt_machine_form(&value.request, &value.envelope, &first).expect("receipt form");
    assert_eq!(
        from_bpv_receipt_machine_form(&value.request, &value.envelope, &receipt_text)
            .expect("parse receipt"),
        first
    );
}

#[test]
fn externally_supplied_classification_remains_unauthorized() {
    let value = bind_envelope(
        signed_envelope(false),
        BpvInputClass::ExternallySuppliedCandidate,
    );
    let receipt = verify(&value).expect("valid external candidate");
    assert!(!receipt.fixture_only);
    assert_eq!(receipt.authority, BPV_AUTHORITY);
    assert!(!receipt.policy_governance_proved);
    assert!(!receipt.execution_authorized);
}

#[test]
fn raw_argument_byte_tamper_is_refused_before_parsing() {
    let value = fixture();
    let mut raw = value.raw_envelope.clone();
    raw.push(b' ');
    let error = verify_bpv_policy_bundle(
        &value.request,
        &value.predecessor_request,
        &value.predecessor_packet,
        &value.predecessor_verification,
        &raw,
    )
    .expect_err("raw byte tamper must fail");
    assert_eq!(error.code, BpvFaultCode::RawBytes);
}

#[test]
fn a1_coordinate_substitution_is_refused() {
    let mut value = fixture();
    value.request.a1_candidate_uuid = "b1000000-0000-4000-8000-000000000099".to_owned();
    value.request.request_sha256 = bpv_request_digest(&value.request).expect("digest laundering");
    let error = verify(&value).expect_err("coordinate substitution must fail");
    assert_eq!(error.code, BpvFaultCode::Coordinate);
}

#[test]
fn denial_removal_is_refused_even_with_fresh_signature_and_digests() {
    let mut envelope = signed_envelope(true);
    envelope.payload.denials.pop();
    envelope.payload.payload_sha256 =
        bpv_payload_digest(&envelope.payload).expect("payload digest");
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    envelope.signature_hex = lower_hex(
        &signing_key
            .sign(&bpv_signature_payload_bytes(&envelope.payload).expect("signing payload"))
            .to_bytes(),
    );
    envelope.envelope_sha256 = bpv_envelope_digest(&envelope).expect("envelope digest");
    let value = bind_envelope(envelope, BpvInputClass::DeterministicFixtureCandidate);
    let error = verify(&value).expect_err("denial removal must fail");
    assert_eq!(error.code, BpvFaultCode::Scope);
}

#[test]
fn signature_tamper_is_refused_after_raw_bytes_are_rebound() {
    let mut envelope = signed_envelope(true);
    envelope.signature_hex.replace_range(0..2, "00");
    envelope.envelope_sha256 = bpv_envelope_digest(&envelope).expect("envelope digest");
    let value = bind_envelope(envelope, BpvInputClass::DeterministicFixtureCandidate);
    let error = verify(&value).expect_err("signature tamper must fail");
    assert_eq!(error.code, BpvFaultCode::Signature);
}

#[test]
fn duplicate_evidence_reference_is_refused_after_digest_laundering() {
    let mut value = fixture();
    value.request.evidence_references[1] = value.request.evidence_references[0].clone();
    value.request.request_sha256 = bpv_request_digest(&value.request).expect("digest laundering");
    let error = verify(&value).expect_err("duplicate reference must fail");
    assert_eq!(error.code, BpvFaultCode::Bound);
}

#[test]
fn receipt_authority_promotion_is_refused_after_digest_laundering() {
    let value = fixture();
    let mut receipt = verify(&value).expect("receipt");
    receipt.policy_governance_proved = true;
    receipt.receipt_sha256 = bpv_receipt_digest(&receipt).expect("digest laundering");
    let error = validate_bpv_receipt(&value.request, &value.envelope, &receipt)
        .expect_err("authority promotion must fail");
    assert_eq!(error.code, BpvFaultCode::Authority);
}

#[test]
fn noncanonical_and_duplicate_json_are_refused() {
    let value = fixture();
    let text = std::str::from_utf8(&value.raw_envelope).expect("UTF-8");
    let whitespace = format!("{text} ");
    assert_eq!(
        from_bpv_envelope_machine_form(&whitespace)
            .expect_err("trailing whitespace must fail")
            .code,
        BpvFaultCode::MachineForm
    );
    let duplicate = text.replacen(
        '{',
        &format!("{{\"profile\":\"{}\",", BPV_ENVELOPE_PROFILE),
        1,
    );
    assert_eq!(
        from_bpv_envelope_machine_form(&duplicate)
            .expect_err("duplicate field must fail")
            .code,
        BpvFaultCode::MachineForm
    );
}

#[test]
fn lineage_digest_and_input_class_laundering_are_refused() {
    let mut lineage = fixture();
    lineage.request.formation_commit = "0000000000000000000000000000000000000001".to_owned();
    lineage.request.request_sha256 =
        bpv_request_digest(&lineage.request).expect("digest laundering");
    assert_eq!(
        verify(&lineage)
            .expect_err("lineage laundering must fail")
            .code,
        BpvFaultCode::Lineage
    );

    let mut digest_tamper = fixture();
    digest_tamper
        .request
        .request_sha256
        .value
        .replace_range(0..2, "00");
    assert_eq!(
        verify(&digest_tamper)
            .expect_err("request digest tamper must fail")
            .code,
        BpvFaultCode::Digest
    );

    let mut origin = fixture();
    origin.request.input_class = BpvInputClass::ExternallySuppliedCandidate;
    origin.request.request_sha256 = bpv_request_digest(&origin.request).expect("digest laundering");
    assert_eq!(
        verify(&origin)
            .expect_err("origin laundering must fail")
            .code,
        BpvFaultCode::Bound
    );
}

#[test]
fn signing_context_and_key_shape_laundering_are_refused() {
    let mut context = signed_envelope(true);
    context.signing_context.push_str(".changed");
    context.envelope_sha256 = bpv_envelope_digest(&context).expect("digest laundering");
    let value = bind_envelope(context, BpvInputClass::DeterministicFixtureCandidate);
    assert_eq!(
        verify(&value)
            .expect_err("signing context laundering must fail")
            .code,
        BpvFaultCode::Payload
    );

    let mut key = signed_envelope(true);
    key.verifying_key_hex.replace_range(0..1, "g");
    key.envelope_sha256 = bpv_envelope_digest(&key).expect("digest laundering");
    let value = bind_envelope(key, BpvInputClass::DeterministicFixtureCandidate);
    assert_eq!(
        verify(&value)
            .expect_err("key shape laundering must fail")
            .code,
        BpvFaultCode::Payload
    );
}

#[test]
fn production_modules_expose_no_signing_clock_process_network_or_write_primitive() {
    let sources = [
        include_str!("../src/b1_operator_policy_governance_bundle_verification.rs"),
        include_str!("../src/b1_operator_policy_governance_bundle_verification_evidence.rs"),
        include_str!("../src/bin/cantor-b1-operator-policy-governance-bundle-verify.rs"),
        include_str!("../src/bin/cantor-b1-operator-policy-governance-evidence-verify.rs"),
    ];
    for forbidden in [
        "SigningKey",
        "SystemTime",
        "std::process::Command",
        "TcpStream",
        "UdpSocket",
        "reqwest",
        "fs::write",
        "fs::create_dir",
        "fs::remove_",
        "unsafe {",
    ] {
        assert!(
            sources.iter().all(|source| !source.contains(forbidden)),
            "forbidden production primitive found: {forbidden}"
        );
    }
}

#[test]
fn independent_evidence_replay_reconstructs_all_six_artifacts() {
    let value = fixture();
    let evidence = temporary_evidence(&value);
    let replay = verify_bpv_evidence_directory(&evidence.0).expect("evidence replay");
    assert_eq!(replay.artifact_count, 6);
    assert_eq!(replay.deterministic_replay_count, 2);
    assert!(replay.byte_identical);
    assert_eq!(replay.receipt, verify(&value).expect("direct receipt"));
    assert!(!replay.receipt.policy_governance_proved);
    assert_eq!(replay.receipt.effect_account, BpvEffectAccount::default());
}

#[test]
fn evidence_raw_byte_tamper_is_refused() {
    let value = fixture();
    let evidence = temporary_evidence(&value);
    let receipt_path = evidence.0.join(BPV_RECEIPT_FILE);
    let mut bytes = fs::read(&receipt_path).expect("read receipt");
    bytes.insert(bytes.len() - 1, b' ');
    fs::write(receipt_path, bytes).expect("tamper receipt");
    verify_bpv_evidence_directory(&evidence.0).expect_err("raw evidence tamper must fail");
}

#[test]
fn missing_or_extra_evidence_file_is_refused() {
    let value = fixture();
    let missing = temporary_evidence(&value);
    fs::remove_file(missing.0.join(BPV_RECEIPT_FILE)).expect("remove test receipt");
    verify_bpv_evidence_directory(&missing.0).expect_err("missing file must fail");

    let extra = temporary_evidence(&value);
    fs::write(extra.0.join("extra.json"), b"{}\n").expect("write extra file");
    verify_bpv_evidence_directory(&extra.0).expect_err("extra file must fail");
}

#[test]
#[ignore = "writes only a fresh explicit test-owned evidence directory"]
fn produce_retained_bpv_fixture_evidence() {
    let root = std::env::var_os("CANTOR_BPV_EVIDENCE_OUTPUT")
        .map(PathBuf::from)
        .expect("CANTOR_BPV_EVIDENCE_OUTPUT must name a fresh explicit directory");
    assert!(!root.exists(), "evidence output must be absent");
    write_evidence(&root, &fixture());
    let replay = verify_bpv_evidence_directory(&root).expect("retained evidence replay");
    println!(
        "bpv_evidence_written root={} artifacts={} bytes={} replay={} byte_identical={} effects=0",
        root.display(),
        replay.artifact_count,
        replay.total_artifact_bytes,
        replay.deterministic_replay_count,
        replay.byte_identical
    );
}
