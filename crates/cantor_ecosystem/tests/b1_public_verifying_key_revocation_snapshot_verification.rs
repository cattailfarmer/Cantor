use cantor_core::{ContentDigest, sha256_bytes};
use cantor_ecosystem::*;
use ed25519_dalek::{Signer, SigningKey};
use serde::de::DeserializeOwned;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const A2_ROOT: &str = "../../../experiments/b1_public_verifying_key_custody_attestation_verification_p0/implementation_provider_free_evidence";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct TempEvidence(PathBuf);

impl Drop for TempEvidence {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    predecessor_request: B1OaprRequest,
    predecessor_packet: B1OaprPacket,
    predecessor_verification: B1OaprVerification,
    a1_envelope: BpvPolicyEnvelope,
    raw_a1_envelope: Vec<u8>,
    a1_request: BpvVerificationRequest,
    a1_receipt: BpvVerificationReceipt,
    a2_attestation: KcvCustodyAttestation,
    raw_a2_attestation: Vec<u8>,
    a2_request: KcvVerificationRequest,
    a2_receipt: KcvVerificationReceipt,
    snapshot: KrvRevocationSnapshot,
    raw_snapshot: Vec<u8>,
    request: KrvVerificationRequest,
}

fn retained(name: &str) -> &'static [u8] {
    match name {
        "predecessor_request.json" => include_bytes!(concat!(
            "../../../experiments/b1_public_verifying_key_custody_attestation_verification_p0/implementation_provider_free_evidence/",
            "predecessor_request.json"
        )),
        "predecessor_packet.json" => include_bytes!(concat!(
            "../../../experiments/b1_public_verifying_key_custody_attestation_verification_p0/implementation_provider_free_evidence/",
            "predecessor_packet.json"
        )),
        "predecessor_verification.json" => include_bytes!(concat!(
            "../../../experiments/b1_public_verifying_key_custody_attestation_verification_p0/implementation_provider_free_evidence/",
            "predecessor_verification.json"
        )),
        "a1_policy_envelope.json" => include_bytes!(concat!(
            "../../../experiments/b1_public_verifying_key_custody_attestation_verification_p0/implementation_provider_free_evidence/",
            "a1_policy_envelope.json"
        )),
        "a1_verification_request.json" => include_bytes!(concat!(
            "../../../experiments/b1_public_verifying_key_custody_attestation_verification_p0/implementation_provider_free_evidence/",
            "a1_verification_request.json"
        )),
        "a1_receipt.json" => include_bytes!(concat!(
            "../../../experiments/b1_public_verifying_key_custody_attestation_verification_p0/implementation_provider_free_evidence/",
            "a1_receipt.json"
        )),
        "custody_attestation.json" => include_bytes!(concat!(
            "../../../experiments/b1_public_verifying_key_custody_attestation_verification_p0/implementation_provider_free_evidence/",
            "custody_attestation.json"
        )),
        "verification_request.json" => include_bytes!(concat!(
            "../../../experiments/b1_public_verifying_key_custody_attestation_verification_p0/implementation_provider_free_evidence/",
            "verification_request.json"
        )),
        "receipt.json" => include_bytes!(concat!(
            "../../../experiments/b1_public_verifying_key_custody_attestation_verification_p0/implementation_provider_free_evidence/",
            "receipt.json"
        )),
        _ => panic!("unknown retained file under {A2_ROOT}"),
    }
}

fn raw(name: &str) -> Vec<u8> {
    let mut value = retained(name).to_vec();
    assert_eq!(value.pop(), Some(b'\n'));
    assert!(!value.contains(&b'\r'));
    value
}

fn parsed<T: DeserializeOwned>(name: &str) -> T {
    serde_json::from_slice(retained(name)).expect("retained typed evidence")
}

fn empty_digest() -> ContentDigest {
    sha256_bytes(b"")
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn resign(snapshot: &mut KrvRevocationSnapshot, key: &SigningKey) {
    snapshot.signature_hex.clear();
    snapshot.snapshot_sha256 = empty_digest();
    snapshot.signature_hex = lower_hex(
        &key.sign(&krv_signature_payload_bytes(snapshot).expect("signature payload"))
            .to_bytes(),
    );
    snapshot.snapshot_sha256 = krv_snapshot_digest(snapshot).expect("snapshot digest");
}

fn bind_snapshot(mut value: Fixture, snapshot: KrvRevocationSnapshot) -> Fixture {
    let raw_snapshot = serde_json::to_vec(&snapshot).expect("raw snapshot");
    {
        let descriptor = &mut value.request.authority_packet_request.descriptors[2];
        descriptor.origin = match snapshot.input_class {
            KcvInputClass::DeterministicFixtureCandidate => {
                B1OaprCandidateOrigin::DeterministicFixtureCandidate
            }
            KcvInputClass::ExternallySuppliedCandidate => {
                B1OaprCandidateOrigin::ExternallySuppliedCandidate
            }
        };
        descriptor.opaque_reference = if snapshot.fixture_only {
            "fixture_candidate_a3_revocation_snapshot".to_owned()
        } else {
            "externally_supplied_a3_revocation_snapshot".to_owned()
        };
        descriptor.content_sha256 = sha256_bytes(&raw_snapshot);
        descriptor.declared_bytes = raw_snapshot.len() as u64;
        descriptor.fixture_only = snapshot.fixture_only;
        descriptor.descriptor_sha256 = b1oapr_descriptor_digest(descriptor).expect("A3 descriptor");
    }
    value.request.authority_packet_request.request_sha256 =
        b1oapr_request_digest(&value.request.authority_packet_request).expect("packet request");
    let packet = compile_b1oapr_packet(&value.request.authority_packet_request).expect("packet");
    value.request.authority_packet_request_sha256 = value
        .request
        .authority_packet_request
        .request_sha256
        .clone();
    value.request.authority_packet_sha256 = packet.packet_sha256;
    value.request.a3_candidate_uuid = value.request.authority_packet_request.descriptors[2]
        .candidate_uuid
        .clone();
    value.request.a3_descriptor_sha256 = value.request.authority_packet_request.descriptors[2]
        .descriptor_sha256
        .clone();
    value.request.revocation_snapshot_bytes = raw_snapshot.len() as u64;
    value.request.revocation_snapshot_raw_sha256 = sha256_bytes(&raw_snapshot);
    value.request.input_class = snapshot.input_class;
    value.request.request_sha256 = krv_request_digest(&value.request).expect("request digest");
    value.snapshot = snapshot;
    value.raw_snapshot = raw_snapshot;
    value
}

fn fixture_for(status: KrvStatusAssertion, input_class: KcvInputClass) -> Fixture {
    let predecessor_request: B1OaprRequest = parsed("predecessor_request.json");
    let predecessor_packet: B1OaprPacket = parsed("predecessor_packet.json");
    let predecessor_verification: B1OaprVerification = parsed("predecessor_verification.json");
    let a1_envelope: BpvPolicyEnvelope = parsed("a1_policy_envelope.json");
    let raw_a1_envelope = raw("a1_policy_envelope.json");
    let a1_request: BpvVerificationRequest = parsed("a1_verification_request.json");
    let a1_receipt: BpvVerificationReceipt = parsed("a1_receipt.json");
    let a2_attestation: KcvCustodyAttestation = parsed("custody_attestation.json");
    let raw_a2_attestation = raw("custody_attestation.json");
    let a2_request: KcvVerificationRequest = parsed("verification_request.json");
    let a2_receipt: KcvVerificationReceipt = parsed("receipt.json");
    let responder_key = SigningKey::from_bytes(&[9_u8; 32]);
    let fixture_only = matches!(input_class, KcvInputClass::DeterministicFixtureCandidate);
    let a3_candidate_uuid = a2_request.authority_packet_request.descriptors[2]
        .candidate_uuid
        .clone();
    let mut snapshot = KrvRevocationSnapshot {
        profile: KRV_SNAPSHOT_PROFILE.to_owned(),
        snapshot_uuid: "a3000000-0000-4000-8000-000000000001".to_owned(),
        candidate_label: if fixture_only {
            "fixture_a3_revocation_snapshot_candidate".to_owned()
        } else {
            "external_a3_revocation_snapshot_candidate".to_owned()
        },
        responder_label: if fixture_only {
            "fixture_responder_untrusted".to_owned()
        } else {
            "external_claimed_responder_untrusted".to_owned()
        },
        snapshot_scope: "a1_public_verifying_key_revocation_status_at_declared_snapshot_interval"
            .to_owned(),
        subject: "cantor_b1_cdrive_production_preparation_p0".to_owned(),
        branch: "codex/self-hosted-corpus".to_owned(),
        canonical_remote: "https://github.com/cattailfarmer/Cantor".to_owned(),
        policy_uuid: a2_receipt.policy_uuid.clone(),
        policy_revision_uuid: a2_receipt.policy_revision_uuid.clone(),
        a1_receipt_sha256: a1_receipt.receipt_sha256.clone(),
        a2_receipt_sha256: a2_receipt.receipt_sha256.clone(),
        a3_candidate_uuid,
        target_verifying_key_hex: a1_envelope.verifying_key_hex.clone(),
        target_public_key_fingerprint_sha256: a2_receipt.public_key_fingerprint_sha256.clone(),
        responder_verifying_key_hex: lower_hex(responder_key.verifying_key().as_bytes()),
        status_assertion: status,
        sequence: 1,
        prior_snapshot_sha256: None,
        this_update_unix_ms: 1_700_000_000_000,
        produced_at_unix_ms: 1_700_000_001_000,
        next_update_unix_ms: 1_700_003_600_000,
        revocation_time_unix_ms: (status == KrvStatusAssertion::RevokedAtSnapshot)
            .then_some(1_699_999_000_000),
        revocation_reason: (status == KrvStatusAssertion::RevokedAtSnapshot)
            .then(|| "key_compromise_fixture_assertion".to_owned()),
        signing_context: KRV_SIGNING_CONTEXT.to_owned(),
        signature_hex: String::new(),
        input_class,
        fixture_only,
        production_authority_claimed: false,
        responder_identity_proved: false,
        responder_authority_proved: false,
        source_completeness_proved: false,
        monotonic_history_proved: false,
        snapshot_freshness_proved: false,
        current_time_compared: false,
        revocation_truth_proved: false,
        snapshot_sha256: empty_digest(),
    };
    resign(&mut snapshot, &responder_key);
    let mut request = KrvVerificationRequest {
        profile: KRV_REQUEST_PROFILE.to_owned(),
        source_snapshot_uuid: KRV_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: KRV_CANONICAL_UUID.to_owned(),
        signature_uuid: KRV_SIGNATURE_UUID.to_owned(),
        source_custody_commit: KRV_SOURCE_CUSTODY_COMMIT.to_owned(),
        formation_commit: KRV_FORMATION_COMMIT.to_owned(),
        formation_bookend_commit: KRV_FORMATION_BOOKEND_COMMIT.to_owned(),
        a2_implementation_commit: KRV_A2_IMPLEMENTATION_COMMIT.to_owned(),
        a2_bookend_commit: KRV_A2_BOOKEND_COMMIT.to_owned(),
        a2_proof_uuid: KRV_A2_PROOF_UUID.to_owned(),
        predecessor_request_sha256: predecessor_request.request_sha256.clone(),
        predecessor_packet_sha256: predecessor_packet.packet_sha256.clone(),
        predecessor_verification_sha256: predecessor_verification.verification_sha256.clone(),
        a1_policy_envelope_raw_sha256: sha256_bytes(&raw_a1_envelope),
        a1_verification_request_sha256: a1_request.request_sha256.clone(),
        a1_receipt_sha256: a1_receipt.receipt_sha256.clone(),
        a2_custody_attestation_raw_sha256: sha256_bytes(&raw_a2_attestation),
        a2_verification_request_sha256: a2_request.request_sha256.clone(),
        a2_receipt_sha256: a2_receipt.receipt_sha256.clone(),
        authority_packet_request: a2_request.authority_packet_request.clone(),
        authority_packet_request_sha256: empty_digest(),
        authority_packet_sha256: empty_digest(),
        a3_candidate_uuid: String::new(),
        a3_descriptor_sha256: empty_digest(),
        revocation_snapshot_bytes: 0,
        revocation_snapshot_raw_sha256: empty_digest(),
        input_class,
        evidence_references: vec![
            "predecessor_request.json",
            "predecessor_packet.json",
            "predecessor_verification.json",
            "a1_policy_envelope.json",
            "a1_verification_request.json",
            "a1_receipt.json",
            "custody_attestation.json",
            "a2_verification_request.json",
            "a2_receipt.json",
            "revocation_snapshot.json",
            "verification_request.json",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        maximum_attempts: 1,
        automatic_retry_count: 0,
        automatic_cleanup_count: 0,
        request_sha256: empty_digest(),
    };
    request.authority_packet_request_sha256 =
        request.authority_packet_request.request_sha256.clone();
    let base = Fixture {
        predecessor_request,
        predecessor_packet,
        predecessor_verification,
        a1_envelope,
        raw_a1_envelope,
        a1_request,
        a1_receipt,
        a2_attestation,
        raw_a2_attestation,
        a2_request,
        a2_receipt,
        snapshot: snapshot.clone(),
        raw_snapshot: Vec::new(),
        request,
    };
    bind_snapshot(base, snapshot)
}

fn fixture() -> Fixture {
    fixture_for(
        KrvStatusAssertion::NotRevokedAtSnapshot,
        KcvInputClass::DeterministicFixtureCandidate,
    )
}

fn verify(value: &Fixture) -> Result<KrvVerificationReceipt, KrvFault> {
    verify_krv_revocation_snapshot(
        &value.request,
        &value.predecessor_request,
        &value.predecessor_packet,
        &value.predecessor_verification,
        &value.a1_envelope,
        &value.raw_a1_envelope,
        &value.a1_request,
        &value.a1_receipt,
        &value.a2_attestation,
        &value.raw_a2_attestation,
        &value.a2_request,
        &value.a2_receipt,
        &value.raw_snapshot,
    )
}

fn retained_line(text: String) -> Vec<u8> {
    let mut bytes = text.into_bytes();
    bytes.push(b'\n');
    bytes
}

fn write_evidence(root: &Path, value: &Fixture) {
    fs::create_dir(root).expect("fresh evidence directory");
    let receipt = verify(value).expect("receipt");
    let artifacts = vec![
        (
            KRV_PREDECESSOR_REQUEST_FILE,
            retained("predecessor_request.json").to_vec(),
        ),
        (
            KRV_PREDECESSOR_PACKET_FILE,
            retained("predecessor_packet.json").to_vec(),
        ),
        (
            KRV_PREDECESSOR_VERIFICATION_FILE,
            retained("predecessor_verification.json").to_vec(),
        ),
        (
            KRV_A1_POLICY_ENVELOPE_FILE,
            retained("a1_policy_envelope.json").to_vec(),
        ),
        (
            KRV_A1_VERIFICATION_REQUEST_FILE,
            retained("a1_verification_request.json").to_vec(),
        ),
        (KRV_A1_RECEIPT_FILE, retained("a1_receipt.json").to_vec()),
        (
            KRV_CUSTODY_ATTESTATION_FILE,
            retained("custody_attestation.json").to_vec(),
        ),
        (
            KRV_A2_VERIFICATION_REQUEST_FILE,
            retained("verification_request.json").to_vec(),
        ),
        (KRV_A2_RECEIPT_FILE, retained("receipt.json").to_vec()),
        (
            KRV_REVOCATION_SNAPSHOT_FILE,
            retained_line(to_krv_snapshot_machine_form(&value.snapshot).expect("snapshot form")),
        ),
        (
            KRV_VERIFICATION_REQUEST_FILE,
            retained_line(to_krv_request_machine_form(&value.request).expect("request form")),
        ),
        (
            KRV_RECEIPT_FILE,
            retained_line(
                to_krv_receipt_machine_form(&value.request, &value.snapshot, &receipt)
                    .expect("receipt form"),
            ),
        ),
    ];
    let mut bindings = Vec::new();
    let mut total = 0_u64;
    for (name, bytes) in artifacts {
        fs::write(root.join(name), &bytes).expect("write artifact");
        total = total
            .checked_add(bytes.len() as u64)
            .expect("artifact total");
        bindings.push(KrvEvidenceArtifact {
            path: name.to_owned(),
            bytes: bytes.len() as u64,
            sha256: sha256_bytes(&bytes),
        });
    }
    let mut manifest = KrvEvidenceManifest {
        profile: KRV_EVIDENCE_PROFILE.to_owned(),
        manifest_uuid: "a3000000-0000-4000-8000-000000000002".to_owned(),
        fixture_only: value.snapshot.fixture_only,
        artifacts: bindings,
        artifact_count: 12,
        total_artifact_bytes: total,
        retained_authority_packet_sha256: receipt.authority_packet_sha256.clone(),
        retained_a1_receipt_sha256: receipt.a1_receipt_sha256.clone(),
        retained_a2_receipt_sha256: receipt.a2_receipt_sha256.clone(),
        retained_receipt_sha256: receipt.receipt_sha256,
        deterministic_replay_count: 2,
        required_fresh_process_replay_count: 2,
        byte_identical: true,
        effect_count: 0,
        manifest_sha256: empty_digest(),
    };
    manifest.manifest_sha256 = krv_evidence_manifest_digest(&manifest).expect("manifest digest");
    fs::write(
        root.join(KRV_EVIDENCE_MANIFEST_FILE),
        retained_line(
            to_krv_evidence_manifest_machine_form(&manifest).expect("manifest machine form"),
        ),
    )
    .expect("write manifest");
}

fn temporary_evidence(value: &Fixture) -> TempEvidence {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "cantor_krv_evidence_{}_{}",
        std::process::id(),
        sequence
    ));
    assert!(!root.exists(), "temporary evidence path must be fresh");
    write_evidence(&root, value);
    TempEvidence(root)
}

#[test]
fn all_three_statuses_project_exactly_without_authority_or_effects() {
    for status in [
        KrvStatusAssertion::NotRevokedAtSnapshot,
        KrvStatusAssertion::RevokedAtSnapshot,
        KrvStatusAssertion::UnknownAtSnapshot,
    ] {
        let value = fixture_for(status, KcvInputClass::DeterministicFixtureCandidate);
        let receipt = verify(&value).expect("valid status fixture");
        assert!(receipt.packet_replayed);
        assert!(receipt.a1_correspondence_receipt_verified);
        assert!(receipt.a2_correspondence_receipt_verified);
        assert!(receipt.a3_candidate_bytes_matched);
        assert!(receipt.descriptor_correspondence_verified);
        assert!(receipt.target_policy_key_correspondence_verified);
        assert!(receipt.snapshot_structure_verified);
        assert!(receipt.interval_structure_verified);
        assert!(receipt.responder_signature_correspondence_verified);
        assert_eq!(
            u8::from(receipt.status_assertion_not_revoked)
                + u8::from(receipt.status_assertion_revoked)
                + u8::from(receipt.status_assertion_unknown),
            1
        );
        assert!(!receipt.responder_authority_proved);
        assert!(!receipt.current_time_compared);
        assert!(!receipt.revocation_truth_proved);
        assert!(!receipt.execution_authorized);
        assert_eq!(receipt.effect_account, KrvEffectAccount::default());
    }
}

#[test]
fn external_candidate_class_is_supported_without_trust_promotion() {
    let value = fixture_for(
        KrvStatusAssertion::UnknownAtSnapshot,
        KcvInputClass::ExternallySuppliedCandidate,
    );
    let receipt = verify(&value).expect("external candidate");
    assert!(!receipt.fixture_only);
    assert!(!receipt.responder_identity_proved);
    assert!(!receipt.responder_authority_proved);
}

#[test]
fn lineage_and_coordinate_substitution_are_refused() {
    let mut lineage = fixture();
    lineage.request.formation_commit = "0000000000000000000000000000000000000001".to_owned();
    lineage.request.request_sha256 = krv_request_digest(&lineage.request).expect("digest");
    assert_eq!(
        verify(&lineage).expect_err("lineage").code,
        KrvFaultCode::Lineage
    );

    let mut coordinate = fixture();
    coordinate.request.a3_candidate_uuid = "a3000000-0000-4000-8000-000000000099".to_owned();
    coordinate.request.request_sha256 = krv_request_digest(&coordinate.request).expect("digest");
    assert_eq!(
        verify(&coordinate).expect_err("coordinate").code,
        KrvFaultCode::Coordinate
    );
}

#[test]
fn raw_snapshot_and_a2_dependency_tamper_are_refused() {
    let mut raw_tamper = fixture();
    raw_tamper.raw_snapshot.push(b' ');
    assert_eq!(
        verify(&raw_tamper).expect_err("raw tamper").code,
        KrvFaultCode::RawBytes
    );

    let mut dependency = fixture();
    dependency.a2_receipt.receipt_sha256 = empty_digest();
    assert_eq!(
        verify(&dependency).expect_err("A2 dependency").code,
        KrvFaultCode::Predecessor
    );
}

#[test]
fn target_key_and_responder_signature_tamper_are_refused_after_rebinding() {
    let responder_key = SigningKey::from_bytes(&[9_u8; 32]);
    let value = fixture();
    let mut target = value.snapshot.clone();
    target.target_verifying_key_hex = "00".repeat(32);
    resign(&mut target, &responder_key);
    let target = bind_snapshot(value, target);
    assert_eq!(
        verify(&target).expect_err("target key").code,
        KrvFaultCode::Key
    );

    let value = fixture();
    let mut signature = value.snapshot.clone();
    signature.signature_hex.replace_range(0..2, "00");
    signature.snapshot_sha256 = krv_snapshot_digest(&signature).expect("digest");
    let signature = bind_snapshot(value, signature);
    assert_eq!(
        verify(&signature).expect_err("signature").code,
        KrvFaultCode::Signature
    );
}

#[test]
fn interval_status_reason_and_rollback_laundering_are_refused() {
    let key = SigningKey::from_bytes(&[9_u8; 32]);
    let value = fixture();
    let mut interval = value.snapshot.clone();
    interval.produced_at_unix_ms = interval.next_update_unix_ms;
    resign(&mut interval, &key);
    let interval = bind_snapshot(value, interval);
    assert_eq!(
        verify(&interval).expect_err("interval").code,
        KrvFaultCode::Interval
    );

    let value = fixture();
    let mut status = value.snapshot.clone();
    status.revocation_reason = Some("unexpected".to_owned());
    resign(&mut status, &key);
    let status = bind_snapshot(value, status);
    assert_eq!(
        verify(&status).expect_err("status").code,
        KrvFaultCode::Status
    );

    let value = fixture();
    let mut rollback = value.snapshot.clone();
    rollback.prior_snapshot_sha256 = Some(empty_digest());
    resign(&mut rollback, &key);
    let rollback = bind_snapshot(value, rollback);
    assert_eq!(
        verify(&rollback).expect_err("rollback").code,
        KrvFaultCode::Rollback
    );
}

#[test]
fn snapshot_and_receipt_authority_promotion_are_refused() {
    let key = SigningKey::from_bytes(&[9_u8; 32]);
    let value = fixture();
    let mut snapshot = value.snapshot.clone();
    snapshot.responder_authority_proved = true;
    resign(&mut snapshot, &key);
    let snapshot = bind_snapshot(value, snapshot);
    assert_eq!(
        verify(&snapshot).expect_err("snapshot authority").code,
        KrvFaultCode::Truth
    );

    let value = fixture();
    let mut receipt = verify(&value).expect("receipt");
    receipt.revocation_truth_proved = true;
    receipt.receipt_sha256 = krv_receipt_digest(&receipt).expect("digest");
    assert_eq!(
        validate_krv_receipt(&value.request, &value.snapshot, &receipt)
            .expect_err("receipt authority")
            .code,
        KrvFaultCode::Truth
    );
}

#[test]
fn receipt_effect_and_request_bound_promotion_are_refused() {
    let value = fixture();
    let mut receipt = verify(&value).expect("receipt");
    receipt.effect_account.clock_read_count = 1;
    receipt.receipt_sha256 = krv_receipt_digest(&receipt).expect("digest");
    assert_eq!(
        validate_krv_receipt(&value.request, &value.snapshot, &receipt)
            .expect_err("effect")
            .code,
        KrvFaultCode::Effect
    );

    let mut request = fixture();
    request.request.evidence_references[1] = request.request.evidence_references[0].clone();
    request.request.request_sha256 = krv_request_digest(&request.request).expect("digest");
    assert_eq!(
        verify(&request).expect_err("duplicate ref").code,
        KrvFaultCode::Bound
    );
}

#[test]
fn noncanonical_unknown_duplicate_and_concatenated_snapshot_forms_are_refused() {
    let value = fixture();
    let text = std::str::from_utf8(&value.raw_snapshot).expect("UTF-8");
    for changed in [
        format!("{text} "),
        format!("{text}{text}"),
        text.replacen(
            '{',
            &format!("{{\"profile\":\"{}\",", KRV_SNAPSHOT_PROFILE),
            1,
        ),
        text.replacen('{', "{\"unknown\":false,", 1),
    ] {
        assert_eq!(
            from_krv_snapshot_machine_form(&changed)
                .expect_err("noncanonical")
                .code,
            KrvFaultCode::MachineForm
        );
    }
}

#[test]
fn machine_forms_round_trip_byte_identically() {
    let value = fixture();
    let receipt = verify(&value).expect("receipt");
    let snapshot = to_krv_snapshot_machine_form(&value.snapshot).expect("snapshot form");
    let request = to_krv_request_machine_form(&value.request).expect("request form");
    let receipt_text = to_krv_receipt_machine_form(&value.request, &value.snapshot, &receipt)
        .expect("receipt form");
    assert_eq!(
        from_krv_snapshot_machine_form(&snapshot).expect("snapshot"),
        value.snapshot
    );
    assert_eq!(
        from_krv_request_machine_form(&request).expect("request"),
        value.request
    );
    assert_eq!(
        from_krv_receipt_machine_form(&value.request, &value.snapshot, &receipt_text)
            .expect("receipt"),
        receipt
    );
}

#[test]
fn production_module_exposes_no_private_key_clock_process_network_or_write_primitive() {
    let sources = [
        include_str!("../src/b1_public_verifying_key_revocation_snapshot_verification.rs"),
        include_str!("../src/b1_public_verifying_key_revocation_snapshot_verification_evidence.rs"),
        include_str!("../src/bin/cantor-b1-public-verifying-key-revocation-snapshot-verify.rs"),
        include_str!("../src/bin/cantor-b1-public-verifying-key-revocation-evidence-verify.rs"),
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
            "forbidden primitive: {forbidden}"
        );
    }
}

#[test]
fn independent_evidence_replay_reconstructs_all_twelve_artifacts() {
    let value = fixture();
    let evidence = temporary_evidence(&value);
    let replay = verify_krv_evidence_directory(&evidence.0).expect("evidence replay");
    assert_eq!(replay.artifact_count, 12);
    assert_eq!(replay.deterministic_replay_count, 2);
    assert_eq!(replay.required_fresh_process_replay_count, 2);
    assert!(replay.byte_identical);
    assert_eq!(replay.receipt, verify(&value).expect("direct receipt"));
    assert_eq!(replay.receipt.effect_account, KrvEffectAccount::default());
}

#[test]
fn evidence_raw_byte_tamper_is_refused() {
    let evidence = temporary_evidence(&fixture());
    let path = evidence.0.join(KRV_REVOCATION_SNAPSHOT_FILE);
    let mut bytes = fs::read(&path).expect("read");
    bytes.insert(bytes.len() - 1, b' ');
    fs::write(path, bytes).expect("tamper");
    verify_krv_evidence_directory(&evidence.0).expect_err("raw evidence tamper");
}

#[test]
fn missing_or_extra_evidence_file_is_refused() {
    let missing = temporary_evidence(&fixture());
    fs::remove_file(missing.0.join(KRV_RECEIPT_FILE)).expect("remove receipt");
    verify_krv_evidence_directory(&missing.0).expect_err("missing file");

    let extra = temporary_evidence(&fixture());
    fs::write(extra.0.join("extra.json"), b"{}\n").expect("extra file");
    verify_krv_evidence_directory(&extra.0).expect_err("extra file");
}

#[test]
#[ignore = "writes only a fresh explicit test-owned evidence directory"]
fn produce_retained_krv_fixture_evidence() {
    let root = std::env::var_os("CANTOR_KRV_EVIDENCE_OUTPUT")
        .map(PathBuf::from)
        .expect("CANTOR_KRV_EVIDENCE_OUTPUT must name a fresh explicit directory");
    assert!(!root.exists(), "evidence output must be absent");
    write_evidence(&root, &fixture());
    let replay = verify_krv_evidence_directory(&root).expect("retained evidence replay");
    println!(
        "krv_evidence_written root={} artifacts={} bytes={} replay={} restart_required={} byte_identical={} effects=0",
        root.display(),
        replay.artifact_count,
        replay.total_artifact_bytes,
        replay.deterministic_replay_count,
        replay.required_fresh_process_replay_count,
        replay.byte_identical
    );
}
