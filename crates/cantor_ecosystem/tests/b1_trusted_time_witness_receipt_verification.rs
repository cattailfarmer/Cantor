use cantor_core::{ContentDigest, sha256_bytes};
use cantor_ecosystem::*;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const A3_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../experiments/b1_public_verifying_key_revocation_snapshot_verification_p0/implementation_provider_free_evidence"
);
const CLI: &str = env!("CARGO_BIN_EXE_cantor-b1-trusted-time-witness-verify");
const EVIDENCE_CLI: &str = env!("CARGO_BIN_EXE_cantor-b1-trusted-time-witness-evidence-verify");
fn empty() -> ContentDigest {
    sha256_bytes(b"")
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn raw(name: &str) -> Vec<u8> {
    let bytes = fs::read(Path::new(A3_ROOT).join(name)).expect("retained A3 fixture");
    bytes.strip_suffix(b"\n").expect("retained LF").to_vec()
}
fn parsed<T: DeserializeOwned>(name: &str) -> T {
    serde_json::from_slice(&raw(name)).expect("retained A3 typed form")
}
fn line<T: Serialize>(value: &T) -> Vec<u8> {
    let mut b = serde_json::to_vec(value).unwrap();
    b.push(b'\n');
    b
}
fn resign(witness: &mut TwvTimeWitness, key: &SigningKey) {
    witness.signature_hex = hex(&key
        .sign(&twv_signature_payload_bytes(witness).unwrap())
        .to_bytes());
    witness.witness_sha256 = twv_witness_digest(witness).unwrap();
}
#[derive(Clone)]
struct Fixture {
    predecessor_request: B1OaprRequest,
    predecessor_packet: B1OaprPacket,
    predecessor_verification: B1OaprVerification,
    a1_envelope: BpvPolicyEnvelope,
    raw_a1: Vec<u8>,
    a1_request: BpvVerificationRequest,
    a1_receipt: BpvVerificationReceipt,
    a2_attestation: KcvCustodyAttestation,
    raw_a2: Vec<u8>,
    a2_request: KcvVerificationRequest,
    a2_receipt: KcvVerificationReceipt,
    raw_a3: Vec<u8>,
    a3_request: KrvVerificationRequest,
    a3_receipt: KrvVerificationReceipt,
    witness: TwvTimeWitness,
    raw_witness: Vec<u8>,
    request: TwvVerificationRequest,
}
impl Fixture {
    fn predecessor(&self) -> TwvPredecessor<'_> {
        TwvPredecessor {
            request: &self.predecessor_request,
            packet: &self.predecessor_packet,
            verification: &self.predecessor_verification,
            a1_envelope: &self.a1_envelope,
            raw_a1_envelope: &self.raw_a1,
            a1_request: &self.a1_request,
            a1_receipt: &self.a1_receipt,
            a2_attestation: &self.a2_attestation,
            raw_a2_attestation: &self.raw_a2,
            a2_request: &self.a2_request,
            a2_receipt: &self.a2_receipt,
            raw_a3_snapshot: &self.raw_a3,
            a3_request: &self.a3_request,
            a3_receipt: &self.a3_receipt,
        }
    }
    fn verify(&self) -> Result<TwvVerificationReceipt, TwvFault> {
        verify_twv_time_witness(&self.request, &self.predecessor(), &self.raw_witness)
    }
    fn bind(&mut self) {
        self.raw_witness = serde_json::to_vec(&self.witness).unwrap();
        let d = &mut self.request.authority_packet_request.descriptors[3];
        d.origin = if self.witness.fixture_only {
            B1OaprCandidateOrigin::DeterministicFixtureCandidate
        } else {
            B1OaprCandidateOrigin::ExternallySuppliedCandidate
        };
        d.fixture_only = self.witness.fixture_only;
        d.declared_bytes = self.raw_witness.len() as u64;
        d.content_sha256 = sha256_bytes(&self.raw_witness);
        d.descriptor_sha256 = b1oapr_descriptor_digest(d).unwrap();
        self.request.a4_candidate_uuid = d.candidate_uuid.clone();
        self.request.a4_descriptor_sha256 = d.descriptor_sha256.clone();
        self.request.time_witness_receipt_bytes = d.declared_bytes;
        self.request.time_witness_receipt_raw_sha256 = d.content_sha256.clone();
        self.request.authority_packet_request.request_sha256 =
            b1oapr_request_digest(&self.request.authority_packet_request).unwrap();
        self.request.authority_packet_request_sha256 =
            self.request.authority_packet_request.request_sha256.clone();
        self.request.authority_packet_sha256 =
            compile_b1oapr_packet(&self.request.authority_packet_request)
                .unwrap()
                .packet_sha256;
        self.request.request_sha256 = twv_request_digest(&self.request).unwrap();
    }
    fn signed_change(&mut self, change: impl FnOnce(&mut TwvTimeWitness)) {
        change(&mut self.witness);
        resign(&mut self.witness, &SigningKey::from_bytes(&[13; 32]));
        self.bind();
    }
}
fn fixture_for(class: KcvInputClass) -> Fixture {
    let a1_receipt: BpvVerificationReceipt = parsed("a1_receipt.json");
    let a2_receipt: KcvVerificationReceipt = parsed("a2_receipt.json");
    let a3_receipt: KrvVerificationReceipt = parsed("receipt.json");
    let a3_request: KrvVerificationRequest = parsed("verification_request.json");
    let key = SigningKey::from_bytes(&[13; 32]);
    let is_fixture = class == KcvInputClass::DeterministicFixtureCandidate;
    let mut witness = TwvTimeWitness {
        profile: TWV_WITNESS_PROFILE.to_owned(),
        witness_uuid: "a4000000-0000-4000-8000-000000000001".to_owned(),
        candidate_label: if is_fixture {
            "fixture_a4_time_witness_candidate"
        } else {
            "external_a4_time_witness_candidate"
        }
        .to_owned(),
        authority_label: "fixture_supplied_witness_not_trusted".to_owned(),
        subject: "cantor_b1_cdrive_production_preparation_p0".to_owned(),
        branch: "codex/self-hosted-corpus".to_owned(),
        canonical_remote: "https://github.com/cattailfarmer/Cantor".to_owned(),
        policy_uuid: a3_receipt.policy_uuid.clone(),
        policy_revision_uuid: a3_receipt.policy_revision_uuid.clone(),
        a1_receipt_sha256: a1_receipt.receipt_sha256.clone(),
        a2_receipt_sha256: a2_receipt.receipt_sha256.clone(),
        a3_receipt_sha256: a3_receipt.receipt_sha256.clone(),
        a3_authority_packet_sha256: a3_receipt.authority_packet_sha256.clone(),
        a3_snapshot_sha256: a3_receipt.snapshot_sha256.clone(),
        a3_snapshot_raw_sha256: a3_receipt.revocation_snapshot_raw_sha256.clone(),
        a4_candidate_uuid: a3_request.authority_packet_request.descriptors[3]
            .candidate_uuid
            .clone(),
        target_policy_key_fingerprint_sha256: a3_receipt
            .target_public_key_fingerprint_sha256
            .clone(),
        witness_verifying_key_hex: hex(key.verifying_key().as_bytes()),
        witness_public_key_fingerprint_sha256: sha256_bytes(key.verifying_key().as_bytes()),
        observed_unix_ms: a3_receipt.this_update_unix_ms + 1000,
        issued_at_unix_ms: 0,
        expires_at_unix_ms: u64::MAX,
        sequence: 1,
        signing_context: TWV_SIGNING_CONTEXT.to_owned(),
        signature_hex: String::new(),
        input_class: class,
        fixture_only: is_fixture,
        production_authority_claimed: false,
        witness_identity_proved: false,
        witness_authority_proved: false,
        witness_freshness_proved: false,
        trusted_current_time_proved: false,
        witness_sha256: empty(),
    };
    resign(&mut witness, &key);
    let predecessor_request: B1OaprRequest = parsed("predecessor_request.json");
    let predecessor_packet: B1OaprPacket = parsed("predecessor_packet.json");
    let predecessor_verification: B1OaprVerification = parsed("predecessor_verification.json");
    let a1_request: BpvVerificationRequest = parsed("a1_verification_request.json");
    let a2_request: KcvVerificationRequest = parsed("a2_verification_request.json");
    let request = TwvVerificationRequest {
        profile: TWV_REQUEST_PROFILE.to_owned(),
        source_snapshot_uuid: TWV_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: TWV_CANONICAL_UUID.to_owned(),
        signature_uuid: TWV_SIGNATURE_UUID.to_owned(),
        source_custody_commit: TWV_SOURCE_CUSTODY_COMMIT.to_owned(),
        formation_commit: TWV_FORMATION_COMMIT.to_owned(),
        formation_bookend_commit: TWV_FORMATION_BOOKEND_COMMIT.to_owned(),
        a3_implementation_commit: TWV_A3_IMPLEMENTATION_COMMIT.to_owned(),
        a3_bookend_commit: TWV_A3_BOOKEND_COMMIT.to_owned(),
        a3_proof_uuid: TWV_A3_PROOF_UUID.to_owned(),
        predecessor_request_sha256: predecessor_request.request_sha256.clone(),
        predecessor_packet_sha256: predecessor_packet.packet_sha256.clone(),
        predecessor_verification_sha256: predecessor_verification.verification_sha256.clone(),
        a1_policy_envelope_raw_sha256: sha256_bytes(&raw("a1_policy_envelope.json")),
        a1_verification_request_sha256: a1_request.request_sha256.clone(),
        a1_receipt_sha256: a1_receipt.receipt_sha256.clone(),
        a2_custody_attestation_raw_sha256: sha256_bytes(&raw("custody_attestation.json")),
        a2_verification_request_sha256: a2_request.request_sha256.clone(),
        a2_receipt_sha256: a2_receipt.receipt_sha256.clone(),
        a3_revocation_snapshot_raw_sha256: sha256_bytes(&raw("revocation_snapshot.json")),
        a3_verification_request_sha256: a3_request.request_sha256.clone(),
        a3_receipt_sha256: a3_receipt.receipt_sha256.clone(),
        authority_packet_request: a3_request.authority_packet_request.clone(),
        authority_packet_request_sha256: empty(),
        authority_packet_sha256: empty(),
        a4_candidate_uuid: witness.a4_candidate_uuid.clone(),
        a4_descriptor_sha256: empty(),
        time_witness_receipt_bytes: 0,
        time_witness_receipt_raw_sha256: empty(),
        expected_witness_uuid: witness.witness_uuid.clone(),
        expected_witness_authority_label: witness.authority_label.clone(),
        expected_witness_verifying_key_hex: witness.witness_verifying_key_hex.clone(),
        expected_witness_public_key_fingerprint_sha256: witness
            .witness_public_key_fingerprint_sha256
            .clone(),
        expected_sequence: 1,
        input_class: class,
        evidence_references: TWV_EVIDENCE_FILES[..14]
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        maximum_attempts: 1,
        automatic_retry_count: 0,
        automatic_cleanup_count: 0,
        request_sha256: empty(),
    };
    let mut fixture = Fixture {
        predecessor_request,
        predecessor_packet,
        predecessor_verification,
        a1_envelope: parsed("a1_policy_envelope.json"),
        raw_a1: raw("a1_policy_envelope.json"),
        a1_request,
        a1_receipt,
        a2_attestation: parsed("custody_attestation.json"),
        raw_a2: raw("custody_attestation.json"),
        a2_request,
        a2_receipt,
        raw_a3: raw("revocation_snapshot.json"),
        a3_request,
        a3_receipt,
        witness,
        raw_witness: Vec::new(),
        request,
    };
    fixture.bind();
    fixture
}
fn fixture() -> Fixture {
    fixture_for(KcvInputClass::DeterministicFixtureCandidate)
}
fn write_evidence(root: &Path, f: &Fixture) {
    fs::create_dir(root).expect("fresh caller-owned evidence directory");
    let receipt = f.verify().expect("valid fixture");
    let payloads = [
        line(&f.predecessor_request),
        line(&f.predecessor_packet),
        line(&f.predecessor_verification),
        line(&f.a1_envelope),
        line(&f.a1_request),
        line(&f.a1_receipt),
        line(&f.a2_attestation),
        line(&f.a2_request),
        line(&f.a2_receipt),
        {
            let mut b = f.raw_a3.clone();
            b.push(b'\n');
            b
        },
        line(&f.a3_request),
        line(&f.a3_receipt),
        line(&f.witness),
        line(&f.request),
        line(&receipt),
    ];
    let mut artifacts = Vec::new();
    let mut total = 0;
    for (name, bytes) in TWV_EVIDENCE_FILES.iter().zip(payloads) {
        fs::write(root.join(name), &bytes).unwrap();
        total += bytes.len() as u64;
        artifacts.push(TwvEvidenceArtifact {
            path: (*name).to_owned(),
            bytes: bytes.len() as u64,
            sha256: sha256_bytes(&bytes),
        });
    }
    let mut manifest = TwvEvidenceManifest {
        profile: TWV_EVIDENCE_PROFILE.to_owned(),
        manifest_uuid: "a4000000-0000-4000-8000-000000000002".to_owned(),
        fixture_only: f.witness.fixture_only,
        artifacts,
        artifact_count: 15,
        total_artifact_bytes: total,
        retained_authority_packet_sha256: receipt.authority_packet_sha256,
        retained_a1_receipt_sha256: receipt.a1_receipt_sha256,
        retained_a2_receipt_sha256: receipt.a2_receipt_sha256,
        retained_a3_receipt_sha256: receipt.a3_receipt_sha256,
        retained_receipt_sha256: receipt.receipt_sha256,
        deterministic_replay_count: 2,
        required_fresh_process_replay_count: 2,
        byte_identical: true,
        effect_count: 0,
        manifest_sha256: empty(),
    };
    manifest.manifest_sha256 = twv_evidence_manifest_digest(&manifest).unwrap();
    fs::write(root.join("evidence_manifest.json"), line(&manifest)).unwrap();
}
struct TempEvidence {
    root: PathBuf,
    parent: PathBuf,
}
impl Drop for TempEvidence {
    fn drop(&mut self) {
        // Only this test's fresh direct child may be removed; never a supplied retained directory.
        assert_eq!(self.root.parent(), Some(self.parent.as_path()));
        assert!(
            self.root
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("cantor_twv_test_")
        );
        if self.root.exists() {
            fs::remove_dir_all(&self.root).expect("remove owned test fixture");
        }
    }
}
fn temporary(f: &Fixture) -> TempEvidence {
    let parent = std::env::temp_dir()
        .canonicalize()
        .expect("temporary parent");
    let root = parent.join(format!(
        "cantor_twv_test_{}_{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    write_evidence(&root, f);
    TempEvidence { root, parent }
}
fn manifest(root: &Path) -> TwvEvidenceManifest {
    serde_json::from_slice(&fs::read(root.join("evidence_manifest.json")).unwrap()).unwrap()
}
fn save_manifest(root: &Path, mut m: TwvEvidenceManifest) {
    m.manifest_sha256 = twv_evidence_manifest_digest(&m).unwrap();
    fs::write(root.join("evidence_manifest.json"), line(&m)).unwrap();
}
fn refresh(root: &Path) {
    let mut m = manifest(root);
    m.total_artifact_bytes = 0;
    for a in &mut m.artifacts {
        let b = fs::read(root.join(&a.path)).unwrap();
        a.bytes = b.len() as u64;
        a.sha256 = sha256_bytes(&b);
        m.total_artifact_bytes += a.bytes;
    }
    save_manifest(root, m);
}
fn change_typed<T: Serialize + DeserializeOwned>(value: &T, field: &str, replacement: Value) -> T {
    let mut v = serde_json::to_value(value).unwrap();
    v[field] = replacement;
    serde_json::from_value(v).unwrap()
}

#[test]
fn both_input_classes_replay_without_promoting_authority() {
    for class in [
        KcvInputClass::DeterministicFixtureCandidate,
        KcvInputClass::ExternallySuppliedCandidate,
    ] {
        let f = fixture_for(class);
        let r = f.verify().unwrap();
        assert_eq!(r, f.verify().unwrap());
        assert_eq!(r.status, TWV_STATUS);
        assert_eq!(r.authority, TWV_AUTHORITY);
        assert_eq!(r.input_class, class);
        assert_eq!(r.effect_account, TwvEffectAccount::default());
        assert!(
            !r.trusted_current_time_proved && !r.execution_authorized && !r.current_time_compared
        );
        assert_eq!(
            r.fixture_only,
            class == KcvInputClass::DeterministicFixtureCandidate
        );
        let text = to_twv_receipt_machine_form(&f.request, &f.witness, &f.a3_receipt, &r).unwrap();
        assert_eq!(
            from_twv_receipt_machine_form(&f.request, &f.witness, &f.a3_receipt, &text).unwrap(),
            r
        );
        assert_eq!(
            from_twv_request_machine_form(&to_twv_request_machine_form(&f.request).unwrap())
                .unwrap(),
            f.request
        );
        assert_eq!(
            from_twv_witness_machine_form(&to_twv_witness_machine_form(&f.witness).unwrap())
                .unwrap(),
            f.witness
        );
        let dir = temporary(&f);
        assert_eq!(verify_twv_evidence_directory(&dir.root).unwrap().receipt, r);
    }
}
#[test]
fn closed_interval_outcomes_endpoints_and_u64_extremes() {
    let base = fixture();
    let start = base.a3_receipt.this_update_unix_ms;
    let end = base.a3_receipt.next_update_unix_ms;
    for (observed, expected) in [
        (0, TwvIntervalRelation::BeforeSnapshotInterval),
        (start - 1, TwvIntervalRelation::BeforeSnapshotInterval),
        (start, TwvIntervalRelation::WithinSnapshotInterval),
        (end, TwvIntervalRelation::WithinSnapshotInterval),
        (end + 1, TwvIntervalRelation::AfterSnapshotInterval),
        (u64::MAX, TwvIntervalRelation::AfterSnapshotInterval),
    ] {
        let mut f = base.clone();
        f.signed_change(|w| w.observed_unix_ms = observed);
        assert_eq!(f.verify().unwrap().comparison_outcome, expected);
    }
    assert_eq!(
        compare_twv_supplied_interval(0, 0, u64::MAX).unwrap(),
        TwvIntervalRelation::WithinSnapshotInterval
    );
    assert_eq!(
        compare_twv_supplied_interval(u64::MAX, 0, u64::MAX).unwrap(),
        TwvIntervalRelation::WithinSnapshotInterval
    );
    for (a, b) in [(0, 0), (2, 1), (u64::MAX, u64::MAX)] {
        assert_eq!(
            compare_twv_supplied_interval(0, a, b).unwrap_err().code,
            TwvFaultCode::Interval
        );
    }
}
#[test]
fn signed_time_bounds_and_positive_sequence_are_structural_only() {
    for (issued, observed, expires, valid) in [
        (0, 0, 0, true),
        (u64::MAX, u64::MAX, u64::MAX, true),
        (2, 1, 3, false),
        (0, 2, 1, false),
    ] {
        let mut f = fixture();
        f.signed_change(|w| {
            w.issued_at_unix_ms = issued;
            w.observed_unix_ms = observed;
            w.expires_at_unix_ms = expires;
        });
        if valid {
            assert!(!f.verify().unwrap().witness_freshness_proved);
        } else {
            assert_eq!(f.verify().unwrap_err().code, TwvFaultCode::Interval);
        }
    }
    let mut f = fixture();
    f.signed_change(|w| w.sequence = 0);
    assert_eq!(f.verify().unwrap_err().code, TwvFaultCode::Sequence);
}
#[test]
fn witness_and_request_identity_pins_cannot_be_substituted() {
    for (field, replacement) in [
        (
            "witness_uuid",
            json!("a4000000-0000-4000-8000-000000000099"),
        ),
        ("authority_label", json!("some_other_label")),
        ("sequence", json!(2)),
    ] {
        let mut f = fixture();
        f.witness = change_typed(&f.witness, field, replacement);
        resign(&mut f.witness, &SigningKey::from_bytes(&[13; 32]));
        f.bind();
        assert_eq!(
            f.verify().unwrap_err().code,
            TwvFaultCode::Expectation,
            "{field}"
        );
    }
    let mut f = fixture();
    let other = SigningKey::from_bytes(&[14; 32]);
    f.witness.witness_verifying_key_hex = hex(other.verifying_key().as_bytes());
    f.witness.witness_public_key_fingerprint_sha256 =
        sha256_bytes(other.verifying_key().as_bytes());
    resign(&mut f.witness, &other);
    f.bind();
    assert_eq!(f.verify().unwrap_err().code, TwvFaultCode::Key);
    // Replacing the entire explicit expectation creates a different request, not external trust.
    f.request.expected_witness_verifying_key_hex = f.witness.witness_verifying_key_hex.clone();
    f.request.expected_witness_public_key_fingerprint_sha256 =
        f.witness.witness_public_key_fingerprint_sha256.clone();
    f.request.request_sha256 = twv_request_digest(&f.request).unwrap();
    let r = f.verify().unwrap();
    assert!(!r.witness_identity_proved && !r.witness_authority_proved);
}
#[test]
fn strict_signature_and_domain_tamper_refuse_after_rehashing() {
    let mut f = fixture();
    f.witness.signature_hex = "00".repeat(64);
    f.witness.witness_sha256 = twv_witness_digest(&f.witness).unwrap();
    f.bind();
    assert_eq!(f.verify().unwrap_err().code, TwvFaultCode::Signature);
    let mut f = fixture();
    f.signed_change(|w| w.signing_context = "other-context".to_owned());
    assert_eq!(f.verify().unwrap_err().code, TwvFaultCode::Signature);
    let mut f = fixture();
    f.witness.observed_unix_ms += 1;
    f.witness.witness_sha256 = twv_witness_digest(&f.witness).unwrap();
    f.bind();
    assert_eq!(f.verify().unwrap_err().code, TwvFaultCode::Signature);
    for field in ["witness_verifying_key_hex", "signature_hex"] {
        for value in [
            "GG",
            "00",
            &"A".repeat(if field == "signature_hex" { 128 } else { 64 }),
        ] {
            let mut f = fixture();
            f.witness = change_typed(&f.witness, field, json!(value));
            f.witness.witness_sha256 = twv_witness_digest(&f.witness).unwrap();
            f.bind();
            assert!(f.verify().is_err());
        }
    }
}
#[test]
fn witness_lineage_subject_and_candidate_drift_refuse() {
    for field in [
        "a1_receipt_sha256",
        "a2_receipt_sha256",
        "a3_receipt_sha256",
        "a3_authority_packet_sha256",
        "a3_snapshot_sha256",
        "a3_snapshot_raw_sha256",
        "target_policy_key_fingerprint_sha256",
    ] {
        let mut f = fixture();
        f.witness = change_typed(&f.witness, field, json!(empty()));
        resign(&mut f.witness, &SigningKey::from_bytes(&[13; 32]));
        f.bind();
        assert_eq!(
            f.verify().unwrap_err().code,
            TwvFaultCode::Dependency,
            "{field}"
        );
    }
    for field in ["policy_uuid", "policy_revision_uuid", "a4_candidate_uuid"] {
        let mut f = fixture();
        f.witness = change_typed(
            &f.witness,
            field,
            json!("a4000000-0000-4000-8000-000000000099"),
        );
        resign(&mut f.witness, &SigningKey::from_bytes(&[13; 32]));
        f.bind();
        assert_eq!(
            f.verify().unwrap_err().code,
            TwvFaultCode::Dependency,
            "{field}"
        );
    }
    for field in [
        "subject",
        "branch",
        "canonical_remote",
        "candidate_label",
        "profile",
    ] {
        let mut f = fixture();
        f.witness = change_typed(&f.witness, field, json!("incorrect"));
        resign(&mut f.witness, &SigningKey::from_bytes(&[13; 32]));
        f.bind();
        assert!(f.verify().is_err(), "{field}");
    }
}
#[test]
fn raw_witness_bytes_lengths_and_digests_refuse_before_parsing() {
    for mode in 0..5 {
        let mut f = fixture();
        match mode {
            0 => f.raw_witness[0] = b'[',
            1 => f.raw_witness.push(b' '),
            2 => {
                f.request.time_witness_receipt_bytes += 1;
                f.request.request_sha256 = twv_request_digest(&f.request).unwrap();
            }
            3 => {
                f.request.time_witness_receipt_raw_sha256 = empty();
                f.request.request_sha256 = twv_request_digest(&f.request).unwrap();
            }
            _ => f.raw_witness.clear(),
        }
        let err = f.verify().unwrap_err();
        assert!(matches!(
            err.code,
            TwvFaultCode::RawBytes | TwvFaultCode::Size
        ));
    }
    let mut f = fixture();
    f.raw_witness = vec![b' '; TWV_MAX_FORM_BYTES + 1];
    assert_eq!(f.verify().unwrap_err().code, TwvFaultCode::Size);
}
#[test]
fn upstream_replay_refuses_promoted_a3_and_tampered_a1_a2_bytes() {
    for mode in 0..6 {
        let mut f = fixture();
        match mode {
            0 => f.a3_receipt.current_time_compared = true,
            1 => f.a3_receipt.effect_account.clock_read_count = 1,
            2 => f.raw_a1.push(b' '),
            3 => f.raw_a2.push(b' '),
            4 => f.raw_a3.push(b' '),
            _ => {
                f.a3_receipt.this_update_unix_ms += 1;
                f.a3_receipt.receipt_sha256 = krv_receipt_digest(&f.a3_receipt).unwrap();
            }
        }
        assert_eq!(f.verify().unwrap_err().code, TwvFaultCode::Predecessor);
    }
}
#[test]
fn request_governance_and_predecessor_binding_drift_refuse() {
    for field in [
        "source_snapshot_uuid",
        "canonical_uuid",
        "signature_uuid",
        "source_custody_commit",
        "formation_commit",
        "formation_bookend_commit",
        "a3_implementation_commit",
        "a3_bookend_commit",
        "a3_proof_uuid",
    ] {
        let mut f = fixture();
        f.request = change_typed(&f.request, field, json!("drift"));
        f.request.request_sha256 = twv_request_digest(&f.request).unwrap();
        assert_eq!(
            f.verify().unwrap_err().code,
            TwvFaultCode::Lineage,
            "{field}"
        );
    }
    for field in [
        "predecessor_request_sha256",
        "predecessor_packet_sha256",
        "predecessor_verification_sha256",
        "a1_policy_envelope_raw_sha256",
        "a1_verification_request_sha256",
        "a1_receipt_sha256",
        "a2_custody_attestation_raw_sha256",
        "a2_verification_request_sha256",
        "a2_receipt_sha256",
        "a3_revocation_snapshot_raw_sha256",
        "a3_verification_request_sha256",
        "a3_receipt_sha256",
    ] {
        let mut f = fixture();
        f.request = change_typed(&f.request, field, json!(empty()));
        f.request.request_sha256 = twv_request_digest(&f.request).unwrap();
        assert_eq!(
            f.verify().unwrap_err().code,
            TwvFaultCode::Predecessor,
            "{field}"
        );
    }
}
#[test]
fn request_attempts_reference_and_expectation_bounds_refuse() {
    for field in [
        "maximum_attempts",
        "automatic_retry_count",
        "automatic_cleanup_count",
    ] {
        let mut f = fixture();
        f.request = change_typed(&f.request, field, json!(2));
        f.request.request_sha256 = twv_request_digest(&f.request).unwrap();
        assert_eq!(f.verify().unwrap_err().code, TwvFaultCode::Effect);
    }
    for refs in [
        vec![],
        vec!["same".to_owned(); 2],
        vec![String::new()],
        (0..49).map(|n| format!("ref-{n}")).collect(),
    ] {
        let mut f = fixture();
        f.request.evidence_references = refs;
        f.request.request_sha256 = twv_request_digest(&f.request).unwrap();
        assert_eq!(f.verify().unwrap_err().code, TwvFaultCode::Evidence);
    }
    for field in ["expected_witness_uuid", "expected_witness_authority_label"] {
        let mut f = fixture();
        f.request = change_typed(&f.request, field, json!(""));
        f.request.request_sha256 = twv_request_digest(&f.request).unwrap();
        assert_eq!(f.verify().unwrap_err().code, TwvFaultCode::Expectation);
    }
    let mut f = fixture();
    f.request.expected_sequence = 0;
    f.request.request_sha256 = twv_request_digest(&f.request).unwrap();
    assert_eq!(f.verify().unwrap_err().code, TwvFaultCode::Sequence);
}
#[test]
fn receipt_all_true_false_and_effect_fields_are_reconstructed() {
    let f = fixture();
    let receipt = f.verify().unwrap();
    let value = serde_json::to_value(&receipt).unwrap();
    let mut tested_bool = 0;
    for (field, value) in value.as_object().unwrap() {
        if let Some(flag) = value.as_bool() {
            let mut r: TwvVerificationReceipt = change_typed(&receipt, field, json!(!flag));
            r.receipt_sha256 = twv_receipt_digest(&r).unwrap();
            assert!(
                validate_twv_receipt(&f.request, &f.witness, &f.a3_receipt, &r).is_err(),
                "{field}"
            );
            tested_bool += 1;
        }
    }
    assert_eq!(tested_bool, 42); // fixture_only, twelve correspondence, twenty-nine authority flags.
    let effects = serde_json::to_value(&receipt.effect_account).unwrap();
    for (field, value) in effects.as_object().unwrap() {
        let mut altered = effects.clone();
        altered[field] = if value.is_boolean() {
            json!(true)
        } else {
            json!(1)
        };
        let mut r = receipt.clone();
        r.effect_account = serde_json::from_value(altered).unwrap();
        r.receipt_sha256 = twv_receipt_digest(&r).unwrap();
        assert_eq!(
            validate_twv_receipt(&f.request, &f.witness, &f.a3_receipt, &r)
                .unwrap_err()
                .code,
            TwvFaultCode::Effect,
            "{field}"
        );
    }
    assert_eq!(effects.as_object().unwrap().len(), 22);
}
#[test]
fn witness_all_authority_flags_refuse_even_with_valid_signature() {
    for field in [
        "production_authority_claimed",
        "witness_identity_proved",
        "witness_authority_proved",
        "witness_freshness_proved",
        "trusted_current_time_proved",
    ] {
        let mut f = fixture();
        f.witness = change_typed(&f.witness, field, json!(true));
        resign(&mut f.witness, &SigningKey::from_bytes(&[13; 32]));
        f.bind();
        assert_eq!(f.verify().unwrap_err().code, TwvFaultCode::Truth, "{field}");
    }
}
#[test]
fn canonical_forms_refuse_duplicates_unknown_fields_whitespace_and_oversize() {
    let f = fixture();
    let text = to_twv_witness_machine_form(&f.witness).unwrap();
    for changed in [
        format!(" {text}"),
        format!("{text}\n"),
        format!("\u{feff}{text}"),
        text.replacen("{", "{\"sequence\":1,", 1),
        text.replacen("{", "{\"unknown\":false,", 1),
        text.replace("\"sequence\":1", "\"sequence\":1.0"),
        serde_json::to_string_pretty(&f.witness).unwrap(),
        serde_json::to_string(&serde_json::to_value(&f.witness).unwrap()).unwrap(),
        " ".repeat(TWV_MAX_FORM_BYTES + 1),
    ] {
        assert!(from_twv_witness_machine_form(&changed).is_err());
    }
    let mut deep = json!(0);
    for _ in 0..33 {
        deep = json!({"x":deep});
    }
    assert_eq!(
        from_twv_witness_machine_form(&serde_json::to_string(&deep).unwrap())
            .unwrap_err()
            .code,
        TwvFaultCode::Size
    );
    let wide: BTreeMap<String, Value> = (0..4097).map(|i| (format!("f{i}"), json!(0))).collect();
    assert_eq!(
        from_twv_witness_machine_form(&serde_json::to_string(&wide).unwrap())
            .unwrap_err()
            .code,
        TwvFaultCode::Size
    );
    for field in ["authority_label", "witness_uuid"] {
        let bad: TwvTimeWitness = change_typed(&f.witness, field, json!("a".repeat(8193)));
        assert!(from_twv_witness_machine_form(&serde_json::to_string(&bad).unwrap()).is_err());
    }
}
#[test]
fn fresh_process_replays_are_byte_identical_and_arg_counts_are_bounded() {
    let f = fixture();
    let dir = temporary(&f);
    let expected = line(&f.verify().unwrap());
    for _ in 0..2 {
        let evidence = Command::new(EVIDENCE_CLI).arg(&dir.root).output().unwrap();
        assert!(
            evidence.status.success(),
            "{}",
            String::from_utf8_lossy(&evidence.stderr)
        );
        assert_eq!(evidence.stdout, expected);
        let core = Command::new(CLI)
            .args(TWV_EVIDENCE_FILES[..14].iter().map(|n| dir.root.join(n)))
            .output()
            .unwrap();
        assert!(
            core.status.success(),
            "{}",
            String::from_utf8_lossy(&core.stderr)
        );
        assert_eq!(core.stdout, expected);
    }
    for (exe, args) in [(CLI, 0), (CLI, 15), (EVIDENCE_CLI, 0), (EVIDENCE_CLI, 2)] {
        let result = Command::new(exe)
            .args(std::iter::repeat_n("not-used", args))
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
    }
}
#[test]
fn fresh_process_raw_and_rehashed_authority_tamper_refuse() {
    for semantic in [false, true] {
        let f = fixture();
        let dir = temporary(&f);
        if semantic {
            let mut r = f.verify().unwrap();
            r.trusted_current_time_proved = true;
            r.receipt_sha256 = twv_receipt_digest(&r).unwrap();
            fs::write(dir.root.join("receipt.json"), line(&r)).unwrap();
            refresh(&dir.root);
            let mut m = manifest(&dir.root);
            m.retained_receipt_sha256 = r.receipt_sha256;
            save_manifest(&dir.root, m);
        } else {
            let path = dir.root.join("time_witness_receipt.json");
            let mut bytes = fs::read(&path).unwrap();
            bytes[0] = b'[';
            fs::write(path, bytes).unwrap();
        }
        for _ in 0..2 {
            let r = Command::new(EVIDENCE_CLI).arg(&dir.root).output().unwrap();
            assert_eq!(r.status.code(), Some(2));
            assert!(r.stdout.is_empty());
        }
    }
}
#[test]
fn evidence_membership_framing_nonregular_size_and_manifest_tamper_refuse() {
    for mode in 0..8 {
        let f = fixture();
        let dir = temporary(&f);
        match mode {
            0 => fs::write(dir.root.join("extra.json"), b"{}\n").unwrap(),
            1 => fs::remove_file(dir.root.join("receipt.json")).unwrap(),
            2 => {
                fs::remove_file(dir.root.join("receipt.json")).unwrap();
                fs::create_dir(dir.root.join("receipt.json")).unwrap();
            }
            3 => {
                let p = dir.root.join("receipt.json");
                let mut b = fs::read(&p).unwrap();
                b.push(b'\n');
                fs::write(p, b).unwrap();
                refresh(&dir.root);
            }
            4 => {
                fs::write(
                    dir.root.join("receipt.json"),
                    vec![b' '; TWV_MAX_FORM_BYTES + 2],
                )
                .unwrap();
            }
            5 => {
                let mut m = manifest(&dir.root);
                m.artifacts[0].path = "../outside.json".to_owned();
                save_manifest(&dir.root, m);
            }
            6 => {
                let mut m = manifest(&dir.root);
                m.artifacts.swap(0, 1);
                save_manifest(&dir.root, m);
            }
            _ => {
                let mut m = manifest(&dir.root);
                m.artifacts[0].bytes += 1;
                save_manifest(&dir.root, m);
            }
        }
        assert!(
            verify_twv_evidence_directory(&dir.root).is_err(),
            "mode {mode}"
        );
    }
}
#[test]
fn manifest_claims_cannot_replace_reconstructed_replay() {
    for (field, replacement) in [
        ("fixture_only", json!(false)),
        ("artifact_count", json!(14)),
        ("deterministic_replay_count", json!(1)),
        ("required_fresh_process_replay_count", json!(1)),
        ("byte_identical", json!(false)),
        ("effect_count", json!(1)),
        ("total_artifact_bytes", json!(0)),
        ("retained_a3_receipt_sha256", json!(empty())),
        ("retained_a2_receipt_sha256", json!(empty())),
        ("retained_a1_receipt_sha256", json!(empty())),
        ("retained_receipt_sha256", json!(empty())),
        ("retained_authority_packet_sha256", json!(empty())),
        (
            "manifest_uuid",
            json!("00000000-0000-0000-0000-000000000000"),
        ),
    ] {
        let dir = temporary(&fixture());
        let m: TwvEvidenceManifest = change_typed(&manifest(&dir.root), field, replacement);
        save_manifest(&dir.root, m);
        assert!(verify_twv_evidence_directory(&dir.root).is_err(), "{field}");
    }
}
#[test]
fn opaque_references_are_never_resolved_and_downstream_authorities_remain() {
    let mut f = fixture();
    f.request.evidence_references = vec![
        "https://not-contacted.invalid/no".to_owned(),
        "D:/never/read/this".to_owned(),
    ];
    f.request.request_sha256 = twv_request_digest(&f.request).unwrap();
    let r = f.verify().unwrap();
    assert_eq!(r.effect_account, TwvEffectAccount::default());
    assert_eq!(
        expected_twv_downstream_authorities(),
        vec![
            "live_decision",
            "fresh_observation",
            "private_execution_permit",
            "broker_projection",
            "physical_preparation"
        ]
    );
}

#[test]
fn only_a4_descriptor_may_change_from_the_replayed_a3_packet() {
    for mode in 0..4 {
        let mut f = fixture();
        let descriptors = &mut f.request.authority_packet_request.descriptors;
        match mode {
            0 => descriptors.clear(),
            1 => descriptors.swap(3, 4),
            2 => descriptors.push(descriptors[3].clone()),
            _ => descriptors[4] = descriptors[3].clone(),
        }
        f.request.authority_packet_request.request_sha256 =
            b1oapr_request_digest(&f.request.authority_packet_request).unwrap();
        f.request.authority_packet_request_sha256 =
            f.request.authority_packet_request.request_sha256.clone();
        f.request.request_sha256 = twv_request_digest(&f.request).unwrap();
        assert!(
            f.verify().is_err(),
            "missing reordered extra or duplicate mode {mode}"
        );
    }
    for index in [0, 1, 2, 4, 5, 6, 7, 8] {
        let mut f = fixture();
        let d = &mut f.request.authority_packet_request.descriptors[index];
        d.content_sha256 = empty();
        d.descriptor_sha256 = b1oapr_descriptor_digest(d).unwrap();
        f.request.authority_packet_request.request_sha256 =
            b1oapr_request_digest(&f.request.authority_packet_request).unwrap();
        f.request.authority_packet_request_sha256 =
            f.request.authority_packet_request.request_sha256.clone();
        if let Ok(packet) = compile_b1oapr_packet(&f.request.authority_packet_request) {
            f.request.authority_packet_sha256 = packet.packet_sha256;
        }
        f.request.request_sha256 = twv_request_digest(&f.request).unwrap();
        assert!(f.verify().is_err(), "coordinate {index}");
    }
    for (field, replacement) in [
        ("ordinal", json!(5)),
        ("authority_name", json!("live_decision")),
        ("artifact_kind", json!("other")),
        ("required_verifier_profile", json!("other")),
        ("dependency_ordinal", json!(2)),
        ("fixture_only", json!(false)),
        ("confidentiality", json!("secret_reference_only")),
        ("origin", json!("externally_supplied_candidate")),
        (
            "candidate_uuid",
            json!("a4000000-0000-4000-8000-000000000099"),
        ),
    ] {
        let mut f = fixture();
        let d = &mut f.request.authority_packet_request.descriptors[3];
        *d = change_typed(d, field, replacement);
        d.descriptor_sha256 = b1oapr_descriptor_digest(d).unwrap();
        f.request.authority_packet_request.request_sha256 =
            b1oapr_request_digest(&f.request.authority_packet_request).unwrap();
        f.request.authority_packet_request_sha256 =
            f.request.authority_packet_request.request_sha256.clone();
        if let Ok(packet) = compile_b1oapr_packet(&f.request.authority_packet_request) {
            f.request.authority_packet_sha256 = packet.packet_sha256;
        }
        f.request.request_sha256 = twv_request_digest(&f.request).unwrap();
        assert!(f.verify().is_err(), "{field}");
    }
}
#[test]
fn receipt_every_non_boolean_scalar_and_digest_remains_exact() {
    let f = fixture();
    let r = f.verify().unwrap();
    let fields = serde_json::to_value(&r).unwrap();
    for (name, value) in fields.as_object().unwrap() {
        if value.is_boolean() || name == "receipt_sha256" || name == "effect_account" {
            continue;
        }
        let changed = match value {
            Value::String(_) if name == "input_class" => json!("externally_supplied_candidate"),
            Value::String(_) if name == "comparison_outcome" => json!("before_snapshot_interval"),
            Value::String(s) => json!(format!("{s}-changed")),
            Value::Number(n) => json!(if n.as_u64().unwrap() == u64::MAX {
                0
            } else {
                n.as_u64().unwrap() + 1
            }),
            Value::Object(_) => json!(empty()),
            _ => panic!("unreviewed receipt type {name}"),
        };
        let mut altered: TwvVerificationReceipt = change_typed(&r, name, changed);
        altered.receipt_sha256 = twv_receipt_digest(&altered).unwrap();
        assert!(
            validate_twv_receipt(&f.request, &f.witness, &f.a3_receipt, &altered).is_err(),
            "{name}"
        );
    }
}
#[test]
fn bare_input_filenames_work_without_an_output_directory() {
    let f = fixture();
    let dir = temporary(&f);
    let result = Command::new(CLI)
        .current_dir(&dir.root)
        .args(&TWV_EVIDENCE_FILES[..14])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, line(&f.verify().unwrap()));
    assert_eq!(fs::read_dir(&dir.root).unwrap().count(), 16);
}
#[cfg(windows)]
#[test]
fn windows_junction_directory_and_ancestor_are_refused() {
    let f = fixture();
    let dir = temporary(&f);
    let junction = dir.root.join("linked_evidence");
    // cmd's built-in junction creator must not interpret metacharacters from TMP.
    // Refuse before launch; never try shell escaping an untrusted parent path.
    assert!(
        !dir.root
            .to_string_lossy()
            .chars()
            .any(|c| "&|<>^%!\"\r\n".contains(c))
    );
    let result = Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&dir.root)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        verify_twv_evidence_directory(&junction).unwrap_err().code,
        TwvFaultCode::Path
    );
    let paths: Vec<_> = TWV_EVIDENCE_FILES[..14]
        .iter()
        .map(|n| junction.join(n))
        .collect();
    assert_eq!(
        verify_twv_payload_paths(&paths).unwrap_err().code,
        TwvFaultCode::Path
    );
    assert_eq!(
        verify_twv_evidence_directory(&dir.root).unwrap_err().code,
        TwvFaultCode::Path
    );
    fs::remove_dir(&junction).expect("remove only owned junction");
}
#[cfg(unix)]
#[test]
fn unix_symlink_root_and_file_are_refused() {
    use std::os::unix::fs::symlink;
    let f = fixture();
    let dir = temporary(&f);
    let link = dir.root.join("linked_evidence");
    symlink(&dir.root, &link).unwrap();
    assert_eq!(
        verify_twv_evidence_directory(&link).unwrap_err().code,
        TwvFaultCode::Path
    );
    fs::remove_file(&link).unwrap();
    let receipt = dir.root.join("receipt.json");
    fs::remove_file(&receipt).unwrap();
    symlink(dir.root.join("a3_receipt.json"), &receipt).unwrap();
    assert_eq!(
        verify_twv_evidence_directory(&dir.root).unwrap_err().code,
        TwvFaultCode::Path
    );
}

#[test]
fn domain_separation_and_normalization_match_independent_contract_construction() {
    let f = fixture();
    let mut normalized = f.witness.clone();
    normalized.signature_hex.clear();
    normalized.witness_sha256 = empty();
    let mut expected = b"cantor-b1-time-witness-signature/0.1\0".to_vec();
    expected.extend_from_slice(&serde_json::to_vec(&normalized).unwrap());
    assert_eq!(twv_signature_payload_bytes(&f.witness).unwrap(), expected);
    let mut normalized = f.witness.clone();
    normalized.witness_sha256 = empty();
    let mut expected = b"cantor.b1.time-witness.digest.v1\0".to_vec();
    expected.extend_from_slice(&serde_json::to_vec(&normalized).unwrap());
    assert_eq!(
        twv_witness_digest(&f.witness).unwrap(),
        sha256_bytes(&expected)
    );
    let mut request = f.request.clone();
    request.request_sha256 = empty();
    let mut expected = b"cantor.b1.time-witness.request.v1\0".to_vec();
    expected.extend_from_slice(&serde_json::to_vec(&request).unwrap());
    assert_eq!(
        twv_request_digest(&f.request).unwrap(),
        sha256_bytes(&expected)
    );
    let receipt = f.verify().unwrap();
    let mut normalized = receipt.clone();
    normalized.receipt_sha256 = empty();
    let mut expected = b"cantor.b1.time-witness.receipt.v1\0".to_vec();
    expected.extend_from_slice(&serde_json::to_vec(&normalized).unwrap());
    assert_eq!(
        twv_receipt_digest(&receipt).unwrap(),
        sha256_bytes(&expected)
    );
    let dir = temporary(&f);
    let manifest = manifest(&dir.root);
    let mut normalized = manifest.clone();
    normalized.manifest_sha256 = empty();
    let mut expected = b"cantor.b1.time-witness.evidence-manifest.v1\0".to_vec();
    expected.extend_from_slice(&serde_json::to_vec(&normalized).unwrap());
    assert_eq!(
        twv_evidence_manifest_digest(&manifest).unwrap(),
        sha256_bytes(&expected)
    );
}
#[test]
fn normalized_packet_subject_and_request_digest_tamper_refuse() {
    let mut f = fixture();
    f.request
        .authority_packet_request
        .principal
        .push_str("_other");
    f.request.authority_packet_request.request_sha256 =
        b1oapr_request_digest(&f.request.authority_packet_request).unwrap();
    f.request.authority_packet_request_sha256 =
        f.request.authority_packet_request.request_sha256.clone();
    assert!(compile_b1oapr_packet(&f.request.authority_packet_request).is_err());
    f.request.request_sha256 = twv_request_digest(&f.request).unwrap();
    // The shared packet validator refuses a changed principal even before A4 normalization.
    assert_eq!(f.verify().unwrap_err().code, TwvFaultCode::Predecessor);
    let mut f = fixture();
    f.request.request_sha256 = empty();
    assert_eq!(f.verify().unwrap_err().code, TwvFaultCode::Digest);
    let mut f = fixture();
    f.witness.witness_sha256 = empty();
    f.bind();
    assert_eq!(f.verify().unwrap_err().code, TwvFaultCode::Digest);
}

#[test]
#[ignore = "explicit fixture-only signer; requires a fresh caller-owned directory"]
fn produce_retained_twv_fixture_evidence() {
    let root = PathBuf::from(
        std::env::var_os("CANTOR_TWV_EVIDENCE_OUTPUT").expect("explicit output directory"),
    );
    assert!(
        !root.exists(),
        "never overwrite retained or foreign evidence"
    );
    write_evidence(&root, &fixture());
    assert!(verify_twv_evidence_directory(&root).is_ok());
}
