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

const A4_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../experiments/b1_trusted_time_witness_receipt_verification_p0/implementation_provider_free_evidence"
);
const CLI: &str = env!("CARGO_BIN_EXE_cantor-b1-operator-decision-chain-verify");
const EVIDENCE_CLI: &str = env!("CARGO_BIN_EXE_cantor-b1-operator-decision-chain-evidence-verify");
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
fn empty() -> ContentDigest {
    sha256_bytes(b"")
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn raw(name: &str) -> Vec<u8> {
    let bytes = fs::read(Path::new(A4_ROOT).join(name)).expect("retained A4 fixture");
    bytes.strip_suffix(b"\n").expect("single LF").to_vec()
}
fn parsed<T: DeserializeOwned>(name: &str) -> T {
    serde_json::from_slice(&raw(name)).unwrap()
}
fn line<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}
fn raw_line(value: &[u8]) -> Vec<u8> {
    let mut bytes = value.to_vec();
    bytes.push(b'\n');
    bytes
}
fn temporary(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "cantor-odcv-{label}-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}
fn resign(envelope: &mut B1CDriveOperatorDecisionEnvelope, key: &SigningKey) {
    envelope.payload.payload_sha256 =
        b1_cdrive_operator_decision_payload_digest(&envelope.payload).unwrap();
    envelope.signature_hex = hex(&key
        .sign(&b1_cdrive_operator_decision_signature_payload_bytes(&envelope.payload).unwrap())
        .to_bytes());
    envelope.envelope_sha256 = b1_cdrive_operator_decision_envelope_digest(envelope).unwrap();
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
    a4_request: TwvVerificationRequest,
    a4_receipt: TwvVerificationReceipt,
    policy: B1CDriveOperatorDecisionPolicy,
    legacy_request: B1CDriveOperatorDecisionRequest,
    envelope: B1CDriveOperatorDecisionEnvelope,
    raw_envelope: Vec<u8>,
    request: OdcvVerificationRequest,
}
impl Fixture {
    fn upstream(&self) -> TwvPredecessor<'_> {
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
    fn predecessor(&self) -> OdcvPredecessor<'_> {
        OdcvPredecessor {
            upstream: self.upstream(),
            raw_a4_witness: &self.raw_witness,
            a4_request: &self.a4_request,
            a4_receipt: &self.a4_receipt,
        }
    }
    fn verify(&self) -> Result<OdcvVerificationReceipt, OdcvFault> {
        verify_odcv_operator_decision(
            &self.request,
            &self.predecessor(),
            &self.policy,
            &self.legacy_request,
            &self.raw_envelope,
        )
    }
    fn validate(&self, receipt: &OdcvVerificationReceipt) -> Result<(), OdcvFault> {
        validate_odcv_receipt(
            &self.request,
            &self.predecessor(),
            &self.policy,
            &self.legacy_request,
            &self.raw_envelope,
            receipt,
        )
    }
    fn redigest_packet(&mut self) {
        for descriptor in &mut self.request.authority_packet_request.descriptors {
            descriptor.descriptor_sha256 = b1oapr_descriptor_digest(descriptor).unwrap();
        }
        self.request.a5_descriptor_sha256 = self.request.authority_packet_request.descriptors[4]
            .descriptor_sha256
            .clone();
        self.request.authority_packet_request.request_sha256 =
            b1oapr_request_digest(&self.request.authority_packet_request).unwrap();
        self.request.authority_packet_request_sha256 =
            self.request.authority_packet_request.request_sha256.clone();
        if let Ok(packet) = compile_b1oapr_packet(&self.request.authority_packet_request) {
            self.request.authority_packet_sha256 = packet.packet_sha256;
        }
        self.request.request_sha256 = odcv_request_digest(&self.request).unwrap();
    }
    fn bind(&mut self) {
        self.raw_envelope = serde_json::to_vec(&self.envelope).unwrap();
        let descriptor = &mut self.request.authority_packet_request.descriptors[4];
        descriptor.origin = if self.envelope.fixture_only {
            B1OaprCandidateOrigin::DeterministicFixtureCandidate
        } else {
            B1OaprCandidateOrigin::ExternallySuppliedCandidate
        };
        descriptor.fixture_only = self.envelope.fixture_only;
        descriptor.declared_bytes = self.raw_envelope.len() as u64;
        descriptor.content_sha256 = sha256_bytes(&self.raw_envelope);
        self.request.a5_candidate_uuid = descriptor.candidate_uuid.clone();
        self.request.operator_decision_envelope_bytes = descriptor.declared_bytes;
        self.request.operator_decision_envelope_raw_sha256 = descriptor.content_sha256.clone();
        self.request.operator_decision_policy_sha256 = self.policy.policy_sha256.clone();
        self.request.operator_decision_request_sha256 = self.legacy_request.request_sha256.clone();
        self.redigest_packet();
    }
    fn signed_change(&mut self, change: impl FnOnce(&mut B1CDriveOperatorDecisionPayload)) {
        change(&mut self.envelope.payload);
        resign(&mut self.envelope, &SigningKey::from_bytes(&[7; 32]));
        self.bind();
    }
    fn rebind_policy(&mut self, key: &SigningKey) {
        self.policy.policy_sha256 =
            b1_cdrive_operator_decision_policy_digest(&self.policy).unwrap();
        self.legacy_request = canonical_b1_cdrive_operator_decision_request(&self.policy).unwrap();
        self.envelope.payload.policy_sha256 = self.policy.policy_sha256.clone();
        self.envelope.payload.request_sha256 = self.legacy_request.request_sha256.clone();
        resign(&mut self.envelope, key);
        self.bind();
    }
    fn set_observed(&mut self, observed: u64) {
        self.witness.observed_unix_ms = observed;
        self.witness.signature_hex = hex(&SigningKey::from_bytes(&[13; 32])
            .sign(&twv_signature_payload_bytes(&self.witness).unwrap())
            .to_bytes());
        self.witness.witness_sha256 = twv_witness_digest(&self.witness).unwrap();
        self.raw_witness = serde_json::to_vec(&self.witness).unwrap();
        let descriptor = &mut self.a4_request.authority_packet_request.descriptors[3];
        descriptor.content_sha256 = sha256_bytes(&self.raw_witness);
        descriptor.declared_bytes = self.raw_witness.len() as u64;
        descriptor.descriptor_sha256 = b1oapr_descriptor_digest(descriptor).unwrap();
        self.a4_request.time_witness_receipt_raw_sha256 = descriptor.content_sha256.clone();
        self.a4_request.time_witness_receipt_bytes = descriptor.declared_bytes;
        self.a4_request.a4_descriptor_sha256 = descriptor.descriptor_sha256.clone();
        self.a4_request.authority_packet_request.request_sha256 =
            b1oapr_request_digest(&self.a4_request.authority_packet_request).unwrap();
        self.a4_request.authority_packet_request_sha256 = self
            .a4_request
            .authority_packet_request
            .request_sha256
            .clone();
        self.a4_request.authority_packet_sha256 =
            compile_b1oapr_packet(&self.a4_request.authority_packet_request)
                .unwrap()
                .packet_sha256;
        self.a4_request.request_sha256 = twv_request_digest(&self.a4_request).unwrap();
        self.a4_receipt =
            verify_twv_time_witness(&self.a4_request, &self.upstream(), &self.raw_witness).unwrap();
        self.request.a4_time_witness_receipt_raw_sha256 = sha256_bytes(&self.raw_witness);
        self.request.a4_verification_request_sha256 = self.a4_request.request_sha256.clone();
        self.request.a4_receipt_sha256 = self.a4_receipt.receipt_sha256.clone();
        self.request.authority_packet_request = self.a4_request.authority_packet_request.clone();
        self.bind();
    }
}
fn fixture_for(class: KcvInputClass, kind: B1CDriveOperatorDecisionKind) -> Fixture {
    let fixture_only = class == KcvInputClass::DeterministicFixtureCandidate;
    let a1_envelope: BpvPolicyEnvelope = parsed("a1_policy_envelope.json");
    let a4_request: TwvVerificationRequest = parsed("verification_request.json");
    let a4_receipt: TwvVerificationReceipt = parsed("receipt.json");
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut policy = B1CDriveOperatorDecisionPolicy {
        profile: B1_CDRIVE_OPERATOR_DECISION_POLICY_PROFILE.to_owned(),
        policy_uuid: a1_envelope.payload.policy_uuid.clone(),
        principal: a1_envelope.payload.issuer_principal.clone(),
        role: a1_envelope.payload.issuer_role.clone(),
        subject: a1_envelope.payload.subject.clone(),
        verifying_key_hex: hex(key.verifying_key().as_bytes()),
        key_fingerprint_sha256: b1_cdrive_operator_key_fingerprint(key.verifying_key().as_bytes()),
        policy_governance_ref: "fixture://exact-A1-envelope-correspondence-only".to_owned(),
        policy_governance_artifact_sha256: sha256_bytes(&raw("a1_policy_envelope.json")),
        revocation_list_artifact_sha256: sha256_bytes(&raw("revocation_snapshot.json")),
        fixture_only,
        policy_sha256: empty(),
    };
    policy.policy_sha256 = b1_cdrive_operator_decision_policy_digest(&policy).unwrap();
    let legacy_request = canonical_b1_cdrive_operator_decision_request(&policy).unwrap();
    let mut envelope = B1CDriveOperatorDecisionEnvelope {
        profile: B1_CDRIVE_OPERATOR_DECISION_ENVELOPE_PROFILE.to_owned(),
        payload: B1CDriveOperatorDecisionPayload {
            profile: B1_CDRIVE_OPERATOR_DECISION_PAYLOAD_PROFILE.to_owned(),
            decision_uuid: "a5000000-0000-4000-8000-000000000001".to_owned(),
            request_sha256: legacy_request.request_sha256.clone(),
            policy_sha256: policy.policy_sha256.clone(),
            decision_kind: kind,
            principal: policy.principal.clone(),
            role: policy.role.clone(),
            subject: policy.subject.clone(),
            purpose: "production_preparation_commission_proposal_decision".to_owned(),
            conversation_uuid: "01a02268-2614-7d80-9737-ea77f4aeacb1".to_owned(),
            external_decision_identity: "fixture-A5-chain-not-live-authorization".to_owned(),
            issued_at_unix_millis: a4_receipt.observed_unix_ms - 1,
            expires_at_unix_millis: a4_receipt.observed_unix_ms + 1,
            maximum_attempts: 1,
            retry_count: 0,
            automatic_cleanup_count: 0,
            fixture_only,
            payload_sha256: empty(),
        },
        signature_hex: String::new(),
        fixture_only,
        envelope_sha256: empty(),
    };
    resign(&mut envelope, &key);
    let request = OdcvVerificationRequest {
        profile: ODCV_REQUEST_PROFILE.to_owned(),
        source_snapshot_uuid: ODCV_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: ODCV_CANONICAL_UUID.to_owned(),
        signature_uuid: ODCV_SIGNATURE_UUID.to_owned(),
        source_custody_commit: ODCV_SOURCE_CUSTODY_COMMIT.to_owned(),
        formation_commit: ODCV_FORMATION_COMMIT.to_owned(),
        formation_bookend_commit: ODCV_FORMATION_BOOKEND_COMMIT.to_owned(),
        a4_implementation_commit: ODCV_A4_IMPLEMENTATION_COMMIT.to_owned(),
        a4_bookend_commit: ODCV_A4_BOOKEND_COMMIT.to_owned(),
        a4_proof_uuid: ODCV_A4_PROOF_UUID.to_owned(),
        legacy_implementation_commit: ODCV_LEGACY_IMPLEMENTATION_COMMIT.to_owned(),
        legacy_bookend_commit: ODCV_LEGACY_BOOKEND_COMMIT.to_owned(),
        legacy_proof_uuid: ODCV_LEGACY_PROOF_UUID.to_owned(),
        predecessor_request_sha256: a4_request.predecessor_request_sha256.clone(),
        predecessor_packet_sha256: a4_request.predecessor_packet_sha256.clone(),
        predecessor_verification_sha256: a4_request.predecessor_verification_sha256.clone(),
        a1_policy_envelope_raw_sha256: a4_request.a1_policy_envelope_raw_sha256.clone(),
        a1_verification_request_sha256: a4_request.a1_verification_request_sha256.clone(),
        a1_receipt_sha256: a4_request.a1_receipt_sha256.clone(),
        a2_custody_attestation_raw_sha256: a4_request.a2_custody_attestation_raw_sha256.clone(),
        a2_verification_request_sha256: a4_request.a2_verification_request_sha256.clone(),
        a2_receipt_sha256: a4_request.a2_receipt_sha256.clone(),
        a3_revocation_snapshot_raw_sha256: a4_request.a3_revocation_snapshot_raw_sha256.clone(),
        a3_verification_request_sha256: a4_request.a3_verification_request_sha256.clone(),
        a3_receipt_sha256: a4_request.a3_receipt_sha256.clone(),
        a4_time_witness_receipt_raw_sha256: sha256_bytes(&raw("time_witness_receipt.json")),
        a4_verification_request_sha256: a4_request.request_sha256.clone(),
        a4_receipt_sha256: a4_receipt.receipt_sha256.clone(),
        authority_packet_request: a4_request.authority_packet_request.clone(),
        authority_packet_request_sha256: empty(),
        authority_packet_sha256: empty(),
        a5_candidate_uuid: a4_request.authority_packet_request.descriptors[4]
            .candidate_uuid
            .clone(),
        a5_descriptor_sha256: empty(),
        operator_decision_policy_sha256: policy.policy_sha256.clone(),
        operator_decision_request_sha256: legacy_request.request_sha256.clone(),
        operator_decision_envelope_bytes: 0,
        operator_decision_envelope_raw_sha256: empty(),
        expected_policy_revision_uuid: a1_envelope.payload.revision_uuid.clone(),
        expected_decision_uuid: envelope.payload.decision_uuid.clone(),
        expected_decision_kind: kind,
        expected_external_decision_identity: envelope.payload.external_decision_identity.clone(),
        input_class: class,
        evidence_references: ODCV_EVIDENCE_FILES[..19]
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        maximum_attempts: 1,
        automatic_retry_count: 0,
        automatic_cleanup_count: 0,
        request_sha256: empty(),
    };
    let mut f = Fixture {
        predecessor_request: parsed("predecessor_request.json"),
        predecessor_packet: parsed("predecessor_packet.json"),
        predecessor_verification: parsed("predecessor_verification.json"),
        a1_envelope,
        raw_a1: raw("a1_policy_envelope.json"),
        a1_request: parsed("a1_verification_request.json"),
        a1_receipt: parsed("a1_receipt.json"),
        a2_attestation: parsed("custody_attestation.json"),
        raw_a2: raw("custody_attestation.json"),
        a2_request: parsed("a2_verification_request.json"),
        a2_receipt: parsed("a2_receipt.json"),
        raw_a3: raw("revocation_snapshot.json"),
        a3_request: parsed("a3_verification_request.json"),
        a3_receipt: parsed("a3_receipt.json"),
        witness: parsed("time_witness_receipt.json"),
        raw_witness: raw("time_witness_receipt.json"),
        a4_request,
        a4_receipt,
        policy,
        legacy_request,
        envelope,
        raw_envelope: Vec::new(),
        request,
    };
    f.bind();
    f
}
fn fixture() -> Fixture {
    fixture_for(
        KcvInputClass::DeterministicFixtureCandidate,
        B1CDriveOperatorDecisionKind::Authorize,
    )
}
fn write_evidence(root: &Path, f: &Fixture) {
    fs::create_dir(root).expect("fresh caller-owned output directory");
    let receipt = f.verify().unwrap();
    let payloads = [
        line(&f.predecessor_request),
        line(&f.predecessor_packet),
        line(&f.predecessor_verification),
        raw_line(&f.raw_a1),
        line(&f.a1_request),
        line(&f.a1_receipt),
        raw_line(&f.raw_a2),
        line(&f.a2_request),
        line(&f.a2_receipt),
        raw_line(&f.raw_a3),
        line(&f.a3_request),
        line(&f.a3_receipt),
        raw_line(&f.raw_witness),
        line(&f.a4_request),
        line(&f.a4_receipt),
        line(&f.policy),
        line(&f.legacy_request),
        raw_line(&f.raw_envelope),
        line(&f.request),
        line(&receipt),
    ];
    let artifacts: Vec<OdcvEvidenceArtifact> = ODCV_EVIDENCE_FILES[..20]
        .iter()
        .zip(payloads.iter())
        .map(|(name, bytes)| {
            fs::write(root.join(name), bytes).unwrap();
            OdcvEvidenceArtifact {
                path: (*name).to_owned(),
                bytes: bytes.len() as u64,
                sha256: sha256_bytes(bytes),
            }
        })
        .collect();
    let mut manifest = OdcvEvidenceManifest {
        profile: ODCV_EVIDENCE_PROFILE.to_owned(),
        manifest_uuid: "a5000000-0000-4000-8000-000000000099".to_owned(),
        fixture_only: receipt.fixture_only,
        artifact_count: 20,
        total_artifact_bytes: artifacts.iter().map(|a| a.bytes).sum(),
        artifacts,
        retained_authority_packet_sha256: receipt.authority_packet_sha256.clone(),
        retained_a1_receipt_sha256: receipt.a1_receipt_sha256.clone(),
        retained_a2_receipt_sha256: receipt.a2_receipt_sha256.clone(),
        retained_a3_receipt_sha256: receipt.a3_receipt_sha256.clone(),
        retained_a4_receipt_sha256: receipt.a4_receipt_sha256.clone(),
        retained_legacy_verification_sha256: receipt.legacy_verification_sha256.clone(),
        retained_receipt_sha256: receipt.receipt_sha256,
        deterministic_replay_count: 2,
        required_fresh_process_replay_count: 2,
        byte_identical: true,
        effect_count: 0,
        manifest_sha256: empty(),
    };
    manifest.manifest_sha256 = odcv_evidence_manifest_digest(&manifest).unwrap();
    fs::write(root.join("evidence_manifest.json"), line(&manifest)).unwrap();
}
fn rehash_evidence(root: &Path) {
    let mut manifest: OdcvEvidenceManifest =
        serde_json::from_slice(&fs::read(root.join("evidence_manifest.json")).unwrap()).unwrap();
    for artifact in &mut manifest.artifacts {
        let bytes = fs::read(root.join(&artifact.path)).unwrap();
        artifact.bytes = bytes.len() as u64;
        artifact.sha256 = sha256_bytes(&bytes);
    }
    manifest.total_artifact_bytes = manifest.artifacts.iter().map(|a| a.bytes).sum();
    manifest.manifest_sha256 = odcv_evidence_manifest_digest(&manifest).unwrap();
    fs::write(root.join("evidence_manifest.json"), line(&manifest)).unwrap();
}
#[test]
fn complete_fixture_replays_and_is_non_authorizing() {
    let f = fixture();
    let first = f.verify().unwrap();
    assert_eq!(first, f.verify().unwrap());
    assert_eq!(first.effect_account, TwvEffectAccount::default());
    assert!(!first.execution_authorized);
    assert!(!first.decision_signature_binds_a4_lineage);
    assert_eq!(
        first.comparison_outcome,
        OdcvIntervalRelation::WithinDecisionInterval
    );
    f.validate(&first).unwrap();
}
#[test]
fn both_classes_and_kinds_replay_the_complete_chain() {
    for class in [
        KcvInputClass::DeterministicFixtureCandidate,
        KcvInputClass::ExternallySuppliedCandidate,
    ] {
        for kind in [
            B1CDriveOperatorDecisionKind::Authorize,
            B1CDriveOperatorDecisionKind::Reject,
        ] {
            let f = fixture_for(class, kind);
            let receipt = f.verify().unwrap();
            assert_eq!(
                receipt.fixture_only,
                class == KcvInputClass::DeterministicFixtureCandidate
            );
            assert!(f.a4_receipt.fixture_only);
            assert_eq!(receipt.decision_kind, kind);
            assert!(!receipt.live_authorization_admitted);
            assert!(!receipt.current_nonexpired);
        }
    }
}
#[test]
fn evidence_reconstructs_exact_manifest() {
    let f = fixture();
    let root = temporary("valid");
    write_evidence(&root, &f);
    let replay = verify_odcv_evidence_directory(&root).unwrap();
    assert_eq!(replay.receipt, f.verify().unwrap());
    assert_eq!(replay.manifest.artifacts.len(), 20);
    assert_eq!(replay.deterministic_replay_count, 2);
    let paths: Vec<PathBuf> = ODCV_EVIDENCE_FILES[..19]
        .iter()
        .map(|n| root.join(n))
        .collect();
    assert_eq!(
        verify_odcv_payload_paths(&paths).unwrap(),
        replay.receipt_machine_form
    );
}
#[test]
#[ignore = "explicit test-only deterministic fixture producer"]
fn produce_provider_free_evidence() {
    let output = std::env::var_os("CANTOR_ODCV_EVIDENCE_OUTPUT_DIR")
        .expect("explicit fresh output directory");
    write_evidence(Path::new(&output), &fixture());
}

fn change_typed<T: Serialize + DeserializeOwned>(original: &T, field: &str, value: Value) -> T {
    let mut object = serde_json::to_value(original).unwrap();
    object[field] = value;
    serde_json::from_value(object).unwrap()
}
fn refresh_request(f: &mut Fixture) {
    f.request.request_sha256 = odcv_request_digest(&f.request).unwrap();
}
#[test]
fn governance_pins_refuse_drift() {
    for field in [
        "source_snapshot_uuid",
        "canonical_uuid",
        "signature_uuid",
        "source_custody_commit",
        "formation_commit",
        "formation_bookend_commit",
        "a4_implementation_commit",
        "a4_bookend_commit",
        "a4_proof_uuid",
        "legacy_implementation_commit",
        "legacy_bookend_commit",
        "legacy_proof_uuid",
    ] {
        let mut f = fixture();
        f.request = change_typed(&f.request, field, json!("changed"));
        refresh_request(&mut f);
        assert_eq!(
            f.verify().unwrap_err().code,
            OdcvFaultCode::Lineage,
            "{field}"
        );
    }
    let mut f = fixture();
    f.request.profile.push('x');
    refresh_request(&mut f);
    assert_eq!(f.verify().unwrap_err().code, OdcvFaultCode::Profile);
}
#[test]
fn request_fields_refuse_tamper() {
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
        "a4_time_witness_receipt_raw_sha256",
        "a4_verification_request_sha256",
        "a4_receipt_sha256",
    ] {
        let mut f = fixture();
        f.request = change_typed(&f.request, field, json!(empty()));
        refresh_request(&mut f);
        assert_eq!(
            f.verify().unwrap_err().code,
            OdcvFaultCode::Predecessor,
            "{field}"
        );
    }
    for field in [
        "authority_packet_request_sha256",
        "authority_packet_sha256",
        "a5_descriptor_sha256",
        "operator_decision_policy_sha256",
        "operator_decision_request_sha256",
        "operator_decision_envelope_raw_sha256",
    ] {
        let mut f = fixture();
        f.request = change_typed(&f.request, field, json!(empty()));
        refresh_request(&mut f);
        assert!(f.verify().is_err(), "{field}");
    }
    let mut f = fixture();
    f.request.request_sha256 = empty();
    assert_eq!(f.verify().unwrap_err().code, OdcvFaultCode::Digest);
}
#[test]
fn predecessor_tampering_refuses() {
    for index in 0..4 {
        let mut f = fixture();
        match index {
            0 => {
                f.a1_receipt.policy_governance_proved = true;
                f.a1_receipt.receipt_sha256 = bpv_receipt_digest(&f.a1_receipt).unwrap();
                f.request.a1_receipt_sha256 = f.a1_receipt.receipt_sha256.clone();
            }
            1 => {
                f.a2_receipt.key_custody_proved = true;
                f.a2_receipt.receipt_sha256 = kcv_receipt_digest(&f.a2_receipt).unwrap();
                f.request.a2_receipt_sha256 = f.a2_receipt.receipt_sha256.clone();
            }
            2 => {
                f.a3_receipt.revocation_truth_proved = true;
                f.a3_receipt.receipt_sha256 = krv_receipt_digest(&f.a3_receipt).unwrap();
                f.request.a3_receipt_sha256 = f.a3_receipt.receipt_sha256.clone();
            }
            _ => {
                f.a4_receipt.trusted_current_time_proved = true;
                f.a4_receipt.receipt_sha256 = twv_receipt_digest(&f.a4_receipt).unwrap();
                f.request.a4_receipt_sha256 = f.a4_receipt.receipt_sha256.clone();
            }
        }
        refresh_request(&mut f);
        assert_eq!(f.verify().unwrap_err().code, OdcvFaultCode::Predecessor);
    }
    for index in 0..4 {
        let mut f = fixture();
        match index {
            0 => f.raw_a1.push(b' '),
            1 => f.raw_a2.push(b' '),
            2 => f.raw_a3.push(b' '),
            _ => f.raw_witness.push(b' '),
        };
        assert_eq!(f.verify().unwrap_err().code, OdcvFaultCode::Predecessor);
    }
}
#[test]
fn decoded_keys_and_distinct_domains() {
    let f = fixture();
    assert_eq!(f.policy.verifying_key_hex, f.a1_envelope.verifying_key_hex);
    let receipt = f.verify().unwrap();
    assert_ne!(
        receipt.legacy_policy_key_fingerprint_sha256,
        receipt.target_policy_key_fingerprint_sha256
    );
    assert!(receipt.decision_policy_key_correspondence_verified);
    let mut f = fixture();
    let other = SigningKey::from_bytes(&[17; 32]);
    f.policy.verifying_key_hex = hex(other.verifying_key().as_bytes());
    f.policy.key_fingerprint_sha256 =
        b1_cdrive_operator_key_fingerprint(other.verifying_key().as_bytes());
    f.rebind_policy(&other);
    verify_b1_cdrive_operator_decision(&f.legacy_request, &f.policy, &f.envelope).unwrap();
    assert_eq!(f.verify().unwrap_err().code, OdcvFaultCode::Key);
}
#[test]
fn policy_artifact_bindings_refuse() {
    for field in [
        "policy_governance_artifact_sha256",
        "revocation_list_artifact_sha256",
    ] {
        let mut f = fixture();
        f.policy = change_typed(&f.policy, field, json!(sha256_bytes(b"wrong but signed")));
        f.rebind_policy(&SigningKey::from_bytes(&[7; 32]));
        verify_b1_cdrive_operator_decision(&f.legacy_request, &f.policy, &f.envelope).unwrap();
        assert_eq!(
            f.verify().unwrap_err().code,
            OdcvFaultCode::Policy,
            "{field}"
        );
    }
}
#[test]
fn policy_identity_and_revision_refuse() {
    let mut f = fixture();
    f.policy.policy_uuid = "a5000000-0000-4000-8000-000000000077".to_owned();
    f.rebind_policy(&SigningKey::from_bytes(&[7; 32]));
    assert_eq!(f.verify().unwrap_err().code, OdcvFaultCode::Policy);
    let mut f = fixture();
    f.request.expected_policy_revision_uuid = "a5000000-0000-4000-8000-000000000078".to_owned();
    refresh_request(&mut f);
    assert_eq!(f.verify().unwrap_err().code, OdcvFaultCode::Policy);
    for field in [
        "principal",
        "role",
        "subject",
        "verifying_key_hex",
        "key_fingerprint_sha256",
    ] {
        let mut f = fixture();
        let value = if field.ends_with("sha256") {
            json!(empty())
        } else {
            json!("wrong")
        };
        f.policy = change_typed(&f.policy, field, value);
        f.policy.policy_sha256 = b1_cdrive_operator_decision_policy_digest(&f.policy).unwrap();
        f.request.operator_decision_policy_sha256 = f.policy.policy_sha256.clone();
        refresh_request(&mut f);
        assert!(f.verify().is_err(), "{field}");
    }
}
#[test]
fn legacy_request_and_signature_replay() {
    let mut f = fixture();
    f.legacy_request.proposal_machine_form.push(' ');
    f.legacy_request.proposal_bytes += 1;
    f.legacy_request.proposal_raw_sha256 =
        sha256_bytes(f.legacy_request.proposal_machine_form.as_bytes());
    f.legacy_request.request_sha256 =
        b1_cdrive_operator_decision_request_digest(&f.legacy_request).unwrap();
    f.envelope.payload.request_sha256 = f.legacy_request.request_sha256.clone();
    resign(&mut f.envelope, &SigningKey::from_bytes(&[7; 32]));
    f.bind();
    assert!(f.verify().is_err());
}
#[test]
fn decision_expectations_refuse() {
    for index in 0..3 {
        let mut f = fixture();
        f.signed_change(|payload| match index {
            0 => payload.decision_uuid = "a5000000-0000-4000-8000-000000000079".to_owned(),
            1 => payload.decision_kind = B1CDriveOperatorDecisionKind::Reject,
            _ => payload.external_decision_identity = "another signed decision".to_owned(),
        });
        verify_b1_cdrive_operator_decision(&f.legacy_request, &f.policy, &f.envelope).unwrap();
        assert_eq!(f.verify().unwrap_err().code, OdcvFaultCode::Expectation);
    }
    for field in [
        "expected_decision_uuid",
        "expected_external_decision_identity",
        "expected_policy_revision_uuid",
    ] {
        let mut f = fixture();
        f.request = change_typed(&f.request, field, json!(""));
        refresh_request(&mut f);
        assert_eq!(
            f.verify().unwrap_err().code,
            OdcvFaultCode::Expectation,
            "{field}"
        );
    }
}
#[test]
fn legacy_signature_tampering_refuses() {
    let mut f = fixture();
    let replacement = if f.envelope.signature_hex.starts_with('0') {
        "1"
    } else {
        "0"
    };
    f.envelope.signature_hex.replace_range(..1, replacement);
    f.envelope.envelope_sha256 = b1_cdrive_operator_decision_envelope_digest(&f.envelope).unwrap();
    f.bind();
    assert_eq!(f.verify().unwrap_err().code, OdcvFaultCode::Signature);
    let mut f = fixture();
    f.envelope.payload.external_decision_identity.push('x');
    f.envelope.payload.payload_sha256 =
        b1_cdrive_operator_decision_payload_digest(&f.envelope.payload).unwrap();
    f.envelope.envelope_sha256 = b1_cdrive_operator_decision_envelope_digest(&f.envelope).unwrap();
    f.bind();
    assert_eq!(f.verify().unwrap_err().code, OdcvFaultCode::Signature);
}
#[test]
fn input_classes_remain_local() {
    for index in 0..4 {
        let mut f = fixture();
        match index {
            0 => f.request.input_class = KcvInputClass::ExternallySuppliedCandidate,
            1 => {
                f.policy.fixture_only = false;
                f.policy.policy_sha256 =
                    b1_cdrive_operator_decision_policy_digest(&f.policy).unwrap();
                f.request.operator_decision_policy_sha256 = f.policy.policy_sha256.clone();
            }
            2 => {
                f.envelope.payload.fixture_only = false;
                resign(&mut f.envelope, &SigningKey::from_bytes(&[7; 32]));
                f.bind();
            }
            _ => {
                f.envelope.fixture_only = false;
                f.envelope.envelope_sha256 =
                    b1_cdrive_operator_decision_envelope_digest(&f.envelope).unwrap();
                f.bind();
            }
        }
        refresh_request(&mut f);
        assert!(f.verify().is_err(), "{index}");
    }
}
#[test]
fn raw_bytes_refuse_before_parse() {
    let mut f = fixture();
    f.raw_envelope[0] = b'!';
    assert_eq!(f.verify().unwrap_err().code, OdcvFaultCode::RawBytes);
    let mut f = fixture();
    f.request.operator_decision_envelope_bytes += 1;
    refresh_request(&mut f);
    assert_eq!(f.verify().unwrap_err().code, OdcvFaultCode::RawBytes);
    let mut f = fixture();
    f.raw_envelope = vec![b'x'; ODCV_MAX_FORM_BYTES + 1];
    assert_eq!(f.verify().unwrap_err().code, OdcvFaultCode::Size);
}
#[test]
fn only_a5_descriptor_may_change() {
    for index in [0, 1, 2, 3, 5, 6, 7, 8] {
        let mut f = fixture();
        f.request.authority_packet_request.descriptors[index].content_sha256 = empty();
        f.redigest_packet();
        assert!(f.verify().is_err(), "coordinate {index}");
    }
    for mode in 0..4 {
        let mut f = fixture();
        match mode {
            0 => f.request.authority_packet_request.descriptors.clear(),
            1 => f.request.authority_packet_request.descriptors.swap(4, 5),
            2 => f
                .request
                .authority_packet_request
                .descriptors
                .push(f.request.authority_packet_request.descriptors[4].clone()),
            _ => {
                f.request.authority_packet_request.descriptors[5] =
                    f.request.authority_packet_request.descriptors[4].clone()
            }
        }
        f.request.authority_packet_request.request_sha256 =
            b1oapr_request_digest(&f.request.authority_packet_request).unwrap();
        f.request.authority_packet_request_sha256 =
            f.request.authority_packet_request.request_sha256.clone();
        refresh_request(&mut f);
        assert!(f.verify().is_err(), "mode {mode}");
    }
}
#[test]
fn packet_coordinate_refuses() {
    for (field, value) in [
        ("ordinal", json!(6)),
        ("authority_name", json!("current_time")),
        ("artifact_kind", json!("other")),
        ("required_verifier_profile", json!("other")),
        ("dependency_ordinal", json!(3)),
        ("confidentiality", json!("secret_reference_only")),
        ("origin", json!("externally_supplied_candidate")),
        ("fixture_only", json!(false)),
        (
            "candidate_uuid",
            json!("a5000000-0000-4000-8000-000000000088"),
        ),
    ] {
        let mut f = fixture();
        let d = &mut f.request.authority_packet_request.descriptors[4];
        *d = change_typed(d, field, value);
        f.redigest_packet();
        assert!(f.verify().is_err(), "{field}");
    }
}
#[test]
fn half_open_endpoints_and_u64_extremes() {
    for class in [
        KcvInputClass::DeterministicFixtureCandidate,
        KcvInputClass::ExternallySuppliedCandidate,
    ] {
        for kind in [
            B1CDriveOperatorDecisionKind::Authorize,
            B1CDriveOperatorDecisionKind::Reject,
        ] {
            for (observed, expected) in [
                (0, OdcvIntervalRelation::BeforeDecisionInterval),
                (1, OdcvIntervalRelation::WithinDecisionInterval),
                (2, OdcvIntervalRelation::WithinDecisionInterval),
                (u64::MAX - 1, OdcvIntervalRelation::WithinDecisionInterval),
                (u64::MAX, OdcvIntervalRelation::AfterDecisionInterval),
            ] {
                let mut f = fixture_for(class, kind);
                f.signed_change(|p| {
                    p.issued_at_unix_millis = 1;
                    p.expires_at_unix_millis = u64::MAX;
                });
                f.set_observed(observed);
                let receipt = f.verify().unwrap();
                assert_eq!(receipt.comparison_outcome, expected);
                assert!(!receipt.current_nonexpired);
                assert!(!receipt.current_time_compared);
                assert!(!receipt.live_authorization_admitted);
            }
        }
    }
    assert_eq!(
        odcv_compare_supplied_interval(0, 0, 1).unwrap(),
        OdcvIntervalRelation::WithinDecisionInterval
    );
    assert_eq!(
        odcv_compare_supplied_interval(1, 0, 1).unwrap(),
        OdcvIntervalRelation::AfterDecisionInterval
    );
}
#[test]
fn decision_interval_structure_refuses() {
    for (issued, expires) in [(0, 0), (2, 1), (u64::MAX, u64::MAX)] {
        assert_eq!(
            odcv_compare_supplied_interval(0, issued, expires)
                .unwrap_err()
                .code,
            OdcvFaultCode::Interval
        );
        let mut f = fixture();
        f.signed_change(|p| {
            p.issued_at_unix_millis = issued;
            p.expires_at_unix_millis = expires;
        });
        assert_eq!(f.verify().unwrap_err().code, OdcvFaultCode::Decision);
    }
}
#[test]
fn unsigned_a4_association_is_not_signature_coverage() {
    let mut f = fixture();
    let signed_bytes = f.raw_envelope.clone();
    let original = f.verify().unwrap();
    f.set_observed(f.envelope.payload.expires_at_unix_millis);
    assert_eq!(f.raw_envelope, signed_bytes);
    let rebound = f.verify().unwrap();
    assert_ne!(original.a4_receipt_sha256, rebound.a4_receipt_sha256);
    assert_eq!(
        rebound.comparison_outcome,
        OdcvIntervalRelation::AfterDecisionInterval
    );
    assert!(!rebound.decision_signature_binds_a4_lineage);
    assert!(!rebound.live_authorization_admitted);
}
#[test]
fn all_truth_and_effect_fields_refuse() {
    let f = fixture();
    let receipt = f.verify().unwrap();
    let value = serde_json::to_value(&receipt).unwrap();
    let mut bools = 0;
    for (field, value) in value.as_object().unwrap() {
        if let Some(flag) = value.as_bool() {
            let mut changed: OdcvVerificationReceipt = change_typed(&receipt, field, json!(!flag));
            changed.receipt_sha256 = odcv_receipt_digest(&changed).unwrap();
            assert!(f.validate(&changed).is_err(), "{field}");
            bools += 1;
        }
    }
    assert_eq!(bools, 49);
    let effects = serde_json::to_value(&receipt.effect_account).unwrap();
    for (field, value) in effects.as_object().unwrap() {
        let mut altered = effects.clone();
        altered[field] = if value.is_boolean() {
            json!(true)
        } else {
            json!(1)
        };
        let mut changed = receipt.clone();
        changed.effect_account = serde_json::from_value(altered).unwrap();
        changed.receipt_sha256 = odcv_receipt_digest(&changed).unwrap();
        assert_eq!(
            f.validate(&changed).unwrap_err().code,
            OdcvFaultCode::Effect,
            "{field}"
        );
    }
    assert_eq!(effects.as_object().unwrap().len(), 22);
}
#[test]
fn receipt_identity_refuses() {
    let f = fixture();
    let receipt = f.verify().unwrap();
    let fields = serde_json::to_value(&receipt).unwrap();
    assert_eq!(fields.as_object().unwrap().len(), 113);
    for (name, value) in fields.as_object().unwrap() {
        if value.is_boolean() || name == "effect_account" || name == "receipt_sha256" {
            continue;
        }
        let changed = match value {
            Value::String(_) if name == "input_class" => json!("externally_supplied_candidate"),
            Value::String(_) if name == "decision_kind" => json!("reject"),
            Value::String(_) if name == "comparison_outcome" => json!("before_decision_interval"),
            Value::String(_) if name == "supplied_a3_status_assertion" => {
                json!("unknown_at_snapshot")
            }
            Value::String(s) => json!(format!("{s}-changed")),
            Value::Number(n) => json!(n.as_u64().unwrap().checked_add(1).unwrap_or(0)),
            Value::Object(_) => json!(empty()),
            _ => panic!("unreviewed type {name}"),
        };
        let mut altered: OdcvVerificationReceipt = change_typed(&receipt, name, changed);
        altered.receipt_sha256 = odcv_receipt_digest(&altered).unwrap();
        assert!(f.validate(&altered).is_err(), "{name}");
    }
    let mut changed = receipt;
    changed.receipt_sha256 = empty();
    assert_eq!(
        f.validate(&changed).unwrap_err().code,
        OdcvFaultCode::Digest
    );
}
#[test]
fn canonical_forms_refuse_noncanonical_input() {
    let f = fixture();
    let text = to_odcv_request_machine_form(&f.request).unwrap();
    assert_eq!(from_odcv_request_machine_form(&text).unwrap(), f.request);
    for altered in [
        format!(" {text}"),
        format!("{text}\n"),
        format!("\u{feff}{text}"),
        format!("{text}{{}}"),
        text.replacen("{", "{\"maximum_attempts\":1,", 1),
        text.replacen("{", "{\"unknown\":true,", 1),
        text.replace("\"maximum_attempts\":1", "\"maximum_attempts\":1.0"),
        serde_json::to_string_pretty(&f.request).unwrap(),
        serde_json::to_string(&serde_json::to_value(&f.request).unwrap()).unwrap(),
        " ".repeat(ODCV_MAX_FORM_BYTES + 1),
    ] {
        assert!(from_odcv_request_machine_form(&altered).is_err());
    }
    let receipt = f.verify().unwrap();
    let text = to_odcv_receipt_machine_form(
        &f.request,
        &f.predecessor(),
        &f.policy,
        &f.legacy_request,
        &f.raw_envelope,
        &receipt,
    )
    .unwrap();
    assert_eq!(
        from_odcv_receipt_machine_form(
            &f.request,
            &f.predecessor(),
            &f.policy,
            &f.legacy_request,
            &f.raw_envelope,
            &text
        )
        .unwrap(),
        receipt
    );
    assert!(
        from_odcv_receipt_machine_form(
            &f.request,
            &f.predecessor(),
            &f.policy,
            &f.legacy_request,
            &f.raw_envelope,
            &format!("{text} ")
        )
        .is_err()
    );
}
#[test]
fn bounded_inputs_and_attempts_refuse() {
    for count in [0, 49] {
        let mut f = fixture();
        f.request.evidence_references = (0..count).map(|i| format!("r{i}")).collect();
        refresh_request(&mut f);
        assert_eq!(f.verify().unwrap_err().code, OdcvFaultCode::Evidence);
    }
    for refs in [
        vec!["same".to_owned(), "same".to_owned()],
        vec!["".to_owned()],
        vec!["x".repeat(8193)],
    ] {
        let mut f = fixture();
        f.request.evidence_references = refs;
        refresh_request(&mut f);
        assert!(f.verify().is_err());
    }
    for field in [
        "maximum_attempts",
        "automatic_retry_count",
        "automatic_cleanup_count",
    ] {
        let mut f = fixture();
        f.request = change_typed(&f.request, field, json!(2));
        refresh_request(&mut f);
        assert_eq!(f.verify().unwrap_err().code, OdcvFaultCode::Effect);
    }
    let mut deep = json!(0);
    for _ in 0..33 {
        deep = json!({"n":deep});
    }
    assert!(from_odcv_request_machine_form(&deep.to_string()).is_err());
    let wide: serde_json::Map<String, Value> =
        (0..4097).map(|i| (format!("k{i}"), json!(i))).collect();
    assert!(from_odcv_request_machine_form(&Value::Object(wide).to_string()).is_err());
}
#[test]
fn opaque_references_do_not_resolve_and_downstream_stays_locked() {
    let mut f = fixture();
    f.request.evidence_references = vec![
        "https://never-resolve.invalid/key".to_owned(),
        "C:/not-a-real-evidence-file".to_owned(),
    ];
    refresh_request(&mut f);
    let receipt = f.verify().unwrap();
    assert_eq!(receipt.effect_account, TwvEffectAccount::default());
    assert_eq!(
        expected_odcv_downstream_authorities(),
        vec![
            "fresh_observation",
            "private_execution_permit",
            "broker_projection",
            "physical_preparation"
        ]
    );
}
#[test]
fn self_digests_are_domain_separated() {
    let f = fixture();
    let mut r = f.request.clone();
    r.request_sha256 = empty();
    let mut bytes = b"cantor.b1.operator-decision-chain.request.v1\0".to_vec();
    bytes.extend(serde_json::to_vec(&r).unwrap());
    assert_eq!(sha256_bytes(&bytes), f.request.request_sha256);
    let receipt = f.verify().unwrap();
    let mut normalized = receipt.clone();
    normalized.receipt_sha256 = empty();
    let mut bytes = b"cantor.b1.operator-decision-chain.receipt.v1\0".to_vec();
    bytes.extend(serde_json::to_vec(&normalized).unwrap());
    assert_eq!(sha256_bytes(&bytes), receipt.receipt_sha256);
    assert_ne!(f.request.request_sha256, receipt.receipt_sha256);
}
#[test]
fn evidence_membership_and_rehashed_promotion_refuse() {
    for mode in 0..6 {
        let f = fixture();
        let root = temporary("refuse");
        write_evidence(&root, &f);
        match mode {
            0 => fs::remove_file(root.join("operator_decision_envelope.json")).unwrap(),
            1 => fs::write(root.join("extra.json"), b"{}\n").unwrap(),
            2 => {
                fs::remove_file(root.join("receipt.json")).unwrap();
                fs::create_dir(root.join("receipt.json")).unwrap();
            }
            3 => {
                let mut receipt = f.verify().unwrap();
                receipt.execution_authorized = true;
                receipt.receipt_sha256 = odcv_receipt_digest(&receipt).unwrap();
                fs::write(root.join("receipt.json"), line(&receipt)).unwrap();
                rehash_evidence(&root);
            }
            4 => {
                let mut bytes = fs::read(root.join("operator_decision_envelope.json")).unwrap();
                bytes[0] = b'!';
                fs::write(root.join("operator_decision_envelope.json"), bytes).unwrap();
                rehash_evidence(&root);
            }
            _ => {
                let mut bytes = fs::read(root.join("receipt.json")).unwrap();
                bytes.push(b'\n');
                fs::write(root.join("receipt.json"), bytes).unwrap();
                rehash_evidence(&root);
            }
        }
        assert!(
            verify_odcv_evidence_directory(&root).is_err(),
            "mode {mode}"
        );
    }
}
#[test]
fn evidence_manifest_accounts_and_paths_refuse() {
    let f = fixture();
    let root = temporary("manifest");
    write_evidence(&root, &f);
    let baseline: OdcvEvidenceManifest =
        serde_json::from_slice(&fs::read(root.join("evidence_manifest.json")).unwrap()).unwrap();
    let files: BTreeMap<String, Vec<u8>> = ODCV_EVIDENCE_FILES
        .iter()
        .map(|n| ((*n).to_owned(), fs::read(root.join(n)).unwrap()))
        .collect();
    for mode in 0..9 {
        let mut m = baseline.clone();
        match mode {
            0 => m.artifacts.swap(0, 1),
            1 => m.artifacts[0].path = "../outside".to_owned(),
            2 => m.artifacts[0].path = "C:/outside".to_owned(),
            3 => m.artifacts.push(m.artifacts[0].clone()),
            4 => m.artifact_count = 19,
            5 => m.effect_count = 1,
            6 => m.byte_identical = false,
            7 => m.required_fresh_process_replay_count = 1,
            _ => m.artifacts[0].bytes += 1,
        }
        m.manifest_sha256 = odcv_evidence_manifest_digest(&m).unwrap();
        assert!(
            validate_odcv_evidence_manifest(&m, &files).is_err(),
            "{mode}"
        );
    }
}
#[test]
fn fresh_processes_match_and_refuse_tamper() {
    let f = fixture();
    let root = temporary("process");
    write_evidence(&root, &f);
    let expected = line(&f.verify().unwrap());
    for _ in 0..2 {
        let result = Command::new(EVIDENCE_CLI).arg(&root).output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(result.stderr.is_empty());
        assert_eq!(result.stdout, expected);
    }
    let result = Command::new(CLI)
        .current_dir(&root)
        .args(&ODCV_EVIDENCE_FILES[..19])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, expected);
    assert_eq!(fs::read_dir(&root).unwrap().count(), 21);
    let mut bytes = fs::read(root.join("operator_decision_envelope.json")).unwrap();
    bytes[0] = b'!';
    fs::write(root.join("operator_decision_envelope.json"), bytes).unwrap();
    rehash_evidence(&root);
    let result = Command::new(EVIDENCE_CLI).arg(&root).output().unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    let root = temporary("process-promotion");
    write_evidence(&root, &f);
    let mut receipt = f.verify().unwrap();
    receipt.decision_signature_binds_a4_lineage = true;
    receipt.receipt_sha256 = odcv_receipt_digest(&receipt).unwrap();
    fs::write(root.join("receipt.json"), line(&receipt)).unwrap();
    rehash_evidence(&root);
    let result = Command::new(EVIDENCE_CLI).arg(&root).output().unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
}
#[test]
fn cli_argument_and_file_bounds_refuse() {
    for args in [Vec::<&str>::new(), vec!["x"; 18], vec!["x"; 20]] {
        let out = Command::new(CLI).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
    }
    for args in [Vec::<&str>::new(), vec!["x", "y"]] {
        let out = Command::new(EVIDENCE_CLI).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
    }
    let f = fixture();
    let root = temporary("oversize");
    write_evidence(&root, &f);
    fs::write(
        root.join("operator_decision_policy.json"),
        vec![b'x'; ODCV_MAX_FORM_BYTES + 2],
    )
    .unwrap();
    assert_eq!(
        verify_odcv_evidence_directory(&root).unwrap_err().code,
        OdcvFaultCode::Size
    );
}
#[cfg(windows)]
#[test]
fn windows_junction_directory_and_ancestor_are_refused() {
    let f = fixture();
    let root = temporary("junction");
    write_evidence(&root, &f);
    let junction = root.join("linked");
    assert!(
        !root
            .to_string_lossy()
            .chars()
            .any(|c| "&|<>^%!\"\r\n".contains(c))
    );
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
        verify_odcv_evidence_directory(&junction).unwrap_err().code,
        OdcvFaultCode::Path
    );
    let paths: Vec<PathBuf> = ODCV_EVIDENCE_FILES[..19]
        .iter()
        .map(|n| junction.join(n))
        .collect();
    assert_eq!(
        verify_odcv_payload_paths(&paths).unwrap_err().code,
        OdcvFaultCode::Path
    );
    fs::remove_dir(&junction).expect("remove only the owned junction, not its target");
    assert_eq!(fs::read_dir(&root).unwrap().count(), 21);
}

impl Fixture {
    fn set_a3_status(&mut self, status: KrvStatusAssertion) {
        let mut snapshot: KrvRevocationSnapshot = serde_json::from_slice(&self.raw_a3).unwrap();
        snapshot.status_assertion = status;
        if status == KrvStatusAssertion::RevokedAtSnapshot {
            snapshot.revocation_time_unix_ms = Some(snapshot.this_update_unix_ms);
            snapshot.revocation_reason =
                Some("fixture supplied revocation not operative authority".to_owned());
        } else {
            snapshot.revocation_time_unix_ms = None;
            snapshot.revocation_reason = None;
        }
        snapshot.signature_hex = hex(&SigningKey::from_bytes(&[9; 32])
            .sign(&krv_signature_payload_bytes(&snapshot).unwrap())
            .to_bytes());
        snapshot.snapshot_sha256 = krv_snapshot_digest(&snapshot).unwrap();
        self.raw_a3 = serde_json::to_vec(&snapshot).unwrap();
        let descriptor = &mut self.a3_request.authority_packet_request.descriptors[2];
        descriptor.content_sha256 = sha256_bytes(&self.raw_a3);
        descriptor.declared_bytes = self.raw_a3.len() as u64;
        descriptor.descriptor_sha256 = b1oapr_descriptor_digest(descriptor).unwrap();
        self.a3_request.a3_descriptor_sha256 = descriptor.descriptor_sha256.clone();
        self.a3_request.revocation_snapshot_bytes = descriptor.declared_bytes;
        self.a3_request.revocation_snapshot_raw_sha256 = descriptor.content_sha256.clone();
        self.a3_request.authority_packet_request.request_sha256 =
            b1oapr_request_digest(&self.a3_request.authority_packet_request).unwrap();
        self.a3_request.authority_packet_request_sha256 = self
            .a3_request
            .authority_packet_request
            .request_sha256
            .clone();
        self.a3_request.authority_packet_sha256 =
            compile_b1oapr_packet(&self.a3_request.authority_packet_request)
                .unwrap()
                .packet_sha256;
        self.a3_request.request_sha256 = krv_request_digest(&self.a3_request).unwrap();
        self.a3_receipt = verify_krv_revocation_snapshot(
            &self.a3_request,
            &self.predecessor_request,
            &self.predecessor_packet,
            &self.predecessor_verification,
            &self.a1_envelope,
            &self.raw_a1,
            &self.a1_request,
            &self.a1_receipt,
            &self.a2_attestation,
            &self.raw_a2,
            &self.a2_request,
            &self.a2_receipt,
            &self.raw_a3,
        )
        .unwrap();
        self.witness.a3_receipt_sha256 = self.a3_receipt.receipt_sha256.clone();
        self.witness.a3_authority_packet_sha256 = self.a3_receipt.authority_packet_sha256.clone();
        self.witness.a3_snapshot_sha256 = self.a3_receipt.snapshot_sha256.clone();
        self.witness.a3_snapshot_raw_sha256 = sha256_bytes(&self.raw_a3);
        self.a4_request.a3_receipt_sha256 = self.a3_receipt.receipt_sha256.clone();
        self.a4_request.a3_verification_request_sha256 = self.a3_request.request_sha256.clone();
        self.a4_request.a3_revocation_snapshot_raw_sha256 = sha256_bytes(&self.raw_a3);
        self.a4_request.authority_packet_request = self.a3_request.authority_packet_request.clone();
        self.request.a3_receipt_sha256 = self.a3_receipt.receipt_sha256.clone();
        self.request.a3_verification_request_sha256 = self.a3_request.request_sha256.clone();
        self.request.a3_revocation_snapshot_raw_sha256 = sha256_bytes(&self.raw_a3);
        self.set_observed(self.witness.observed_unix_ms);
        self.policy.revocation_list_artifact_sha256 = sha256_bytes(&self.raw_a3);
        self.rebind_policy(&SigningKey::from_bytes(&[7; 32]));
    }
}
#[test]
fn both_kinds_all_intervals_and_a3_status() {
    for kind in [
        B1CDriveOperatorDecisionKind::Authorize,
        B1CDriveOperatorDecisionKind::Reject,
    ] {
        for status in [
            KrvStatusAssertion::NotRevokedAtSnapshot,
            KrvStatusAssertion::RevokedAtSnapshot,
            KrvStatusAssertion::UnknownAtSnapshot,
        ] {
            let mut f = fixture_for(KcvInputClass::DeterministicFixtureCandidate, kind);
            f.set_a3_status(status);
            for observed in [
                f.envelope.payload.issued_at_unix_millis - 1,
                f.envelope.payload.issued_at_unix_millis,
                f.envelope.payload.expires_at_unix_millis,
            ] {
                f.set_observed(observed);
                let receipt = f.verify().unwrap();
                assert_eq!(receipt.supplied_a3_status_assertion, status);
                assert!(!receipt.revocation_truth_proved);
                assert!(!receipt.live_authorization_admitted);
                assert_eq!(receipt.decision_kind, kind);
            }
        }
    }
}
#[test]
fn maximum_reference_bounds_are_accepted_without_resolution() {
    let mut f = fixture();
    f.request.evidence_references = (0..48).map(|i| format!("opaque-{i}")).collect();
    refresh_request(&mut f);
    f.verify().unwrap();
    f.request.evidence_references = vec!["x".repeat(8192)];
    refresh_request(&mut f);
    f.verify().unwrap();
}
#[test]
fn production_effect_boundary() {
    let core = include_str!("../src/b1_operator_decision_chain_verification.rs");
    let evidence = include_str!("../src/b1_operator_decision_chain_verification_evidence.rs");
    for forbidden in [
        "unsafe {",
        "SigningKey",
        "std::process",
        "std::env",
        "SystemTime::now",
        "TcpStream",
        ".write(true)",
        ".create(true)",
        "fs::write",
        "remove_file(",
        "remove_dir(",
    ] {
        assert!(!core.contains(forbidden), "core {forbidden}");
        assert!(!evidence.contains(forbidden), "evidence {forbidden}");
    }
    assert!(core.contains("verify_twv_time_witness("));
    assert!(core.contains("verify_b1_cdrive_operator_decision("));
}
#[test]
fn evidence_total_bound_and_imported_canonical_forms_refuse() {
    for name in [
        "operator_decision_policy.json",
        "operator_decision_request.json",
        "operator_decision_envelope.json",
        "verification_request.json",
        "receipt.json",
    ] {
        let f = fixture();
        let root = temporary("canonical-file");
        write_evidence(&root, &f);
        let text = fs::read_to_string(root.join(name))
            .unwrap()
            .replacen("{", "{\"unknown\":0,", 1);
        fs::write(root.join(name), text).unwrap();
        rehash_evidence(&root);
        assert!(verify_odcv_evidence_directory(&root).is_err(), "{name}");
    }
    let root = temporary("total-bound");
    fs::create_dir(&root).unwrap();
    let bytes = vec![b'x'; ODCV_MAX_FORM_BYTES];
    for name in ODCV_EVIDENCE_FILES {
        fs::write(root.join(name), &bytes).unwrap();
    }
    assert_eq!(
        verify_odcv_evidence_directory(&root).unwrap_err().code,
        OdcvFaultCode::Size
    );
}
