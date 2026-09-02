use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use cantor_core::{ContentDigest, sha256_bytes};
use cantor_ecosystem::*;
use ed25519_dalek::{Signer, SigningKey};

struct Fixture {
    predecessor_request: B1OaprRequest,
    predecessor_packet: B1OaprPacket,
    predecessor_verification: B1OaprVerification,
    a1_envelope: BpvPolicyEnvelope,
    raw_a1_envelope: Vec<u8>,
    a1_request: BpvVerificationRequest,
    a1_receipt: BpvVerificationReceipt,
    attestation: KcvCustodyAttestation,
    raw_attestation: Vec<u8>,
    request: KcvVerificationRequest,
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

fn a1_envelope(signing_key: &SigningKey, fixture_only: bool) -> BpvPolicyEnvelope {
    let mut payload = deterministic_bpv_fixture_payload().expect("fixture payload");
    payload.fixture_only = fixture_only;
    payload.payload_sha256 = bpv_payload_digest(&payload).expect("payload digest");
    let signature =
        signing_key.sign(&bpv_signature_payload_bytes(&payload).expect("A1 signature payload"));
    let mut envelope = BpvPolicyEnvelope {
        profile: BPV_ENVELOPE_PROFILE.to_owned(),
        payload,
        verifying_key_hex: lower_hex(signing_key.verifying_key().as_bytes()),
        signature_hex: lower_hex(&signature.to_bytes()),
        signing_context: BPV_SIGNING_CONTEXT.to_owned(),
        envelope_sha256: empty_digest(),
    };
    envelope.envelope_sha256 = bpv_envelope_digest(&envelope).expect("A1 envelope digest");
    envelope
}

fn bind_a1(
    envelope: BpvPolicyEnvelope,
    input_class: KcvInputClass,
) -> (
    B1OaprRequest,
    B1OaprPacket,
    B1OaprVerification,
    BpvVerificationRequest,
    BpvVerificationReceipt,
    Vec<u8>,
) {
    let raw_envelope = serde_json::to_vec(&envelope).expect("raw A1 envelope");
    let mut predecessor_request = canonical_b1oapr_request().expect("packet request");
    {
        let descriptor = &mut predecessor_request.descriptors[0];
        descriptor.origin = origin(input_class);
        descriptor.fixture_only = fixture_only(input_class);
        descriptor.opaque_reference = if descriptor.fixture_only {
            "fixture_candidate_a1_policy_bundle".to_owned()
        } else {
            "externally_supplied_candidate_a1_policy_bundle".to_owned()
        };
        descriptor.declared_bytes = raw_envelope.len() as u64;
        descriptor.content_sha256 = sha256_bytes(&raw_envelope);
        descriptor.descriptor_sha256 = b1oapr_descriptor_digest(descriptor).expect("A1 descriptor");
    }
    predecessor_request.request_sha256 =
        b1oapr_request_digest(&predecessor_request).expect("packet request digest");
    let predecessor_packet =
        compile_b1oapr_packet(&predecessor_request).expect("predecessor packet");
    let predecessor_verification = verify_b1oapr_packet(&predecessor_request, &predecessor_packet)
        .expect("predecessor verification");
    let a1 = &predecessor_packet.descriptors[0];
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
        input_class: match input_class {
            KcvInputClass::DeterministicFixtureCandidate => {
                BpvInputClass::DeterministicFixtureCandidate
            }
            KcvInputClass::ExternallySuppliedCandidate => {
                BpvInputClass::ExternallySuppliedCandidate
            }
        },
        evidence_references: vec![
            KCV_PREDECESSOR_REQUEST_FILE.to_owned(),
            KCV_PREDECESSOR_PACKET_FILE.to_owned(),
            KCV_PREDECESSOR_VERIFICATION_FILE.to_owned(),
            KCV_A1_POLICY_ENVELOPE_FILE.to_owned(),
        ],
        request_sha256: empty_digest(),
    };
    request.request_sha256 = bpv_request_digest(&request).expect("A1 request digest");
    let receipt = verify_bpv_policy_bundle(
        &request,
        &predecessor_request,
        &predecessor_packet,
        &predecessor_verification,
        &raw_envelope,
    )
    .expect("A1 receipt");
    (
        predecessor_request,
        predecessor_packet,
        predecessor_verification,
        request,
        receipt,
        raw_envelope,
    )
}

fn signed_attestation(
    signing_key: &SigningKey,
    input_class: KcvInputClass,
    a1_receipt: &BpvVerificationReceipt,
    a2_candidate_uuid: &str,
) -> KcvCustodyAttestation {
    let fixture = fixture_only(input_class);
    let mut challenge = KcvChallenge {
        profile: KCV_CHALLENGE_PROFILE.to_owned(),
        challenge_uuid: "a2000000-0000-4000-8000-000000000001".to_owned(),
        challenge_domain: "cantor.b1.key-custody-proof.challenge.v1".to_owned(),
        subject: "cantor_b1_cdrive_production_preparation_p0".to_owned(),
        branch: "codex/self-hosted-corpus".to_owned(),
        canonical_remote: "https://github.com/cattailfarmer/Cantor".to_owned(),
        policy_uuid: a1_receipt.policy_uuid.clone(),
        policy_revision_uuid: a1_receipt.revision_uuid.clone(),
        a1_receipt_sha256: a1_receipt.receipt_sha256.clone(),
        a2_candidate_uuid: a2_candidate_uuid.to_owned(),
        custody_proof_uuid: "a2000000-0000-4000-8000-000000000002".to_owned(),
        public_key_fingerprint_sha256: a1_receipt.public_key_fingerprint_sha256.clone(),
        issuer_class: input_class,
        fixture_only: fixture,
        nonce_hex: "11".repeat(32),
        challenge_sha256: empty_digest(),
    };
    challenge.challenge_sha256 = kcv_challenge_digest(&challenge).expect("challenge digest");
    let signature =
        signing_key.sign(&kcv_signature_payload_bytes(&challenge).expect("KCV signature payload"));
    let mut attestation = KcvCustodyAttestation {
        profile: KCV_ATTESTATION_PROFILE.to_owned(),
        attestation_uuid: "a2000000-0000-4000-8000-000000000003".to_owned(),
        custody_proof_uuid: challenge.custody_proof_uuid.clone(),
        candidate_label: if fixture {
            "fixture_a2_public_verifying_key_candidate".to_owned()
        } else {
            "external_a2_public_verifying_key_candidate".to_owned()
        },
        custodian_label: if fixture {
            "fixture_custodian_untrusted".to_owned()
        } else {
            "external_claimed_custodian_untrusted".to_owned()
        },
        custody_purpose: "prove_correspondence_to_a1_public_verifying_key_only".to_owned(),
        subject: challenge.subject.clone(),
        branch: challenge.branch.clone(),
        canonical_remote: challenge.canonical_remote.clone(),
        policy_uuid: challenge.policy_uuid.clone(),
        policy_revision_uuid: challenge.policy_revision_uuid.clone(),
        a1_implementation_commit: KCV_A1_IMPLEMENTATION_COMMIT.to_owned(),
        a1_bookend_commit: KCV_A1_BOOKEND_COMMIT.to_owned(),
        a1_proof_uuid: KCV_A1_PROOF_UUID.to_owned(),
        a1_receipt_sha256: a1_receipt.receipt_sha256.clone(),
        verifying_key_hex: lower_hex(signing_key.verifying_key().as_bytes()),
        public_key_fingerprint_sha256: a1_receipt.public_key_fingerprint_sha256.clone(),
        challenge,
        signing_context: KCV_SIGNING_CONTEXT.to_owned(),
        signature_hex: lower_hex(&signature.to_bytes()),
        input_class,
        fixture_only: fixture,
        production_authority_claimed: false,
        challenge_freshness_proved: false,
        replay_prevention_proved: false,
        custodian_identity_proved: false,
        protected_storage_proved: false,
        private_key_nonexportability_proved: false,
        exclusive_control_proved: false,
        current_possession_proved: false,
        key_custody_proved: false,
        attestation_sha256: empty_digest(),
    };
    attestation.attestation_sha256 =
        kcv_attestation_digest(&attestation).expect("attestation digest");
    attestation
}

fn bind_attestation(mut value: Fixture, attestation: KcvCustodyAttestation) -> Fixture {
    let raw_attestation = serde_json::to_vec(&attestation).expect("raw attestation");
    {
        let descriptor = &mut value.request.authority_packet_request.descriptors[1];
        descriptor.origin = origin(attestation.input_class);
        descriptor.fixture_only = attestation.fixture_only;
        descriptor.opaque_reference = if attestation.fixture_only {
            "fixture_candidate_a2_custody_attestation".to_owned()
        } else {
            "externally_supplied_a2_custody_attestation".to_owned()
        };
        descriptor.declared_bytes = raw_attestation.len() as u64;
        descriptor.content_sha256 = sha256_bytes(&raw_attestation);
        descriptor.descriptor_sha256 = b1oapr_descriptor_digest(descriptor).expect("A2 descriptor");
    }
    value.request.authority_packet_request.request_sha256 =
        b1oapr_request_digest(&value.request.authority_packet_request)
            .expect("current packet request digest");
    let packet =
        compile_b1oapr_packet(&value.request.authority_packet_request).expect("current packet");
    value.request.authority_packet_request_sha256 = value
        .request
        .authority_packet_request
        .request_sha256
        .clone();
    value.request.authority_packet_sha256 = packet.packet_sha256;
    value.request.a2_candidate_uuid = value.request.authority_packet_request.descriptors[1]
        .candidate_uuid
        .clone();
    value.request.a2_descriptor_sha256 = value.request.authority_packet_request.descriptors[1]
        .descriptor_sha256
        .clone();
    value.request.custody_attestation_bytes = raw_attestation.len() as u64;
    value.request.custody_attestation_raw_sha256 = sha256_bytes(&raw_attestation);
    value.request.input_class = attestation.input_class;
    value.request.request_sha256 = kcv_request_digest(&value.request).expect("KCV request digest");
    value.attestation = attestation;
    value.raw_attestation = raw_attestation;
    value
}

fn fixture_for(input_class: KcvInputClass) -> Fixture {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let envelope = a1_envelope(&signing_key, fixture_only(input_class));
    let (
        predecessor_request,
        predecessor_packet,
        predecessor_verification,
        a1_request,
        a1_receipt,
        raw_a1_envelope,
    ) = bind_a1(envelope.clone(), input_class);
    let mut request = KcvVerificationRequest {
        profile: KCV_REQUEST_PROFILE.to_owned(),
        source_snapshot_uuid: KCV_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: KCV_CANONICAL_UUID.to_owned(),
        signature_uuid: KCV_SIGNATURE_UUID.to_owned(),
        source_custody_commit: KCV_SOURCE_CUSTODY_COMMIT.to_owned(),
        formation_commit: KCV_FORMATION_COMMIT.to_owned(),
        formation_bookend_commit: KCV_FORMATION_BOOKEND_COMMIT.to_owned(),
        a1_implementation_commit: KCV_A1_IMPLEMENTATION_COMMIT.to_owned(),
        a1_bookend_commit: KCV_A1_BOOKEND_COMMIT.to_owned(),
        a1_proof_uuid: KCV_A1_PROOF_UUID.to_owned(),
        predecessor_request_sha256: predecessor_request.request_sha256.clone(),
        predecessor_packet_sha256: predecessor_packet.packet_sha256.clone(),
        predecessor_verification_sha256: predecessor_verification.verification_sha256.clone(),
        a1_policy_envelope_raw_sha256: sha256_bytes(&raw_a1_envelope),
        a1_verification_request_sha256: a1_request.request_sha256.clone(),
        a1_receipt_sha256: a1_receipt.receipt_sha256.clone(),
        authority_packet_request: predecessor_request.clone(),
        authority_packet_request_sha256: empty_digest(),
        authority_packet_sha256: empty_digest(),
        a2_candidate_uuid: predecessor_request.descriptors[1].candidate_uuid.clone(),
        a2_descriptor_sha256: empty_digest(),
        custody_attestation_bytes: 0,
        custody_attestation_raw_sha256: empty_digest(),
        input_class,
        evidence_references: expected_kcv_artifact_files().into_iter().take(8).collect(),
        maximum_attempts: 1,
        automatic_retry_count: 0,
        automatic_cleanup_count: 0,
        request_sha256: empty_digest(),
    };
    request.authority_packet_request_sha256 =
        request.authority_packet_request.request_sha256.clone();
    let empty_attestation = KcvCustodyAttestation {
        profile: String::new(),
        attestation_uuid: String::new(),
        custody_proof_uuid: String::new(),
        candidate_label: String::new(),
        custodian_label: String::new(),
        custody_purpose: String::new(),
        subject: String::new(),
        branch: String::new(),
        canonical_remote: String::new(),
        policy_uuid: String::new(),
        policy_revision_uuid: String::new(),
        a1_implementation_commit: String::new(),
        a1_bookend_commit: String::new(),
        a1_proof_uuid: String::new(),
        a1_receipt_sha256: empty_digest(),
        verifying_key_hex: String::new(),
        public_key_fingerprint_sha256: empty_digest(),
        challenge: KcvChallenge {
            profile: String::new(),
            challenge_uuid: String::new(),
            challenge_domain: String::new(),
            subject: String::new(),
            branch: String::new(),
            canonical_remote: String::new(),
            policy_uuid: String::new(),
            policy_revision_uuid: String::new(),
            a1_receipt_sha256: empty_digest(),
            a2_candidate_uuid: String::new(),
            custody_proof_uuid: String::new(),
            public_key_fingerprint_sha256: empty_digest(),
            issuer_class: input_class,
            fixture_only: fixture_only(input_class),
            nonce_hex: String::new(),
            challenge_sha256: empty_digest(),
        },
        signing_context: String::new(),
        signature_hex: String::new(),
        input_class,
        fixture_only: fixture_only(input_class),
        production_authority_claimed: false,
        challenge_freshness_proved: false,
        replay_prevention_proved: false,
        custodian_identity_proved: false,
        protected_storage_proved: false,
        private_key_nonexportability_proved: false,
        exclusive_control_proved: false,
        current_possession_proved: false,
        key_custody_proved: false,
        attestation_sha256: empty_digest(),
    };
    let base = Fixture {
        predecessor_request,
        predecessor_packet,
        predecessor_verification,
        a1_envelope: envelope,
        raw_a1_envelope,
        a1_request,
        a1_receipt,
        attestation: empty_attestation,
        raw_attestation: Vec::new(),
        request,
    };
    let attestation = signed_attestation(
        &signing_key,
        input_class,
        &base.a1_receipt,
        &base.request.a2_candidate_uuid,
    );
    bind_attestation(base, attestation)
}

fn fixture() -> Fixture {
    fixture_for(KcvInputClass::DeterministicFixtureCandidate)
}

fn fixture_only(input: KcvInputClass) -> bool {
    matches!(input, KcvInputClass::DeterministicFixtureCandidate)
}

fn origin(input: KcvInputClass) -> B1OaprCandidateOrigin {
    match input {
        KcvInputClass::DeterministicFixtureCandidate => {
            B1OaprCandidateOrigin::DeterministicFixtureCandidate
        }
        KcvInputClass::ExternallySuppliedCandidate => {
            B1OaprCandidateOrigin::ExternallySuppliedCandidate
        }
    }
}

fn verify(value: &Fixture) -> Result<KcvVerificationReceipt, KcvFault> {
    verify_kcv_custody_attestation(
        &value.request,
        &value.predecessor_request,
        &value.predecessor_packet,
        &value.predecessor_verification,
        &value.a1_envelope,
        &value.raw_a1_envelope,
        &value.a1_request,
        &value.a1_receipt,
        &value.raw_attestation,
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
            KCV_PREDECESSOR_REQUEST_FILE,
            retained(to_b1oapr_request_machine_form(&value.predecessor_request).expect("form")),
        ),
        (
            KCV_PREDECESSOR_PACKET_FILE,
            retained(
                to_b1oapr_packet_machine_form(
                    &value.predecessor_request,
                    &value.predecessor_packet,
                )
                .expect("form"),
            ),
        ),
        (
            KCV_PREDECESSOR_VERIFICATION_FILE,
            retained(
                to_b1oapr_verification_machine_form(
                    &value.predecessor_request,
                    &value.predecessor_packet,
                    &value.predecessor_verification,
                )
                .expect("form"),
            ),
        ),
        (
            KCV_A1_POLICY_ENVELOPE_FILE,
            retained(to_bpv_envelope_machine_form(&value.a1_envelope).expect("form")),
        ),
        (
            KCV_A1_VERIFICATION_REQUEST_FILE,
            retained(to_bpv_request_machine_form(&value.a1_request).expect("form")),
        ),
        (
            KCV_A1_RECEIPT_FILE,
            retained(
                to_bpv_receipt_machine_form(
                    &value.a1_request,
                    &value.a1_envelope,
                    &value.a1_receipt,
                )
                .expect("form"),
            ),
        ),
        (
            KCV_CUSTODY_ATTESTATION_FILE,
            retained(to_kcv_attestation_machine_form(&value.attestation).expect("form")),
        ),
        (
            KCV_VERIFICATION_REQUEST_FILE,
            retained(to_kcv_request_machine_form(&value.request).expect("form")),
        ),
        (
            KCV_RECEIPT_FILE,
            retained(
                to_kcv_receipt_machine_form(&value.request, &value.attestation, &receipt)
                    .expect("form"),
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
        bindings.push(KcvEvidenceArtifact {
            path: name.to_owned(),
            bytes: bytes.len() as u64,
            sha256: sha256_bytes(&bytes),
        });
    }
    let mut manifest = KcvEvidenceManifest {
        profile: KCV_EVIDENCE_PROFILE.to_owned(),
        manifest_uuid: "a2000000-0000-4000-8000-000000000004".to_owned(),
        fixture_only: value.attestation.fixture_only,
        artifacts: bindings,
        artifact_count: 9,
        total_artifact_bytes: total,
        retained_authority_packet_sha256: receipt.authority_packet_sha256.clone(),
        retained_a1_receipt_sha256: receipt.a1_receipt_sha256.clone(),
        retained_receipt_sha256: receipt.receipt_sha256,
        deterministic_replay_count: 2,
        required_fresh_process_replay_count: 2,
        byte_identical: true,
        effect_count: 0,
        manifest_sha256: empty_digest(),
    };
    manifest.manifest_sha256 = kcv_evidence_manifest_digest(&manifest).expect("manifest digest");
    fs::write(
        root.join(KCV_EVIDENCE_MANIFEST_FILE),
        retained(to_kcv_evidence_manifest_machine_form(&manifest).expect("manifest form")),
    )
    .expect("write manifest");
}

fn temporary_evidence(value: &Fixture) -> TempEvidence {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "cantor_kcv_evidence_{}_{}",
        std::process::id(),
        sequence
    ));
    assert!(!root.exists(), "temporary path must be fresh");
    write_evidence(&root, value);
    TempEvidence(root)
}

fn resign_attestation(value: &mut KcvCustodyAttestation, key: &SigningKey) {
    value.challenge.challenge_sha256 =
        kcv_challenge_digest(&value.challenge).expect("challenge digest");
    value.signature_hex = lower_hex(
        &key.sign(&kcv_signature_payload_bytes(&value.challenge).expect("signature payload"))
            .to_bytes(),
    );
    value.attestation_sha256 = kcv_attestation_digest(value).expect("attestation digest");
}

#[test]
fn fixture_proves_exact_correspondence_without_custody_authority_or_effects() {
    let receipt = verify(&fixture()).expect("valid fixture");
    assert!(receipt.packet_replayed);
    assert!(receipt.a1_correspondence_receipt_verified);
    assert!(receipt.a2_candidate_bytes_matched);
    assert!(receipt.descriptor_correspondence_verified);
    assert!(receipt.policy_key_correspondence_verified);
    assert!(receipt.challenge_structure_verified);
    assert!(receipt.possession_signature_correspondence_verified);
    assert!(!receipt.challenge_freshness_proved);
    assert!(!receipt.replay_prevention_proved);
    assert!(!receipt.custodian_identity_proved);
    assert!(!receipt.protected_storage_proved);
    assert!(!receipt.private_key_nonexportability_proved);
    assert!(!receipt.exclusive_control_proved);
    assert!(!receipt.current_possession_proved);
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
    assert_eq!(receipt.effect_account, KcvEffectAccount::default());
}

#[test]
fn packet_a1_a2_replay_and_machine_forms_are_byte_identical() {
    let value = fixture();
    let first = verify(&value).expect("first replay");
    let second = verify(&value).expect("second replay");
    assert_eq!(first, second);
    let attestation_text =
        to_kcv_attestation_machine_form(&value.attestation).expect("attestation form");
    assert_eq!(
        from_kcv_attestation_machine_form(&attestation_text).expect("parse"),
        value.attestation
    );
    let request_text = to_kcv_request_machine_form(&value.request).expect("request form");
    assert_eq!(
        from_kcv_request_machine_form(&request_text).expect("parse"),
        value.request
    );
    let receipt_text =
        to_kcv_receipt_machine_form(&value.request, &value.attestation, &first).expect("form");
    assert_eq!(
        from_kcv_receipt_machine_form(&value.request, &value.attestation, &receipt_text)
            .expect("parse"),
        first
    );
}

#[test]
fn external_candidate_classification_remains_unauthorized() {
    let value = fixture_for(KcvInputClass::ExternallySuppliedCandidate);
    let receipt = verify(&value).expect("external candidate correspondence");
    assert!(!receipt.fixture_only);
    assert_eq!(receipt.authority, KCV_AUTHORITY);
    assert!(!receipt.current_possession_proved);
    assert!(!receipt.key_custody_proved);
    assert!(!receipt.execution_authorized);
}

#[test]
fn raw_attestation_argument_tamper_is_refused_before_parsing() {
    let value = fixture();
    let mut raw = value.raw_attestation.clone();
    raw.push(b' ');
    let error = verify_kcv_custody_attestation(
        &value.request,
        &value.predecessor_request,
        &value.predecessor_packet,
        &value.predecessor_verification,
        &value.a1_envelope,
        &value.raw_a1_envelope,
        &value.a1_request,
        &value.a1_receipt,
        &raw,
    )
    .expect_err("raw tamper must fail");
    assert_eq!(error.code, KcvFaultCode::RawBytes);
}

#[test]
fn oversized_attestation_and_raw_a1_tamper_are_refused() {
    let value = fixture();
    let oversized = vec![b'x'; KCV_MAX_FORM_BYTES + 1];
    let error = verify_kcv_custody_attestation(
        &value.request,
        &value.predecessor_request,
        &value.predecessor_packet,
        &value.predecessor_verification,
        &value.a1_envelope,
        &value.raw_a1_envelope,
        &value.a1_request,
        &value.a1_receipt,
        &oversized,
    )
    .expect_err("oversized attestation");
    assert_eq!(error.code, KcvFaultCode::Size);

    let mut raw_a1 = value.raw_a1_envelope.clone();
    raw_a1.push(b' ');
    let error = verify_kcv_custody_attestation(
        &value.request,
        &value.predecessor_request,
        &value.predecessor_packet,
        &value.predecessor_verification,
        &value.a1_envelope,
        &raw_a1,
        &value.a1_request,
        &value.a1_receipt,
        &value.raw_attestation,
    )
    .expect_err("raw A1 tamper");
    assert_eq!(error.code, KcvFaultCode::Predecessor);
}

#[test]
fn profile_lineage_and_fixture_laundering_are_refused() {
    let value = fixture();
    let mut profile = value.attestation.clone();
    profile.profile.push_str(".changed");
    profile.attestation_sha256 = kcv_attestation_digest(&profile).expect("digest");
    assert_eq!(
        validate_kcv_attestation(&profile)
            .expect_err("profile laundering")
            .code,
        KcvFaultCode::Profile
    );

    let mut lineage = fixture();
    lineage.request.formation_commit = "0000000000000000000000000000000000000001".to_owned();
    lineage.request.request_sha256 = kcv_request_digest(&lineage.request).expect("digest");
    assert_eq!(
        verify(&lineage).expect_err("lineage laundering").code,
        KcvFaultCode::Lineage
    );

    let mut fixture_label = value.attestation.clone();
    fixture_label.fixture_only = false;
    fixture_label.attestation_sha256 =
        kcv_attestation_digest(&fixture_label).expect("digest laundering");
    assert_eq!(
        validate_kcv_attestation(&fixture_label)
            .expect_err("fixture laundering")
            .code,
        KcvFaultCode::Fixture
    );
}

#[test]
fn a2_coordinate_substitution_is_refused_after_digest_laundering() {
    let mut value = fixture();
    value.request.a2_candidate_uuid = "a2000000-0000-4000-8000-000000000099".to_owned();
    value.request.request_sha256 = kcv_request_digest(&value.request).expect("digest laundering");
    assert_eq!(
        verify(&value).expect_err("coordinate substitution").code,
        KcvFaultCode::Coordinate
    );
}

#[test]
fn a1_dependency_substitution_is_refused() {
    let mut value = fixture();
    let descriptor = &mut value.request.authority_packet_request.descriptors[0];
    descriptor.candidate_uuid = "a1000000-0000-4000-8000-000000000099".to_owned();
    descriptor.descriptor_sha256 = b1oapr_descriptor_digest(descriptor).expect("digest");
    value.request.authority_packet_request.request_sha256 =
        b1oapr_request_digest(&value.request.authority_packet_request).expect("digest");
    let packet = compile_b1oapr_packet(&value.request.authority_packet_request).expect("packet");
    value.request.authority_packet_request_sha256 = value
        .request
        .authority_packet_request
        .request_sha256
        .clone();
    value.request.authority_packet_sha256 = packet.packet_sha256;
    value.request.request_sha256 = kcv_request_digest(&value.request).expect("digest");
    assert_eq!(
        verify(&value).expect_err("dependency substitution").code,
        KcvFaultCode::Dependency
    );
}

#[test]
fn policy_key_substitution_is_refused_even_with_valid_new_signature() {
    let value = fixture();
    let key = SigningKey::from_bytes(&[9_u8; 32]);
    let mut attestation = value.attestation.clone();
    attestation.verifying_key_hex = lower_hex(key.verifying_key().as_bytes());
    resign_attestation(&mut attestation, &key);
    let value = bind_attestation(value, attestation);
    assert_eq!(
        verify(&value).expect_err("key substitution").code,
        KcvFaultCode::Key
    );
}

#[test]
fn possession_signature_tamper_is_refused_after_raw_rebinding() {
    let value = fixture();
    let mut attestation = value.attestation.clone();
    attestation.signature_hex.replace_range(0..2, "00");
    attestation.attestation_sha256 =
        kcv_attestation_digest(&attestation).expect("attestation digest");
    let value = bind_attestation(value, attestation);
    assert_eq!(
        verify(&value).expect_err("signature tamper").code,
        KcvFaultCode::Signature
    );
}

#[test]
fn nonce_and_context_laundering_are_refused() {
    let value = fixture();
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let mut nonce = value.attestation.clone();
    nonce.challenge.nonce_hex.pop();
    resign_attestation(&mut nonce, &key);
    let nonce = bind_attestation(value, nonce);
    assert_eq!(
        verify(&nonce).expect_err("short nonce").code,
        KcvFaultCode::Nonce
    );

    let value = fixture();
    let mut context = value.attestation.clone();
    context.signing_context.push_str(".changed");
    context.attestation_sha256 = kcv_attestation_digest(&context).expect("digest");
    let context = bind_attestation(value, context);
    assert_eq!(
        verify(&context).expect_err("context laundering").code,
        KcvFaultCode::Context
    );
}

#[test]
fn challenge_domain_and_issuer_laundering_are_refused() {
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let value = fixture();
    let mut challenge = value.attestation.clone();
    challenge.challenge.challenge_domain.push_str(".changed");
    resign_attestation(&mut challenge, &key);
    let challenge = bind_attestation(value, challenge);
    assert_eq!(
        verify(&challenge).expect_err("challenge domain").code,
        KcvFaultCode::Challenge
    );

    let value = fixture();
    let mut issuer = value.attestation.clone();
    issuer.challenge.issuer_class = KcvInputClass::ExternallySuppliedCandidate;
    resign_attestation(&mut issuer, &key);
    let issuer = bind_attestation(value, issuer);
    assert_eq!(
        verify(&issuer).expect_err("issuer class").code,
        KcvFaultCode::Issuer
    );
}

#[test]
fn attestation_claim_promotion_is_refused() {
    let value = fixture();
    let mut attestation = value.attestation.clone();
    attestation.current_possession_proved = true;
    attestation.attestation_sha256 = kcv_attestation_digest(&attestation).expect("digest");
    let value = bind_attestation(value, attestation);
    assert_eq!(
        verify(&value).expect_err("claim promotion").code,
        KcvFaultCode::Claim
    );
}

#[test]
fn receipt_authority_promotion_is_refused_after_digest_laundering() {
    let value = fixture();
    let mut receipt = verify(&value).expect("receipt");
    receipt.key_custody_proved = true;
    receipt.receipt_sha256 = kcv_receipt_digest(&receipt).expect("digest laundering");
    assert_eq!(
        validate_kcv_receipt(&value.request, &value.attestation, &receipt)
            .expect_err("authority promotion")
            .code,
        KcvFaultCode::Truth
    );
}

#[test]
fn receipt_effect_promotion_is_refused_after_digest_laundering() {
    let value = fixture();
    let mut receipt = verify(&value).expect("receipt");
    receipt.effect_account.network_contact_count = 1;
    receipt.receipt_sha256 = kcv_receipt_digest(&receipt).expect("digest laundering");
    assert_eq!(
        validate_kcv_receipt(&value.request, &value.attestation, &receipt)
            .expect_err("effect promotion")
            .code,
        KcvFaultCode::Effect
    );
}

#[test]
fn duplicate_evidence_reference_and_attempt_laundering_are_refused() {
    let mut duplicate = fixture();
    duplicate.request.evidence_references[1] = duplicate.request.evidence_references[0].clone();
    duplicate.request.request_sha256 =
        kcv_request_digest(&duplicate.request).expect("digest laundering");
    assert_eq!(
        verify(&duplicate).expect_err("duplicate").code,
        KcvFaultCode::Bound
    );

    let mut attempts = fixture();
    attempts.request.maximum_attempts = 2;
    attempts.request.request_sha256 = kcv_request_digest(&attempts.request).expect("digest");
    assert_eq!(
        verify(&attempts).expect_err("attempts").code,
        KcvFaultCode::Bound
    );
}

#[test]
fn noncanonical_unknown_duplicate_and_concatenated_json_are_refused() {
    let value = fixture();
    let text = std::str::from_utf8(&value.raw_attestation).expect("UTF-8");
    for changed in [
        format!("{text} "),
        format!("{text}{text}"),
        text.replacen(
            '{',
            &format!("{{\"profile\":\"{}\",", KCV_ATTESTATION_PROFILE),
            1,
        ),
        text.replacen('{', "{\"unknown\":false,", 1),
    ] {
        assert_eq!(
            from_kcv_attestation_machine_form(&changed)
                .expect_err("noncanonical form")
                .code,
            KcvFaultCode::MachineForm
        );
    }
}

#[test]
fn production_modules_expose_no_private_key_clock_process_network_or_write_primitive() {
    let sources = [
        include_str!("../src/b1_public_verifying_key_custody_attestation_verification.rs"),
        include_str!("../src/b1_public_verifying_key_custody_attestation_verification_evidence.rs"),
        include_str!("../src/bin/cantor-b1-public-verifying-key-custody-attestation-verify.rs"),
        include_str!("../src/bin/cantor-b1-public-verifying-key-custody-evidence-verify.rs"),
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
fn independent_evidence_replay_reconstructs_all_nine_artifacts() {
    let value = fixture();
    let evidence = temporary_evidence(&value);
    let replay = verify_kcv_evidence_directory(&evidence.0).expect("evidence replay");
    assert_eq!(replay.artifact_count, 9);
    assert_eq!(replay.deterministic_replay_count, 2);
    assert_eq!(replay.required_fresh_process_replay_count, 2);
    assert!(replay.byte_identical);
    assert_eq!(replay.receipt, verify(&value).expect("direct receipt"));
    assert_eq!(replay.receipt.effect_account, KcvEffectAccount::default());
}

#[test]
fn evidence_raw_byte_tamper_is_refused() {
    let evidence = temporary_evidence(&fixture());
    let path = evidence.0.join(KCV_CUSTODY_ATTESTATION_FILE);
    let mut bytes = fs::read(&path).expect("read");
    bytes.insert(bytes.len() - 1, b' ');
    fs::write(path, bytes).expect("tamper");
    verify_kcv_evidence_directory(&evidence.0).expect_err("raw evidence tamper");
}

#[test]
fn missing_or_extra_evidence_file_is_refused() {
    let missing = temporary_evidence(&fixture());
    fs::remove_file(missing.0.join(KCV_RECEIPT_FILE)).expect("remove receipt");
    verify_kcv_evidence_directory(&missing.0).expect_err("missing file");

    let extra = temporary_evidence(&fixture());
    fs::write(extra.0.join("extra.json"), b"{}\n").expect("extra file");
    verify_kcv_evidence_directory(&extra.0).expect_err("extra file");
}

#[test]
fn fresh_restart_style_reparse_is_byte_identical() {
    let evidence = temporary_evidence(&fixture());
    let first = verify_kcv_evidence_directory(&evidence.0).expect("first instance");
    drop(first.clone());
    let second = verify_kcv_evidence_directory(&evidence.0).expect("fresh instance");
    assert_eq!(first.receipt_machine_form, second.receipt_machine_form);
    assert_eq!(first.receipt.receipt_sha256, second.receipt.receipt_sha256);
}

#[test]
#[ignore = "writes only a fresh explicit test-owned evidence directory"]
fn produce_retained_kcv_fixture_evidence() {
    let root = std::env::var_os("CANTOR_KCV_EVIDENCE_OUTPUT")
        .map(PathBuf::from)
        .expect("CANTOR_KCV_EVIDENCE_OUTPUT must name a fresh explicit directory");
    assert!(!root.exists(), "evidence output must be absent");
    write_evidence(&root, &fixture());
    let replay = verify_kcv_evidence_directory(&root).expect("retained evidence replay");
    println!(
        "kcv_evidence_written root={} artifacts={} bytes={} replay={} restart_required={} byte_identical={} effects=0",
        root.display(),
        replay.artifact_count,
        replay.total_artifact_bytes,
        replay.deterministic_replay_count,
        replay.required_fresh_process_replay_count,
        replay.byte_identical
    );
}
