//! Test-owned A5 fixture construction copied from the published A5 test carrier.
//! Original A5 source remains unchanged. Public fixed keys are test data only.
use cantor_core::{ContentDigest, sha256_bytes};
use cantor_ecosystem::*;
use ed25519_dalek::{Signer, SigningKey};
use serde::de::DeserializeOwned;
use std::{fs, path::Path};
const A4_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../experiments/b1_trusted_time_witness_receipt_verification_p0/implementation_provider_free_evidence"
);
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
fn resign(envelope: &mut B1CDriveOperatorDecisionEnvelope, key: &SigningKey) {
    envelope.payload.payload_sha256 =
        b1_cdrive_operator_decision_payload_digest(&envelope.payload).unwrap();
    envelope.signature_hex = hex(&key
        .sign(&b1_cdrive_operator_decision_signature_payload_bytes(&envelope.payload).unwrap())
        .to_bytes());
    envelope.envelope_sha256 = b1_cdrive_operator_decision_envelope_digest(envelope).unwrap();
}
#[derive(Clone)]
pub(super) struct Fixture {
    pub(super) predecessor_request: B1OaprRequest,
    pub(super) predecessor_packet: B1OaprPacket,
    pub(super) predecessor_verification: B1OaprVerification,
    pub(super) a1_envelope: BpvPolicyEnvelope,
    pub(super) raw_a1: Vec<u8>,
    pub(super) a1_request: BpvVerificationRequest,
    pub(super) a1_receipt: BpvVerificationReceipt,
    pub(super) a2_attestation: KcvCustodyAttestation,
    pub(super) raw_a2: Vec<u8>,
    pub(super) a2_request: KcvVerificationRequest,
    pub(super) a2_receipt: KcvVerificationReceipt,
    pub(super) raw_a3: Vec<u8>,
    pub(super) a3_request: KrvVerificationRequest,
    pub(super) a3_receipt: KrvVerificationReceipt,
    pub(super) witness: TwvTimeWitness,
    pub(super) raw_witness: Vec<u8>,
    pub(super) a4_request: TwvVerificationRequest,
    pub(super) a4_receipt: TwvVerificationReceipt,
    pub(super) policy: B1CDriveOperatorDecisionPolicy,
    pub(super) legacy_request: B1CDriveOperatorDecisionRequest,
    pub(super) envelope: B1CDriveOperatorDecisionEnvelope,
    pub(super) raw_envelope: Vec<u8>,
    pub(super) request: OdcvVerificationRequest,
}
impl Fixture {
    pub(super) fn upstream(&self) -> TwvPredecessor<'_> {
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
    pub(super) fn predecessor(&self) -> OdcvPredecessor<'_> {
        OdcvPredecessor {
            upstream: self.upstream(),
            raw_a4_witness: &self.raw_witness,
            a4_request: &self.a4_request,
            a4_receipt: &self.a4_receipt,
        }
    }
    pub(super) fn verify(&self) -> Result<OdcvVerificationReceipt, OdcvFault> {
        verify_odcv_operator_decision(
            &self.request,
            &self.predecessor(),
            &self.policy,
            &self.legacy_request,
            &self.raw_envelope,
        )
    }
    pub(super) fn redigest_packet(&mut self) {
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
    pub(super) fn bind(&mut self) {
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
    pub(super) fn signed_change(
        &mut self,
        change: impl FnOnce(&mut B1CDriveOperatorDecisionPayload),
    ) {
        change(&mut self.envelope.payload);
        resign(&mut self.envelope, &SigningKey::from_bytes(&[7; 32]));
        self.bind();
    }
    pub(super) fn rebind_policy(&mut self, key: &SigningKey) {
        self.policy.policy_sha256 =
            b1_cdrive_operator_decision_policy_digest(&self.policy).unwrap();
        self.legacy_request = canonical_b1_cdrive_operator_decision_request(&self.policy).unwrap();
        self.envelope.payload.policy_sha256 = self.policy.policy_sha256.clone();
        self.envelope.payload.request_sha256 = self.legacy_request.request_sha256.clone();
        resign(&mut self.envelope, key);
        self.bind();
    }
    pub(super) fn set_observed(&mut self, observed: u64) {
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
pub(super) fn fixture_for(class: KcvInputClass, kind: B1CDriveOperatorDecisionKind) -> Fixture {
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
impl Fixture {
    pub(super) fn set_a3_status(&mut self, status: KrvStatusAssertion) {
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
