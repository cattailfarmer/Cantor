use std::{
    fs,
    path::{Path, PathBuf},
};

use cantor_core::{ContentDigest, sha256_bytes};
use cantor_ecosystem::*;
use ed25519_dalek::{Signer, SigningKey};

const POLICY_UUID: &str = "cb27f6a1-9d30-4d57-bdb4-8a1a06db31f4";
const AUTHORIZE_UUID: &str = "71806df1-b615-4d9d-870f-81ec958ad38c";
const REJECT_UUID: &str = "53984d31-251d-4454-a5bf-36d50f8592af";

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42_u8; 32])
}

fn fixture_policy() -> B1CDriveOperatorDecisionPolicy {
    let verifying_key = signing_key().verifying_key().to_bytes();
    let mut policy = B1CDriveOperatorDecisionPolicy {
        profile: B1_CDRIVE_OPERATOR_DECISION_POLICY_PROFILE.to_owned(),
        policy_uuid: POLICY_UUID.to_owned(),
        principal: r"THEBRAIN\enjer".to_owned(),
        role: "operator_authorizer".to_owned(),
        subject: "cantor_b1_cdrive_production_preparation_p0".to_owned(),
        verifying_key_hex: hex(&verifying_key),
        key_fingerprint_sha256: b1_cdrive_operator_key_fingerprint(&verifying_key),
        policy_governance_ref: "fixture://governance-not-proved".to_owned(),
        policy_governance_artifact_sha256: sha256_bytes(b"fixture governance artifact"),
        revocation_list_artifact_sha256: sha256_bytes(b"fixture revocation artifact"),
        fixture_only: true,
        policy_sha256: empty_digest(),
    };
    redigest_policy(&mut policy);
    policy
}

fn redigest_policy(policy: &mut B1CDriveOperatorDecisionPolicy) {
    policy.policy_sha256 = empty_digest();
    policy.policy_sha256 = b1_cdrive_operator_decision_policy_digest(policy).unwrap();
}

fn fixture_request(policy: &B1CDriveOperatorDecisionPolicy) -> B1CDriveOperatorDecisionRequest {
    canonical_b1_cdrive_operator_decision_request(policy).unwrap()
}

fn redigest_request(request: &mut B1CDriveOperatorDecisionRequest) {
    request.request_sha256 = empty_digest();
    request.request_sha256 = b1_cdrive_operator_decision_request_digest(request).unwrap();
}

fn fixture_envelope(
    policy: &B1CDriveOperatorDecisionPolicy,
    request: &B1CDriveOperatorDecisionRequest,
    decision_kind: B1CDriveOperatorDecisionKind,
) -> B1CDriveOperatorDecisionEnvelope {
    let (decision_uuid, external_decision_identity) = match decision_kind {
        B1CDriveOperatorDecisionKind::Authorize => (AUTHORIZE_UUID, "fixture-authorize-001"),
        B1CDriveOperatorDecisionKind::Reject => (REJECT_UUID, "fixture-reject-001"),
    };
    let payload = B1CDriveOperatorDecisionPayload {
        profile: B1_CDRIVE_OPERATOR_DECISION_PAYLOAD_PROFILE.to_owned(),
        decision_uuid: decision_uuid.to_owned(),
        request_sha256: request.request_sha256.clone(),
        policy_sha256: policy.policy_sha256.clone(),
        decision_kind,
        principal: policy.principal.clone(),
        role: policy.role.clone(),
        subject: policy.subject.clone(),
        purpose: "production_preparation_commission_proposal_decision".to_owned(),
        conversation_uuid: "01a02268-2614-7d80-9737-ea77f4aeacb1".to_owned(),
        external_decision_identity: external_decision_identity.to_owned(),
        issued_at_unix_millis: 1_000,
        expires_at_unix_millis: 2_000,
        maximum_attempts: 1,
        retry_count: 0,
        automatic_cleanup_count: 0,
        fixture_only: true,
        payload_sha256: empty_digest(),
    };
    resign(payload)
}

fn resign(mut payload: B1CDriveOperatorDecisionPayload) -> B1CDriveOperatorDecisionEnvelope {
    payload.payload_sha256 = empty_digest();
    payload.payload_sha256 = b1_cdrive_operator_decision_payload_digest(&payload).unwrap();
    let signature =
        signing_key().sign(&b1_cdrive_operator_decision_signature_payload_bytes(&payload).unwrap());
    let mut envelope = B1CDriveOperatorDecisionEnvelope {
        profile: B1_CDRIVE_OPERATOR_DECISION_ENVELOPE_PROFILE.to_owned(),
        payload,
        signature_hex: hex(&signature.to_bytes()),
        fixture_only: true,
        envelope_sha256: empty_digest(),
    };
    envelope.envelope_sha256 = b1_cdrive_operator_decision_envelope_digest(&envelope).unwrap();
    envelope
}

fn fixture(
    kind: B1CDriveOperatorDecisionKind,
) -> (
    B1CDriveOperatorDecisionPolicy,
    B1CDriveOperatorDecisionRequest,
    B1CDriveOperatorDecisionEnvelope,
    B1CDriveOperatorDecisionVerification,
) {
    let policy = fixture_policy();
    let request = fixture_request(&policy);
    let envelope = fixture_envelope(&policy, &request, kind);
    let receipt = verify_b1_cdrive_operator_decision(&request, &policy, &envelope).unwrap();
    (policy, request, envelope, receipt)
}

#[test]
fn authorize_and_reject_are_deterministic_correspondence_only_and_zero_effect() {
    for (kind, status) in [
        (
            B1CDriveOperatorDecisionKind::Authorize,
            B1_CDRIVE_OPERATOR_DECISION_AUTHORIZE_STATUS,
        ),
        (
            B1CDriveOperatorDecisionKind::Reject,
            B1_CDRIVE_OPERATOR_DECISION_REJECT_STATUS,
        ),
    ] {
        let (policy, request, envelope, receipt) = fixture(kind);
        assert_eq!(
            receipt,
            verify_b1_cdrive_operator_decision(&request, &policy, &envelope).unwrap()
        );
        assert_eq!(receipt.status, status);
        assert_eq!(receipt.authority, B1_CDRIVE_OPERATOR_DECISION_AUTHORITY);
        assert!(receipt.proposal_correspondence_verified);
        assert!(receipt.cryptographic_signature_verified);
        assert!(receipt.fixture_only);
        assert!(!receipt.policy_governance_proved);
        assert!(!receipt.current_nonexpired);
        assert!(!receipt.live_authorization_admitted);
        assert!(!receipt.fresh_observation_proved);
        assert!(!receipt.private_execution_permit_present);
        assert!(!receipt.physical_preparation_authorized);
        assert!(!receipt.production_broker_projection_present);
        assert_eq!(receipt.effect_account, Default::default());
    }
}

#[test]
fn machine_forms_are_canonical_duplicate_free_unknown_free_and_bounded() {
    let (policy, request, envelope, receipt) = fixture(B1CDriveOperatorDecisionKind::Authorize);
    let policy_text = to_b1_cdrive_operator_decision_policy_machine_form(&policy).unwrap();
    assert_eq!(
        from_b1_cdrive_operator_decision_policy_machine_form(&policy_text).unwrap(),
        policy
    );
    let request_text =
        to_b1_cdrive_operator_decision_request_machine_form(&policy, &request).unwrap();
    assert_eq!(
        from_b1_cdrive_operator_decision_request_machine_form(&policy, &request_text).unwrap(),
        request
    );
    let envelope_text =
        to_b1_cdrive_operator_decision_envelope_machine_form(&request, &policy, &envelope).unwrap();
    assert_eq!(
        from_b1_cdrive_operator_decision_envelope_machine_form(&request, &policy, &envelope_text)
            .unwrap(),
        envelope
    );
    let receipt_text = to_b1_cdrive_operator_decision_verification_machine_form(
        &request, &policy, &envelope, &receipt,
    )
    .unwrap();
    assert_eq!(
        from_b1_cdrive_operator_decision_verification_machine_form(
            &request,
            &policy,
            &envelope,
            &receipt_text
        )
        .unwrap(),
        receipt
    );
    assert!(
        from_b1_cdrive_operator_decision_policy_machine_form(&(policy_text.clone() + "\n"))
            .is_err()
    );
    assert!(
        from_b1_cdrive_operator_decision_policy_machine_form(&policy_text.replacen(
            "{\"profile\":",
            "{\"profile\":\"duplicate\",\"profile\":",
            1
        ))
        .is_err()
    );
    assert!(
        from_b1_cdrive_operator_decision_policy_machine_form(&policy_text.replacen(
            '{',
            "{\"unknown\":0,",
            1
        ))
        .is_err()
    );
    assert!(
        from_b1_cdrive_operator_decision_policy_machine_form(
            &"x".repeat(B1_CDRIVE_OPERATOR_DECISION_MAX_MACHINE_FORM_BYTES + 1)
        )
        .is_err()
    );
}

#[test]
fn exact_published_proposal_raw_bytes_uuid_self_digest_and_bookends_are_replayed() {
    let policy = fixture_policy();
    let base = fixture_request(&policy);
    let mut variants = Vec::new();
    let mut changed = base.clone();
    changed.proposal_machine_form.push(' ');
    variants.push(changed);
    let mut changed = base.clone();
    changed.proposal_uuid = POLICY_UUID.to_owned();
    variants.push(changed);
    let mut changed = base.clone();
    changed.proposal_self_sha256.value.replace_range(0..1, "0");
    variants.push(changed);
    let mut changed = base.clone();
    changed.proposal_implementation_commit = "0".repeat(40);
    variants.push(changed);
    let mut changed = base.clone();
    changed.proposal_bookend_commit = "0".repeat(40);
    variants.push(changed);
    let mut changed = base.clone();
    changed.formation_commit = "0".repeat(40);
    variants.push(changed);
    for mut variant in variants {
        variant.proposal_bytes = variant.proposal_machine_form.len() as u64;
        variant.proposal_raw_sha256 = sha256_bytes(variant.proposal_machine_form.as_bytes());
        redigest_request(&mut variant);
        assert!(validate_b1_cdrive_operator_decision_request(&policy, &variant).is_err());
    }
}

#[test]
fn policy_identity_key_governance_and_revocation_mutations_refuse() {
    let base = fixture_policy();
    let request = fixture_request(&base);
    let envelope = fixture_envelope(&base, &request, B1CDriveOperatorDecisionKind::Authorize);
    let mut variants = Vec::new();
    let mut changed = base.clone();
    changed.principal.push('x');
    variants.push(changed);
    let mut changed = base.clone();
    changed.role.push('x');
    variants.push(changed);
    let mut changed = base.clone();
    changed.subject.push('x');
    variants.push(changed);
    let mut changed = base.clone();
    changed.verifying_key_hex.replace_range(0..2, "00");
    variants.push(changed);
    let mut changed = base.clone();
    changed
        .key_fingerprint_sha256
        .value
        .replace_range(0..1, "0");
    variants.push(changed);
    let mut changed = base.clone();
    changed.policy_governance_ref.clear();
    variants.push(changed);
    let mut changed = base.clone();
    changed.policy_governance_artifact_sha256 = sha256_bytes(b"replacement governance artifact");
    variants.push(changed);
    let mut changed = base.clone();
    changed.revocation_list_artifact_sha256 = sha256_bytes(b"replacement revocation artifact");
    variants.push(changed);
    for mut variant in variants {
        redigest_policy(&mut variant);
        if validate_b1_cdrive_operator_decision_policy(&variant).is_ok() {
            assert!(verify_b1_cdrive_operator_decision(&request, &variant, &envelope).is_err());
        }
    }
}

#[test]
fn decision_identity_time_ceiling_fixture_and_binding_mutations_refuse() {
    let (policy, request, base, _) = fixture(B1CDriveOperatorDecisionKind::Authorize);
    let mut variants = Vec::new();
    let mut changed = base.payload.clone();
    changed.decision_uuid = request.canonical_uuid.clone();
    variants.push(changed);
    let mut changed = base.payload.clone();
    changed.request_sha256.value.replace_range(0..1, "0");
    variants.push(changed);
    let mut changed = base.payload.clone();
    changed.policy_sha256.value.replace_range(0..1, "0");
    variants.push(changed);
    let mut changed = base.payload.clone();
    changed.purpose.push('x');
    variants.push(changed);
    let mut changed = base.payload.clone();
    changed.conversation_uuid = POLICY_UUID.to_owned();
    variants.push(changed);
    let mut changed = base.payload.clone();
    changed.external_decision_identity.clear();
    variants.push(changed);
    let mut changed = base.payload.clone();
    changed.expires_at_unix_millis = changed.issued_at_unix_millis;
    variants.push(changed);
    let mut changed = base.payload.clone();
    changed.maximum_attempts = 2;
    variants.push(changed);
    let mut changed = base.payload.clone();
    changed.retry_count = 1;
    variants.push(changed);
    let mut changed = base.payload.clone();
    changed.automatic_cleanup_count = 1;
    variants.push(changed);
    let mut changed = base.payload.clone();
    changed.fixture_only = false;
    variants.push(changed);
    for variant in variants {
        assert!(
            validate_b1_cdrive_operator_decision_envelope(&request, &policy, &resign(variant))
                .is_err()
        );
    }
}

#[test]
fn signature_tamper_wrong_key_and_cross_decision_reuse_refuse() {
    let (policy, request, mut authorize, _) = fixture(B1CDriveOperatorDecisionKind::Authorize);
    authorize.signature_hex.replace_range(0..2, "00");
    authorize.envelope_sha256 = empty_digest();
    authorize.envelope_sha256 = b1_cdrive_operator_decision_envelope_digest(&authorize).unwrap();
    assert!(verify_b1_cdrive_operator_decision(&request, &policy, &authorize).is_err());

    let mut wrong_policy = policy.clone();
    let wrong_key = SigningKey::from_bytes(&[7_u8; 32])
        .verifying_key()
        .to_bytes();
    wrong_policy.verifying_key_hex = hex(&wrong_key);
    wrong_policy.key_fingerprint_sha256 = b1_cdrive_operator_key_fingerprint(&wrong_key);
    redigest_policy(&mut wrong_policy);
    assert!(canonical_b1_cdrive_operator_decision_request(&wrong_policy).is_ok());
    assert!(
        verify_b1_cdrive_operator_decision(
            &request,
            &wrong_policy,
            &fixture_envelope(&policy, &request, B1CDriveOperatorDecisionKind::Authorize)
        )
        .is_err()
    );

    let reject = fixture_envelope(&policy, &request, B1CDriveOperatorDecisionKind::Reject);
    let mut cross = reject.clone();
    cross.signature_hex =
        fixture_envelope(&policy, &request, B1CDriveOperatorDecisionKind::Authorize).signature_hex;
    cross.envelope_sha256 = empty_digest();
    cross.envelope_sha256 = b1_cdrive_operator_decision_envelope_digest(&cross).unwrap();
    assert!(verify_b1_cdrive_operator_decision(&request, &policy, &cross).is_err());
}

#[test]
fn receipt_authority_freshness_broker_and_effect_laundering_refuse() {
    let (policy, request, envelope, base) = fixture(B1CDriveOperatorDecisionKind::Authorize);
    let mut variants = Vec::new();
    let mut changed = base.clone();
    changed.policy_governance_proved = true;
    variants.push(changed);
    let mut changed = base.clone();
    changed.current_nonexpired = true;
    variants.push(changed);
    let mut changed = base.clone();
    changed.live_authorization_admitted = true;
    variants.push(changed);
    let mut changed = base.clone();
    changed.fresh_observation_proved = true;
    variants.push(changed);
    let mut changed = base.clone();
    changed.private_execution_permit_present = true;
    variants.push(changed);
    let mut changed = base.clone();
    changed.physical_preparation_authorized = true;
    variants.push(changed);
    let mut changed = base.clone();
    changed.production_broker_projection_present = true;
    variants.push(changed);
    let mut changed = base.clone();
    changed.effect_account.process_count = 1;
    variants.push(changed);
    for mut variant in variants {
        variant.verification_sha256 = empty_digest();
        variant.verification_sha256 =
            b1_cdrive_operator_decision_verification_digest(&variant).unwrap();
        assert!(
            validate_b1_cdrive_operator_decision_verification(
                &request, &policy, &envelope, &variant
            )
            .is_err()
        );
    }
}

#[test]
fn production_verifier_has_no_signer_clock_process_network_or_broker_projection() {
    let source = include_str!(
        "../src/self_work_update_broker_b1_cdrive_production_preparation_operator_decision_verification.rs"
    );
    for forbidden in [
        "SigningKey",
        "Signer",
        ".sign(",
        "std::env",
        "SystemTime",
        "std::process",
        "Command::",
        "TcpStream",
        "production_broker(",
        "fs::write",
        "create_dir",
        "remove_dir",
        "unsafe",
    ] {
        assert!(
            !source.contains(forbidden),
            "production verifier effect surface: {forbidden}"
        );
    }
    assert!(include_str!("../../../narrative/registries/Cantor_Self_Work_Update_Broker_B1_CDrive_Production_Preparation_Operator_Decision_Verification_P0_Satisfaction_Signature.sop").contains(B1_CDRIVE_OPERATOR_DECISION_SIGNATURE_UUID));
    assert!(include_str!("../../../source_documents/2026-08-27_cantor_self_work_update_broker_b1_cdrive_production_preparation_operator_decision_verification_p0/Cantor_Self_Work_Update_Broker_B1_CDrive_Production_Preparation_Operator_Decision_Verification_P0_Source.sop").contains(B1_CDRIVE_OPERATOR_DECISION_SOURCE_SNAPSHOT_UUID));
}

#[test]
fn retained_evidence_replays_both_decisions_twice_without_live_authority() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../experiments/self_work_update_broker_b1_cdrive_production_preparation_operator_decision_verification_p0/implementation_provider_free_evidence",
    );
    let left = verify_b1_cdrive_operator_decision_evidence_directory(&root).unwrap();
    let right = verify_b1_cdrive_operator_decision_evidence_directory(&root).unwrap();
    assert_eq!(left, right);
    assert_eq!(left.artifact_count, 6);
    assert_eq!(left.decision_count, 2);
    assert_eq!(left.independent_replay_count, 4);
    assert!(left.byte_identical_replays);
    assert!(left.signature_correspondence_verified);
    assert!(left.fixture_only);
    assert!(!left.policy_governance_proved);
    assert!(!left.current_nonexpired);
    assert!(!left.live_authorization_admitted);
    assert!(!left.physical_preparation_authorized);
    assert!(!left.production_broker_projection_present);
    assert_eq!(left.effect_account, Default::default());
}

#[test]
fn evidence_refuses_extra_entry_raw_byte_and_manifest_coordinate_tamper() {
    let root = temporary_root("evidence-tamper");
    write_fixture_artifacts(&root);
    fs::write(root.join("extra.json"), b"{}").unwrap();
    assert!(verify_b1_cdrive_operator_decision_evidence_directory(&root).is_err());
    fs::remove_file(root.join("extra.json")).unwrap();
    let mut request = fs::read(root.join("request.json")).unwrap();
    request.push(b'\n');
    fs::write(root.join("request.json"), request).unwrap();
    assert!(verify_b1_cdrive_operator_decision_evidence_directory(&root).is_err());
    fs::remove_dir_all(&root).unwrap();

    let root = temporary_root("manifest-tamper");
    write_fixture_artifacts(&root);
    let path = root.join("evidence_manifest.json");
    let text = fs::read_to_string(&path).unwrap();
    fs::write(&path, text.replacen("policy.json", "policy-drift.json", 1)).unwrap();
    assert!(verify_b1_cdrive_operator_decision_evidence_directory(&root).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn evidence_refuses_decision_signature_and_retained_receipt_tamper() {
    let root = temporary_root("decision-tamper");
    write_fixture_artifacts(&root);
    let path = root.join("authorize_decision.json");
    let text = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        text.replacen("fixture-authorize-001", "fixture-authorize-002", 1),
    )
    .unwrap();
    assert!(verify_b1_cdrive_operator_decision_evidence_directory(&root).is_err());
    fs::remove_dir_all(&root).unwrap();

    let root = temporary_root("receipt-tamper");
    write_fixture_artifacts(&root);
    let path = root.join("authorize_verification.json");
    let text = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        text.replacen(
            "\"current_nonexpired\":false",
            "\"current_nonexpired\":true",
            1,
        ),
    )
    .unwrap();
    assert!(verify_b1_cdrive_operator_decision_evidence_directory(&root).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn fault_codes_distinguish_policy_signature_and_authority_refusals() {
    let (mut policy, request, mut envelope, mut receipt) =
        fixture(B1CDriveOperatorDecisionKind::Authorize);
    policy.role.push('x');
    redigest_policy(&mut policy);
    assert_eq!(
        validate_b1_cdrive_operator_decision_policy(&policy)
            .unwrap_err()
            .code,
        B1CDriveOperatorDecisionFaultCode::Policy
    );
    let policy = fixture_policy();
    envelope.signature_hex.replace_range(0..2, "00");
    envelope.envelope_sha256 = empty_digest();
    envelope.envelope_sha256 = b1_cdrive_operator_decision_envelope_digest(&envelope).unwrap();
    assert_eq!(
        validate_b1_cdrive_operator_decision_envelope(&request, &policy, &envelope)
            .unwrap_err()
            .code,
        B1CDriveOperatorDecisionFaultCode::Signature
    );
    let envelope = fixture_envelope(&policy, &request, B1CDriveOperatorDecisionKind::Authorize);
    receipt.current_nonexpired = true;
    receipt.verification_sha256 = empty_digest();
    receipt.verification_sha256 =
        b1_cdrive_operator_decision_verification_digest(&receipt).unwrap();
    assert_eq!(
        validate_b1_cdrive_operator_decision_verification(&request, &policy, &envelope, &receipt)
            .unwrap_err()
            .code,
        B1CDriveOperatorDecisionFaultCode::Authority
    );
}

#[test]
#[ignore = "writes only the explicitly supplied owned evidence root"]
fn write_owned_operator_decision_verification_evidence() {
    let root = std::env::var_os("CANTOR_B1PODV_EVIDENCE_ROOT")
        .map(PathBuf::from)
        .expect("CANTOR_B1PODV_EVIDENCE_ROOT");
    assert!(!root.exists(), "owned evidence root must be absent");
    write_fixture_artifacts(&root);
}

fn write_fixture_artifacts(root: &Path) {
    fs::create_dir(root).unwrap();
    let (policy, request, authorize, authorize_receipt) =
        fixture(B1CDriveOperatorDecisionKind::Authorize);
    let reject = fixture_envelope(&policy, &request, B1CDriveOperatorDecisionKind::Reject);
    let reject_receipt = verify_b1_cdrive_operator_decision(&request, &policy, &reject).unwrap();
    let files = [
        (
            "policy.json",
            to_b1_cdrive_operator_decision_policy_machine_form(&policy).unwrap(),
        ),
        (
            "request.json",
            to_b1_cdrive_operator_decision_request_machine_form(&policy, &request).unwrap(),
        ),
        (
            "authorize_decision.json",
            to_b1_cdrive_operator_decision_envelope_machine_form(&request, &policy, &authorize)
                .unwrap(),
        ),
        (
            "reject_decision.json",
            to_b1_cdrive_operator_decision_envelope_machine_form(&request, &policy, &reject)
                .unwrap(),
        ),
        (
            "authorize_verification.json",
            to_b1_cdrive_operator_decision_verification_machine_form(
                &request,
                &policy,
                &authorize,
                &authorize_receipt,
            )
            .unwrap(),
        ),
        (
            "reject_verification.json",
            to_b1_cdrive_operator_decision_verification_machine_form(
                &request,
                &policy,
                &reject,
                &reject_receipt,
            )
            .unwrap(),
        ),
    ];
    let artifacts = files
        .iter()
        .map(|(path, text)| B1CDriveOperatorDecisionEvidenceArtifact {
            path: (*path).to_owned(),
            bytes: text.len() as u64,
            sha256: sha256_bytes(text.as_bytes()),
        })
        .collect();
    for (path, text) in &files {
        fs::write(root.join(path), text).unwrap();
    }
    let mut manifest = B1CDriveOperatorDecisionEvidenceManifest {
        profile: B1_CDRIVE_OPERATOR_DECISION_EVIDENCE_MANIFEST_PROFILE.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_OPERATOR_DECISION_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: B1_CDRIVE_OPERATOR_DECISION_CANONICAL_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_OPERATOR_DECISION_SIGNATURE_UUID.to_owned(),
        formation_commit: B1_CDRIVE_OPERATOR_DECISION_FORMATION_COMMIT.to_owned(),
        artifacts,
        fixture_only: true,
        live_authorization_admitted: false,
        physical_execution_authorized: false,
        non_authority_statement: "Fixture-only signature-correspondence evidence; policy governance, current nonexpiration, live authority, fresh observation, private execution permit, physical preparation, production-broker projection, process, provider, model, MCP, network, writer, Git or filesystem runtime mutation, persistence, activation, D-drive runtime contact, WSL compilation, cleanup, and foreign effects remain absent.".to_owned(),
        manifest_sha256: empty_digest(),
    };
    manifest.manifest_sha256 =
        b1_cdrive_operator_decision_evidence_manifest_digest(&manifest).unwrap();
    fs::write(
        root.join("evidence_manifest.json"),
        to_b1_cdrive_operator_decision_evidence_manifest_machine_form(&manifest).unwrap(),
    )
    .unwrap();
}

fn temporary_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("cantor_b1podv_{label}_{}", std::process::id()))
}
