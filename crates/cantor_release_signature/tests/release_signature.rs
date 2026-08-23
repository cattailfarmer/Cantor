use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};

use cantor_release_signature::{
    PORTABLE_EVIDENCE_NON_AUTHORITY, PORTABLE_EVIDENCE_PROFILE, PORTABLE_EVIDENCE_STATUS,
    PublisherPolicyUseStatus, SIGNATURE_NON_AUTHORITY,
    generate_synthetic_release_signature_fixture, parse_policy, signature_payload_bytes,
    verify_release_signature, verify_release_signature_bytes,
};

fn fixture_bytes() -> (Vec<u8>, Vec<u8>) {
    let bundle = b"synthetic portable archive bytes".to_vec();
    let evidence = serde_json::to_vec_pretty(&json!({
        "profile": PORTABLE_EVIDENCE_PROFILE,
        "status": PORTABLE_EVIDENCE_STATUS,
        "source_commit": "f23a6ce7788aa1fc4988a2dcd0c51d9054092ec7",
        "target": "windows-x86_64",
        "build_mode": "built_locked_offline",
        "cargo_lock": { "path": "Cargo.lock" },
        "archive": {
            "file_name": "cantor-provider-free-windows-x86_64-p0.zip",
            "bytes": bundle.len(),
            "sha256": digest(&bundle),
            "format": "zip",
            "compression": "store",
            "timestamp_contract": "zip_dos_epoch_1980_01_01_00_00_00",
            "entry_count": 6
        },
        "embedded_manifest": { "path": "bundle-manifest.json" },
        "entries": [0, 1, 2, 3, 4, 5],
        "determinism": { "byte_equal": true },
        "safety": { "archive_extracted": false },
        "capability_denials": ["production_trust"],
        "non_authority_statement": PORTABLE_EVIDENCE_NON_AUTHORITY
    }))
    .unwrap();
    (bundle, evidence)
}

#[test]
fn synthetic_fixture_verifies_with_exhaustive_nonclaims() {
    let (bundle, evidence) = fixture_bytes();
    let fixture = generate_synthetic_release_signature_fixture(&bundle, &evidence).unwrap();
    let receipt =
        verify_release_signature(&bundle, &evidence, &fixture.policy, &fixture.envelope).unwrap();
    assert_eq!(receipt, fixture.receipt);
    assert!(receipt.signature_verified);
    assert_eq!(
        receipt.use_status,
        PublisherPolicyUseStatus::SyntheticFixtureOnly
    );
    assert!(!receipt.safety.policy_governance_proved);
    assert!(!receipt.safety.production_publisher_authenticity_proved);
    assert!(!receipt.safety.supported_delivery_proved);
    assert!(!receipt.safety.archive_extracted);
    assert!(!receipt.safety.archive_executed);
    assert!(!receipt.safety.installation_performed);
    assert!(!receipt.safety.signing_key_created_or_retained);
    assert!(!receipt.safety.service_started);
    assert!(!receipt.safety.provider_contacted);
    assert!(!receipt.safety.remote_accessed);
    assert_eq!(receipt.non_authority_statement, SIGNATURE_NON_AUTHORITY);
}

#[test]
fn externally_governed_status_is_mechanical_not_governance_proof() {
    let (bundle, evidence) = fixture_bytes();
    let mut fixture = generate_synthetic_release_signature_fixture(&bundle, &evidence).unwrap();
    fixture.policy.use_status = PublisherPolicyUseStatus::ExternallyGoverned;
    fixture.envelope.payload.use_status = PublisherPolicyUseStatus::ExternallyGoverned;
    let signing_key = SigningKey::from_bytes(&[97_u8; 32]);
    fixture.envelope.signature_hex = encode_hex(
        &signing_key
            .sign(&signature_payload_bytes(&fixture.envelope.payload).unwrap())
            .to_bytes(),
    );
    let receipt =
        verify_release_signature(&bundle, &evidence, &fixture.policy, &fixture.envelope).unwrap();
    assert_eq!(
        receipt.use_status,
        PublisherPolicyUseStatus::ExternallyGoverned
    );
    assert!(!receipt.safety.policy_governance_proved);
    assert!(!receipt.safety.production_publisher_authenticity_proved);
}

#[test]
fn policy_payload_key_and_signature_tampering_refuse() {
    let (bundle, evidence) = fixture_bytes();
    let fixture = generate_synthetic_release_signature_fixture(&bundle, &evidence).unwrap();

    let mut changed = fixture.clone();
    changed.policy.publisher_id = "publisher:changed".to_owned();
    assert!(
        verify_release_signature(&bundle, &evidence, &changed.policy, &changed.envelope).is_err()
    );

    let mut changed = fixture.clone();
    changed.envelope.payload.publisher_id = "publisher:changed".to_owned();
    assert!(
        verify_release_signature(&bundle, &evidence, &changed.policy, &changed.envelope).is_err()
    );

    let mut changed = fixture.clone();
    changed.policy.verifying_key_hex.replace_range(0..2, "00");
    assert!(
        verify_release_signature(&bundle, &evidence, &changed.policy, &changed.envelope).is_err()
    );

    let mut changed = fixture.clone();
    changed.envelope.signature_hex.replace_range(0..2, "00");
    assert!(
        verify_release_signature(&bundle, &evidence, &changed.policy, &changed.envelope).is_err()
    );
}

#[test]
fn bundle_evidence_source_target_and_archive_tampering_refuse() {
    let (bundle, evidence) = fixture_bytes();
    let fixture = generate_synthetic_release_signature_fixture(&bundle, &evidence).unwrap();

    let mut changed_bundle = bundle.clone();
    changed_bundle[0] ^= 1;
    assert!(
        verify_release_signature(
            &changed_bundle,
            &evidence,
            &fixture.policy,
            &fixture.envelope
        )
        .is_err()
    );

    let mut changed_evidence = evidence.clone();
    changed_evidence.push(b' ');
    assert!(
        verify_release_signature(
            &bundle,
            &changed_evidence,
            &fixture.policy,
            &fixture.envelope
        )
        .is_err()
    );

    let mut changed = fixture.clone();
    changed.envelope.payload.source_commit = "0".repeat(40);
    assert!(
        verify_release_signature(&bundle, &evidence, &changed.policy, &changed.envelope).is_err()
    );

    let mut report: serde_json::Value = serde_json::from_slice(&evidence).unwrap();
    report["archive"]["sha256"] = json!("A".repeat(64));
    let changed_evidence = serde_json::to_vec(&report).unwrap();
    assert!(generate_synthetic_release_signature_fixture(&bundle, &changed_evidence).is_err());
}

#[test]
fn strict_unknown_fields_malformed_json_and_bounds_refuse() {
    let (bundle, evidence) = fixture_bytes();
    let fixture = generate_synthetic_release_signature_fixture(&bundle, &evidence).unwrap();
    let mut policy: serde_json::Value = serde_json::to_value(&fixture.policy).unwrap();
    policy["production_trusted"] = json!(true);
    assert!(parse_policy(&serde_json::to_vec(&policy).unwrap()).is_err());
    assert!(parse_policy(b"{").is_err());
    assert!(parse_policy(&vec![b'x'; 16 * 1024 + 1]).is_err());
    let policy_bytes = serde_json::to_vec(&fixture.policy).unwrap();
    let envelope_bytes = serde_json::to_vec(&fixture.envelope).unwrap();
    assert!(
        verify_release_signature_bytes(&[], &evidence, &policy_bytes, &envelope_bytes).is_err()
    );
    assert!(verify_release_signature_bytes(&bundle, &[], &policy_bytes, &envelope_bytes).is_err());
}

fn digest(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0F) as usize] as char);
    }
    output
}
