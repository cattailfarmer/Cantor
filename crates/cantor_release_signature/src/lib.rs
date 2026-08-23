//! Detached release-signature verification with explicit trust nonclaims.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const POLICY_PROFILE: &str = "cantor-release-publisher-policy/0.1";
pub const PAYLOAD_PROFILE: &str = "cantor-provider-free-release-signature-payload/0.1";
pub const ENVELOPE_PROFILE: &str = "cantor-provider-free-release-signature-envelope/0.1";
pub const RECEIPT_PROFILE: &str = "cantor-provider-free-release-signature-receipt/0.1";
pub const SYNTHETIC_FIXTURE_PROFILE: &str =
    "cantor-provider-free-release-signature-synthetic-fixture/0.1";
pub const PORTABLE_EVIDENCE_PROFILE: &str =
    "cantor-provider-free-portable-release-bundle-evidence/0.1";
pub const PORTABLE_EVIDENCE_STATUS: &str =
    "provider_free_portable_release_bundle_verified_with_declared_gaps";
pub const PORTABLE_EVIDENCE_NON_AUTHORITY: &str = "This deterministic archive proves portable provider-free package identity only. SHA256 reproducibility is not publisher authenticity and grants no installer, trust, configuration, provider, effect, persistence, operator-product, or production authority.";
pub const SIGNATURE_NON_AUTHORITY: &str = "Signature verification proves payload integrity and possession of a key pinned by the supplied policy. It does not prove policy governance, publisher identity, trust onboarding, supported delivery, installation, production secret lifecycle, operator acceptance, or production authority.";
pub const SYNTHETIC_NON_AUTHORITY: &str = "This fixed public-key synthetic fixture proves detached release-signature mechanics only. It is not a governed publisher policy, production key, trust root, supported delivery channel, or production authenticity claim.";
pub const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_EVIDENCE_BYTES: usize = 64 * 1024;
pub const MAX_POLICY_BYTES: usize = 16 * 1024;
pub const MAX_ENVELOPE_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherPolicyUseStatus {
    ExternallyGoverned,
    SyntheticFixtureOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePublisherPolicy {
    pub profile: String,
    pub use_status: PublisherPolicyUseStatus,
    pub policy_id: String,
    pub publisher_id: String,
    pub verifying_key_hex: String,
    pub allowed_release_profile: String,
    pub allowed_target: String,
    pub non_authority_statement: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByteIdentity {
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSignaturePayload {
    pub profile: String,
    pub use_status: PublisherPolicyUseStatus,
    pub policy_id: String,
    pub publisher_id: String,
    pub release_profile: String,
    pub target: String,
    pub source_commit: String,
    pub bundle: ByteIdentity,
    pub evidence: ByteIdentity,
    pub non_authority_statement: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReleaseEnvelope {
    pub profile: String,
    pub payload: ReleaseSignaturePayload,
    pub signature_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseVerificationSafety {
    pub policy_governance_proved: bool,
    pub production_publisher_authenticity_proved: bool,
    pub supported_delivery_proved: bool,
    pub archive_extracted: bool,
    pub archive_executed: bool,
    pub installation_performed: bool,
    pub signing_key_created_or_retained: bool,
    pub service_started: bool,
    pub provider_contacted: bool,
    pub remote_accessed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSignatureReceipt {
    pub profile: String,
    pub status: String,
    pub use_status: PublisherPolicyUseStatus,
    pub policy_id: String,
    pub publisher_id: String,
    pub release_profile: String,
    pub target: String,
    pub source_commit: String,
    pub bundle: ByteIdentity,
    pub evidence: ByteIdentity,
    pub signature_verified: bool,
    pub safety: ReleaseVerificationSafety,
    pub non_authority_statement: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyntheticReleaseSignatureFixture {
    pub profile: String,
    pub policy: ReleasePublisherPolicy,
    pub envelope: SignedReleaseEnvelope,
    pub receipt: ReleaseSignatureReceipt,
    pub non_authority_statement: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PortableBundleEvidence {
    profile: String,
    status: String,
    source_commit: String,
    target: String,
    build_mode: String,
    cargo_lock: Value,
    archive: PortableArchiveIdentity,
    embedded_manifest: Value,
    entries: Vec<Value>,
    determinism: Value,
    safety: Value,
    capability_denials: Vec<String>,
    non_authority_statement: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PortableArchiveIdentity {
    file_name: String,
    bytes: u64,
    sha256: String,
    format: String,
    compression: String,
    timestamp_contract: String,
    entry_count: u64,
}

pub fn signature_payload_bytes(payload: &ReleaseSignaturePayload) -> Result<Vec<u8>, String> {
    validate_payload(payload)?;
    serde_json::to_vec(payload).map_err(|error| format!("payload serialization failed: {error}"))
}

pub fn parse_policy(bytes: &[u8]) -> Result<ReleasePublisherPolicy, String> {
    validate_bounded(bytes, MAX_POLICY_BYTES, "policy")?;
    let policy: ReleasePublisherPolicy =
        serde_json::from_slice(bytes).map_err(|error| format!("policy JSON refused: {error}"))?;
    validate_policy(&policy)?;
    Ok(policy)
}

pub fn parse_envelope(bytes: &[u8]) -> Result<SignedReleaseEnvelope, String> {
    validate_bounded(bytes, MAX_ENVELOPE_BYTES, "envelope")?;
    let envelope: SignedReleaseEnvelope =
        serde_json::from_slice(bytes).map_err(|error| format!("envelope JSON refused: {error}"))?;
    validate_envelope(&envelope)?;
    Ok(envelope)
}

pub fn verify_release_signature_bytes(
    bundle_bytes: &[u8],
    evidence_bytes: &[u8],
    policy_bytes: &[u8],
    envelope_bytes: &[u8],
) -> Result<ReleaseSignatureReceipt, String> {
    validate_bounded(bundle_bytes, MAX_BUNDLE_BYTES, "bundle")?;
    validate_bounded(evidence_bytes, MAX_EVIDENCE_BYTES, "bundle evidence")?;
    let policy = parse_policy(policy_bytes)?;
    let envelope = parse_envelope(envelope_bytes)?;
    verify_release_signature(bundle_bytes, evidence_bytes, &policy, &envelope)
}

pub fn verify_release_signature(
    bundle_bytes: &[u8],
    evidence_bytes: &[u8],
    policy: &ReleasePublisherPolicy,
    envelope: &SignedReleaseEnvelope,
) -> Result<ReleaseSignatureReceipt, String> {
    validate_bounded(bundle_bytes, MAX_BUNDLE_BYTES, "bundle")?;
    validate_bounded(evidence_bytes, MAX_EVIDENCE_BYTES, "bundle evidence")?;
    validate_policy(policy)?;
    validate_envelope(envelope)?;
    let payload = &envelope.payload;
    if payload.use_status != policy.use_status
        || payload.policy_id != policy.policy_id
        || payload.publisher_id != policy.publisher_id
        || payload.release_profile != policy.allowed_release_profile
        || payload.target != policy.allowed_target
    {
        return Err("policy and signed payload binding differs".to_owned());
    }
    let bundle_identity = identity(bundle_bytes);
    let evidence_identity = identity(evidence_bytes);
    if payload.bundle != bundle_identity || payload.evidence != evidence_identity {
        return Err("signed bundle or evidence byte identity differs".to_owned());
    }
    let report: PortableBundleEvidence = serde_json::from_slice(evidence_bytes)
        .map_err(|error| format!("portable bundle evidence JSON refused: {error}"))?;
    validate_portable_evidence(&report)?;
    if report.profile != payload.release_profile
        || report.target != payload.target
        || report.source_commit != payload.source_commit
        || report.archive.bytes != bundle_identity.bytes
        || report.archive.sha256 != bundle_identity.sha256
    {
        return Err("portable bundle evidence and signed payload binding differs".to_owned());
    }
    let key_bytes = decode_fixed_hex::<32>(&policy.verifying_key_hex, "policy verifying key")?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| "policy verifying key refused")?;
    let signature_bytes = decode_fixed_hex::<64>(&envelope.signature_hex, "release signature")?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(&signature_payload_bytes(payload)?, &signature)
        .map_err(|_| "release signature refused")?;
    Ok(ReleaseSignatureReceipt {
        profile: RECEIPT_PROFILE.to_owned(),
        status: "verified_with_declared_trust_gaps".to_owned(),
        use_status: payload.use_status.clone(),
        policy_id: payload.policy_id.clone(),
        publisher_id: payload.publisher_id.clone(),
        release_profile: payload.release_profile.clone(),
        target: payload.target.clone(),
        source_commit: payload.source_commit.clone(),
        bundle: bundle_identity,
        evidence: evidence_identity,
        signature_verified: true,
        safety: ReleaseVerificationSafety {
            policy_governance_proved: false,
            production_publisher_authenticity_proved: false,
            supported_delivery_proved: false,
            archive_extracted: false,
            archive_executed: false,
            installation_performed: false,
            signing_key_created_or_retained: false,
            service_started: false,
            provider_contacted: false,
            remote_accessed: false,
        },
        non_authority_statement: SIGNATURE_NON_AUTHORITY.to_owned(),
    })
}

pub fn generate_synthetic_release_signature_fixture(
    bundle_bytes: &[u8],
    evidence_bytes: &[u8],
) -> Result<SyntheticReleaseSignatureFixture, String> {
    validate_bounded(bundle_bytes, MAX_BUNDLE_BYTES, "bundle")?;
    validate_bounded(evidence_bytes, MAX_EVIDENCE_BYTES, "bundle evidence")?;
    let report: PortableBundleEvidence = serde_json::from_slice(evidence_bytes)
        .map_err(|error| format!("portable bundle evidence JSON refused: {error}"))?;
    validate_portable_evidence(&report)?;
    let signing_key = SigningKey::from_bytes(&[97_u8; 32]);
    let policy = ReleasePublisherPolicy {
        profile: POLICY_PROFILE.to_owned(),
        use_status: PublisherPolicyUseStatus::SyntheticFixtureOnly,
        policy_id: "policy:synthetic_release_fixture_only".to_owned(),
        publisher_id: "publisher:synthetic_release_fixture_only".to_owned(),
        verifying_key_hex: encode_hex(&signing_key.verifying_key().to_bytes()),
        allowed_release_profile: report.profile.clone(),
        allowed_target: report.target.clone(),
        non_authority_statement: SIGNATURE_NON_AUTHORITY.to_owned(),
    };
    let payload = ReleaseSignaturePayload {
        profile: PAYLOAD_PROFILE.to_owned(),
        use_status: PublisherPolicyUseStatus::SyntheticFixtureOnly,
        policy_id: policy.policy_id.clone(),
        publisher_id: policy.publisher_id.clone(),
        release_profile: report.profile,
        target: report.target,
        source_commit: report.source_commit,
        bundle: identity(bundle_bytes),
        evidence: identity(evidence_bytes),
        non_authority_statement: SIGNATURE_NON_AUTHORITY.to_owned(),
    };
    let signature_hex = encode_hex(
        &signing_key
            .sign(&signature_payload_bytes(&payload)?)
            .to_bytes(),
    );
    let envelope = SignedReleaseEnvelope {
        profile: ENVELOPE_PROFILE.to_owned(),
        payload,
        signature_hex,
    };
    let receipt = verify_release_signature(bundle_bytes, evidence_bytes, &policy, &envelope)?;
    Ok(SyntheticReleaseSignatureFixture {
        profile: SYNTHETIC_FIXTURE_PROFILE.to_owned(),
        policy,
        envelope,
        receipt,
        non_authority_statement: SYNTHETIC_NON_AUTHORITY.to_owned(),
    })
}

fn validate_policy(policy: &ReleasePublisherPolicy) -> Result<(), String> {
    if policy.profile != POLICY_PROFILE
        || policy.allowed_release_profile != PORTABLE_EVIDENCE_PROFILE
        || policy.allowed_target != "windows-x86_64"
        || policy.non_authority_statement != SIGNATURE_NON_AUTHORITY
        || !valid_identifier(&policy.policy_id)
        || !valid_identifier(&policy.publisher_id)
    {
        return Err("publisher policy form differs".to_owned());
    }
    decode_fixed_hex::<32>(&policy.verifying_key_hex, "policy verifying key")?;
    Ok(())
}

fn validate_payload(payload: &ReleaseSignaturePayload) -> Result<(), String> {
    if payload.profile != PAYLOAD_PROFILE
        || payload.release_profile != PORTABLE_EVIDENCE_PROFILE
        || payload.target != "windows-x86_64"
        || payload.non_authority_statement != SIGNATURE_NON_AUTHORITY
        || !valid_identifier(&payload.policy_id)
        || !valid_identifier(&payload.publisher_id)
        || !valid_commit(&payload.source_commit)
    {
        return Err("release signature payload form differs".to_owned());
    }
    validate_identity(&payload.bundle, MAX_BUNDLE_BYTES, "bundle identity")?;
    validate_identity(&payload.evidence, MAX_EVIDENCE_BYTES, "evidence identity")?;
    Ok(())
}

fn validate_envelope(envelope: &SignedReleaseEnvelope) -> Result<(), String> {
    if envelope.profile != ENVELOPE_PROFILE {
        return Err("release signature envelope profile differs".to_owned());
    }
    validate_payload(&envelope.payload)?;
    decode_fixed_hex::<64>(&envelope.signature_hex, "release signature")?;
    Ok(())
}

fn validate_portable_evidence(report: &PortableBundleEvidence) -> Result<(), String> {
    if report.profile != PORTABLE_EVIDENCE_PROFILE
        || report.status != PORTABLE_EVIDENCE_STATUS
        || report.target != "windows-x86_64"
        || !valid_commit(&report.source_commit)
        || !matches!(
            report.build_mode.as_str(),
            "built_locked_offline" | "verified_prebuilt"
        )
        || report.non_authority_statement != PORTABLE_EVIDENCE_NON_AUTHORITY
        || report.archive.file_name != "cantor-provider-free-windows-x86_64-p0.zip"
        || report.archive.format != "zip"
        || report.archive.compression != "store"
        || report.archive.timestamp_contract != "zip_dos_epoch_1980_01_01_00_00_00"
        || report.archive.entry_count != 6
        || report.entries.len() != 6
        || report.capability_denials.is_empty()
        || report.cargo_lock.is_null()
        || report.embedded_manifest.is_null()
        || report.determinism.is_null()
        || report.safety.is_null()
    {
        return Err("portable bundle evidence form differs".to_owned());
    }
    validate_identity(
        &ByteIdentity {
            bytes: report.archive.bytes,
            sha256: report.archive.sha256.clone(),
        },
        MAX_BUNDLE_BYTES,
        "portable archive identity",
    )
}

fn validate_identity(identity: &ByteIdentity, maximum: usize, label: &str) -> Result<(), String> {
    if identity.bytes == 0 || identity.bytes > maximum as u64 || !is_upper_hex(&identity.sha256, 64)
    {
        return Err(format!("{label} form differs"));
    }
    Ok(())
}

fn validate_bounded(bytes: &[u8], maximum: usize, label: &str) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(format!("{label} byte bound differs"));
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-' | b'.'))
}

fn valid_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn identity(bytes: &[u8]) -> ByteIdentity {
    ByteIdentity {
        bytes: bytes.len() as u64,
        sha256: encode_hex(&Sha256::digest(bytes)),
    }
}

fn is_upper_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
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

fn decode_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if !is_upper_hex(value, N * 2) {
        return Err(format!("{label} form differs"));
    }
    let mut output = [0_u8; N];
    let bytes = value.as_bytes();
    for index in 0..N {
        output[index] =
            (decode_nibble(bytes[index * 2])? << 4) | decode_nibble(bytes[index * 2 + 1])?;
    }
    Ok(output)
}

fn decode_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("hexadecimal value differs".to_owned()),
    }
}
