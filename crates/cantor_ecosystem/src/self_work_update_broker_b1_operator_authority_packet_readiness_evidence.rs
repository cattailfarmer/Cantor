//! Independent retained-evidence verifier for the B1 candidate packet.

use std::{collections::BTreeSet, fmt, fs, path::Path};

use cantor_core::{ContentDigest, sha256_bytes};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::self_work_update_broker_b1_operator_authority_packet_readiness::{
    B1OAPR_AUTHORITY, B1OAPR_CANONICAL_UUID, B1OAPR_FORMATION_COMMIT, B1OAPR_MAX_FORM_BYTES,
    B1OAPR_SIGNATURE_UUID, B1OAPR_SOURCE_SNAPSHOT_UUID, B1OAPR_STATUS, B1OaprEffectAccount,
    B1OaprPacket, B1OaprRequest, B1OaprVerification, compile_b1oapr_packet,
    from_b1oapr_packet_machine_form, from_b1oapr_request_machine_form,
    from_b1oapr_verification_machine_form, to_b1oapr_packet_machine_form,
    to_b1oapr_verification_machine_form, validate_b1oapr_verification, verify_b1oapr_packet,
};

pub const B1OAPR_EVIDENCE_PROFILE: &str = "cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-authority-packet-readiness-evidence/0.1";
pub const B1OAPR_EVIDENCE_MANIFEST_PROFILE: &str = "cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-authority-packet-readiness-evidence-manifest/0.1";
pub const B1OAPR_NON_AUTHORITY: &str = "candidate metadata shape only; no candidate material was authenticated, no authority was admitted, and no physical execution was authorized";
pub const B1OAPR_REQUEST_FILE: &str = "request.json";
pub const B1OAPR_PACKET_FILE: &str = "packet.json";
pub const B1OAPR_VERIFICATION_FILE: &str = "verification.json";
pub const B1OAPR_MANIFEST_FILE: &str = "evidence_manifest.json";

const MANIFEST_DOMAIN: &str = "cantor.b1.operator-authority-packet-readiness.evidence-manifest.v1";
const EVIDENCE_DOMAIN: &str = "cantor.b1.operator-authority-packet-readiness.evidence.v1";
const MAX_JSON_DEPTH: usize = 24;
const MAX_JSON_FIELDS: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1OaprEvidenceArtifact {
    pub path: String,
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1OaprEvidenceManifest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub formation_commit: String,
    pub artifacts: Vec<B1OaprEvidenceArtifact>,
    pub fixture_only: bool,
    pub candidate_material_authenticated: bool,
    pub authority_admitted: bool,
    pub physical_execution_authorized: bool,
    pub non_authority_statement: String,
    pub manifest_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1OaprEvidenceVerification {
    pub profile: String,
    pub status: String,
    pub authority: String,
    pub request_sha256: ContentDigest,
    pub packet_sha256: ContentDigest,
    pub verification_sha256: ContentDigest,
    pub manifest_sha256: ContentDigest,
    pub artifact_count: u8,
    pub descriptor_count: u8,
    pub independent_replay_count: u8,
    pub byte_identical_replays: bool,
    pub fixture_only: bool,
    pub candidate_material_authenticated: bool,
    pub authority_admitted: bool,
    pub physical_execution_authorized: bool,
    pub effect_account: B1OaprEffectAccount,
    pub non_authority_statement: String,
    pub evidence_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B1OaprEvidenceFault {
    pub message: String,
}

impl fmt::Display for B1OaprEvidenceFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for B1OaprEvidenceFault {}

pub fn verify_b1oapr_evidence_directory(
    root: &Path,
) -> Result<B1OaprEvidenceVerification, B1OaprEvidenceFault> {
    let metadata = fs::symlink_metadata(root).map_err(evidence_fault)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(evidence_fault("evidence root must be a nonlink directory"));
    }
    let expected = BTreeSet::from([
        B1OAPR_MANIFEST_FILE.to_owned(),
        B1OAPR_PACKET_FILE.to_owned(),
        B1OAPR_REQUEST_FILE.to_owned(),
        B1OAPR_VERIFICATION_FILE.to_owned(),
    ]);
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(root).map_err(evidence_fault)? {
        let entry = entry.map_err(evidence_fault)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| evidence_fault("evidence filename is not UTF-8"))?;
        let file_type = entry.file_type().map_err(evidence_fault)?;
        if !file_type.is_file() || file_type.is_symlink() || !actual.insert(name) {
            return Err(evidence_fault(
                "evidence member is not one unique regular nonlink file",
            ));
        }
    }
    if actual != expected {
        return Err(evidence_fault("evidence directory membership differs"));
    }

    let request_bytes = read_bounded_file(&root.join(B1OAPR_REQUEST_FILE))?;
    let packet_bytes = read_bounded_file(&root.join(B1OAPR_PACKET_FILE))?;
    let verification_bytes = read_bounded_file(&root.join(B1OAPR_VERIFICATION_FILE))?;
    let manifest_bytes = read_bounded_file(&root.join(B1OAPR_MANIFEST_FILE))?;
    let request_text = std::str::from_utf8(&request_bytes).map_err(evidence_fault)?;
    let packet_text = std::str::from_utf8(&packet_bytes).map_err(evidence_fault)?;
    let verification_text = std::str::from_utf8(&verification_bytes).map_err(evidence_fault)?;
    let manifest_text = std::str::from_utf8(&manifest_bytes).map_err(evidence_fault)?;

    let request = from_b1oapr_request_machine_form(request_text).map_err(evidence_fault)?;
    let packet = from_b1oapr_packet_machine_form(&request, packet_text).map_err(evidence_fault)?;
    let verification = from_b1oapr_verification_machine_form(&request, &packet, verification_text)
        .map_err(evidence_fault)?;
    let manifest: B1OaprEvidenceManifest = from_evidence_form(manifest_text)?;
    validate_b1oapr_evidence_manifest(&manifest)?;
    validate_artifacts(
        &manifest,
        &request_bytes,
        &packet_bytes,
        &verification_bytes,
    )?;

    let first_packet = compile_b1oapr_packet(&request).map_err(evidence_fault)?;
    let second_packet = compile_b1oapr_packet(&request).map_err(evidence_fault)?;
    let first_verification =
        verify_b1oapr_packet(&request, &first_packet).map_err(evidence_fault)?;
    let second_verification =
        verify_b1oapr_packet(&request, &second_packet).map_err(evidence_fault)?;
    if first_packet != packet
        || second_packet != packet
        || first_verification != verification
        || second_verification != verification
        || to_b1oapr_packet_machine_form(&request, &first_packet)
            .map_err(evidence_fault)?
            .as_bytes()
            != packet_bytes
        || to_b1oapr_verification_machine_form(&request, &first_packet, &first_verification)
            .map_err(evidence_fault)?
            .as_bytes()
            != verification_bytes
    {
        return Err(evidence_fault("independent evidence replay differs"));
    }
    compile_b1oapr_evidence_verification(&request, &packet, &verification, &manifest)
}

pub fn compile_b1oapr_evidence_verification(
    request: &B1OaprRequest,
    packet: &B1OaprPacket,
    verification: &B1OaprVerification,
    manifest: &B1OaprEvidenceManifest,
) -> Result<B1OaprEvidenceVerification, B1OaprEvidenceFault> {
    validate_b1oapr_verification(request, packet, verification).map_err(evidence_fault)?;
    validate_b1oapr_evidence_manifest(manifest)?;
    let mut evidence = B1OaprEvidenceVerification {
        profile: B1OAPR_EVIDENCE_PROFILE.to_owned(),
        status: B1OAPR_STATUS.to_owned(),
        authority: B1OAPR_AUTHORITY.to_owned(),
        request_sha256: request.request_sha256.clone(),
        packet_sha256: packet.packet_sha256.clone(),
        verification_sha256: verification.verification_sha256.clone(),
        manifest_sha256: manifest.manifest_sha256.clone(),
        artifact_count: 3,
        descriptor_count: 9,
        independent_replay_count: 2,
        byte_identical_replays: true,
        fixture_only: manifest.fixture_only,
        candidate_material_authenticated: false,
        authority_admitted: false,
        physical_execution_authorized: false,
        effect_account: B1OaprEffectAccount::default(),
        non_authority_statement: B1OAPR_NON_AUTHORITY.to_owned(),
        evidence_sha256: empty_digest(),
    };
    evidence.evidence_sha256 = b1oapr_evidence_digest(&evidence)?;
    validate_b1oapr_evidence_verification(&evidence)?;
    Ok(evidence)
}

pub fn validate_b1oapr_evidence_manifest(
    manifest: &B1OaprEvidenceManifest,
) -> Result<(), B1OaprEvidenceFault> {
    if manifest.profile != B1OAPR_EVIDENCE_MANIFEST_PROFILE
        || manifest.source_snapshot_uuid != B1OAPR_SOURCE_SNAPSHOT_UUID
        || manifest.canonical_uuid != B1OAPR_CANONICAL_UUID
        || manifest.signature_uuid != B1OAPR_SIGNATURE_UUID
        || manifest.formation_commit != B1OAPR_FORMATION_COMMIT
        || manifest.artifacts.len() != 3
        || !manifest.fixture_only
        || manifest.candidate_material_authenticated
        || manifest.authority_admitted
        || manifest.physical_execution_authorized
        || manifest.non_authority_statement != B1OAPR_NON_AUTHORITY
    {
        return Err(evidence_fault(
            "evidence manifest identity or nonauthority differs",
        ));
    }
    let paths: Vec<&str> = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect();
    if paths
        != [
            B1OAPR_PACKET_FILE,
            B1OAPR_REQUEST_FILE,
            B1OAPR_VERIFICATION_FILE,
        ]
        || manifest
            .artifacts
            .iter()
            .any(|artifact| artifact.bytes == 0 || !valid_digest(&artifact.sha256))
    {
        return Err(evidence_fault("evidence artifact table differs"));
    }
    if manifest.manifest_sha256 != b1oapr_evidence_manifest_digest(manifest)? {
        return Err(evidence_fault("evidence manifest digest differs"));
    }
    Ok(())
}

pub fn validate_b1oapr_evidence_verification(
    evidence: &B1OaprEvidenceVerification,
) -> Result<(), B1OaprEvidenceFault> {
    if evidence.profile != B1OAPR_EVIDENCE_PROFILE
        || evidence.status != B1OAPR_STATUS
        || evidence.authority != B1OAPR_AUTHORITY
        || evidence.artifact_count != 3
        || evidence.descriptor_count != 9
        || evidence.independent_replay_count != 2
        || !evidence.byte_identical_replays
        || !evidence.fixture_only
        || evidence.candidate_material_authenticated
        || evidence.authority_admitted
        || evidence.physical_execution_authorized
        || evidence.effect_account != B1OaprEffectAccount::default()
        || evidence.non_authority_statement != B1OAPR_NON_AUTHORITY
    {
        return Err(evidence_fault("evidence verification account differs"));
    }
    if evidence.evidence_sha256 != b1oapr_evidence_digest(evidence)? {
        return Err(evidence_fault("evidence verification digest differs"));
    }
    Ok(())
}

pub fn b1oapr_evidence_manifest_digest(
    manifest: &B1OaprEvidenceManifest,
) -> Result<ContentDigest, B1OaprEvidenceFault> {
    let mut unsigned = manifest.clone();
    unsigned.manifest_sha256 = empty_digest();
    domain_digest(MANIFEST_DOMAIN, &unsigned)
}

pub fn b1oapr_evidence_digest(
    evidence: &B1OaprEvidenceVerification,
) -> Result<ContentDigest, B1OaprEvidenceFault> {
    let mut unsigned = evidence.clone();
    unsigned.evidence_sha256 = empty_digest();
    domain_digest(EVIDENCE_DOMAIN, &unsigned)
}

pub fn to_b1oapr_evidence_manifest_machine_form(
    manifest: &B1OaprEvidenceManifest,
) -> Result<String, B1OaprEvidenceFault> {
    validate_b1oapr_evidence_manifest(manifest)?;
    to_evidence_form(manifest)
}

pub fn to_b1oapr_evidence_verification_machine_form(
    evidence: &B1OaprEvidenceVerification,
) -> Result<String, B1OaprEvidenceFault> {
    validate_b1oapr_evidence_verification(evidence)?;
    to_evidence_form(evidence)
}

fn validate_artifacts(
    manifest: &B1OaprEvidenceManifest,
    request: &[u8],
    packet: &[u8],
    verification: &[u8],
) -> Result<(), B1OaprEvidenceFault> {
    let actual = [
        (B1OAPR_PACKET_FILE, packet),
        (B1OAPR_REQUEST_FILE, request),
        (B1OAPR_VERIFICATION_FILE, verification),
    ];
    for (artifact, (path, bytes)) in manifest.artifacts.iter().zip(actual) {
        if artifact.path != path
            || artifact.bytes != bytes.len() as u64
            || artifact.sha256 != sha256_bytes(bytes)
        {
            return Err(evidence_fault("evidence artifact bytes or digest differ"));
        }
    }
    Ok(())
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, B1OaprEvidenceFault> {
    let metadata = fs::symlink_metadata(path).map_err(evidence_fault)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > B1OAPR_MAX_FORM_BYTES as u64
    {
        return Err(evidence_fault("evidence file kind or byte bound differs"));
    }
    fs::read(path).map_err(evidence_fault)
}

fn to_evidence_form<T: Serialize>(value: &T) -> Result<String, B1OaprEvidenceFault> {
    let text = serde_json::to_string(value).map_err(evidence_fault)?;
    if text.len() > B1OAPR_MAX_FORM_BYTES {
        return Err(evidence_fault("evidence form exceeds byte bound"));
    }
    Ok(text)
}

fn from_evidence_form<T: DeserializeOwned + Serialize>(
    text: &str,
) -> Result<T, B1OaprEvidenceFault> {
    if text.is_empty() || text.len() > B1OAPR_MAX_FORM_BYTES {
        return Err(evidence_fault("evidence form byte bound differs"));
    }
    let value: Value = serde_json::from_str(text).map_err(evidence_fault)?;
    let mut fields = 0_usize;
    measure_value(&value, 1, &mut fields)?;
    let parsed: T = serde_json::from_str(text).map_err(evidence_fault)?;
    if serde_json::to_string(&parsed).map_err(evidence_fault)? != text {
        return Err(evidence_fault(
            "evidence form is not canonical duplicate-free JSON",
        ));
    }
    Ok(parsed)
}

fn measure_value(
    value: &Value,
    depth: usize,
    fields: &mut usize,
) -> Result<(), B1OaprEvidenceFault> {
    if depth > MAX_JSON_DEPTH {
        return Err(evidence_fault("evidence JSON depth exceeds bound"));
    }
    match value {
        Value::Object(map) => {
            *fields = fields
                .checked_add(map.len())
                .ok_or_else(|| evidence_fault("evidence JSON field count overflow"))?;
            if *fields > MAX_JSON_FIELDS {
                return Err(evidence_fault("evidence JSON field count exceeds bound"));
            }
            for child in map.values() {
                measure_value(child, depth + 1, fields)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                measure_value(child, depth + 1, fields)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn valid_digest(digest: &ContentDigest) -> bool {
    digest.algorithm == "sha256"
        && digest.value.len() == 64
        && digest
            .value
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
}

fn domain_digest<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<ContentDigest, B1OaprEvidenceFault> {
    let payload = serde_json::to_vec(value).map_err(evidence_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + payload.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&payload);
    Ok(sha256_bytes(&bytes))
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

fn evidence_fault(error: impl fmt::Display) -> B1OaprEvidenceFault {
    B1OaprEvidenceFault {
        message: error.to_string(),
    }
}
