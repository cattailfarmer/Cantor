//! Independent retained-evidence replay for the bounded A3 verifier.

use std::{collections::BTreeMap, fmt, fs, path::Path};

use cantor_core::{ContentDigest, sha256_bytes};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    B1OaprPacket, B1OaprRequest, B1OaprVerification, BpvPolicyEnvelope, BpvVerificationReceipt,
    BpvVerificationRequest, KRV_EVIDENCE_PROFILE, KRV_MAX_EVIDENCE_BYTES, KRV_MAX_FORM_BYTES,
    KcvCustodyAttestation, KcvVerificationReceipt, KcvVerificationRequest, KrvFault, KrvFaultCode,
    KrvRevocationSnapshot, KrvVerificationReceipt, KrvVerificationRequest,
    from_krv_receipt_machine_form, from_krv_request_machine_form, from_krv_snapshot_machine_form,
    to_krv_receipt_machine_form, verify_krv_revocation_snapshot,
};

pub const KRV_PREDECESSOR_REQUEST_FILE: &str = "predecessor_request.json";
pub const KRV_PREDECESSOR_PACKET_FILE: &str = "predecessor_packet.json";
pub const KRV_PREDECESSOR_VERIFICATION_FILE: &str = "predecessor_verification.json";
pub const KRV_A1_POLICY_ENVELOPE_FILE: &str = "a1_policy_envelope.json";
pub const KRV_A1_VERIFICATION_REQUEST_FILE: &str = "a1_verification_request.json";
pub const KRV_A1_RECEIPT_FILE: &str = "a1_receipt.json";
pub const KRV_CUSTODY_ATTESTATION_FILE: &str = "custody_attestation.json";
pub const KRV_A2_VERIFICATION_REQUEST_FILE: &str = "a2_verification_request.json";
pub const KRV_A2_RECEIPT_FILE: &str = "a2_receipt.json";
pub const KRV_REVOCATION_SNAPSHOT_FILE: &str = "revocation_snapshot.json";
pub const KRV_VERIFICATION_REQUEST_FILE: &str = "verification_request.json";
pub const KRV_RECEIPT_FILE: &str = "receipt.json";
pub const KRV_EVIDENCE_MANIFEST_FILE: &str = "evidence_manifest.json";

const MANIFEST_DOMAIN: &str = "cantor.b1.revocation-snapshot.evidence-manifest.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KrvEvidenceArtifact {
    pub path: String,
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KrvEvidenceManifest {
    pub profile: String,
    pub manifest_uuid: String,
    pub fixture_only: bool,
    pub artifacts: Vec<KrvEvidenceArtifact>,
    pub artifact_count: u8,
    pub total_artifact_bytes: u64,
    pub retained_authority_packet_sha256: ContentDigest,
    pub retained_a1_receipt_sha256: ContentDigest,
    pub retained_a2_receipt_sha256: ContentDigest,
    pub retained_receipt_sha256: ContentDigest,
    pub deterministic_replay_count: u8,
    pub required_fresh_process_replay_count: u8,
    pub byte_identical: bool,
    pub effect_count: u32,
    pub manifest_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KrvEvidenceReplay {
    pub manifest: KrvEvidenceManifest,
    pub receipt: KrvVerificationReceipt,
    pub receipt_machine_form: String,
    pub artifact_count: u8,
    pub total_artifact_bytes: u64,
    pub deterministic_replay_count: u8,
    pub required_fresh_process_replay_count: u8,
    pub byte_identical: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KrvEvidenceFault {
    pub code: KrvFaultCode,
    pub message: String,
}

impl fmt::Display for KrvEvidenceFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for KrvEvidenceFault {}

pub fn verify_krv_evidence_directory(root: &Path) -> Result<KrvEvidenceReplay, KrvEvidenceFault> {
    let root_metadata = fs::symlink_metadata(root).map_err(evidence_fault)?;
    if !root_metadata.is_dir()
        || root_metadata.file_type().is_symlink()
        || is_reparse_point(&root_metadata)
    {
        return Err(coded_fault(
            KrvFaultCode::Path,
            "evidence root is not a direct regular directory",
        ));
    }
    let expected = expected_krv_evidence_files();
    let mut entries = Vec::new();
    for entry in fs::read_dir(root).map_err(evidence_fault)? {
        let entry = entry.map_err(evidence_fault)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| coded_fault(KrvFaultCode::Path, "evidence filename is not Unicode"))?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(evidence_fault)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(coded_fault(
                KrvFaultCode::Path,
                format_args!("evidence entry is not a regular nonlink file: {name}"),
            ));
        }
        entries.push(name);
    }
    entries.sort();
    let mut expected_sorted = expected.clone();
    expected_sorted.sort();
    if entries != expected_sorted {
        return Err(coded_fault(
            KrvFaultCode::Evidence,
            "evidence filename set differs",
        ));
    }
    let mut files = BTreeMap::new();
    let mut directory_total = 0_u64;
    for name in &expected {
        let bytes = read_bounded_file(&root.join(name))?;
        directory_total = directory_total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| coded_fault(KrvFaultCode::Arithmetic, "evidence total overflow"))?;
        if directory_total > KRV_MAX_EVIDENCE_BYTES {
            return Err(coded_fault(
                KrvFaultCode::Size,
                "evidence directory exceeds bound",
            ));
        }
        files.insert(name.clone(), bytes);
    }

    let manifest: KrvEvidenceManifest =
        parse_retained(required(&files, KRV_EVIDENCE_MANIFEST_FILE)?)?;
    validate_krv_evidence_manifest(&manifest, &files)?;
    let predecessor_request: B1OaprRequest =
        parse_retained(required(&files, KRV_PREDECESSOR_REQUEST_FILE)?)?;
    let predecessor_packet: B1OaprPacket =
        parse_retained(required(&files, KRV_PREDECESSOR_PACKET_FILE)?)?;
    let predecessor_verification: B1OaprVerification =
        parse_retained(required(&files, KRV_PREDECESSOR_VERIFICATION_FILE)?)?;
    let a1_envelope: BpvPolicyEnvelope =
        parse_retained(required(&files, KRV_A1_POLICY_ENVELOPE_FILE)?)?;
    let a1_request: BpvVerificationRequest =
        parse_retained(required(&files, KRV_A1_VERIFICATION_REQUEST_FILE)?)?;
    let a1_receipt: BpvVerificationReceipt =
        parse_retained(required(&files, KRV_A1_RECEIPT_FILE)?)?;
    let a2_attestation: KcvCustodyAttestation =
        parse_retained(required(&files, KRV_CUSTODY_ATTESTATION_FILE)?)?;
    let a2_request: KcvVerificationRequest =
        parse_retained(required(&files, KRV_A2_VERIFICATION_REQUEST_FILE)?)?;
    let a2_receipt: KcvVerificationReceipt =
        parse_retained(required(&files, KRV_A2_RECEIPT_FILE)?)?;
    let raw_snapshot = retained_text(required(&files, KRV_REVOCATION_SNAPSHOT_FILE)?)?;
    let snapshot: KrvRevocationSnapshot =
        from_krv_snapshot_machine_form(raw_snapshot).map_err(krv_fault)?;
    let request: KrvVerificationRequest = from_krv_request_machine_form(retained_text(required(
        &files,
        KRV_VERIFICATION_REQUEST_FILE,
    )?)?)
    .map_err(krv_fault)?;
    let raw_a1 = retained_bytes(required(&files, KRV_A1_POLICY_ENVELOPE_FILE)?)?;
    let raw_a2 = retained_bytes(required(&files, KRV_CUSTODY_ATTESTATION_FILE)?)?;
    let first = verify_krv_revocation_snapshot(
        &request,
        &predecessor_request,
        &predecessor_packet,
        &predecessor_verification,
        &a1_envelope,
        raw_a1,
        &a1_request,
        &a1_receipt,
        &a2_attestation,
        raw_a2,
        &a2_request,
        &a2_receipt,
        raw_snapshot.as_bytes(),
    )
    .map_err(krv_fault)?;
    let second = verify_krv_revocation_snapshot(
        &request,
        &predecessor_request,
        &predecessor_packet,
        &predecessor_verification,
        &a1_envelope,
        raw_a1,
        &a1_request,
        &a1_receipt,
        &a2_attestation,
        raw_a2,
        &a2_request,
        &a2_receipt,
        raw_snapshot.as_bytes(),
    )
    .map_err(krv_fault)?;
    let retained_receipt = from_krv_receipt_machine_form(
        &request,
        &snapshot,
        retained_text(required(&files, KRV_RECEIPT_FILE)?)?,
    )
    .map_err(krv_fault)?;
    let first_text = to_krv_receipt_machine_form(&request, &snapshot, &first).map_err(krv_fault)?;
    let second_text =
        to_krv_receipt_machine_form(&request, &snapshot, &second).map_err(krv_fault)?;
    if first != second
        || first != retained_receipt
        || first_text != second_text
        || first_text != retained_text(required(&files, KRV_RECEIPT_FILE)?)?
        || manifest.retained_authority_packet_sha256 != first.authority_packet_sha256
        || manifest.retained_a1_receipt_sha256 != first.a1_receipt_sha256
        || manifest.retained_a2_receipt_sha256 != first.a2_receipt_sha256
        || manifest.retained_receipt_sha256 != first.receipt_sha256
    {
        return Err(coded_fault(
            KrvFaultCode::Restart,
            "independent retained replay differs",
        ));
    }
    let artifact_total = manifest.total_artifact_bytes;
    Ok(KrvEvidenceReplay {
        manifest,
        receipt: first,
        receipt_machine_form: first_text,
        artifact_count: 12,
        total_artifact_bytes: artifact_total,
        deterministic_replay_count: 2,
        required_fresh_process_replay_count: 2,
        byte_identical: true,
    })
}

pub fn validate_krv_evidence_manifest(
    manifest: &KrvEvidenceManifest,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), KrvEvidenceFault> {
    let expected = expected_krv_artifact_files();
    if manifest.profile != KRV_EVIDENCE_PROFILE
        || !valid_uuid(&manifest.manifest_uuid)
        || manifest.artifact_count != 12
        || manifest.artifacts.len() != 12
        || manifest.deterministic_replay_count != 2
        || manifest.required_fresh_process_replay_count != 2
        || !manifest.byte_identical
        || manifest.effect_count != 0
    {
        return Err(coded_fault(
            KrvFaultCode::Evidence,
            "manifest identity or account differs",
        ));
    }
    let paths: Vec<_> = manifest
        .artifacts
        .iter()
        .map(|item| item.path.clone())
        .collect();
    if paths != expected {
        return Err(coded_fault(
            KrvFaultCode::Evidence,
            "manifest artifact sequence differs",
        ));
    }
    let mut total = 0_u64;
    for artifact in &manifest.artifacts {
        let bytes = required(files, &artifact.path)?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| coded_fault(KrvFaultCode::Arithmetic, "manifest total overflow"))?;
        if artifact.bytes != bytes.len() as u64 || artifact.sha256 != sha256_bytes(bytes) {
            return Err(coded_fault(
                KrvFaultCode::Evidence,
                format_args!("artifact binding differs: {}", artifact.path),
            ));
        }
    }
    if total != manifest.total_artifact_bytes
        || manifest.manifest_sha256 != krv_evidence_manifest_digest(manifest)?
    {
        return Err(coded_fault(
            KrvFaultCode::Digest,
            "manifest digest or total differs",
        ));
    }
    Ok(())
}

pub fn krv_evidence_manifest_digest(
    manifest: &KrvEvidenceManifest,
) -> Result<ContentDigest, KrvEvidenceFault> {
    let mut normalized = manifest.clone();
    normalized.manifest_sha256 = empty_digest();
    let canonical = serde_json::to_vec(&normalized).map_err(evidence_fault)?;
    let mut bytes = Vec::with_capacity(MANIFEST_DOMAIN.len() + 1 + canonical.len());
    bytes.extend_from_slice(MANIFEST_DOMAIN.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(sha256_bytes(&bytes))
}

pub fn to_krv_evidence_manifest_machine_form(
    manifest: &KrvEvidenceManifest,
) -> Result<String, KrvEvidenceFault> {
    if manifest.manifest_sha256 != krv_evidence_manifest_digest(manifest)? {
        return Err(coded_fault(KrvFaultCode::Digest, "manifest digest differs"));
    }
    serde_json::to_string(manifest).map_err(evidence_fault)
}

pub fn expected_krv_artifact_files() -> Vec<String> {
    [
        KRV_PREDECESSOR_REQUEST_FILE,
        KRV_PREDECESSOR_PACKET_FILE,
        KRV_PREDECESSOR_VERIFICATION_FILE,
        KRV_A1_POLICY_ENVELOPE_FILE,
        KRV_A1_VERIFICATION_REQUEST_FILE,
        KRV_A1_RECEIPT_FILE,
        KRV_CUSTODY_ATTESTATION_FILE,
        KRV_A2_VERIFICATION_REQUEST_FILE,
        KRV_A2_RECEIPT_FILE,
        KRV_REVOCATION_SNAPSHOT_FILE,
        KRV_VERIFICATION_REQUEST_FILE,
        KRV_RECEIPT_FILE,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

pub fn expected_krv_evidence_files() -> Vec<String> {
    let mut files = expected_krv_artifact_files();
    files.push(KRV_EVIDENCE_MANIFEST_FILE.to_owned());
    files
}

fn required<'a>(
    files: &'a BTreeMap<String, Vec<u8>>,
    name: &str,
) -> Result<&'a Vec<u8>, KrvEvidenceFault> {
    files.get(name).ok_or_else(|| {
        coded_fault(
            KrvFaultCode::Evidence,
            format_args!("required evidence absent: {name}"),
        )
    })
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, KrvEvidenceFault> {
    let metadata = fs::symlink_metadata(path).map_err(evidence_fault)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || is_reparse_point(&metadata)
        || metadata.len() == 0
        || metadata.len() > KRV_MAX_FORM_BYTES as u64
    {
        return Err(coded_fault(
            KrvFaultCode::Path,
            "evidence file type or size differs",
        ));
    }
    fs::read(path).map_err(evidence_fault)
}

fn retained_bytes(bytes: &[u8]) -> Result<&[u8], KrvEvidenceFault> {
    if bytes.last() != Some(&b'\n')
        || bytes[..bytes.len() - 1].contains(&b'\n')
        || bytes.contains(&b'\r')
    {
        return Err(coded_fault(
            KrvFaultCode::MachineForm,
            "retained LF framing differs",
        ));
    }
    Ok(&bytes[..bytes.len() - 1])
}

fn retained_text(bytes: &[u8]) -> Result<&str, KrvEvidenceFault> {
    std::str::from_utf8(retained_bytes(bytes)?)
        .map_err(|_| coded_fault(KrvFaultCode::MachineForm, "evidence is not UTF-8"))
}

fn parse_retained<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, KrvEvidenceFault> {
    let text = retained_text(bytes)?;
    let value: T = serde_json::from_str(text).map_err(evidence_fault)?;
    if serde_json::to_string(&value).map_err(evidence_fault)? != text {
        return Err(coded_fault(
            KrvFaultCode::MachineForm,
            "retained form is not compact canonical JSON",
        ));
    }
    Ok(value)
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.as_bytes().iter().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn empty_digest() -> ContentDigest {
    sha256_bytes(b"")
}
fn evidence_fault(error: impl fmt::Display) -> KrvEvidenceFault {
    coded_fault(KrvFaultCode::Evidence, error)
}
fn krv_fault(error: KrvFault) -> KrvEvidenceFault {
    coded_fault(error.code, error)
}
fn coded_fault(code: KrvFaultCode, message: impl fmt::Display) -> KrvEvidenceFault {
    KrvEvidenceFault {
        code,
        message: message.to_string(),
    }
}
