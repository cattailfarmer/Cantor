//! Independent ten-file retained-evidence replay for the B1 A2 verifier.

use std::{collections::BTreeMap, fmt, fs, path::Path};

use cantor_core::{ContentDigest, sha256_bytes};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    KCV_MAX_EVIDENCE_BYTES, KCV_MAX_FORM_BYTES, KcvCustodyAttestation, KcvFaultCode,
    KcvVerificationReceipt, KcvVerificationRequest, from_b1oapr_packet_machine_form,
    from_b1oapr_request_machine_form, from_b1oapr_verification_machine_form,
    from_bpv_envelope_machine_form, from_bpv_receipt_machine_form, from_bpv_request_machine_form,
    from_kcv_attestation_machine_form, from_kcv_receipt_machine_form,
    from_kcv_request_machine_form, to_kcv_receipt_machine_form, verify_kcv_custody_attestation,
};

pub const KCV_EVIDENCE_PROFILE: &str =
    "cantor-b1-public-verifying-key-custody-verification-evidence/0.1";
pub const KCV_PREDECESSOR_REQUEST_FILE: &str = "predecessor_request.json";
pub const KCV_PREDECESSOR_PACKET_FILE: &str = "predecessor_packet.json";
pub const KCV_PREDECESSOR_VERIFICATION_FILE: &str = "predecessor_verification.json";
pub const KCV_A1_POLICY_ENVELOPE_FILE: &str = "a1_policy_envelope.json";
pub const KCV_A1_VERIFICATION_REQUEST_FILE: &str = "a1_verification_request.json";
pub const KCV_A1_RECEIPT_FILE: &str = "a1_receipt.json";
pub const KCV_CUSTODY_ATTESTATION_FILE: &str = "custody_attestation.json";
pub const KCV_VERIFICATION_REQUEST_FILE: &str = "verification_request.json";
pub const KCV_RECEIPT_FILE: &str = "receipt.json";
pub const KCV_EVIDENCE_MANIFEST_FILE: &str = "evidence_manifest.json";

const MANIFEST_DOMAIN: &str = "cantor.b1.key-custody-proof.evidence-manifest.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KcvEvidenceArtifact {
    pub path: String,
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KcvEvidenceManifest {
    pub profile: String,
    pub manifest_uuid: String,
    pub fixture_only: bool,
    pub artifacts: Vec<KcvEvidenceArtifact>,
    pub artifact_count: u8,
    pub total_artifact_bytes: u64,
    pub retained_authority_packet_sha256: ContentDigest,
    pub retained_a1_receipt_sha256: ContentDigest,
    pub retained_receipt_sha256: ContentDigest,
    pub deterministic_replay_count: u8,
    pub required_fresh_process_replay_count: u8,
    pub byte_identical: bool,
    pub effect_count: u32,
    pub manifest_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KcvEvidenceReplay {
    pub manifest_uuid: String,
    pub artifact_count: u8,
    pub total_artifact_bytes: u64,
    pub deterministic_replay_count: u8,
    pub required_fresh_process_replay_count: u8,
    pub byte_identical: bool,
    pub receipt: KcvVerificationReceipt,
    pub receipt_machine_form: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KcvEvidenceFault {
    pub code: KcvFaultCode,
    pub message: String,
}

impl fmt::Display for KcvEvidenceFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for KcvEvidenceFault {}

pub fn verify_kcv_evidence_directory(root: &Path) -> Result<KcvEvidenceReplay, KcvEvidenceFault> {
    let root_metadata = fs::symlink_metadata(root).map_err(evidence_fault)?;
    if !root_metadata.file_type().is_dir()
        || root_metadata.file_type().is_symlink()
        || is_reparse_point(&root_metadata)
    {
        return Err(coded_evidence_fault(
            KcvFaultCode::Path,
            "evidence root is not a direct regular nonlink directory",
        ));
    }
    let expected_files = expected_kcv_evidence_files();
    let mut observed_names = Vec::new();
    for entry in fs::read_dir(root).map_err(evidence_fault)? {
        let entry = entry.map_err(evidence_fault)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| evidence_fault("non-UTF-8 evidence filename refused"))?;
        let file_type = entry.file_type().map_err(evidence_fault)?;
        let metadata = entry.metadata().map_err(evidence_fault)?;
        if !file_type.is_file() || file_type.is_symlink() || is_reparse_point(&metadata) {
            return Err(coded_evidence_fault(
                KcvFaultCode::Path,
                format!("evidence entry is not a direct regular nonlink file: {name}"),
            ));
        }
        observed_names.push(name);
    }
    observed_names.sort();
    let mut sorted_expected = expected_files.clone();
    sorted_expected.sort();
    if observed_names != sorted_expected {
        return Err(coded_evidence_fault(
            KcvFaultCode::Path,
            "evidence directory membership differs",
        ));
    }

    let mut raw = BTreeMap::new();
    let mut directory_bytes = 0_u64;
    for name in &expected_files {
        let bytes = read_bounded_file(&root.join(name))?;
        directory_bytes = directory_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| {
                coded_evidence_fault(
                    KcvFaultCode::Arithmetic,
                    "evidence directory byte count overflow",
                )
            })?;
        if directory_bytes > KCV_MAX_EVIDENCE_BYTES {
            return Err(coded_evidence_fault(
                KcvFaultCode::Size,
                "evidence directory exceeds byte bound",
            ));
        }
        raw.insert(name.clone(), bytes);
    }

    let manifest: KcvEvidenceManifest =
        parse_canonical(retained_text(required(&raw, KCV_EVIDENCE_MANIFEST_FILE)?)?)?;
    validate_kcv_evidence_manifest(&manifest, &raw)?;

    let predecessor_request = from_b1oapr_request_machine_form(retained_text(required(
        &raw,
        KCV_PREDECESSOR_REQUEST_FILE,
    )?)?)
    .map_err(evidence_fault)?;
    let predecessor_packet = from_b1oapr_packet_machine_form(
        &predecessor_request,
        retained_text(required(&raw, KCV_PREDECESSOR_PACKET_FILE)?)?,
    )
    .map_err(evidence_fault)?;
    let predecessor_verification = from_b1oapr_verification_machine_form(
        &predecessor_request,
        &predecessor_packet,
        retained_text(required(&raw, KCV_PREDECESSOR_VERIFICATION_FILE)?)?,
    )
    .map_err(evidence_fault)?;
    let raw_a1_envelope = retained_text(required(&raw, KCV_A1_POLICY_ENVELOPE_FILE)?)?.as_bytes();
    let a1_envelope = from_bpv_envelope_machine_form(
        std::str::from_utf8(raw_a1_envelope).map_err(evidence_fault)?,
    )
    .map_err(evidence_fault)?;
    let a1_request = from_bpv_request_machine_form(retained_text(required(
        &raw,
        KCV_A1_VERIFICATION_REQUEST_FILE,
    )?)?)
    .map_err(evidence_fault)?;
    let a1_receipt = from_bpv_receipt_machine_form(
        &a1_request,
        &a1_envelope,
        retained_text(required(&raw, KCV_A1_RECEIPT_FILE)?)?,
    )
    .map_err(evidence_fault)?;
    let raw_attestation = retained_text(required(&raw, KCV_CUSTODY_ATTESTATION_FILE)?)?.as_bytes();
    let attestation: KcvCustodyAttestation = from_kcv_attestation_machine_form(
        std::str::from_utf8(raw_attestation).map_err(evidence_fault)?,
    )
    .map_err(evidence_fault)?;
    let request: KcvVerificationRequest = from_kcv_request_machine_form(retained_text(required(
        &raw,
        KCV_VERIFICATION_REQUEST_FILE,
    )?)?)
    .map_err(evidence_fault)?;

    let first = verify_kcv_custody_attestation(
        &request,
        &predecessor_request,
        &predecessor_packet,
        &predecessor_verification,
        &a1_envelope,
        raw_a1_envelope,
        &a1_request,
        &a1_receipt,
        raw_attestation,
    )
    .map_err(evidence_fault)?;
    let second = verify_kcv_custody_attestation(
        &request,
        &predecessor_request,
        &predecessor_packet,
        &predecessor_verification,
        &a1_envelope,
        raw_a1_envelope,
        &a1_request,
        &a1_receipt,
        raw_attestation,
    )
    .map_err(evidence_fault)?;
    let first_text =
        to_kcv_receipt_machine_form(&request, &attestation, &first).map_err(evidence_fault)?;
    let second_text =
        to_kcv_receipt_machine_form(&request, &attestation, &second).map_err(evidence_fault)?;
    let retained_receipt = from_kcv_receipt_machine_form(
        &request,
        &attestation,
        retained_text(required(&raw, KCV_RECEIPT_FILE)?)?,
    )
    .map_err(evidence_fault)?;
    if first != second
        || first != retained_receipt
        || first_text != second_text
        || first_text.as_bytes() != retained_text(required(&raw, KCV_RECEIPT_FILE)?)?.as_bytes()
        || manifest.retained_authority_packet_sha256 != first.authority_packet_sha256
        || manifest.retained_a1_receipt_sha256 != first.a1_receipt_sha256
        || manifest.retained_receipt_sha256 != first.receipt_sha256
        || manifest.fixture_only != first.fixture_only
    {
        return Err(coded_evidence_fault(
            KcvFaultCode::Restart,
            "retained packet, A1 receipt, A2 receipt, replay, or fixture correspondence differs",
        ));
    }
    Ok(KcvEvidenceReplay {
        manifest_uuid: manifest.manifest_uuid,
        artifact_count: manifest.artifact_count,
        total_artifact_bytes: manifest.total_artifact_bytes,
        deterministic_replay_count: 2,
        required_fresh_process_replay_count: manifest.required_fresh_process_replay_count,
        byte_identical: true,
        receipt: first,
        receipt_machine_form: first_text,
    })
}

pub fn validate_kcv_evidence_manifest(
    manifest: &KcvEvidenceManifest,
    raw: &BTreeMap<String, Vec<u8>>,
) -> Result<(), KcvEvidenceFault> {
    let expected_names = expected_kcv_artifact_files();
    if manifest.profile != KCV_EVIDENCE_PROFILE
        || !valid_uuid(&manifest.manifest_uuid)
        || manifest.artifact_count != 9
        || manifest.artifacts.len() != 9
        || manifest.deterministic_replay_count != 2
        || manifest.required_fresh_process_replay_count != 2
        || !manifest.byte_identical
        || manifest.effect_count != 0
    {
        return Err(evidence_fault(
            "evidence manifest identity or account differs",
        ));
    }
    let mut total = 0_u64;
    for (artifact, expected_name) in manifest.artifacts.iter().zip(expected_names.iter()) {
        let bytes = required(raw, expected_name)?;
        let byte_count = u64::try_from(bytes.len()).map_err(|_| {
            coded_evidence_fault(KcvFaultCode::Arithmetic, "artifact byte count overflow")
        })?;
        if artifact.path != *expected_name
            || artifact.bytes != byte_count
            || artifact.sha256 != sha256_bytes(bytes)
        {
            return Err(evidence_fault(format!(
                "evidence artifact binding differs: {expected_name}"
            )));
        }
        total = total.checked_add(byte_count).ok_or_else(|| {
            coded_evidence_fault(KcvFaultCode::Arithmetic, "artifact total overflow")
        })?;
    }
    if manifest.total_artifact_bytes != total
        || total > KCV_MAX_EVIDENCE_BYTES
        || manifest.manifest_sha256 != kcv_evidence_manifest_digest(manifest)?
    {
        return Err(evidence_fault("evidence total, bound, or digest differs"));
    }
    Ok(())
}

pub fn kcv_evidence_manifest_digest(
    manifest: &KcvEvidenceManifest,
) -> Result<ContentDigest, KcvEvidenceFault> {
    let mut normalized = manifest.clone();
    normalized.manifest_sha256 = empty_digest();
    let body = serde_json::to_vec(&normalized).map_err(evidence_fault)?;
    let mut bytes = Vec::with_capacity(MANIFEST_DOMAIN.len() + 1 + body.len());
    bytes.extend_from_slice(MANIFEST_DOMAIN.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&body);
    Ok(sha256_bytes(&bytes))
}

pub fn to_kcv_evidence_manifest_machine_form(
    manifest: &KcvEvidenceManifest,
) -> Result<String, KcvEvidenceFault> {
    if manifest.profile != KCV_EVIDENCE_PROFILE
        || manifest.manifest_sha256 != kcv_evidence_manifest_digest(manifest)?
    {
        return Err(evidence_fault("evidence manifest digest differs"));
    }
    serde_json::to_string(manifest).map_err(evidence_fault)
}

pub fn expected_kcv_artifact_files() -> Vec<String> {
    [
        KCV_PREDECESSOR_REQUEST_FILE,
        KCV_PREDECESSOR_PACKET_FILE,
        KCV_PREDECESSOR_VERIFICATION_FILE,
        KCV_A1_POLICY_ENVELOPE_FILE,
        KCV_A1_VERIFICATION_REQUEST_FILE,
        KCV_A1_RECEIPT_FILE,
        KCV_CUSTODY_ATTESTATION_FILE,
        KCV_VERIFICATION_REQUEST_FILE,
        KCV_RECEIPT_FILE,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

pub fn expected_kcv_evidence_files() -> Vec<String> {
    let mut values = expected_kcv_artifact_files();
    values.push(KCV_EVIDENCE_MANIFEST_FILE.to_owned());
    values
}

fn required<'a>(
    raw: &'a BTreeMap<String, Vec<u8>>,
    name: &str,
) -> Result<&'a [u8], KcvEvidenceFault> {
    raw.get(name).map(Vec::as_slice).ok_or_else(|| {
        coded_evidence_fault(
            KcvFaultCode::Path,
            format!("required evidence file absent: {name}"),
        )
    })
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, KcvEvidenceFault> {
    let metadata = fs::symlink_metadata(path).map_err(evidence_fault)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || is_reparse_point(&metadata)
        || metadata.len() == 0
        || metadata.len() > KCV_MAX_EVIDENCE_BYTES
    {
        return Err(coded_evidence_fault(
            KcvFaultCode::Path,
            format!("evidence file type or size refused: {}", path.display()),
        ));
    }
    fs::read(path).map_err(evidence_fault)
}

fn retained_text(bytes: &[u8]) -> Result<&str, KcvEvidenceFault> {
    if bytes.is_empty() || bytes.len() > KCV_MAX_FORM_BYTES + 1 || bytes.contains(&b'\r') {
        return Err(coded_evidence_fault(
            KcvFaultCode::Shape,
            "retained file size or CR framing differs",
        ));
    }
    let core = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if core.is_empty() || core.contains(&b'\n') {
        return Err(coded_evidence_fault(
            KcvFaultCode::Shape,
            "retained file LF framing differs",
        ));
    }
    std::str::from_utf8(core).map_err(evidence_fault)
}

fn parse_canonical<T: DeserializeOwned + Serialize>(text: &str) -> Result<T, KcvEvidenceFault> {
    let value = serde_json::from_str(text).map_err(evidence_fault)?;
    if serde_json::to_string(&value).map_err(evidence_fault)? != text {
        return Err(evidence_fault(
            "evidence manifest is not compact canonical JSON",
        ));
    }
    Ok(value)
}

fn valid_uuid(value: &str) -> bool {
    value != "00000000-0000-0000-0000-000000000000"
        && value.len() == 36
        && value.as_bytes().iter().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
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
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn evidence_fault(error: impl fmt::Display) -> KcvEvidenceFault {
    coded_evidence_fault(KcvFaultCode::Evidence, error)
}

fn coded_evidence_fault(code: KcvFaultCode, error: impl fmt::Display) -> KcvEvidenceFault {
    KcvEvidenceFault {
        code,
        message: error.to_string(),
    }
}
