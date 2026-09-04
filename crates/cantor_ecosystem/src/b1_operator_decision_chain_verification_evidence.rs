//! Independent bounded A5 evidence replay. No producer import or signing capability.
//!
//! Stable explicitly supplied files are required. Regular/nonlink checks and bounded
//! reads do not claim an atomic filesystem snapshot or an OS access sandbox.
use crate::b1_operator_decision_chain_verification::{
    odcv_fault, parse_odcv_canonical, valid_odcv_uuid, validate_odcv_receipt_fields,
};
use crate::{
    B1CDriveOperatorDecisionPolicy, B1CDriveOperatorDecisionRequest, B1OaprPacket, B1OaprRequest,
    B1OaprVerification, BpvPolicyEnvelope, BpvVerificationReceipt, BpvVerificationRequest,
    KcvCustodyAttestation, KcvVerificationReceipt, KcvVerificationRequest, KrvVerificationReceipt,
    KrvVerificationRequest, ODCV_EVIDENCE_PROFILE, ODCV_MAX_EVIDENCE_BYTES, ODCV_MAX_FORM_BYTES,
    OdcvFault, OdcvFaultCode, OdcvPredecessor, OdcvVerificationReceipt, OdcvVerificationRequest,
    TwvPredecessor, TwvVerificationReceipt, TwvVerificationRequest, verify_odcv_operator_decision,
};
use cantor_core::{ContentDigest, sha256_bytes};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

pub const ODCV_EVIDENCE_FILES: [&str; 21] = [
    "predecessor_request.json",
    "predecessor_packet.json",
    "predecessor_verification.json",
    "a1_policy_envelope.json",
    "a1_verification_request.json",
    "a1_receipt.json",
    "custody_attestation.json",
    "a2_verification_request.json",
    "a2_receipt.json",
    "revocation_snapshot.json",
    "a3_verification_request.json",
    "a3_receipt.json",
    "time_witness_receipt.json",
    "a4_verification_request.json",
    "a4_receipt.json",
    "operator_decision_policy.json",
    "operator_decision_request.json",
    "operator_decision_envelope.json",
    "verification_request.json",
    "receipt.json",
    "evidence_manifest.json",
];
const MANIFEST_DOMAIN: &str = "cantor.b1.operator-decision-chain.evidence-manifest.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OdcvEvidenceArtifact {
    pub path: String,
    pub bytes: u64,
    pub sha256: ContentDigest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OdcvEvidenceManifest {
    pub profile: String,
    pub manifest_uuid: String,
    pub fixture_only: bool,
    pub artifacts: Vec<OdcvEvidenceArtifact>,
    pub artifact_count: u8,
    pub total_artifact_bytes: u64,
    pub retained_authority_packet_sha256: ContentDigest,
    pub retained_a1_receipt_sha256: ContentDigest,
    pub retained_a2_receipt_sha256: ContentDigest,
    pub retained_a3_receipt_sha256: ContentDigest,
    pub retained_a4_receipt_sha256: ContentDigest,
    pub retained_legacy_verification_sha256: ContentDigest,
    pub retained_receipt_sha256: ContentDigest,
    pub deterministic_replay_count: u8,
    pub required_fresh_process_replay_count: u8,
    pub byte_identical: bool,
    pub effect_count: u32,
    pub manifest_sha256: ContentDigest,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OdcvEvidenceReplay {
    pub manifest: OdcvEvidenceManifest,
    pub receipt: OdcvVerificationReceipt,
    pub receipt_machine_form: String,
    pub deterministic_replay_count: u8,
    /// An obligation for the external gate, not a claim that this call spawned processes.
    pub required_fresh_process_replay_count: u8,
    pub byte_identical: bool,
}

/// Replay exactly nineteen explicit retained input files; writes nothing.
/// The file sequence is ODCV_EVIDENCE_FILES[0..19].
pub fn verify_odcv_payload_paths(paths: &[PathBuf]) -> Result<String, OdcvFault> {
    if paths.len() != 19 {
        return Err(odcv_fault(
            OdcvFaultCode::Path,
            "expected nineteen explicit input paths",
        ));
    }
    let files = read_paths(
        paths
            .iter()
            .zip(ODCV_EVIDENCE_FILES.iter())
            .map(|(p, n)| (*n, p.clone())),
    )?;
    let (_, text) = replay_payload(&files)?;
    Ok(text)
}

pub fn verify_odcv_evidence_directory(root: &Path) -> Result<OdcvEvidenceReplay, OdcvFault> {
    check_direct_directory(root)?;
    let mut names = Vec::with_capacity(21);
    for entry in fs::read_dir(root).map_err(io_fault)? {
        if names.len() == 21 {
            return Err(odcv_fault(
                OdcvFaultCode::Evidence,
                "extra evidence directory entry",
            ));
        }
        let entry = entry.map_err(io_fault)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| odcv_fault(OdcvFaultCode::Path, "non-Unicode evidence entry"))?;
        check_regular(&fs::symlink_metadata(entry.path()).map_err(io_fault)?)?;
        names.push(name);
    }
    names.sort();
    let mut expected = ODCV_EVIDENCE_FILES.map(str::to_owned);
    expected.sort();
    if names.as_slice() != expected {
        return Err(odcv_fault(
            OdcvFaultCode::Evidence,
            "evidence filename set differs",
        ));
    }
    let files = read_paths(
        ODCV_EVIDENCE_FILES
            .into_iter()
            .map(|name| (name, root.join(name))),
    )?;
    let manifest: OdcvEvidenceManifest =
        parse_retained(required(&files, "evidence_manifest.json")?)?;
    validate_odcv_evidence_manifest(&manifest, &files)?;
    let (first, first_text) = replay_payload(&files)?;
    let (second, second_text) = replay_payload(&files)?;
    let retained: OdcvVerificationReceipt = parse_retained(required(&files, "receipt.json")?)?;
    validate_odcv_receipt_fields(&retained)?;
    if first != second
        || first != retained
        || first_text != second_text
        || first_text.as_bytes() != retained_bytes(required(&files, "receipt.json")?)?
        || manifest.fixture_only != first.fixture_only
        || manifest.retained_authority_packet_sha256 != first.authority_packet_sha256
        || manifest.retained_a1_receipt_sha256 != first.a1_receipt_sha256
        || manifest.retained_a2_receipt_sha256 != first.a2_receipt_sha256
        || manifest.retained_a3_receipt_sha256 != first.a3_receipt_sha256
        || manifest.retained_a4_receipt_sha256 != first.a4_receipt_sha256
        || manifest.retained_legacy_verification_sha256 != first.legacy_verification_sha256
        || manifest.retained_receipt_sha256 != first.receipt_sha256
    {
        return Err(odcv_fault(
            OdcvFaultCode::Restart,
            "independent replay or retained account differs",
        ));
    }
    Ok(OdcvEvidenceReplay {
        manifest,
        receipt: first,
        receipt_machine_form: first_text,
        deterministic_replay_count: 2,
        required_fresh_process_replay_count: 2,
        byte_identical: true,
    })
}

fn replay_payload(
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(OdcvVerificationReceipt, String), OdcvFault> {
    let predecessor_request: B1OaprRequest =
        parse_retained(required(files, "predecessor_request.json")?)?;
    let predecessor_packet: B1OaprPacket =
        parse_retained(required(files, "predecessor_packet.json")?)?;
    let predecessor_verification: B1OaprVerification =
        parse_retained(required(files, "predecessor_verification.json")?)?;
    let a1_envelope: BpvPolicyEnvelope =
        parse_retained(required(files, "a1_policy_envelope.json")?)?;
    let a1_request: BpvVerificationRequest =
        parse_retained(required(files, "a1_verification_request.json")?)?;
    let a1_receipt: BpvVerificationReceipt = parse_retained(required(files, "a1_receipt.json")?)?;
    let a2_attestation: KcvCustodyAttestation =
        parse_retained(required(files, "custody_attestation.json")?)?;
    let a2_request: KcvVerificationRequest =
        parse_retained(required(files, "a2_verification_request.json")?)?;
    let a2_receipt: KcvVerificationReceipt = parse_retained(required(files, "a2_receipt.json")?)?;
    let a3_request: KrvVerificationRequest =
        parse_retained(required(files, "a3_verification_request.json")?)?;
    let a3_receipt: KrvVerificationReceipt = parse_retained(required(files, "a3_receipt.json")?)?;
    let a4_request: TwvVerificationRequest =
        parse_retained(required(files, "a4_verification_request.json")?)?;
    let a4_receipt: TwvVerificationReceipt = parse_retained(required(files, "a4_receipt.json")?)?;
    let policy: B1CDriveOperatorDecisionPolicy =
        parse_retained(required(files, "operator_decision_policy.json")?)?;
    let legacy_request: B1CDriveOperatorDecisionRequest =
        parse_retained(required(files, "operator_decision_request.json")?)?;
    let request: OdcvVerificationRequest =
        parse_retained(required(files, "verification_request.json")?)?;
    let predecessor = OdcvPredecessor {
        upstream: TwvPredecessor {
            request: &predecessor_request,
            packet: &predecessor_packet,
            verification: &predecessor_verification,
            a1_envelope: &a1_envelope,
            raw_a1_envelope: retained_bytes(required(files, "a1_policy_envelope.json")?)?,
            a1_request: &a1_request,
            a1_receipt: &a1_receipt,
            a2_attestation: &a2_attestation,
            raw_a2_attestation: retained_bytes(required(files, "custody_attestation.json")?)?,
            a2_request: &a2_request,
            a2_receipt: &a2_receipt,
            raw_a3_snapshot: retained_bytes(required(files, "revocation_snapshot.json")?)?,
            a3_request: &a3_request,
            a3_receipt: &a3_receipt,
        },
        raw_a4_witness: retained_bytes(required(files, "time_witness_receipt.json")?)?,
        a4_request: &a4_request,
        a4_receipt: &a4_receipt,
    };
    // Keep raw A5 bytes unparsed until the core verifies their descriptor identity.
    let raw_envelope = retained_bytes(required(files, "operator_decision_envelope.json")?)?;
    let receipt = verify_odcv_operator_decision(
        &request,
        &predecessor,
        &policy,
        &legacy_request,
        raw_envelope,
    )?;
    let text = serde_json::to_string(&receipt).map_err(io_fault)?;
    Ok((receipt, text))
}

pub fn validate_odcv_evidence_manifest(
    manifest: &OdcvEvidenceManifest,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), OdcvFault> {
    if manifest.profile != ODCV_EVIDENCE_PROFILE
        || !valid_odcv_uuid(&manifest.manifest_uuid)
        || manifest.artifacts.len() != 20
        || manifest.artifact_count != 20
        || manifest.deterministic_replay_count != 2
        || manifest.required_fresh_process_replay_count != 2
        || !manifest.byte_identical
        || manifest.effect_count != 0
    {
        return Err(odcv_fault(
            OdcvFaultCode::Evidence,
            "manifest identity or account differs",
        ));
    }
    let mut total = 0u64;
    for (artifact, name) in manifest.artifacts.iter().zip(&ODCV_EVIDENCE_FILES[..20]) {
        // Compare against constants before looking up bytes: manifest paths are never resolved.
        if artifact.path != *name {
            return Err(odcv_fault(
                OdcvFaultCode::Path,
                "manifest artifact sequence differs",
            ));
        }
        let bytes = required(files, name)?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| odcv_fault(OdcvFaultCode::Arithmetic, "artifact total overflow"))?;
        if bytes.len() > ODCV_MAX_FORM_BYTES + 1
            || artifact.bytes != bytes.len() as u64
            || artifact.sha256 != sha256_bytes(bytes)
        {
            return Err(odcv_fault(
                OdcvFaultCode::Evidence,
                format_args!("artifact raw binding differs: {name}"),
            ));
        }
    }
    if total > ODCV_MAX_EVIDENCE_BYTES
        || total != manifest.total_artifact_bytes
        || manifest.manifest_sha256 != odcv_evidence_manifest_digest(manifest)?
    {
        return Err(odcv_fault(
            OdcvFaultCode::Digest,
            "manifest digest or total differs",
        ));
    }
    Ok(())
}
pub fn odcv_evidence_manifest_digest(
    manifest: &OdcvEvidenceManifest,
) -> Result<ContentDigest, OdcvFault> {
    let mut normalized = manifest.clone();
    normalized.manifest_sha256 = sha256_bytes(b"");
    let canonical = serde_json::to_vec(&normalized).map_err(io_fault)?;
    if canonical.len() > ODCV_MAX_FORM_BYTES {
        return Err(odcv_fault(
            OdcvFaultCode::Size,
            "manifest exceeds form bound",
        ));
    }
    let mut bytes = Vec::with_capacity(MANIFEST_DOMAIN.len() + 1 + canonical.len());
    bytes.extend_from_slice(MANIFEST_DOMAIN.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(sha256_bytes(&bytes))
}
pub fn to_odcv_evidence_manifest_machine_form(
    manifest: &OdcvEvidenceManifest,
) -> Result<String, OdcvFault> {
    if manifest.manifest_sha256 != odcv_evidence_manifest_digest(manifest)? {
        return Err(odcv_fault(OdcvFaultCode::Digest, "manifest digest differs"));
    }
    serde_json::to_string(manifest).map_err(io_fault)
}
fn read_paths<'a>(
    paths: impl Iterator<Item = (&'a str, PathBuf)>,
) -> Result<BTreeMap<String, Vec<u8>>, OdcvFault> {
    let mut files = BTreeMap::new();
    let mut total = 0u64;
    for (name, path) in paths {
        let bytes = read_bounded_file(&path)?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| odcv_fault(OdcvFaultCode::Arithmetic, "directory total overflow"))?;
        if total > ODCV_MAX_EVIDENCE_BYTES {
            return Err(odcv_fault(
                OdcvFaultCode::Size,
                "directory exceeds byte bound",
            ));
        }
        files.insert(name.to_owned(), bytes);
    }
    Ok(files)
}
fn required<'a>(files: &'a BTreeMap<String, Vec<u8>>, name: &str) -> Result<&'a [u8], OdcvFault> {
    files.get(name).map(Vec::as_slice).ok_or_else(|| {
        odcv_fault(
            OdcvFaultCode::Evidence,
            format_args!("required artifact absent: {name}"),
        )
    })
}
fn retained_bytes(bytes: &[u8]) -> Result<&[u8], OdcvFault> {
    let payload = bytes
        .strip_suffix(b"\n")
        .ok_or_else(|| odcv_fault(OdcvFaultCode::MachineForm, "missing single LF terminator"))?;
    if payload.is_empty() || payload.contains(&b'\n') || payload.contains(&b'\r') {
        return Err(odcv_fault(
            OdcvFaultCode::MachineForm,
            "retained framing differs",
        ));
    }
    Ok(payload)
}
fn parse_retained<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, OdcvFault> {
    let text = std::str::from_utf8(retained_bytes(bytes)?).map_err(io_fault)?;
    parse_odcv_canonical(text)
}
fn check_direct_directory(path: &Path) -> Result<(), OdcvFault> {
    // Walk only explicit ancestry, never discover unrelated paths or follow a manifest reference.
    for ancestor in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let metadata = fs::symlink_metadata(ancestor).map_err(io_fault)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(odcv_fault(
                OdcvFaultCode::Path,
                "evidence directory ancestry is not direct",
            ));
        }
    }
    Ok(())
}
fn check_regular(metadata: &fs::Metadata) -> Result<(), OdcvFault> {
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(metadata) {
        return Err(odcv_fault(
            OdcvFaultCode::Path,
            "evidence is not a regular nonlink file",
        ));
    }
    if metadata.len() == 0 || metadata.len() > (ODCV_MAX_FORM_BYTES + 1) as u64 {
        return Err(odcv_fault(
            OdcvFaultCode::Size,
            "evidence file exceeds bounded framing",
        ));
    }
    Ok(())
}
fn read_bounded_file(path: &Path) -> Result<Vec<u8>, OdcvFault> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        check_direct_directory(parent)?;
    }
    let before = fs::symlink_metadata(path).map_err(io_fault)?;
    check_regular(&before)?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).map_err(io_fault)?;
    let opened = file.metadata().map_err(io_fault)?;
    check_regular(&opened)?;
    if opened.len() != before.len() {
        return Err(odcv_fault(OdcvFaultCode::Path, "file changed at open"));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    (&file)
        .take((ODCV_MAX_FORM_BYTES + 2) as u64)
        .read_to_end(&mut bytes)
        .map_err(io_fault)?;
    let after = file.metadata().map_err(io_fault)?;
    check_regular(&after)?;
    check_regular(&fs::symlink_metadata(path).map_err(io_fault)?)?;
    if bytes.len() != opened.len() as usize
        || after.len() != opened.len()
        || bytes.len() > ODCV_MAX_FORM_BYTES + 1
    {
        return Err(odcv_fault(
            OdcvFaultCode::Size,
            "file changed or exceeded bound during read",
        ));
    }
    Ok(bytes)
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
fn io_fault(error: impl std::fmt::Display) -> OdcvFault {
    odcv_fault(OdcvFaultCode::Evidence, error)
}
