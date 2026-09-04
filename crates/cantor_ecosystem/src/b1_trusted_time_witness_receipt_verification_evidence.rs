//! Independent bounded A4 evidence replay. No fixture producer or signing capability.
//!
//! The caller supplies a stable local directory. File identity is checked before
//! and after opening; bytes are bounded during reading and then hash-bound. This
//! is not an OS-level atomic directory snapshot or a filesystem access sandbox.

use crate::b1_trusted_time_witness_receipt_verification::{
    parse_twv_canonical, twv_fault, valid_twv_uuid,
};
use crate::{
    B1OaprPacket, B1OaprRequest, B1OaprVerification, BpvPolicyEnvelope, BpvVerificationReceipt,
    BpvVerificationRequest, KcvCustodyAttestation, KcvVerificationReceipt, KcvVerificationRequest,
    KrvVerificationReceipt, KrvVerificationRequest, TWV_EVIDENCE_PROFILE, TWV_MAX_EVIDENCE_BYTES,
    TWV_MAX_FORM_BYTES, TwvFault, TwvFaultCode, TwvPredecessor, TwvTimeWitness,
    TwvVerificationReceipt, TwvVerificationRequest, to_twv_receipt_machine_form,
    verify_twv_time_witness,
};
use cantor_core::{ContentDigest, sha256_bytes};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

pub const TWV_EVIDENCE_FILES: [&str; 16] = [
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
    "verification_request.json",
    "receipt.json",
    "evidence_manifest.json",
];
const MANIFEST_DOMAIN: &str = "cantor.b1.time-witness.evidence-manifest.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TwvEvidenceArtifact {
    pub path: String,
    pub bytes: u64,
    pub sha256: ContentDigest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TwvEvidenceManifest {
    pub profile: String,
    pub manifest_uuid: String,
    pub fixture_only: bool,
    pub artifacts: Vec<TwvEvidenceArtifact>,
    pub artifact_count: u8,
    pub total_artifact_bytes: u64,
    pub retained_authority_packet_sha256: ContentDigest,
    pub retained_a1_receipt_sha256: ContentDigest,
    pub retained_a2_receipt_sha256: ContentDigest,
    pub retained_a3_receipt_sha256: ContentDigest,
    pub retained_receipt_sha256: ContentDigest,
    pub deterministic_replay_count: u8,
    pub required_fresh_process_replay_count: u8,
    pub byte_identical: bool,
    pub effect_count: u32,
    pub manifest_sha256: ContentDigest,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwvEvidenceReplay {
    pub manifest: TwvEvidenceManifest,
    pub receipt: TwvVerificationReceipt,
    pub receipt_machine_form: String,
    pub deterministic_replay_count: u8,
    /// An obligation for the external gate, not a claim that this call spawned processes.
    pub required_fresh_process_replay_count: u8,
    pub byte_identical: bool,
}

/// Replay exactly fourteen explicit retained input files; writes nothing.
/// The file sequence is TWV_EVIDENCE_FILES[0..14].
pub fn verify_twv_payload_paths(paths: &[PathBuf]) -> Result<String, TwvFault> {
    if paths.len() != 14 {
        return Err(twv_fault(
            TwvFaultCode::Path,
            "expected fourteen explicit input paths",
        ));
    }
    let files = read_paths(
        paths
            .iter()
            .zip(TWV_EVIDENCE_FILES.iter())
            .map(|(p, n)| (*n, p.clone())),
    )?;
    let (_, text) = replay_payload(&files)?;
    Ok(text)
}

pub fn verify_twv_evidence_directory(root: &Path) -> Result<TwvEvidenceReplay, TwvFault> {
    check_direct_directory(root)?;
    let mut names = Vec::with_capacity(16);
    for entry in fs::read_dir(root).map_err(io_fault)? {
        if names.len() == 16 {
            return Err(twv_fault(
                TwvFaultCode::Evidence,
                "extra evidence directory entry",
            ));
        }
        let entry = entry.map_err(io_fault)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| twv_fault(TwvFaultCode::Path, "non-Unicode evidence entry"))?;
        check_regular(&fs::symlink_metadata(entry.path()).map_err(io_fault)?)?;
        names.push(name);
    }
    names.sort();
    let mut expected = TWV_EVIDENCE_FILES.map(str::to_owned);
    expected.sort();
    if names.as_slice() != expected {
        return Err(twv_fault(
            TwvFaultCode::Evidence,
            "evidence filename set differs",
        ));
    }
    let files = read_paths(
        TWV_EVIDENCE_FILES
            .into_iter()
            .map(|name| (name, root.join(name))),
    )?;
    let manifest: TwvEvidenceManifest =
        parse_retained(required(&files, "evidence_manifest.json")?)?;
    validate_twv_evidence_manifest(&manifest, &files)?;
    let (first, first_text) = replay_payload(&files)?;
    let (second, second_text) = replay_payload(&files)?;
    let retained: TwvVerificationReceipt = parse_retained(required(&files, "receipt.json")?)?;
    if first != second
        || first != retained
        || first_text != second_text
        || first_text.as_bytes() != retained_bytes(required(&files, "receipt.json")?)?
        || manifest.fixture_only != first.fixture_only
        || manifest.retained_authority_packet_sha256 != first.authority_packet_sha256
        || manifest.retained_a1_receipt_sha256 != first.a1_receipt_sha256
        || manifest.retained_a2_receipt_sha256 != first.a2_receipt_sha256
        || manifest.retained_a3_receipt_sha256 != first.a3_receipt_sha256
        || manifest.retained_receipt_sha256 != first.receipt_sha256
    {
        return Err(twv_fault(
            TwvFaultCode::Restart,
            "independent replay or retained account differs",
        ));
    }
    Ok(TwvEvidenceReplay {
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
) -> Result<(TwvVerificationReceipt, String), TwvFault> {
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
    let request: TwvVerificationRequest =
        parse_retained(required(files, "verification_request.json")?)?;
    let raw_witness = retained_bytes(required(files, "time_witness_receipt.json")?)?;
    let predecessor = TwvPredecessor {
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
    };
    // The core checks raw hashes before parsing the witness. Do not reverse that order.
    let receipt = verify_twv_time_witness(&request, &predecessor, raw_witness)?;
    let witness: TwvTimeWitness = parse_retained(required(files, "time_witness_receipt.json")?)?;
    let text = to_twv_receipt_machine_form(&request, &witness, &a3_receipt, &receipt)?;
    Ok((receipt, text))
}

pub fn validate_twv_evidence_manifest(
    manifest: &TwvEvidenceManifest,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), TwvFault> {
    if manifest.profile != TWV_EVIDENCE_PROFILE
        || !valid_twv_uuid(&manifest.manifest_uuid)
        || manifest.artifacts.len() != 15
        || manifest.artifact_count != 15
        || manifest.deterministic_replay_count != 2
        || manifest.required_fresh_process_replay_count != 2
        || !manifest.byte_identical
        || manifest.effect_count != 0
    {
        return Err(twv_fault(
            TwvFaultCode::Evidence,
            "manifest identity or account differs",
        ));
    }
    let mut total = 0u64;
    for (artifact, name) in manifest.artifacts.iter().zip(&TWV_EVIDENCE_FILES[..15]) {
        // Compare against constants before looking up bytes: manifest paths are never resolved.
        if artifact.path != *name {
            return Err(twv_fault(
                TwvFaultCode::Path,
                "manifest artifact sequence differs",
            ));
        }
        let bytes = required(files, name)?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| twv_fault(TwvFaultCode::Arithmetic, "artifact total overflow"))?;
        if bytes.len() > TWV_MAX_FORM_BYTES + 1
            || artifact.bytes != bytes.len() as u64
            || artifact.sha256 != sha256_bytes(bytes)
        {
            return Err(twv_fault(
                TwvFaultCode::Evidence,
                format_args!("artifact raw binding differs: {name}"),
            ));
        }
    }
    if total > TWV_MAX_EVIDENCE_BYTES
        || total != manifest.total_artifact_bytes
        || manifest.manifest_sha256 != twv_evidence_manifest_digest(manifest)?
    {
        return Err(twv_fault(
            TwvFaultCode::Digest,
            "manifest digest or total differs",
        ));
    }
    Ok(())
}
pub fn twv_evidence_manifest_digest(
    manifest: &TwvEvidenceManifest,
) -> Result<ContentDigest, TwvFault> {
    let mut normalized = manifest.clone();
    normalized.manifest_sha256 = sha256_bytes(b"");
    let canonical = serde_json::to_vec(&normalized).map_err(io_fault)?;
    if canonical.len() > TWV_MAX_FORM_BYTES {
        return Err(twv_fault(TwvFaultCode::Size, "manifest exceeds form bound"));
    }
    let mut bytes = Vec::with_capacity(MANIFEST_DOMAIN.len() + 1 + canonical.len());
    bytes.extend_from_slice(MANIFEST_DOMAIN.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(sha256_bytes(&bytes))
}
pub fn to_twv_evidence_manifest_machine_form(
    manifest: &TwvEvidenceManifest,
) -> Result<String, TwvFault> {
    if manifest.manifest_sha256 != twv_evidence_manifest_digest(manifest)? {
        return Err(twv_fault(TwvFaultCode::Digest, "manifest digest differs"));
    }
    serde_json::to_string(manifest).map_err(io_fault)
}
fn read_paths<'a>(
    paths: impl Iterator<Item = (&'a str, PathBuf)>,
) -> Result<BTreeMap<String, Vec<u8>>, TwvFault> {
    let mut files = BTreeMap::new();
    let mut total = 0u64;
    for (name, path) in paths {
        let bytes = read_bounded_file(&path)?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| twv_fault(TwvFaultCode::Arithmetic, "directory total overflow"))?;
        if total > TWV_MAX_EVIDENCE_BYTES {
            return Err(twv_fault(
                TwvFaultCode::Size,
                "directory exceeds byte bound",
            ));
        }
        files.insert(name.to_owned(), bytes);
    }
    Ok(files)
}
fn required<'a>(files: &'a BTreeMap<String, Vec<u8>>, name: &str) -> Result<&'a [u8], TwvFault> {
    files.get(name).map(Vec::as_slice).ok_or_else(|| {
        twv_fault(
            TwvFaultCode::Evidence,
            format_args!("required artifact absent: {name}"),
        )
    })
}
fn retained_bytes(bytes: &[u8]) -> Result<&[u8], TwvFault> {
    let payload = bytes
        .strip_suffix(b"\n")
        .ok_or_else(|| twv_fault(TwvFaultCode::MachineForm, "missing single LF terminator"))?;
    if payload.is_empty() || payload.contains(&b'\n') || payload.contains(&b'\r') {
        return Err(twv_fault(
            TwvFaultCode::MachineForm,
            "retained framing differs",
        ));
    }
    Ok(payload)
}
fn parse_retained<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, TwvFault> {
    let text = std::str::from_utf8(retained_bytes(bytes)?).map_err(io_fault)?;
    parse_twv_canonical(text)
}
fn check_direct_directory(path: &Path) -> Result<(), TwvFault> {
    // Walk only explicit ancestry, never discover unrelated paths or follow a manifest reference.
    for ancestor in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let metadata = fs::symlink_metadata(ancestor).map_err(io_fault)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(twv_fault(
                TwvFaultCode::Path,
                "evidence directory ancestry is not direct",
            ));
        }
    }
    Ok(())
}
fn check_regular(metadata: &fs::Metadata) -> Result<(), TwvFault> {
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(metadata) {
        return Err(twv_fault(
            TwvFaultCode::Path,
            "evidence is not a regular nonlink file",
        ));
    }
    if metadata.len() == 0 || metadata.len() > (TWV_MAX_FORM_BYTES + 1) as u64 {
        return Err(twv_fault(
            TwvFaultCode::Size,
            "evidence file exceeds bounded framing",
        ));
    }
    Ok(())
}
fn read_bounded_file(path: &Path) -> Result<Vec<u8>, TwvFault> {
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
        return Err(twv_fault(TwvFaultCode::Path, "file changed at open"));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    (&file)
        .take((TWV_MAX_FORM_BYTES + 2) as u64)
        .read_to_end(&mut bytes)
        .map_err(io_fault)?;
    let after = file.metadata().map_err(io_fault)?;
    check_regular(&after)?;
    check_regular(&fs::symlink_metadata(path).map_err(io_fault)?)?;
    if bytes.len() != opened.len() as usize
        || after.len() != opened.len()
        || bytes.len() > TWV_MAX_FORM_BYTES + 1
    {
        return Err(twv_fault(
            TwvFaultCode::Size,
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
fn io_fault(error: impl std::fmt::Display) -> TwvFault {
    twv_fault(TwvFaultCode::Evidence, error)
}
