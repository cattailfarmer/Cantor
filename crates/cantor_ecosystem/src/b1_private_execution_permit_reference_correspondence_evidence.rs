//! Independent bounded A7 evidence replay; no permit resolution or effect API.
use crate::b1_expected_observation_correspondence::{
    eocv_fault, parse_eocv_canonical, valid_eocv_uuid,
};
use crate::{
    B1CDriveOperatorDecisionPolicy, B1CDriveOperatorDecisionRequest, B1OaprPacket, B1OaprRequest,
    B1OaprVerification, BpvPolicyEnvelope, BpvVerificationReceipt, BpvVerificationRequest,
    EocvFault, EocvFaultCode, EocvPredecessor, EocvVerificationReceipt, EocvVerificationRequest,
    KcvCustodyAttestation, KcvVerificationReceipt, KcvVerificationRequest, KrvVerificationReceipt,
    KrvVerificationRequest, OdcvPredecessor, OdcvVerificationReceipt, OdcvVerificationRequest,
    PERC_CANONICAL_UUID, PERC_EVIDENCE_PROFILE, PERC_MAX_EVIDENCE_BYTES, PERC_MAX_FORM_BYTES,
    PERC_SOURCE_SNAPSHOT_UUID, PercEvidenceManifest, PercPredecessor, PercVerificationReceipt,
    PercVerificationRequest, TwvPredecessor, TwvVerificationReceipt, TwvVerificationRequest,
    validate_perc_receipt_fields, verify_perc_reference_correspondence,
};
use cantor_core::{ContentDigest, sha256_bytes};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

pub const PERC_EVIDENCE_FILES: [&str; 30] = [
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
    "a5_verification_request.json",
    "a5_receipt.json",
    "preparation_plan_request.json",
    "preparation_plan.json",
    "observation_bundle.json",
    "a6_verification_request.json",
    "a6_receipt.json",
    "a6_evidence_manifest.json",
    "permit_reference_envelope.json",
    "verification_request.json",
    "receipt.json",
    "evidence_manifest.json",
];
const EXPLICIT_INPUT_INDICES: [usize; 27] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 26,
    27,
];
const MANIFEST_DOMAIN: &str = "cantor.b1.private-execution-permit-reference.evidence-manifest.v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PercEvidenceReplay {
    pub manifest: PercEvidenceManifest,
    pub receipt: PercVerificationReceipt,
    pub receipt_machine_form: String,
    pub deterministic_replay_count: u8,
    pub required_fresh_process_replay_count: u8,
    pub byte_identical: bool,
}

pub fn verify_perc_payload_paths(paths: &[PathBuf]) -> Result<String, EocvFault> {
    if paths.len() != EXPLICIT_INPUT_INDICES.len() {
        return Err(eocv_fault(
            EocvFaultCode::Path,
            "expected twenty-seven explicit input paths",
        ));
    }
    let files = read_paths(paths.iter().enumerate().map(|(index, path)| {
        (
            PERC_EVIDENCE_FILES[EXPLICIT_INPUT_INDICES[index]],
            path.clone(),
        )
    }))?;
    let (_, text) = replay_payload(&files)?;
    Ok(text)
}

pub fn verify_perc_evidence_directory(root: &Path) -> Result<PercEvidenceReplay, EocvFault> {
    check_direct_directory(root)?;
    let mut names = Vec::with_capacity(PERC_EVIDENCE_FILES.len());
    for entry in fs::read_dir(root).map_err(io_fault)? {
        if names.len() == PERC_EVIDENCE_FILES.len() {
            return Err(eocv_fault(
                EocvFaultCode::Evidence,
                "extra evidence directory entry",
            ));
        }
        let entry = entry.map_err(io_fault)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| eocv_fault(EocvFaultCode::Path, "non-Unicode evidence entry"))?;
        check_regular(&fs::symlink_metadata(entry.path()).map_err(io_fault)?)?;
        names.push(name);
    }
    names.sort();
    let mut expected = PERC_EVIDENCE_FILES.map(str::to_owned);
    expected.sort();
    if names != expected {
        return Err(eocv_fault(
            EocvFaultCode::Evidence,
            "evidence filename set differs",
        ));
    }
    let files = read_paths(
        PERC_EVIDENCE_FILES
            .into_iter()
            .map(|name| (name, root.join(name))),
    )?;
    let manifest: PercEvidenceManifest =
        parse_retained(required(&files, "evidence_manifest.json")?)?;
    validate_perc_evidence_manifest(&manifest, &files)?;
    let (first, first_text) = replay_payload(&files)?;
    let (second, second_text) = replay_payload(&files)?;
    let retained: PercVerificationReceipt = parse_retained(required(&files, "receipt.json")?)?;
    validate_perc_receipt_fields(&retained)?;
    if first != second
        || first != retained
        || first_text != second_text
        || first_text.as_bytes() != retained_bytes(required(&files, "receipt.json")?)?
        || manifest.retained_authority_packet_sha256 != first.authority_packet_sha256
        || manifest.retained_a6_receipt_sha256 != first.a6_receipt_sha256
        || manifest.retained_reference_envelope_sha256 != first.reference_envelope_sha256
        || manifest.retained_receipt_sha256 != first.receipt_sha256
    {
        return Err(eocv_fault(
            EocvFaultCode::Restart,
            "independent replay or retained account differs",
        ));
    }
    Ok(PercEvidenceReplay {
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
) -> Result<(PercVerificationReceipt, String), EocvFault> {
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
    let a5_request: OdcvVerificationRequest =
        parse_retained(required(files, "a5_verification_request.json")?)?;
    let a5_receipt: OdcvVerificationReceipt = parse_retained(required(files, "a5_receipt.json")?)?;
    let a6_request: EocvVerificationRequest =
        parse_retained(required(files, "a6_verification_request.json")?)?;
    let a6_receipt: EocvVerificationReceipt = parse_retained(required(files, "a6_receipt.json")?)?;
    let request: PercVerificationRequest =
        parse_retained(required(files, "verification_request.json")?)?;
    let a6_predecessor = EocvPredecessor {
        upstream: OdcvPredecessor {
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
        },
        a5_policy: &policy,
        a5_legacy_request: &legacy_request,
        raw_a5_envelope: retained_bytes(required(files, "operator_decision_envelope.json")?)?,
        a5_request: &a5_request,
        a5_receipt: &a5_receipt,
    };
    let predecessor = PercPredecessor {
        a6_request: &a6_request,
        a6_predecessor,
        raw_plan_request: retained_bytes(required(files, "preparation_plan_request.json")?)?,
        raw_plan: retained_bytes(required(files, "preparation_plan.json")?)?,
        raw_observation_bundle: retained_bytes(required(files, "observation_bundle.json")?)?,
        a6_receipt: &a6_receipt,
    };
    let receipt = verify_perc_reference_correspondence(
        &request,
        &predecessor,
        retained_bytes(required(files, "permit_reference_envelope.json")?)?,
    )?;
    let text = serde_json::to_string(&receipt).map_err(io_fault)?;
    Ok((receipt, text))
}

fn validate_perc_evidence_manifest(
    manifest: &PercEvidenceManifest,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), EocvFault> {
    if manifest.profile != PERC_EVIDENCE_PROFILE
        || !valid_eocv_uuid(&manifest.manifest_uuid)
        || manifest.source_snapshot_uuid != PERC_SOURCE_SNAPSHOT_UUID
        || manifest.canonical_uuid != PERC_CANONICAL_UUID
        || manifest.artifacts.len() != 29
        || manifest.artifact_count != 29
        || manifest.deterministic_replay_count != 2
        || manifest.required_fresh_process_replay_count != 2
        || !manifest.byte_identical
        || manifest.effect_count != 0
    {
        return Err(eocv_fault(
            EocvFaultCode::Evidence,
            "manifest identity or account differs",
        ));
    }
    let mut total = 0u64;
    for (artifact, name) in manifest.artifacts.iter().zip(&PERC_EVIDENCE_FILES[..29]) {
        if artifact.path != *name {
            return Err(eocv_fault(
                EocvFaultCode::Path,
                "manifest artifact sequence differs",
            ));
        }
        let bytes = required(files, name)?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| eocv_fault(EocvFaultCode::Arithmetic, "artifact total overflow"))?;
        if bytes.len() > PERC_MAX_FORM_BYTES + 1
            || artifact.bytes != bytes.len() as u64
            || artifact.sha256 != sha256_bytes(bytes)
        {
            return Err(eocv_fault(
                EocvFaultCode::Evidence,
                format_args!("artifact raw binding differs: {name}"),
            ));
        }
    }
    if total > PERC_MAX_EVIDENCE_BYTES
        || total != manifest.total_artifact_bytes
        || manifest.manifest_sha256 != perc_evidence_manifest_digest(manifest)?
    {
        return Err(eocv_fault(
            EocvFaultCode::Digest,
            "manifest digest or total differs",
        ));
    }
    Ok(())
}

pub fn perc_evidence_manifest_digest(
    manifest: &PercEvidenceManifest,
) -> Result<ContentDigest, EocvFault> {
    let mut normalized = manifest.clone();
    normalized.manifest_sha256 = sha256_bytes(b"");
    let canonical = serde_json::to_vec(&normalized).map_err(io_fault)?;
    if canonical.len() > PERC_MAX_FORM_BYTES {
        return Err(eocv_fault(
            EocvFaultCode::Size,
            "manifest exceeds form bound",
        ));
    }
    let mut bytes = Vec::with_capacity(MANIFEST_DOMAIN.len() + 1 + canonical.len());
    bytes.extend_from_slice(MANIFEST_DOMAIN.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(sha256_bytes(&bytes))
}

pub fn to_perc_evidence_manifest_machine_form(
    manifest: &PercEvidenceManifest,
) -> Result<String, EocvFault> {
    if manifest.manifest_sha256 != perc_evidence_manifest_digest(manifest)? {
        return Err(eocv_fault(EocvFaultCode::Digest, "manifest digest differs"));
    }
    serde_json::to_string(manifest).map_err(io_fault)
}

fn read_paths<'a>(
    paths: impl Iterator<Item = (&'a str, PathBuf)>,
) -> Result<BTreeMap<String, Vec<u8>>, EocvFault> {
    let mut files = BTreeMap::new();
    let mut total = 0u64;
    for (name, path) in paths {
        let bytes = read_bounded_file(&path)?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| eocv_fault(EocvFaultCode::Arithmetic, "evidence total overflow"))?;
        if total > PERC_MAX_EVIDENCE_BYTES {
            return Err(eocv_fault(
                EocvFaultCode::Size,
                "evidence exceeds byte bound",
            ));
        }
        if files.insert(name.to_owned(), bytes).is_some() {
            return Err(eocv_fault(EocvFaultCode::Path, "duplicate evidence input"));
        }
    }
    Ok(files)
}

fn required<'a>(files: &'a BTreeMap<String, Vec<u8>>, name: &str) -> Result<&'a [u8], EocvFault> {
    files.get(name).map(Vec::as_slice).ok_or_else(|| {
        eocv_fault(
            EocvFaultCode::Evidence,
            format_args!("required artifact absent: {name}"),
        )
    })
}

fn retained_bytes(bytes: &[u8]) -> Result<&[u8], EocvFault> {
    let payload = bytes
        .strip_suffix(b"\n")
        .ok_or_else(|| eocv_fault(EocvFaultCode::MachineForm, "missing single LF terminator"))?;
    if payload.is_empty() || payload.contains(&b'\n') || payload.contains(&b'\r') {
        return Err(eocv_fault(
            EocvFaultCode::MachineForm,
            "retained framing differs",
        ));
    }
    Ok(payload)
}

fn parse_retained<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, EocvFault> {
    let text = std::str::from_utf8(retained_bytes(bytes)?).map_err(io_fault)?;
    parse_eocv_canonical(text)
}

fn check_direct_directory(path: &Path) -> Result<(), EocvFault> {
    for ancestor in path.ancestors().filter(|item| !item.as_os_str().is_empty()) {
        let metadata = fs::symlink_metadata(ancestor).map_err(io_fault)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(eocv_fault(
                EocvFaultCode::Path,
                "evidence directory ancestry is not direct",
            ));
        }
    }
    Ok(())
}

fn check_regular(metadata: &fs::Metadata) -> Result<(), EocvFault> {
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(metadata) {
        return Err(eocv_fault(
            EocvFaultCode::Path,
            "evidence is not a regular nonlink file",
        ));
    }
    if metadata.len() == 0 || metadata.len() > (PERC_MAX_FORM_BYTES + 1) as u64 {
        return Err(eocv_fault(
            EocvFaultCode::Size,
            "evidence file exceeds bound",
        ));
    }
    Ok(())
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, EocvFault> {
    if let Some(parent) = path.parent().filter(|item| !item.as_os_str().is_empty()) {
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
        return Err(eocv_fault(EocvFaultCode::Path, "file changed at open"));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    (&file)
        .take((PERC_MAX_FORM_BYTES + 2) as u64)
        .read_to_end(&mut bytes)
        .map_err(io_fault)?;
    let after = file.metadata().map_err(io_fault)?;
    check_regular(&after)?;
    check_regular(&fs::symlink_metadata(path).map_err(io_fault)?)?;
    if bytes.len() != opened.len() as usize
        || after.len() != opened.len()
        || bytes.len() > PERC_MAX_FORM_BYTES + 1
    {
        return Err(eocv_fault(
            EocvFaultCode::Size,
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

fn io_fault(error: impl std::fmt::Display) -> EocvFault {
    eocv_fault(EocvFaultCode::Evidence, error)
}
