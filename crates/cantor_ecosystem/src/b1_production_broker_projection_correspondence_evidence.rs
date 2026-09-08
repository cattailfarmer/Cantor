//! Independent bounded A8 evidence replay; no endpoint, broker, permit, or effect API.
use crate::b1_expected_observation_correspondence::{
    eocv_fault, parse_eocv_canonical, valid_eocv_uuid,
};
use crate::{
    B1CDriveOperatorDecisionPolicy, B1CDriveOperatorDecisionRequest, B1OaprPacket, B1OaprRequest,
    B1OaprVerification, BpvPolicyEnvelope, BpvVerificationReceipt, BpvVerificationRequest,
    EocvFault, EocvFaultCode, EocvPredecessor, EocvVerificationReceipt, EocvVerificationRequest,
    KcvCustodyAttestation, KcvVerificationReceipt, KcvVerificationRequest, KrvVerificationReceipt,
    KrvVerificationRequest, OdcvPredecessor, OdcvVerificationReceipt, OdcvVerificationRequest,
    PBPC_CANONICAL_UUID, PBPC_EVIDENCE_PROFILE, PBPC_MAX_EVIDENCE_BYTES, PBPC_MAX_FORM_BYTES,
    PBPC_SOURCE_SNAPSHOT_UUID, PbpcEvidenceManifest, PbpcPredecessor, PbpcProjectionDeclaration,
    PbpcVerificationReceipt, PbpcVerificationRequest, PercPredecessor, PercVerificationReceipt,
    PercVerificationRequest, TwvPredecessor, TwvVerificationReceipt, TwvVerificationRequest,
    pbpc_evidence_manifest_digest, validate_pbpc_evidence_manifest, validate_pbpc_receipt_fields,
    verify_pbpc_projection_correspondence,
};
use cantor_core::sha256_bytes;
use serde::{Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

pub const PBPC_EVIDENCE_FILES: [&str; 34] = [
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
    "a7_verification_request.json",
    "a7_receipt.json",
    "a7_evidence_manifest.json",
    "broker_projection_declaration.json",
    "verification_request.json",
    "receipt.json",
    "evidence_manifest.json",
];

const EXPLICIT_INPUT_INDICES: [usize; 30] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 26,
    27, 28, 30, 31,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PbpcEvidenceReplay {
    pub manifest: PbpcEvidenceManifest,
    pub receipt: PbpcVerificationReceipt,
    pub receipt_machine_form: String,
    pub deterministic_replay_count: u8,
    pub required_fresh_process_replay_count: u8,
    pub byte_identical: bool,
}

pub fn verify_pbpc_payload_paths(paths: &[PathBuf]) -> Result<String, EocvFault> {
    if paths.len() != EXPLICIT_INPUT_INDICES.len() {
        return Err(eocv_fault(
            EocvFaultCode::Path,
            "expected thirty explicit A8 input paths",
        ));
    }
    let files = read_paths(paths.iter().enumerate().map(|(index, path)| {
        (
            PBPC_EVIDENCE_FILES[EXPLICIT_INPUT_INDICES[index]],
            path.clone(),
        )
    }))?;
    let (_, text) = replay_payload(&files)?;
    Ok(text)
}

pub fn verify_pbpc_evidence_directory(root: &Path) -> Result<PbpcEvidenceReplay, EocvFault> {
    check_direct_directory(root)?;
    let mut names = Vec::with_capacity(PBPC_EVIDENCE_FILES.len());
    for entry in fs::read_dir(root).map_err(io_fault)? {
        if names.len() == PBPC_EVIDENCE_FILES.len() {
            return Err(eocv_fault(
                EocvFaultCode::Evidence,
                "extra A8 evidence directory entry",
            ));
        }
        let entry = entry.map_err(io_fault)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| eocv_fault(EocvFaultCode::Path, "non-Unicode A8 evidence entry"))?;
        check_regular(&fs::symlink_metadata(entry.path()).map_err(io_fault)?)?;
        names.push(name);
    }
    names.sort();
    let mut expected = PBPC_EVIDENCE_FILES.map(str::to_owned);
    expected.sort();
    if names != expected {
        return Err(eocv_fault(
            EocvFaultCode::Evidence,
            "A8 evidence filename set differs",
        ));
    }
    let files = read_paths(
        PBPC_EVIDENCE_FILES
            .into_iter()
            .map(|name| (name, root.join(name))),
    )?;
    let manifest: PbpcEvidenceManifest =
        parse_retained(required(&files, "evidence_manifest.json")?)?;
    validate_manifest_bindings(&manifest, &files)?;
    let (first, first_text) = replay_payload(&files)?;
    let (second, second_text) = replay_payload(&files)?;
    let retained: PbpcVerificationReceipt = parse_retained(required(&files, "receipt.json")?)?;
    validate_pbpc_receipt_fields(&retained)?;
    if first != second
        || first != retained
        || first_text != second_text
        || first_text.as_bytes() != retained_bytes(required(&files, "receipt.json")?)?
        || manifest.retained_authority_packet_sha256 != first.authority_packet_sha256
        || manifest.retained_a7_receipt_sha256 != first.a7_receipt_sha256
        || manifest.retained_projection_declaration_sha256 != first.projection_declaration_sha256
        || manifest.retained_receipt_sha256 != first.receipt_sha256
    {
        return Err(eocv_fault(
            EocvFaultCode::Restart,
            "A8 independent replay or retained account differs",
        ));
    }
    Ok(PbpcEvidenceReplay {
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
) -> Result<(PbpcVerificationReceipt, String), EocvFault> {
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
    let a7_request: PercVerificationRequest =
        parse_retained(required(files, "a7_verification_request.json")?)?;
    let a7_receipt: PercVerificationReceipt = parse_retained(required(files, "a7_receipt.json")?)?;
    let declaration: PbpcProjectionDeclaration =
        parse_retained(required(files, "broker_projection_declaration.json")?)?;
    let request: PbpcVerificationRequest =
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
    let predecessor = PbpcPredecessor {
        a7_request: &a7_request,
        a7_predecessor: PercPredecessor {
            a6_request: &a6_request,
            a6_predecessor,
            raw_plan_request: retained_bytes(required(files, "preparation_plan_request.json")?)?,
            raw_plan: retained_bytes(required(files, "preparation_plan.json")?)?,
            raw_observation_bundle: retained_bytes(required(files, "observation_bundle.json")?)?,
            a6_receipt: &a6_receipt,
        },
        raw_a7_envelope: retained_bytes(required(files, "permit_reference_envelope.json")?)?,
        a7_receipt: &a7_receipt,
    };
    let receipt = verify_pbpc_projection_correspondence(
        &request,
        &predecessor,
        retained_bytes(required(files, "broker_projection_declaration.json")?)?,
    )?;
    if declaration.projection_sha256 != receipt.projection_declaration_sha256 {
        return Err(eocv_fault(
            EocvFaultCode::Identity,
            "A8 retained declaration identity differs",
        ));
    }
    let text = serde_json::to_string(&receipt).map_err(io_fault)?;
    Ok((receipt, text))
}

fn validate_manifest_bindings(
    manifest: &PbpcEvidenceManifest,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), EocvFault> {
    validate_pbpc_evidence_manifest(manifest)?;
    if manifest.profile != PBPC_EVIDENCE_PROFILE
        || !valid_eocv_uuid(&manifest.manifest_uuid)
        || manifest.source_snapshot_uuid != PBPC_SOURCE_SNAPSHOT_UUID
        || manifest.canonical_uuid != PBPC_CANONICAL_UUID
    {
        return Err(eocv_fault(
            EocvFaultCode::Evidence,
            "A8 manifest identity differs",
        ));
    }
    let mut total = 0u64;
    for (artifact, name) in manifest.artifacts.iter().zip(&PBPC_EVIDENCE_FILES[..33]) {
        if artifact.path != *name {
            return Err(eocv_fault(
                EocvFaultCode::Path,
                "A8 manifest artifact sequence differs",
            ));
        }
        let bytes = required(files, name)?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| eocv_fault(EocvFaultCode::Arithmetic, "A8 artifact total overflow"))?;
        if bytes.len() > PBPC_MAX_FORM_BYTES + 1
            || artifact.bytes != bytes.len() as u64
            || artifact.sha256 != sha256_bytes(bytes)
        {
            return Err(eocv_fault(
                EocvFaultCode::Evidence,
                "A8 artifact raw binding differs",
            ));
        }
    }
    if total > PBPC_MAX_EVIDENCE_BYTES
        || total != manifest.total_artifact_bytes
        || manifest.manifest_sha256 != pbpc_evidence_manifest_digest(manifest)?
    {
        return Err(eocv_fault(
            EocvFaultCode::Digest,
            "A8 manifest digest or total differs",
        ));
    }
    Ok(())
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
            .ok_or_else(|| eocv_fault(EocvFaultCode::Arithmetic, "A8 evidence total overflow"))?;
        if total > PBPC_MAX_EVIDENCE_BYTES {
            return Err(eocv_fault(
                EocvFaultCode::Size,
                "A8 evidence exceeds aggregate byte bound",
            ));
        }
        if files.insert(name.to_owned(), bytes).is_some() {
            return Err(eocv_fault(
                EocvFaultCode::Path,
                "duplicate A8 evidence input",
            ));
        }
    }
    Ok(files)
}

fn required<'a>(files: &'a BTreeMap<String, Vec<u8>>, name: &str) -> Result<&'a [u8], EocvFault> {
    files.get(name).map(Vec::as_slice).ok_or_else(|| {
        eocv_fault(
            EocvFaultCode::Evidence,
            "required A8 evidence artifact absent",
        )
    })
}

fn retained_bytes(bytes: &[u8]) -> Result<&[u8], EocvFault> {
    let payload = bytes.strip_suffix(b"\n").ok_or_else(|| {
        eocv_fault(
            EocvFaultCode::MachineForm,
            "A8 retained framing lacks one LF",
        )
    })?;
    if payload.is_empty() || payload.contains(&b'\n') || payload.contains(&b'\r') {
        return Err(eocv_fault(
            EocvFaultCode::MachineForm,
            "A8 retained framing differs",
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
                "A8 evidence directory ancestry is not direct",
            ));
        }
    }
    Ok(())
}

fn check_regular(metadata: &fs::Metadata) -> Result<(), EocvFault> {
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(metadata) {
        return Err(eocv_fault(
            EocvFaultCode::Path,
            "A8 evidence is not a regular nonlink file",
        ));
    }
    if metadata.len() == 0 || metadata.len() > (PBPC_MAX_FORM_BYTES + 1) as u64 {
        return Err(eocv_fault(
            EocvFaultCode::Size,
            "A8 evidence file exceeds bound",
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
        return Err(eocv_fault(
            EocvFaultCode::Path,
            "A8 evidence changed at open",
        ));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    (&file)
        .take((PBPC_MAX_FORM_BYTES + 2) as u64)
        .read_to_end(&mut bytes)
        .map_err(io_fault)?;
    let after = file.metadata().map_err(io_fault)?;
    check_regular(&after)?;
    check_regular(&fs::symlink_metadata(path).map_err(io_fault)?)?;
    if bytes.len() != opened.len() as usize
        || after.len() != opened.len()
        || bytes.len() > PBPC_MAX_FORM_BYTES + 1
    {
        return Err(eocv_fault(
            EocvFaultCode::Size,
            "A8 evidence changed or exceeded bound during read",
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
