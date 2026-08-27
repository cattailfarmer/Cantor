//! Independent read-only evidence replay for the B1 preparation commission proposal.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::Path,
};

use cantor_core::{ContentDigest, sha256_bytes};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{
    B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_CANONICAL_UUID,
    B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_FORMATION_COMMIT,
    B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_MAX_MACHINE_FORM_BYTES,
    B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SIGNATURE_UUID,
    B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SOURCE_SNAPSHOT_UUID,
    B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_UUID,
    B1CDriveProductionPreparationCommissionProposal,
    B1CDriveProductionPreparationCommissionProposalRequest,
    B1CDriveProductionPreparationEffectAccount,
    compile_b1_cdrive_production_preparation_commission_proposal,
    from_b1_cdrive_production_preparation_commission_proposal_machine_form,
    from_b1_cdrive_production_preparation_commission_proposal_request_machine_form,
    to_b1_cdrive_production_preparation_commission_proposal_machine_form,
};

pub const B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_EVIDENCE_MANIFEST_PROFILE: &str = "cantor-self-work-update-broker-b1-cdrive-production-preparation-commission-proposal-evidence/0.1";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_EVIDENCE_VERIFICATION_PROFILE: &str = "cantor-self-work-update-broker-b1-cdrive-production-preparation-commission-proposal-evidence-verification/0.1";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_EVIDENCE_VERIFICATION_STATUS: &str = "production_preparation_commission_proposal_independently_verified_awaiting_external_authorization";

const MANIFEST_DOMAIN: &str =
    "cantor.b1.cdrive.production-preparation-commission-proposal.evidence-manifest.v1";
const VERIFICATION_DOMAIN: &str =
    "cantor.b1.cdrive.production-preparation-commission-proposal.evidence-verification.v1";
const EXPECTED_ARTIFACTS: [&str; 3] = ["request.json", "proposal.json", "verification.json"];
const MAX_AGGREGATE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 24;
const MAX_JSON_FIELDS: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionPreparationCommissionProposalEvidenceArtifact {
    pub path: String,
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionPreparationCommissionProposalEvidenceManifest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub formation_commit: String,
    pub proposal_uuid: String,
    pub artifacts: Vec<B1CDriveProductionPreparationCommissionProposalEvidenceArtifact>,
    pub external_authorization_present: bool,
    pub physical_execution_authorized: bool,
    pub non_authority_statement: String,
    pub manifest_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionPreparationCommissionProposalEvidenceVerification {
    pub profile: String,
    pub status: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub formation_commit: String,
    pub proposal_uuid: String,
    pub request_sha256: ContentDigest,
    pub proposal_sha256: ContentDigest,
    pub inherited_plan_sha256: ContentDigest,
    pub artifact_count: u8,
    pub independent_replay_count: u8,
    pub byte_identical_replays: bool,
    pub responsibility_count: u8,
    pub unresolved_gap_count: u8,
    pub external_authorization_present: bool,
    pub physical_preparation_authorized: bool,
    pub effect_account: B1CDriveProductionPreparationEffectAccount,
    pub verification_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B1CDriveProductionPreparationCommissionProposalEvidenceFault {
    pub message: String,
}

impl fmt::Display for B1CDriveProductionPreparationCommissionProposalEvidenceFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for B1CDriveProductionPreparationCommissionProposalEvidenceFault {}

pub fn compile_b1_cdrive_production_preparation_commission_proposal_evidence_verification(
    request: &B1CDriveProductionPreparationCommissionProposalRequest,
    proposal: &B1CDriveProductionPreparationCommissionProposal,
) -> Result<
    B1CDriveProductionPreparationCommissionProposalEvidenceVerification,
    B1CDriveProductionPreparationCommissionProposalEvidenceFault,
> {
    let first = compile_b1_cdrive_production_preparation_commission_proposal(request)
        .map_err(evidence_fault)?;
    let second = compile_b1_cdrive_production_preparation_commission_proposal(request)
        .map_err(evidence_fault)?;
    let first_text =
        to_b1_cdrive_production_preparation_commission_proposal_machine_form(request, &first)
            .map_err(evidence_fault)?;
    let second_text =
        to_b1_cdrive_production_preparation_commission_proposal_machine_form(request, &second)
            .map_err(evidence_fault)?;
    if &first != proposal || first != second || first_text != second_text {
        return Err(evidence_fault("commission proposal double replay differs"));
    }
    let mut verification = B1CDriveProductionPreparationCommissionProposalEvidenceVerification {
        profile: B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_EVIDENCE_VERIFICATION_PROFILE
            .to_owned(),
        status: B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_EVIDENCE_VERIFICATION_STATUS
            .to_owned(),
        source_snapshot_uuid:
            B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_CANONICAL_UUID
            .to_owned(),
        signature_uuid: B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SIGNATURE_UUID
            .to_owned(),
        formation_commit: B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_FORMATION_COMMIT
            .to_owned(),
        proposal_uuid: B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_UUID.to_owned(),
        request_sha256: request.request_sha256.clone(),
        proposal_sha256: proposal.proposal_sha256.clone(),
        inherited_plan_sha256: proposal.inherited_plan_sha256.clone(),
        artifact_count: EXPECTED_ARTIFACTS.len() as u8,
        independent_replay_count: 2,
        byte_identical_replays: true,
        responsibility_count: proposal.responsibilities.len() as u8,
        unresolved_gap_count: proposal.authorization_gaps.len() as u8,
        external_authorization_present: false,
        physical_preparation_authorized: false,
        effect_account: B1CDriveProductionPreparationEffectAccount::default(),
        verification_sha256: empty_digest(),
    };
    verification.verification_sha256 =
        b1_cdrive_production_preparation_commission_proposal_evidence_verification_digest(
            &verification,
        )?;
    validate_verification(&verification)?;
    Ok(verification)
}

pub fn verify_b1_cdrive_production_preparation_commission_proposal_evidence_directory(
    root: &Path,
) -> Result<
    B1CDriveProductionPreparationCommissionProposalEvidenceVerification,
    B1CDriveProductionPreparationCommissionProposalEvidenceFault,
> {
    let metadata = fs::symlink_metadata(root).map_err(evidence_fault)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(evidence_fault(
            "evidence root must be one nonlink nonreparse directory",
        ));
    }
    let actual: BTreeSet<String> = fs::read_dir(root)
        .map_err(evidence_fault)?
        .map(|entry| {
            entry.map_err(evidence_fault).and_then(|entry| {
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| evidence_fault("evidence name is not UTF-8"))
            })
        })
        .collect::<Result<_, _>>()?;
    let expected: BTreeSet<String> = EXPECTED_ARTIFACTS
        .into_iter()
        .map(str::to_owned)
        .chain(std::iter::once("evidence_manifest.json".to_owned()))
        .collect();
    if actual != expected {
        return Err(evidence_fault("evidence directory membership differs"));
    }

    let manifest_text = read_text(root, "evidence_manifest.json")?;
    let manifest: B1CDriveProductionPreparationCommissionProposalEvidenceManifest =
        parse_canonical(&manifest_text)?;
    validate_manifest(&manifest)?;
    let mut texts = BTreeMap::new();
    let mut aggregate = 0_u64;
    for artifact in &manifest.artifacts {
        let bytes = read_bytes(root, &artifact.path)?;
        aggregate = aggregate
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| evidence_fault("aggregate byte count overflowed"))?;
        if aggregate > MAX_AGGREGATE_BYTES
            || bytes.len() as u64 != artifact.bytes
            || sha256_bytes(&bytes) != artifact.sha256
        {
            return Err(evidence_fault(format!(
                "artifact identity differs: {}",
                artifact.path
            )));
        }
        texts.insert(
            artifact.path.clone(),
            String::from_utf8(bytes).map_err(evidence_fault)?,
        );
    }
    let request_text = texts
        .get("request.json")
        .ok_or_else(|| evidence_fault("request artifact absent"))?;
    let request = from_b1_cdrive_production_preparation_commission_proposal_request_machine_form(
        request_text,
    )
    .map_err(evidence_fault)?;
    let proposal_text = texts
        .get("proposal.json")
        .ok_or_else(|| evidence_fault("proposal artifact absent"))?;
    let proposal = from_b1_cdrive_production_preparation_commission_proposal_machine_form(
        &request,
        proposal_text,
    )
    .map_err(evidence_fault)?;
    let recomputed =
        compile_b1_cdrive_production_preparation_commission_proposal_evidence_verification(
            &request, &proposal,
        )?;
    let retained_text = texts
        .get("verification.json")
        .ok_or_else(|| evidence_fault("verification artifact absent"))?;
    let retained =
        from_b1_cdrive_production_preparation_commission_proposal_evidence_verification_machine_form(
            retained_text,
        )?;
    if retained != recomputed
        || to_b1_cdrive_production_preparation_commission_proposal_evidence_verification_machine_form(
            &recomputed,
        )? != *retained_text
    {
        return Err(evidence_fault(
            "retained verification differs from independent replay",
        ));
    }
    Ok(recomputed)
}

pub fn b1_cdrive_production_preparation_commission_proposal_evidence_manifest_digest(
    manifest: &B1CDriveProductionPreparationCommissionProposalEvidenceManifest,
) -> Result<ContentDigest, B1CDriveProductionPreparationCommissionProposalEvidenceFault> {
    let mut normalized = manifest.clone();
    normalized.manifest_sha256 = empty_digest();
    domain_digest(MANIFEST_DOMAIN, &normalized)
}

pub fn b1_cdrive_production_preparation_commission_proposal_evidence_verification_digest(
    verification: &B1CDriveProductionPreparationCommissionProposalEvidenceVerification,
) -> Result<ContentDigest, B1CDriveProductionPreparationCommissionProposalEvidenceFault> {
    let mut normalized = verification.clone();
    normalized.verification_sha256 = empty_digest();
    domain_digest(VERIFICATION_DOMAIN, &normalized)
}

pub fn to_b1_cdrive_production_preparation_commission_proposal_evidence_manifest_machine_form(
    manifest: &B1CDriveProductionPreparationCommissionProposalEvidenceManifest,
) -> Result<String, B1CDriveProductionPreparationCommissionProposalEvidenceFault> {
    validate_manifest(manifest)?;
    serde_json::to_string(manifest).map_err(evidence_fault)
}

pub fn to_b1_cdrive_production_preparation_commission_proposal_evidence_verification_machine_form(
    verification: &B1CDriveProductionPreparationCommissionProposalEvidenceVerification,
) -> Result<String, B1CDriveProductionPreparationCommissionProposalEvidenceFault> {
    validate_verification(verification)?;
    serde_json::to_string(verification).map_err(evidence_fault)
}

pub fn from_b1_cdrive_production_preparation_commission_proposal_evidence_verification_machine_form(
    machine_form: &str,
) -> Result<
    B1CDriveProductionPreparationCommissionProposalEvidenceVerification,
    B1CDriveProductionPreparationCommissionProposalEvidenceFault,
> {
    let verification = parse_canonical(machine_form)?;
    validate_verification(&verification)?;
    Ok(verification)
}

fn validate_manifest(
    manifest: &B1CDriveProductionPreparationCommissionProposalEvidenceManifest,
) -> Result<(), B1CDriveProductionPreparationCommissionProposalEvidenceFault> {
    let paths: Vec<_> = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect();
    if manifest.profile
        != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_EVIDENCE_MANIFEST_PROFILE
        || manifest.source_snapshot_uuid
            != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SOURCE_SNAPSHOT_UUID
        || manifest.canonical_uuid
            != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_CANONICAL_UUID
        || manifest.signature_uuid
            != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SIGNATURE_UUID
        || manifest.formation_commit
            != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_FORMATION_COMMIT
        || manifest.proposal_uuid != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_UUID
        || paths != EXPECTED_ARTIFACTS
        || manifest.artifacts.iter().any(|artifact| {
            artifact.bytes == 0
                || artifact.bytes
                    > B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_MAX_MACHINE_FORM_BYTES
                        as u64
                || artifact.sha256.algorithm != "sha256"
                || !is_lower_hex_64(&artifact.sha256.value)
        })
        || manifest.external_authorization_present
        || manifest.physical_execution_authorized
        || manifest.non_authority_statement.is_empty()
        || manifest.manifest_sha256
            != b1_cdrive_production_preparation_commission_proposal_evidence_manifest_digest(
                manifest,
            )?
    {
        return Err(evidence_fault("evidence manifest differs"));
    }
    Ok(())
}

fn validate_verification(
    verification: &B1CDriveProductionPreparationCommissionProposalEvidenceVerification,
) -> Result<(), B1CDriveProductionPreparationCommissionProposalEvidenceFault> {
    if verification.profile
        != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_EVIDENCE_VERIFICATION_PROFILE
        || verification.status
            != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_EVIDENCE_VERIFICATION_STATUS
        || verification.source_snapshot_uuid
            != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SOURCE_SNAPSHOT_UUID
        || verification.canonical_uuid
            != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_CANONICAL_UUID
        || verification.signature_uuid
            != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SIGNATURE_UUID
        || verification.formation_commit
            != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_FORMATION_COMMIT
        || verification.proposal_uuid != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_UUID
        || verification.artifact_count != 3
        || verification.independent_replay_count != 2
        || !verification.byte_identical_replays
        || verification.responsibility_count != 9
        || verification.unresolved_gap_count != 5
        || verification.external_authorization_present
        || verification.physical_preparation_authorized
        || verification.effect_account != B1CDriveProductionPreparationEffectAccount::default()
        || verification.verification_sha256
            != b1_cdrive_production_preparation_commission_proposal_evidence_verification_digest(
                verification,
            )?
    {
        return Err(evidence_fault("evidence verification differs"));
    }
    Ok(())
}

fn read_text(
    root: &Path,
    name: &str,
) -> Result<String, B1CDriveProductionPreparationCommissionProposalEvidenceFault> {
    String::from_utf8(read_bytes(root, name)?).map_err(evidence_fault)
}

fn read_bytes(
    root: &Path,
    name: &str,
) -> Result<Vec<u8>, B1CDriveProductionPreparationCommissionProposalEvidenceFault> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name == "." || name == ".." {
        return Err(evidence_fault("artifact name differs"));
    }
    let path = root.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(evidence_fault)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || is_reparse_point(&metadata)
        || metadata.len() == 0
        || metadata.len()
            > B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_MAX_MACHINE_FORM_BYTES as u64
    {
        return Err(evidence_fault(
            "artifact must be one bounded nonlink nonreparse regular file",
        ));
    }
    fs::read(path).map_err(evidence_fault)
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

fn parse_canonical<T: DeserializeOwned + Serialize>(
    machine_form: &str,
) -> Result<T, B1CDriveProductionPreparationCommissionProposalEvidenceFault> {
    if machine_form.is_empty()
        || machine_form.len()
            > B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_MAX_MACHINE_FORM_BYTES
    {
        return Err(evidence_fault("machine form byte bound differs"));
    }
    let value: Value = serde_json::from_str(machine_form).map_err(evidence_fault)?;
    let mut fields = 0_usize;
    measure_value(&value, 1, &mut fields)?;
    let parsed: T = serde_json::from_str(machine_form).map_err(evidence_fault)?;
    if serde_json::to_string(&parsed).map_err(evidence_fault)? != machine_form {
        return Err(evidence_fault(
            "machine form is not canonical duplicate-free JSON",
        ));
    }
    Ok(parsed)
}

fn measure_value(
    value: &Value,
    depth: usize,
    fields: &mut usize,
) -> Result<(), B1CDriveProductionPreparationCommissionProposalEvidenceFault> {
    if depth > MAX_JSON_DEPTH {
        return Err(evidence_fault("JSON depth exceeds bound"));
    }
    match value {
        Value::Object(map) => {
            *fields = fields
                .checked_add(map.len())
                .ok_or_else(|| evidence_fault("JSON field count overflowed"))?;
            if *fields > MAX_JSON_FIELDS {
                return Err(evidence_fault("JSON field count exceeds bound"));
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

fn domain_digest<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<ContentDigest, B1CDriveProductionPreparationCommissionProposalEvidenceFault> {
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

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn evidence_fault(
    error: impl fmt::Display,
) -> B1CDriveProductionPreparationCommissionProposalEvidenceFault {
    B1CDriveProductionPreparationCommissionProposalEvidenceFault {
        message: error.to_string(),
    }
}
