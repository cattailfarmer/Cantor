//! Independent read-only evidence replay for the B1 preparation plan.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::Path,
};

use cantor_core::{ContentDigest, sha256_bytes};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    B1_CDRIVE_PRODUCTION_PREPARATION_CANONICAL_UUID,
    B1_CDRIVE_PRODUCTION_PREPARATION_FORMATION_COMMIT,
    B1_CDRIVE_PRODUCTION_PREPARATION_MAX_MACHINE_FORM_BYTES,
    B1_CDRIVE_PRODUCTION_PREPARATION_SIGNATURE_UUID,
    B1_CDRIVE_PRODUCTION_PREPARATION_SOURCE_SNAPSHOT_UUID,
    B1CDriveProductionPreparationEffectAccount, B1CDriveProductionPreparationPlan,
    B1CDriveProductionPreparationPlanRequest, compile_b1_cdrive_production_preparation_plan,
    from_b1_cdrive_production_preparation_plan_machine_form,
    from_b1_cdrive_production_preparation_request_machine_form,
    to_b1_cdrive_production_preparation_plan_machine_form,
};

pub const B1_CDRIVE_PRODUCTION_PREPARATION_EVIDENCE_MANIFEST_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-production-preparation-plan-evidence/0.1";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_EVIDENCE_VERIFICATION_PROFILE: &str = "cantor-self-work-update-broker-b1-cdrive-production-preparation-plan-evidence-verification/0.1";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_EVIDENCE_VERIFICATION_STATUS: &str =
    "production_preparation_plan_independently_verified_physical_preparation_not_authorized";

const MANIFEST_DOMAIN: &str = "cantor.b1.cdrive.production-preparation-plan.evidence-manifest.v1";
const VERIFICATION_DOMAIN: &str =
    "cantor.b1.cdrive.production-preparation-plan.evidence-verification.v1";
const EXPECTED_ARTIFACTS: [&str; 3] = ["plan.json", "request.json", "verification.json"];
const MAX_AGGREGATE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionPreparationEvidenceArtifact {
    pub path: String,
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionPreparationEvidenceManifest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub formation_commit: String,
    pub artifacts: Vec<B1CDriveProductionPreparationEvidenceArtifact>,
    pub physical_execution_authorized: bool,
    pub non_authority_statement: String,
    pub manifest_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionPreparationEvidenceVerification {
    pub profile: String,
    pub status: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub formation_commit: String,
    pub request_sha256: ContentDigest,
    pub plan_sha256: ContentDigest,
    pub artifact_count: u8,
    pub independent_replay_count: u8,
    pub byte_identical_replays: bool,
    pub physical_preparation_authorized: bool,
    pub effect_account: B1CDriveProductionPreparationEffectAccount,
    pub verification_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B1CDriveProductionPreparationEvidenceFault {
    pub message: String,
}

impl fmt::Display for B1CDriveProductionPreparationEvidenceFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for B1CDriveProductionPreparationEvidenceFault {}

pub fn compile_b1_cdrive_production_preparation_evidence_verification(
    request: &B1CDriveProductionPreparationPlanRequest,
    plan: &B1CDriveProductionPreparationPlan,
) -> Result<
    B1CDriveProductionPreparationEvidenceVerification,
    B1CDriveProductionPreparationEvidenceFault,
> {
    let first = compile_b1_cdrive_production_preparation_plan(request).map_err(evidence_fault)?;
    let second = compile_b1_cdrive_production_preparation_plan(request).map_err(evidence_fault)?;
    let first_text = to_b1_cdrive_production_preparation_plan_machine_form(request, &first)
        .map_err(evidence_fault)?;
    let second_text = to_b1_cdrive_production_preparation_plan_machine_form(request, &second)
        .map_err(evidence_fault)?;
    if &first != plan || first != second || first_text != second_text {
        return Err(evidence_fault("preparation plan double replay differs"));
    }
    let mut verification = B1CDriveProductionPreparationEvidenceVerification {
        profile: B1_CDRIVE_PRODUCTION_PREPARATION_EVIDENCE_VERIFICATION_PROFILE.to_owned(),
        status: B1_CDRIVE_PRODUCTION_PREPARATION_EVIDENCE_VERIFICATION_STATUS.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_PRODUCTION_PREPARATION_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: B1_CDRIVE_PRODUCTION_PREPARATION_CANONICAL_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_PRODUCTION_PREPARATION_SIGNATURE_UUID.to_owned(),
        formation_commit: B1_CDRIVE_PRODUCTION_PREPARATION_FORMATION_COMMIT.to_owned(),
        request_sha256: request.request_sha256.clone(),
        plan_sha256: plan.plan_sha256.clone(),
        artifact_count: EXPECTED_ARTIFACTS.len() as u8,
        independent_replay_count: 2,
        byte_identical_replays: true,
        physical_preparation_authorized: false,
        effect_account: B1CDriveProductionPreparationEffectAccount::default(),
        verification_sha256: empty_digest(),
    };
    verification.verification_sha256 =
        b1_cdrive_production_preparation_evidence_verification_digest(&verification)?;
    Ok(verification)
}

pub fn verify_b1_cdrive_production_preparation_evidence_directory(
    root: &Path,
) -> Result<
    B1CDriveProductionPreparationEvidenceVerification,
    B1CDriveProductionPreparationEvidenceFault,
> {
    let metadata = fs::symlink_metadata(root).map_err(evidence_fault)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(evidence_fault(
            "evidence root must be one nonlink directory",
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
    let manifest: B1CDriveProductionPreparationEvidenceManifest = parse_canonical(&manifest_text)?;
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
    let request = from_b1_cdrive_production_preparation_request_machine_form(request_text)
        .map_err(evidence_fault)?;
    let plan_text = texts
        .get("plan.json")
        .ok_or_else(|| evidence_fault("plan artifact absent"))?;
    let plan = from_b1_cdrive_production_preparation_plan_machine_form(&request, plan_text)
        .map_err(evidence_fault)?;
    let recomputed =
        compile_b1_cdrive_production_preparation_evidence_verification(&request, &plan)?;
    let retained_text = texts
        .get("verification.json")
        .ok_or_else(|| evidence_fault("verification artifact absent"))?;
    let retained =
        from_b1_cdrive_production_preparation_evidence_verification_machine_form(retained_text)?;
    if retained != recomputed
        || to_b1_cdrive_production_preparation_evidence_verification_machine_form(&recomputed)?
            != *retained_text
    {
        return Err(evidence_fault(
            "retained verification differs from independent replay",
        ));
    }
    Ok(recomputed)
}

pub fn b1_cdrive_production_preparation_evidence_manifest_digest(
    manifest: &B1CDriveProductionPreparationEvidenceManifest,
) -> Result<ContentDigest, B1CDriveProductionPreparationEvidenceFault> {
    let mut normalized = manifest.clone();
    normalized.manifest_sha256 = empty_digest();
    domain_digest(MANIFEST_DOMAIN, &normalized)
}

pub fn b1_cdrive_production_preparation_evidence_verification_digest(
    verification: &B1CDriveProductionPreparationEvidenceVerification,
) -> Result<ContentDigest, B1CDriveProductionPreparationEvidenceFault> {
    let mut normalized = verification.clone();
    normalized.verification_sha256 = empty_digest();
    domain_digest(VERIFICATION_DOMAIN, &normalized)
}

pub fn to_b1_cdrive_production_preparation_evidence_manifest_machine_form(
    manifest: &B1CDriveProductionPreparationEvidenceManifest,
) -> Result<String, B1CDriveProductionPreparationEvidenceFault> {
    validate_manifest(manifest)?;
    serde_json::to_string(manifest).map_err(evidence_fault)
}

pub fn to_b1_cdrive_production_preparation_evidence_verification_machine_form(
    verification: &B1CDriveProductionPreparationEvidenceVerification,
) -> Result<String, B1CDriveProductionPreparationEvidenceFault> {
    validate_verification(verification)?;
    serde_json::to_string(verification).map_err(evidence_fault)
}

pub fn from_b1_cdrive_production_preparation_evidence_verification_machine_form(
    machine_form: &str,
) -> Result<
    B1CDriveProductionPreparationEvidenceVerification,
    B1CDriveProductionPreparationEvidenceFault,
> {
    let verification = parse_canonical(machine_form)?;
    validate_verification(&verification)?;
    Ok(verification)
}

fn validate_manifest(
    manifest: &B1CDriveProductionPreparationEvidenceManifest,
) -> Result<(), B1CDriveProductionPreparationEvidenceFault> {
    let paths: Vec<_> = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect();
    if manifest.profile != B1_CDRIVE_PRODUCTION_PREPARATION_EVIDENCE_MANIFEST_PROFILE
        || manifest.source_snapshot_uuid != B1_CDRIVE_PRODUCTION_PREPARATION_SOURCE_SNAPSHOT_UUID
        || manifest.canonical_uuid != B1_CDRIVE_PRODUCTION_PREPARATION_CANONICAL_UUID
        || manifest.signature_uuid != B1_CDRIVE_PRODUCTION_PREPARATION_SIGNATURE_UUID
        || manifest.formation_commit != B1_CDRIVE_PRODUCTION_PREPARATION_FORMATION_COMMIT
        || paths != EXPECTED_ARTIFACTS
        || manifest.artifacts.iter().any(|artifact| {
            artifact.bytes == 0
                || artifact.bytes > B1_CDRIVE_PRODUCTION_PREPARATION_MAX_MACHINE_FORM_BYTES as u64
                || artifact.sha256.algorithm != "sha256"
                || artifact.sha256.value.len() != 64
        })
        || manifest.physical_execution_authorized
        || manifest.non_authority_statement.is_empty()
        || manifest.manifest_sha256
            != b1_cdrive_production_preparation_evidence_manifest_digest(manifest)?
    {
        return Err(evidence_fault("evidence manifest differs"));
    }
    Ok(())
}

fn validate_verification(
    verification: &B1CDriveProductionPreparationEvidenceVerification,
) -> Result<(), B1CDriveProductionPreparationEvidenceFault> {
    if verification.profile != B1_CDRIVE_PRODUCTION_PREPARATION_EVIDENCE_VERIFICATION_PROFILE
        || verification.status != B1_CDRIVE_PRODUCTION_PREPARATION_EVIDENCE_VERIFICATION_STATUS
        || verification.source_snapshot_uuid
            != B1_CDRIVE_PRODUCTION_PREPARATION_SOURCE_SNAPSHOT_UUID
        || verification.canonical_uuid != B1_CDRIVE_PRODUCTION_PREPARATION_CANONICAL_UUID
        || verification.signature_uuid != B1_CDRIVE_PRODUCTION_PREPARATION_SIGNATURE_UUID
        || verification.formation_commit != B1_CDRIVE_PRODUCTION_PREPARATION_FORMATION_COMMIT
        || verification.artifact_count != 3
        || verification.independent_replay_count != 2
        || !verification.byte_identical_replays
        || verification.physical_preparation_authorized
        || verification.effect_account != B1CDriveProductionPreparationEffectAccount::default()
        || verification.verification_sha256
            != b1_cdrive_production_preparation_evidence_verification_digest(verification)?
    {
        return Err(evidence_fault("evidence verification differs"));
    }
    Ok(())
}

fn read_text(
    root: &Path,
    name: &str,
) -> Result<String, B1CDriveProductionPreparationEvidenceFault> {
    String::from_utf8(read_bytes(root, name)?).map_err(evidence_fault)
}

fn read_bytes(
    root: &Path,
    name: &str,
) -> Result<Vec<u8>, B1CDriveProductionPreparationEvidenceFault> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name == "." || name == ".." {
        return Err(evidence_fault("artifact name differs"));
    }
    let path = root.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(evidence_fault)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > B1_CDRIVE_PRODUCTION_PREPARATION_MAX_MACHINE_FORM_BYTES as u64
    {
        return Err(evidence_fault(
            "artifact must be one bounded nonlink regular file",
        ));
    }
    fs::read(path).map_err(evidence_fault)
}

fn parse_canonical<T: DeserializeOwned + Serialize>(
    machine_form: &str,
) -> Result<T, B1CDriveProductionPreparationEvidenceFault> {
    if machine_form.is_empty()
        || machine_form.len() > B1_CDRIVE_PRODUCTION_PREPARATION_MAX_MACHINE_FORM_BYTES
    {
        return Err(evidence_fault("machine form byte bound differs"));
    }
    let parsed: T = serde_json::from_str(machine_form).map_err(evidence_fault)?;
    if serde_json::to_string(&parsed).map_err(evidence_fault)? != machine_form {
        return Err(evidence_fault(
            "machine form is not canonical duplicate-free JSON",
        ));
    }
    Ok(parsed)
}

fn domain_digest<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<ContentDigest, B1CDriveProductionPreparationEvidenceFault> {
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
fn evidence_fault(error: impl fmt::Display) -> B1CDriveProductionPreparationEvidenceFault {
    B1CDriveProductionPreparationEvidenceFault {
        message: error.to_string(),
    }
}
