//! Independent read-only replay for provider-free ceremony-plan evidence.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::Path,
};

use cantor_core::{ContentDigest, sha256_bytes};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_AUTHORITY,
    B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_CANONICAL_UUID,
    B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_FORMATION_COMMIT,
    B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_MAX_MACHINE_FORM_BYTES,
    B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_SIGNATURE_UUID,
    B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_SOURCE_SNAPSHOT_UUID,
    B1CDriveOperatorAuthorityCeremonyEffectAccount, B1CDriveOperatorAuthorityCeremonyPlan,
    B1CDriveOperatorAuthorityCeremonyRequest, B1CDriveOperatorAuthorityCeremonyVerification,
    from_b1_cdrive_operator_authority_ceremony_plan_machine_form,
    from_b1_cdrive_operator_authority_ceremony_request_machine_form,
    to_b1_cdrive_operator_authority_ceremony_verification_machine_form,
    verify_b1_cdrive_operator_authority_ceremony_plan,
};

pub const B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_EVIDENCE_MANIFEST_PROFILE: &str = "cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-authority-ceremony-plan-evidence/0.1";
pub const B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_EVIDENCE_VERIFICATION_PROFILE: &str = "cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-authority-ceremony-plan-evidence-verification/0.1";
pub const B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_EVIDENCE_STATUS: &str =
    "operator_authority_ceremony_plan_independently_verified_all_live_authorities_unresolved";
pub const B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_NON_AUTHORITY: &str = "Provider-free evidence proves only deterministic ceremony-plan correspondence. It does not prove policy governance, key custody, revocation truth, current time, live authorization, fresh observation, a private execution permit, broker projection, physical preparation, or any runtime effect.";

const MANIFEST_DOMAIN: &str = "cantor.b1.cdrive.operator-authority-ceremony.evidence-manifest.v1";
const EVIDENCE_VERIFICATION_DOMAIN: &str =
    "cantor.b1.cdrive.operator-authority-ceremony.evidence-verification.v1";
const EXPECTED_ARTIFACTS: [&str; 3] = ["plan.json", "request.json", "verification.json"];
const MAX_AGGREGATE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 24;
const MAX_JSON_FIELDS: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveOperatorAuthorityCeremonyEvidenceArtifact {
    pub path: String,
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveOperatorAuthorityCeremonyEvidenceManifest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub formation_commit: String,
    pub artifacts: Vec<B1CDriveOperatorAuthorityCeremonyEvidenceArtifact>,
    pub fixture_only: bool,
    pub physical_execution_authorized: bool,
    pub non_authority_statement: String,
    pub manifest_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveOperatorAuthorityCeremonyEvidenceVerification {
    pub profile: String,
    pub status: String,
    pub authority: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub formation_commit: String,
    pub request_sha256: ContentDigest,
    pub plan_sha256: ContentDigest,
    pub verification_sha256: ContentDigest,
    pub artifact_count: u8,
    pub independent_replay_count: u8,
    pub byte_identical_replays: bool,
    pub role_count: u8,
    pub stage_count: u8,
    pub unresolved_authority_count: u8,
    pub fixture_only: bool,
    pub policy_governance_proved: bool,
    pub key_custody_proved: bool,
    pub revocation_truth_proved: bool,
    pub current_nonexpired: bool,
    pub live_authorization_admitted: bool,
    pub fresh_observation_proved: bool,
    pub private_execution_permit_present: bool,
    pub production_broker_projection_present: bool,
    pub physical_preparation_authorized: bool,
    pub effect_account: B1CDriveOperatorAuthorityCeremonyEffectAccount,
    pub evidence_verification_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B1CDriveOperatorAuthorityCeremonyEvidenceFault {
    pub message: String,
}

impl fmt::Display for B1CDriveOperatorAuthorityCeremonyEvidenceFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for B1CDriveOperatorAuthorityCeremonyEvidenceFault {}

pub fn compile_b1_cdrive_operator_authority_ceremony_evidence_verification(
    request: &B1CDriveOperatorAuthorityCeremonyRequest,
    plan: &B1CDriveOperatorAuthorityCeremonyPlan,
    verification: &B1CDriveOperatorAuthorityCeremonyVerification,
) -> Result<
    B1CDriveOperatorAuthorityCeremonyEvidenceVerification,
    B1CDriveOperatorAuthorityCeremonyEvidenceFault,
> {
    let first =
        verify_b1_cdrive_operator_authority_ceremony_plan(request, plan).map_err(evidence_fault)?;
    let second =
        verify_b1_cdrive_operator_authority_ceremony_plan(request, plan).map_err(evidence_fault)?;
    let first_text =
        to_b1_cdrive_operator_authority_ceremony_verification_machine_form(request, plan, &first)
            .map_err(evidence_fault)?;
    let second_text =
        to_b1_cdrive_operator_authority_ceremony_verification_machine_form(request, plan, &second)
            .map_err(evidence_fault)?;
    if &first != verification || first != second || first_text != second_text {
        return Err(evidence_fault(
            "ceremony verification double replay differs",
        ));
    }

    let mut evidence = B1CDriveOperatorAuthorityCeremonyEvidenceVerification {
        profile: B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_EVIDENCE_VERIFICATION_PROFILE.to_owned(),
        status: B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_EVIDENCE_STATUS.to_owned(),
        authority: B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_AUTHORITY.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_CANONICAL_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_SIGNATURE_UUID.to_owned(),
        formation_commit: B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_FORMATION_COMMIT.to_owned(),
        request_sha256: request.request_sha256.clone(),
        plan_sha256: plan.plan_sha256.clone(),
        verification_sha256: verification.verification_sha256.clone(),
        artifact_count: EXPECTED_ARTIFACTS.len() as u8,
        independent_replay_count: 2,
        byte_identical_replays: true,
        role_count: 8,
        stage_count: 9,
        unresolved_authority_count: 9,
        fixture_only: true,
        policy_governance_proved: false,
        key_custody_proved: false,
        revocation_truth_proved: false,
        current_nonexpired: false,
        live_authorization_admitted: false,
        fresh_observation_proved: false,
        private_execution_permit_present: false,
        production_broker_projection_present: false,
        physical_preparation_authorized: false,
        effect_account: B1CDriveOperatorAuthorityCeremonyEffectAccount::default(),
        evidence_verification_sha256: empty_digest(),
    };
    evidence.evidence_verification_sha256 =
        b1_cdrive_operator_authority_ceremony_evidence_verification_digest(&evidence)?;
    validate_evidence_verification(&evidence)?;
    Ok(evidence)
}

pub fn verify_b1_cdrive_operator_authority_ceremony_evidence_directory(
    root: &Path,
) -> Result<
    B1CDriveOperatorAuthorityCeremonyEvidenceVerification,
    B1CDriveOperatorAuthorityCeremonyEvidenceFault,
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
    let manifest: B1CDriveOperatorAuthorityCeremonyEvidenceManifest =
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
    let request = from_b1_cdrive_operator_authority_ceremony_request_machine_form(request_text)
        .map_err(evidence_fault)?;
    let plan_text = texts
        .get("plan.json")
        .ok_or_else(|| evidence_fault("plan artifact absent"))?;
    let plan = from_b1_cdrive_operator_authority_ceremony_plan_machine_form(&request, plan_text)
        .map_err(evidence_fault)?;
    let verification_text = texts
        .get("verification.json")
        .ok_or_else(|| evidence_fault("verification artifact absent"))?;
    let verification: B1CDriveOperatorAuthorityCeremonyVerification =
        parse_canonical(verification_text)?;
    let recomputed_core = verify_b1_cdrive_operator_authority_ceremony_plan(&request, &plan)
        .map_err(evidence_fault)?;
    let canonical_core = to_b1_cdrive_operator_authority_ceremony_verification_machine_form(
        &request,
        &plan,
        &recomputed_core,
    )
    .map_err(evidence_fault)?;
    if verification != recomputed_core || canonical_core != *verification_text {
        return Err(evidence_fault(
            "retained ceremony verification differs from replay",
        ));
    }
    compile_b1_cdrive_operator_authority_ceremony_evidence_verification(
        &request,
        &plan,
        &verification,
    )
}

pub fn b1_cdrive_operator_authority_ceremony_evidence_manifest_digest(
    manifest: &B1CDriveOperatorAuthorityCeremonyEvidenceManifest,
) -> Result<ContentDigest, B1CDriveOperatorAuthorityCeremonyEvidenceFault> {
    let mut normalized = manifest.clone();
    normalized.manifest_sha256 = empty_digest();
    domain_digest(MANIFEST_DOMAIN, &normalized)
}

pub fn b1_cdrive_operator_authority_ceremony_evidence_verification_digest(
    verification: &B1CDriveOperatorAuthorityCeremonyEvidenceVerification,
) -> Result<ContentDigest, B1CDriveOperatorAuthorityCeremonyEvidenceFault> {
    let mut normalized = verification.clone();
    normalized.evidence_verification_sha256 = empty_digest();
    domain_digest(EVIDENCE_VERIFICATION_DOMAIN, &normalized)
}

pub fn to_b1_cdrive_operator_authority_ceremony_evidence_manifest_machine_form(
    manifest: &B1CDriveOperatorAuthorityCeremonyEvidenceManifest,
) -> Result<String, B1CDriveOperatorAuthorityCeremonyEvidenceFault> {
    validate_manifest(manifest)?;
    serde_json::to_string(manifest).map_err(evidence_fault)
}

pub fn to_b1_cdrive_operator_authority_ceremony_evidence_verification_machine_form(
    verification: &B1CDriveOperatorAuthorityCeremonyEvidenceVerification,
) -> Result<String, B1CDriveOperatorAuthorityCeremonyEvidenceFault> {
    validate_evidence_verification(verification)?;
    serde_json::to_string(verification).map_err(evidence_fault)
}

fn validate_manifest(
    manifest: &B1CDriveOperatorAuthorityCeremonyEvidenceManifest,
) -> Result<(), B1CDriveOperatorAuthorityCeremonyEvidenceFault> {
    let paths: Vec<_> = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect();
    if manifest.profile != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_EVIDENCE_MANIFEST_PROFILE
        || manifest.source_snapshot_uuid
            != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_SOURCE_SNAPSHOT_UUID
        || manifest.canonical_uuid != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_CANONICAL_UUID
        || manifest.signature_uuid != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_SIGNATURE_UUID
        || manifest.formation_commit != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_FORMATION_COMMIT
        || paths != EXPECTED_ARTIFACTS
        || !manifest.fixture_only
        || manifest.physical_execution_authorized
        || manifest.non_authority_statement != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_NON_AUTHORITY
        || manifest.artifacts.iter().any(|artifact| {
            artifact.bytes == 0
                || artifact.bytes
                    > B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_MAX_MACHINE_FORM_BYTES as u64
                || artifact.sha256.algorithm != "sha256"
                || artifact.sha256.value.len() != 64
                || !artifact
                    .sha256
                    .value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return Err(evidence_fault("ceremony evidence manifest differs"));
    }
    if manifest.manifest_sha256
        != b1_cdrive_operator_authority_ceremony_evidence_manifest_digest(manifest)?
    {
        return Err(evidence_fault("ceremony evidence manifest digest differs"));
    }
    Ok(())
}

fn validate_evidence_verification(
    verification: &B1CDriveOperatorAuthorityCeremonyEvidenceVerification,
) -> Result<(), B1CDriveOperatorAuthorityCeremonyEvidenceFault> {
    if verification.profile != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_EVIDENCE_VERIFICATION_PROFILE
        || verification.status != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_EVIDENCE_STATUS
        || verification.authority != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_AUTHORITY
        || verification.source_snapshot_uuid
            != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_SOURCE_SNAPSHOT_UUID
        || verification.canonical_uuid != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_CANONICAL_UUID
        || verification.signature_uuid != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_SIGNATURE_UUID
        || verification.formation_commit != B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_FORMATION_COMMIT
        || verification.artifact_count != 3
        || verification.independent_replay_count != 2
        || !verification.byte_identical_replays
        || verification.role_count != 8
        || verification.stage_count != 9
        || verification.unresolved_authority_count != 9
        || !verification.fixture_only
        || verification.policy_governance_proved
        || verification.key_custody_proved
        || verification.revocation_truth_proved
        || verification.current_nonexpired
        || verification.live_authorization_admitted
        || verification.fresh_observation_proved
        || verification.private_execution_permit_present
        || verification.production_broker_projection_present
        || verification.physical_preparation_authorized
        || verification.effect_account != B1CDriveOperatorAuthorityCeremonyEffectAccount::default()
    {
        return Err(evidence_fault(
            "ceremony evidence verification truth differs",
        ));
    }
    if verification.evidence_verification_sha256
        != b1_cdrive_operator_authority_ceremony_evidence_verification_digest(verification)?
    {
        return Err(evidence_fault(
            "ceremony evidence verification digest differs",
        ));
    }
    Ok(())
}

fn read_text(
    root: &Path,
    name: &str,
) -> Result<String, B1CDriveOperatorAuthorityCeremonyEvidenceFault> {
    String::from_utf8(read_bytes(root, name)?).map_err(evidence_fault)
}

fn read_bytes(
    root: &Path,
    name: &str,
) -> Result<Vec<u8>, B1CDriveOperatorAuthorityCeremonyEvidenceFault> {
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(evidence_fault("evidence name is not simple"));
    }
    let path = root.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(evidence_fault)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_MAX_MACHINE_FORM_BYTES as u64
    {
        return Err(evidence_fault(
            "evidence artifact is not bounded regular data",
        ));
    }
    fs::read(path).map_err(evidence_fault)
}

fn parse_canonical<T: DeserializeOwned + Serialize>(
    text: &str,
) -> Result<T, B1CDriveOperatorAuthorityCeremonyEvidenceFault> {
    if text.is_empty() || text.len() > B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_MAX_MACHINE_FORM_BYTES
    {
        return Err(evidence_fault(
            "ceremony evidence machine-form bound differs",
        ));
    }
    let value: serde_json::Value = serde_json::from_str(text).map_err(evidence_fault)?;
    let mut fields = 0_usize;
    measure_value(&value, 1, &mut fields)?;
    let parsed: T = serde_json::from_str(text).map_err(evidence_fault)?;
    if serde_json::to_string(&parsed).map_err(evidence_fault)? != text {
        return Err(evidence_fault(
            "ceremony evidence form is not canonical duplicate-free JSON",
        ));
    }
    Ok(parsed)
}

fn measure_value(
    value: &serde_json::Value,
    depth: usize,
    fields: &mut usize,
) -> Result<(), B1CDriveOperatorAuthorityCeremonyEvidenceFault> {
    if depth > MAX_JSON_DEPTH {
        return Err(evidence_fault("ceremony evidence JSON depth exceeds bound"));
    }
    match value {
        serde_json::Value::Object(map) => {
            *fields = fields
                .checked_add(map.len())
                .ok_or_else(|| evidence_fault("ceremony evidence field count overflowed"))?;
            if *fields > MAX_JSON_FIELDS {
                return Err(evidence_fault(
                    "ceremony evidence field count exceeds bound",
                ));
            }
            for child in map.values() {
                measure_value(child, depth + 1, fields)?;
            }
        }
        serde_json::Value::Array(values) => {
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
) -> Result<ContentDigest, B1CDriveOperatorAuthorityCeremonyEvidenceFault> {
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

fn evidence_fault(error: impl fmt::Display) -> B1CDriveOperatorAuthorityCeremonyEvidenceFault {
    B1CDriveOperatorAuthorityCeremonyEvidenceFault {
        message: error.to_string(),
    }
}
