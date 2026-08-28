//! Independent read-only evidence replay for B1 operator decision verification.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::Path,
};

use cantor_core::{ContentDigest, sha256_bytes};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{
    B1_CDRIVE_OPERATOR_DECISION_CANONICAL_UUID, B1_CDRIVE_OPERATOR_DECISION_FORMATION_COMMIT,
    B1_CDRIVE_OPERATOR_DECISION_MAX_MACHINE_FORM_BYTES, B1_CDRIVE_OPERATOR_DECISION_SIGNATURE_UUID,
    B1_CDRIVE_OPERATOR_DECISION_SOURCE_SNAPSHOT_UUID, B1CDriveOperatorDecisionEffectAccount,
    B1CDriveOperatorDecisionEnvelope, B1CDriveOperatorDecisionKind, B1CDriveOperatorDecisionPolicy,
    B1CDriveOperatorDecisionRequest, B1CDriveOperatorDecisionVerification,
    from_b1_cdrive_operator_decision_envelope_machine_form,
    from_b1_cdrive_operator_decision_policy_machine_form,
    from_b1_cdrive_operator_decision_request_machine_form,
    from_b1_cdrive_operator_decision_verification_machine_form,
    to_b1_cdrive_operator_decision_verification_machine_form, verify_b1_cdrive_operator_decision,
};

pub const B1_CDRIVE_OPERATOR_DECISION_EVIDENCE_MANIFEST_PROFILE: &str = "cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-decision-evidence/0.1";
pub const B1_CDRIVE_OPERATOR_DECISION_EVIDENCE_VERIFICATION_PROFILE: &str = "cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-decision-evidence-verification/0.1";
pub const B1_CDRIVE_OPERATOR_DECISION_EVIDENCE_VERIFICATION_STATUS: &str =
    "operator_authorize_and_reject_correspondence_independently_verified_without_live_authority";

const MANIFEST_DOMAIN: &str =
    "cantor.b1.cdrive.production-preparation.operator-decision.evidence-manifest.v1";
const VERIFICATION_DOMAIN: &str =
    "cantor.b1.cdrive.production-preparation.operator-decision.evidence-verification.v1";
const EXPECTED_ARTIFACTS: [&str; 6] = [
    "policy.json",
    "request.json",
    "authorize_decision.json",
    "reject_decision.json",
    "authorize_verification.json",
    "reject_verification.json",
];
const MAX_AGGREGATE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 24;
const MAX_JSON_FIELDS: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveOperatorDecisionEvidenceArtifact {
    pub path: String,
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveOperatorDecisionEvidenceManifest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub formation_commit: String,
    pub artifacts: Vec<B1CDriveOperatorDecisionEvidenceArtifact>,
    pub fixture_only: bool,
    pub live_authorization_admitted: bool,
    pub physical_execution_authorized: bool,
    pub non_authority_statement: String,
    pub manifest_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveOperatorDecisionEvidenceVerification {
    pub profile: String,
    pub status: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub formation_commit: String,
    pub policy_sha256: ContentDigest,
    pub request_sha256: ContentDigest,
    pub authorize_decision_sha256: ContentDigest,
    pub reject_decision_sha256: ContentDigest,
    pub authorize_verification_sha256: ContentDigest,
    pub reject_verification_sha256: ContentDigest,
    pub artifact_count: u8,
    pub decision_count: u8,
    pub independent_replay_count: u8,
    pub byte_identical_replays: bool,
    pub signature_correspondence_verified: bool,
    pub fixture_only: bool,
    pub policy_governance_proved: bool,
    pub current_nonexpired: bool,
    pub live_authorization_admitted: bool,
    pub fresh_observation_proved: bool,
    pub private_execution_permit_present: bool,
    pub physical_preparation_authorized: bool,
    pub production_broker_projection_present: bool,
    pub effect_account: B1CDriveOperatorDecisionEffectAccount,
    pub verification_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B1CDriveOperatorDecisionEvidenceFault {
    pub message: String,
}

impl fmt::Display for B1CDriveOperatorDecisionEvidenceFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for B1CDriveOperatorDecisionEvidenceFault {}

pub fn compile_b1_cdrive_operator_decision_evidence_verification(
    policy: &B1CDriveOperatorDecisionPolicy,
    request: &B1CDriveOperatorDecisionRequest,
    authorize: &B1CDriveOperatorDecisionEnvelope,
    reject: &B1CDriveOperatorDecisionEnvelope,
    retained_authorize: &B1CDriveOperatorDecisionVerification,
    retained_reject: &B1CDriveOperatorDecisionVerification,
) -> Result<B1CDriveOperatorDecisionEvidenceVerification, B1CDriveOperatorDecisionEvidenceFault> {
    let authorize_first =
        verify_b1_cdrive_operator_decision(request, policy, authorize).map_err(evidence_fault)?;
    let authorize_second =
        verify_b1_cdrive_operator_decision(request, policy, authorize).map_err(evidence_fault)?;
    let reject_first =
        verify_b1_cdrive_operator_decision(request, policy, reject).map_err(evidence_fault)?;
    let reject_second =
        verify_b1_cdrive_operator_decision(request, policy, reject).map_err(evidence_fault)?;
    let authorize_first_text = to_b1_cdrive_operator_decision_verification_machine_form(
        request,
        policy,
        authorize,
        &authorize_first,
    )
    .map_err(evidence_fault)?;
    let authorize_second_text = to_b1_cdrive_operator_decision_verification_machine_form(
        request,
        policy,
        authorize,
        &authorize_second,
    )
    .map_err(evidence_fault)?;
    let reject_first_text = to_b1_cdrive_operator_decision_verification_machine_form(
        request,
        policy,
        reject,
        &reject_first,
    )
    .map_err(evidence_fault)?;
    let reject_second_text = to_b1_cdrive_operator_decision_verification_machine_form(
        request,
        policy,
        reject,
        &reject_second,
    )
    .map_err(evidence_fault)?;
    if authorize.payload.decision_kind != B1CDriveOperatorDecisionKind::Authorize
        || reject.payload.decision_kind != B1CDriveOperatorDecisionKind::Reject
        || authorize.payload.decision_uuid == reject.payload.decision_uuid
        || &authorize_first != retained_authorize
        || &reject_first != retained_reject
        || authorize_first != authorize_second
        || reject_first != reject_second
        || authorize_first_text != authorize_second_text
        || reject_first_text != reject_second_text
    {
        return Err(evidence_fault(
            "authorize or reject independent double replay differs",
        ));
    }
    let mut verification = B1CDriveOperatorDecisionEvidenceVerification {
        profile: B1_CDRIVE_OPERATOR_DECISION_EVIDENCE_VERIFICATION_PROFILE.to_owned(),
        status: B1_CDRIVE_OPERATOR_DECISION_EVIDENCE_VERIFICATION_STATUS.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_OPERATOR_DECISION_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: B1_CDRIVE_OPERATOR_DECISION_CANONICAL_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_OPERATOR_DECISION_SIGNATURE_UUID.to_owned(),
        formation_commit: B1_CDRIVE_OPERATOR_DECISION_FORMATION_COMMIT.to_owned(),
        policy_sha256: policy.policy_sha256.clone(),
        request_sha256: request.request_sha256.clone(),
        authorize_decision_sha256: authorize.envelope_sha256.clone(),
        reject_decision_sha256: reject.envelope_sha256.clone(),
        authorize_verification_sha256: retained_authorize.verification_sha256.clone(),
        reject_verification_sha256: retained_reject.verification_sha256.clone(),
        artifact_count: EXPECTED_ARTIFACTS.len() as u8,
        decision_count: 2,
        independent_replay_count: 4,
        byte_identical_replays: true,
        signature_correspondence_verified: true,
        fixture_only: true,
        policy_governance_proved: false,
        current_nonexpired: false,
        live_authorization_admitted: false,
        fresh_observation_proved: false,
        private_execution_permit_present: false,
        physical_preparation_authorized: false,
        production_broker_projection_present: false,
        effect_account: B1CDriveOperatorDecisionEffectAccount::default(),
        verification_sha256: empty_digest(),
    };
    verification.verification_sha256 =
        b1_cdrive_operator_decision_evidence_verification_digest(&verification)?;
    validate_verification(&verification)?;
    Ok(verification)
}

pub fn verify_b1_cdrive_operator_decision_evidence_directory(
    root: &Path,
) -> Result<B1CDriveOperatorDecisionEvidenceVerification, B1CDriveOperatorDecisionEvidenceFault> {
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
    let manifest: B1CDriveOperatorDecisionEvidenceManifest = parse_canonical(&manifest_text)?;
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
    let policy_text = artifact_text(&texts, "policy.json")?;
    let policy = from_b1_cdrive_operator_decision_policy_machine_form(policy_text)
        .map_err(evidence_fault)?;
    let request_text = artifact_text(&texts, "request.json")?;
    let request = from_b1_cdrive_operator_decision_request_machine_form(&policy, request_text)
        .map_err(evidence_fault)?;
    let authorize_text = artifact_text(&texts, "authorize_decision.json")?;
    let authorize =
        from_b1_cdrive_operator_decision_envelope_machine_form(&request, &policy, authorize_text)
            .map_err(evidence_fault)?;
    let reject_text = artifact_text(&texts, "reject_decision.json")?;
    let reject =
        from_b1_cdrive_operator_decision_envelope_machine_form(&request, &policy, reject_text)
            .map_err(evidence_fault)?;
    let authorize_verification_text = artifact_text(&texts, "authorize_verification.json")?;
    let authorize_verification = from_b1_cdrive_operator_decision_verification_machine_form(
        &request,
        &policy,
        &authorize,
        authorize_verification_text,
    )
    .map_err(evidence_fault)?;
    let reject_verification_text = artifact_text(&texts, "reject_verification.json")?;
    let reject_verification = from_b1_cdrive_operator_decision_verification_machine_form(
        &request,
        &policy,
        &reject,
        reject_verification_text,
    )
    .map_err(evidence_fault)?;
    let recomputed = compile_b1_cdrive_operator_decision_evidence_verification(
        &policy,
        &request,
        &authorize,
        &reject,
        &authorize_verification,
        &reject_verification,
    )?;
    if to_b1_cdrive_operator_decision_verification_machine_form(
        &request,
        &policy,
        &authorize,
        &authorize_verification,
    )
    .map_err(evidence_fault)?
        != *authorize_verification_text
        || to_b1_cdrive_operator_decision_verification_machine_form(
            &request,
            &policy,
            &reject,
            &reject_verification,
        )
        .map_err(evidence_fault)?
            != *reject_verification_text
    {
        return Err(evidence_fault(
            "retained verification bytes differ from canonical replay",
        ));
    }
    Ok(recomputed)
}

pub fn b1_cdrive_operator_decision_evidence_manifest_digest(
    manifest: &B1CDriveOperatorDecisionEvidenceManifest,
) -> Result<ContentDigest, B1CDriveOperatorDecisionEvidenceFault> {
    let mut normalized = manifest.clone();
    normalized.manifest_sha256 = empty_digest();
    domain_digest(MANIFEST_DOMAIN, &normalized)
}

pub fn b1_cdrive_operator_decision_evidence_verification_digest(
    verification: &B1CDriveOperatorDecisionEvidenceVerification,
) -> Result<ContentDigest, B1CDriveOperatorDecisionEvidenceFault> {
    let mut normalized = verification.clone();
    normalized.verification_sha256 = empty_digest();
    domain_digest(VERIFICATION_DOMAIN, &normalized)
}

pub fn to_b1_cdrive_operator_decision_evidence_manifest_machine_form(
    manifest: &B1CDriveOperatorDecisionEvidenceManifest,
) -> Result<String, B1CDriveOperatorDecisionEvidenceFault> {
    validate_manifest(manifest)?;
    serde_json::to_string(manifest).map_err(evidence_fault)
}

pub fn to_b1_cdrive_operator_decision_evidence_verification_machine_form(
    verification: &B1CDriveOperatorDecisionEvidenceVerification,
) -> Result<String, B1CDriveOperatorDecisionEvidenceFault> {
    validate_verification(verification)?;
    serde_json::to_string(verification).map_err(evidence_fault)
}

fn validate_manifest(
    manifest: &B1CDriveOperatorDecisionEvidenceManifest,
) -> Result<(), B1CDriveOperatorDecisionEvidenceFault> {
    let paths: Vec<_> = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect();
    if manifest.profile != B1_CDRIVE_OPERATOR_DECISION_EVIDENCE_MANIFEST_PROFILE
        || manifest.source_snapshot_uuid != B1_CDRIVE_OPERATOR_DECISION_SOURCE_SNAPSHOT_UUID
        || manifest.canonical_uuid != B1_CDRIVE_OPERATOR_DECISION_CANONICAL_UUID
        || manifest.signature_uuid != B1_CDRIVE_OPERATOR_DECISION_SIGNATURE_UUID
        || manifest.formation_commit != B1_CDRIVE_OPERATOR_DECISION_FORMATION_COMMIT
        || paths != EXPECTED_ARTIFACTS
        || manifest.artifacts.iter().any(|artifact| {
            artifact.bytes == 0
                || artifact.bytes > B1_CDRIVE_OPERATOR_DECISION_MAX_MACHINE_FORM_BYTES as u64
                || !valid_digest(&artifact.sha256)
        })
        || !manifest.fixture_only
        || manifest.live_authorization_admitted
        || manifest.physical_execution_authorized
        || manifest.non_authority_statement.is_empty()
        || manifest.manifest_sha256
            != b1_cdrive_operator_decision_evidence_manifest_digest(manifest)?
    {
        return Err(evidence_fault("evidence manifest differs"));
    }
    Ok(())
}

fn validate_verification(
    verification: &B1CDriveOperatorDecisionEvidenceVerification,
) -> Result<(), B1CDriveOperatorDecisionEvidenceFault> {
    if verification.profile != B1_CDRIVE_OPERATOR_DECISION_EVIDENCE_VERIFICATION_PROFILE
        || verification.status != B1_CDRIVE_OPERATOR_DECISION_EVIDENCE_VERIFICATION_STATUS
        || verification.source_snapshot_uuid != B1_CDRIVE_OPERATOR_DECISION_SOURCE_SNAPSHOT_UUID
        || verification.canonical_uuid != B1_CDRIVE_OPERATOR_DECISION_CANONICAL_UUID
        || verification.signature_uuid != B1_CDRIVE_OPERATOR_DECISION_SIGNATURE_UUID
        || verification.formation_commit != B1_CDRIVE_OPERATOR_DECISION_FORMATION_COMMIT
        || !valid_digest(&verification.policy_sha256)
        || !valid_digest(&verification.request_sha256)
        || !valid_digest(&verification.authorize_decision_sha256)
        || !valid_digest(&verification.reject_decision_sha256)
        || !valid_digest(&verification.authorize_verification_sha256)
        || !valid_digest(&verification.reject_verification_sha256)
        || verification.artifact_count != 6
        || verification.decision_count != 2
        || verification.independent_replay_count != 4
        || !verification.byte_identical_replays
        || !verification.signature_correspondence_verified
        || !verification.fixture_only
        || verification.policy_governance_proved
        || verification.current_nonexpired
        || verification.live_authorization_admitted
        || verification.fresh_observation_proved
        || verification.private_execution_permit_present
        || verification.physical_preparation_authorized
        || verification.production_broker_projection_present
        || verification.effect_account != B1CDriveOperatorDecisionEffectAccount::default()
        || verification.verification_sha256
            != b1_cdrive_operator_decision_evidence_verification_digest(verification)?
    {
        return Err(evidence_fault("evidence verification differs"));
    }
    Ok(())
}

fn artifact_text<'a>(
    texts: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<&'a String, B1CDriveOperatorDecisionEvidenceFault> {
    texts
        .get(name)
        .ok_or_else(|| evidence_fault(format!("artifact absent: {name}")))
}

fn read_text(root: &Path, name: &str) -> Result<String, B1CDriveOperatorDecisionEvidenceFault> {
    String::from_utf8(read_bytes(root, name)?).map_err(evidence_fault)
}

fn read_bytes(root: &Path, name: &str) -> Result<Vec<u8>, B1CDriveOperatorDecisionEvidenceFault> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name == "." || name == ".." {
        return Err(evidence_fault("artifact name differs"));
    }
    let path = root.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(evidence_fault)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || is_reparse_point(&metadata)
        || metadata.len() == 0
        || metadata.len() > B1_CDRIVE_OPERATOR_DECISION_MAX_MACHINE_FORM_BYTES as u64
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
) -> Result<T, B1CDriveOperatorDecisionEvidenceFault> {
    if machine_form.is_empty()
        || machine_form.len() > B1_CDRIVE_OPERATOR_DECISION_MAX_MACHINE_FORM_BYTES
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
) -> Result<(), B1CDriveOperatorDecisionEvidenceFault> {
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
) -> Result<ContentDigest, B1CDriveOperatorDecisionEvidenceFault> {
    let payload = serde_json::to_vec(value).map_err(evidence_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + payload.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&payload);
    Ok(sha256_bytes(&bytes))
}

fn valid_digest(value: &ContentDigest) -> bool {
    value.algorithm == "sha256"
        && value.value.len() == 64
        && value
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

fn evidence_fault(error: impl fmt::Display) -> B1CDriveOperatorDecisionEvidenceFault {
    B1CDriveOperatorDecisionEvidenceFault {
        message: error.to_string(),
    }
}
