//! Read-only, provider-independent replay of B1 production-broker evidence.
//!
//! This verifier accepts one closed evidence directory, binds every artifact
//! by byte count and SHA-256, replays the pure broker twice, and returns one
//! canonical receipt. It has no process, write, clock, environment, Git,
//! network, provider, model, MCP, cleanup, or recovery surface.

use std::{
    collections::{BTreeMap, HashSet},
    fmt, fs,
    path::{Path, PathBuf},
};

use cantor_core::{ContentDigest, sha256_bytes};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::Number;

use crate::{
    B1_CDRIVE_PRODUCTION_BROKER_CANONICAL_UUID, B1_CDRIVE_PRODUCTION_BROKER_FORMATION_BOOKEND,
    B1_CDRIVE_PRODUCTION_BROKER_FORMATION_COMMIT,
    B1_CDRIVE_PRODUCTION_BROKER_MAX_MACHINE_FORM_BYTES, B1_CDRIVE_PRODUCTION_BROKER_SIGNATURE_UUID,
    B1_CDRIVE_PRODUCTION_BROKER_SOURCE_SNAPSHOT_UUID, B1CDriveProductionBrokerEffectAccount,
    compile_b1_cdrive_production_broker_implementation_receipt,
    from_b1_cdrive_production_broker_fixture_input_machine_form,
    from_b1_cdrive_production_broker_fixture_outcome_machine_form,
    from_b1_cdrive_production_broker_implementation_receipt_machine_form,
    from_b1_cdrive_production_broker_implementation_request_machine_form,
    run_b1_cdrive_production_broker_fixture,
    to_b1_cdrive_production_broker_fixture_outcome_machine_form,
    to_b1_cdrive_production_broker_implementation_receipt_machine_form,
};

pub const B1_CDRIVE_PRODUCTION_BROKER_EVIDENCE_MANIFEST_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-production-broker-evidence/0.1";
pub const B1_CDRIVE_PRODUCTION_BROKER_EVIDENCE_VERIFICATION_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-production-broker-evidence-verification/0.1";
pub const B1_CDRIVE_PRODUCTION_BROKER_EVIDENCE_VERIFICATION_STATUS: &str =
    "provider_free_broker_implementation_verified_physical_run_not_authorized";

const MANIFEST_DOMAIN: &str =
    "cantor.self-work-update-broker.b1.cdrive-production-broker-evidence-manifest.v1";
const VERIFICATION_DOMAIN: &str =
    "cantor.self-work-update-broker.b1.cdrive-production-broker-evidence-verification.v1";
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_FIELDS: usize = 256;
const MAX_EVIDENCE_ARTIFACTS: usize = 32;
const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_AGGREGATE_BYTES: u64 = 64 * 1024 * 1024;
const EXPECTED_ARTIFACTS: [&str; 4] = [
    "fixture_input.json",
    "fixture_outcome.json",
    "implementation_receipt.json",
    "implementation_request.json",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionBrokerEvidenceArtifact {
    pub path: String,
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionBrokerEvidenceManifest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub formation_commit: String,
    pub formation_bookend: String,
    pub artifacts: Vec<B1CDriveProductionBrokerEvidenceArtifact>,
    pub fixture_only: bool,
    pub physical_execution_authorized: bool,
    pub non_authority_statement: String,
    pub manifest_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionBrokerEvidenceVerification {
    pub profile: String,
    pub status: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub formation_commit: String,
    pub formation_bookend: String,
    pub manifest_sha256: ContentDigest,
    pub implementation_request_sha256: ContentDigest,
    pub implementation_receipt_sha256: ContentDigest,
    pub fixture_input_sha256: ContentDigest,
    pub fixture_outcome_sha256: ContentDigest,
    pub artifact_count: u8,
    pub aggregate_artifact_bytes: u64,
    pub independent_replay_count: u8,
    pub byte_identical_replays: bool,
    pub fixture_only: bool,
    pub physical_execution_authorized: bool,
    pub private_execution_permit_constructed: bool,
    pub windows_backend_invoked: bool,
    pub effect_account: B1CDriveProductionBrokerEffectAccount,
    pub verification_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B1CDriveProductionBrokerEvidenceFault {
    pub message: String,
}

impl fmt::Display for B1CDriveProductionBrokerEvidenceFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for B1CDriveProductionBrokerEvidenceFault {}

pub fn b1_cdrive_production_broker_evidence_manifest_digest(
    manifest: &B1CDriveProductionBrokerEvidenceManifest,
) -> Result<ContentDigest, B1CDriveProductionBrokerEvidenceFault> {
    let mut normalized = manifest.clone();
    normalized.manifest_sha256 = empty_digest();
    domain_digest(MANIFEST_DOMAIN, &normalized)
}

pub fn b1_cdrive_production_broker_evidence_verification_digest(
    verification: &B1CDriveProductionBrokerEvidenceVerification,
) -> Result<ContentDigest, B1CDriveProductionBrokerEvidenceFault> {
    let mut normalized = verification.clone();
    normalized.verification_sha256 = empty_digest();
    domain_digest(VERIFICATION_DOMAIN, &normalized)
}

pub fn verify_b1_cdrive_production_broker_evidence_directory(
    root: &Path,
) -> Result<B1CDriveProductionBrokerEvidenceVerification, B1CDriveProductionBrokerEvidenceFault> {
    validate_root(root)?;
    let manifest_bytes = read_artifact(root, "evidence_manifest.json", MAX_ARTIFACT_BYTES)?;
    let manifest_text = std::str::from_utf8(&manifest_bytes)
        .map_err(|error| evidence_fault(format!("manifest UTF-8 failed: {error}")))?;
    let manifest: B1CDriveProductionBrokerEvidenceManifest = parse_strict(manifest_text)?;
    validate_manifest(&manifest)?;
    if serde_json::to_string(&manifest).map_err(evidence_fault)? != manifest_text {
        return Err(evidence_fault("manifest is not canonical compact JSON"));
    }

    let mut bytes_by_name = BTreeMap::new();
    let mut aggregate_bytes = 0_u64;
    for artifact in &manifest.artifacts {
        let bytes = read_artifact(root, &artifact.path, MAX_ARTIFACT_BYTES)?;
        aggregate_bytes = aggregate_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| evidence_fault("aggregate artifact byte count overflowed"))?;
        if aggregate_bytes > MAX_AGGREGATE_BYTES
            || bytes.len() as u64 != artifact.bytes
            || sha256_bytes(&bytes) != artifact.sha256
        {
            return Err(evidence_fault(format!(
                "artifact identity differs: {}",
                artifact.path
            )));
        }
        bytes_by_name.insert(artifact.path.clone(), bytes);
    }

    let request_text = artifact_text(&bytes_by_name, "implementation_request.json")?;
    let request =
        from_b1_cdrive_production_broker_implementation_request_machine_form(request_text)
            .map_err(evidence_fault)?;
    let receipt_text = artifact_text(&bytes_by_name, "implementation_receipt.json")?;
    let receipt = from_b1_cdrive_production_broker_implementation_receipt_machine_form(
        &request,
        receipt_text,
    )
    .map_err(evidence_fault)?;
    let recomputed_receipt = compile_b1_cdrive_production_broker_implementation_receipt(&request)
        .map_err(evidence_fault)?;
    if receipt != recomputed_receipt
        || to_b1_cdrive_production_broker_implementation_receipt_machine_form(
            &request,
            &recomputed_receipt,
        )
        .map_err(evidence_fault)?
            != receipt_text
    {
        return Err(evidence_fault("implementation receipt replay differs"));
    }

    let input_text = artifact_text(&bytes_by_name, "fixture_input.json")?;
    let input = from_b1_cdrive_production_broker_fixture_input_machine_form(input_text)
        .map_err(evidence_fault)?;
    if input.implementation_request_machine_form != request_text {
        return Err(evidence_fault(
            "fixture input does not bind the exact implementation request bytes",
        ));
    }
    let outcome_text = artifact_text(&bytes_by_name, "fixture_outcome.json")?;
    let outcome =
        from_b1_cdrive_production_broker_fixture_outcome_machine_form(&input, outcome_text)
            .map_err(evidence_fault)?;
    let replay_one = run_b1_cdrive_production_broker_fixture(&input).map_err(evidence_fault)?;
    let replay_two = run_b1_cdrive_production_broker_fixture(&input).map_err(evidence_fault)?;
    let replay_one_text =
        to_b1_cdrive_production_broker_fixture_outcome_machine_form(&input, &replay_one)
            .map_err(evidence_fault)?;
    let replay_two_text =
        to_b1_cdrive_production_broker_fixture_outcome_machine_form(&input, &replay_two)
            .map_err(evidence_fault)?;
    if outcome != replay_one
        || replay_one != replay_two
        || replay_one_text != replay_two_text
        || replay_one_text != outcome_text
    {
        return Err(evidence_fault("fixture outcome double replay differs"));
    }

    let mut verification = B1CDriveProductionBrokerEvidenceVerification {
        profile: B1_CDRIVE_PRODUCTION_BROKER_EVIDENCE_VERIFICATION_PROFILE.to_owned(),
        status: B1_CDRIVE_PRODUCTION_BROKER_EVIDENCE_VERIFICATION_STATUS.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_PRODUCTION_BROKER_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: B1_CDRIVE_PRODUCTION_BROKER_CANONICAL_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_PRODUCTION_BROKER_SIGNATURE_UUID.to_owned(),
        formation_commit: B1_CDRIVE_PRODUCTION_BROKER_FORMATION_COMMIT.to_owned(),
        formation_bookend: B1_CDRIVE_PRODUCTION_BROKER_FORMATION_BOOKEND.to_owned(),
        manifest_sha256: manifest.manifest_sha256,
        implementation_request_sha256: request.request_sha256,
        implementation_receipt_sha256: receipt.receipt_sha256,
        fixture_input_sha256: input.input_sha256,
        fixture_outcome_sha256: outcome.outcome_sha256,
        artifact_count: manifest.artifacts.len() as u8,
        aggregate_artifact_bytes: aggregate_bytes,
        independent_replay_count: 2,
        byte_identical_replays: true,
        fixture_only: true,
        physical_execution_authorized: false,
        private_execution_permit_constructed: false,
        windows_backend_invoked: false,
        effect_account: outcome.effect_account,
        verification_sha256: empty_digest(),
    };
    verification.verification_sha256 =
        b1_cdrive_production_broker_evidence_verification_digest(&verification)?;
    let retained_verification = root.join("verification.json");
    if retained_verification.exists() {
        let retained = read_artifact(root, "verification.json", MAX_ARTIFACT_BYTES)?;
        let expected =
            to_b1_cdrive_production_broker_evidence_verification_machine_form(&verification)?;
        if retained != expected.as_bytes() {
            return Err(evidence_fault(
                "retained verification receipt differs from independent replay",
            ));
        }
    }
    Ok(verification)
}

pub fn to_b1_cdrive_production_broker_evidence_manifest_machine_form(
    manifest: &B1CDriveProductionBrokerEvidenceManifest,
) -> Result<String, B1CDriveProductionBrokerEvidenceFault> {
    validate_manifest(manifest)?;
    serde_json::to_string(manifest).map_err(evidence_fault)
}

pub fn to_b1_cdrive_production_broker_evidence_verification_machine_form(
    verification: &B1CDriveProductionBrokerEvidenceVerification,
) -> Result<String, B1CDriveProductionBrokerEvidenceFault> {
    if verification.profile != B1_CDRIVE_PRODUCTION_BROKER_EVIDENCE_VERIFICATION_PROFILE
        || verification.status != B1_CDRIVE_PRODUCTION_BROKER_EVIDENCE_VERIFICATION_STATUS
        || verification.source_snapshot_uuid != B1_CDRIVE_PRODUCTION_BROKER_SOURCE_SNAPSHOT_UUID
        || verification.canonical_uuid != B1_CDRIVE_PRODUCTION_BROKER_CANONICAL_UUID
        || verification.signature_uuid != B1_CDRIVE_PRODUCTION_BROKER_SIGNATURE_UUID
        || verification.formation_commit != B1_CDRIVE_PRODUCTION_BROKER_FORMATION_COMMIT
        || verification.formation_bookend != B1_CDRIVE_PRODUCTION_BROKER_FORMATION_BOOKEND
        || verification.artifact_count != EXPECTED_ARTIFACTS.len() as u8
        || verification.independent_replay_count != 2
        || !verification.byte_identical_replays
        || !verification.fixture_only
        || verification.physical_execution_authorized
        || verification.private_execution_permit_constructed
        || verification.windows_backend_invoked
        || !effect_account_is_zero(&verification.effect_account)
        || verification.verification_sha256
            != b1_cdrive_production_broker_evidence_verification_digest(verification)?
    {
        return Err(evidence_fault("evidence verification receipt differs"));
    }
    serde_json::to_string(verification).map_err(evidence_fault)
}

fn validate_root(root: &Path) -> Result<(), B1CDriveProductionBrokerEvidenceFault> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| evidence_fault(format!("evidence root metadata failed: {error}")))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata_is_reparse(&metadata) {
        return Err(evidence_fault(
            "evidence root must be one nonlink nonreparse directory",
        ));
    }
    let mut names = fs::read_dir(root)
        .map_err(|error| evidence_fault(format!("evidence root read failed: {error}")))?
        .map(|entry| {
            entry
                .map_err(|error| evidence_fault(format!("evidence entry failed: {error}")))?
                .file_name()
                .into_string()
                .map_err(|_| evidence_fault("evidence entry name is not Unicode"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    let mut expected = EXPECTED_ARTIFACTS.map(str::to_owned).to_vec();
    expected.push("evidence_manifest.json".to_owned());
    expected.sort();
    let mut expected_with_verification = expected.clone();
    expected_with_verification.push("verification.json".to_owned());
    expected_with_verification.sort();
    if names != expected && names != expected_with_verification {
        return Err(evidence_fault("evidence directory membership differs"));
    }
    Ok(())
}

fn validate_manifest(
    manifest: &B1CDriveProductionBrokerEvidenceManifest,
) -> Result<(), B1CDriveProductionBrokerEvidenceFault> {
    if manifest.profile != B1_CDRIVE_PRODUCTION_BROKER_EVIDENCE_MANIFEST_PROFILE
        || manifest.source_snapshot_uuid != B1_CDRIVE_PRODUCTION_BROKER_SOURCE_SNAPSHOT_UUID
        || manifest.canonical_uuid != B1_CDRIVE_PRODUCTION_BROKER_CANONICAL_UUID
        || manifest.signature_uuid != B1_CDRIVE_PRODUCTION_BROKER_SIGNATURE_UUID
        || manifest.formation_commit != B1_CDRIVE_PRODUCTION_BROKER_FORMATION_COMMIT
        || manifest.formation_bookend != B1_CDRIVE_PRODUCTION_BROKER_FORMATION_BOOKEND
        || !manifest.fixture_only
        || manifest.physical_execution_authorized
        || manifest.non_authority_statement.is_empty()
        || manifest.non_authority_statement.len() > 1024
        || manifest.artifacts.len() != EXPECTED_ARTIFACTS.len()
        || manifest.artifacts.len() > MAX_EVIDENCE_ARTIFACTS
        || manifest.manifest_sha256
            != b1_cdrive_production_broker_evidence_manifest_digest(manifest)?
    {
        return Err(evidence_fault(
            "evidence manifest authority or digest differs",
        ));
    }
    for (artifact, expected) in manifest.artifacts.iter().zip(EXPECTED_ARTIFACTS) {
        if artifact.path != expected
            || artifact.bytes == 0
            || artifact.bytes > MAX_ARTIFACT_BYTES
            || !valid_digest(&artifact.sha256)
        {
            return Err(evidence_fault("evidence artifact identity differs"));
        }
    }
    Ok(())
}

fn read_artifact(
    root: &Path,
    name: &str,
    maximum_bytes: u64,
) -> Result<Vec<u8>, B1CDriveProductionBrokerEvidenceFault> {
    if name.is_empty()
        || name.len() > 128
        || name.contains(['/', '\\', '\0', '\r', '\n'])
        || name == "."
        || name == ".."
    {
        return Err(evidence_fault("artifact name differs"));
    }
    let path: PathBuf = root.join(name);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| evidence_fault(format!("artifact metadata failed for {name}: {error}")))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata_is_reparse(&metadata)
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(evidence_fault(format!(
            "artifact must be one bounded nonlink regular file: {name}"
        )));
    }
    let bytes = fs::read(&path)
        .map_err(|error| evidence_fault(format!("artifact read failed for {name}: {error}")))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(evidence_fault(format!(
            "artifact changed while read: {name}"
        )));
    }
    Ok(bytes)
}

fn artifact_text<'a>(
    artifacts: &'a BTreeMap<String, Vec<u8>>,
    name: &str,
) -> Result<&'a str, B1CDriveProductionBrokerEvidenceFault> {
    std::str::from_utf8(
        artifacts
            .get(name)
            .ok_or_else(|| evidence_fault(format!("artifact is absent: {name}")))?,
    )
    .map_err(|error| evidence_fault(format!("artifact UTF-8 failed for {name}: {error}")))
}

fn domain_digest(
    domain: &str,
    value: &impl Serialize,
) -> Result<ContentDigest, B1CDriveProductionBrokerEvidenceFault> {
    let payload = serde_json::to_vec(value).map_err(evidence_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + payload.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&payload);
    Ok(sha256_bytes(&bytes))
}

fn effect_account_is_zero(account: &B1CDriveProductionBrokerEffectAccount) -> bool {
    !account.physical_contact
        && account.process_creation_count == 0
        && account.provider_trial_count == 0
        && account.model_turn_count == 0
        && account.mcp_call_count == 0
        && account.network_contact_count == 0
        && account.writer_run_count == 0
        && account.git_mutation_count == 0
        && account.publication_count == 0
        && account.persistence_count == 0
        && account.activation_count == 0
        && account.d_drive_contact_count == 0
        && account.remote_contact_count == 0
        && account.fpga_contact_count == 0
        && account.minecraft_contact_count == 0
        && account.wsl_compile_count == 0
        && account.cleanup_count == 0
        && account.foreign_effect_count == 0
}

fn valid_digest(digest: &ContentDigest) -> bool {
    digest.algorithm == "sha256"
        && digest.value.len() == 64
        && digest.value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(windows)]
fn metadata_is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse(_: &fs::Metadata) -> bool {
    false
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn evidence_fault(error: impl fmt::Display) -> B1CDriveProductionBrokerEvidenceFault {
    let mut message = error.to_string();
    if message.len() > 1024 {
        message.truncate(1024);
    }
    B1CDriveProductionBrokerEvidenceFault { message }
}

fn parse_strict<T: DeserializeOwned>(
    value: &str,
) -> Result<T, B1CDriveProductionBrokerEvidenceFault> {
    if value.len() > B1_CDRIVE_PRODUCTION_BROKER_MAX_MACHINE_FORM_BYTES {
        return Err(evidence_fault("JSON machine form exceeds bound"));
    }
    let mut deserializer = serde_json::Deserializer::from_str(value);
    StrictSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(evidence_fault)?;
    deserializer.end().map_err(evidence_fault)?;
    serde_json::from_str(value).map_err(evidence_fault)
}

#[derive(Debug)]
struct StrictValue;

struct StrictSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = StrictValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.depth > MAX_JSON_DEPTH {
            return Err(de::Error::custom("JSON nesting exceeds bound"));
        }
        deserializer.deserialize_any(StrictVisitor { depth: self.depth })
    }
}

struct StrictVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded duplicate-free JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(StrictValue)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(StrictValue)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(StrictValue)
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .ok_or_else(|| E::custom("non-finite JSON number"))
            .map(|_| StrictValue)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(StrictValue)
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(StrictValue)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(StrictSeed {
                depth: self.depth + 1,
            })?
            .is_some()
        {}
        Ok(StrictValue)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate JSON key: {key}")));
            }
            if keys.len() > MAX_JSON_FIELDS {
                return Err(de::Error::custom("JSON object field count exceeds bound"));
            }
            map.next_value_seed(StrictSeed {
                depth: self.depth + 1,
            })?;
        }
        Ok(StrictValue)
    }
}

#[cfg(test)]
mod tests {
    use super::{B1CDriveProductionBrokerEvidenceManifest, parse_strict};

    #[test]
    fn strict_manifest_parser_rejects_duplicate_and_unknown_fields() {
        let duplicate = r#"{"profile":"a","profile":"b"}"#;
        assert!(parse_strict::<B1CDriveProductionBrokerEvidenceManifest>(duplicate).is_err());
        let unknown = r#"{"unknown":true}"#;
        assert!(parse_strict::<B1CDriveProductionBrokerEvidenceManifest>(unknown).is_err());
    }
}
