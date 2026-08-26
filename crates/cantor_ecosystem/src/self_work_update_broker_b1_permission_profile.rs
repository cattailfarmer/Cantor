//! Provider-free SWA-05 B1 permission-profile capability revalidation.
//!
//! This module independently verifies caller-supplied evidence from the exact
//! operator-selected npm-native App Server. It proves only that one pinned
//! local host enforced one allowed-read and one denied-read coordinate. It has
//! no process, provider, model, network, Git, cleanup, or write surface and it
//! never authorizes the B1 writer.

use std::{
    collections::BTreeSet,
    fmt, fs,
    path::{Component, Path},
};

use cantor_core::{ContentDigest, sha256_bytes};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};

pub const B1_PERMISSION_PROFILE_EVIDENCE_MANIFEST_PROFILE: &str =
    "cantor-self-work-update-broker-b1-permission-profile-evidence-manifest/0.1";
pub const B1_PERMISSION_PROFILE_OBSERVATION_PROFILE: &str =
    "cantor-self-work-update-broker-b1-permission-profile-observation/0.1";
pub const B1_PERMISSION_PROFILE_RECEIPT_PROFILE: &str =
    "cantor-self-work-update-broker-b1-permission-profile-receipt/0.1";
pub const B1_PERMISSION_PROFILE_SOURCE_SNAPSHOT_UUID: &str = "3654826b-14d1-4e96-81a4-ab27be83dcd8";
pub const B1_PERMISSION_PROFILE_PREDECESSOR_COMMIT: &str =
    "75aa325b0063416f088d76f60e702a9ed5f3f3a7";
pub const B1_PERMISSION_PROFILE_MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
pub const B1_PERMISSION_PROFILE_MAX_MACHINE_FORM_BYTES: usize = 2 * 1024 * 1024;

const OBSERVATION_FILE: &str = "observation.json";
const STANDARD_SCHEMA_FILE: &str = "standard_schema.json";
const EXPERIMENTAL_SCHEMA_FILE: &str = "experimental_schema.json";
const SELECTED_EXECUTABLE: &str = "C:\\Users\\enjer\\AppData\\Roaming\\npm\\node_modules\\@openai\\codex\\node_modules\\@openai\\codex-win32-x64\\vendor\\x86_64-pc-windows-msvc\\bin\\codex.exe";
const SELECTED_EXECUTABLE_BYTES: u64 = 242_541_872;
const SELECTED_EXECUTABLE_SHA256: &str =
    "FE12887B4AB4A4E988F0FA5BAAE9E5CB7D8505C26401378628E762DB9A2E798F";
const HISTORICAL_NOT_RUN_DIGEST: &str =
    "b7d65c4877932aaf14a32e4e65d04f40e053af39435d56e8dedaad5d021816ad";
const HISTORICAL_REFUSAL: &str = "selected_schema_missing_read_scope_control";
const PERMISSION_PROFILE_ID: &str = "swa05_probe";
const ALLOWED_SENTINEL: &str = "SWA05_ALLOWED_READ_SENTINEL\n";
const DENIED_SENTINEL: &str = "SWA05_DENIED_READ_SENTINEL\n";
const RECEIPT_DOMAIN: &str = "cantor.self-work-update-broker-b1.permission-profile-receipt.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceManifest {
    profile: String,
    source_snapshot_uuid: String,
    predecessor_commit: String,
    artifacts: Vec<ArtifactIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactIdentity {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityObservation {
    profile: String,
    source_snapshot_uuid: String,
    predecessor_commit: String,
    historical_not_run: HistoricalNotRun,
    selected_executable: SelectedExecutable,
    schema_generation: SchemaGeneration,
    permission_profile: PermissionProfileObservation,
    sentinels: SentinelObservation,
    transcript: Vec<Value>,
    boundaries: CapabilityBoundaries,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalNotRun {
    profile: String,
    refusal_code: String,
    run_count: u8,
    record_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectedExecutable {
    path: String,
    bytes: u64,
    sha256: String,
    version_output: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaGeneration {
    standard: SchemaRun,
    experimental: SchemaRun,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaRun {
    argv: Vec<String>,
    exit_code: i32,
    stdout: String,
    stderr: String,
    evidence_file: String,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PermissionProfileObservation {
    id: String,
    root_access: String,
    minimal_access: String,
    fixture_root: String,
    fixture_access: String,
    denied_path: String,
    denied_access: String,
    network_enabled: bool,
    filesystem_override: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SentinelObservation {
    allowed_path: String,
    allowed_sha256: String,
    denied_path: String,
    denied_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityBoundaries {
    writer_run_count: u8,
    provider_contact_count: u8,
    model_turn_count: u8,
    mcp_call_count: u8,
    git_command_count: u8,
    remote_contact_count: u8,
    d_drive_contact_count: u8,
    product_mutation_count: u8,
    cleanup_count: u8,
    scratch_mutation_performed: bool,
    service_network_observed: bool,
    live_writer_allowed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1PermissionProfileStatus {
    HostCapabilityVerifiedWriterNotRun,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1PermissionProfileAuthority {
    CapabilityObservationOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1PermissionProfileReceipt {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub predecessor_commit: String,
    pub historical_not_run_record_digest: String,
    pub evidence_manifest_digest: ContentDigest,
    pub observation_digest: ContentDigest,
    pub standard_schema_digest: ContentDigest,
    pub experimental_schema_digest: ContentDigest,
    pub status: B1PermissionProfileStatus,
    pub authority: B1PermissionProfileAuthority,
    pub selected_host_pinned: bool,
    pub historical_not_run_preserved: bool,
    pub read_scope_representable: bool,
    pub allowed_read_enforced: bool,
    pub denied_read_enforced: bool,
    pub writer_run_count: u8,
    pub provider_contact_count: u8,
    pub model_turn_count: u8,
    pub mcp_call_count: u8,
    pub git_command_count: u8,
    pub remote_contact_count: u8,
    pub d_drive_contact_count: u8,
    pub product_mutation_count: u8,
    pub cleanup_count: u8,
    pub service_network_observed: bool,
    pub live_writer_allowed: bool,
    pub next_writer_preflight_formation_supported: bool,
    pub receipt_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1PermissionProfileFaultCode {
    Path,
    Bound,
    Manifest,
    Digest,
    MachineForm,
    Lineage,
    Selection,
    Schema,
    Profile,
    Transcript,
    Enforcement,
    Authority,
    Receipt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1PermissionProfileFault {
    pub code: B1PermissionProfileFaultCode,
    pub message: String,
}

impl fmt::Display for B1PermissionProfileFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for B1PermissionProfileFault {}

pub fn verify_b1_permission_profile_evidence(
    evidence_root: &Path,
) -> Result<B1PermissionProfileReceipt, B1PermissionProfileFault> {
    let metadata = fs::symlink_metadata(evidence_root).map_err(|error| {
        fault(
            B1PermissionProfileFaultCode::Path,
            format!("evidence root metadata failed: {error}"),
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(fault(
            B1PermissionProfileFaultCode::Path,
            "evidence root must be one real directory",
        ));
    }
    let root = fs::canonicalize(evidence_root).map_err(|error| {
        fault(
            B1PermissionProfileFaultCode::Path,
            format!("evidence root canonicalization failed: {error}"),
        )
    })?;

    let manifest_bytes = read_bounded_regular_file(&root, "manifest.json")?;
    let manifest: EvidenceManifest = parse_strict_json(&manifest_bytes)?;
    validate_manifest(&manifest)?;

    let mut artifact_bytes = Vec::new();
    for artifact in &manifest.artifacts {
        let bytes = read_bounded_regular_file(&root, &artifact.path)?;
        if bytes.len() as u64 != artifact.bytes || sha256_upper(&bytes) != artifact.sha256 {
            return Err(fault(
                B1PermissionProfileFaultCode::Digest,
                format!("artifact identity differs for {}", artifact.path),
            ));
        }
        artifact_bytes.push((artifact.path.as_str(), bytes));
    }

    let experimental_schema_bytes = artifact(&artifact_bytes, EXPERIMENTAL_SCHEMA_FILE)?;
    let observation_bytes = artifact(&artifact_bytes, OBSERVATION_FILE)?;
    let standard_schema_bytes = artifact(&artifact_bytes, STANDARD_SCHEMA_FILE)?;
    let observation: CapabilityObservation = parse_strict_json(observation_bytes)?;
    validate_observation(
        &observation,
        standard_schema_bytes,
        experimental_schema_bytes,
    )?;

    let mut receipt = B1PermissionProfileReceipt {
        profile: B1_PERMISSION_PROFILE_RECEIPT_PROFILE.to_owned(),
        source_snapshot_uuid: B1_PERMISSION_PROFILE_SOURCE_SNAPSHOT_UUID.to_owned(),
        predecessor_commit: B1_PERMISSION_PROFILE_PREDECESSOR_COMMIT.to_owned(),
        historical_not_run_record_digest: HISTORICAL_NOT_RUN_DIGEST.to_owned(),
        evidence_manifest_digest: sha256_bytes(&manifest_bytes),
        observation_digest: sha256_bytes(observation_bytes),
        standard_schema_digest: sha256_bytes(standard_schema_bytes),
        experimental_schema_digest: sha256_bytes(experimental_schema_bytes),
        status: B1PermissionProfileStatus::HostCapabilityVerifiedWriterNotRun,
        authority: B1PermissionProfileAuthority::CapabilityObservationOnly,
        selected_host_pinned: true,
        historical_not_run_preserved: true,
        read_scope_representable: true,
        allowed_read_enforced: true,
        denied_read_enforced: true,
        writer_run_count: 0,
        provider_contact_count: 0,
        model_turn_count: 0,
        mcp_call_count: 0,
        git_command_count: 0,
        remote_contact_count: 0,
        d_drive_contact_count: 0,
        product_mutation_count: 0,
        cleanup_count: 0,
        service_network_observed: false,
        live_writer_allowed: false,
        next_writer_preflight_formation_supported: true,
        receipt_digest: empty_digest(),
    };
    receipt.receipt_digest = b1_permission_profile_receipt_digest(&receipt)?;
    validate_b1_permission_profile_receipt(&receipt)?;
    Ok(receipt)
}

pub fn validate_b1_permission_profile_receipt(
    receipt: &B1PermissionProfileReceipt,
) -> Result<(), B1PermissionProfileFault> {
    if receipt.profile != B1_PERMISSION_PROFILE_RECEIPT_PROFILE
        || receipt.source_snapshot_uuid != B1_PERMISSION_PROFILE_SOURCE_SNAPSHOT_UUID
        || receipt.predecessor_commit != B1_PERMISSION_PROFILE_PREDECESSOR_COMMIT
        || receipt.historical_not_run_record_digest != HISTORICAL_NOT_RUN_DIGEST
        || receipt.status != B1PermissionProfileStatus::HostCapabilityVerifiedWriterNotRun
        || receipt.authority != B1PermissionProfileAuthority::CapabilityObservationOnly
    {
        return Err(fault(
            B1PermissionProfileFaultCode::Receipt,
            "receipt profile lineage status or authority differs",
        ));
    }
    if !receipt.selected_host_pinned
        || !receipt.historical_not_run_preserved
        || !receipt.read_scope_representable
        || !receipt.allowed_read_enforced
        || !receipt.denied_read_enforced
        || receipt.writer_run_count != 0
        || receipt.provider_contact_count != 0
        || receipt.model_turn_count != 0
        || receipt.mcp_call_count != 0
        || receipt.git_command_count != 0
        || receipt.remote_contact_count != 0
        || receipt.d_drive_contact_count != 0
        || receipt.product_mutation_count != 0
        || receipt.cleanup_count != 0
        || receipt.service_network_observed
        || receipt.live_writer_allowed
        || !receipt.next_writer_preflight_formation_supported
    {
        return Err(fault(
            B1PermissionProfileFaultCode::Authority,
            "receipt capability or zero-effect boundary differs",
        ));
    }
    for digest in [
        &receipt.evidence_manifest_digest,
        &receipt.observation_digest,
        &receipt.standard_schema_digest,
        &receipt.experimental_schema_digest,
        &receipt.receipt_digest,
    ] {
        validate_digest(digest)?;
    }
    if receipt.receipt_digest != b1_permission_profile_receipt_digest(receipt)? {
        return Err(fault(
            B1PermissionProfileFaultCode::Digest,
            "receipt self-digest differs",
        ));
    }
    Ok(())
}

pub fn to_b1_permission_profile_receipt_machine_form(
    receipt: &B1PermissionProfileReceipt,
) -> Result<String, B1PermissionProfileFault> {
    validate_b1_permission_profile_receipt(receipt)?;
    let machine_form = serde_json::to_string(receipt).map_err(machine_fault)?;
    if machine_form.len() > B1_PERMISSION_PROFILE_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            B1PermissionProfileFaultCode::Bound,
            "receipt machine form is oversized",
        ));
    }
    Ok(machine_form)
}

pub fn from_b1_permission_profile_receipt_machine_form(
    machine_form: &str,
) -> Result<B1PermissionProfileReceipt, B1PermissionProfileFault> {
    let receipt: B1PermissionProfileReceipt = parse_strict_json(machine_form.as_bytes())?;
    validate_b1_permission_profile_receipt(&receipt)?;
    Ok(receipt)
}

pub fn b1_permission_profile_receipt_digest(
    receipt: &B1PermissionProfileReceipt,
) -> Result<ContentDigest, B1PermissionProfileFault> {
    let mut normalized = receipt.clone();
    normalized.receipt_digest = empty_digest();
    let payload = serde_json::to_vec(&normalized).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(RECEIPT_DOMAIN.len() + 1 + payload.len());
    bytes.extend_from_slice(RECEIPT_DOMAIN.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&payload);
    Ok(sha256_bytes(&bytes))
}

fn validate_manifest(manifest: &EvidenceManifest) -> Result<(), B1PermissionProfileFault> {
    if manifest.profile != B1_PERMISSION_PROFILE_EVIDENCE_MANIFEST_PROFILE
        || manifest.source_snapshot_uuid != B1_PERMISSION_PROFILE_SOURCE_SNAPSHOT_UUID
        || manifest.predecessor_commit != B1_PERMISSION_PROFILE_PREDECESSOR_COMMIT
    {
        return Err(fault(
            B1PermissionProfileFaultCode::Manifest,
            "manifest profile or lineage differs",
        ));
    }
    let expected = [
        EXPERIMENTAL_SCHEMA_FILE,
        OBSERVATION_FILE,
        STANDARD_SCHEMA_FILE,
    ];
    if manifest.artifacts.len() != expected.len() {
        return Err(fault(
            B1PermissionProfileFaultCode::Manifest,
            "manifest artifact count differs",
        ));
    }
    for (artifact, expected_path) in manifest.artifacts.iter().zip(expected) {
        if artifact.path != expected_path
            || artifact.bytes == 0
            || artifact.bytes > B1_PERMISSION_PROFILE_MAX_ARTIFACT_BYTES
            || !is_upper_sha256(&artifact.sha256)
        {
            return Err(fault(
                B1PermissionProfileFaultCode::Manifest,
                "manifest artifact coordinate differs",
            ));
        }
    }
    Ok(())
}

fn validate_observation(
    observation: &CapabilityObservation,
    standard_schema_bytes: &[u8],
    experimental_schema_bytes: &[u8],
) -> Result<(), B1PermissionProfileFault> {
    if observation.profile != B1_PERMISSION_PROFILE_OBSERVATION_PROFILE
        || observation.source_snapshot_uuid != B1_PERMISSION_PROFILE_SOURCE_SNAPSHOT_UUID
        || observation.predecessor_commit != B1_PERMISSION_PROFILE_PREDECESSOR_COMMIT
    {
        return Err(fault(
            B1PermissionProfileFaultCode::Lineage,
            "observation profile or lineage differs",
        ));
    }
    validate_historical_not_run(&observation.historical_not_run)?;
    validate_selected_executable(&observation.selected_executable)?;
    validate_schema_generation(
        &observation.schema_generation,
        standard_schema_bytes,
        experimental_schema_bytes,
    )?;
    validate_schema_coordinates(standard_schema_bytes, experimental_schema_bytes)?;
    validate_permission_profile(&observation.permission_profile)?;
    validate_sentinels(&observation.sentinels, &observation.permission_profile)?;
    validate_transcript(&observation.transcript)?;
    validate_boundaries(&observation.boundaries)?;
    Ok(())
}

fn validate_historical_not_run(value: &HistoricalNotRun) -> Result<(), B1PermissionProfileFault> {
    if value.profile != "cantor-self-work-update-broker-b1-preflight-record/0.1"
        || value.refusal_code != HISTORICAL_REFUSAL
        || value.run_count != 0
        || value.record_digest != HISTORICAL_NOT_RUN_DIGEST
    {
        return Err(fault(
            B1PermissionProfileFaultCode::Lineage,
            "historical NotRun identity differs",
        ));
    }
    Ok(())
}

fn validate_selected_executable(
    value: &SelectedExecutable,
) -> Result<(), B1PermissionProfileFault> {
    if value.path != SELECTED_EXECUTABLE
        || value.bytes != SELECTED_EXECUTABLE_BYTES
        || value.sha256 != SELECTED_EXECUTABLE_SHA256
        || value.version_output != "codex-cli 0.135.0"
    {
        return Err(fault(
            B1PermissionProfileFaultCode::Selection,
            "selected executable identity differs",
        ));
    }
    Ok(())
}

fn validate_schema_generation(
    value: &SchemaGeneration,
    standard: &[u8],
    experimental: &[u8],
) -> Result<(), B1PermissionProfileFault> {
    validate_schema_run(&value.standard, false, STANDARD_SCHEMA_FILE, standard)?;
    validate_schema_run(
        &value.experimental,
        true,
        EXPERIMENTAL_SCHEMA_FILE,
        experimental,
    )?;
    if value.standard.argv.last() == value.experimental.argv.last() {
        return Err(fault(
            B1PermissionProfileFaultCode::Schema,
            "standard and experimental output roots are not distinct",
        ));
    }
    Ok(())
}

fn validate_schema_run(
    value: &SchemaRun,
    experimental: bool,
    expected_file: &str,
    raw: &[u8],
) -> Result<(), B1PermissionProfileFault> {
    let expected_prefix = if experimental {
        vec![
            "app-server",
            "generate-json-schema",
            "--experimental",
            "--out",
        ]
    } else {
        vec!["app-server", "generate-json-schema", "--out"]
    };
    if value.argv.len() != expected_prefix.len() + 1
        || value
            .argv
            .iter()
            .zip(expected_prefix)
            .any(|(actual, expected)| actual != expected)
        || !is_cantor_local_path(value.argv.last().expect("length checked"))
        || value.exit_code != 0
        || !value.stdout.is_empty()
        || !value.stderr.is_empty()
        || value.evidence_file != expected_file
        || value.bytes != raw.len() as u64
        || value.sha256 != sha256_upper(raw)
    {
        return Err(fault(
            B1PermissionProfileFaultCode::Schema,
            "schema generation observation differs",
        ));
    }
    Ok(())
}

fn validate_schema_coordinates(
    standard_bytes: &[u8],
    experimental_bytes: &[u8],
) -> Result<(), B1PermissionProfileFault> {
    let standard: Value = parse_strict_json(standard_bytes)?;
    let experimental: Value = parse_strict_json(experimental_bytes)?;

    let standard_properties = read_only_properties(&standard)?;
    if standard_properties != ["networkAccess", "type"] {
        return Err(fault(
            B1PermissionProfileFaultCode::Schema,
            "stable readOnly property set differs",
        ));
    }

    for pointer in [
        "/definitions/v2/CommandExecParams/properties/permissionProfile",
        "/definitions/v2/ThreadStartParams/properties/permissions",
        "/definitions/v2/ThreadStartParams/properties/runtimeWorkspaceRoots",
        "/definitions/v2/TurnStartParams/properties/permissions",
        "/definitions/v2/TurnStartParams/properties/runtimeWorkspaceRoots",
        "/definitions/v2/RequestPermissionProfile/properties/fileSystem",
        "/definitions/v2/AdditionalFileSystemPermissions/properties/entries",
    ] {
        if experimental.pointer(pointer).is_none() {
            return Err(fault(
                B1PermissionProfileFaultCode::Schema,
                format!("experimental schema coordinate is absent: {pointer}"),
            ));
        }
    }
    if !contains_string(&experimental, "permissionProfile/list") {
        return Err(fault(
            B1PermissionProfileFaultCode::Schema,
            "permissionProfile/list method is absent",
        ));
    }
    let mut access_modes = string_array(
        experimental
            .pointer("/definitions/v2/FileSystemAccessMode/enum")
            .ok_or_else(|| {
                fault(
                    B1PermissionProfileFaultCode::Schema,
                    "filesystem access-mode enum is absent",
                )
            })?,
    )?;
    access_modes.sort();
    if access_modes != ["deny", "read", "write"] {
        return Err(fault(
            B1PermissionProfileFaultCode::Schema,
            "filesystem access-mode set differs",
        ));
    }
    let mut path_kinds = BTreeSet::new();
    let variants = experimental
        .pointer("/definitions/v2/FileSystemPath/oneOf")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            fault(
                B1PermissionProfileFaultCode::Schema,
                "filesystem path variants are absent",
            )
        })?;
    for variant in variants {
        let kind = variant
            .pointer("/properties/type/enum/0")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                fault(
                    B1PermissionProfileFaultCode::Schema,
                    "filesystem path kind differs",
                )
            })?;
        path_kinds.insert(kind);
    }
    if path_kinds != BTreeSet::from(["glob_pattern", "path", "special"]) {
        return Err(fault(
            B1PermissionProfileFaultCode::Schema,
            "filesystem path-kind set differs",
        ));
    }
    Ok(())
}

fn read_only_properties(schema: &Value) -> Result<Vec<&str>, B1PermissionProfileFault> {
    let variants = schema
        .pointer("/definitions/v2/SandboxPolicy/oneOf")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            fault(
                B1PermissionProfileFaultCode::Schema,
                "SandboxPolicy variants are absent",
            )
        })?;
    let read_only = variants
        .iter()
        .find(|variant| {
            variant.get("title").and_then(Value::as_str) == Some("ReadOnlySandboxPolicy")
        })
        .ok_or_else(|| {
            fault(
                B1PermissionProfileFaultCode::Schema,
                "ReadOnlySandboxPolicy is absent",
            )
        })?;
    let properties = read_only
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            fault(
                B1PermissionProfileFaultCode::Schema,
                "readOnly properties are absent",
            )
        })?;
    let mut names: Vec<_> = properties.keys().map(String::as_str).collect();
    names.sort();
    Ok(names)
}

fn validate_permission_profile(
    value: &PermissionProfileObservation,
) -> Result<(), B1PermissionProfileFault> {
    if value.id != PERMISSION_PROFILE_ID
        || value.root_access != "deny"
        || value.minimal_access != "read"
        || value.fixture_access != "read"
        || value.denied_access != "deny"
        || value.network_enabled
        || !is_cantor_local_path(&value.fixture_root)
        || value.denied_path != format!("{}\\denied.txt", value.fixture_root)
    {
        return Err(fault(
            B1PermissionProfileFaultCode::Profile,
            "permission-profile coordinate differs",
        ));
    }
    let expected_override = format!(
        "permissions.swa05_probe.filesystem={{':root'='deny',':minimal'='read','{}'='read','{}'='deny'}}",
        value.fixture_root, value.denied_path
    );
    if value.filesystem_override != expected_override {
        return Err(fault(
            B1PermissionProfileFaultCode::Profile,
            "permission-profile override differs",
        ));
    }
    Ok(())
}

fn validate_sentinels(
    sentinels: &SentinelObservation,
    profile: &PermissionProfileObservation,
) -> Result<(), B1PermissionProfileFault> {
    if sentinels.allowed_path != format!("{}\\allowed.txt", profile.fixture_root)
        || sentinels.denied_path != profile.denied_path
        || sentinels.allowed_sha256 != sha256_upper(ALLOWED_SENTINEL.as_bytes())
        || sentinels.denied_sha256 != sha256_upper(DENIED_SENTINEL.as_bytes())
    {
        return Err(fault(
            B1PermissionProfileFaultCode::Enforcement,
            "sentinel identity differs",
        ));
    }
    Ok(())
}

fn validate_transcript(transcript: &[Value]) -> Result<(), B1PermissionProfileFault> {
    if transcript.len() != 5 {
        return Err(fault(
            B1PermissionProfileFaultCode::Transcript,
            "transcript frame count differs",
        ));
    }
    let initialize = response_result(&transcript[0], 0)?;
    let user_agent = initialize
        .get("userAgent")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            fault(
                B1PermissionProfileFaultCode::Transcript,
                "userAgent is absent",
            )
        })?;
    if !user_agent.starts_with("Codex Desktop/0.135.0 (Windows ")
        || !user_agent.ends_with("dumb (cantor_swa05_probe; 0.1.0)")
        || initialize.get("codexHome").and_then(Value::as_str) != Some("C:\\Users\\enjer\\.codex")
        || initialize.get("platformFamily").and_then(Value::as_str) != Some("windows")
        || initialize.get("platformOs").and_then(Value::as_str) != Some("windows")
        || initialize.len() != 4
    {
        return Err(fault(
            B1PermissionProfileFaultCode::Transcript,
            "initialize result differs",
        ));
    }

    let notification = transcript[1].as_object().ok_or_else(|| {
        fault(
            B1PermissionProfileFaultCode::Transcript,
            "status notification is not an object",
        )
    })?;
    if notification.len() != 2
        || notification.get("method").and_then(Value::as_str)
            != Some("remoteControl/status/changed")
        || notification
            .get("params")
            .and_then(|value| value.get("status"))
            .and_then(Value::as_str)
            != Some("disabled")
        || notification
            .get("params")
            .and_then(|value| value.get("environmentId"))
            != Some(&Value::Null)
    {
        return Err(fault(
            B1PermissionProfileFaultCode::Transcript,
            "local status notification differs",
        ));
    }
    let status_params = notification["params"].as_object().ok_or_else(|| {
        fault(
            B1PermissionProfileFaultCode::Transcript,
            "local status params differ",
        )
    })?;
    let installation_id = status_params
        .get("installationId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if status_params.len() != 4
        || status_params.get("serverName").and_then(Value::as_str) != Some("TheBrain")
        || !is_lower_uuid(installation_id)
    {
        return Err(fault(
            B1PermissionProfileFaultCode::Transcript,
            "local status identity differs",
        ));
    }

    let profile_list = response_result(&transcript[2], 1)?;
    let profiles = profile_list
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            fault(
                B1PermissionProfileFaultCode::Transcript,
                "profile list is absent",
            )
        })?;
    let expected_profiles = [
        ":read-only",
        ":workspace",
        ":danger-full-access",
        PERMISSION_PROFILE_ID,
    ];
    if profiles.len() != expected_profiles.len()
        || profiles
            .iter()
            .zip(expected_profiles)
            .any(|(profile, expected)| {
                profile.as_object().map(Map::len) != Some(2)
                    || profile.get("id").and_then(Value::as_str) != Some(expected)
                    || profile.get("description") != Some(&Value::Null)
            })
        || profile_list.get("nextCursor") != Some(&Value::Null)
        || profile_list.len() != 2
    {
        return Err(fault(
            B1PermissionProfileFaultCode::Transcript,
            "permission profile list differs",
        ));
    }

    let allowed = command_result(&transcript[3], 2)?;
    if allowed != (0, ALLOWED_SENTINEL, "") {
        return Err(fault(
            B1PermissionProfileFaultCode::Enforcement,
            "allowed-read result differs",
        ));
    }
    let denied = command_result(&transcript[4], 3)?;
    if denied.0 == 0
        || !denied.1.is_empty()
        || denied.2 != "Access is denied.\r\n"
        || denied.1.contains("SWA05_DENIED_READ_SENTINEL")
        || denied.2.contains("SWA05_DENIED_READ_SENTINEL")
    {
        return Err(fault(
            B1PermissionProfileFaultCode::Enforcement,
            "denied-read result differs",
        ));
    }
    Ok(())
}

fn response_result(
    frame: &Value,
    id: u64,
) -> Result<&Map<String, Value>, B1PermissionProfileFault> {
    let object = frame.as_object().ok_or_else(|| {
        fault(
            B1PermissionProfileFaultCode::Transcript,
            "response frame is not an object",
        )
    })?;
    if object.len() != 2 || object.get("id").and_then(Value::as_u64) != Some(id) {
        return Err(fault(
            B1PermissionProfileFaultCode::Transcript,
            "response id or shape differs",
        ));
    }
    object
        .get("result")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            fault(
                B1PermissionProfileFaultCode::Transcript,
                "response result is absent",
            )
        })
}

fn command_result(frame: &Value, id: u64) -> Result<(i64, &str, &str), B1PermissionProfileFault> {
    let result = response_result(frame, id)?;
    if result.len() != 3 {
        return Err(fault(
            B1PermissionProfileFaultCode::Transcript,
            "command result shape differs",
        ));
    }
    Ok((
        result
            .get("exitCode")
            .and_then(Value::as_i64)
            .ok_or_else(|| {
                fault(
                    B1PermissionProfileFaultCode::Transcript,
                    "command exit code is absent",
                )
            })?,
        result
            .get("stdout")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                fault(
                    B1PermissionProfileFaultCode::Transcript,
                    "command stdout is absent",
                )
            })?,
        result
            .get("stderr")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                fault(
                    B1PermissionProfileFaultCode::Transcript,
                    "command stderr is absent",
                )
            })?,
    ))
}

fn validate_boundaries(value: &CapabilityBoundaries) -> Result<(), B1PermissionProfileFault> {
    if value.writer_run_count != 0
        || value.provider_contact_count != 0
        || value.model_turn_count != 0
        || value.mcp_call_count != 0
        || value.git_command_count != 0
        || value.remote_contact_count != 0
        || value.d_drive_contact_count != 0
        || value.product_mutation_count != 0
        || value.cleanup_count != 0
        || !value.scratch_mutation_performed
        || value.service_network_observed
        || value.live_writer_allowed
    {
        return Err(fault(
            B1PermissionProfileFaultCode::Authority,
            "observation effect boundary differs",
        ));
    }
    Ok(())
}

fn read_bounded_regular_file(root: &Path, name: &str) -> Result<Vec<u8>, B1PermissionProfileFault> {
    if !is_simple_name(name) {
        return Err(fault(
            B1PermissionProfileFaultCode::Path,
            "artifact path is not one simple name",
        ));
    }
    let path = root.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        fault(
            B1PermissionProfileFaultCode::Path,
            format!("artifact metadata failed for {name}: {error}"),
        )
    })?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > B1_PERMISSION_PROFILE_MAX_ARTIFACT_BYTES
    {
        return Err(fault(
            B1PermissionProfileFaultCode::Bound,
            format!("artifact is not one bounded regular file: {name}"),
        ));
    }
    let canonical = fs::canonicalize(&path).map_err(|error| {
        fault(
            B1PermissionProfileFaultCode::Path,
            format!("artifact canonicalization failed for {name}: {error}"),
        )
    })?;
    if canonical.parent() != Some(root) {
        return Err(fault(
            B1PermissionProfileFaultCode::Path,
            format!("artifact escapes evidence root: {name}"),
        ));
    }
    fs::read(&canonical).map_err(|error| {
        fault(
            B1PermissionProfileFaultCode::Path,
            format!("artifact read failed for {name}: {error}"),
        )
    })
}

fn artifact<'a>(
    artifacts: &'a [(&str, Vec<u8>)],
    name: &str,
) -> Result<&'a [u8], B1PermissionProfileFault> {
    artifacts
        .iter()
        .find(|(path, _)| *path == name)
        .map(|(_, bytes)| bytes.as_slice())
        .ok_or_else(|| {
            fault(
                B1PermissionProfileFaultCode::Manifest,
                format!("required artifact is absent: {name}"),
            )
        })
}

fn is_simple_name(value: &str) -> bool {
    !value.is_empty()
        && Path::new(value).components().count() == 1
        && matches!(
            Path::new(value).components().next(),
            Some(Component::Normal(_))
        )
        && !value.contains(['/', '\\'])
}

fn is_cantor_local_path(value: &str) -> bool {
    value.starts_with("C:\\Project\\Cantor\\.local\\")
        && !value.contains("..")
        && !value.starts_with("D:")
}

fn is_lower_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn contains_string(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(value) => value == expected,
        Value::Array(values) => values.iter().any(|value| contains_string(value, expected)),
        Value::Object(values) => values
            .values()
            .any(|value| contains_string(value, expected)),
        _ => false,
    }
}

fn string_array(value: &Value) -> Result<Vec<&str>, B1PermissionProfileFault> {
    value
        .as_array()
        .ok_or_else(|| {
            fault(
                B1PermissionProfileFaultCode::Schema,
                "schema string array differs",
            )
        })?
        .iter()
        .map(|value| {
            value.as_str().ok_or_else(|| {
                fault(
                    B1PermissionProfileFaultCode::Schema,
                    "schema string-array member differs",
                )
            })
        })
        .collect()
}

fn parse_strict_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, B1PermissionProfileFault> {
    if bytes.is_empty() || bytes.len() > B1_PERMISSION_PROFILE_MAX_ARTIFACT_BYTES as usize {
        return Err(fault(
            B1PermissionProfileFaultCode::Bound,
            "JSON artifact is empty or oversized",
        ));
    }
    let value: NoDuplicateValue = serde_json::from_slice(bytes).map_err(machine_fault)?;
    serde_json::from_value(value.0).map_err(machine_fault)
}

struct NoDuplicateValue(Value);

impl<'de> Deserialize<'de> for NoDuplicateValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateVisitor)
    }
}

struct NoDuplicateVisitor;

impl<'de> Visitor<'de> for NoDuplicateVisitor {
    type Value = NoDuplicateValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a duplicate-free JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(NoDuplicateValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<NoDuplicateValue>()? {
            values.push(value.0);
        }
        Ok(NoDuplicateValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate JSON key: {key}")));
            }
            let value = map.next_value::<NoDuplicateValue>()?;
            values.insert(key, value.0);
        }
        Ok(NoDuplicateValue(Value::Object(values)))
    }
}

fn validate_digest(value: &ContentDigest) -> Result<(), B1PermissionProfileFault> {
    if value.algorithm != "sha256"
        || value.value.len() != 64
        || !value
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(fault(
            B1PermissionProfileFaultCode::Digest,
            "content digest differs",
        ));
    }
    Ok(())
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn sha256_upper(bytes: &[u8]) -> String {
    sha256_bytes(bytes).value.to_uppercase()
}

fn is_upper_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
}

fn machine_fault(error: serde_json::Error) -> B1PermissionProfileFault {
    fault(B1PermissionProfileFaultCode::MachineForm, error.to_string())
}

fn fault(
    code: B1PermissionProfileFaultCode,
    message: impl Into<String>,
) -> B1PermissionProfileFault {
    B1PermissionProfileFault {
        code,
        message: message.into(),
    }
}
