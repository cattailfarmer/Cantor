//! Independent SWA-05 B1 preparation-evidence verification.
//!
//! The selected npm-native schema cannot express the governed denied-read
//! coordinate, so this module can emit only a deterministic `NotRun` record.
//! It reads caller-supplied evidence; it has no producer, process, cleanup, or
//! provider surface.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::{Component, Path},
};

use cantor_core::{ContentDigest, sha256_bytes};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};

pub const B1_PREPARATION_MANIFEST_PROFILE: &str =
    "cantor-self-work-update-broker-b1-preparation-evidence-manifest/0.1";
pub const B1_PREPARATION_PROFILE: &str =
    "cantor-self-work-update-broker-b1-npm-native-preparation/0.1";
pub const B1_PREFLIGHT_RECORD_PROFILE: &str =
    "cantor-self-work-update-broker-b1-preflight-record/0.1";
pub const B1_SOURCE_SNAPSHOT_UUID: &str = "1df674af-2786-4135-972f-3ac52bfba036";
pub const B1_PREPARATION_SOURCE_SNAPSHOT_UUID: &str = "ba57adf0-46fa-40e1-b29f-59c14f5c83f0";
pub const B1_PREDECESSOR_COMMIT: &str = "12d9c8a71d653680056233d5b75b0fa05702926b";
pub const B1_REFUSAL_CODE: &str = "selected_schema_missing_read_scope_control";
pub const B1_RECOVERY_OWNER: &str = "THEBRAIN\\enjer";
pub const B1_MAX_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024;
pub const B1_MAX_MACHINE_FORM_BYTES: usize = 1024 * 1024;

const MANIFEST_FILE: &str = "manifest.json";
const RESULT_FILE: &str = "preparation_result.json";
const SCHEMA_INVENTORY_FILE: &str = "schema_inventory.tsv";
const ENVELOPE_INVENTORY_FILE: &str = "envelope_inventory.tsv";
const DIRECTORY_INVENTORY_FILE: &str = "directory_inventory.tsv";
const SELECTED_EXECUTABLE_SHA256: &str =
    "FE12887B4AB4A4E988F0FA5BAAE9E5CB7D8505C26401378628E762DB9A2E798F";
const SELECTED_PACKAGE_SHA256: &str =
    "371B503B75F22FAAEC071D87C2DB45D9B438056CB52FE5959731EF1D6025C013";
const COMMAND_EXEC_PARAMS_SHA256: &str =
    "9F6C382E9F494C133952B828BD08E02CF091FF3490719A0C2C5EEA35705DCBC8";
const COMMAND_EXEC_RESPONSE_SHA256: &str =
    "0DBCACAA27D794D801E701513A8CFB9D247CF20624C9A05BB6231866EBEEECB8";
const INITIALIZE_PARAMS_SHA256: &str =
    "F6540330C6492971750AD0CAA532904EB08547BD8D849A053AECF36C803C49F7";
const INITIALIZE_RESPONSE_SHA256: &str =
    "86DCD236D0576A82C85B933586DC45731260EAB1B6EDB3447B03F790277322B1";
const RECORD_DOMAIN: &str = "cantor.self-work-update-broker-b1.preflight-record.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceManifest {
    profile: String,
    source_snapshot_uuid: String,
    artifacts: Vec<ArtifactIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactIdentity {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparationResult {
    profile: String,
    source_snapshot_uuid: String,
    predecessor_commit: String,
    disposition: String,
    recovery_owner: String,
    selected_executable: SelectedExecutable,
    fixture: PreparedFixture,
    schema_generation: SchemaGeneration,
    final_b1_admission: FinalB1Admission,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectedExecutable {
    path: String,
    bytes: u64,
    sha256: String,
    file_id: String,
    package_path: String,
    package_sha256: String,
    package_version: String,
    signer: String,
    signer_thumbprint: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleIdentity {
    role: String,
    path: String,
    file_id: String,
    attributes: u32,
    reparse: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedFixture {
    volume_id: String,
    roles: Vec<RoleIdentity>,
    directory_count: usize,
    directory_inventory_bytes: usize,
    directory_inventory_sha256: String,
    file_count: usize,
    file_inventory_bytes: usize,
    file_inventory_sha256: String,
    candidate_head: String,
    candidate_branch: String,
    candidate_common_dir: String,
    candidate_git_dir: String,
    candidate_clean: bool,
    candidate_remote_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentDigest {
    name: String,
    value_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaGeneration {
    argv: Vec<String>,
    environment_clear_first: bool,
    environment: Vec<EnvironmentDigest>,
    started_utc: String,
    ended_utc: String,
    elapsed_milliseconds: u64,
    deadline_milliseconds: u64,
    stdout_bytes: usize,
    stderr_bytes: usize,
    exit_code: i32,
    timed_out: bool,
    selected_executable_post_sha256: String,
    active_selected_process_count_after: usize,
    schema_file_count: usize,
    schema_total_bytes: f64,
    schema_inventory_bytes: usize,
    schema_inventory_sha256: String,
    command_exec_params_sha256: String,
    command_exec_response_sha256: String,
    initialize_params_sha256: String,
    initialize_response_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalB1Admission {
    eligible: bool,
    run_count: usize,
    transcript_frame_count: usize,
    restricted_read_scope_representable: bool,
    read_only_policy_properties: Vec<String>,
    refusal_code: Option<String>,
    provider_contact_count: usize,
    model_turn_count: usize,
    mcp_call_count: usize,
    external_network_count: usize,
    mutation_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1PreflightDisposition {
    NotRun,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1PreflightAuthority {
    PreflightObservationOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1PreflightRecord {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub preparation_source_snapshot_uuid: String,
    pub preparation_manifest_sha256: ContentDigest,
    pub preparation_result_sha256: ContentDigest,
    pub disposition: B1PreflightDisposition,
    pub authority: B1PreflightAuthority,
    pub refusal_code: String,
    pub run_count: u8,
    pub transcript_frame_count: u8,
    pub provider_contact_count: u8,
    pub model_turn_count: u8,
    pub mcp_call_count: u8,
    pub external_network_count: u8,
    pub mutation_count: u8,
    pub physical_contact: bool,
    pub may_have_mutated: bool,
    pub live_process_launched: bool,
    pub fixture_quarantined: bool,
    pub cleanup_performed: bool,
    pub recovery_owner: String,
    pub record_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1PreflightFaultCode {
    Path,
    Bound,
    Manifest,
    Digest,
    MachineForm,
    Inventory,
    Selection,
    Fixture,
    Schema,
    Compatibility,
    Authority,
    Record,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1PreflightFault {
    pub code: B1PreflightFaultCode,
    pub message: String,
}

impl fmt::Display for B1PreflightFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for B1PreflightFault {}

pub fn verify_b1_preparation_evidence(
    evidence_root: &Path,
) -> Result<B1PreflightRecord, B1PreflightFault> {
    let root = fs::canonicalize(evidence_root).map_err(|error| {
        fault(
            B1PreflightFaultCode::Path,
            format!("evidence root cannot be canonicalized: {error}"),
        )
    })?;
    if !root.is_dir() {
        return Err(fault(
            B1PreflightFaultCode::Path,
            "evidence root is not a directory",
        ));
    }

    let manifest_bytes = read_bounded_regular_file(&root, MANIFEST_FILE)?;
    let manifest: EvidenceManifest = parse_strict_json(&manifest_bytes)?;
    validate_manifest(&manifest)?;

    let mut artifacts = BTreeMap::new();
    for artifact in &manifest.artifacts {
        let bytes = read_bounded_regular_file(&root, &artifact.path)?;
        if bytes.len() as u64 != artifact.bytes || sha256_upper(&bytes) != artifact.sha256 {
            return Err(fault(
                B1PreflightFaultCode::Digest,
                format!("artifact identity differs for {}", artifact.path),
            ));
        }
        artifacts.insert(artifact.path.clone(), bytes);
    }

    let result_bytes = artifact(&artifacts, RESULT_FILE)?;
    let schema_bytes = artifact(&artifacts, SCHEMA_INVENTORY_FILE)?;
    let envelope_bytes = artifact(&artifacts, ENVELOPE_INVENTORY_FILE)?;
    let directory_bytes = artifact(&artifacts, DIRECTORY_INVENTORY_FILE)?;
    let result: PreparationResult = parse_strict_json(result_bytes)?;
    let schema = parse_file_inventory(schema_bytes, "schema inventory")?;
    let envelope = parse_file_inventory(envelope_bytes, "envelope inventory")?;
    let directory_count = parse_directory_inventory(directory_bytes)?;
    validate_preparation_result(
        &result,
        schema_bytes,
        &schema,
        envelope_bytes,
        &envelope,
        directory_bytes,
        directory_count,
    )?;

    let mut record = B1PreflightRecord {
        profile: B1_PREFLIGHT_RECORD_PROFILE.to_owned(),
        source_snapshot_uuid: B1_SOURCE_SNAPSHOT_UUID.to_owned(),
        preparation_source_snapshot_uuid: B1_PREPARATION_SOURCE_SNAPSHOT_UUID.to_owned(),
        preparation_manifest_sha256: digest(&manifest_bytes),
        preparation_result_sha256: digest(result_bytes),
        disposition: B1PreflightDisposition::NotRun,
        authority: B1PreflightAuthority::PreflightObservationOnly,
        refusal_code: B1_REFUSAL_CODE.to_owned(),
        run_count: 0,
        transcript_frame_count: 0,
        provider_contact_count: 0,
        model_turn_count: 0,
        mcp_call_count: 0,
        external_network_count: 0,
        mutation_count: 0,
        physical_contact: false,
        may_have_mutated: false,
        live_process_launched: false,
        fixture_quarantined: true,
        cleanup_performed: false,
        recovery_owner: B1_RECOVERY_OWNER.to_owned(),
        record_digest: empty_digest(),
    };
    record.record_digest = b1_preflight_record_digest(&record)?;
    verify_b1_preflight_record(&record)?;
    Ok(record)
}

pub fn verify_b1_preflight_record(record: &B1PreflightRecord) -> Result<(), B1PreflightFault> {
    if record.profile != B1_PREFLIGHT_RECORD_PROFILE
        || record.source_snapshot_uuid != B1_SOURCE_SNAPSHOT_UUID
        || record.preparation_source_snapshot_uuid != B1_PREPARATION_SOURCE_SNAPSHOT_UUID
    {
        return Err(fault(
            B1PreflightFaultCode::Record,
            "record profile or source identity differs",
        ));
    }
    if record.disposition != B1PreflightDisposition::NotRun
        || record.authority != B1PreflightAuthority::PreflightObservationOnly
        || record.refusal_code != B1_REFUSAL_CODE
        || record.run_count != 0
        || record.transcript_frame_count != 0
        || record.provider_contact_count != 0
        || record.model_turn_count != 0
        || record.mcp_call_count != 0
        || record.external_network_count != 0
        || record.mutation_count != 0
        || record.physical_contact
        || record.may_have_mutated
        || record.live_process_launched
        || !record.fixture_quarantined
        || record.cleanup_performed
        || record.recovery_owner != B1_RECOVERY_OWNER
    {
        return Err(fault(
            B1PreflightFaultCode::Authority,
            "record widens NotRun authority or count boundary",
        ));
    }
    validate_digest(&record.preparation_manifest_sha256)?;
    validate_digest(&record.preparation_result_sha256)?;
    validate_digest(&record.record_digest)?;
    if record.record_digest != b1_preflight_record_digest(record)? {
        return Err(fault(
            B1PreflightFaultCode::Digest,
            "record self-digest differs",
        ));
    }
    Ok(())
}

pub fn to_b1_preflight_record_machine_form(
    record: &B1PreflightRecord,
) -> Result<String, B1PreflightFault> {
    verify_b1_preflight_record(record)?;
    let value = serde_json::to_string(record).map_err(machine_fault)?;
    if value.len() > B1_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            B1PreflightFaultCode::Bound,
            "record machine form is oversized",
        ));
    }
    Ok(value)
}

pub fn from_b1_preflight_record_machine_form(
    value: &str,
) -> Result<B1PreflightRecord, B1PreflightFault> {
    if value.is_empty() || value.len() > B1_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            B1PreflightFaultCode::Bound,
            "record machine form is empty or oversized",
        ));
    }
    let record: B1PreflightRecord = parse_strict_json(value.as_bytes())?;
    verify_b1_preflight_record(&record)?;
    Ok(record)
}

fn validate_manifest(manifest: &EvidenceManifest) -> Result<(), B1PreflightFault> {
    if manifest.profile != B1_PREPARATION_MANIFEST_PROFILE
        || manifest.source_snapshot_uuid != B1_PREPARATION_SOURCE_SNAPSHOT_UUID
    {
        return Err(fault(
            B1PreflightFaultCode::Manifest,
            "manifest profile or source identity differs",
        ));
    }
    let expected = [
        DIRECTORY_INVENTORY_FILE,
        ENVELOPE_INVENTORY_FILE,
        RESULT_FILE,
        SCHEMA_INVENTORY_FILE,
    ];
    if manifest.artifacts.len() != expected.len() {
        return Err(fault(
            B1PreflightFaultCode::Manifest,
            "manifest artifact count differs",
        ));
    }
    for (artifact, expected_path) in manifest.artifacts.iter().zip(expected) {
        if artifact.path != expected_path
            || artifact.bytes == 0
            || artifact.bytes > B1_MAX_ARTIFACT_BYTES
            || !is_upper_sha256(&artifact.sha256)
        {
            return Err(fault(
                B1PreflightFaultCode::Manifest,
                "manifest artifact coordinate differs",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_preparation_result(
    result: &PreparationResult,
    schema_raw: &[u8],
    schema: &InventoryAccount,
    envelope_raw: &[u8],
    envelope: &InventoryAccount,
    directory_raw: &[u8],
    directory_count: usize,
) -> Result<(), B1PreflightFault> {
    if result.profile != B1_PREPARATION_PROFILE
        || result.source_snapshot_uuid != B1_PREPARATION_SOURCE_SNAPSHOT_UUID
        || result.predecessor_commit != B1_PREDECESSOR_COMMIT
        || result.disposition != "prepared_final_b1_not_run"
        || result.recovery_owner != B1_RECOVERY_OWNER
    {
        return Err(fault(
            B1PreflightFaultCode::Selection,
            "preparation lineage or disposition differs",
        ));
    }
    validate_selected_executable(&result.selected_executable)?;
    validate_fixture(
        &result.fixture,
        envelope_raw,
        envelope,
        directory_raw,
        directory_count,
    )?;
    validate_schema_generation(&result.schema_generation, schema_raw, schema)?;
    validate_final_admission(&result.final_b1_admission)?;
    Ok(())
}

fn validate_selected_executable(value: &SelectedExecutable) -> Result<(), B1PreflightFault> {
    if value.path
        != "C:\\Users\\enjer\\AppData\\Roaming\\npm\\node_modules\\@openai\\codex\\node_modules\\@openai\\codex-win32-x64\\vendor\\x86_64-pc-windows-msvc\\bin\\codex.exe"
        || value.bytes != 242_541_872
        || value.sha256 != SELECTED_EXECUTABLE_SHA256
        || value.file_id != "0x0000000000000000000300000007640e"
        || value.package_path
            != "C:\\Users\\enjer\\AppData\\Roaming\\npm\\node_modules\\@openai\\codex\\package.json"
        || value.package_sha256 != SELECTED_PACKAGE_SHA256
        || value.package_version != "0.135.0"
        || value.signer != "OpenAI OpCo LLC"
        || value.signer_thumbprint != "E370424E072D7BD3CE08EBF7D30A8B5581605535"
    {
        return Err(fault(
            B1PreflightFaultCode::Selection,
            "selected executable identity differs",
        ));
    }
    Ok(())
}

fn validate_fixture(
    fixture: &PreparedFixture,
    envelope_raw: &[u8],
    envelope: &InventoryAccount,
    directory_raw: &[u8],
    directory_count: usize,
) -> Result<(), B1PreflightFault> {
    if fixture.volume_id != "\\\\?\\Volume{1bfda880-4592-426d-bc09-a5733fb130ac}\\"
        || fixture.roles.len() != 9
        || fixture.roles.iter().any(|role| role.reparse)
        || fixture.directory_count != 30
        || fixture.directory_count != directory_count
        || fixture.directory_inventory_bytes != directory_raw.len()
        || fixture.directory_inventory_sha256 != sha256_upper(directory_raw)
        || fixture.file_count != 284
        || fixture.file_count != envelope.rows
        || fixture.file_inventory_bytes != envelope_raw.len()
        || fixture.file_inventory_sha256 != sha256_upper(envelope_raw)
        || fixture.candidate_head != "e451901290384fc8a509327139e5a475596fbf18"
        || fixture.candidate_branch != "refs/heads/main"
        || fixture.candidate_common_dir != "D:\\CantorB1\\fixture\\candidate\\.git"
        || fixture.candidate_git_dir != "D:\\CantorB1\\fixture\\candidate\\.git"
        || !fixture.candidate_clean
        || fixture.candidate_remote_count != 0
    {
        return Err(fault(
            B1PreflightFaultCode::Fixture,
            "fixture identity or inventory differs",
        ));
    }
    let expected_roles = [
        ("authorization_envelope", "D:\\CantorB1"),
        ("disposable_fixture", "D:\\CantorB1\\fixture"),
        ("candidate_workspace", "D:\\CantorB1\\fixture\\candidate"),
        ("app_server_state", "D:\\CantorB1\\fixture\\codex-home"),
        ("sqlite_state", "D:\\CantorB1\\fixture\\codex-sqlite"),
        ("canary", "D:\\CantorB1\\fixture\\canary"),
        ("temporary", "D:\\CantorB1\\fixture\\temp"),
        ("schema_output", "D:\\CantorB1\\fixture\\schema"),
        ("prospective_evidence", "D:\\CantorB1\\evidence"),
    ];
    for (role, expected) in fixture.roles.iter().zip(expected_roles) {
        if role.role != expected.0
            || role.path != expected.1
            || !is_file_id(&role.file_id)
            || role.attributes != 16
        {
            return Err(fault(
                B1PreflightFaultCode::Fixture,
                "fixture role identity differs",
            ));
        }
    }
    Ok(())
}

fn validate_schema_generation(
    schema: &SchemaGeneration,
    raw: &[u8],
    account: &InventoryAccount,
) -> Result<(), B1PreflightFault> {
    let expected_argv = [
        "app-server",
        "generate-json-schema",
        "--out",
        "D:\\CantorB1\\fixture\\schema",
    ];
    let expected_environment = [
        (
            "CODEX_HOME",
            "BAA23517E4A7432C4ACF1AC1C4050C496C0EF5F14DC19F4210A2DF577EB77233",
        ),
        (
            "CODEX_SQLITE_HOME",
            "4482467A0509D0830496C406CF33A3D5A629CE44B5A0D210D47E9EA13E9692EC",
        ),
        (
            "RUST_LOG",
            "CA00FCCFB408989EDDC401062C4D1219A6ACEB6B9B55412357F1790862E8F178",
        ),
        (
            "SystemRoot",
            "4C754B6DC9CD24A7E1A0801560911FBF9A832BF0F5B3BCBA0F3844A71356489C",
        ),
        (
            "TEMP",
            "1B34E64F487FA6553FFCFD9BF06D82426D2698CF0AB3F66186B212271191D56E",
        ),
        (
            "TMP",
            "1B34E64F487FA6553FFCFD9BF06D82426D2698CF0AB3F66186B212271191D56E",
        ),
    ];
    if schema.argv.iter().map(String::as_str).ne(expected_argv)
        || !schema.environment_clear_first
        || schema.environment.len() != expected_environment.len()
        || schema
            .environment
            .iter()
            .zip(expected_environment)
            .any(|(observed, expected)| {
                observed.name != expected.0 || observed.value_sha256 != expected.1
            })
        || schema.started_utc != "2026-08-25T17:15:47.9979737+00:00"
        || schema.ended_utc != "2026-08-25T17:15:49.4211572+00:00"
        || schema.elapsed_milliseconds != 1423
        || schema.deadline_milliseconds != 60_000
        || schema.stdout_bytes != 0
        || schema.stderr_bytes != 0
        || schema.exit_code != 0
        || schema.timed_out
        || schema.selected_executable_post_sha256 != SELECTED_EXECUTABLE_SHA256
        || schema.active_selected_process_count_after != 0
        || schema.schema_file_count != 254
        || schema.schema_file_count != account.rows
        || schema.schema_total_bytes != 2_468_056.0
        || account.total_file_bytes != 2_468_056
        || schema.schema_inventory_bytes != raw.len()
        || schema.schema_inventory_sha256 != sha256_upper(raw)
        || schema.command_exec_params_sha256 != COMMAND_EXEC_PARAMS_SHA256
        || schema.command_exec_response_sha256 != COMMAND_EXEC_RESPONSE_SHA256
        || schema.initialize_params_sha256 != INITIALIZE_PARAMS_SHA256
        || schema.initialize_response_sha256 != INITIALIZE_RESPONSE_SHA256
    {
        return Err(fault(
            B1PreflightFaultCode::Schema,
            "schema-generation account differs",
        ));
    }
    Ok(())
}

fn validate_final_admission(value: &FinalB1Admission) -> Result<(), B1PreflightFault> {
    if value.eligible
        || value.run_count != 0
        || value.transcript_frame_count != 0
        || value.restricted_read_scope_representable
        || value.read_only_policy_properties != ["networkAccess", "type"]
        || value.refusal_code.as_deref() != Some(B1_REFUSAL_CODE)
        || value.provider_contact_count != 0
        || value.model_turn_count != 0
        || value.mcp_call_count != 0
        || value.external_network_count != 0
        || value.mutation_count != 0
    {
        return Err(fault(
            B1PreflightFaultCode::Compatibility,
            "final B1 compatibility refusal differs",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InventoryAccount {
    rows: usize,
    total_file_bytes: u64,
}

fn parse_file_inventory(bytes: &[u8], label: &str) -> Result<InventoryAccount, B1PreflightFault> {
    let text = inventory_text(bytes, label)?;
    let mut previous: Option<String> = None;
    let mut total_file_bytes = 0_u64;
    let mut rows = 0_usize;
    for line in text[..text.len() - 1].split('\n') {
        let mut fields = line.split('\t');
        let path = fields.next().unwrap_or_default();
        let byte_text = fields.next().unwrap_or_default();
        let sha256 = fields.next().unwrap_or_default();
        if fields.next().is_some() || !is_safe_inventory_path(path) || !is_upper_sha256(sha256) {
            return Err(fault(
                B1PreflightFaultCode::Inventory,
                format!("{label} row grammar differs"),
            ));
        }
        let order_key = path.to_ascii_lowercase();
        if previous.as_ref().is_some_and(|prior| prior >= &order_key) {
            return Err(fault(
                B1PreflightFaultCode::Inventory,
                format!("{label} rows are duplicate or unsorted"),
            ));
        }
        let file_bytes = byte_text.parse::<u64>().map_err(|_| {
            fault(
                B1PreflightFaultCode::Inventory,
                format!("{label} byte count is invalid"),
            )
        })?;
        total_file_bytes = total_file_bytes.checked_add(file_bytes).ok_or_else(|| {
            fault(
                B1PreflightFaultCode::Bound,
                format!("{label} byte total overflowed"),
            )
        })?;
        previous = Some(order_key);
        rows += 1;
    }
    if rows == 0 {
        return Err(fault(
            B1PreflightFaultCode::Inventory,
            format!("{label} is empty"),
        ));
    }
    Ok(InventoryAccount {
        rows,
        total_file_bytes,
    })
}

fn parse_directory_inventory(bytes: &[u8]) -> Result<usize, B1PreflightFault> {
    let text = inventory_text(bytes, "directory inventory")?;
    let mut previous: Option<String> = None;
    let mut rows = 0_usize;
    for line in text[..text.len() - 1].split('\n') {
        let mut fields = line.split('\t');
        let path = fields.next().unwrap_or_default();
        let file_id = fields.next().unwrap_or_default();
        let attributes = fields.next().unwrap_or_default();
        let order_key = path.to_ascii_lowercase();
        if fields.next().is_some()
            || (path != "." && !is_safe_inventory_path(path))
            || !is_file_id(file_id)
            || attributes.parse::<u32>().is_err()
            || previous.as_ref().is_some_and(|prior| prior >= &order_key)
        {
            return Err(fault(
                B1PreflightFaultCode::Inventory,
                "directory inventory row grammar order or identity differs",
            ));
        }
        previous = Some(order_key);
        rows += 1;
    }
    if rows == 0 {
        return Err(fault(
            B1PreflightFaultCode::Inventory,
            "directory inventory is empty",
        ));
    }
    Ok(rows)
}

fn inventory_text<'a>(bytes: &'a [u8], label: &str) -> Result<&'a str, B1PreflightFault> {
    if bytes.is_empty() || bytes.last() != Some(&b'\n') || bytes.contains(&b'\r') {
        return Err(fault(
            B1PreflightFaultCode::Inventory,
            format!("{label} is not canonical LF-terminated text"),
        ));
    }
    std::str::from_utf8(bytes).map_err(|_| {
        fault(
            B1PreflightFaultCode::Inventory,
            format!("{label} is not UTF-8"),
        )
    })
}

fn is_safe_inventory_path(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 1024
        || value.contains(['\\', ':', '\0', '\r', '\n', '\t'])
        || value.starts_with('/')
        || value.ends_with('/')
    {
        return false;
    }
    let path = Path::new(value);
    path.components().all(|component| match component {
        Component::Normal(value) => {
            let text = value.to_string_lossy();
            text != "." && text != ".."
        }
        _ => false,
    })
}

fn read_bounded_regular_file(root: &Path, name: &str) -> Result<Vec<u8>, B1PreflightFault> {
    if name.is_empty()
        || name.len() > 128
        || name.contains(['/', '\\', ':', '\0'])
        || name == "."
        || name == ".."
    {
        return Err(fault(
            B1PreflightFaultCode::Path,
            "artifact name is not a simple filename",
        ));
    }
    let path = root.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        fault(
            B1PreflightFaultCode::Path,
            format!("artifact metadata failed for {name}: {error}"),
        )
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(fault(
            B1PreflightFaultCode::Path,
            format!("artifact is not a regular nonsymlink file: {name}"),
        ));
    }
    if metadata.len() == 0 || metadata.len() > B1_MAX_ARTIFACT_BYTES {
        return Err(fault(
            B1PreflightFaultCode::Bound,
            format!("artifact is empty or oversized: {name}"),
        ));
    }
    let canonical = fs::canonicalize(&path).map_err(|error| {
        fault(
            B1PreflightFaultCode::Path,
            format!("artifact canonicalization failed for {name}: {error}"),
        )
    })?;
    if canonical.parent() != Some(root) {
        return Err(fault(
            B1PreflightFaultCode::Path,
            format!("artifact escaped the evidence root: {name}"),
        ));
    }
    let bytes = fs::read(&canonical).map_err(|error| {
        fault(
            B1PreflightFaultCode::Path,
            format!("artifact read failed for {name}: {error}"),
        )
    })?;
    if bytes.len() as u64 != metadata.len() {
        return Err(fault(
            B1PreflightFaultCode::Digest,
            format!("artifact length drifted during read: {name}"),
        ));
    }
    Ok(bytes)
}

fn artifact<'a>(
    artifacts: &'a BTreeMap<String, Vec<u8>>,
    name: &str,
) -> Result<&'a [u8], B1PreflightFault> {
    artifacts.get(name).map(Vec::as_slice).ok_or_else(|| {
        fault(
            B1PreflightFaultCode::Manifest,
            format!("manifest member missing: {name}"),
        )
    })
}

fn b1_preflight_record_digest(
    record: &B1PreflightRecord,
) -> Result<ContentDigest, B1PreflightFault> {
    let mut value = record.clone();
    value.record_digest = empty_digest();
    let form = serde_json::to_vec(&value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(RECORD_DOMAIN.len() + 1 + form.len());
    bytes.extend_from_slice(RECORD_DOMAIN.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&form);
    Ok(sha256_bytes(&bytes))
}

fn digest(bytes: &[u8]) -> ContentDigest {
    sha256_bytes(bytes)
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn validate_digest(value: &ContentDigest) -> Result<(), B1PreflightFault> {
    if value.algorithm != "sha256"
        || value.value.len() != 64
        || !value
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(fault(
            B1PreflightFaultCode::Digest,
            "digest is not canonical lowercase SHA-256",
        ));
    }
    Ok(())
}

fn sha256_upper(bytes: &[u8]) -> String {
    sha256_bytes(bytes).value.to_ascii_uppercase()
}

fn is_upper_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
}

fn is_file_id(value: &str) -> bool {
    value.len() == 34
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_strict_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, B1PreflightFault> {
    if bytes.is_empty() || bytes.len() > B1_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            B1PreflightFaultCode::Bound,
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

fn machine_fault(error: serde_json::Error) -> B1PreflightFault {
    fault(B1PreflightFaultCode::MachineForm, error.to_string())
}

fn fault(code: B1PreflightFaultCode, message: impl Into<String>) -> B1PreflightFault {
    B1PreflightFault {
        code,
        message: message.into(),
    }
}
