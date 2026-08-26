//! Independent verification for the provider-free C-drive B1 host preflight.
//!
//! The verifier consumes caller-supplied evidence only. It cannot launch the
//! producer, App Server, Git, a provider, or a model and has no write, cleanup,
//! recovery, publication, or activation surface.

use std::{
    collections::HashSet,
    fmt, fs,
    path::{Component, Path},
};

use cantor_core::{ContentDigest, sha256_bytes};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};

use crate::{
    AdmissionReceipt, CandidateWorkspaceRequest, SelfWorkUpdateHandoffProposal,
    SelfWorkUpdateHandoffRequest, from_self_work_update_handoff_proposal_machine_form,
    from_self_work_update_handoff_request_machine_form, self_work_update_handoff_proposal_digest,
    self_work_update_handoff_request_digest, to_self_work_update_handoff_proposal_machine_form,
    to_self_work_update_handoff_request_machine_form,
    workspace_admission::update_broker_protocol::{
        CapabilityKind, FormationValidationRecord, ProtocolFormationRequest,
        from_protocol_request_machine_form, from_protocol_result_machine_form,
        protocol_request_digest, protocol_result_digest, to_protocol_request_machine_form,
        to_protocol_result_machine_form,
    },
};

pub const B1_CDRIVE_PREFLIGHT_MANIFEST_PROFILE: &str =
    "cantor-self-work-update-broker-b1-permission-profile-preflight-evidence-manifest/0.2";
pub const B1_CDRIVE_PREFLIGHT_OBSERVATION_PROFILE: &str =
    "cantor-self-work-update-broker-b1-permission-profile-preflight-observation/0.2";
pub const B1_CDRIVE_PREFLIGHT_RECEIPT_PROFILE: &str =
    "cantor-self-work-update-broker-b1-permission-profile-preflight-receipt/0.2";
pub const B1_CDRIVE_PREFLIGHT_SOURCE_SNAPSHOT_UUID: &str = "661679ac-325d-4dc2-808d-232d732027b5";
pub const B1_CDRIVE_PREFLIGHT_PREDECESSOR_COMMIT: &str = "a8a4780b6ce9e71ee0350033b4509c39e5bbdba8";
pub const B1_CDRIVE_PREFLIGHT_MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
pub const B1_CDRIVE_PREFLIGHT_MAX_MACHINE_FORM_BYTES: usize = 2 * 1024 * 1024;

const HISTORICAL_NOT_RUN_DIGEST: &str =
    "b7d65c4877932aaf14a32e4e65d04f40e053af39435d56e8dedaad5d021816ad";
const CAPABILITY_RECEIPT_DIGEST: &str =
    "b0b9d7933fc8cfeb6c7907fb713cd3422c1c6fe157dd3d913636fc77974e83cb";
const SELECTED_EXECUTABLE: &str = "C:\\Users\\enjer\\AppData\\Roaming\\npm\\node_modules\\@openai\\codex\\node_modules\\@openai\\codex-win32-x64\\vendor\\x86_64-pc-windows-msvc\\bin\\codex.exe";
const SELECTED_EXECUTABLE_BYTES: u64 = 242_541_872;
const SELECTED_EXECUTABLE_SHA256: &str =
    "FE12887B4AB4A4E988F0FA5BAAE9E5CB7D8505C26401378628E762DB9A2E798F";
const STANDARD_SCHEMA_SHA256: &str =
    "99B3E93A3E5C96554E23A0B9EFB9FA4BDD1B05699CCB72B86A4F6A5CD69350E8";
const EXPERIMENTAL_SCHEMA_SHA256: &str =
    "3846D4F0D17D301277E9809AE6F69C9E552CEAD5385476E3B9B4F83211DF9AD2";
const PERMISSION_PROFILE_ID: &str = "swa05_b1_preflight";
const PRINCIPAL_WORKSPACE: &str = "C:\\Project\\Cantor";
const ALLOWED_SENTINEL: &str = "SWA05_B1_ALLOWED_READ_SENTINEL\n";
const DENIED_SENTINEL: &str = "SWA05_B1_DENIED_READ_SENTINEL\n";
const WRITE_SENTINEL: &str = "SWA05_B1_DENIED_WRITE_SENTINEL";
const SENTINEL_RELATIVE_ROOT: &str = "fixtures\\swa05_b1_cdrive_preflight";
const COMMAND_EXECUTABLE: &str = "C:\\Windows\\System32\\cmd.exe";
const COMMAND_TIMEOUT_MILLIS: u64 = 10_000;
const RECEIPT_DOMAIN: &str = "cantor.self-work-update-broker.b1.cdrive-preflight-receipt.v2";
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_FIELDS: usize = 256;

const CURRENT_ADMISSION_FILE: &str = "current_admission.json";
const EXPERIMENTAL_SCHEMA_FILE: &str = "experimental_schema.json";
const HANDOFF_PROPOSAL_FILE: &str = "handoff_proposal.json";
const HANDOFF_REQUEST_FILE: &str = "handoff_request.json";
const OBSERVATION_FILE: &str = "observation.json";
const PRIOR_ADMISSION_FILE: &str = "prior_admission.json";
const PROTOCOL_REQUEST_FILE: &str = "protocol_request.json";
const PROTOCOL_RESULT_FILE: &str = "protocol_result.json";
const STANDARD_SCHEMA_FILE: &str = "standard_schema.json";

const EXPECTED_ARTIFACTS: [&str; 9] = [
    CURRENT_ADMISSION_FILE,
    EXPERIMENTAL_SCHEMA_FILE,
    HANDOFF_PROPOSAL_FILE,
    HANDOFF_REQUEST_FILE,
    OBSERVATION_FILE,
    PRIOR_ADMISSION_FILE,
    PROTOCOL_REQUEST_FILE,
    PROTOCOL_RESULT_FILE,
    STANDARD_SCHEMA_FILE,
];

const REQUIRED_ENVIRONMENT: [&str; 7] = [
    "CODEX_HOME",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "WINDIR",
];

const DENIED_ENVIRONMENT: [&str; 16] = [
    "ALL_PROXY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AZURE_OPENAI_API_KEY",
    "CODEX_API_KEY",
    "EDITOR",
    "GH_TOKEN",
    "GIT_ASKPASS",
    "GIT_CONFIG_GLOBAL",
    "GIT_SSH_COMMAND",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "OPENAI_API_KEY",
    "PAGER",
    "VISUAL",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDrivePreflightEvidenceManifest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub predecessor_commit: String,
    pub artifacts: Vec<B1CDrivePreflightArtifactIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDrivePreflightArtifactIdentity {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDrivePreflightObservation {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub predecessor_commit: String,
    pub historical_not_run_record_digest: String,
    pub capability_receipt_digest: String,
    pub selected_executable: B1CDriveSelectedExecutable,
    pub schemas: B1CDriveSchemaIdentity,
    pub commission: B1CDriveCommission,
    pub transcript: Vec<Value>,
    pub pre_inventory: Vec<B1CDriveInventoryEntry>,
    pub post_inventory: Vec<B1CDriveInventoryEntry>,
    pub process: B1CDriveProcessAccount,
    pub resources: B1CDriveResourceAccount,
    pub boundaries: B1CDriveBoundaryAccount,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveSelectedExecutable {
    pub path: String,
    pub bytes: u64,
    pub sha256_before: String,
    pub sha256_after: String,
    pub version_output: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveSchemaIdentity {
    pub standard_file: String,
    pub standard_bytes: u64,
    pub standard_sha256: String,
    pub experimental_file: String,
    pub experimental_bytes: u64,
    pub experimental_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveCommission {
    pub permission_profile_id: String,
    pub filesystem_override: String,
    pub network_enabled: bool,
    pub granted: Vec<CapabilityKind>,
    pub explicitly_not_granted: Vec<CapabilityKind>,
    pub topology: B1CDriveTopology,
    pub allowed_environment: Vec<B1CDriveEnvironmentIdentity>,
    pub denied_environment: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveTopology {
    pub scratch_root: String,
    pub principal_workspace: String,
    pub candidate_root: String,
    pub repository_common_dir: String,
    pub candidate_git_dir: String,
    pub evidence_root: String,
    pub temp_root: String,
    pub codex_home: String,
    pub allowed_path: String,
    pub denied_path: String,
    pub write_canary_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveEnvironmentIdentity {
    pub name: String,
    pub value_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveInventoryEntry {
    pub relative_path: String,
    pub kind: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProcessAccount {
    pub app_server_process_count: u8,
    pub app_server_started: bool,
    pub stdin_closed: bool,
    pub interrupted: bool,
    pub terminated: bool,
    pub reaped: bool,
    pub exit_code: i32,
    pub descendant_count: u16,
    pub late_stdout_bytes: u64,
    pub late_stderr_bytes: u64,
    pub elapsed_millis: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveResourceAccount {
    pub phase3_process_count: u16,
    pub total_process_count: u16,
    pub transcript_frames: u16,
    pub inventory_entries: u16,
    pub observed_bytes: u64,
    pub timeout_millis: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveBoundaryAccount {
    pub current_revalidation_count: u8,
    pub allowed_read_count: u8,
    pub denied_read_count: u8,
    pub denied_write_count: u8,
    pub writer_run_count: u8,
    pub provider_contact_count: u8,
    pub model_turn_count: u8,
    pub mcp_call_count: u8,
    pub git_observation_process_count: u16,
    pub git_history_count: u8,
    pub commit_count: u8,
    pub push_count: u8,
    pub service_network_observed: bool,
    pub remote_contact_count: u8,
    pub d_drive_contact_count: u8,
    pub product_mutation_count: u8,
    pub cleanup_count: u8,
    pub sop_authorship_count: u8,
    pub semantic_signature_count: u8,
    pub persistence_count: u8,
    pub activation_count: u8,
    pub fpga_count: u8,
    pub minecraft_count: u8,
    pub principal_workspace_mutation_count: u8,
    pub physical_contact: bool,
    pub may_have_mutated: bool,
    pub quarantine_required: bool,
    pub scratch_reusable: bool,
    pub write_canary_absent_before: bool,
    pub write_canary_absent_after: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDrivePreflightStatus {
    PreflightEligibleWriterNotRun,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDrivePreflightAuthority {
    PreflightObservationOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDrivePreflightReceipt {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub predecessor_commit: String,
    pub historical_not_run_record_digest: String,
    pub capability_receipt_digest: String,
    pub evidence_manifest_digest: ContentDigest,
    pub observation_digest: ContentDigest,
    pub protocol_request_digest: String,
    pub protocol_result_digest: String,
    pub handoff_request_digest: ContentDigest,
    pub handoff_proposal_digest: ContentDigest,
    pub prior_admission_digest: ContentDigest,
    pub current_admission_digest: ContentDigest,
    pub standard_schema_digest: ContentDigest,
    pub experimental_schema_digest: ContentDigest,
    pub status: B1CDrivePreflightStatus,
    pub authority: B1CDrivePreflightAuthority,
    pub selected_host_pinned: bool,
    pub upstream_join_verified: bool,
    pub current_admission_verified: bool,
    pub allowed_read_enforced: bool,
    pub denied_read_enforced: bool,
    pub denied_write_enforced: bool,
    pub stable_inventory_verified: bool,
    pub child_quiescent: bool,
    pub physical_contact: bool,
    pub may_have_mutated: bool,
    pub quarantine_required: bool,
    pub writer_run_count: u8,
    pub provider_contact_count: u8,
    pub model_turn_count: u8,
    pub mcp_call_count: u8,
    pub git_observation_process_count: u16,
    pub git_history_count: u8,
    pub commit_count: u8,
    pub push_count: u8,
    pub remote_contact_count: u8,
    pub d_drive_contact_count: u8,
    pub product_mutation_count: u8,
    pub cleanup_count: u8,
    pub principal_workspace_mutation_count: u8,
    pub next_b2_formation_supported: bool,
    pub receipt_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDrivePreflightFaultCode {
    Path,
    Bound,
    Manifest,
    MachineForm,
    Lineage,
    Upstream,
    Capability,
    Selection,
    Schema,
    Environment,
    Topology,
    Admission,
    Profile,
    Transcript,
    Enforcement,
    Process,
    Inventory,
    Consequence,
    Resource,
    Authority,
    Digest,
    Receipt,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDrivePreflightFault {
    pub code: B1CDrivePreflightFaultCode,
    pub message: String,
}

impl fmt::Display for B1CDrivePreflightFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for B1CDrivePreflightFault {}

struct VerifiedUpstream {
    protocol_request_digest: String,
    protocol_result_digest: String,
    handoff_request_digest: ContentDigest,
    handoff_proposal_digest: ContentDigest,
    prior_admission_digest: ContentDigest,
    current_admission_digest: ContentDigest,
    request: CandidateWorkspaceRequest,
    current: AdmissionReceipt,
}

pub fn verify_b1_cdrive_preflight_evidence(
    evidence_root: &Path,
) -> Result<B1CDrivePreflightReceipt, B1CDrivePreflightFault> {
    let metadata = fs::symlink_metadata(evidence_root).map_err(|error| {
        fault(
            B1CDrivePreflightFaultCode::Path,
            format!("evidence root metadata failed: {error}"),
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(fault(
            B1CDrivePreflightFaultCode::Path,
            "evidence root must be one real directory",
        ));
    }
    let root = fs::canonicalize(evidence_root).map_err(|error| {
        fault(
            B1CDrivePreflightFaultCode::Path,
            format!("evidence root canonicalization failed: {error}"),
        )
    })?;

    let manifest_bytes = read_bounded_regular_file(&root, "manifest.json")?;
    let manifest: B1CDrivePreflightEvidenceManifest = parse_strict_json(&manifest_bytes)?;
    validate_manifest(&manifest)?;

    let mut artifacts = Vec::with_capacity(manifest.artifacts.len());
    let mut total_bytes = 0_u64;
    for artifact in &manifest.artifacts {
        let bytes = read_bounded_regular_file(&root, &artifact.path)?;
        total_bytes = total_bytes.checked_add(bytes.len() as u64).ok_or_else(|| {
            fault(
                B1CDrivePreflightFaultCode::Bound,
                "artifact byte total overflow",
            )
        })?;
        if total_bytes > 48 * 1024 * 1024
            || bytes.len() as u64 != artifact.bytes
            || sha256_upper(&bytes) != artifact.sha256
        {
            return Err(fault(
                B1CDrivePreflightFaultCode::Digest,
                format!("artifact identity differs for {}", artifact.path),
            ));
        }
        artifacts.push((artifact.path.as_str(), bytes));
    }

    let upstream = validate_upstream(&artifacts)?;
    let standard = artifact(&artifacts, STANDARD_SCHEMA_FILE)?;
    let experimental = artifact(&artifacts, EXPERIMENTAL_SCHEMA_FILE)?;
    let observation_bytes = artifact(&artifacts, OBSERVATION_FILE)?;
    let observation: B1CDrivePreflightObservation = parse_strict_json(observation_bytes)?;
    validate_observation(&observation, &upstream, standard, experimental, &root)?;

    let mut receipt = B1CDrivePreflightReceipt {
        profile: B1_CDRIVE_PREFLIGHT_RECEIPT_PROFILE.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_PREFLIGHT_SOURCE_SNAPSHOT_UUID.to_owned(),
        predecessor_commit: B1_CDRIVE_PREFLIGHT_PREDECESSOR_COMMIT.to_owned(),
        historical_not_run_record_digest: HISTORICAL_NOT_RUN_DIGEST.to_owned(),
        capability_receipt_digest: CAPABILITY_RECEIPT_DIGEST.to_owned(),
        evidence_manifest_digest: sha256_bytes(&manifest_bytes),
        observation_digest: sha256_bytes(observation_bytes),
        protocol_request_digest: upstream.protocol_request_digest,
        protocol_result_digest: upstream.protocol_result_digest,
        handoff_request_digest: upstream.handoff_request_digest,
        handoff_proposal_digest: upstream.handoff_proposal_digest,
        prior_admission_digest: upstream.prior_admission_digest,
        current_admission_digest: upstream.current_admission_digest,
        standard_schema_digest: sha256_bytes(standard),
        experimental_schema_digest: sha256_bytes(experimental),
        status: B1CDrivePreflightStatus::PreflightEligibleWriterNotRun,
        authority: B1CDrivePreflightAuthority::PreflightObservationOnly,
        selected_host_pinned: true,
        upstream_join_verified: true,
        current_admission_verified: true,
        allowed_read_enforced: true,
        denied_read_enforced: true,
        denied_write_enforced: true,
        stable_inventory_verified: true,
        child_quiescent: true,
        physical_contact: true,
        may_have_mutated: false,
        quarantine_required: false,
        writer_run_count: 0,
        provider_contact_count: 0,
        model_turn_count: 0,
        mcp_call_count: 0,
        git_observation_process_count: observation.boundaries.git_observation_process_count,
        git_history_count: 0,
        commit_count: 0,
        push_count: 0,
        remote_contact_count: 0,
        d_drive_contact_count: 0,
        product_mutation_count: 0,
        cleanup_count: 0,
        principal_workspace_mutation_count: 0,
        next_b2_formation_supported: true,
        receipt_digest: empty_digest(),
    };
    receipt.receipt_digest = b1_cdrive_preflight_receipt_digest(&receipt)?;
    validate_b1_cdrive_preflight_receipt(&receipt)?;
    Ok(receipt)
}

pub fn validate_b1_cdrive_preflight_receipt(
    receipt: &B1CDrivePreflightReceipt,
) -> Result<(), B1CDrivePreflightFault> {
    if receipt.profile != B1_CDRIVE_PREFLIGHT_RECEIPT_PROFILE
        || receipt.source_snapshot_uuid != B1_CDRIVE_PREFLIGHT_SOURCE_SNAPSHOT_UUID
        || receipt.predecessor_commit != B1_CDRIVE_PREFLIGHT_PREDECESSOR_COMMIT
        || receipt.historical_not_run_record_digest != HISTORICAL_NOT_RUN_DIGEST
        || receipt.capability_receipt_digest != CAPABILITY_RECEIPT_DIGEST
        || receipt.status != B1CDrivePreflightStatus::PreflightEligibleWriterNotRun
        || receipt.authority != B1CDrivePreflightAuthority::PreflightObservationOnly
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Receipt,
            "receipt lineage status or authority differs",
        ));
    }
    if !receipt.selected_host_pinned
        || !receipt.upstream_join_verified
        || !receipt.current_admission_verified
        || !receipt.allowed_read_enforced
        || !receipt.denied_read_enforced
        || !receipt.denied_write_enforced
        || !receipt.stable_inventory_verified
        || !receipt.child_quiescent
        || !receipt.physical_contact
        || receipt.may_have_mutated
        || receipt.quarantine_required
        || receipt.writer_run_count != 0
        || receipt.provider_contact_count != 0
        || receipt.model_turn_count != 0
        || receipt.mcp_call_count != 0
        || receipt.git_observation_process_count == 0
        || receipt.git_history_count != 0
        || receipt.commit_count != 0
        || receipt.push_count != 0
        || receipt.remote_contact_count != 0
        || receipt.d_drive_contact_count != 0
        || receipt.product_mutation_count != 0
        || receipt.cleanup_count != 0
        || receipt.principal_workspace_mutation_count != 0
        || !receipt.next_b2_formation_supported
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Authority,
            "receipt capability consequence or zero-effect account differs",
        ));
    }
    for digest in [
        &receipt.evidence_manifest_digest,
        &receipt.observation_digest,
        &receipt.handoff_request_digest,
        &receipt.handoff_proposal_digest,
        &receipt.prior_admission_digest,
        &receipt.current_admission_digest,
        &receipt.standard_schema_digest,
        &receipt.experimental_schema_digest,
        &receipt.receipt_digest,
    ] {
        validate_digest(digest)?;
    }
    for digest in [
        &receipt.protocol_request_digest,
        &receipt.protocol_result_digest,
    ] {
        if !is_lower_sha256(digest) {
            return Err(fault(
                B1CDrivePreflightFaultCode::Digest,
                "protocol digest differs",
            ));
        }
    }
    if receipt.receipt_digest != b1_cdrive_preflight_receipt_digest(receipt)? {
        return Err(fault(
            B1CDrivePreflightFaultCode::Digest,
            "receipt self-digest differs",
        ));
    }
    Ok(())
}

pub fn to_b1_cdrive_preflight_receipt_machine_form(
    receipt: &B1CDrivePreflightReceipt,
) -> Result<String, B1CDrivePreflightFault> {
    validate_b1_cdrive_preflight_receipt(receipt)?;
    let value = serde_json::to_string(receipt).map_err(machine_fault)?;
    if value.len() > B1_CDRIVE_PREFLIGHT_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            B1CDrivePreflightFaultCode::Bound,
            "receipt machine form is oversized",
        ));
    }
    Ok(value)
}

pub fn from_b1_cdrive_preflight_receipt_machine_form(
    value: &str,
) -> Result<B1CDrivePreflightReceipt, B1CDrivePreflightFault> {
    if value.len() > B1_CDRIVE_PREFLIGHT_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            B1CDrivePreflightFaultCode::Bound,
            "receipt machine form is oversized",
        ));
    }
    let receipt: B1CDrivePreflightReceipt = parse_strict_json(value.as_bytes())?;
    validate_b1_cdrive_preflight_receipt(&receipt)?;
    Ok(receipt)
}

pub fn b1_cdrive_preflight_receipt_digest(
    receipt: &B1CDrivePreflightReceipt,
) -> Result<ContentDigest, B1CDrivePreflightFault> {
    let mut normalized = receipt.clone();
    normalized.receipt_digest = empty_digest();
    let payload = serde_json::to_vec(&normalized).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(RECEIPT_DOMAIN.len() + 1 + payload.len());
    bytes.extend_from_slice(RECEIPT_DOMAIN.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&payload);
    Ok(sha256_bytes(&bytes))
}

fn validate_manifest(
    manifest: &B1CDrivePreflightEvidenceManifest,
) -> Result<(), B1CDrivePreflightFault> {
    if manifest.profile != B1_CDRIVE_PREFLIGHT_MANIFEST_PROFILE
        || manifest.source_snapshot_uuid != B1_CDRIVE_PREFLIGHT_SOURCE_SNAPSHOT_UUID
        || manifest.predecessor_commit != B1_CDRIVE_PREFLIGHT_PREDECESSOR_COMMIT
        || manifest.artifacts.len() != EXPECTED_ARTIFACTS.len()
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Manifest,
            "manifest profile lineage or artifact count differs",
        ));
    }
    for (artifact, expected) in manifest.artifacts.iter().zip(EXPECTED_ARTIFACTS) {
        if artifact.path != expected
            || artifact.bytes == 0
            || artifact.bytes > B1_CDRIVE_PREFLIGHT_MAX_ARTIFACT_BYTES
            || !is_upper_sha256(&artifact.sha256)
        {
            return Err(fault(
                B1CDrivePreflightFaultCode::Manifest,
                "manifest artifact coordinate differs",
            ));
        }
    }
    Ok(())
}

fn validate_upstream(
    artifacts: &[(&str, Vec<u8>)],
) -> Result<VerifiedUpstream, B1CDrivePreflightFault> {
    let protocol_request_bytes = artifact(artifacts, PROTOCOL_REQUEST_FILE)?;
    reject_duplicate_json(protocol_request_bytes, Some(MAX_JSON_FIELDS))?;
    let protocol_request: ProtocolFormationRequest =
        from_protocol_request_machine_form(protocol_request_bytes).map_err(|error| {
            fault(
                B1CDrivePreflightFaultCode::Upstream,
                format!("protocol request refused: {error}"),
            )
        })?;
    if to_protocol_request_machine_form(&protocol_request).map_err(upstream_fault)?
        != protocol_request_bytes
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::MachineForm,
            "protocol request is not canonical",
        ));
    }
    let protocol_result_bytes = artifact(artifacts, PROTOCOL_RESULT_FILE)?;
    reject_duplicate_json(protocol_result_bytes, Some(MAX_JSON_FIELDS))?;
    let protocol_result: FormationValidationRecord =
        from_protocol_result_machine_form(&protocol_request, protocol_result_bytes).map_err(
            |error| {
                fault(
                    B1CDrivePreflightFaultCode::Upstream,
                    format!("protocol result refused: {error}"),
                )
            },
        )?;
    if to_protocol_result_machine_form(&protocol_request, &protocol_result)
        .map_err(upstream_fault)?
        != protocol_result_bytes
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::MachineForm,
            "protocol result is not canonical",
        ));
    }

    let handoff_request_bytes = artifact(artifacts, HANDOFF_REQUEST_FILE)?;
    reject_duplicate_json(handoff_request_bytes, Some(MAX_JSON_FIELDS))?;
    let handoff_request_text = std::str::from_utf8(handoff_request_bytes).map_err(machine_fault)?;
    let handoff_request: SelfWorkUpdateHandoffRequest =
        from_self_work_update_handoff_request_machine_form(handoff_request_text)
            .map_err(upstream_fault)?;
    if to_self_work_update_handoff_request_machine_form(&handoff_request)
        .map_err(upstream_fault)?
        .as_bytes()
        != handoff_request_bytes
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::MachineForm,
            "handoff request is not canonical",
        ));
    }
    let handoff_proposal_bytes = artifact(artifacts, HANDOFF_PROPOSAL_FILE)?;
    reject_duplicate_json(handoff_proposal_bytes, Some(MAX_JSON_FIELDS))?;
    let handoff_proposal_text =
        std::str::from_utf8(handoff_proposal_bytes).map_err(machine_fault)?;
    let handoff_proposal: SelfWorkUpdateHandoffProposal =
        from_self_work_update_handoff_proposal_machine_form(handoff_proposal_text)
            .map_err(upstream_fault)?;
    if to_self_work_update_handoff_proposal_machine_form(&handoff_proposal)
        .map_err(upstream_fault)?
        .as_bytes()
        != handoff_proposal_bytes
        || handoff_proposal.request != handoff_request
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Upstream,
            "handoff proposal request correspondence differs",
        ));
    }

    let prior_bytes = artifact(artifacts, PRIOR_ADMISSION_FILE)?;
    let current_bytes = artifact(artifacts, CURRENT_ADMISSION_FILE)?;
    let prior: AdmissionReceipt = parse_strict_json(prior_bytes)?;
    let current: AdmissionReceipt = parse_strict_json(current_bytes)?;
    if serde_json::to_vec(&prior).map_err(machine_fault)? != prior_bytes
        || serde_json::to_vec(&current).map_err(machine_fault)? != current_bytes
        || prior != handoff_request.prior_admission_receipt
        || current != prior
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Admission,
            "prior or current admission correspondence differs",
        ));
    }

    let handoff_request_digest =
        self_work_update_handoff_request_digest(&handoff_request).map_err(upstream_fault)?;
    let handoff_proposal_digest =
        self_work_update_handoff_proposal_digest(&handoff_proposal).map_err(upstream_fault)?;
    let request = &handoff_request.workspace_request;
    if protocol_request.root.handoff_request_sha256 != handoff_request_digest.value
        || protocol_request.root.handoff_proposal_sha256 != handoff_proposal_digest.value
        || protocol_request.root.workspace_correlation_uuid != request.correlation_uuid
        || protocol_request.root.base_commit != request.expected_base_commit
        || protocol_request.root.branch_ref != request.expected_branch_ref
        || protocol_request.root.git_executable_sha256 != request.git_executable_sha256
        || protocol_request.root.allowed_relative_paths != request.allowed_relative_paths
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Upstream,
            "B0 and SWA-04A workspace join differs",
        ));
    }

    Ok(VerifiedUpstream {
        protocol_request_digest: protocol_request_digest(&protocol_request)
            .map_err(upstream_fault)?,
        protocol_result_digest: protocol_result_digest(&protocol_result).map_err(upstream_fault)?,
        handoff_request_digest,
        handoff_proposal_digest,
        prior_admission_digest: sha256_bytes(prior_bytes),
        current_admission_digest: sha256_bytes(current_bytes),
        request: request.clone(),
        current,
    })
}

fn validate_observation(
    value: &B1CDrivePreflightObservation,
    upstream: &VerifiedUpstream,
    standard: &[u8],
    experimental: &[u8],
    evidence_root: &Path,
) -> Result<(), B1CDrivePreflightFault> {
    if value.profile != B1_CDRIVE_PREFLIGHT_OBSERVATION_PROFILE
        || value.source_snapshot_uuid != B1_CDRIVE_PREFLIGHT_SOURCE_SNAPSHOT_UUID
        || value.predecessor_commit != B1_CDRIVE_PREFLIGHT_PREDECESSOR_COMMIT
        || value.historical_not_run_record_digest != HISTORICAL_NOT_RUN_DIGEST
        || value.capability_receipt_digest != CAPABILITY_RECEIPT_DIGEST
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Lineage,
            "observation lineage differs",
        ));
    }
    validate_selected_executable(&value.selected_executable)?;
    validate_schemas(&value.schemas, standard, experimental)?;
    validate_commission(&value.commission, upstream, evidence_root)?;
    validate_transcript(&value.transcript, &value.commission.topology)?;
    validate_inventory(
        &value.pre_inventory,
        &value.post_inventory,
        &value.commission.topology,
    )?;
    validate_process(&value.process)?;
    validate_resources(&value.resources, upstream, value)?;
    validate_boundaries(&value.boundaries, upstream)?;
    Ok(())
}

fn validate_selected_executable(
    value: &B1CDriveSelectedExecutable,
) -> Result<(), B1CDrivePreflightFault> {
    if value.path != SELECTED_EXECUTABLE
        || value.bytes != SELECTED_EXECUTABLE_BYTES
        || value.sha256_before != SELECTED_EXECUTABLE_SHA256
        || value.sha256_after != SELECTED_EXECUTABLE_SHA256
        || value.version_output != "codex-cli 0.135.0"
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Selection,
            "selected executable identity differs",
        ));
    }
    Ok(())
}

fn validate_schemas(
    value: &B1CDriveSchemaIdentity,
    standard: &[u8],
    experimental: &[u8],
) -> Result<(), B1CDrivePreflightFault> {
    if value.standard_file != STANDARD_SCHEMA_FILE
        || value.standard_bytes != standard.len() as u64
        || value.standard_sha256 != STANDARD_SCHEMA_SHA256
        || sha256_upper(standard) != STANDARD_SCHEMA_SHA256
        || value.experimental_file != EXPERIMENTAL_SCHEMA_FILE
        || value.experimental_bytes != experimental.len() as u64
        || value.experimental_sha256 != EXPERIMENTAL_SCHEMA_SHA256
        || sha256_upper(experimental) != EXPERIMENTAL_SCHEMA_SHA256
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Schema,
            "schema identity differs",
        ));
    }
    let standard_value = parse_strict_schema_json(standard)?;
    let experimental_value = parse_strict_schema_json(experimental)?;
    if !schema_has_read_only_policy(&standard_value)?
        || pointer(
            &experimental_value,
            "/definitions/v2/CommandExecParams/properties/permissionProfile",
        )?
        .is_null()
        || pointer(
            &experimental_value,
            "/definitions/v2/PermissionProfileListParams",
        )?
        .is_null()
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Schema,
            "required schema coordinates are absent",
        ));
    }
    Ok(())
}

fn schema_has_read_only_policy(value: &Value) -> Result<bool, B1CDrivePreflightFault> {
    let alternatives = pointer(value, "/definitions/v2/SandboxPolicy/oneOf")?
        .as_array()
        .ok_or_else(|| {
            fault(
                B1CDrivePreflightFaultCode::Schema,
                "sandbox policy alternatives are not an array",
            )
        })?;
    Ok(alternatives.iter().any(|alternative| {
        alternative.get("title").and_then(Value::as_str) == Some("ReadOnlySandboxPolicy")
            && alternative
                .pointer("/properties/type/enum")
                .and_then(Value::as_array)
                .is_some_and(|values| {
                    values.len() == 1 && values.first().and_then(Value::as_str) == Some("readOnly")
                })
            && alternative.pointer("/properties/networkAccess").is_some()
    }))
}

fn validate_commission(
    value: &B1CDriveCommission,
    upstream: &VerifiedUpstream,
    evidence_root: &Path,
) -> Result<(), B1CDrivePreflightFault> {
    let expected_granted = vec![
        CapabilityKind::ReadObservation,
        CapabilityKind::ProcessLaunch,
        CapabilityKind::ProcessInterrupt,
        CapabilityKind::ProcessTerminate,
    ];
    let expected_denied = vec![
        CapabilityKind::EvidenceRootWrite,
        CapabilityKind::CandidateMutation,
        CapabilityKind::SupervisorTest,
        CapabilityKind::IndependentReview,
        CapabilityKind::RollbackAttempt,
        CapabilityKind::Cleanup,
        CapabilityKind::GitHistory,
        CapabilityKind::Commit,
        CapabilityKind::Push,
        CapabilityKind::Provider,
        CapabilityKind::SopAuthorship,
        CapabilityKind::SemanticSignature,
        CapabilityKind::Activation,
        CapabilityKind::Persistence,
        CapabilityKind::Remote,
        CapabilityKind::Fpga,
        CapabilityKind::Minecraft,
        CapabilityKind::PrincipalWorkspaceMutation,
    ];
    if value.permission_profile_id != PERMISSION_PROFILE_ID
        || value.network_enabled
        || value.granted != expected_granted
        || value.explicitly_not_granted != expected_denied
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Capability,
            "permission profile or capability partition differs",
        ));
    }
    validate_topology(&value.topology, upstream, evidence_root)?;
    let expected_override = format!(
        "permissions.{PERMISSION_PROFILE_ID}.filesystem={{':root'='deny',':minimal'='read','{}'='read','{}'='deny'}}",
        value.topology.candidate_root, value.topology.denied_path
    );
    if value.filesystem_override != expected_override {
        return Err(fault(
            B1CDrivePreflightFaultCode::Profile,
            "filesystem override differs",
        ));
    }
    validate_environment(value)?;
    Ok(())
}

fn validate_environment(value: &B1CDriveCommission) -> Result<(), B1CDrivePreflightFault> {
    if value.allowed_environment.len() != REQUIRED_ENVIRONMENT.len()
        || value.denied_environment != DENIED_ENVIRONMENT.map(str::to_owned).to_vec()
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Environment,
            "environment name sets differ",
        ));
    }
    for (entry, expected) in value.allowed_environment.iter().zip(REQUIRED_ENVIRONMENT) {
        if entry.name != expected || !is_upper_sha256(&entry.value_sha256) {
            return Err(fault(
                B1CDrivePreflightFaultCode::Environment,
                "allowed environment identity differs",
            ));
        }
        if entry.name == "CODEX_HOME"
            && entry.value_sha256 != sha256_upper(value.topology.codex_home.as_bytes())
        {
            return Err(fault(
                B1CDrivePreflightFaultCode::Environment,
                "CODEX_HOME identity differs",
            ));
        }
    }
    Ok(())
}

fn validate_topology(
    value: &B1CDriveTopology,
    upstream: &VerifiedUpstream,
    evidence_root: &Path,
) -> Result<(), B1CDrivePreflightFault> {
    let actual_evidence_root_text = path_text(evidence_root)?;
    let actual_evidence_root = normalize_windows_path(&actual_evidence_root_text);
    if !is_windows_scratch_root(&value.scratch_root)
        || value.principal_workspace != PRINCIPAL_WORKSPACE
        || value.principal_workspace != path_text(&upstream.request.principal_workspace)?
        || value.candidate_root != path_text(&upstream.request.candidate_workspace)?
        || value.repository_common_dir != path_text(&upstream.current.repository_common_dir)?
        || value.candidate_git_dir != path_text(&upstream.current.candidate_git_dir)?
        || value.candidate_root != format!("{}\\candidate", value.scratch_root)
        || value.evidence_root != format!("{}\\evidence", value.scratch_root)
        || !value
            .evidence_root
            .eq_ignore_ascii_case(actual_evidence_root)
        || value.temp_root != format!("{}\\temp", value.scratch_root)
        || value.codex_home != format!("{}\\codex-home", value.scratch_root)
        || value.allowed_path
            != format!(
                "{}\\{SENTINEL_RELATIVE_ROOT}\\allowed.txt",
                value.candidate_root
            )
        || value.denied_path
            != format!(
                "{}\\{SENTINEL_RELATIVE_ROOT}\\denied.txt",
                value.candidate_root
            )
        || value.write_canary_path
            != format!(
                "{}\\{SENTINEL_RELATIVE_ROOT}\\write_canary.txt",
                value.candidate_root
            )
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Topology,
            "topology relation differs",
        ));
    }
    let paths = [
        &value.scratch_root,
        &value.principal_workspace,
        &value.candidate_root,
        &value.repository_common_dir,
        &value.candidate_git_dir,
        &value.evidence_root,
        &value.temp_root,
        &value.codex_home,
        &value.allowed_path,
        &value.denied_path,
        &value.write_canary_path,
    ];
    if paths.iter().any(|path| !is_safe_windows_absolute(path))
        || paths
            .iter()
            .any(|path| path.to_ascii_uppercase().starts_with("D:\\"))
        || value
            .principal_workspace
            .eq_ignore_ascii_case(&value.candidate_root)
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Topology,
            "topology path is unsafe or outside the C-drive boundary",
        ));
    }
    Ok(())
}

fn validate_transcript(
    transcript: &[Value],
    topology: &B1CDriveTopology,
) -> Result<(), B1CDrivePreflightFault> {
    if transcript.len() != 12 {
        return Err(fault(
            B1CDrivePreflightFaultCode::Transcript,
            "transcript frame count differs",
        ));
    }
    let mut core = Vec::with_capacity(11);
    let mut notification_seen = false;
    for frame in transcript {
        if frame.get("method").and_then(Value::as_str) == Some("remoteControl/status/changed") {
            if notification_seen {
                return Err(fault(
                    B1CDrivePreflightFaultCode::Transcript,
                    "duplicate local status notification",
                ));
            }
            validate_status_notification(frame)?;
            notification_seen = true;
        } else {
            core.push(frame);
        }
    }
    if core.len() != 11 || !notification_seen {
        return Err(fault(
            B1CDrivePreflightFaultCode::Transcript,
            "core transcript frame count differs",
        ));
    }
    validate_initialize_request(core[0])?;
    let initialize = response_result(core[1], 0)?;
    let user_agent = initialize
        .get("userAgent")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if initialize.len() != 4
        || !user_agent.starts_with("Codex Desktop/0.135.0 (Windows ")
        || !user_agent.ends_with("dumb (cantor_swa05_b1_preflight; 0.2.0)")
        || initialize.get("codexHome").and_then(Value::as_str) != Some(topology.codex_home.as_str())
        || initialize.get("platformFamily").and_then(Value::as_str) != Some("windows")
        || initialize.get("platformOs").and_then(Value::as_str) != Some("windows")
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Transcript,
            "initialize result differs",
        ));
    }
    validate_initialized_notification(core[2])?;
    validate_profile_list_request(core[3], topology)?;
    let list = response_result(core[4], 1)?;
    let profiles = list.get("data").and_then(Value::as_array).ok_or_else(|| {
        fault(
            B1CDrivePreflightFaultCode::Transcript,
            "permission profile list is absent",
        )
    })?;
    let expected = [
        ":read-only",
        ":workspace",
        ":danger-full-access",
        PERMISSION_PROFILE_ID,
    ];
    if profiles.len() != expected.len()
        || profiles.iter().zip(expected).any(|(profile, expected)| {
            profile.as_object().map(Map::len) != Some(2)
                || profile.get("id").and_then(Value::as_str) != Some(expected)
                || profile.get("description") != Some(&Value::Null)
        })
        || list.get("nextCursor") != Some(&Value::Null)
        || list.len() != 2
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Transcript,
            "permission profile list differs",
        ));
    }
    validate_command_request(core[5], 2, "type", &topology.allowed_path, topology)?;
    if command_result(core[6], 2)? != (0, ALLOWED_SENTINEL, "") {
        return Err(fault(
            B1CDrivePreflightFaultCode::Enforcement,
            "allowed-read result differs",
        ));
    }
    validate_command_request(core[7], 3, "type", &topology.denied_path, topology)?;
    let denied = command_result(core[8], 3)?;
    if denied.0 == 0
        || !denied.1.is_empty()
        || denied.2 != "Access is denied.\r\n"
        || denied.1.contains(DENIED_SENTINEL)
        || denied.2.contains(DENIED_SENTINEL)
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Enforcement,
            "denied-read result differs",
        ));
    }
    validate_command_request(core[9], 4, "echo", &topology.write_canary_path, topology)?;
    let write = command_result(core[10], 4)?;
    if write.0 == 0
        || !write.1.is_empty()
        || write.2 != "Access is denied.\r\n"
        || write.1.contains(WRITE_SENTINEL)
        || write.2.contains(WRITE_SENTINEL)
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Enforcement,
            "denied-write result differs",
        ));
    }
    Ok(())
}

fn validate_initialize_request(frame: &Value) -> Result<(), B1CDrivePreflightFault> {
    let params = request_params(frame, 0, "initialize")?;
    let client = params
        .get("clientInfo")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            fault(
                B1CDrivePreflightFaultCode::Transcript,
                "initialize client identity is absent",
            )
        })?;
    let capabilities = params
        .get("capabilities")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            fault(
                B1CDrivePreflightFaultCode::Transcript,
                "initialize capabilities are absent",
            )
        })?;
    if params.len() != 2
        || client.len() != 3
        || client.get("name").and_then(Value::as_str) != Some("cantor_swa05_b1_preflight")
        || client.get("title").and_then(Value::as_str) != Some("Cantor SWA-05 B1 Preflight")
        || client.get("version").and_then(Value::as_str) != Some("0.2.0")
        || capabilities.len() != 1
        || capabilities.get("experimentalApi").and_then(Value::as_bool) != Some(true)
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Transcript,
            "initialize request differs",
        ));
    }
    Ok(())
}

fn validate_initialized_notification(frame: &Value) -> Result<(), B1CDrivePreflightFault> {
    let object = frame.as_object().ok_or_else(|| {
        fault(
            B1CDrivePreflightFaultCode::Transcript,
            "initialized notification is not an object",
        )
    })?;
    if object.len() != 2
        || object.get("method").and_then(Value::as_str) != Some("initialized")
        || object
            .get("params")
            .and_then(Value::as_object)
            .is_none_or(|params| !params.is_empty())
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Transcript,
            "initialized notification differs",
        ));
    }
    Ok(())
}

fn validate_profile_list_request(
    frame: &Value,
    topology: &B1CDriveTopology,
) -> Result<(), B1CDrivePreflightFault> {
    let params = request_params(frame, 1, "permissionProfile/list")?;
    if params.len() != 1
        || params.get("cwd").and_then(Value::as_str) != Some(topology.candidate_root.as_str())
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Transcript,
            "permission profile list request differs",
        ));
    }
    Ok(())
}

fn validate_command_request(
    frame: &Value,
    id: u64,
    operation: &str,
    path: &str,
    topology: &B1CDriveTopology,
) -> Result<(), B1CDrivePreflightFault> {
    let params = request_params(frame, id, "command/exec")?;
    let command = params
        .get("command")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            fault(
                B1CDrivePreflightFaultCode::Transcript,
                "command argv is absent",
            )
        })?;
    let expected = if operation == "echo" {
        vec![
            COMMAND_EXECUTABLE,
            "/d",
            "/c",
            "echo",
            WRITE_SENTINEL,
            ">",
            path,
        ]
    } else {
        vec![COMMAND_EXECUTABLE, "/d", "/c", "type", path]
    };
    if params.len() != 5
        || command.len() > 32
        || command
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            != Some(expected)
        || params.get("cwd").and_then(Value::as_str) != Some(topology.candidate_root.as_str())
        || params.get("permissionProfile").and_then(Value::as_str) != Some(PERMISSION_PROFILE_ID)
        || params.get("timeoutMs").and_then(Value::as_u64) != Some(COMMAND_TIMEOUT_MILLIS)
        || params.get("disableOutputCap").and_then(Value::as_bool) != Some(false)
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Transcript,
            "command request differs",
        ));
    }
    Ok(())
}

fn request_params<'a>(
    frame: &'a Value,
    id: u64,
    method: &str,
) -> Result<&'a Map<String, Value>, B1CDrivePreflightFault> {
    let object = frame.as_object().ok_or_else(|| {
        fault(
            B1CDrivePreflightFaultCode::Transcript,
            "request frame is not an object",
        )
    })?;
    if object.len() != 3
        || object.get("id").and_then(Value::as_u64) != Some(id)
        || object.get("method").and_then(Value::as_str) != Some(method)
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Transcript,
            "request id method or shape differs",
        ));
    }
    object
        .get("params")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            fault(
                B1CDrivePreflightFaultCode::Transcript,
                "request params are absent",
            )
        })
}

fn validate_status_notification(frame: &Value) -> Result<(), B1CDrivePreflightFault> {
    let object = frame.as_object().ok_or_else(|| {
        fault(
            B1CDrivePreflightFaultCode::Transcript,
            "status notification is not an object",
        )
    })?;
    let params = object
        .get("params")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            fault(
                B1CDrivePreflightFaultCode::Transcript,
                "status params absent",
            )
        })?;
    if object.len() != 2
        || params.len() != 4
        || params.get("status").and_then(Value::as_str) != Some("disabled")
        || params
            .get("serverName")
            .and_then(Value::as_str)
            .is_none_or(|value| {
                value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
            })
        || params.get("environmentId") != Some(&Value::Null)
        || params
            .get("installationId")
            .and_then(Value::as_str)
            .map(is_lower_uuid)
            != Some(true)
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Transcript,
            "status notification differs",
        ));
    }
    Ok(())
}

fn validate_inventory(
    before: &[B1CDriveInventoryEntry],
    after: &[B1CDriveInventoryEntry],
    topology: &B1CDriveTopology,
) -> Result<(), B1CDrivePreflightFault> {
    if before.is_empty() || before.len() > 8192 || before != after {
        return Err(fault(
            B1CDrivePreflightFaultCode::Inventory,
            "pre-post inventory differs or is outside bounds",
        ));
    }
    let mut prior: Option<&str> = None;
    let mut allowed = false;
    let mut denied = false;
    for entry in before {
        if prior.is_some_and(|value| value >= entry.relative_path.as_str())
            || entry.kind != "file"
            || entry.bytes == 0
            || !is_upper_sha256(&entry.sha256)
            || !is_safe_relative_path(&entry.relative_path)
            || entry.relative_path == "write_canary.txt"
        {
            return Err(fault(
                B1CDrivePreflightFaultCode::Inventory,
                "inventory entry differs",
            ));
        }
        if entry.relative_path == "fixtures/swa05_b1_cdrive_preflight/allowed.txt" {
            allowed = entry.bytes == ALLOWED_SENTINEL.len() as u64
                && entry.sha256 == sha256_upper(ALLOWED_SENTINEL.as_bytes());
        }
        if entry.relative_path == "fixtures/swa05_b1_cdrive_preflight/denied.txt" {
            denied = entry.bytes == DENIED_SENTINEL.len() as u64
                && entry.sha256 == sha256_upper(DENIED_SENTINEL.as_bytes());
        }
        prior = Some(&entry.relative_path);
    }
    if !allowed
        || !denied
        || topology.allowed_path
            != format!(
                "{}\\{SENTINEL_RELATIVE_ROOT}\\allowed.txt",
                topology.candidate_root
            )
        || topology.denied_path
            != format!(
                "{}\\{SENTINEL_RELATIVE_ROOT}\\denied.txt",
                topology.candidate_root
            )
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Inventory,
            "required sentinel inventory differs",
        ));
    }
    Ok(())
}

fn validate_process(value: &B1CDriveProcessAccount) -> Result<(), B1CDrivePreflightFault> {
    if value.app_server_process_count != 1
        || !value.app_server_started
        || !value.stdin_closed
        || value.interrupted
        || value.terminated
        || !value.reaped
        || value.exit_code != 0
        || value.descendant_count != 0
        || value.late_stdout_bytes != 0
        || value.late_stderr_bytes != 0
        || value.elapsed_millis == 0
        || value.elapsed_millis > 30_000
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Process,
            "owned process account differs",
        ));
    }
    Ok(())
}

fn validate_resources(
    value: &B1CDriveResourceAccount,
    upstream: &VerifiedUpstream,
    observation: &B1CDrivePreflightObservation,
) -> Result<(), B1CDrivePreflightFault> {
    if value.phase3_process_count != upstream.current.resource_account.process_count
        || value.phase3_process_count == 0
        || value.total_process_count != value.phase3_process_count + 1
        || value.transcript_frames as usize != observation.transcript.len()
        || value.inventory_entries as usize != observation.pre_inventory.len()
        || value.observed_bytes == 0
        || value.observed_bytes > 48 * 1024 * 1024
        || value.timeout_millis == 0
        || value.timeout_millis > 30_000
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Resource,
            "resource account differs",
        ));
    }
    Ok(())
}

fn validate_boundaries(
    value: &B1CDriveBoundaryAccount,
    upstream: &VerifiedUpstream,
) -> Result<(), B1CDrivePreflightFault> {
    if value.current_revalidation_count != 1
        || value.allowed_read_count != 1
        || value.denied_read_count != 1
        || value.denied_write_count != 1
        || value.writer_run_count != 0
        || value.provider_contact_count != 0
        || value.model_turn_count != 0
        || value.mcp_call_count != 0
        || value.git_observation_process_count != upstream.current.resource_account.process_count
        || value.git_history_count != 0
        || value.commit_count != 0
        || value.push_count != 0
        || value.service_network_observed
        || value.remote_contact_count != 0
        || value.d_drive_contact_count != 0
        || value.product_mutation_count != 0
        || value.cleanup_count != 0
        || value.sop_authorship_count != 0
        || value.semantic_signature_count != 0
        || value.persistence_count != 0
        || value.activation_count != 0
        || value.fpga_count != 0
        || value.minecraft_count != 0
        || value.principal_workspace_mutation_count != 0
        || !value.physical_contact
        || value.may_have_mutated
        || value.quarantine_required
        || !value.scratch_reusable
        || !value.write_canary_absent_before
        || !value.write_canary_absent_after
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Consequence,
            "effect or consequence boundary differs",
        ));
    }
    Ok(())
}

fn response_result(frame: &Value, id: u64) -> Result<&Map<String, Value>, B1CDrivePreflightFault> {
    let object = frame.as_object().ok_or_else(|| {
        fault(
            B1CDrivePreflightFaultCode::Transcript,
            "response frame is not an object",
        )
    })?;
    if object.len() != 2 || object.get("id").and_then(Value::as_u64) != Some(id) {
        return Err(fault(
            B1CDrivePreflightFaultCode::Transcript,
            "response id or shape differs",
        ));
    }
    object
        .get("result")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            fault(
                B1CDrivePreflightFaultCode::Transcript,
                "response result is absent",
            )
        })
}

fn command_result(frame: &Value, id: u64) -> Result<(i64, &str, &str), B1CDrivePreflightFault> {
    let result = response_result(frame, id)?;
    if result.len() != 3 {
        return Err(fault(
            B1CDrivePreflightFaultCode::Transcript,
            "command result shape differs",
        ));
    }
    Ok((
        result
            .get("exitCode")
            .and_then(Value::as_i64)
            .ok_or_else(|| fault(B1CDrivePreflightFaultCode::Transcript, "exit code absent"))?,
        result
            .get("stdout")
            .and_then(Value::as_str)
            .ok_or_else(|| fault(B1CDrivePreflightFaultCode::Transcript, "stdout absent"))?,
        result
            .get("stderr")
            .and_then(Value::as_str)
            .ok_or_else(|| fault(B1CDrivePreflightFaultCode::Transcript, "stderr absent"))?,
    ))
}

fn artifact<'a>(
    artifacts: &'a [(&str, Vec<u8>)],
    name: &str,
) -> Result<&'a [u8], B1CDrivePreflightFault> {
    artifacts
        .iter()
        .find_map(|(path, bytes)| (*path == name).then_some(bytes.as_slice()))
        .ok_or_else(|| {
            fault(
                B1CDrivePreflightFaultCode::Manifest,
                format!("required artifact is absent: {name}"),
            )
        })
}

fn read_bounded_regular_file(root: &Path, name: &str) -> Result<Vec<u8>, B1CDrivePreflightFault> {
    if !is_simple_name(name) {
        return Err(fault(
            B1CDrivePreflightFaultCode::Path,
            "artifact path is not one simple name",
        ));
    }
    let path = root.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        fault(
            B1CDrivePreflightFaultCode::Path,
            format!("artifact metadata failed for {name}: {error}"),
        )
    })?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > B1_CDRIVE_PREFLIGHT_MAX_ARTIFACT_BYTES
    {
        return Err(fault(
            B1CDrivePreflightFaultCode::Bound,
            format!("artifact is not one bounded regular file: {name}"),
        ));
    }
    let canonical = fs::canonicalize(&path).map_err(|error| {
        fault(
            B1CDrivePreflightFaultCode::Path,
            format!("artifact canonicalization failed for {name}: {error}"),
        )
    })?;
    if canonical.parent() != Some(root) {
        return Err(fault(
            B1CDrivePreflightFaultCode::Path,
            format!("artifact escapes evidence root: {name}"),
        ));
    }
    fs::read(&canonical).map_err(|error| {
        fault(
            B1CDrivePreflightFaultCode::Path,
            format!("artifact read failed for {name}: {error}"),
        )
    })
}

fn parse_strict_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, B1CDrivePreflightFault> {
    reject_duplicate_json(bytes, Some(MAX_JSON_FIELDS))?;
    serde_json::from_slice(bytes).map_err(machine_fault)
}

fn parse_strict_schema_json(bytes: &[u8]) -> Result<Value, B1CDrivePreflightFault> {
    reject_duplicate_json(bytes, None)?;
    serde_json::from_slice(bytes).map_err(machine_fault)
}

fn reject_duplicate_json(
    bytes: &[u8],
    maximum_fields: Option<usize>,
) -> Result<(), B1CDrivePreflightFault> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    StrictSeed {
        depth: 0,
        maximum_fields,
    }
    .deserialize(&mut deserializer)
    .map_err(machine_fault)?;
    deserializer.end().map_err(machine_fault)
}

#[derive(Debug)]
struct StrictValue;

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictSeed {
            depth: 0,
            maximum_fields: Some(MAX_JSON_FIELDS),
        }
        .deserialize(deserializer)
    }
}

struct StrictSeed {
    depth: usize,
    maximum_fields: Option<usize>,
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
        deserializer.deserialize_any(StrictVisitor {
            depth: self.depth,
            maximum_fields: self.maximum_fields,
        })
    }
}

struct StrictVisitor {
    depth: usize,
    maximum_fields: Option<usize>,
}

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a duplicate-free JSON value")
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
                maximum_fields: self.maximum_fields,
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
            if self
                .maximum_fields
                .is_some_and(|maximum| keys.len() > maximum)
            {
                return Err(de::Error::custom("JSON object field count exceeds bound"));
            }
            map.next_value_seed(StrictSeed {
                depth: self.depth + 1,
                maximum_fields: self.maximum_fields,
            })?;
        }
        Ok(StrictValue)
    }
}

fn pointer<'a>(value: &'a Value, path: &str) -> Result<&'a Value, B1CDrivePreflightFault> {
    value.pointer(path).ok_or_else(|| {
        fault(
            B1CDrivePreflightFaultCode::Schema,
            format!("schema coordinate is absent: {path}"),
        )
    })
}

fn is_simple_name(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && value.len() <= 128
        && !value.contains(['/', '\\', ':'])
        && path.components().count() == 1
        && matches!(path.components().next(), Some(Component::Normal(_)))
}

fn is_safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.contains(['\\', ':'])
        && !value.starts_with('/')
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn is_windows_scratch_root(value: &str) -> bool {
    let prefix = "C:\\Project\\CantorWorktrees\\swa05_b1_cdrive_preflight_";
    value.starts_with(prefix)
        && value.len() > prefix.len()
        && value.len() <= 512
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn is_safe_windows_absolute(value: &str) -> bool {
    value.len() >= 4
        && value.len() <= 1024
        && value.as_bytes()[1] == b':'
        && value.as_bytes()[2] == b'\\'
        && value.as_bytes()[0].is_ascii_alphabetic()
        && !value.contains('/')
        && !value.contains("\\.\\")
        && !value.contains("\\..\\")
        && !value.ends_with("\\.")
        && !value.ends_with("\\..")
}

fn path_text(path: &Path) -> Result<String, B1CDrivePreflightFault> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        fault(
            B1CDrivePreflightFaultCode::Topology,
            "upstream path is not UTF-8",
        )
    })
}

fn normalize_windows_path(value: &str) -> &str {
    value.strip_prefix("\\\\?\\").unwrap_or(value)
}

fn is_upper_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_lower_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn sha256_upper(bytes: &[u8]) -> String {
    sha256_bytes(bytes).value.to_ascii_uppercase()
}

fn validate_digest(value: &ContentDigest) -> Result<(), B1CDrivePreflightFault> {
    if value.algorithm != "sha256" || !is_lower_sha256(&value.value) {
        return Err(fault(
            B1CDrivePreflightFaultCode::Digest,
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

fn fault(code: B1CDrivePreflightFaultCode, message: impl Into<String>) -> B1CDrivePreflightFault {
    B1CDrivePreflightFault {
        code,
        message: message.into(),
    }
}

fn machine_fault(error: impl fmt::Display) -> B1CDrivePreflightFault {
    fault(B1CDrivePreflightFaultCode::MachineForm, error.to_string())
}

fn upstream_fault(error: impl fmt::Display) -> B1CDrivePreflightFault {
    fault(B1CDrivePreflightFaultCode::Upstream, error.to_string())
}
