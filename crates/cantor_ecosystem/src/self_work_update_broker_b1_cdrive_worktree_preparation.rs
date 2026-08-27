//! Provider-only compilation and independent verification of the corrective
//! C-drive linked-worktree preparation plan.
//!
//! This module deliberately contains no production process runner or
//! filesystem-write broker. It can compile the signed twelve-child plan,
//! exercise it through a caller-supplied fake broker, and verify retained raw
//! evidence. A later separately signed physical commission must add and pin a
//! production broker before the reserved worktree can be touched.

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
use serde_json::Number;

pub const B1_CDRIVE_WORKTREE_PREPARATION_REQUEST_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-linked-worktree-preparation-request/0.4";
pub const B1_CDRIVE_WORKTREE_PREPARATION_PROOF_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-linked-worktree-preparation-publication-proof/0.3";
pub const B1_CDRIVE_WORKTREE_PREPARATION_PLAN_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-linked-worktree-preparation-plan/0.4";
pub const B1_CDRIVE_WORKTREE_PREPARATION_LOCAL_GATE_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-linked-worktree-preparation-local-gate/0.4";
pub const B1_CDRIVE_WORKTREE_PREPARATION_FILESYSTEM_PROFILE: &str = "cantor-self-work-update-broker-b1-cdrive-linked-worktree-preparation-filesystem-observation/0.4";
pub const B1_CDRIVE_WORKTREE_PREPARATION_GIT_OBSERVATION_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-linked-worktree-preparation-git-observation/0.2";
pub const B1_CDRIVE_WORKTREE_PREPARATION_OUTCOME_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-linked-worktree-preparation-outcome/0.4";
pub const B1_CDRIVE_WORKTREE_PREPARATION_SIMULATION_RECEIPT_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-linked-worktree-preparation-simulation-receipt/0.4";
pub const B1_CDRIVE_WORKTREE_PREPARATION_EVIDENCE_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-linked-worktree-preparation-simulation-evidence/0.4";

pub const B1_CDRIVE_WORKTREE_PREPARATION_SOURCE_SNAPSHOT_UUID: &str =
    "17ed9314-3bf0-49e1-9222-3cb1276b6fc9";
pub const B1_CDRIVE_WORKTREE_PREPARATION_SIGNATURE_UUID: &str =
    "2c6d3b9d-d852-43bf-b979-8e544e281a31";
pub const B1_CDRIVE_WORKTREE_PREPARATION_INVALIDATION_UUID: &str =
    "fd8a1a55-9384-4c8c-8e96-1c50c0a61e04";
pub const B1_CDRIVE_WORKTREE_PREPARATION_CARRIER: &str = "b5bcd03ec28ed99a0cdeb028a2a0db21efe8313d";
pub const B1_CDRIVE_WORKTREE_PREPARATION_IMPLEMENTATION: &str =
    "b5443f4dbc0a7469933e1ddcac5cd8d7b8901252";
pub const B1_CDRIVE_WORKTREE_PREPARATION_BOOKEND: &str = "3984bb3282571448a49cb5a79d1c219a5c9f00e7";
pub const B1_CDRIVE_WORKTREE_PREPARATION_PROOF_UUID: &str = "c19d3102-f4d7-4761-a2b8-97ddbfc08c1d";
pub const B1_CDRIVE_WORKTREE_PREPARATION_BRANCH: &str =
    "refs/heads/codex/swa05-b1-cdrive-preflight-b5bcd03e";
pub const B1_CDRIVE_WORKTREE_PREPARATION_SCRATCH: &str =
    "C:\\Project\\CantorWorktrees\\swa05_b1_cdrive_preflight_b5bcd03e";
pub const B1_CDRIVE_WORKTREE_PREPARATION_HOOK_QUARANTINE: &str =
    "C:\\Project\\CantorWorktrees\\swa05_b1_cdrive_preflight_b5bcd03e\\hook-quarantine";
pub const B1_CDRIVE_WORKTREE_PREPARATION_ATTRIBUTE_QUARANTINE: &str =
    "C:\\Project\\CantorWorktrees\\swa05_b1_cdrive_preflight_b5bcd03e\\attribute-quarantine";
pub const B1_CDRIVE_WORKTREE_PREPARATION_GIT: &str = "C:\\Program Files\\Git\\cmd\\git.exe";
pub const B1_CDRIVE_WORKTREE_PREPARATION_GIT_SHA256: &str =
    "81EF35AE005CA9318018D18E3327578CE939FB99FEAAD6B2D7C8AB15F3DE8DB5";
pub const B1_CDRIVE_WORKTREE_PREPARATION_GIT_VERSION: &str = "git version 2.54.0.windows.1";

const PRINCIPAL: &str = "C:\\Project\\Cantor";
const COMMON_DIR: &str = "C:\\Project\\Cantor\\.git";
const WORKTREE_PARENT: &str = "C:\\Project\\CantorWorktrees";
const WORKTREE_ADMIN_ROOT: &str = "C:\\Project\\Cantor\\.git\\worktrees";
const C_VOLUME_GUID: &str = "\\\\?\\Volume{3ca93d52-bee3-4c52-9c03-263040cc104d}\\";
const TRACKING_BRANCH: &str = "refs/heads/codex/self-hosted-corpus";
const ALLOWED_SENTINEL_SHA256: &str =
    "BE8C5B7129F046B3B6A3E290DC3E352810E13C40906E98122E99F66DEEE2312C";
const DENIED_SENTINEL_SHA256: &str =
    "19992D428A24A764DBD744B1C06AFACB7A1379DDAD8CEE0095D5071940E002A3";
const EMPTY_SHA256: &str = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
const CARRIER_GITATTRIBUTES_BLOB: &str = "9dd384ba9cb5cb1008b666ec9591d34ba3c618a3";
const CARRIER_GITATTRIBUTES_SHA256: &str =
    "6237DA886CEDCC229E18AFCC5617A464D4B18FAC1977F58260E0017F72DCCAFA";
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_FIELDS: usize = 256;
const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EVIDENCE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_STREAM_BYTES: usize = 1024 * 1024;
const MAX_TOTAL_PROCESS_BYTES: usize = 4 * 1024 * 1024;
const EXACT_PROCESS_COUNT: usize = 12;
const PROCESS_DEADLINE_MILLIS: u64 = 30_000;
const GIT_PATH: &str = "C:\\Program Files\\Git\\cmd;C:\\Windows\\System32;C:\\Windows";
const PATHEXT: &str = ".COM;.EXE;.BAT;.CMD";
const SIMULATION_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"cantor-self-work-update-broker-b1-cdrive-linked-worktree-preparation-simulation-receipt/0.4\0";
const EXACT_ARTIFACT_NAMES: [&str; 7] = [
    "consequences.json",
    "plan.json",
    "process_observations.json",
    "projection.json",
    "publication_proof.json",
    "request.json",
    "simulation_receipt.json",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationArtifactIdentity {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationEnvironmentEntry {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisingPublicationProof {
    pub profile: String,
    pub proof_uuid: String,
    pub implementation_commit: String,
    pub bookend_commit: String,
    pub branch_ref: String,
    pub bookend_local_head: String,
    pub bookend_local_tracking: String,
    pub bookend_origin_remote_tracking: String,
    pub bookend_ls_remote: String,
    pub implementation_parent_of_bookend: bool,
    pub carrier_ancestor_of_implementation: bool,
    pub focused_debug_test_count: u32,
    pub focused_release_test_count: u32,
    pub focused_failure_count: u32,
    pub evidence_manifest_count: u32,
    pub evidence_reference_count: u32,
    pub evidence_stale_count: u32,
    pub physical_preparation_run_count: u32,
    pub placement: String,
    pub contains_own_commit_identity: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CDriveWorktreePreparationRequest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub signature_uuid: String,
    pub predecessor_invalidation_uuid: String,
    pub carrier_commit: String,
    pub implementation_commit: String,
    pub bookend_commit: String,
    pub expected_current_commit: String,
    pub publication_proof_artifact: PreparationArtifactIdentity,
    pub physical_commission_uuid: Option<String>,
    pub physical_preparation_authorized: bool,
    pub recovery_owner: String,
    pub principal_workspace: String,
    pub repository_common_dir: String,
    pub scratch_root: String,
    pub candidate_root: String,
    pub evidence_root: String,
    pub temp_root: String,
    pub codex_home: String,
    pub hook_quarantine_root: String,
    pub attribute_quarantine_file: String,
    pub branch_ref: String,
    pub git_executable: String,
    pub git_executable_bytes: u64,
    pub git_executable_sha256: String,
    pub git_version: String,
    pub maximum_processes: u16,
    pub maximum_stream_bytes: usize,
    pub maximum_total_process_bytes: usize,
    pub deadline_millis: u64,
    pub minimum_pre_effect_free_bytes: u64,
    pub minimum_final_free_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationLocalGateObservation {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub signature_uuid: String,
    pub recovery_owner: String,
    pub principal_workspace: String,
    pub repository_common_dir: String,
    pub worktree_parent: String,
    pub volume_guid: String,
    pub volume_filesystem: String,
    pub parent_is_canonical_directory: bool,
    pub parent_is_reparse_point: bool,
    pub scratch_root_absent: bool,
    pub hook_quarantine_root: String,
    pub attribute_quarantine_file: String,
    pub hook_quarantine_root_absent: bool,
    pub attribute_quarantine_file_absent: bool,
    pub repository_info_attributes_absent: bool,
    pub branch_ref_absent: bool,
    pub carrier_commit: String,
    pub implementation_commit: String,
    pub bookend_commit: String,
    pub expected_current_commit: String,
    pub local_head: String,
    pub local_tracking: String,
    pub origin_remote_tracking: String,
    pub carrier_ancestor_of_implementation: bool,
    pub implementation_immediate_parent_of_bookend: bool,
    pub bookend_ancestor_of_current_commit: bool,
    pub carrier_tracked_entry_count: u32,
    pub carrier_mode_100644_count: u32,
    pub carrier_other_mode_count: u32,
    pub carrier_attributes_file_count: u16,
    pub carrier_gitattributes_blob: String,
    pub carrier_gitattributes_bytes: u64,
    pub carrier_gitattributes_sha256: String,
    pub carrier_filter_assignment_count: u32,
    pub carrier_gitmodules_absent: bool,
    pub git_executable: String,
    pub git_executable_bytes: u64,
    pub git_executable_sha256: String,
    pub git_version: String,
    pub pre_effect_free_bytes: u64,
    pub process_count: u16,
    pub network_contact_count: u32,
    pub physical_contact: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationChildSpec {
    pub sequence: u16,
    pub operation: String,
    pub executable: String,
    pub arguments: Vec<String>,
    pub expected_stdout_lines: Vec<String>,
    pub allowed_exit_codes: Vec<i32>,
    pub mutating: bool,
    pub network: bool,
    pub environment_clear_first: bool,
    pub environment: Vec<PreparationEnvironmentEntry>,
    pub stdin_closed: bool,
    pub maximum_stdout_bytes: usize,
    pub maximum_stderr_bytes: usize,
    pub maximum_total_bytes: usize,
    pub deadline_millis: u64,
    pub deadline_scope: String,
    pub rehash_executable_before_start: bool,
    pub terminate_on_timeout: bool,
    pub wait_after_terminate: bool,
    pub require_descendant_free: bool,
    pub require_late_output_free: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CDriveWorktreePreparationPlan {
    pub profile: String,
    pub request_sha256: ContentDigest,
    pub publication_proof_sha256: ContentDigest,
    pub expected_current_commit: String,
    pub children: Vec<PreparationChildSpec>,
    pub physical_execution_authorized: bool,
    pub planned_directory_creations: u16,
    pub planned_regular_file_creations: u16,
    pub planned_branch_ref_mutations: u16,
    pub planned_worktree_metadata_mutations: u16,
    pub planned_checkout_file_count: u32,
    pub network_command_count: u16,
    pub maximum_processes: u16,
    pub maximum_stream_bytes: usize,
    pub maximum_total_process_bytes: usize,
    pub total_deadline_millis: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationProcessObservation {
    pub sequence: u16,
    pub operation: String,
    pub arguments: Vec<String>,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub reaped: bool,
    pub descendant_count_after: u32,
    pub late_output_bytes: usize,
    pub network_contact_count: u32,
    pub physical_effect_performed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationStateProjection {
    pub principal_workspace: String,
    pub repository_common_dir: String,
    pub scratch_root: String,
    pub candidate_root: String,
    pub evidence_root: String,
    pub temp_root: String,
    pub codex_home: String,
    pub hook_quarantine_root: String,
    pub attribute_quarantine_file: String,
    pub branch_ref: String,
    pub carrier_commit: String,
    pub carrier_tracked_file_count: u32,
    pub carrier_tracked_bytes: u64,
    pub carrier_mode_100644_count: u32,
    pub carrier_other_mode_count: u32,
    pub carrier_attributes_file_count: u16,
    pub carrier_gitattributes_blob: String,
    pub carrier_gitattributes_bytes: u64,
    pub carrier_gitattributes_sha256: String,
    pub carrier_filter_assignment_count: u32,
    pub carrier_gitmodules_absent: bool,
    pub repository_info_attributes_expected_absent: bool,
    pub hook_quarantine_expected_empty: bool,
    pub attribute_quarantine_expected_empty: bool,
    pub allowed_sentinel_sha256: String,
    pub denied_sentinel_sha256: String,
    pub write_canary_expected_absent: bool,
    pub candidate_status_expected_empty: bool,
    pub submodule_status_expected_empty: bool,
    pub reserved_root_contact: bool,
    pub reserved_ref_contact: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationFilesystemObservation {
    pub profile: String,
    pub scratch_root: String,
    pub candidate_root: String,
    pub evidence_root: String,
    pub temp_root: String,
    pub codex_home: String,
    pub hook_quarantine_root: String,
    pub attribute_quarantine_file: String,
    pub scratch_present: bool,
    pub candidate_present: bool,
    pub evidence_present: bool,
    pub temp_present: bool,
    pub codex_home_present: bool,
    pub hook_quarantine_present: bool,
    pub hook_quarantine_is_directory: bool,
    pub hook_quarantine_is_reparse_point: bool,
    pub hook_quarantine_entry_count: u32,
    pub attribute_quarantine_present: bool,
    pub attribute_quarantine_is_regular_file: bool,
    pub attribute_quarantine_is_reparse_point: bool,
    pub attribute_quarantine_bytes: u64,
    pub attribute_quarantine_sha256: String,
    pub repository_info_attributes_absent: bool,
    pub roles_pairwise_disjoint: bool,
    pub roles_strict_scratch_descendants: bool,
    pub principal_strictly_nonoverlapping: bool,
    pub same_selected_volume: bool,
    pub directory_creation_count: u16,
    pub regular_file_creation_count: u16,
    pub other_path_effect_count: u32,
    pub principal_worktree_file_mutation_count: u32,
    pub candidate_post_checkout_authorship_count: u32,
    pub allowed_sentinel_bytes: u64,
    pub allowed_sentinel_sha256: String,
    pub denied_sentinel_bytes: u64,
    pub denied_sentinel_sha256: String,
    pub write_canary_present: bool,
    pub cleanup_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationGitObservation {
    pub profile: String,
    pub carrier_commit: String,
    pub candidate_head: String,
    pub candidate_branch_ref: String,
    pub candidate_top_level: String,
    pub candidate_common_dir: String,
    pub candidate_git_dir: String,
    pub candidate_git_dir_under_worktree_admin: bool,
    pub candidate_status_bytes: u64,
    pub recursive_submodule_status_bytes: u64,
    pub exact_worktree_membership_count: u16,
    pub branch_ref_mutation_count: u16,
    pub worktree_metadata_mutation_count: u16,
    pub checkout_file_count: u32,
    pub protected_ref_mutation_count: u32,
    pub fetch_count: u32,
    pub pull_count: u32,
    pub remote_update_count: u32,
    pub commit_count: u32,
    pub push_count: u32,
    pub retry_count: u32,
    pub worktree_remove_count: u32,
    pub branch_delete_count: u32,
    pub git_version_before: String,
    pub git_version_after: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationOutcomeDisposition {
    NotRun,
    Quarantined,
    PreparedForPhase3aAcquisition,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationOutcomeAccount {
    pub profile: String,
    pub disposition: PreparationOutcomeDisposition,
    pub authority: String,
    pub pre_effect_gate_passed: bool,
    pub post_effect_verification_passed: bool,
    pub physical_contact: bool,
    pub may_have_mutated: bool,
    pub retained_state: bool,
    pub reserved_root_contact: bool,
    pub reserved_ref_contact: bool,
    pub actual_directory_creations: u16,
    pub actual_regular_file_creations: u16,
    pub actual_branch_ref_mutations: u16,
    pub actual_worktree_metadata_mutations: u16,
    pub actual_checkout_file_count: u32,
    pub final_free_bytes: Option<u64>,
    pub success_receipt_emitted: bool,
    pub network_contact_count: u32,
    pub phase3a_run_count: u32,
    pub p1_app_server_run_count: u32,
    pub writer_run_count: u32,
    pub provider_trial_count: u32,
    pub model_turn_count: u32,
    pub mcp_call_count: u32,
    pub d_drive_contact_count: u32,
    pub wsl_compile_count: u32,
    pub cleanup_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationSimulationConsequences {
    pub planned_directory_creations: u16,
    pub planned_regular_file_creations: u16,
    pub planned_branch_ref_mutations: u16,
    pub planned_worktree_metadata_mutations: u16,
    pub planned_checkout_file_count: u32,
    pub actual_directory_creations: u16,
    pub actual_regular_file_creations: u16,
    pub actual_branch_ref_mutations: u16,
    pub actual_worktree_metadata_mutations: u16,
    pub actual_checkout_file_count: u32,
    pub physical_contact: bool,
    pub may_have_mutated: bool,
    pub retained_state: bool,
    pub network_contact_count: u32,
    pub phase3a_run_count: u32,
    pub p1_app_server_run_count: u32,
    pub writer_run_count: u32,
    pub provider_trial_count: u32,
    pub model_turn_count: u32,
    pub mcp_call_count: u32,
    pub d_drive_contact_count: u32,
    pub wsl_compile_count: u32,
    pub cleanup_count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationSimulationStatus {
    ProviderOnlyPlanVerified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationSimulationAuthority {
    ProviderOnlySimulation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationSimulationReceipt {
    pub profile: String,
    pub status: PreparationSimulationStatus,
    pub authority: PreparationSimulationAuthority,
    pub source_snapshot_uuid: String,
    pub signature_uuid: String,
    pub carrier_commit: String,
    pub implementation_commit: String,
    pub bookend_commit: String,
    pub expected_current_commit: String,
    pub request_sha256: ContentDigest,
    pub publication_proof_sha256: ContentDigest,
    pub plan_sha256: ContentDigest,
    pub process_observations_sha256: ContentDigest,
    pub projection_sha256: ContentDigest,
    pub consequences_sha256: ContentDigest,
    pub receipt_sha256: ContentDigest,
    pub process_count: u16,
    pub network_command_count: u16,
    pub physical_preparation_authorized: bool,
    pub physical_contact: bool,
    pub may_have_mutated: bool,
    pub reserved_root_contact: bool,
    pub reserved_ref_contact: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationEvidenceManifest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub artifacts: Vec<PreparationArtifactIdentity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationFailureDisposition {
    NotRun,
    Quarantined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CDriveWorktreePreparationFaultCode {
    Path,
    Manifest,
    MachineForm,
    Request,
    PublicationProof,
    Plan,
    Process,
    Projection,
    Consequence,
    Receipt,
    Bound,
    Authority,
    Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CDriveWorktreePreparationFault {
    pub code: CDriveWorktreePreparationFaultCode,
    pub message: String,
}

impl fmt::Display for CDriveWorktreePreparationFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for CDriveWorktreePreparationFault {}

pub trait ProviderOnlyPreparationBroker {
    fn simulate(
        &mut self,
        child: &PreparationChildSpec,
    ) -> Result<PreparationProcessObservation, CDriveWorktreePreparationFault>;
}

#[derive(Serialize)]
struct PreparationSimulationReceiptBody<'a> {
    profile: &'a str,
    status: PreparationSimulationStatus,
    authority: PreparationSimulationAuthority,
    source_snapshot_uuid: &'a str,
    signature_uuid: &'a str,
    carrier_commit: &'a str,
    implementation_commit: &'a str,
    bookend_commit: &'a str,
    expected_current_commit: &'a str,
    request_sha256: &'a ContentDigest,
    publication_proof_sha256: &'a ContentDigest,
    plan_sha256: &'a ContentDigest,
    process_observations_sha256: &'a ContentDigest,
    projection_sha256: &'a ContentDigest,
    consequences_sha256: &'a ContentDigest,
    process_count: u16,
    network_command_count: u16,
    physical_preparation_authorized: bool,
    physical_contact: bool,
    may_have_mutated: bool,
    reserved_root_contact: bool,
    reserved_ref_contact: bool,
}

pub fn compile_cdrive_worktree_preparation_plan(
    request: &CDriveWorktreePreparationRequest,
    proof: &SupervisingPublicationProof,
) -> Result<CDriveWorktreePreparationPlan, CDriveWorktreePreparationFault> {
    validate_request(request)?;
    validate_publication_proof(request, proof)?;
    let principal = request.principal_workspace.clone();
    let candidate = request.candidate_root.clone();
    let short_branch = request
        .branch_ref
        .strip_prefix("refs/heads/")
        .ok_or_else(|| {
            fault(
                CDriveWorktreePreparationFaultCode::Request,
                "branch prefix differs",
            )
        })?;
    let mut children = vec![
        child(1, "git_version_before", vec!["--version"], vec![0], false),
        child(
            2,
            "branch_absence",
            vec![
                "-C",
                &principal,
                "show-ref",
                "--verify",
                "--quiet",
                &request.branch_ref,
            ],
            vec![1],
            false,
        ),
        child(
            3,
            "carrier_ancestry",
            vec![
                "-C",
                &principal,
                "merge-base",
                "--is-ancestor",
                &request.carrier_commit,
                &request.implementation_commit,
            ],
            vec![0],
            false,
        ),
        child(
            4,
            "local_publication_identity",
            vec![
                "-C",
                &principal,
                "rev-parse",
                "HEAD",
                "@{u}",
                "refs/remotes/origin/codex/self-hosted-corpus",
            ],
            vec![0],
            false,
        ),
        child(
            5,
            "worktree_inventory_before",
            vec!["-C", &principal, "worktree", "list", "--porcelain", "-z"],
            vec![0],
            false,
        ),
        child(
            6,
            "worktree_add",
            vec![
                "-C",
                &principal,
                "worktree",
                "add",
                "-b",
                short_branch,
                &candidate,
                &request.carrier_commit,
            ],
            vec![0],
            true,
        ),
        child(
            7,
            "candidate_topology",
            vec![
                "-C",
                &candidate,
                "rev-parse",
                "--show-toplevel",
                "--path-format=absolute",
                "--git-common-dir",
                "--git-dir",
                "HEAD",
            ],
            vec![0],
            false,
        ),
        child(
            8,
            "candidate_branch",
            vec!["-C", &candidate, "symbolic-ref", "--quiet", "HEAD"],
            vec![0],
            false,
        ),
        child(
            9,
            "candidate_status",
            vec![
                "-C",
                &candidate,
                "status",
                "--porcelain=v2",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ],
            vec![0],
            false,
        ),
        child(
            10,
            "worktree_inventory_after",
            vec!["-C", &principal, "worktree", "list", "--porcelain", "-z"],
            vec![0],
            false,
        ),
        child(
            11,
            "submodule_status",
            vec!["-C", &candidate, "submodule", "status", "--recursive"],
            vec![0],
            false,
        ),
        child(12, "git_version_after", vec!["--version"], vec![0], false),
    ];
    children[3].expected_stdout_lines = vec![request.expected_current_commit.clone(); 3];
    if children
        .iter()
        .any(|item| !has_closed_process_contract(item))
        || children.iter().filter(|item| item.mutating).count() != 1
        || children
            .iter()
            .any(|item| !item.arguments.starts_with(&git_configuration_prefix()))
        || children[3].expected_stdout_lines != vec![request.expected_current_commit.clone(); 3]
        || children
            .iter()
            .enumerate()
            .any(|(index, item)| index != 3 && !item.expected_stdout_lines.is_empty())
    {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::Plan,
            "closed command plan differs",
        ));
    }
    Ok(CDriveWorktreePreparationPlan {
        profile: B1_CDRIVE_WORKTREE_PREPARATION_PLAN_PROFILE.to_owned(),
        request_sha256: digest(request)?,
        publication_proof_sha256: digest(proof)?,
        expected_current_commit: request.expected_current_commit.clone(),
        children,
        physical_execution_authorized: false,
        planned_directory_creations: 5,
        planned_regular_file_creations: 1,
        planned_branch_ref_mutations: 1,
        planned_worktree_metadata_mutations: 1,
        planned_checkout_file_count: 4_416,
        network_command_count: 0,
        maximum_processes: EXACT_PROCESS_COUNT as u16,
        maximum_stream_bytes: MAX_STREAM_BYTES,
        maximum_total_process_bytes: MAX_TOTAL_PROCESS_BYTES,
        total_deadline_millis: PROCESS_DEADLINE_MILLIS,
    })
}

pub fn parse_and_validate_cdrive_worktree_preparation_publication_proof(
    request: &CDriveWorktreePreparationRequest,
    proof_bytes: &[u8],
) -> Result<SupervisingPublicationProof, CDriveWorktreePreparationFault> {
    validate_request(request)?;
    if request.publication_proof_artifact.bytes != proof_bytes.len() as u64
        || request.publication_proof_artifact.sha256 != sha256_upper(proof_bytes)
    {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::PublicationProof,
            "raw publication proof identity differs",
        ));
    }
    let proof = parse_strict(proof_bytes)?;
    validate_publication_proof(request, &proof)?;
    Ok(proof)
}

fn has_closed_process_contract(child: &PreparationChildSpec) -> bool {
    child.executable == B1_CDRIVE_WORKTREE_PREPARATION_GIT
        && !child.network
        && child.environment_clear_first
        && child.environment == closed_environment()
        && child.stdin_closed
        && child.maximum_stdout_bytes == MAX_STREAM_BYTES
        && child.maximum_stderr_bytes == MAX_STREAM_BYTES
        && child.maximum_total_bytes == MAX_TOTAL_PROCESS_BYTES
        && child.deadline_millis == PROCESS_DEADLINE_MILLIS
        && child.deadline_scope == "shared_plan_total"
        && child.rehash_executable_before_start
        && child.terminate_on_timeout
        && child.wait_after_terminate
        && child.require_descendant_free
        && child.require_late_output_free
}

pub fn simulate_cdrive_worktree_preparation_plan(
    request: &CDriveWorktreePreparationRequest,
    proof: &SupervisingPublicationProof,
    broker: &mut impl ProviderOnlyPreparationBroker,
) -> Result<
    (
        CDriveWorktreePreparationPlan,
        Vec<PreparationProcessObservation>,
        PreparationStateProjection,
        PreparationSimulationConsequences,
        PreparationSimulationReceipt,
    ),
    CDriveWorktreePreparationFault,
> {
    let plan = compile_cdrive_worktree_preparation_plan(request, proof)?;
    let mut observations = Vec::with_capacity(plan.children.len());
    for spec in &plan.children {
        let observed = broker.simulate(spec)?;
        validate_process_observation(spec, &observed)?;
        observations.push(observed);
    }
    validate_process_observations(&plan, &observations)?;
    let projection = expected_projection(request);
    let consequences = expected_simulation_consequences(&plan);
    let receipt = compile_simulation_receipt(
        request,
        proof,
        &plan,
        &observations,
        &projection,
        &consequences,
    )?;
    Ok((plan, observations, projection, consequences, receipt))
}

pub fn verify_cdrive_worktree_preparation_evidence(
    evidence_root: &Path,
) -> Result<PreparationSimulationReceipt, CDriveWorktreePreparationFault> {
    let canonical_root = fs::canonicalize(evidence_root).map_err(|error| {
        fault(
            CDriveWorktreePreparationFaultCode::Path,
            format!("evidence root canonicalization failed: {error}"),
        )
    })?;
    if !canonical_root.is_dir() {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::Path,
            "evidence root is not a directory",
        ));
    }
    let manifest_bytes = read_regular(&canonical_root, "evidence_manifest.json")?;
    let manifest: PreparationEvidenceManifest = parse_strict(&manifest_bytes)?;
    validate_manifest(&manifest)?;
    let mut total = manifest_bytes.len() as u64;
    let mut artifacts = Vec::with_capacity(EXACT_ARTIFACT_NAMES.len());
    for identity in &manifest.artifacts {
        let bytes = read_regular(&canonical_root, &identity.path)?;
        total = total.checked_add(bytes.len() as u64).ok_or_else(|| {
            fault(
                CDriveWorktreePreparationFaultCode::Bound,
                "evidence bytes overflowed",
            )
        })?;
        if total > MAX_EVIDENCE_BYTES
            || identity.bytes != bytes.len() as u64
            || identity.sha256 != sha256_upper(&bytes)
        {
            return Err(fault(
                CDriveWorktreePreparationFaultCode::Manifest,
                format!("artifact identity differs: {}", identity.path),
            ));
        }
        artifacts.push((identity.path.as_str(), bytes));
    }
    let request: CDriveWorktreePreparationRequest =
        parse_strict(artifact(&artifacts, "request.json")?)?;
    let proof = parse_and_validate_cdrive_worktree_preparation_publication_proof(
        &request,
        artifact(&artifacts, "publication_proof.json")?,
    )?;
    let supplied_plan: CDriveWorktreePreparationPlan =
        parse_strict(artifact(&artifacts, "plan.json")?)?;
    let observations: Vec<PreparationProcessObservation> =
        parse_strict(artifact(&artifacts, "process_observations.json")?)?;
    let projection: PreparationStateProjection =
        parse_strict(artifact(&artifacts, "projection.json")?)?;
    let consequences: PreparationSimulationConsequences =
        parse_strict(artifact(&artifacts, "consequences.json")?)?;
    let supplied_receipt: PreparationSimulationReceipt =
        parse_strict(artifact(&artifacts, "simulation_receipt.json")?)?;
    if request.publication_proof_artifact.path != "publication_proof.json" {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::PublicationProof,
            "request publication proof identity differs",
        ));
    }
    let expected_plan = compile_cdrive_worktree_preparation_plan(&request, &proof)?;
    if supplied_plan != expected_plan {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::Plan,
            "supplied plan or process count differs",
        ));
    }
    validate_process_observations(&expected_plan, &observations)?;
    if projection != expected_projection(&request) {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::Projection,
            "provider-only state projection differs",
        ));
    }
    let expected_consequences = expected_simulation_consequences(&expected_plan);
    if consequences != expected_consequences {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::Consequence,
            "provider-only consequences differ",
        ));
    }
    let expected_receipt = compile_simulation_receipt(
        &request,
        &proof,
        &expected_plan,
        &observations,
        &projection,
        &consequences,
    )?;
    if supplied_receipt != expected_receipt {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::Receipt,
            "simulation receipt differs",
        ));
    }
    validate_simulation_receipt(&supplied_receipt)?;
    Ok(supplied_receipt)
}

pub fn classify_cdrive_worktree_preparation_failure(
    physical_effect_started: bool,
) -> PreparationFailureDisposition {
    if physical_effect_started {
        PreparationFailureDisposition::Quarantined
    } else {
        PreparationFailureDisposition::NotRun
    }
}

pub fn validate_cdrive_worktree_preparation_local_gate(
    request: &CDriveWorktreePreparationRequest,
    proof: &SupervisingPublicationProof,
    observation: &PreparationLocalGateObservation,
) -> Result<(), CDriveWorktreePreparationFault> {
    validate_request(request)?;
    validate_publication_proof(request, proof)?;
    let exact = observation.profile == B1_CDRIVE_WORKTREE_PREPARATION_LOCAL_GATE_PROFILE
        && observation.source_snapshot_uuid == B1_CDRIVE_WORKTREE_PREPARATION_SOURCE_SNAPSHOT_UUID
        && observation.signature_uuid == B1_CDRIVE_WORKTREE_PREPARATION_SIGNATURE_UUID
        && observation.recovery_owner == request.recovery_owner
        && observation.principal_workspace == request.principal_workspace
        && observation.repository_common_dir == request.repository_common_dir
        && observation.worktree_parent == WORKTREE_PARENT
        && observation.volume_guid == C_VOLUME_GUID
        && observation.volume_filesystem == "NTFS"
        && observation.parent_is_canonical_directory
        && !observation.parent_is_reparse_point
        && observation.scratch_root_absent
        && observation.hook_quarantine_root == request.hook_quarantine_root
        && observation.attribute_quarantine_file == request.attribute_quarantine_file
        && observation.hook_quarantine_root_absent
        && observation.attribute_quarantine_file_absent
        && observation.repository_info_attributes_absent
        && observation.branch_ref_absent
        && observation.carrier_commit == request.carrier_commit
        && observation.implementation_commit == request.implementation_commit
        && observation.bookend_commit == request.bookend_commit
        && observation.expected_current_commit == request.expected_current_commit
        && observation.local_head == request.expected_current_commit
        && observation.local_tracking == request.expected_current_commit
        && observation.origin_remote_tracking == request.expected_current_commit
        && observation.carrier_ancestor_of_implementation
        && observation.implementation_immediate_parent_of_bookend
        && observation.bookend_ancestor_of_current_commit
        && observation.carrier_tracked_entry_count == 4_416
        && observation.carrier_mode_100644_count == 4_416
        && observation.carrier_other_mode_count == 0
        && observation.carrier_attributes_file_count == 1
        && observation.carrier_gitattributes_blob == CARRIER_GITATTRIBUTES_BLOB
        && observation.carrier_gitattributes_bytes == 185
        && observation.carrier_gitattributes_sha256 == CARRIER_GITATTRIBUTES_SHA256
        && observation.carrier_filter_assignment_count == 0
        && observation.carrier_gitmodules_absent
        && observation.git_executable == request.git_executable
        && observation.git_executable_bytes == request.git_executable_bytes
        && observation.git_executable_sha256 == request.git_executable_sha256
        && observation.git_version == request.git_version
        && observation.pre_effect_free_bytes >= request.minimum_pre_effect_free_bytes
        && observation.process_count == 5
        && observation.network_contact_count == 0
        && !observation.physical_contact;
    if !exact {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::Authority,
            "local pre-effect gate differs",
        ));
    }
    Ok(())
}

pub fn validate_cdrive_worktree_preparation_outcome(
    request: &CDriveWorktreePreparationRequest,
    outcome: &PreparationOutcomeAccount,
) -> Result<(), CDriveWorktreePreparationFault> {
    validate_request(request)?;
    let zero_downstream = outcome.network_contact_count == 0
        && outcome.phase3a_run_count == 0
        && outcome.p1_app_server_run_count == 0
        && outcome.writer_run_count == 0
        && outcome.provider_trial_count == 0
        && outcome.model_turn_count == 0
        && outcome.mcp_call_count == 0
        && outcome.d_drive_contact_count == 0
        && outcome.wsl_compile_count == 0
        && outcome.cleanup_count == 0;
    let counts_bounded = outcome.actual_directory_creations <= 5
        && outcome.actual_regular_file_creations <= 1
        && outcome.actual_branch_ref_mutations <= 1
        && outcome.actual_worktree_metadata_mutations <= 1
        && outcome.actual_checkout_file_count <= 4_416;
    let disposition_exact = match outcome.disposition {
        PreparationOutcomeDisposition::NotRun => {
            !outcome.pre_effect_gate_passed
                && !outcome.post_effect_verification_passed
                && !outcome.physical_contact
                && !outcome.may_have_mutated
                && !outcome.retained_state
                && !outcome.reserved_root_contact
                && !outcome.reserved_ref_contact
                && outcome.actual_directory_creations == 0
                && outcome.actual_regular_file_creations == 0
                && outcome.actual_branch_ref_mutations == 0
                && outcome.actual_worktree_metadata_mutations == 0
                && outcome.actual_checkout_file_count == 0
                && outcome.final_free_bytes.is_none()
                && !outcome.success_receipt_emitted
        }
        PreparationOutcomeDisposition::Quarantined => {
            outcome.pre_effect_gate_passed
                && !outcome.post_effect_verification_passed
                && outcome.physical_contact
                && outcome.may_have_mutated
                && outcome.retained_state
                && outcome.reserved_root_contact
                && !outcome.success_receipt_emitted
                && counts_bounded
        }
        PreparationOutcomeDisposition::PreparedForPhase3aAcquisition => {
            outcome.pre_effect_gate_passed
                && outcome.post_effect_verification_passed
                && outcome.physical_contact
                && outcome.may_have_mutated
                && outcome.retained_state
                && outcome.reserved_root_contact
                && outcome.reserved_ref_contact
                && outcome.actual_directory_creations == 5
                && outcome.actual_regular_file_creations == 1
                && outcome.actual_branch_ref_mutations == 1
                && outcome.actual_worktree_metadata_mutations == 1
                && outcome.actual_checkout_file_count == 4_416
                && outcome
                    .final_free_bytes
                    .is_some_and(|bytes| bytes >= request.minimum_final_free_bytes)
                && outcome.success_receipt_emitted
        }
    };
    if outcome.profile != B1_CDRIVE_WORKTREE_PREPARATION_OUTCOME_PROFILE
        || outcome.authority != "linked_worktree_preparation_observation_only"
        || !zero_downstream
        || !counts_bounded
        || !disposition_exact
    {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::Consequence,
            "preparation outcome account differs",
        ));
    }
    Ok(())
}

pub fn validate_cdrive_worktree_prepared_observations(
    request: &CDriveWorktreePreparationRequest,
    filesystem: &PreparationFilesystemObservation,
    git: &PreparationGitObservation,
    outcome: &PreparationOutcomeAccount,
) -> Result<(), CDriveWorktreePreparationFault> {
    validate_cdrive_worktree_preparation_outcome(request, outcome)?;
    if outcome.disposition != PreparationOutcomeDisposition::PreparedForPhase3aAcquisition {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::Authority,
            "prepared observations require prepared disposition",
        ));
    }
    let filesystem_exact = filesystem.profile == B1_CDRIVE_WORKTREE_PREPARATION_FILESYSTEM_PROFILE
        && filesystem.scratch_root == request.scratch_root
        && filesystem.candidate_root == request.candidate_root
        && filesystem.evidence_root == request.evidence_root
        && filesystem.temp_root == request.temp_root
        && filesystem.codex_home == request.codex_home
        && filesystem.hook_quarantine_root == request.hook_quarantine_root
        && filesystem.attribute_quarantine_file == request.attribute_quarantine_file
        && filesystem.scratch_present
        && filesystem.candidate_present
        && filesystem.evidence_present
        && filesystem.temp_present
        && filesystem.codex_home_present
        && filesystem.hook_quarantine_present
        && filesystem.hook_quarantine_is_directory
        && !filesystem.hook_quarantine_is_reparse_point
        && filesystem.hook_quarantine_entry_count == 0
        && filesystem.attribute_quarantine_present
        && filesystem.attribute_quarantine_is_regular_file
        && !filesystem.attribute_quarantine_is_reparse_point
        && filesystem.attribute_quarantine_bytes == 0
        && filesystem.attribute_quarantine_sha256 == EMPTY_SHA256
        && filesystem.repository_info_attributes_absent
        && filesystem.roles_pairwise_disjoint
        && filesystem.roles_strict_scratch_descendants
        && filesystem.principal_strictly_nonoverlapping
        && filesystem.same_selected_volume
        && filesystem.directory_creation_count == 5
        && filesystem.regular_file_creation_count == 1
        && filesystem.other_path_effect_count == 0
        && filesystem.principal_worktree_file_mutation_count == 0
        && filesystem.candidate_post_checkout_authorship_count == 0
        && filesystem.allowed_sentinel_bytes == 31
        && filesystem.allowed_sentinel_sha256 == ALLOWED_SENTINEL_SHA256
        && filesystem.denied_sentinel_bytes == 30
        && filesystem.denied_sentinel_sha256 == DENIED_SENTINEL_SHA256
        && !filesystem.write_canary_present
        && filesystem.cleanup_count == 0;
    let git_exact = git.profile == B1_CDRIVE_WORKTREE_PREPARATION_GIT_OBSERVATION_PROFILE
        && git.carrier_commit == request.carrier_commit
        && git.candidate_head == request.carrier_commit
        && git.candidate_branch_ref == request.branch_ref
        && git.candidate_top_level == request.candidate_root
        && git.candidate_common_dir == request.repository_common_dir
        && is_worktree_git_dir(&git.candidate_git_dir)
        && git.candidate_git_dir_under_worktree_admin
        && git.candidate_status_bytes == 0
        && git.recursive_submodule_status_bytes == 0
        && git.exact_worktree_membership_count == 1
        && git.branch_ref_mutation_count == 1
        && git.worktree_metadata_mutation_count == 1
        && git.checkout_file_count == 4_416
        && git.protected_ref_mutation_count == 0
        && git.fetch_count == 0
        && git.pull_count == 0
        && git.remote_update_count == 0
        && git.commit_count == 0
        && git.push_count == 0
        && git.retry_count == 0
        && git.worktree_remove_count == 0
        && git.branch_delete_count == 0
        && git.git_version_before == request.git_version
        && git.git_version_after == request.git_version;
    if !filesystem_exact || !git_exact {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::Projection,
            "prepared filesystem or Git observation differs",
        ));
    }
    Ok(())
}

pub fn from_cdrive_worktree_preparation_local_gate_machine_form(
    machine_form: &str,
) -> Result<PreparationLocalGateObservation, CDriveWorktreePreparationFault> {
    parse_strict(machine_form.as_bytes())
}

pub fn from_cdrive_worktree_preparation_filesystem_machine_form(
    machine_form: &str,
) -> Result<PreparationFilesystemObservation, CDriveWorktreePreparationFault> {
    parse_strict(machine_form.as_bytes())
}

pub fn from_cdrive_worktree_preparation_git_observation_machine_form(
    machine_form: &str,
) -> Result<PreparationGitObservation, CDriveWorktreePreparationFault> {
    parse_strict(machine_form.as_bytes())
}

pub fn to_cdrive_worktree_preparation_outcome_machine_form(
    request: &CDriveWorktreePreparationRequest,
    outcome: &PreparationOutcomeAccount,
) -> Result<String, CDriveWorktreePreparationFault> {
    validate_cdrive_worktree_preparation_outcome(request, outcome)?;
    serde_json::to_string(outcome).map_err(machine_fault)
}

pub fn from_cdrive_worktree_preparation_outcome_machine_form(
    request: &CDriveWorktreePreparationRequest,
    machine_form: &str,
) -> Result<PreparationOutcomeAccount, CDriveWorktreePreparationFault> {
    let outcome = parse_strict(machine_form.as_bytes())?;
    validate_cdrive_worktree_preparation_outcome(request, &outcome)?;
    Ok(outcome)
}

pub fn to_cdrive_worktree_preparation_plan_machine_form(
    plan: &CDriveWorktreePreparationPlan,
) -> Result<String, CDriveWorktreePreparationFault> {
    serde_json::to_string(plan).map_err(machine_fault)
}

pub fn from_cdrive_worktree_preparation_request_machine_form(
    machine_form: &str,
) -> Result<CDriveWorktreePreparationRequest, CDriveWorktreePreparationFault> {
    parse_strict(machine_form.as_bytes())
}

pub fn from_cdrive_worktree_preparation_publication_proof_machine_form(
    machine_form: &str,
) -> Result<SupervisingPublicationProof, CDriveWorktreePreparationFault> {
    parse_strict(machine_form.as_bytes())
}

pub fn to_cdrive_worktree_preparation_simulation_receipt_machine_form(
    receipt: &PreparationSimulationReceipt,
) -> Result<String, CDriveWorktreePreparationFault> {
    validate_simulation_receipt(receipt)?;
    serde_json::to_string(receipt).map_err(machine_fault)
}

pub fn from_cdrive_worktree_preparation_simulation_receipt_machine_form(
    machine_form: &str,
) -> Result<PreparationSimulationReceipt, CDriveWorktreePreparationFault> {
    let receipt = parse_strict(machine_form.as_bytes())?;
    validate_simulation_receipt(&receipt)?;
    Ok(receipt)
}

fn validate_request(
    request: &CDriveWorktreePreparationRequest,
) -> Result<(), CDriveWorktreePreparationFault> {
    let scratch = B1_CDRIVE_WORKTREE_PREPARATION_SCRATCH;
    let exact = request.profile == B1_CDRIVE_WORKTREE_PREPARATION_REQUEST_PROFILE
        && request.source_snapshot_uuid == B1_CDRIVE_WORKTREE_PREPARATION_SOURCE_SNAPSHOT_UUID
        && request.signature_uuid == B1_CDRIVE_WORKTREE_PREPARATION_SIGNATURE_UUID
        && request.predecessor_invalidation_uuid
            == B1_CDRIVE_WORKTREE_PREPARATION_INVALIDATION_UUID
        && request.carrier_commit == B1_CDRIVE_WORKTREE_PREPARATION_CARRIER
        && request.implementation_commit == B1_CDRIVE_WORKTREE_PREPARATION_IMPLEMENTATION
        && request.bookend_commit == B1_CDRIVE_WORKTREE_PREPARATION_BOOKEND
        && request.physical_commission_uuid.is_none()
        && !request.physical_preparation_authorized
        && request.recovery_owner == "THEBRAIN\\enjer"
        && request.principal_workspace == PRINCIPAL
        && request.repository_common_dir == COMMON_DIR
        && request.scratch_root == scratch
        && request.candidate_root == format!("{scratch}\\candidate")
        && request.evidence_root == format!("{scratch}\\evidence")
        && request.temp_root == format!("{scratch}\\temp")
        && request.codex_home == format!("{scratch}\\codex-home")
        && request.hook_quarantine_root == B1_CDRIVE_WORKTREE_PREPARATION_HOOK_QUARANTINE
        && request.attribute_quarantine_file == B1_CDRIVE_WORKTREE_PREPARATION_ATTRIBUTE_QUARANTINE
        && request.branch_ref == B1_CDRIVE_WORKTREE_PREPARATION_BRANCH
        && request.git_executable == B1_CDRIVE_WORKTREE_PREPARATION_GIT
        && request.git_executable_bytes == 46_480
        && request.git_executable_sha256 == B1_CDRIVE_WORKTREE_PREPARATION_GIT_SHA256
        && request.git_version == B1_CDRIVE_WORKTREE_PREPARATION_GIT_VERSION
        && request.maximum_processes == 12
        && request.maximum_stream_bytes == MAX_STREAM_BYTES
        && request.maximum_total_process_bytes == MAX_TOTAL_PROCESS_BYTES
        && request.deadline_millis == 30_000
        && request.minimum_pre_effect_free_bytes == 15_032_385_536
        && request.minimum_final_free_bytes == 12_884_901_888
        && is_lower_git_object_id(&request.implementation_commit)
        && is_lower_git_object_id(&request.bookend_commit)
        && is_lower_git_object_id(&request.expected_current_commit)
        && request.implementation_commit != request.bookend_commit
        && request.expected_current_commit != request.implementation_commit
        && request.expected_current_commit != request.bookend_commit
        && is_safe_relative_path(&request.publication_proof_artifact.path)
        && request.publication_proof_artifact.bytes > 0
        && request.publication_proof_artifact.bytes <= MAX_ARTIFACT_BYTES
        && is_upper_sha256(&request.publication_proof_artifact.sha256);
    if !exact {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::Request,
            "provider-only request differs from corrective authority",
        ));
    }
    Ok(())
}

fn validate_publication_proof(
    request: &CDriveWorktreePreparationRequest,
    proof: &SupervisingPublicationProof,
) -> Result<(), CDriveWorktreePreparationFault> {
    let exact = proof.profile == B1_CDRIVE_WORKTREE_PREPARATION_PROOF_PROFILE
        && proof.proof_uuid == B1_CDRIVE_WORKTREE_PREPARATION_PROOF_UUID
        && proof.implementation_commit == request.implementation_commit
        && proof.bookend_commit == request.bookend_commit
        && proof.branch_ref == TRACKING_BRANCH
        && proof.bookend_local_head == request.bookend_commit
        && proof.bookend_local_tracking == request.bookend_commit
        && proof.bookend_origin_remote_tracking == request.bookend_commit
        && proof.bookend_ls_remote == request.bookend_commit
        && proof.implementation_parent_of_bookend
        && proof.carrier_ancestor_of_implementation
        && proof.focused_debug_test_count == 11
        && proof.focused_release_test_count == 11
        && proof.focused_failure_count == 0
        && proof.evidence_manifest_count == 55
        && proof.evidence_reference_count == 1_966
        && proof.evidence_stale_count == 0
        && proof.physical_preparation_run_count == 0
        && proof.placement == "committed_descendant_artifact"
        && !proof.contains_own_commit_identity;
    if !exact {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::PublicationProof,
            "supervising publication proof differs",
        ));
    }
    Ok(())
}

fn child(
    sequence: u16,
    operation: &str,
    arguments: Vec<&str>,
    allowed_exit_codes: Vec<i32>,
    mutating: bool,
) -> PreparationChildSpec {
    let mut exact_arguments = git_configuration_prefix();
    exact_arguments.extend(arguments.into_iter().map(str::to_owned));
    PreparationChildSpec {
        sequence,
        operation: operation.to_owned(),
        executable: B1_CDRIVE_WORKTREE_PREPARATION_GIT.to_owned(),
        arguments: exact_arguments,
        expected_stdout_lines: Vec::new(),
        allowed_exit_codes,
        mutating,
        network: false,
        environment_clear_first: true,
        environment: closed_environment(),
        stdin_closed: true,
        maximum_stdout_bytes: MAX_STREAM_BYTES,
        maximum_stderr_bytes: MAX_STREAM_BYTES,
        maximum_total_bytes: MAX_TOTAL_PROCESS_BYTES,
        deadline_millis: PROCESS_DEADLINE_MILLIS,
        deadline_scope: "shared_plan_total".to_owned(),
        rehash_executable_before_start: true,
        terminate_on_timeout: true,
        wait_after_terminate: true,
        require_descendant_free: true,
        require_late_output_free: true,
    }
}

fn git_configuration_prefix() -> Vec<String> {
    [
        "-c".to_owned(),
        format!("core.hooksPath={B1_CDRIVE_WORKTREE_PREPARATION_HOOK_QUARANTINE}"),
        "-c".to_owned(),
        "core.fsmonitor=false".to_owned(),
        "-c".to_owned(),
        format!("core.attributesFile={B1_CDRIVE_WORKTREE_PREPARATION_ATTRIBUTE_QUARANTINE}"),
        "-c".to_owned(),
        "maintenance.auto=false".to_owned(),
        "-c".to_owned(),
        "gc.auto=0".to_owned(),
        "-c".to_owned(),
        "protocol.file.allow=never".to_owned(),
    ]
    .into_iter()
    .collect()
}

fn closed_environment() -> Vec<PreparationEnvironmentEntry> {
    let scratch = B1_CDRIVE_WORKTREE_PREPARATION_SCRATCH;
    [
        ("GIT_ASKPASS", "NUL".to_owned()),
        ("GIT_ATTR_NOSYSTEM", "1".to_owned()),
        ("GIT_CONFIG_GLOBAL", "NUL".to_owned()),
        ("GIT_CONFIG_NOSYSTEM", "1".to_owned()),
        ("GIT_NO_LAZY_FETCH", "1".to_owned()),
        ("GIT_OPTIONAL_LOCKS", "0".to_owned()),
        ("GIT_TERMINAL_PROMPT", "0".to_owned()),
        ("HOME", format!("{scratch}\\codex-home")),
        ("PATH", GIT_PATH.to_owned()),
        ("PATHEXT", PATHEXT.to_owned()),
        ("SYSTEMROOT", "C:\\Windows".to_owned()),
        ("TEMP", format!("{scratch}\\temp")),
        ("TMP", format!("{scratch}\\temp")),
        ("WINDIR", "C:\\Windows".to_owned()),
    ]
    .into_iter()
    .map(|(name, value)| PreparationEnvironmentEntry {
        name: name.to_owned(),
        value,
    })
    .collect()
}

fn validate_process_observation(
    spec: &PreparationChildSpec,
    observed: &PreparationProcessObservation,
) -> Result<(), CDriveWorktreePreparationFault> {
    if observed.sequence != spec.sequence
        || observed.operation != spec.operation
        || observed.arguments != spec.arguments
        || (!spec.expected_stdout_lines.is_empty()
            && observed.stdout.lines().collect::<Vec<_>>() != spec.expected_stdout_lines)
        || !spec.allowed_exit_codes.contains(&observed.exit_code)
        || observed.stdout.len() > MAX_STREAM_BYTES
        || observed.stderr.len() > MAX_STREAM_BYTES
        || observed.stdout.len().saturating_add(observed.stderr.len()) > MAX_TOTAL_PROCESS_BYTES
        || observed.timed_out
        || !observed.reaped
        || observed.descendant_count_after != 0
        || observed.late_output_bytes != 0
        || observed.network_contact_count != 0
        || observed.physical_effect_performed
    {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::Process,
            format!(
                "provider-only process observation differs at {}",
                spec.sequence
            ),
        ));
    }
    Ok(())
}

fn validate_process_observations(
    plan: &CDriveWorktreePreparationPlan,
    observations: &[PreparationProcessObservation],
) -> Result<(), CDriveWorktreePreparationFault> {
    if observations.len() != EXACT_PROCESS_COUNT
        || observations.len() != usize::from(plan.maximum_processes)
    {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::Process,
            "provider-only process count differs",
        ));
    }
    let mut total_bytes = 0usize;
    for (spec, observed) in plan.children.iter().zip(observations) {
        validate_process_observation(spec, observed)?;
        total_bytes = total_bytes
            .checked_add(observed.stdout.len())
            .and_then(|value| value.checked_add(observed.stderr.len()))
            .ok_or_else(|| {
                fault(
                    CDriveWorktreePreparationFaultCode::Bound,
                    "total process bytes overflowed",
                )
            })?;
    }
    if total_bytes > plan.maximum_total_process_bytes {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::Bound,
            "total process bytes exceed bound",
        ));
    }
    Ok(())
}

fn expected_projection(request: &CDriveWorktreePreparationRequest) -> PreparationStateProjection {
    PreparationStateProjection {
        principal_workspace: request.principal_workspace.clone(),
        repository_common_dir: request.repository_common_dir.clone(),
        scratch_root: request.scratch_root.clone(),
        candidate_root: request.candidate_root.clone(),
        evidence_root: request.evidence_root.clone(),
        temp_root: request.temp_root.clone(),
        codex_home: request.codex_home.clone(),
        hook_quarantine_root: request.hook_quarantine_root.clone(),
        attribute_quarantine_file: request.attribute_quarantine_file.clone(),
        branch_ref: request.branch_ref.clone(),
        carrier_commit: request.carrier_commit.clone(),
        carrier_tracked_file_count: 4_416,
        carrier_tracked_bytes: 31_972_357,
        carrier_mode_100644_count: 4_416,
        carrier_other_mode_count: 0,
        carrier_attributes_file_count: 1,
        carrier_gitattributes_blob: CARRIER_GITATTRIBUTES_BLOB.to_owned(),
        carrier_gitattributes_bytes: 185,
        carrier_gitattributes_sha256: CARRIER_GITATTRIBUTES_SHA256.to_owned(),
        carrier_filter_assignment_count: 0,
        carrier_gitmodules_absent: true,
        repository_info_attributes_expected_absent: true,
        hook_quarantine_expected_empty: true,
        attribute_quarantine_expected_empty: true,
        allowed_sentinel_sha256: ALLOWED_SENTINEL_SHA256.to_owned(),
        denied_sentinel_sha256: DENIED_SENTINEL_SHA256.to_owned(),
        write_canary_expected_absent: true,
        candidate_status_expected_empty: true,
        submodule_status_expected_empty: true,
        reserved_root_contact: false,
        reserved_ref_contact: false,
    }
}

fn expected_simulation_consequences(
    plan: &CDriveWorktreePreparationPlan,
) -> PreparationSimulationConsequences {
    PreparationSimulationConsequences {
        planned_directory_creations: plan.planned_directory_creations,
        planned_regular_file_creations: plan.planned_regular_file_creations,
        planned_branch_ref_mutations: plan.planned_branch_ref_mutations,
        planned_worktree_metadata_mutations: plan.planned_worktree_metadata_mutations,
        planned_checkout_file_count: plan.planned_checkout_file_count,
        actual_directory_creations: 0,
        actual_regular_file_creations: 0,
        actual_branch_ref_mutations: 0,
        actual_worktree_metadata_mutations: 0,
        actual_checkout_file_count: 0,
        physical_contact: false,
        may_have_mutated: false,
        retained_state: false,
        network_contact_count: 0,
        phase3a_run_count: 0,
        p1_app_server_run_count: 0,
        writer_run_count: 0,
        provider_trial_count: 0,
        model_turn_count: 0,
        mcp_call_count: 0,
        d_drive_contact_count: 0,
        wsl_compile_count: 0,
        cleanup_count: 0,
    }
}

fn compile_simulation_receipt(
    request: &CDriveWorktreePreparationRequest,
    proof: &SupervisingPublicationProof,
    plan: &CDriveWorktreePreparationPlan,
    observations: &[PreparationProcessObservation],
    projection: &PreparationStateProjection,
    consequences: &PreparationSimulationConsequences,
) -> Result<PreparationSimulationReceipt, CDriveWorktreePreparationFault> {
    let request_sha256 = digest(request)?;
    let publication_proof_sha256 = digest(proof)?;
    let plan_sha256 = digest(plan)?;
    let process_observations_sha256 = digest(&observations)?;
    let projection_sha256 = digest(projection)?;
    let consequences_sha256 = digest(consequences)?;
    let receipt_sha256 = {
        let body = PreparationSimulationReceiptBody {
            profile: B1_CDRIVE_WORKTREE_PREPARATION_SIMULATION_RECEIPT_PROFILE,
            status: PreparationSimulationStatus::ProviderOnlyPlanVerified,
            authority: PreparationSimulationAuthority::ProviderOnlySimulation,
            source_snapshot_uuid: &request.source_snapshot_uuid,
            signature_uuid: &request.signature_uuid,
            carrier_commit: &request.carrier_commit,
            implementation_commit: &request.implementation_commit,
            bookend_commit: &request.bookend_commit,
            expected_current_commit: &request.expected_current_commit,
            request_sha256: &request_sha256,
            publication_proof_sha256: &publication_proof_sha256,
            plan_sha256: &plan_sha256,
            process_observations_sha256: &process_observations_sha256,
            projection_sha256: &projection_sha256,
            consequences_sha256: &consequences_sha256,
            process_count: observations.len() as u16,
            network_command_count: 0,
            physical_preparation_authorized: false,
            physical_contact: false,
            may_have_mutated: false,
            reserved_root_contact: false,
            reserved_ref_contact: false,
        };
        digest_in_domain(SIMULATION_RECEIPT_DIGEST_DOMAIN, &body)?
    };
    let receipt = PreparationSimulationReceipt {
        profile: B1_CDRIVE_WORKTREE_PREPARATION_SIMULATION_RECEIPT_PROFILE.to_owned(),
        status: PreparationSimulationStatus::ProviderOnlyPlanVerified,
        authority: PreparationSimulationAuthority::ProviderOnlySimulation,
        source_snapshot_uuid: request.source_snapshot_uuid.clone(),
        signature_uuid: request.signature_uuid.clone(),
        carrier_commit: request.carrier_commit.clone(),
        implementation_commit: request.implementation_commit.clone(),
        bookend_commit: request.bookend_commit.clone(),
        expected_current_commit: request.expected_current_commit.clone(),
        request_sha256,
        publication_proof_sha256,
        plan_sha256,
        process_observations_sha256,
        projection_sha256,
        consequences_sha256,
        receipt_sha256,
        process_count: observations.len() as u16,
        network_command_count: 0,
        physical_preparation_authorized: false,
        physical_contact: false,
        may_have_mutated: false,
        reserved_root_contact: false,
        reserved_ref_contact: false,
    };
    validate_simulation_receipt(&receipt)?;
    Ok(receipt)
}

fn validate_simulation_receipt(
    receipt: &PreparationSimulationReceipt,
) -> Result<(), CDriveWorktreePreparationFault> {
    for value in [
        &receipt.request_sha256,
        &receipt.publication_proof_sha256,
        &receipt.plan_sha256,
        &receipt.process_observations_sha256,
        &receipt.projection_sha256,
        &receipt.consequences_sha256,
        &receipt.receipt_sha256,
    ] {
        validate_digest(value)?;
    }
    let body = PreparationSimulationReceiptBody {
        profile: &receipt.profile,
        status: receipt.status,
        authority: receipt.authority,
        source_snapshot_uuid: &receipt.source_snapshot_uuid,
        signature_uuid: &receipt.signature_uuid,
        carrier_commit: &receipt.carrier_commit,
        implementation_commit: &receipt.implementation_commit,
        bookend_commit: &receipt.bookend_commit,
        expected_current_commit: &receipt.expected_current_commit,
        request_sha256: &receipt.request_sha256,
        publication_proof_sha256: &receipt.publication_proof_sha256,
        plan_sha256: &receipt.plan_sha256,
        process_observations_sha256: &receipt.process_observations_sha256,
        projection_sha256: &receipt.projection_sha256,
        consequences_sha256: &receipt.consequences_sha256,
        process_count: receipt.process_count,
        network_command_count: receipt.network_command_count,
        physical_preparation_authorized: receipt.physical_preparation_authorized,
        physical_contact: receipt.physical_contact,
        may_have_mutated: receipt.may_have_mutated,
        reserved_root_contact: receipt.reserved_root_contact,
        reserved_ref_contact: receipt.reserved_ref_contact,
    };
    if receipt.profile != B1_CDRIVE_WORKTREE_PREPARATION_SIMULATION_RECEIPT_PROFILE
        || receipt.status != PreparationSimulationStatus::ProviderOnlyPlanVerified
        || receipt.authority != PreparationSimulationAuthority::ProviderOnlySimulation
        || receipt.source_snapshot_uuid != B1_CDRIVE_WORKTREE_PREPARATION_SOURCE_SNAPSHOT_UUID
        || receipt.signature_uuid != B1_CDRIVE_WORKTREE_PREPARATION_SIGNATURE_UUID
        || receipt.carrier_commit != B1_CDRIVE_WORKTREE_PREPARATION_CARRIER
        || receipt.implementation_commit != B1_CDRIVE_WORKTREE_PREPARATION_IMPLEMENTATION
        || receipt.bookend_commit != B1_CDRIVE_WORKTREE_PREPARATION_BOOKEND
        || !is_lower_git_object_id(&receipt.expected_current_commit)
        || receipt.expected_current_commit == receipt.implementation_commit
        || receipt.expected_current_commit == receipt.bookend_commit
        || receipt.process_count != EXACT_PROCESS_COUNT as u16
        || receipt.network_command_count != 0
        || receipt.physical_preparation_authorized
        || receipt.physical_contact
        || receipt.may_have_mutated
        || receipt.reserved_root_contact
        || receipt.reserved_ref_contact
        || digest_in_domain(SIMULATION_RECEIPT_DIGEST_DOMAIN, &body)? != receipt.receipt_sha256
    {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::Receipt,
            "simulation receipt authority or digest differs",
        ));
    }
    Ok(())
}

fn validate_manifest(
    manifest: &PreparationEvidenceManifest,
) -> Result<(), CDriveWorktreePreparationFault> {
    let names: Vec<&str> = manifest
        .artifacts
        .iter()
        .map(|item| item.path.as_str())
        .collect();
    if manifest.profile != B1_CDRIVE_WORKTREE_PREPARATION_EVIDENCE_PROFILE
        || manifest.source_snapshot_uuid != B1_CDRIVE_WORKTREE_PREPARATION_SOURCE_SNAPSHOT_UUID
        || names != EXACT_ARTIFACT_NAMES
        || manifest.artifacts.iter().any(|item| {
            item.bytes == 0
                || item.bytes > MAX_ARTIFACT_BYTES
                || !is_upper_sha256(&item.sha256)
                || !is_simple_name(&item.path)
        })
    {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::Manifest,
            "evidence manifest differs",
        ));
    }
    Ok(())
}

fn read_regular(root: &Path, name: &str) -> Result<Vec<u8>, CDriveWorktreePreparationFault> {
    if !is_simple_name(name) {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::Path,
            "artifact name differs",
        ));
    }
    let path = root.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        fault(
            CDriveWorktreePreparationFaultCode::Path,
            format!("artifact metadata failed: {error}"),
        )
    })?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_ARTIFACT_BYTES
    {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::Bound,
            format!("artifact is not a bounded regular file: {name}"),
        ));
    }
    let canonical = fs::canonicalize(&path).map_err(|error| {
        fault(
            CDriveWorktreePreparationFaultCode::Path,
            format!("artifact canonicalize failed: {error}"),
        )
    })?;
    if canonical.parent() != Some(root) {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::Path,
            "artifact escapes root",
        ));
    }
    fs::read(canonical).map_err(|error| {
        fault(
            CDriveWorktreePreparationFaultCode::Path,
            format!("artifact read failed: {error}"),
        )
    })
}

fn artifact<'a>(
    artifacts: &'a [(&str, Vec<u8>)],
    name: &str,
) -> Result<&'a [u8], CDriveWorktreePreparationFault> {
    artifacts
        .iter()
        .find_map(|(candidate, bytes)| (*candidate == name).then_some(bytes.as_slice()))
        .ok_or_else(|| {
            fault(
                CDriveWorktreePreparationFaultCode::Manifest,
                format!("artifact absent: {name}"),
            )
        })
}

fn digest<T: Serialize + ?Sized>(
    value: &T,
) -> Result<ContentDigest, CDriveWorktreePreparationFault> {
    let bytes = serde_json::to_vec(value).map_err(machine_fault)?;
    Ok(sha256_bytes(&bytes))
}

fn digest_in_domain<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
) -> Result<ContentDigest, CDriveWorktreePreparationFault> {
    let machine_form = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + machine_form.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&machine_form);
    Ok(sha256_bytes(&bytes))
}

fn sha256_upper(bytes: &[u8]) -> String {
    sha256_bytes(bytes).value.to_ascii_uppercase()
}

fn validate_digest(value: &ContentDigest) -> Result<(), CDriveWorktreePreparationFault> {
    if value.algorithm != "sha256" || !is_lower_sha256(&value.value) {
        return Err(fault(
            CDriveWorktreePreparationFaultCode::Digest,
            "digest differs",
        ));
    }
    Ok(())
}

fn is_lower_git_object_id(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_upper_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
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

fn is_worktree_git_dir(value: &str) -> bool {
    value
        .strip_prefix(&format!("{WORKTREE_ADMIN_ROOT}\\"))
        .is_some_and(|leaf| {
            !leaf.is_empty() && !leaf.contains(['\\', '/']) && leaf != "." && leaf != ".."
        })
}

fn fault(
    code: CDriveWorktreePreparationFaultCode,
    message: impl Into<String>,
) -> CDriveWorktreePreparationFault {
    CDriveWorktreePreparationFault {
        code,
        message: message.into(),
    }
}

fn machine_fault(error: impl fmt::Display) -> CDriveWorktreePreparationFault {
    fault(
        CDriveWorktreePreparationFaultCode::MachineForm,
        error.to_string(),
    )
}

fn parse_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CDriveWorktreePreparationFault> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    StrictSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(machine_fault)?;
    deserializer.end().map_err(machine_fault)?;
    serde_json::from_slice(bytes).map_err(machine_fault)
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
        formatter.write_str("a duplicate-free bounded JSON value")
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

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .ok_or_else(|| E::custom("non-finite JSON number"))
            .map(|_| StrictValue)
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
