//! Pure admission of a future B1 C-drive preparation commission.
//!
//! This module joins canonical B0 formation evidence with the published
//! Revision 0.4 provider-only preparation receipt. It validates a supplied
//! commission, capability partition, and ten-step mutation fence, but it does
//! not issue a commission, acquire a lease, write a ledger, launch a process,
//! mutate Git, or touch the reserved worktree.

use std::{
    collections::HashSet,
    fmt, fs,
    path::{Component, Path},
};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::Number;
use sha2::{Digest, Sha256};

use crate::{
    self_work_update_broker_b1_cdrive_worktree_preparation::{
        PreparationSimulationReceipt,
        from_cdrive_worktree_preparation_simulation_receipt_machine_form,
        to_cdrive_worktree_preparation_simulation_receipt_machine_form,
    },
    workspace_admission::update_broker_protocol::{
        CapabilityKind, FormationAuthority, FormationDisposition,
        from_protocol_request_machine_form, from_protocol_result_machine_form,
        to_protocol_request_machine_form, to_protocol_result_machine_form,
    },
};

pub const PREPARATION_COMMISSION_ADMISSION_REQUEST_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-preparation-commission-admission-request/0.2";
pub const PREPARATION_COMMISSION_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-preparation-commission/0.2";
pub const PREPARATION_COMMISSION_CAPABILITY_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-preparation-commission-capability-account/0.2";
pub const PREPARATION_MUTATION_FENCE_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-preparation-mutation-fence-plan/0.2";
pub const PREPARATION_OPERATOR_AUTHORIZATION_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-preparation-operator-authorization/0.2";
pub const PREPARATION_COMMISSION_UNRESOLVED_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-preparation-commission-unresolved-account/0.2";
pub const PREPARATION_COMMISSION_ADMISSION_RECEIPT_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-preparation-commission-admission-receipt/0.2";
pub const PREPARATION_COMMISSION_ADMISSION_EVIDENCE_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-preparation-commission-admission-evidence/0.2";

pub const PREPARATION_COMMISSION_ADMISSION_SOURCE_SNAPSHOT_UUID: &str =
    "3b3509ee-6d2d-4490-a95a-f57bd6f81ba2";
pub const PREPARATION_COMMISSION_ADMISSION_SIGNATURE_UUID: &str =
    "3617e7ab-52af-402a-98c5-86e025671bd6";
pub const PREPARATION_COMMISSION_ADMISSION_CANONICAL_UUID: &str =
    "c2972c4d-27b3-4cd4-b6eb-c5a74ba6b982";
pub const PREPARATION_COMMISSION_CORRECTION_COMMIT: &str =
    "ebcbc042ae358475717b5fe2ad5816671c830767";
pub const PREPARATION_PUBLISHED_IMPLEMENTATION_COMMIT: &str =
    "7676903ca85d80706100eee1995cb0412a2d4870";
pub const PREPARATION_PUBLISHED_BOOKEND_COMMIT: &str = "17d9c141eedecf06559744df0a14b239bc5473a4";

pub const PREPARATION_COMMISSION_ISSUER: &str = "THEBRAIN\\enjer";
pub const PREPARATION_COMMISSION_SUBJECT: &str = "cantor_b1_cdrive_preparation_production_broker";
pub const PREPARATION_COMMISSION_STAGE: &str = "b1_cdrive_linked_worktree_preparation";
pub const PREPARATION_PRINCIPAL_WORKSPACE: &str = "C:\\Project\\Cantor";
pub const PREPARATION_REPOSITORY_COMMON_DIR: &str = "C:\\Project\\Cantor\\.git";
pub const PREPARATION_WORKTREE_PARENT: &str = "C:\\Project\\CantorWorktrees";
pub const PREPARATION_LEDGER_ROOT: &str = "C:\\Project\\CantorWorktrees\\.cantor-broker";

pub const PREPARATION_FENCE_STEPS: [&str; 10] = [
    "validate_commission",
    "validate_upstream",
    "acquire_exclusive_lease",
    "reobserve_pre_effect_state",
    "create_quarantine_setup",
    "execute_closed_plan",
    "verify_retained_state",
    "publish_outcome",
    "mark_commission_consumed",
    "release_lease",
];

const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_FIELDS: usize = 256;
const MAX_ARTIFACTS: usize = 16;
const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EVIDENCE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MACHINE_FORM_BYTES: usize = 2 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 4096;
const MAX_PATH_BYTES: usize = 1024;

const COMMISSION_DOMAIN: &[u8] =
    b"cantor:self-work-update-broker:b1:cdrive:preparation-commission:0.2";
const CAPABILITY_DOMAIN: &[u8] =
    b"cantor:self-work-update-broker:b1:cdrive:preparation-commission-capability:0.2";
const FENCE_DOMAIN: &[u8] =
    b"cantor:self-work-update-broker:b1:cdrive:preparation-mutation-fence:0.2";
const AUTHORIZATION_DOMAIN: &[u8] =
    b"cantor:self-work-update-broker:b1:cdrive:preparation-operator-authorization:0.2";
const UNRESOLVED_DOMAIN: &[u8] =
    b"cantor:self-work-update-broker:b1:cdrive:preparation-commission-unresolved:0.2";
const REQUEST_DOMAIN: &[u8] =
    b"cantor:self-work-update-broker:b1:cdrive:preparation-commission-admission-request:0.2";
const RECEIPT_DOMAIN: &[u8] =
    b"cantor:self-work-update-broker:b1:cdrive:preparation-commission-admission-receipt:0.2";

const EXACT_ARTIFACT_NAMES: [&str; 10] = [
    "admission_receipt.json",
    "capability_account.json",
    "commission.json",
    "fence_plan.json",
    "operator_authorization.json",
    "preparation_receipt.json",
    "protocol_request.json",
    "protocol_result.json",
    "request.json",
    "unresolved_account.json",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommissionArtifactIdentity {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationCommissionEnvelope {
    pub profile: String,
    pub commission_uuid: String,
    pub correlation_uuid: String,
    pub attempt_uuid: String,
    pub issuer_identity: String,
    pub subject_identity: String,
    pub recovery_owner: String,
    pub stage: String,
    pub operator_authorization_artifact: CommissionArtifactIdentity,
    pub carrier_commit: String,
    pub preparation_implementation_commit: String,
    pub preparation_bookend_commit: String,
    pub expected_current_commit: String,
    pub provider_only_plan_sha256: String,
    pub branch_ref: String,
    pub principal_workspace: String,
    pub repository_common_dir: String,
    pub worktree_parent: String,
    pub ledger_root: String,
    pub scratch_root: String,
    pub candidate_root: String,
    pub evidence_root: String,
    pub temp_root: String,
    pub codex_home: String,
    pub hook_quarantine_root: String,
    pub attribute_quarantine_file: String,
    pub maximum_attempts: u8,
    pub retry_count: u8,
    pub commission_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationCommissionCapabilityAccount {
    pub profile: String,
    pub requested_future_grants: Vec<CapabilityKind>,
    pub explicit_denials: Vec<CapabilityKind>,
    pub requested_grant_count: u8,
    pub explicit_denial_count: u8,
    pub unique_capability_count: u8,
    pub overlap_count: u8,
    pub issued_capability_count: u8,
    pub capability_account_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationMutationFencePlan {
    pub profile: String,
    pub steps: Vec<String>,
    pub declared_step_count: u8,
    pub maximum_step_count: u8,
    pub lease_kind: String,
    pub lease_name: String,
    pub acquisition_wait_millis: u64,
    pub lease_hold_from_step: String,
    pub lease_hold_through_step: String,
    pub ledger_claim_path: String,
    pub ledger_consumed_path: String,
    pub ledger_claim_mode: String,
    pub claim_before_any_effect: bool,
    pub reobserve_after_lease_before_effect: bool,
    pub publish_before_consumption: bool,
    pub consumption_before_release: bool,
    pub no_retry: bool,
    pub no_delete: bool,
    pub no_replace: bool,
    pub no_cleanup: bool,
    pub retain_uncertain_state: bool,
    pub fence_plan_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationOperatorAuthorizationRecord {
    pub profile: String,
    pub authorization_uuid: String,
    pub operator_identity: String,
    pub subject_identity: String,
    pub stage: String,
    pub commission_uuid: String,
    pub externally_issued: bool,
    pub authorization_authenticated: bool,
    pub operator_consent_observed: bool,
    pub authorization_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationCommissionUnresolvedAccount {
    pub profile: String,
    pub items: Vec<String>,
    pub unresolved_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationCommissionAdmissionRequest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub signature_uuid: String,
    pub protocol_request_artifact: CommissionArtifactIdentity,
    pub protocol_result_artifact: CommissionArtifactIdentity,
    pub preparation_receipt_artifact: CommissionArtifactIdentity,
    pub commission_artifact: CommissionArtifactIdentity,
    pub capability_account_artifact: CommissionArtifactIdentity,
    pub fence_plan_artifact: CommissionArtifactIdentity,
    pub operator_authorization_artifact: CommissionArtifactIdentity,
    pub unresolved_account_artifact: CommissionArtifactIdentity,
    pub physical_contact_expected: bool,
    pub request_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationCommissionAdmissionStatus {
    CommissionShapeAdmittedProductionBrokerNotRun,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationCommissionAdmissionAuthority {
    CommissionAdmissionOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationCommissionAdmissionReceipt {
    pub profile: String,
    pub status: PreparationCommissionAdmissionStatus,
    pub authority: PreparationCommissionAdmissionAuthority,
    pub source_snapshot_uuid: String,
    pub signature_uuid: String,
    pub protocol_request_raw_sha256: String,
    pub protocol_result_raw_sha256: String,
    pub preparation_receipt_raw_sha256: String,
    pub request_sha256: String,
    pub commission_sha256: String,
    pub capability_account_sha256: String,
    pub fence_plan_sha256: String,
    pub authorization_sha256: String,
    pub unresolved_sha256: String,
    pub actual_fence_step_count: u8,
    pub declared_fence_step_count: u8,
    pub maximum_fence_step_count: u8,
    pub requested_future_grant_count: u8,
    pub explicit_denial_count: u8,
    pub issued_capability_count: u8,
    pub commission_issued: bool,
    pub authorization_authenticated: bool,
    pub operator_consent_observed: bool,
    pub current_freshness_proved: bool,
    pub external_clock_observed: bool,
    pub exclusive_lease_acquired: bool,
    pub consumption_ledger_claimed: bool,
    pub commission_consumed: bool,
    pub capacity_observed: bool,
    pub physical_execution_authorized: bool,
    pub production_broker_implemented: bool,
    pub production_broker_run: bool,
    pub physical_contact: bool,
    pub may_have_mutated: bool,
    pub retained_state: bool,
    pub process_run_count: u32,
    pub filesystem_write_count: u32,
    pub git_mutation_count: u32,
    pub network_contact_count: u32,
    pub provider_trial_count: u32,
    pub model_turn_count: u32,
    pub mcp_call_count: u32,
    pub phase3a_run_count: u32,
    pub p1_app_server_run_count: u32,
    pub writer_run_count: u32,
    pub commit_count: u32,
    pub push_count: u32,
    pub persistence_count: u32,
    pub activation_count: u32,
    pub d_drive_contact_count: u32,
    pub wsl_compile_count: u32,
    pub wsl_compaction_count: u32,
    pub cleanup_count: u32,
    pub foreign_effect_count: u32,
    pub receipt_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationCommissionAdmissionEvidenceManifest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub artifacts: Vec<CommissionArtifactIdentity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationCommissionAdmissionFaultCode {
    Path,
    Manifest,
    MachineForm,
    Upstream,
    Commission,
    Capability,
    Fence,
    Authority,
    Bound,
    Digest,
    Receipt,
    Determinism,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationCommissionAdmissionFault {
    pub code: PreparationCommissionAdmissionFaultCode,
    pub message: String,
}

impl fmt::Display for PreparationCommissionAdmissionFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for PreparationCommissionAdmissionFault {}

#[allow(clippy::too_many_arguments)]
pub fn compile_preparation_commission_admission(
    protocol_request_bytes: &[u8],
    protocol_result_bytes: &[u8],
    preparation_receipt_bytes: &[u8],
    request: &PreparationCommissionAdmissionRequest,
    commission: &PreparationCommissionEnvelope,
    capabilities: &PreparationCommissionCapabilityAccount,
    fence: &PreparationMutationFencePlan,
    authorization: &PreparationOperatorAuthorizationRecord,
    unresolved: &PreparationCommissionUnresolvedAccount,
) -> Result<PreparationCommissionAdmissionReceipt, PreparationCommissionAdmissionFault> {
    reject_duplicate_json(protocol_request_bytes)?;
    reject_duplicate_json(protocol_result_bytes)?;
    reject_duplicate_json(preparation_receipt_bytes)?;
    validate_request(request)?;
    validate_identity_bytes(
        &request.protocol_request_artifact,
        "protocol_request.json",
        protocol_request_bytes,
    )?;
    validate_identity_bytes(
        &request.protocol_result_artifact,
        "protocol_result.json",
        protocol_result_bytes,
    )?;
    validate_identity_bytes(
        &request.preparation_receipt_artifact,
        "preparation_receipt.json",
        preparation_receipt_bytes,
    )?;
    let commission_bytes = canonical_bytes(commission)?;
    let capability_bytes = canonical_bytes(capabilities)?;
    let fence_bytes = canonical_bytes(fence)?;
    let authorization_bytes = canonical_bytes(authorization)?;
    let unresolved_bytes = canonical_bytes(unresolved)?;
    for (identity, expected_name, bytes) in [
        (
            &request.commission_artifact,
            "commission.json",
            commission_bytes.as_slice(),
        ),
        (
            &request.capability_account_artifact,
            "capability_account.json",
            capability_bytes.as_slice(),
        ),
        (
            &request.fence_plan_artifact,
            "fence_plan.json",
            fence_bytes.as_slice(),
        ),
        (
            &request.operator_authorization_artifact,
            "operator_authorization.json",
            authorization_bytes.as_slice(),
        ),
        (
            &request.unresolved_account_artifact,
            "unresolved_account.json",
            unresolved_bytes.as_slice(),
        ),
    ] {
        validate_identity_bytes(identity, expected_name, bytes)?;
    }

    let protocol_request = from_protocol_request_machine_form(protocol_request_bytes)
        .map_err(|error| upstream_fault(format!("B0 request replay refused: {error}")))?;
    let protocol_result =
        from_protocol_result_machine_form(&protocol_request, protocol_result_bytes)
            .map_err(|error| upstream_fault(format!("B0 result replay refused: {error}")))?;
    let canonical_protocol_request = to_protocol_request_machine_form(&protocol_request)
        .map_err(|error| upstream_fault(format!("B0 request encoding refused: {error}")))?;
    let canonical_protocol_result =
        to_protocol_result_machine_form(&protocol_request, &protocol_result)
            .map_err(|error| upstream_fault(format!("B0 result encoding refused: {error}")))?;
    if canonical_protocol_request != protocol_request_bytes
        || canonical_protocol_result != protocol_result_bytes
    {
        return Err(upstream_fault("B0 raw machine form is not canonical"));
    }
    if protocol_result.authority != FormationAuthority::FormationOnly
        || protocol_result.disposition != FormationDisposition::FormationValidated
        || protocol_result.physical_contact
    {
        return Err(upstream_fault("B0 result authority differs"));
    }

    let preparation_receipt_text = std::str::from_utf8(preparation_receipt_bytes)
        .map_err(|error| machine_fault(error.to_string()))?;
    let preparation_receipt =
        from_cdrive_worktree_preparation_simulation_receipt_machine_form(preparation_receipt_text)
            .map_err(|error| {
                upstream_fault(format!("preparation receipt replay refused: {error}"))
            })?;
    let canonical_preparation_receipt =
        to_cdrive_worktree_preparation_simulation_receipt_machine_form(&preparation_receipt)
            .map_err(|error| {
                upstream_fault(format!("preparation receipt encoding refused: {error}"))
            })?;
    if canonical_preparation_receipt.as_bytes() != preparation_receipt_bytes {
        return Err(upstream_fault(
            "preparation receipt raw machine form is not canonical",
        ));
    }

    validate_commission(commission, &preparation_receipt)?;
    validate_capabilities(capabilities)?;
    validate_fence(fence, commission)?;
    validate_authorization(authorization, commission)?;
    validate_unresolved(unresolved)?;

    if request.operator_authorization_artifact != commission.operator_authorization_artifact {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Commission,
            "commission authorization artifact identity differs",
        ));
    }

    let mut receipt = PreparationCommissionAdmissionReceipt {
        profile: PREPARATION_COMMISSION_ADMISSION_RECEIPT_PROFILE.to_owned(),
        status: PreparationCommissionAdmissionStatus::CommissionShapeAdmittedProductionBrokerNotRun,
        authority: PreparationCommissionAdmissionAuthority::CommissionAdmissionOnly,
        source_snapshot_uuid: PREPARATION_COMMISSION_ADMISSION_SOURCE_SNAPSHOT_UUID.to_owned(),
        signature_uuid: PREPARATION_COMMISSION_ADMISSION_SIGNATURE_UUID.to_owned(),
        protocol_request_raw_sha256: sha256_upper(protocol_request_bytes),
        protocol_result_raw_sha256: sha256_upper(protocol_result_bytes),
        preparation_receipt_raw_sha256: sha256_upper(preparation_receipt_bytes),
        request_sha256: request.request_sha256.clone(),
        commission_sha256: commission.commission_sha256.clone(),
        capability_account_sha256: capabilities.capability_account_sha256.clone(),
        fence_plan_sha256: fence.fence_plan_sha256.clone(),
        authorization_sha256: authorization.authorization_sha256.clone(),
        unresolved_sha256: unresolved.unresolved_sha256.clone(),
        actual_fence_step_count: fence.steps.len() as u8,
        declared_fence_step_count: fence.declared_step_count,
        maximum_fence_step_count: fence.maximum_step_count,
        requested_future_grant_count: capabilities.requested_grant_count,
        explicit_denial_count: capabilities.explicit_denial_count,
        issued_capability_count: 0,
        commission_issued: false,
        authorization_authenticated: false,
        operator_consent_observed: false,
        current_freshness_proved: false,
        external_clock_observed: false,
        exclusive_lease_acquired: false,
        consumption_ledger_claimed: false,
        commission_consumed: false,
        capacity_observed: false,
        physical_execution_authorized: false,
        production_broker_implemented: false,
        production_broker_run: false,
        physical_contact: false,
        may_have_mutated: false,
        retained_state: false,
        process_run_count: 0,
        filesystem_write_count: 0,
        git_mutation_count: 0,
        network_contact_count: 0,
        provider_trial_count: 0,
        model_turn_count: 0,
        mcp_call_count: 0,
        phase3a_run_count: 0,
        p1_app_server_run_count: 0,
        writer_run_count: 0,
        commit_count: 0,
        push_count: 0,
        persistence_count: 0,
        activation_count: 0,
        d_drive_contact_count: 0,
        wsl_compile_count: 0,
        wsl_compaction_count: 0,
        cleanup_count: 0,
        foreign_effect_count: 0,
        receipt_sha256: String::new(),
    };
    receipt.receipt_sha256 = preparation_commission_admission_receipt_digest(&receipt)?;
    validate_receipt_shape(&receipt)?;
    Ok(receipt)
}

pub fn verify_preparation_commission_admission_evidence(
    evidence_root: &Path,
) -> Result<PreparationCommissionAdmissionReceipt, PreparationCommissionAdmissionFault> {
    let canonical_root = fs::canonicalize(evidence_root).map_err(|error| {
        fault_value(
            PreparationCommissionAdmissionFaultCode::Path,
            format!("evidence root canonicalization failed: {error}"),
        )
    })?;
    if !canonical_root.is_dir() {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Path,
            "evidence root is not a directory",
        ));
    }
    let manifest_bytes = read_regular(&canonical_root, "evidence_manifest.json")?;
    let manifest: PreparationCommissionAdmissionEvidenceManifest = parse_strict(&manifest_bytes)?;
    validate_manifest(&manifest)?;
    let mut total = manifest_bytes.len() as u64;
    let mut artifacts = Vec::with_capacity(EXACT_ARTIFACT_NAMES.len());
    for identity in &manifest.artifacts {
        let bytes = read_regular(&canonical_root, &identity.path)?;
        total = total.checked_add(bytes.len() as u64).ok_or_else(|| {
            fault_value(
                PreparationCommissionAdmissionFaultCode::Bound,
                "evidence byte count overflowed",
            )
        })?;
        if total > MAX_EVIDENCE_BYTES
            || identity.bytes != bytes.len() as u64
            || identity.sha256 != sha256_upper(&bytes)
        {
            return Err(fault_value(
                PreparationCommissionAdmissionFaultCode::Manifest,
                format!("artifact identity differs: {}", identity.path),
            ));
        }
        reject_duplicate_json(&bytes)?;
        artifacts.push((identity.path.as_str(), bytes));
    }

    let request_bytes = artifact(&artifacts, "request.json")?;
    let commission_bytes = artifact(&artifacts, "commission.json")?;
    let capability_bytes = artifact(&artifacts, "capability_account.json")?;
    let fence_bytes = artifact(&artifacts, "fence_plan.json")?;
    let authorization_bytes = artifact(&artifacts, "operator_authorization.json")?;
    let unresolved_bytes = artifact(&artifacts, "unresolved_account.json")?;
    let supplied_receipt_bytes = artifact(&artifacts, "admission_receipt.json")?;

    let request: PreparationCommissionAdmissionRequest = parse_strict(request_bytes)?;
    let commission: PreparationCommissionEnvelope = parse_strict(commission_bytes)?;
    let capabilities: PreparationCommissionCapabilityAccount = parse_strict(capability_bytes)?;
    let fence: PreparationMutationFencePlan = parse_strict(fence_bytes)?;
    let authorization: PreparationOperatorAuthorizationRecord = parse_strict(authorization_bytes)?;
    let unresolved: PreparationCommissionUnresolvedAccount = parse_strict(unresolved_bytes)?;
    let supplied_receipt: PreparationCommissionAdmissionReceipt =
        parse_strict(supplied_receipt_bytes)?;

    for (identity, expected_name, bytes) in [
        (
            &request.commission_artifact,
            "commission.json",
            commission_bytes,
        ),
        (
            &request.capability_account_artifact,
            "capability_account.json",
            capability_bytes,
        ),
        (&request.fence_plan_artifact, "fence_plan.json", fence_bytes),
        (
            &request.operator_authorization_artifact,
            "operator_authorization.json",
            authorization_bytes,
        ),
        (
            &request.unresolved_account_artifact,
            "unresolved_account.json",
            unresolved_bytes,
        ),
    ] {
        validate_identity_bytes(identity, expected_name, bytes)?;
    }

    let first = compile_preparation_commission_admission(
        artifact(&artifacts, "protocol_request.json")?,
        artifact(&artifacts, "protocol_result.json")?,
        artifact(&artifacts, "preparation_receipt.json")?,
        &request,
        &commission,
        &capabilities,
        &fence,
        &authorization,
        &unresolved,
    )?;
    if supplied_receipt != first {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Receipt,
            "supplied admission receipt differs from replay",
        ));
    }
    let second = compile_preparation_commission_admission(
        artifact(&artifacts, "protocol_request.json")?,
        artifact(&artifacts, "protocol_result.json")?,
        artifact(&artifacts, "preparation_receipt.json")?,
        &request,
        &commission,
        &capabilities,
        &fence,
        &authorization,
        &unresolved,
    )?;
    if first != second
        || to_preparation_commission_admission_receipt_machine_form(&first)?
            != to_preparation_commission_admission_receipt_machine_form(&second)?
    {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Determinism,
            "second admission replay differs",
        ));
    }
    Ok(first)
}

pub fn to_preparation_commission_admission_request_machine_form(
    request: &PreparationCommissionAdmissionRequest,
) -> Result<String, PreparationCommissionAdmissionFault> {
    validate_request(request)?;
    serde_json::to_string(request).map_err(|error| machine_fault(error.to_string()))
}

pub fn from_preparation_commission_admission_request_machine_form(
    machine_form: &str,
) -> Result<PreparationCommissionAdmissionRequest, PreparationCommissionAdmissionFault> {
    let request = parse_strict(machine_form.as_bytes())?;
    validate_request(&request)?;
    Ok(request)
}

pub fn to_preparation_commission_admission_receipt_machine_form(
    receipt: &PreparationCommissionAdmissionReceipt,
) -> Result<String, PreparationCommissionAdmissionFault> {
    validate_receipt_shape(receipt)?;
    serde_json::to_string(receipt).map_err(|error| machine_fault(error.to_string()))
}

pub fn from_preparation_commission_admission_receipt_machine_form(
    machine_form: &str,
) -> Result<PreparationCommissionAdmissionReceipt, PreparationCommissionAdmissionFault> {
    let receipt = parse_strict(machine_form.as_bytes())?;
    validate_receipt_shape(&receipt)?;
    Ok(receipt)
}

pub fn preparation_commission_digest(
    commission: &PreparationCommissionEnvelope,
) -> Result<String, PreparationCommissionAdmissionFault> {
    let mut body = commission.clone();
    body.commission_sha256.clear();
    digest_form(COMMISSION_DOMAIN, &body)
}

pub fn preparation_commission_capability_account_digest(
    account: &PreparationCommissionCapabilityAccount,
) -> Result<String, PreparationCommissionAdmissionFault> {
    let mut body = account.clone();
    body.capability_account_sha256.clear();
    digest_form(CAPABILITY_DOMAIN, &body)
}

pub fn preparation_mutation_fence_digest(
    fence: &PreparationMutationFencePlan,
) -> Result<String, PreparationCommissionAdmissionFault> {
    let mut body = fence.clone();
    body.fence_plan_sha256.clear();
    digest_form(FENCE_DOMAIN, &body)
}

pub fn preparation_operator_authorization_digest(
    authorization: &PreparationOperatorAuthorizationRecord,
) -> Result<String, PreparationCommissionAdmissionFault> {
    let mut body = authorization.clone();
    body.authorization_sha256.clear();
    digest_form(AUTHORIZATION_DOMAIN, &body)
}

pub fn preparation_commission_unresolved_digest(
    unresolved: &PreparationCommissionUnresolvedAccount,
) -> Result<String, PreparationCommissionAdmissionFault> {
    let mut body = unresolved.clone();
    body.unresolved_sha256.clear();
    digest_form(UNRESOLVED_DOMAIN, &body)
}

pub fn preparation_commission_admission_request_digest(
    request: &PreparationCommissionAdmissionRequest,
) -> Result<String, PreparationCommissionAdmissionFault> {
    let mut body = request.clone();
    body.request_sha256.clear();
    digest_form(REQUEST_DOMAIN, &body)
}

pub fn preparation_commission_admission_receipt_digest(
    receipt: &PreparationCommissionAdmissionReceipt,
) -> Result<String, PreparationCommissionAdmissionFault> {
    let mut body = receipt.clone();
    body.receipt_sha256.clear();
    digest_form(RECEIPT_DOMAIN, &body)
}

pub fn expected_preparation_commission_scratch_root(
    commission_uuid: &str,
) -> Result<String, PreparationCommissionAdmissionFault> {
    let token = commission_token(commission_uuid)?;
    Ok(format!(
        "{PREPARATION_WORKTREE_PARENT}\\swa05_b1_cdrive_preflight_{token}"
    ))
}

pub fn expected_preparation_commission_branch_ref(
    commission_uuid: &str,
) -> Result<String, PreparationCommissionAdmissionFault> {
    let token = commission_token(commission_uuid)?;
    Ok(format!(
        "refs/heads/codex/swa05-b1-cdrive-preflight-{token}"
    ))
}

pub fn expected_preparation_commission_lease_name(
    commission_uuid: &str,
) -> Result<String, PreparationCommissionAdmissionFault> {
    if !is_uuid(commission_uuid) {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Commission,
            "commission UUID is not canonical",
        ));
    }
    let common_digest = sha256_upper(PREPARATION_REPOSITORY_COMMON_DIR.as_bytes());
    Ok(format!(
        "Global\\Cantor.SWA05.B1.CDrive.{}.{commission_uuid}",
        &common_digest[..16]
    ))
}

pub fn exact_preparation_requested_future_grants() -> Vec<CapabilityKind> {
    use CapabilityKind::*;
    vec![
        ReadObservation,
        EvidenceRootWrite,
        CandidateMutation,
        ProcessLaunch,
        ProcessInterrupt,
        ProcessTerminate,
        GitHistory,
    ]
}

pub fn exact_preparation_explicit_denials() -> Vec<CapabilityKind> {
    use CapabilityKind::*;
    vec![
        SupervisorTest,
        IndependentReview,
        RollbackAttempt,
        Cleanup,
        Commit,
        Push,
        Provider,
        SopAuthorship,
        SemanticSignature,
        Activation,
        Persistence,
        Remote,
        Fpga,
        Minecraft,
        PrincipalWorkspaceMutation,
    ]
}

pub fn exact_preparation_commission_unresolved_items() -> Vec<String> {
    [
        "authentic_commission_issuance",
        "operator_consent",
        "current_clock",
        "exclusive_lease",
        "consumption_ledger",
        "production_broker",
        "capacity_restoration",
        "physical_preparation",
        "phase3a_acquisition",
        "p1_app_server",
        "swa06b_independent_review",
        "succeeding_sop_persistence",
        "activation",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn validate_commission(
    commission: &PreparationCommissionEnvelope,
    preparation_receipt: &PreparationSimulationReceipt,
) -> Result<(), PreparationCommissionAdmissionFault> {
    let ids = [
        commission.commission_uuid.as_str(),
        commission.correlation_uuid.as_str(),
        commission.attempt_uuid.as_str(),
    ];
    if ids.iter().any(|value| !is_uuid(value))
        || ids.iter().collect::<HashSet<_>>().len() != ids.len()
        || ids.iter().any(|value| is_nil_uuid(value))
    {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Commission,
            "commission UUID account differs",
        ));
    }
    let scratch = expected_preparation_commission_scratch_root(&commission.commission_uuid)?;
    let exact = commission.profile == PREPARATION_COMMISSION_PROFILE
        && commission.issuer_identity == PREPARATION_COMMISSION_ISSUER
        && commission.recovery_owner == PREPARATION_COMMISSION_ISSUER
        && commission.subject_identity == PREPARATION_COMMISSION_SUBJECT
        && commission.subject_identity != commission.issuer_identity
        && commission.stage == PREPARATION_COMMISSION_STAGE
        && commission.carrier_commit == preparation_receipt.carrier_commit
        && commission.preparation_implementation_commit
            == PREPARATION_PUBLISHED_IMPLEMENTATION_COMMIT
        && commission.preparation_bookend_commit == PREPARATION_PUBLISHED_BOOKEND_COMMIT
        && commission.expected_current_commit == preparation_receipt.expected_current_commit
        && is_lower_commit(&commission.expected_current_commit)
        && commission.expected_current_commit != commission.preparation_implementation_commit
        && commission.expected_current_commit != commission.preparation_bookend_commit
        && preparation_receipt.plan_sha256.algorithm == "sha256"
        && commission.provider_only_plan_sha256
            == preparation_receipt.plan_sha256.value.to_ascii_uppercase()
        && is_upper_sha256(&commission.provider_only_plan_sha256)
        && commission.branch_ref
            == expected_preparation_commission_branch_ref(&commission.commission_uuid)?
        && commission.principal_workspace == PREPARATION_PRINCIPAL_WORKSPACE
        && commission.repository_common_dir == PREPARATION_REPOSITORY_COMMON_DIR
        && commission.worktree_parent == PREPARATION_WORKTREE_PARENT
        && commission.ledger_root == PREPARATION_LEDGER_ROOT
        && commission.scratch_root == scratch
        && commission.candidate_root == format!("{scratch}\\candidate")
        && commission.evidence_root == format!("{scratch}\\evidence")
        && commission.temp_root == format!("{scratch}\\temp")
        && commission.codex_home == format!("{scratch}\\codex-home")
        && commission.hook_quarantine_root == format!("{scratch}\\hook-quarantine")
        && commission.attribute_quarantine_file == format!("{scratch}\\attribute-quarantine")
        && commission.maximum_attempts == 1
        && commission.retry_count == 0
        && validate_identity_shape(
            &commission.operator_authorization_artifact,
            "operator_authorization.json",
        )
        .is_ok()
        && commission.commission_sha256 == preparation_commission_digest(commission)?;
    if !exact {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Commission,
            "commission envelope differs from exact scope",
        ));
    }
    Ok(())
}

fn validate_capabilities(
    account: &PreparationCommissionCapabilityAccount,
) -> Result<(), PreparationCommissionAdmissionFault> {
    let grants = exact_preparation_requested_future_grants();
    let denials = exact_preparation_explicit_denials();
    let granted_set = grants.iter().copied().collect::<HashSet<_>>();
    let denied_set = denials.iter().copied().collect::<HashSet<_>>();
    let unique = granted_set
        .union(&denied_set)
        .copied()
        .collect::<HashSet<_>>();
    let overlap = granted_set.intersection(&denied_set).count();
    let exact = account.profile == PREPARATION_COMMISSION_CAPABILITY_PROFILE
        && account.requested_future_grants == grants
        && account.explicit_denials == denials
        && account.requested_grant_count == 7
        && account.explicit_denial_count == 15
        && account.unique_capability_count == 22
        && account.overlap_count == 0
        && account.issued_capability_count == 0
        && unique.len() == 22
        && overlap == 0
        && account.capability_account_sha256
            == preparation_commission_capability_account_digest(account)?;
    if !exact {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Capability,
            "future capability partition differs",
        ));
    }
    Ok(())
}

fn validate_fence(
    fence: &PreparationMutationFencePlan,
    commission: &PreparationCommissionEnvelope,
) -> Result<(), PreparationCommissionAdmissionFault> {
    let steps = PREPARATION_FENCE_STEPS
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let claim = format!(
        "{}\\commissions\\{}.claimed.json",
        PREPARATION_LEDGER_ROOT, commission.commission_uuid
    );
    let consumed = format!(
        "{}\\commissions\\{}.consumed.json",
        PREPARATION_LEDGER_ROOT, commission.commission_uuid
    );
    let exact = fence.profile == PREPARATION_MUTATION_FENCE_PROFILE
        && fence.steps == steps
        && fence.steps.len() == 10
        && fence.steps.iter().collect::<HashSet<_>>().len() == 10
        && fence.declared_step_count == 10
        && fence.maximum_step_count == 10
        && usize::from(fence.declared_step_count) == fence.steps.len()
        && fence.lease_kind == "windows_named_mutex"
        && fence.lease_name
            == expected_preparation_commission_lease_name(&commission.commission_uuid)?
        && fence.acquisition_wait_millis == 0
        && fence.lease_hold_from_step == "acquire_exclusive_lease"
        && fence.lease_hold_through_step == "mark_commission_consumed"
        && fence.ledger_claim_path == claim
        && fence.ledger_consumed_path == consumed
        && fence.ledger_claim_mode == "create_new"
        && fence.claim_before_any_effect
        && fence.reobserve_after_lease_before_effect
        && fence.publish_before_consumption
        && fence.consumption_before_release
        && fence.no_retry
        && fence.no_delete
        && fence.no_replace
        && fence.no_cleanup
        && fence.retain_uncertain_state
        && fence.fence_plan_sha256 == preparation_mutation_fence_digest(fence)?;
    if !exact {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Fence,
            "ten-step mutation fence differs",
        ));
    }
    Ok(())
}

fn validate_authorization(
    authorization: &PreparationOperatorAuthorizationRecord,
    commission: &PreparationCommissionEnvelope,
) -> Result<(), PreparationCommissionAdmissionFault> {
    let exact = authorization.profile == PREPARATION_OPERATOR_AUTHORIZATION_PROFILE
        && is_uuid(&authorization.authorization_uuid)
        && !is_nil_uuid(&authorization.authorization_uuid)
        && authorization.authorization_uuid != commission.commission_uuid
        && authorization.authorization_uuid != commission.correlation_uuid
        && authorization.authorization_uuid != commission.attempt_uuid
        && authorization.operator_identity == commission.issuer_identity
        && authorization.subject_identity == commission.subject_identity
        && authorization.stage == commission.stage
        && authorization.commission_uuid == commission.commission_uuid
        && !authorization.externally_issued
        && !authorization.authorization_authenticated
        && !authorization.operator_consent_observed
        && authorization.authorization_sha256
            == preparation_operator_authorization_digest(authorization)?;
    if !exact {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Authority,
            "supplied operator authorization nonauthority record differs",
        ));
    }
    Ok(())
}

fn validate_unresolved(
    unresolved: &PreparationCommissionUnresolvedAccount,
) -> Result<(), PreparationCommissionAdmissionFault> {
    if unresolved.profile != PREPARATION_COMMISSION_UNRESOLVED_PROFILE
        || unresolved.items != exact_preparation_commission_unresolved_items()
        || unresolved.unresolved_sha256 != preparation_commission_unresolved_digest(unresolved)?
    {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Authority,
            "unresolved production-broker account differs",
        ));
    }
    Ok(())
}

fn validate_request(
    request: &PreparationCommissionAdmissionRequest,
) -> Result<(), PreparationCommissionAdmissionFault> {
    let identities = [
        (&request.protocol_request_artifact, "protocol_request.json"),
        (&request.protocol_result_artifact, "protocol_result.json"),
        (
            &request.preparation_receipt_artifact,
            "preparation_receipt.json",
        ),
        (&request.commission_artifact, "commission.json"),
        (
            &request.capability_account_artifact,
            "capability_account.json",
        ),
        (&request.fence_plan_artifact, "fence_plan.json"),
        (
            &request.operator_authorization_artifact,
            "operator_authorization.json",
        ),
        (
            &request.unresolved_account_artifact,
            "unresolved_account.json",
        ),
    ];
    for (identity, expected) in identities {
        validate_identity_shape(identity, expected)?;
    }
    let unique = identities
        .iter()
        .map(|(identity, _)| identity.path.as_str())
        .collect::<HashSet<_>>();
    if request.profile != PREPARATION_COMMISSION_ADMISSION_REQUEST_PROFILE
        || request.source_snapshot_uuid != PREPARATION_COMMISSION_ADMISSION_SOURCE_SNAPSHOT_UUID
        || request.signature_uuid != PREPARATION_COMMISSION_ADMISSION_SIGNATURE_UUID
        || request.physical_contact_expected
        || unique.len() != identities.len()
        || request.request_sha256 != preparation_commission_admission_request_digest(request)?
    {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Authority,
            "admission request generation authority or digest differs",
        ));
    }
    Ok(())
}

fn validate_receipt_shape(
    receipt: &PreparationCommissionAdmissionReceipt,
) -> Result<(), PreparationCommissionAdmissionFault> {
    for digest in [
        &receipt.protocol_request_raw_sha256,
        &receipt.protocol_result_raw_sha256,
        &receipt.preparation_receipt_raw_sha256,
        &receipt.request_sha256,
        &receipt.commission_sha256,
        &receipt.capability_account_sha256,
        &receipt.fence_plan_sha256,
        &receipt.authorization_sha256,
        &receipt.unresolved_sha256,
        &receipt.receipt_sha256,
    ] {
        if !is_upper_sha256(digest) {
            return Err(fault_value(
                PreparationCommissionAdmissionFaultCode::Digest,
                "receipt digest is not canonical uppercase SHA256",
            ));
        }
    }
    let false_flags = [
        receipt.commission_issued,
        receipt.authorization_authenticated,
        receipt.operator_consent_observed,
        receipt.current_freshness_proved,
        receipt.external_clock_observed,
        receipt.exclusive_lease_acquired,
        receipt.consumption_ledger_claimed,
        receipt.commission_consumed,
        receipt.capacity_observed,
        receipt.physical_execution_authorized,
        receipt.production_broker_implemented,
        receipt.production_broker_run,
        receipt.physical_contact,
        receipt.may_have_mutated,
        receipt.retained_state,
    ];
    let zero_counts = [
        receipt.process_run_count,
        receipt.filesystem_write_count,
        receipt.git_mutation_count,
        receipt.network_contact_count,
        receipt.provider_trial_count,
        receipt.model_turn_count,
        receipt.mcp_call_count,
        receipt.phase3a_run_count,
        receipt.p1_app_server_run_count,
        receipt.writer_run_count,
        receipt.commit_count,
        receipt.push_count,
        receipt.persistence_count,
        receipt.activation_count,
        receipt.d_drive_contact_count,
        receipt.wsl_compile_count,
        receipt.wsl_compaction_count,
        receipt.cleanup_count,
        receipt.foreign_effect_count,
    ];
    let exact = receipt.profile == PREPARATION_COMMISSION_ADMISSION_RECEIPT_PROFILE
        && receipt.status
            == PreparationCommissionAdmissionStatus::CommissionShapeAdmittedProductionBrokerNotRun
        && receipt.authority == PreparationCommissionAdmissionAuthority::CommissionAdmissionOnly
        && receipt.source_snapshot_uuid == PREPARATION_COMMISSION_ADMISSION_SOURCE_SNAPSHOT_UUID
        && receipt.signature_uuid == PREPARATION_COMMISSION_ADMISSION_SIGNATURE_UUID
        && receipt.actual_fence_step_count == 10
        && receipt.declared_fence_step_count == 10
        && receipt.maximum_fence_step_count == 10
        && receipt.requested_future_grant_count == 7
        && receipt.explicit_denial_count == 15
        && receipt.issued_capability_count == 0
        && false_flags.iter().all(|value| !value)
        && zero_counts.iter().all(|value| *value == 0)
        && receipt.receipt_sha256 == preparation_commission_admission_receipt_digest(receipt)?;
    if !exact {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Receipt,
            "pure admission receipt authority or effect account differs",
        ));
    }
    Ok(())
}

fn validate_manifest(
    manifest: &PreparationCommissionAdmissionEvidenceManifest,
) -> Result<(), PreparationCommissionAdmissionFault> {
    if manifest.profile != PREPARATION_COMMISSION_ADMISSION_EVIDENCE_PROFILE
        || manifest.source_snapshot_uuid != PREPARATION_COMMISSION_ADMISSION_SOURCE_SNAPSHOT_UUID
        || manifest.artifacts.len() != EXACT_ARTIFACT_NAMES.len()
        || manifest.artifacts.len() > MAX_ARTIFACTS
    {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Manifest,
            "evidence manifest profile or artifact count differs",
        ));
    }
    let actual = manifest
        .artifacts
        .iter()
        .map(|identity| identity.path.as_str())
        .collect::<Vec<_>>();
    if actual != EXACT_ARTIFACT_NAMES
        || actual.iter().copied().collect::<HashSet<_>>().len() != actual.len()
    {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Manifest,
            "evidence artifact order or uniqueness differs",
        ));
    }
    for (identity, expected) in manifest.artifacts.iter().zip(EXACT_ARTIFACT_NAMES) {
        validate_identity_shape(identity, expected)?;
    }
    Ok(())
}

fn validate_identity_shape(
    identity: &CommissionArtifactIdentity,
    expected_name: &str,
) -> Result<(), PreparationCommissionAdmissionFault> {
    if identity.path != expected_name
        || !is_safe_relative_path(&identity.path)
        || identity.bytes == 0
        || identity.bytes > MAX_ARTIFACT_BYTES
        || !is_upper_sha256(&identity.sha256)
    {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Manifest,
            format!("artifact identity differs: {expected_name}"),
        ));
    }
    Ok(())
}

fn validate_identity_bytes(
    identity: &CommissionArtifactIdentity,
    expected_name: &str,
    bytes: &[u8],
) -> Result<(), PreparationCommissionAdmissionFault> {
    validate_identity_shape(identity, expected_name)?;
    if identity.bytes != bytes.len() as u64 || identity.sha256 != sha256_upper(bytes) {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Manifest,
            format!("raw artifact identity differs: {expected_name}"),
        ));
    }
    Ok(())
}

fn read_regular(root: &Path, name: &str) -> Result<Vec<u8>, PreparationCommissionAdmissionFault> {
    if !is_simple_name(name) {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Path,
            format!("artifact name is not simple: {name}"),
        ));
    }
    let path = root.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        fault_value(
            PreparationCommissionAdmissionFaultCode::Path,
            format!("artifact metadata failed for {name}: {error}"),
        )
    })?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_ARTIFACT_BYTES
    {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Path,
            format!("artifact is not one bounded regular file: {name}"),
        ));
    }
    let canonical = fs::canonicalize(&path).map_err(|error| {
        fault_value(
            PreparationCommissionAdmissionFaultCode::Path,
            format!("artifact canonicalization failed for {name}: {error}"),
        )
    })?;
    if canonical.parent() != Some(root) {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Path,
            format!("artifact escapes evidence root: {name}"),
        ));
    }
    fs::read(&canonical).map_err(|error| {
        fault_value(
            PreparationCommissionAdmissionFaultCode::Path,
            format!("artifact read failed for {name}: {error}"),
        )
    })
}

fn artifact<'a>(
    artifacts: &'a [(&str, Vec<u8>)],
    name: &str,
) -> Result<&'a [u8], PreparationCommissionAdmissionFault> {
    artifacts
        .iter()
        .find_map(|(candidate, bytes)| (*candidate == name).then_some(bytes.as_slice()))
        .ok_or_else(|| {
            fault_value(
                PreparationCommissionAdmissionFaultCode::Manifest,
                format!("artifact absent: {name}"),
            )
        })
}

fn parse_strict<T: DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, PreparationCommissionAdmissionFault> {
    if bytes.len() > MAX_MACHINE_FORM_BYTES {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Bound,
            "machine form byte bound exceeded",
        ));
    }
    reject_duplicate_json(bytes)?;
    serde_json::from_slice(bytes).map_err(|error| machine_fault(error.to_string()))
}

fn reject_duplicate_json(bytes: &[u8]) -> Result<(), PreparationCommissionAdmissionFault> {
    if bytes.len() > MAX_MACHINE_FORM_BYTES {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Bound,
            "machine form byte bound exceeded",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    StrictSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|error| machine_fault(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| machine_fault(error.to_string()))
}

#[derive(Debug)]
struct StrictValue;

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictSeed { depth: 0 }.deserialize(deserializer)
    }
}

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

fn digest_form<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
) -> Result<String, PreparationCommissionAdmissionFault> {
    let bytes = serde_json::to_vec(value).map_err(|error| machine_fault(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(bytes);
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect())
}

fn canonical_bytes<T: Serialize + ?Sized>(
    value: &T,
) -> Result<Vec<u8>, PreparationCommissionAdmissionFault> {
    serde_json::to_vec(value).map_err(|error| machine_fault(error.to_string()))
}

fn sha256_upper(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

fn commission_token(commission_uuid: &str) -> Result<&str, PreparationCommissionAdmissionFault> {
    if !is_uuid(commission_uuid) || is_nil_uuid(commission_uuid) {
        return Err(fault_value(
            PreparationCommissionAdmissionFaultCode::Commission,
            "commission UUID is not canonical",
        ));
    }
    Ok(&commission_uuid[..8])
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn is_nil_uuid(value: &str) -> bool {
    value == "00000000-0000-0000-0000-000000000000"
}

fn is_upper_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
}

fn is_lower_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
        && value.len() <= MAX_PATH_BYTES
        && !value.contains(['\\', ':'])
        && !value.starts_with('/')
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn machine_fault(message: impl Into<String>) -> PreparationCommissionAdmissionFault {
    fault_value(
        PreparationCommissionAdmissionFaultCode::MachineForm,
        message,
    )
}

fn upstream_fault(message: impl Into<String>) -> PreparationCommissionAdmissionFault {
    fault_value(PreparationCommissionAdmissionFaultCode::Upstream, message)
}

fn fault_value(
    code: PreparationCommissionAdmissionFaultCode,
    message: impl Into<String>,
) -> PreparationCommissionAdmissionFault {
    let mut message = message.into();
    if message.len() > MAX_TEXT_BYTES {
        message.truncate(MAX_TEXT_BYTES);
    }
    PreparationCommissionAdmissionFault { code, message }
}
