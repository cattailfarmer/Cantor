//! Pure supplied-data plan for later B1 C-drive production preparation.
//!
//! This module validates and compiles an exact preparation plan. It never
//! observes or follows the declared paths and cannot perform a preparation.

use std::fmt;

use cantor_core::{ContentDigest, sha256_bytes};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

pub const B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_REQUEST_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-production-preparation-plan-request/0.1";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-production-preparation-plan/0.1";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_STATUS: &str =
    "production_preparation_plan_verified_physical_preparation_not_authorized";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_AUTHORITY: &str = "supplied_data_plan_only";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_SOURCE_SNAPSHOT_UUID: &str =
    "4b141945-a4f3-4621-b4ec-fc4cfacbe680";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_CANONICAL_UUID: &str =
    "209c5c94-fd65-4f93-946b-bec56912b29e";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_SIGNATURE_UUID: &str =
    "0d6c9fe8-14a3-4e2e-9d73-ee5e002612b3";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_SOURCE_CUSTODY_COMMIT: &str =
    "0b4b3ad3ba1584be00d21d07120bba4f0dd0ae38";
pub const B1_CDRIVE_PRODUCTION_BROKER_IMPLEMENTATION_COMMIT: &str =
    "69a2b957971f7188e845e6fd67ebcc17c7920726";
pub const B1_CDRIVE_PRODUCTION_BROKER_BOOKEND_COMMIT: &str =
    "49af9aa11db6696a95a13fead653c5edc1253f0d";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_FORMATION_COMMIT: &str =
    "bb983954c291a58826b05b494251ed8169c52609";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_MINIMUM_FREE_BYTES: u64 = 15_032_385_536;
pub const B1_CDRIVE_PRODUCTION_PREPARATION_OBSERVED_FREE_BYTES: u64 = 43_004_325_888;
pub const B1_CDRIVE_PRODUCTION_PREPARATION_LEDGER_BYTES: usize = 512;
pub const B1_CDRIVE_PRODUCTION_PREPARATION_MAX_MACHINE_FORM_BYTES: usize = 1_048_576;

const REQUEST_DOMAIN: &str = "cantor.b1.cdrive.production-preparation-plan.request.v1";
const PLAN_DOMAIN: &str = "cantor.b1.cdrive.production-preparation-plan.v1";
const LEDGER_PREFIX: &[u8] = b"CANTOR_B1_CDRIVE_LEDGER_UNCLAIMED_V1\n";
const MAX_JSON_DEPTH: usize = 24;
const MAX_JSON_FIELDS: usize = 256;
const EXACT_BRANCH: &str = "codex/self-hosted-corpus";
const EXACT_REMOTE: &str = "https://github.com/cattailfarmer/Cantor";
const EXACT_PROJECT: &str = r"C:\Project\Cantor";
const SCRATCH_PREFIX: &str = r"C:\Project\CantorWorktrees\swa05_b1_cdrive_preflight_";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDriveProductionPreparationUpstreamRole {
    WorktreePreparation,
    CommissionAdmission,
    P1ProducerPlan,
    ProductionBrokerPublication,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionPreparationUpstreamIdentity {
    pub role: B1CDriveProductionPreparationUpstreamRole,
    pub profile: String,
    pub artifact_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionPreparationBuildJunction {
    pub source: String,
    pub target: String,
    pub junction_verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionPreparationPlanRequest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_custody_commit: String,
    pub production_broker_implementation_commit: String,
    pub production_broker_bookend_commit: String,
    pub expected_current_commit: String,
    pub branch: String,
    pub canonical_remote: String,
    pub working_project: String,
    pub observed_cdrive_free_bytes: u64,
    pub minimum_cdrive_free_bytes: u64,
    pub build_junctions: Vec<B1CDriveProductionPreparationBuildJunction>,
    pub upstream_identities: Vec<B1CDriveProductionPreparationUpstreamIdentity>,
    pub plan_namespace_uuid: String,
    pub provider_available: bool,
    pub request_sha256: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDriveProductionPreparationRoleKind {
    Scratch,
    Candidate,
    Evidence,
    Lease,
    Ledger,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionPreparationRole {
    pub kind: B1CDriveProductionPreparationRoleKind,
    pub path: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDriveProductionPreparationOperationKind {
    ValidateCurrentCarrier,
    ValidateCapacity,
    ValidateBuildJunctions,
    ValidateUpstreamIdentities,
    ReserveAbsentScratchNamespace,
    CreateCandidateWorktree,
    CreateEvidenceRoot,
    CreateLeaseFile,
    CreateUnclaimedFixedLedger,
    AcquireFreshPhase3a,
    EmitPreparedReceipt,
    IndependentReplay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDriveProductionPreparationEffectClass {
    ReadOnly,
    PlannedEffect,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionPreparationOperation {
    pub sequence: u8,
    pub kind: B1CDriveProductionPreparationOperationKind,
    pub effect_class: B1CDriveProductionPreparationEffectClass,
    pub later_authority_required: bool,
    pub prerequisites: Vec<String>,
    pub postconditions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionPreparationEffectAccount {
    pub physical_contact: bool,
    pub process_count: u32,
    pub provider_trial_count: u32,
    pub model_turn_count: u32,
    pub mcp_call_count: u32,
    pub network_contact_count: u32,
    pub writer_run_count: u32,
    pub git_runtime_mutation_count: u32,
    pub publication_count: u32,
    pub persistence_count: u32,
    pub activation_count: u32,
    pub d_drive_runtime_contact_count: u32,
    pub remote_contact_count: u32,
    pub wsl_compile_count: u32,
    pub cleanup_count: u32,
    pub foreign_effect_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionPreparationPlan {
    pub profile: String,
    pub status: String,
    pub authority: String,
    pub request_sha256: ContentDigest,
    pub roles: Vec<B1CDriveProductionPreparationRole>,
    pub operations: Vec<B1CDriveProductionPreparationOperation>,
    pub fixed_ledger_bytes: u32,
    pub unclaimed_ledger_sha256: ContentDigest,
    pub unresolved_authorities: Vec<String>,
    pub effect_account: B1CDriveProductionPreparationEffectAccount,
    pub physical_preparation_authorized: bool,
    pub plan_sha256: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum B1CDriveProductionPreparationFaultCode {
    Bound,
    MachineForm,
    Identity,
    Topology,
    Order,
    Authority,
    Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B1CDriveProductionPreparationFault {
    pub code: B1CDriveProductionPreparationFaultCode,
    pub message: String,
}

impl fmt::Display for B1CDriveProductionPreparationFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for B1CDriveProductionPreparationFault {}

pub fn compile_b1_cdrive_production_preparation_plan(
    request: &B1CDriveProductionPreparationPlanRequest,
) -> Result<B1CDriveProductionPreparationPlan, B1CDriveProductionPreparationFault> {
    validate_b1_cdrive_production_preparation_plan_request(request)?;
    let scratch = format!("{SCRATCH_PREFIX}{}", request.plan_namespace_uuid);
    let mut plan = B1CDriveProductionPreparationPlan {
        profile: B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_PROFILE.to_owned(),
        status: B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_STATUS.to_owned(),
        authority: B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_AUTHORITY.to_owned(),
        request_sha256: request.request_sha256.clone(),
        roles: vec![
            role(B1CDriveProductionPreparationRoleKind::Scratch, &scratch),
            role(
                B1CDriveProductionPreparationRoleKind::Candidate,
                &format!(r"{scratch}\candidate"),
            ),
            role(
                B1CDriveProductionPreparationRoleKind::Evidence,
                &format!(r"{scratch}\evidence"),
            ),
            role(
                B1CDriveProductionPreparationRoleKind::Lease,
                &format!(r"{scratch}\broker.lease"),
            ),
            role(
                B1CDriveProductionPreparationRoleKind::Ledger,
                &format!(r"{scratch}\consumption.ledger"),
            ),
        ],
        operations: expected_operations(),
        fixed_ledger_bytes: B1_CDRIVE_PRODUCTION_PREPARATION_LEDGER_BYTES as u32,
        unclaimed_ledger_sha256: sha256_bytes(&canonical_b1_cdrive_unclaimed_ledger_bytes()),
        unresolved_authorities: expected_unresolved_authorities(),
        effect_account: B1CDriveProductionPreparationEffectAccount::default(),
        physical_preparation_authorized: false,
        plan_sha256: empty_digest(),
    };
    plan.plan_sha256 = b1_cdrive_production_preparation_plan_digest(&plan)?;
    validate_b1_cdrive_production_preparation_plan(request, &plan)?;
    Ok(plan)
}

pub fn validate_b1_cdrive_production_preparation_plan_request(
    request: &B1CDriveProductionPreparationPlanRequest,
) -> Result<(), B1CDriveProductionPreparationFault> {
    if request.profile != B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_REQUEST_PROFILE
        || request.source_snapshot_uuid != B1_CDRIVE_PRODUCTION_PREPARATION_SOURCE_SNAPSHOT_UUID
        || request.canonical_uuid != B1_CDRIVE_PRODUCTION_PREPARATION_CANONICAL_UUID
        || request.signature_uuid != B1_CDRIVE_PRODUCTION_PREPARATION_SIGNATURE_UUID
        || request.source_custody_commit != B1_CDRIVE_PRODUCTION_PREPARATION_SOURCE_CUSTODY_COMMIT
        || request.production_broker_implementation_commit
            != B1_CDRIVE_PRODUCTION_BROKER_IMPLEMENTATION_COMMIT
        || request.production_broker_bookend_commit != B1_CDRIVE_PRODUCTION_BROKER_BOOKEND_COMMIT
        || request.expected_current_commit != B1_CDRIVE_PRODUCTION_BROKER_BOOKEND_COMMIT
        || request.branch != EXACT_BRANCH
        || request.canonical_remote != EXACT_REMOTE
        || request.working_project != EXACT_PROJECT
        || request.observed_cdrive_free_bytes
            != B1_CDRIVE_PRODUCTION_PREPARATION_OBSERVED_FREE_BYTES
        || request.minimum_cdrive_free_bytes != B1_CDRIVE_PRODUCTION_PREPARATION_MINIMUM_FREE_BYTES
        || request.observed_cdrive_free_bytes < request.minimum_cdrive_free_bytes
        || request.provider_available
        || !is_uuid(&request.plan_namespace_uuid)
        || request.plan_namespace_uuid == request.source_snapshot_uuid
        || request.plan_namespace_uuid == request.canonical_uuid
    {
        return Err(fault(
            B1CDriveProductionPreparationFaultCode::Identity,
            "request identity or supplied observation differs",
        ));
    }
    if request.build_junctions != expected_build_junctions() {
        return Err(fault(
            B1CDriveProductionPreparationFaultCode::Topology,
            "build junction account differs",
        ));
    }
    if request.upstream_identities != expected_upstream_identities() {
        return Err(fault(
            B1CDriveProductionPreparationFaultCode::Identity,
            "upstream identity account differs",
        ));
    }
    if request.request_sha256 != b1_cdrive_production_preparation_request_digest(request)? {
        return Err(fault(
            B1CDriveProductionPreparationFaultCode::Digest,
            "request digest differs",
        ));
    }
    Ok(())
}

pub fn validate_b1_cdrive_production_preparation_plan(
    request: &B1CDriveProductionPreparationPlanRequest,
    plan: &B1CDriveProductionPreparationPlan,
) -> Result<(), B1CDriveProductionPreparationFault> {
    validate_b1_cdrive_production_preparation_plan_request(request)?;
    if plan.profile != B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_PROFILE
        || plan.status != B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_STATUS
        || plan.authority != B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_AUTHORITY
        || plan.request_sha256 != request.request_sha256
        || plan.fixed_ledger_bytes != B1_CDRIVE_PRODUCTION_PREPARATION_LEDGER_BYTES as u32
        || plan.unclaimed_ledger_sha256
            != sha256_bytes(&canonical_b1_cdrive_unclaimed_ledger_bytes())
        || plan.unresolved_authorities != expected_unresolved_authorities()
        || plan.effect_account != B1CDriveProductionPreparationEffectAccount::default()
        || plan.physical_preparation_authorized
    {
        return Err(fault(
            B1CDriveProductionPreparationFaultCode::Authority,
            "plan authority, ledger, or effect truth differs",
        ));
    }
    validate_roles(request, &plan.roles)?;
    if plan.operations != expected_operations() {
        return Err(fault(
            B1CDriveProductionPreparationFaultCode::Order,
            "operation circuit differs",
        ));
    }
    if plan.plan_sha256 != b1_cdrive_production_preparation_plan_digest(plan)? {
        return Err(fault(
            B1CDriveProductionPreparationFaultCode::Digest,
            "plan digest differs",
        ));
    }
    Ok(())
}

pub fn b1_cdrive_production_preparation_request_digest(
    request: &B1CDriveProductionPreparationPlanRequest,
) -> Result<ContentDigest, B1CDriveProductionPreparationFault> {
    let mut normalized = request.clone();
    normalized.request_sha256 = empty_digest();
    domain_digest(REQUEST_DOMAIN, &normalized)
}

pub fn b1_cdrive_production_preparation_plan_digest(
    plan: &B1CDriveProductionPreparationPlan,
) -> Result<ContentDigest, B1CDriveProductionPreparationFault> {
    let mut normalized = plan.clone();
    normalized.plan_sha256 = empty_digest();
    domain_digest(PLAN_DOMAIN, &normalized)
}

pub fn to_b1_cdrive_production_preparation_request_machine_form(
    request: &B1CDriveProductionPreparationPlanRequest,
) -> Result<String, B1CDriveProductionPreparationFault> {
    validate_b1_cdrive_production_preparation_plan_request(request)?;
    serde_json::to_string(request).map_err(machine_fault)
}

pub fn from_b1_cdrive_production_preparation_request_machine_form(
    machine_form: &str,
) -> Result<B1CDriveProductionPreparationPlanRequest, B1CDriveProductionPreparationFault> {
    let request = parse_canonical(machine_form)?;
    validate_b1_cdrive_production_preparation_plan_request(&request)?;
    Ok(request)
}

pub fn to_b1_cdrive_production_preparation_plan_machine_form(
    request: &B1CDriveProductionPreparationPlanRequest,
    plan: &B1CDriveProductionPreparationPlan,
) -> Result<String, B1CDriveProductionPreparationFault> {
    validate_b1_cdrive_production_preparation_plan(request, plan)?;
    serde_json::to_string(plan).map_err(machine_fault)
}

pub fn from_b1_cdrive_production_preparation_plan_machine_form(
    request: &B1CDriveProductionPreparationPlanRequest,
    machine_form: &str,
) -> Result<B1CDriveProductionPreparationPlan, B1CDriveProductionPreparationFault> {
    let plan = parse_canonical(machine_form)?;
    validate_b1_cdrive_production_preparation_plan(request, &plan)?;
    Ok(plan)
}

pub fn canonical_b1_cdrive_unclaimed_ledger_bytes()
-> [u8; B1_CDRIVE_PRODUCTION_PREPARATION_LEDGER_BYTES] {
    let mut bytes = [0_u8; B1_CDRIVE_PRODUCTION_PREPARATION_LEDGER_BYTES];
    bytes[..LEDGER_PREFIX.len()].copy_from_slice(LEDGER_PREFIX);
    bytes
}

pub fn expected_b1_cdrive_production_preparation_unresolved_authorities() -> Vec<String> {
    expected_unresolved_authorities()
}

pub fn expected_b1_cdrive_production_preparation_upstream_identities()
-> Vec<B1CDriveProductionPreparationUpstreamIdentity> {
    expected_upstream_identities()
}

pub fn expected_b1_cdrive_production_preparation_build_junctions()
-> Vec<B1CDriveProductionPreparationBuildJunction> {
    expected_build_junctions()
}

fn expected_build_junctions() -> Vec<B1CDriveProductionPreparationBuildJunction> {
    vec![
        B1CDriveProductionPreparationBuildJunction {
            source: r"C:\Project\Cantor\target".to_owned(),
            target: r"D:\CantorBuilds\cantor-windows-workspace-target".to_owned(),
            junction_verified: true,
        },
        B1CDriveProductionPreparationBuildJunction {
            source: r"C:\Project\Cantor\experiments\llama_tool_reflection\target".to_owned(),
            target: r"D:\CantorBuilds\cantor-llama-tool-reflection-target".to_owned(),
            junction_verified: true,
        },
    ]
}

fn expected_upstream_identities() -> Vec<B1CDriveProductionPreparationUpstreamIdentity> {
    use B1CDriveProductionPreparationUpstreamRole as Role;
    [
        (
            Role::WorktreePreparation,
            "cantor-b1-cdrive-worktree-preparation-publication-proof/0.4",
            "bfb7a25b61b210cbc2236f71089ac92162d76e0bd3e7df819da86da5fc5a6ed1",
        ),
        (
            Role::CommissionAdmission,
            "cantor-b1-cdrive-commission-admission-publication-proof/0.2",
            "00b754518d84f75ccaf0ca87ed05c2711426010d1ab0af9d83329037cb9f6fde",
        ),
        (
            Role::P1ProducerPlan,
            "cantor-b1-cdrive-p1-producer-plan-publication-proof/0.2",
            "00c09ad22d6e1190ac34bfcc9599dedd991db21966fa55e48cdf4e9f1d8081af",
        ),
        (
            Role::ProductionBrokerPublication,
            "cantor-b1-cdrive-production-broker-publication-proof/0.1",
            "fe2838bca616b91c97cc1db67a84326251aee8de83acb1f43a15aabe70fe9fed",
        ),
    ]
    .into_iter()
    .map(
        |(role, profile, value)| B1CDriveProductionPreparationUpstreamIdentity {
            role,
            profile: profile.to_owned(),
            artifact_sha256: ContentDigest {
                algorithm: "sha256".to_owned(),
                value: value.to_owned(),
            },
        },
    )
    .collect()
}

fn expected_operations() -> Vec<B1CDriveProductionPreparationOperation> {
    use B1CDriveProductionPreparationEffectClass as Effect;
    use B1CDriveProductionPreparationOperationKind as Kind;
    let definitions = [
        (
            Kind::ValidateCurrentCarrier,
            Effect::ReadOnly,
            false,
            "published_lineage",
            "carrier_correspondence_planned",
        ),
        (
            Kind::ValidateCapacity,
            Effect::ReadOnly,
            false,
            "capacity_observation",
            "capacity_reacquisition_required",
        ),
        (
            Kind::ValidateBuildJunctions,
            Effect::ReadOnly,
            false,
            "junction_observations",
            "build_outputs_remain_separate",
        ),
        (
            Kind::ValidateUpstreamIdentities,
            Effect::ReadOnly,
            false,
            "four_upstream_identities",
            "upstream_correspondence_planned",
        ),
        (
            Kind::ReserveAbsentScratchNamespace,
            Effect::ReadOnly,
            true,
            "later_absence_observation",
            "scratch_namespace_remains_uncreated",
        ),
        (
            Kind::CreateCandidateWorktree,
            Effect::PlannedEffect,
            true,
            "physical_preparation_commission",
            "candidate_worktree_to_be_created",
        ),
        (
            Kind::CreateEvidenceRoot,
            Effect::PlannedEffect,
            true,
            "physical_preparation_commission",
            "evidence_root_to_be_created",
        ),
        (
            Kind::CreateLeaseFile,
            Effect::PlannedEffect,
            true,
            "physical_preparation_commission",
            "lease_file_to_be_created",
        ),
        (
            Kind::CreateUnclaimedFixedLedger,
            Effect::PlannedEffect,
            true,
            "physical_preparation_commission",
            "unclaimed_ledger_to_be_created",
        ),
        (
            Kind::AcquireFreshPhase3a,
            Effect::PlannedEffect,
            true,
            "physical_preparation_commission",
            "fresh_phase3a_to_be_acquired",
        ),
        (
            Kind::EmitPreparedReceipt,
            Effect::PlannedEffect,
            true,
            "all_physical_postconditions",
            "prepared_receipt_to_be_issued",
        ),
        (
            Kind::IndependentReplay,
            Effect::ReadOnly,
            false,
            "retained_exact_artifacts",
            "byte_identical_replay_required",
        ),
    ];
    definitions
        .into_iter()
        .enumerate()
        .map(
            |(
                index,
                (kind, effect_class, later_authority_required, prerequisite, postcondition),
            )| B1CDriveProductionPreparationOperation {
                sequence: (index + 1) as u8,
                kind,
                effect_class,
                later_authority_required,
                prerequisites: vec![prerequisite.to_owned()],
                postconditions: vec![postcondition.to_owned()],
            },
        )
        .collect()
}

fn expected_unresolved_authorities() -> Vec<String> {
    [
        "physical_preparation_commission",
        "scratch_namespace_creation",
        "candidate_worktree_creation",
        "reserved_ref_creation",
        "evidence_root_creation",
        "lease_file_creation",
        "fixed_ledger_creation",
        "fresh_phase3a_acquisition",
        "prepared_receipt_issuance",
        "production_broker_activation",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn validate_roles(
    request: &B1CDriveProductionPreparationPlanRequest,
    roles: &[B1CDriveProductionPreparationRole],
) -> Result<(), B1CDriveProductionPreparationFault> {
    let scratch = format!("{SCRATCH_PREFIX}{}", request.plan_namespace_uuid);
    let expected = vec![
        role(B1CDriveProductionPreparationRoleKind::Scratch, &scratch),
        role(
            B1CDriveProductionPreparationRoleKind::Candidate,
            &format!(r"{scratch}\candidate"),
        ),
        role(
            B1CDriveProductionPreparationRoleKind::Evidence,
            &format!(r"{scratch}\evidence"),
        ),
        role(
            B1CDriveProductionPreparationRoleKind::Lease,
            &format!(r"{scratch}\broker.lease"),
        ),
        role(
            B1CDriveProductionPreparationRoleKind::Ledger,
            &format!(r"{scratch}\consumption.ledger"),
        ),
    ];
    if roles != expected
        || roles.iter().any(|role| {
            role.path.contains('/') || role.path.contains("..") || !role.path.starts_with(r"C:\")
        })
    {
        return Err(fault(
            B1CDriveProductionPreparationFaultCode::Topology,
            "role topology differs",
        ));
    }
    for (left_index, left) in roles.iter().enumerate().skip(1) {
        for right in roles.iter().skip(left_index + 1) {
            if overlaps(&left.path, &right.path) {
                return Err(fault(
                    B1CDriveProductionPreparationFaultCode::Topology,
                    "child roles overlap",
                ));
            }
        }
    }
    Ok(())
}

fn role(
    kind: B1CDriveProductionPreparationRoleKind,
    path: &str,
) -> B1CDriveProductionPreparationRole {
    B1CDriveProductionPreparationRole {
        kind,
        path: path.to_owned(),
    }
}

fn overlaps(left: &str, right: &str) -> bool {
    let left = left.to_ascii_lowercase();
    let right = right.to_ascii_lowercase();
    left == right
        || left.starts_with(&format!(r"{right}\"))
        || right.starts_with(&format!(r"{left}\"))
}

fn parse_canonical<T: DeserializeOwned + Serialize>(
    machine_form: &str,
) -> Result<T, B1CDriveProductionPreparationFault> {
    if machine_form.is_empty()
        || machine_form.len() > B1_CDRIVE_PRODUCTION_PREPARATION_MAX_MACHINE_FORM_BYTES
    {
        return Err(fault(
            B1CDriveProductionPreparationFaultCode::Bound,
            "machine form byte bound differs",
        ));
    }
    let value: Value = serde_json::from_str(machine_form).map_err(machine_fault)?;
    let mut fields = 0_usize;
    measure_value(&value, 1, &mut fields)?;
    let parsed: T = serde_json::from_str(machine_form).map_err(machine_fault)?;
    if serde_json::to_string(&parsed).map_err(machine_fault)? != machine_form {
        return Err(fault(
            B1CDriveProductionPreparationFaultCode::MachineForm,
            "machine form is not canonical duplicate-free JSON",
        ));
    }
    Ok(parsed)
}

fn measure_value(
    value: &Value,
    depth: usize,
    fields: &mut usize,
) -> Result<(), B1CDriveProductionPreparationFault> {
    if depth > MAX_JSON_DEPTH {
        return Err(fault(
            B1CDriveProductionPreparationFaultCode::Bound,
            "JSON depth exceeds bound",
        ));
    }
    match value {
        Value::Object(map) => {
            *fields = fields.checked_add(map.len()).ok_or_else(|| {
                fault(
                    B1CDriveProductionPreparationFaultCode::Bound,
                    "JSON field count overflowed",
                )
            })?;
            if *fields > MAX_JSON_FIELDS {
                return Err(fault(
                    B1CDriveProductionPreparationFaultCode::Bound,
                    "JSON field count exceeds bound",
                ));
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
) -> Result<ContentDigest, B1CDriveProductionPreparationFault> {
    let payload = serde_json::to_vec(value).map_err(machine_fault)?;
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

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value
            .as_bytes()
            .iter()
            .enumerate()
            .all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => *byte == b'-',
                _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
            })
        && value != "00000000-0000-0000-0000-000000000000"
}

fn fault(
    code: B1CDriveProductionPreparationFaultCode,
    message: impl Into<String>,
) -> B1CDriveProductionPreparationFault {
    B1CDriveProductionPreparationFault {
        code,
        message: message.into(),
    }
}

fn machine_fault(error: impl fmt::Display) -> B1CDriveProductionPreparationFault {
    fault(
        B1CDriveProductionPreparationFaultCode::MachineForm,
        error.to_string(),
    )
}
