//! Pure proposal for a later B1 C-drive production-preparation commission.
//!
//! This module binds the published preparation plan into a reviewable proposal.
//! It cannot authorize, observe, contact, or execute the proposed preparation.

use std::fmt;

use cantor_core::{ContentDigest, sha256_bytes};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{
    B1_CDRIVE_PRODUCTION_BROKER_BOOKEND_COMMIT, B1_CDRIVE_PRODUCTION_BROKER_IMPLEMENTATION_COMMIT,
    B1_CDRIVE_PRODUCTION_PREPARATION_CANONICAL_UUID,
    B1_CDRIVE_PRODUCTION_PREPARATION_MINIMUM_FREE_BYTES,
    B1_CDRIVE_PRODUCTION_PREPARATION_OBSERVED_FREE_BYTES,
    B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_REQUEST_PROFILE,
    B1_CDRIVE_PRODUCTION_PREPARATION_SIGNATURE_UUID,
    B1_CDRIVE_PRODUCTION_PREPARATION_SOURCE_CUSTODY_COMMIT,
    B1_CDRIVE_PRODUCTION_PREPARATION_SOURCE_SNAPSHOT_UUID,
    B1CDriveProductionPreparationEffectAccount, B1CDriveProductionPreparationOperation,
    B1CDriveProductionPreparationPlan, B1CDriveProductionPreparationPlanRequest,
    B1CDriveProductionPreparationRole, b1_cdrive_production_preparation_request_digest,
    compile_b1_cdrive_production_preparation_plan,
    expected_b1_cdrive_production_preparation_build_junctions,
    expected_b1_cdrive_production_preparation_upstream_identities,
};

pub const B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_REQUEST_PROFILE: &str = "cantor-self-work-update-broker-b1-cdrive-production-preparation-commission-proposal-request/0.1";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-production-preparation-commission-proposal/0.1";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_STATUS: &str =
    "production_preparation_commission_proposal_verified_awaiting_external_authorization";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_AUTHORITY: &str = "proposal_only";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SOURCE_SNAPSHOT_UUID: &str =
    "90de0165-97ea-4aca-9410-6d759d58dec6";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_CANONICAL_UUID: &str =
    "d81ead0d-4108-46ac-b739-e1e108cfeb4d";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SIGNATURE_UUID: &str =
    "441a9e09-ce45-4769-8b0a-655a7763a939";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SOURCE_CUSTODY_COMMIT: &str =
    "0735644b5cb43d8b64f0ce139571017cbae9f518";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_IMPLEMENTATION_COMMIT: &str =
    "2ae87673cfd343cc7a4685a5d0ebbdfc37256ea3";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_BOOKEND_COMMIT: &str =
    "1b70fbd46a3bf6c1970d590ec6ec02ddc84d2cde";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_FORMATION_COMMIT: &str =
    "7cde85484074e02f4a44e91c31985acd0a5d3c24";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_UUID: &str =
    "a5822c1d-1613-408e-93b5-34f78bdbd571";
pub const B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_MAX_MACHINE_FORM_BYTES: usize =
    1_048_576;

const REQUEST_DOMAIN: &str =
    "cantor.b1.cdrive.production-preparation-commission-proposal.request.v1";
const PROPOSAL_DOMAIN: &str = "cantor.b1.cdrive.production-preparation-commission-proposal.v1";
const MAX_JSON_DEPTH: usize = 24;
const MAX_JSON_FIELDS: usize = 256;
const EXACT_BRANCH: &str = "codex/self-hosted-corpus";
const EXACT_REMOTE: &str = "https://github.com/cattailfarmer/Cantor";
const EXACT_PROJECT: &str = r"C:\Project\Cantor";
const PLAN_NAMESPACE_UUID: &str = "cf39b696-21e1-41c4-b382-b68606515f89";
const PROPOSED_REF: &str = "refs/heads/codex/swa05-b1-cdrive-production-preparation-cf39b696";
const RECOVERY_OWNER: &str = r"THEBRAIN\enjer";
const PLANNER_REQUEST_DIGEST: &str =
    "1bb8a8e893c7584e40dd51e90f19824ae000ad2080cb01389c0474ca2facaab1";
const PLANNER_PLAN_DIGEST: &str =
    "3971cd71cd55c931b21d9ca5f06fa0249fa4ff475b62f8a5f2ef379d50d876f4";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDriveProductionPreparationPlannerArtifactKind {
    EvidenceManifest,
    Request,
    Plan,
    Verification,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionPreparationPlannerArtifactIdentity {
    pub kind: B1CDriveProductionPreparationPlannerArtifactKind,
    pub path: String,
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionPreparationCommissionProposalRequest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_custody_commit: String,
    pub production_preparation_plan_implementation_commit: String,
    pub production_preparation_plan_bookend_commit: String,
    pub expected_current_commit: String,
    pub branch: String,
    pub canonical_remote: String,
    pub working_project: String,
    pub planner_artifacts: Vec<B1CDriveProductionPreparationPlannerArtifactIdentity>,
    pub proposal_uuid: String,
    pub roles: Vec<B1CDriveProductionPreparationRole>,
    pub proposed_ref: String,
    pub recovery_owner: String,
    pub attempt_ceiling: u8,
    pub retry_ceiling: u8,
    pub automatic_cleanup_ceiling: u8,
    pub request_sha256: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDriveProductionPreparationResponsibilityKind {
    ScratchNamespace,
    CandidateWorktree,
    ReservedRef,
    EvidenceRoot,
    LeaseFile,
    FixedLedger,
    FreshPhase3a,
    PreparedReceipt,
    ProductionBrokerActivation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionPreparationResponsibility {
    pub sequence: u8,
    pub kind: B1CDriveProductionPreparationResponsibilityKind,
    pub ceiling: u8,
    pub actual_count: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDriveProductionPreparationAuthorizationGapKind {
    ExternalOperatorAuthorization,
    PostAuthorizationObservation,
    CurrentCapacityTopologyAdmission,
    PrivateSingleUseExecutionPermit,
    PhysicalPreparationExecution,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDriveProductionPreparationAuthorizationGapStatus {
    Unresolved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionPreparationAuthorizationGap {
    pub sequence: u8,
    pub kind: B1CDriveProductionPreparationAuthorizationGapKind,
    pub status: B1CDriveProductionPreparationAuthorizationGapStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDriveProductionPreparationContactOutcome {
    NotRun,
    Quarantined,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionPreparationQuarantinePolicy {
    pub maximum_attempts: u8,
    pub retry_count: u8,
    pub automatic_cleanup_count: u8,
    pub pre_contact_drift_outcome: B1CDriveProductionPreparationContactOutcome,
    pub pre_contact_retained_state: bool,
    pub pre_contact_created_object_count: u8,
    pub post_contact_ambiguity_outcome: B1CDriveProductionPreparationContactOutcome,
    pub post_contact_retained_state: bool,
    pub recovery_owner: String,
    pub success_receipt_possible: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionPreparationCommissionProposal {
    pub profile: String,
    pub status: String,
    pub authority: String,
    pub proposal_uuid: String,
    pub request_sha256: ContentDigest,
    pub inherited_plan_sha256: ContentDigest,
    pub roles: Vec<B1CDriveProductionPreparationRole>,
    pub operations: Vec<B1CDriveProductionPreparationOperation>,
    pub proposed_ref: String,
    pub responsibilities: Vec<B1CDriveProductionPreparationResponsibility>,
    pub authorization_gaps: Vec<B1CDriveProductionPreparationAuthorizationGap>,
    pub quarantine_policy: B1CDriveProductionPreparationQuarantinePolicy,
    pub effect_account: B1CDriveProductionPreparationEffectAccount,
    pub external_authorization_present: bool,
    pub physical_preparation_authorized: bool,
    pub proposal_sha256: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum B1CDriveProductionPreparationCommissionProposalFaultCode {
    Bound,
    MachineForm,
    Identity,
    Artifact,
    Topology,
    Order,
    Authority,
    Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B1CDriveProductionPreparationCommissionProposalFault {
    pub code: B1CDriveProductionPreparationCommissionProposalFaultCode,
    pub message: String,
}

impl fmt::Display for B1CDriveProductionPreparationCommissionProposalFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for B1CDriveProductionPreparationCommissionProposalFault {}

pub fn canonical_b1_cdrive_production_preparation_commission_proposal_request() -> Result<
    B1CDriveProductionPreparationCommissionProposalRequest,
    B1CDriveProductionPreparationCommissionProposalFault,
> {
    let (_, plan) = expected_published_planner_forms()?;
    let mut request = B1CDriveProductionPreparationCommissionProposalRequest {
        profile: B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_REQUEST_PROFILE.to_owned(),
        source_snapshot_uuid:
            B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_CANONICAL_UUID
            .to_owned(),
        signature_uuid: B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SIGNATURE_UUID
            .to_owned(),
        source_custody_commit:
            B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SOURCE_CUSTODY_COMMIT.to_owned(),
        production_preparation_plan_implementation_commit:
            B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_IMPLEMENTATION_COMMIT.to_owned(),
        production_preparation_plan_bookend_commit:
            B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_BOOKEND_COMMIT.to_owned(),
        expected_current_commit: B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_BOOKEND_COMMIT.to_owned(),
        branch: EXACT_BRANCH.to_owned(),
        canonical_remote: EXACT_REMOTE.to_owned(),
        working_project: EXACT_PROJECT.to_owned(),
        planner_artifacts: expected_planner_artifacts(),
        proposal_uuid: B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_UUID.to_owned(),
        roles: plan.roles,
        proposed_ref: PROPOSED_REF.to_owned(),
        recovery_owner: RECOVERY_OWNER.to_owned(),
        attempt_ceiling: 1,
        retry_ceiling: 0,
        automatic_cleanup_ceiling: 0,
        request_sha256: empty_digest(),
    };
    request.request_sha256 =
        b1_cdrive_production_preparation_commission_proposal_request_digest(&request)?;
    validate_b1_cdrive_production_preparation_commission_proposal_request(&request)?;
    Ok(request)
}

pub fn compile_b1_cdrive_production_preparation_commission_proposal(
    request: &B1CDriveProductionPreparationCommissionProposalRequest,
) -> Result<
    B1CDriveProductionPreparationCommissionProposal,
    B1CDriveProductionPreparationCommissionProposalFault,
> {
    validate_b1_cdrive_production_preparation_commission_proposal_request(request)?;
    let (_, planner) = expected_published_planner_forms()?;
    let mut proposal = B1CDriveProductionPreparationCommissionProposal {
        profile: B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_PROFILE.to_owned(),
        status: B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_STATUS.to_owned(),
        authority: B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_AUTHORITY.to_owned(),
        proposal_uuid: request.proposal_uuid.clone(),
        request_sha256: request.request_sha256.clone(),
        inherited_plan_sha256: planner.plan_sha256,
        roles: request.roles.clone(),
        operations: planner.operations,
        proposed_ref: request.proposed_ref.clone(),
        responsibilities: expected_responsibilities(),
        authorization_gaps: expected_authorization_gaps(),
        quarantine_policy: expected_quarantine_policy(),
        effect_account: B1CDriveProductionPreparationEffectAccount::default(),
        external_authorization_present: false,
        physical_preparation_authorized: false,
        proposal_sha256: empty_digest(),
    };
    proposal.proposal_sha256 =
        b1_cdrive_production_preparation_commission_proposal_digest(&proposal)?;
    validate_b1_cdrive_production_preparation_commission_proposal(request, &proposal)?;
    Ok(proposal)
}

pub fn validate_b1_cdrive_production_preparation_commission_proposal_request(
    request: &B1CDriveProductionPreparationCommissionProposalRequest,
) -> Result<(), B1CDriveProductionPreparationCommissionProposalFault> {
    if request.profile != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_REQUEST_PROFILE
        || request.source_snapshot_uuid
            != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SOURCE_SNAPSHOT_UUID
        || request.canonical_uuid
            != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_CANONICAL_UUID
        || request.signature_uuid
            != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SIGNATURE_UUID
        || request.source_custody_commit
            != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SOURCE_CUSTODY_COMMIT
        || request.production_preparation_plan_implementation_commit
            != B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_IMPLEMENTATION_COMMIT
        || request.production_preparation_plan_bookend_commit
            != B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_BOOKEND_COMMIT
        || request.expected_current_commit != B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_BOOKEND_COMMIT
        || request.branch != EXACT_BRANCH
        || request.canonical_remote != EXACT_REMOTE
        || request.working_project != EXACT_PROJECT
        || request.proposal_uuid != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_UUID
        || !is_uuid(&request.proposal_uuid)
        || request.proposal_uuid == request.source_snapshot_uuid
        || request.proposal_uuid == request.canonical_uuid
        || request.proposal_uuid == request.signature_uuid
        || request.recovery_owner != RECOVERY_OWNER
        || request.attempt_ceiling != 1
        || request.retry_ceiling != 0
        || request.automatic_cleanup_ceiling != 0
    {
        return Err(fault(
            B1CDriveProductionPreparationCommissionProposalFaultCode::Identity,
            "proposal request identity or authority separation differs",
        ));
    }
    if request.planner_artifacts != expected_planner_artifacts() {
        return Err(fault(
            B1CDriveProductionPreparationCommissionProposalFaultCode::Artifact,
            "retained planner artifact identity account differs",
        ));
    }
    let (_, planner) = expected_published_planner_forms()?;
    if request.roles != planner.roles || request.proposed_ref != PROPOSED_REF {
        return Err(fault(
            B1CDriveProductionPreparationCommissionProposalFaultCode::Topology,
            "role or proposed ref coordinate differs",
        ));
    }
    if request.request_sha256
        != b1_cdrive_production_preparation_commission_proposal_request_digest(request)?
    {
        return Err(fault(
            B1CDriveProductionPreparationCommissionProposalFaultCode::Digest,
            "proposal request digest differs",
        ));
    }
    Ok(())
}

pub fn validate_b1_cdrive_production_preparation_commission_proposal(
    request: &B1CDriveProductionPreparationCommissionProposalRequest,
    proposal: &B1CDriveProductionPreparationCommissionProposal,
) -> Result<(), B1CDriveProductionPreparationCommissionProposalFault> {
    validate_b1_cdrive_production_preparation_commission_proposal_request(request)?;
    let (_, planner) = expected_published_planner_forms()?;
    if proposal.profile != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_PROFILE
        || proposal.status != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_STATUS
        || proposal.authority != B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_AUTHORITY
        || proposal.proposal_uuid != request.proposal_uuid
        || proposal.request_sha256 != request.request_sha256
        || proposal.inherited_plan_sha256 != planner.plan_sha256
        || proposal.roles != planner.roles
        || proposal.proposed_ref != PROPOSED_REF
    {
        return Err(fault(
            B1CDriveProductionPreparationCommissionProposalFaultCode::Identity,
            "proposal lineage or coordinate identity differs",
        ));
    }
    if proposal.operations != planner.operations
        || proposal.responsibilities != expected_responsibilities()
        || proposal.authorization_gaps != expected_authorization_gaps()
    {
        return Err(fault(
            B1CDriveProductionPreparationCommissionProposalFaultCode::Order,
            "operation responsibility or authorization-gap circuit differs",
        ));
    }
    if proposal.quarantine_policy != expected_quarantine_policy()
        || proposal.effect_account != B1CDriveProductionPreparationEffectAccount::default()
        || proposal.external_authorization_present
        || proposal.physical_preparation_authorized
    {
        return Err(fault(
            B1CDriveProductionPreparationCommissionProposalFaultCode::Authority,
            "quarantine authorization or zero-effect truth differs",
        ));
    }
    if proposal.proposal_sha256
        != b1_cdrive_production_preparation_commission_proposal_digest(proposal)?
    {
        return Err(fault(
            B1CDriveProductionPreparationCommissionProposalFaultCode::Digest,
            "proposal digest differs",
        ));
    }
    Ok(())
}

pub fn b1_cdrive_production_preparation_commission_proposal_request_digest(
    request: &B1CDriveProductionPreparationCommissionProposalRequest,
) -> Result<ContentDigest, B1CDriveProductionPreparationCommissionProposalFault> {
    let mut normalized = request.clone();
    normalized.request_sha256 = empty_digest();
    domain_digest(REQUEST_DOMAIN, &normalized)
}

pub fn b1_cdrive_production_preparation_commission_proposal_digest(
    proposal: &B1CDriveProductionPreparationCommissionProposal,
) -> Result<ContentDigest, B1CDriveProductionPreparationCommissionProposalFault> {
    let mut normalized = proposal.clone();
    normalized.proposal_sha256 = empty_digest();
    domain_digest(PROPOSAL_DOMAIN, &normalized)
}

pub fn to_b1_cdrive_production_preparation_commission_proposal_request_machine_form(
    request: &B1CDriveProductionPreparationCommissionProposalRequest,
) -> Result<String, B1CDriveProductionPreparationCommissionProposalFault> {
    validate_b1_cdrive_production_preparation_commission_proposal_request(request)?;
    serde_json::to_string(request).map_err(machine_fault)
}

pub fn from_b1_cdrive_production_preparation_commission_proposal_request_machine_form(
    machine_form: &str,
) -> Result<
    B1CDriveProductionPreparationCommissionProposalRequest,
    B1CDriveProductionPreparationCommissionProposalFault,
> {
    let request = parse_canonical(machine_form)?;
    validate_b1_cdrive_production_preparation_commission_proposal_request(&request)?;
    Ok(request)
}

pub fn to_b1_cdrive_production_preparation_commission_proposal_machine_form(
    request: &B1CDriveProductionPreparationCommissionProposalRequest,
    proposal: &B1CDriveProductionPreparationCommissionProposal,
) -> Result<String, B1CDriveProductionPreparationCommissionProposalFault> {
    validate_b1_cdrive_production_preparation_commission_proposal(request, proposal)?;
    serde_json::to_string(proposal).map_err(machine_fault)
}

pub fn from_b1_cdrive_production_preparation_commission_proposal_machine_form(
    request: &B1CDriveProductionPreparationCommissionProposalRequest,
    machine_form: &str,
) -> Result<
    B1CDriveProductionPreparationCommissionProposal,
    B1CDriveProductionPreparationCommissionProposalFault,
> {
    let proposal = parse_canonical(machine_form)?;
    validate_b1_cdrive_production_preparation_commission_proposal(request, &proposal)?;
    Ok(proposal)
}

pub fn expected_b1_cdrive_production_preparation_planner_artifacts()
-> Vec<B1CDriveProductionPreparationPlannerArtifactIdentity> {
    expected_planner_artifacts()
}

pub fn expected_b1_cdrive_production_preparation_responsibilities()
-> Vec<B1CDriveProductionPreparationResponsibility> {
    expected_responsibilities()
}

pub fn expected_b1_cdrive_production_preparation_authorization_gaps()
-> Vec<B1CDriveProductionPreparationAuthorizationGap> {
    expected_authorization_gaps()
}

fn expected_planner_artifacts() -> Vec<B1CDriveProductionPreparationPlannerArtifactIdentity> {
    use B1CDriveProductionPreparationPlannerArtifactKind as Kind;
    let root = "experiments/self_work_update_broker_b1_cdrive_production_preparation_plan_p0/implementation_provider_free_evidence";
    [
        (
            Kind::EvidenceManifest,
            "evidence_manifest.json",
            1243,
            "d99525b59d6c373bfdb3af2d75893e7cdaa822cf0228b006c8c7f0f0f8d12ee0",
        ),
        (
            Kind::Request,
            "request.json",
            2204,
            "2ae9c77d8565b0804481dd7fb7c775f325ffc62928fd3f1f65a9a6232a0fb229",
        ),
        (
            Kind::Plan,
            "plan.json",
            4512,
            "6498c4c705ce226cf2cd389c67357134efa59bcc99c3e8c39e90e73bc73c8f70",
        ),
        (
            Kind::Verification,
            "verification.json",
            1301,
            "c276ce68d3ccd730f6e9529965b15c88e8a90b342af2e955ad8accb5a46bf33b",
        ),
    ]
    .into_iter()
    .map(
        |(kind, name, bytes, value)| B1CDriveProductionPreparationPlannerArtifactIdentity {
            kind,
            path: format!("{root}/{name}"),
            bytes,
            sha256: digest(value),
        },
    )
    .collect()
}

fn expected_responsibilities() -> Vec<B1CDriveProductionPreparationResponsibility> {
    use B1CDriveProductionPreparationResponsibilityKind as Kind;
    [
        Kind::ScratchNamespace,
        Kind::CandidateWorktree,
        Kind::ReservedRef,
        Kind::EvidenceRoot,
        Kind::LeaseFile,
        Kind::FixedLedger,
        Kind::FreshPhase3a,
        Kind::PreparedReceipt,
        Kind::ProductionBrokerActivation,
    ]
    .into_iter()
    .enumerate()
    .map(
        |(index, kind)| B1CDriveProductionPreparationResponsibility {
            sequence: (index + 1) as u8,
            kind,
            ceiling: 1,
            actual_count: 0,
        },
    )
    .collect()
}

fn expected_authorization_gaps() -> Vec<B1CDriveProductionPreparationAuthorizationGap> {
    use B1CDriveProductionPreparationAuthorizationGapKind as Kind;
    [
        Kind::ExternalOperatorAuthorization,
        Kind::PostAuthorizationObservation,
        Kind::CurrentCapacityTopologyAdmission,
        Kind::PrivateSingleUseExecutionPermit,
        Kind::PhysicalPreparationExecution,
    ]
    .into_iter()
    .enumerate()
    .map(
        |(index, kind)| B1CDriveProductionPreparationAuthorizationGap {
            sequence: (index + 1) as u8,
            kind,
            status: B1CDriveProductionPreparationAuthorizationGapStatus::Unresolved,
        },
    )
    .collect()
}

fn expected_quarantine_policy() -> B1CDriveProductionPreparationQuarantinePolicy {
    B1CDriveProductionPreparationQuarantinePolicy {
        maximum_attempts: 1,
        retry_count: 0,
        automatic_cleanup_count: 0,
        pre_contact_drift_outcome: B1CDriveProductionPreparationContactOutcome::NotRun,
        pre_contact_retained_state: false,
        pre_contact_created_object_count: 0,
        post_contact_ambiguity_outcome: B1CDriveProductionPreparationContactOutcome::Quarantined,
        post_contact_retained_state: true,
        recovery_owner: RECOVERY_OWNER.to_owned(),
        success_receipt_possible: false,
    }
}

fn expected_published_planner_forms() -> Result<
    (
        B1CDriveProductionPreparationPlanRequest,
        B1CDriveProductionPreparationPlan,
    ),
    B1CDriveProductionPreparationCommissionProposalFault,
> {
    let mut request = B1CDriveProductionPreparationPlanRequest {
        profile: B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_REQUEST_PROFILE.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_PRODUCTION_PREPARATION_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: B1_CDRIVE_PRODUCTION_PREPARATION_CANONICAL_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_PRODUCTION_PREPARATION_SIGNATURE_UUID.to_owned(),
        source_custody_commit: B1_CDRIVE_PRODUCTION_PREPARATION_SOURCE_CUSTODY_COMMIT.to_owned(),
        production_broker_implementation_commit: B1_CDRIVE_PRODUCTION_BROKER_IMPLEMENTATION_COMMIT
            .to_owned(),
        production_broker_bookend_commit: B1_CDRIVE_PRODUCTION_BROKER_BOOKEND_COMMIT.to_owned(),
        expected_current_commit: B1_CDRIVE_PRODUCTION_BROKER_BOOKEND_COMMIT.to_owned(),
        branch: EXACT_BRANCH.to_owned(),
        canonical_remote: EXACT_REMOTE.to_owned(),
        working_project: EXACT_PROJECT.to_owned(),
        observed_cdrive_free_bytes: B1_CDRIVE_PRODUCTION_PREPARATION_OBSERVED_FREE_BYTES,
        minimum_cdrive_free_bytes: B1_CDRIVE_PRODUCTION_PREPARATION_MINIMUM_FREE_BYTES,
        build_junctions: expected_b1_cdrive_production_preparation_build_junctions(),
        upstream_identities: expected_b1_cdrive_production_preparation_upstream_identities(),
        plan_namespace_uuid: PLAN_NAMESPACE_UUID.to_owned(),
        provider_available: false,
        request_sha256: empty_digest(),
    };
    request.request_sha256 = b1_cdrive_production_preparation_request_digest(&request)
        .map_err(|error| planner_fault("published planner request digest", error))?;
    if request.request_sha256 != digest(PLANNER_REQUEST_DIGEST) {
        return Err(fault(
            B1CDriveProductionPreparationCommissionProposalFaultCode::Artifact,
            "published planner request digest differs",
        ));
    }
    let plan = compile_b1_cdrive_production_preparation_plan(&request)
        .map_err(|error| planner_fault("published planner replay", error))?;
    if plan.plan_sha256 != digest(PLANNER_PLAN_DIGEST) {
        return Err(fault(
            B1CDriveProductionPreparationCommissionProposalFaultCode::Artifact,
            "published planner plan digest differs",
        ));
    }
    Ok((request, plan))
}

fn parse_canonical<T: DeserializeOwned + Serialize>(
    machine_form: &str,
) -> Result<T, B1CDriveProductionPreparationCommissionProposalFault> {
    if machine_form.is_empty()
        || machine_form.len()
            > B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_MAX_MACHINE_FORM_BYTES
    {
        return Err(fault(
            B1CDriveProductionPreparationCommissionProposalFaultCode::Bound,
            "machine form byte bound differs",
        ));
    }
    let value: Value = serde_json::from_str(machine_form).map_err(machine_fault)?;
    let mut fields = 0_usize;
    measure_value(&value, 1, &mut fields)?;
    let parsed: T = serde_json::from_str(machine_form).map_err(machine_fault)?;
    if serde_json::to_string(&parsed).map_err(machine_fault)? != machine_form {
        return Err(fault(
            B1CDriveProductionPreparationCommissionProposalFaultCode::MachineForm,
            "machine form is not canonical duplicate-free JSON",
        ));
    }
    Ok(parsed)
}

fn measure_value(
    value: &Value,
    depth: usize,
    fields: &mut usize,
) -> Result<(), B1CDriveProductionPreparationCommissionProposalFault> {
    if depth > MAX_JSON_DEPTH {
        return Err(fault(
            B1CDriveProductionPreparationCommissionProposalFaultCode::Bound,
            "JSON depth exceeds bound",
        ));
    }
    match value {
        Value::Object(map) => {
            *fields = fields.checked_add(map.len()).ok_or_else(|| {
                fault(
                    B1CDriveProductionPreparationCommissionProposalFaultCode::Bound,
                    "JSON field count overflowed",
                )
            })?;
            if *fields > MAX_JSON_FIELDS {
                return Err(fault(
                    B1CDriveProductionPreparationCommissionProposalFaultCode::Bound,
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
) -> Result<ContentDigest, B1CDriveProductionPreparationCommissionProposalFault> {
    let payload = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + payload.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&payload);
    Ok(sha256_bytes(&bytes))
}

fn digest(value: &str) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: value.to_owned(),
    }
}

fn empty_digest() -> ContentDigest {
    digest("")
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

fn planner_fault(
    context: &str,
    error: impl fmt::Display,
) -> B1CDriveProductionPreparationCommissionProposalFault {
    fault(
        B1CDriveProductionPreparationCommissionProposalFaultCode::Artifact,
        format!("{context} failed: {error}"),
    )
}

fn fault(
    code: B1CDriveProductionPreparationCommissionProposalFaultCode,
    message: impl Into<String>,
) -> B1CDriveProductionPreparationCommissionProposalFault {
    B1CDriveProductionPreparationCommissionProposalFault {
        code,
        message: message.into(),
    }
}

fn machine_fault(error: impl fmt::Display) -> B1CDriveProductionPreparationCommissionProposalFault {
    fault(
        B1CDriveProductionPreparationCommissionProposalFaultCode::MachineForm,
        error.to_string(),
    )
}
