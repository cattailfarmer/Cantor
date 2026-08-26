//! Pure SWA-06B2A succeeding-SOP activation-transaction admission.
//!
//! This module replays an exact SWA-06B1 receipt and verifies supplied plans
//! for later source reacquisition, current-registry comparison, atomic
//! transition, supersession, and rollback. It never observes or writes a file,
//! selects or boots an SOP, executes rollback, or grants physical eligibility.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    ContentDigest, SUCCEEDING_SOP_ACTIVATION_OBLIGATIONS,
    SUCCEEDING_SOP_REVIEW_ADMISSION_RECEIPT_PROFILE, SemanticId,
    SucceedingSopReviewAdmissionReceipt, sha256_bytes,
    validate_succeeding_sop_review_admission_receipt,
};

pub const SUCCEEDING_SOP_ACTIVATION_POLICY_PROFILE: &str =
    "cantor-succeeding-sop-activation-policy/0.1";
pub const SUCCEEDING_SOP_SOURCE_REACQUISITION_PLAN_PROFILE: &str =
    "cantor-succeeding-sop-source-reacquisition-plan/0.1";
pub const SUCCEEDING_SOP_CURRENT_REGISTRY_SNAPSHOT_PROFILE: &str =
    "cantor-succeeding-sop-current-registry-snapshot/0.1";
pub const SUCCEEDING_SOP_REGISTRY_TRANSITION_PLAN_PROFILE: &str =
    "cantor-succeeding-sop-registry-transition-plan/0.1";
pub const SUCCEEDING_SOP_SUPERSESSION_PLAN_PROFILE: &str =
    "cantor-succeeding-sop-supersession-plan/0.1";
pub const SUCCEEDING_SOP_ROLLBACK_PLAN_PROFILE: &str = "cantor-succeeding-sop-rollback-plan/0.1";
pub const SUCCEEDING_SOP_ACTIVATION_TRANSACTION_REQUEST_PROFILE: &str =
    "cantor-succeeding-sop-activation-transaction-request/0.1";
pub const SUCCEEDING_SOP_ACTIVATION_TRANSACTION_RECEIPT_PROFILE: &str =
    "cantor-succeeding-sop-activation-transaction-receipt/0.1";
pub const SUCCEEDING_SOP_ACTIVATION_TRANSACTION_MAX_MACHINE_FORM_BYTES: usize = 16 * 1024 * 1024;
pub const SUCCEEDING_SOP_ACTIVATION_TRANSACTION_NON_AUTHORITY: &str = "Pure verification of a supplied SWA-06B1 review-admission receipt and supplied activation policy, source-reacquisition plan, current-registry snapshot, atomic transition, supersession, and rollback plans. Correspondence proves only internal consistency of supplied data. It does not prove policy governance, operator consent, recovery ownership, semantic truth, source custody, filesystem or boot state, atomicity, durability, or physical eligibility. No filesystem, registry, SOP, workspace, environment, clock, process, network, provider, or model is observed or changed; no source is reacquired or persisted; no SOP is selected, booted, activated, made current, recovered, or rolled back; no update, test, commit, push, remote, FPGA, or Minecraft effect occurs.";

pub const SUCCEEDING_SOP_ACTIVATION_WRITE_PROTOCOL: [&str; 6] = [
    "write_new_file",
    "verify_new_file",
    "flush_new_file",
    "atomically_replace_registry",
    "flush_parent_directory",
    "reopen_and_verify_registry",
];

pub const SUCCEEDING_SOP_ACTIVATION_ROLLBACK_TRIGGERS: [&str; 6] = [
    "boot_validation_failure",
    "operator_abort",
    "persistence_failure",
    "post_write_verification_failure",
    "registry_precondition_mismatch",
    "source_reacquisition_mismatch",
];

pub const SUCCEEDING_SOP_ACTIVATION_TRANSACTION_VERIFIED_CHECKS: [&str; 10] = [
    "activation_policy_shape",
    "atomic_transition_correspondence",
    "authority_denial",
    "current_registry_correspondence",
    "deterministic_digests",
    "duty_separation",
    "rollback_correspondence",
    "source_reacquisition_correspondence",
    "supersession_correspondence",
    "upstream_replay",
];

const POLICY_DOMAIN: &str = "cantor.succeeding-sop-activation.policy.v1";
const SOURCE_PLAN_DOMAIN: &str = "cantor.succeeding-sop-activation.source-plan.v1";
const REGISTRY_SNAPSHOT_DOMAIN: &str = "cantor.succeeding-sop-activation.registry-snapshot.v1";
const TRANSITION_PLAN_DOMAIN: &str = "cantor.succeeding-sop-activation.transition-plan.v1";
const SUPERSESSION_PLAN_DOMAIN: &str = "cantor.succeeding-sop-activation.supersession-plan.v1";
const ROLLBACK_PLAN_DOMAIN: &str = "cantor.succeeding-sop-activation.rollback-plan.v1";
const REQUEST_DOMAIN: &str = "cantor.succeeding-sop-activation.request.v1";
const RECEIPT_DOMAIN: &str = "cantor.succeeding-sop-activation.receipt.v1";
const MAX_EVIDENCE_REFS: usize = 32;
const MAX_PATH_BYTES: usize = 1024;
const MAX_REASON_BYTES: usize = 512;

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopActivationPolicyUseStatus {
    ExternallyGoverned,
    SyntheticFixtureOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopSourceAcquisitionMode {
    ExactRawBytesReopenNoFollow,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopRegistryAtomicity {
    SameVolumeReplaceRequired,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopRegistryDurability {
    FileAndParentFlushRequired,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopActivationTransactionStatus {
    TransactionCorrespondenceVerifiedAwaitingPhysicalExecution,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopActivationTransactionAuthority {
    SuppliedActivationPlanCorrespondenceOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopActivationPolicy {
    pub profile: String,
    pub use_status: SucceedingSopActivationPolicyUseStatus,
    pub policy_ref: SemanticId,
    pub activation_authority_ref: SemanticId,
    pub recovery_owner_ref: SemanticId,
    pub registry_ref: SemanticId,
    pub allowed_review_receipt_profile: String,
    pub required_acquisition_mode: SucceedingSopSourceAcquisitionMode,
    pub required_atomicity: SucceedingSopRegistryAtomicity,
    pub required_durability: SucceedingSopRegistryDurability,
    pub governance_evidence_refs: BTreeSet<SemanticId>,
    pub non_authority: String,
    pub policy_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopSourceReacquisitionPlan {
    pub profile: String,
    pub plan_ref: SemanticId,
    pub repository_root_ref: SemanticId,
    pub preservation_ref: SemanticId,
    pub source_snapshot_ref: SemanticId,
    pub source_path: String,
    pub source_subject: String,
    pub source_sha256: ContentDigest,
    pub source_bytes: u64,
    pub proposal_digest: ContentDigest,
    pub immutable_required: bool,
    pub no_normalization: bool,
    pub acquisition_mode: SucceedingSopSourceAcquisitionMode,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub plan_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopCurrentRegistrySnapshot {
    pub profile: String,
    pub snapshot_ref: SemanticId,
    pub registry_ref: SemanticId,
    pub registry_path: String,
    pub generation: u64,
    pub current_revision_ref: SemanticId,
    pub current_revision_digest: ContentDigest,
    pub current_source_path: String,
    pub current_source_bytes: u64,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub snapshot_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopRegistryTransitionPlan {
    pub profile: String,
    pub transaction_ref: SemanticId,
    pub expected_registry_snapshot_digest: ContentDigest,
    pub registry_ref: SemanticId,
    pub registry_final_path: String,
    pub registry_temp_path: String,
    pub before_generation: u64,
    pub after_generation: u64,
    pub candidate_proposal_ref: SemanticId,
    pub candidate_proposal_digest: ContentDigest,
    pub candidate_source_path: String,
    pub candidate_source_sha256: ContentDigest,
    pub activation_authority_ref: SemanticId,
    pub recovery_owner_ref: SemanticId,
    pub write_protocol: Vec<String>,
    pub atomicity: SucceedingSopRegistryAtomicity,
    pub durability: SucceedingSopRegistryDurability,
    pub transition_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopSupersessionPlan {
    pub profile: String,
    pub supersession_ref: SemanticId,
    pub predecessor_revision_ref: SemanticId,
    pub predecessor_revision_digest: ContentDigest,
    pub predecessor_source_path: String,
    pub predecessor_generation: u64,
    pub successor_proposal_ref: SemanticId,
    pub successor_proposal_digest: ContentDigest,
    pub successor_source_path: String,
    pub reason: String,
    pub preserve_predecessor: bool,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub supersession_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopRollbackPlan {
    pub profile: String,
    pub rollback_ref: SemanticId,
    pub recovery_owner_ref: SemanticId,
    pub rollback_revision_ref: SemanticId,
    pub rollback_revision_digest: ContentDigest,
    pub rollback_source_path: String,
    pub rollback_source_bytes: u64,
    pub failed_candidate_ref: SemanticId,
    pub failed_candidate_digest: ContentDigest,
    pub expected_registry_generation: u64,
    pub triggers: BTreeSet<String>,
    pub preserve_failed_candidate: bool,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub rollback_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopActivationTransactionRequest {
    pub profile: String,
    pub admission_id: SemanticId,
    pub review_admission: SucceedingSopReviewAdmissionReceipt,
    pub activation_policy: SucceedingSopActivationPolicy,
    pub source_reacquisition: SucceedingSopSourceReacquisitionPlan,
    pub current_registry: SucceedingSopCurrentRegistrySnapshot,
    pub transition: SucceedingSopRegistryTransitionPlan,
    pub supersession: SucceedingSopSupersessionPlan,
    pub rollback: SucceedingSopRollbackPlan,
    pub activation_obligations: BTreeSet<String>,
    pub non_authority: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopActivationTransactionReceipt {
    pub profile: String,
    pub request: SucceedingSopActivationTransactionRequest,
    pub admission_ref: SemanticId,
    pub transaction_ref: SemanticId,
    pub proposal_ref: SemanticId,
    pub policy_ref: SemanticId,
    pub activation_authority_ref: SemanticId,
    pub recovery_owner_ref: SemanticId,
    pub registry_ref: SemanticId,
    pub policy_use_status: SucceedingSopActivationPolicyUseStatus,
    pub status: SucceedingSopActivationTransactionStatus,
    pub authority: SucceedingSopActivationTransactionAuthority,
    pub upstream_review_verified: bool,
    pub transaction_correspondence_verified: bool,
    pub physical_contact: bool,
    pub source_reacquired: bool,
    pub registry_observed: bool,
    pub registry_persisted: bool,
    pub current_sop_selected: bool,
    pub boot_activation_verified: bool,
    pub rollback_executed: bool,
    pub physical_execution_eligible: bool,
    pub verified_checks: BTreeSet<String>,
    pub activation_obligations: BTreeSet<String>,
    pub policy_digest: ContentDigest,
    pub source_plan_digest: ContentDigest,
    pub registry_snapshot_digest: ContentDigest,
    pub transition_digest: ContentDigest,
    pub supersession_digest: ContentDigest,
    pub rollback_digest: ContentDigest,
    pub upstream_review_receipt_digest: ContentDigest,
    pub upstream_review_request_digest: ContentDigest,
    pub proposal_digest: ContentDigest,
    pub proposal_verification_digest: ContentDigest,
    pub review_payload_digest: ContentDigest,
    pub request_digest: ContentDigest,
    pub non_authority: String,
    pub receipt_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopActivationTransactionFaultCode {
    InvalidProfile,
    InvalidUpstream,
    InvalidPolicy,
    InvalidIdentity,
    InvalidEvidence,
    InvalidPath,
    InvalidSource,
    InvalidRegistry,
    InvalidGeneration,
    InvalidTransition,
    InvalidSupersession,
    InvalidRollback,
    InvalidObligation,
    InvalidAuthority,
    InvalidCorrespondence,
    InvalidDigest,
    InvalidBound,
    InvalidMachineForm,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopActivationTransactionFault {
    pub code: SucceedingSopActivationTransactionFaultCode,
    pub message: String,
}

impl fmt::Display for SucceedingSopActivationTransactionFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for SucceedingSopActivationTransactionFault {}

pub fn admit_succeeding_sop_activation_transaction(
    request: &SucceedingSopActivationTransactionRequest,
) -> Result<SucceedingSopActivationTransactionReceipt, SucceedingSopActivationTransactionFault> {
    validate_succeeding_sop_activation_transaction_request(request)?;
    let receipt = build_receipt(request)?;
    validate_succeeding_sop_activation_transaction_receipt(&receipt)?;
    Ok(receipt)
}

pub fn validate_succeeding_sop_activation_transaction_request(
    request: &SucceedingSopActivationTransactionRequest,
) -> Result<(), SucceedingSopActivationTransactionFault> {
    if request.profile != SUCCEEDING_SOP_ACTIVATION_TRANSACTION_REQUEST_PROFILE {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidProfile,
            "activation transaction request profile differs",
        ));
    }
    validate_succeeding_sop_review_admission_receipt(&request.review_admission).map_err(
        |error| {
            fault(
                SucceedingSopActivationTransactionFaultCode::InvalidUpstream,
                error.to_string(),
            )
        },
    )?;
    validate_policy(&request.activation_policy)?;
    validate_identity_and_evidence_separation(request)?;
    validate_source_plan(request)?;
    validate_current_registry(request)?;
    validate_transition(request)?;
    validate_supersession(request)?;
    validate_rollback(request)?;
    if request.activation_obligations != required_activation_obligations() {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidObligation,
            "activation obligations differ",
        ));
    }
    if request.non_authority != SUCCEEDING_SOP_ACTIVATION_TRANSACTION_NON_AUTHORITY {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidAuthority,
            "activation transaction request non-authority differs",
        ));
    }
    Ok(())
}

pub fn validate_succeeding_sop_activation_transaction_receipt(
    receipt: &SucceedingSopActivationTransactionReceipt,
) -> Result<(), SucceedingSopActivationTransactionFault> {
    if receipt.profile != SUCCEEDING_SOP_ACTIVATION_TRANSACTION_RECEIPT_PROFILE {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidProfile,
            "activation transaction receipt profile differs",
        ));
    }
    validate_succeeding_sop_activation_transaction_request(&receipt.request)?;
    let expected = build_receipt(&receipt.request)?;
    if receipt != &expected {
        let mut supplied = receipt.clone();
        supplied.receipt_digest = empty_digest();
        let mut without_digest = expected;
        without_digest.receipt_digest = empty_digest();
        return Err(fault(
            if supplied == without_digest {
                SucceedingSopActivationTransactionFaultCode::InvalidDigest
            } else {
                SucceedingSopActivationTransactionFaultCode::InvalidCorrespondence
            },
            "activation transaction receipt differs from exact replay",
        ));
    }
    Ok(())
}

pub fn succeeding_sop_activation_policy_digest(
    policy: &SucceedingSopActivationPolicy,
) -> Result<ContentDigest, SucceedingSopActivationTransactionFault> {
    let mut body = policy.clone();
    body.policy_digest = empty_digest();
    sha256_form(POLICY_DOMAIN, &body)
}

pub fn succeeding_sop_source_reacquisition_plan_digest(
    plan: &SucceedingSopSourceReacquisitionPlan,
) -> Result<ContentDigest, SucceedingSopActivationTransactionFault> {
    let mut body = plan.clone();
    body.plan_digest = empty_digest();
    sha256_form(SOURCE_PLAN_DOMAIN, &body)
}

pub fn succeeding_sop_current_registry_snapshot_digest(
    snapshot: &SucceedingSopCurrentRegistrySnapshot,
) -> Result<ContentDigest, SucceedingSopActivationTransactionFault> {
    let mut body = snapshot.clone();
    body.snapshot_digest = empty_digest();
    sha256_form(REGISTRY_SNAPSHOT_DOMAIN, &body)
}

pub fn succeeding_sop_registry_transition_plan_digest(
    plan: &SucceedingSopRegistryTransitionPlan,
) -> Result<ContentDigest, SucceedingSopActivationTransactionFault> {
    let mut body = plan.clone();
    body.transition_digest = empty_digest();
    sha256_form(TRANSITION_PLAN_DOMAIN, &body)
}

pub fn succeeding_sop_supersession_plan_digest(
    plan: &SucceedingSopSupersessionPlan,
) -> Result<ContentDigest, SucceedingSopActivationTransactionFault> {
    let mut body = plan.clone();
    body.supersession_digest = empty_digest();
    sha256_form(SUPERSESSION_PLAN_DOMAIN, &body)
}

pub fn succeeding_sop_rollback_plan_digest(
    plan: &SucceedingSopRollbackPlan,
) -> Result<ContentDigest, SucceedingSopActivationTransactionFault> {
    let mut body = plan.clone();
    body.rollback_digest = empty_digest();
    sha256_form(ROLLBACK_PLAN_DOMAIN, &body)
}

pub fn succeeding_sop_activation_transaction_request_digest(
    request: &SucceedingSopActivationTransactionRequest,
) -> Result<ContentDigest, SucceedingSopActivationTransactionFault> {
    sha256_form(REQUEST_DOMAIN, request)
}

pub fn succeeding_sop_activation_transaction_receipt_digest(
    receipt: &SucceedingSopActivationTransactionReceipt,
) -> Result<ContentDigest, SucceedingSopActivationTransactionFault> {
    let mut body = receipt.clone();
    body.receipt_digest = empty_digest();
    sha256_form(RECEIPT_DOMAIN, &body)
}

pub fn to_succeeding_sop_activation_transaction_request_machine_form(
    request: &SucceedingSopActivationTransactionRequest,
) -> Result<String, SucceedingSopActivationTransactionFault> {
    validate_succeeding_sop_activation_transaction_request(request)?;
    machine_form(request)
}

pub fn from_succeeding_sop_activation_transaction_request_machine_form(
    value: &str,
) -> Result<SucceedingSopActivationTransactionRequest, SucceedingSopActivationTransactionFault> {
    validate_machine_form_bound(value)?;
    let request = serde_json::from_str(value).map_err(machine_fault)?;
    validate_succeeding_sop_activation_transaction_request(&request)?;
    Ok(request)
}

pub fn to_succeeding_sop_activation_transaction_receipt_machine_form(
    receipt: &SucceedingSopActivationTransactionReceipt,
) -> Result<String, SucceedingSopActivationTransactionFault> {
    validate_succeeding_sop_activation_transaction_receipt(receipt)?;
    machine_form(receipt)
}

pub fn from_succeeding_sop_activation_transaction_receipt_machine_form(
    value: &str,
) -> Result<SucceedingSopActivationTransactionReceipt, SucceedingSopActivationTransactionFault> {
    validate_machine_form_bound(value)?;
    let receipt = serde_json::from_str(value).map_err(machine_fault)?;
    validate_succeeding_sop_activation_transaction_receipt(&receipt)?;
    Ok(receipt)
}

fn validate_policy(
    policy: &SucceedingSopActivationPolicy,
) -> Result<(), SucceedingSopActivationTransactionFault> {
    if policy.profile != SUCCEEDING_SOP_ACTIVATION_POLICY_PROFILE
        || policy.allowed_review_receipt_profile != SUCCEEDING_SOP_REVIEW_ADMISSION_RECEIPT_PROFILE
        || policy.required_acquisition_mode
            != SucceedingSopSourceAcquisitionMode::ExactRawBytesReopenNoFollow
        || policy.required_atomicity != SucceedingSopRegistryAtomicity::SameVolumeReplaceRequired
        || policy.required_durability != SucceedingSopRegistryDurability::FileAndParentFlushRequired
    {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidPolicy,
            "activation policy profile or required protocol differs",
        ));
    }
    validate_evidence(
        &policy.governance_evidence_refs,
        "policy governance evidence",
    )?;
    if policy.non_authority != SUCCEEDING_SOP_ACTIVATION_TRANSACTION_NON_AUTHORITY {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidAuthority,
            "activation policy non-authority differs",
        ));
    }
    validate_digest(&policy.policy_digest, "activation policy digest")?;
    if policy.policy_digest != succeeding_sop_activation_policy_digest(policy)? {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidDigest,
            "activation policy digest differs",
        ));
    }
    Ok(())
}

fn validate_identity_and_evidence_separation(
    request: &SucceedingSopActivationTransactionRequest,
) -> Result<(), SucceedingSopActivationTransactionFault> {
    let upstream = &request.review_admission.request;
    let proposal = &upstream.proposal_verification.proposal;
    let roles = [
        &request.admission_id,
        &request.activation_policy.policy_ref,
        &request.activation_policy.activation_authority_ref,
        &request.activation_policy.recovery_owner_ref,
        &request.activation_policy.registry_ref,
        &request.source_reacquisition.plan_ref,
        &request.source_reacquisition.repository_root_ref,
        &request.current_registry.snapshot_ref,
        &request.transition.transaction_ref,
        &request.supersession.supersession_ref,
        &request.rollback.rollback_ref,
        &request.review_admission.admission_ref,
        &upstream.reviewer_policy.reviewer_ref,
        &proposal.author_ref,
        &upstream.proposal_verification.verifier_ref,
        &proposal.proposal_ref,
        &upstream.source_preservation.preservation_ref,
        &upstream.source_preservation.source_snapshot_ref,
    ];
    let mut unique_roles = BTreeSet::new();
    if roles
        .iter()
        .any(|identity| !unique_roles.insert((*identity).clone()))
    {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidIdentity,
            "activation transaction duty identities collide",
        ));
    }
    let evidence_sets = [
        &request.activation_policy.governance_evidence_refs,
        &request.source_reacquisition.evidence_refs,
        &request.current_registry.evidence_refs,
        &request.supersession.evidence_refs,
        &request.rollback.evidence_refs,
    ];
    let mut evidence_seen = BTreeSet::new();
    for evidence in evidence_sets.into_iter().flat_map(|values| values.iter()) {
        if unique_roles.contains(evidence) || !evidence_seen.insert(evidence.clone()) {
            return Err(fault(
                SucceedingSopActivationTransactionFaultCode::InvalidIdentity,
                "activation transaction evidence identities collide",
            ));
        }
    }
    Ok(())
}

fn validate_source_plan(
    request: &SucceedingSopActivationTransactionRequest,
) -> Result<(), SucceedingSopActivationTransactionFault> {
    let plan = &request.source_reacquisition;
    let preservation = &request.review_admission.request.source_preservation;
    if plan.profile != SUCCEEDING_SOP_SOURCE_REACQUISITION_PLAN_PROFILE
        || plan.preservation_ref != preservation.preservation_ref
        || plan.source_snapshot_ref != preservation.source_snapshot_ref
        || plan.source_path != preservation.source_path
        || plan.source_subject != preservation.source_subject
        || plan.source_sha256 != preservation.source_sha256
        || plan.source_bytes != preservation.source_bytes
        || plan.proposal_digest != preservation.proposal_digest
        || !plan.immutable_required
        || !plan.no_normalization
        || plan.acquisition_mode != request.activation_policy.required_acquisition_mode
    {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidSource,
            "source reacquisition plan differs from exact preservation",
        ));
    }
    validate_source_path(&plan.source_path)?;
    validate_evidence(&plan.evidence_refs, "source reacquisition evidence")?;
    validate_digest(&plan.plan_digest, "source reacquisition plan digest")?;
    if plan.plan_digest != succeeding_sop_source_reacquisition_plan_digest(plan)? {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidDigest,
            "source reacquisition plan digest differs",
        ));
    }
    Ok(())
}

fn validate_current_registry(
    request: &SucceedingSopActivationTransactionRequest,
) -> Result<(), SucceedingSopActivationTransactionFault> {
    let snapshot = &request.current_registry;
    let proposal = &request
        .review_admission
        .request
        .proposal_verification
        .proposal;
    if snapshot.profile != SUCCEEDING_SOP_CURRENT_REGISTRY_SNAPSHOT_PROFILE
        || snapshot.registry_ref != request.activation_policy.registry_ref
        || snapshot.current_revision_ref != proposal.predecessor_sop_revision_ref
        || snapshot.current_revision_digest != proposal.predecessor_sop_revision_digest
        || snapshot.current_source_bytes == 0
        || snapshot.current_source_bytes
            > SUCCEEDING_SOP_ACTIVATION_TRANSACTION_MAX_MACHINE_FORM_BYTES as u64
    {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidRegistry,
            "current registry differs from policy or proposal predecessor",
        ));
    }
    validate_registry_path(&snapshot.registry_path, ".sop")?;
    validate_source_path(&snapshot.current_source_path)?;
    validate_evidence(&snapshot.evidence_refs, "current registry evidence")?;
    validate_digest(
        &snapshot.snapshot_digest,
        "current registry snapshot digest",
    )?;
    if snapshot.snapshot_digest != succeeding_sop_current_registry_snapshot_digest(snapshot)? {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidDigest,
            "current registry snapshot digest differs",
        ));
    }
    Ok(())
}

fn validate_transition(
    request: &SucceedingSopActivationTransactionRequest,
) -> Result<(), SucceedingSopActivationTransactionFault> {
    let plan = &request.transition;
    let proposal = &request
        .review_admission
        .request
        .proposal_verification
        .proposal;
    let next_generation = request
        .current_registry
        .generation
        .checked_add(1)
        .ok_or_else(|| {
            fault(
                SucceedingSopActivationTransactionFaultCode::InvalidGeneration,
                "registry generation overflows",
            )
        })?;
    if plan.profile != SUCCEEDING_SOP_REGISTRY_TRANSITION_PLAN_PROFILE
        || plan.expected_registry_snapshot_digest != request.current_registry.snapshot_digest
        || plan.registry_ref != request.current_registry.registry_ref
        || plan.registry_final_path != request.current_registry.registry_path
        || plan.before_generation != request.current_registry.generation
        || plan.after_generation != next_generation
        || plan.candidate_proposal_ref != proposal.proposal_ref
        || plan.candidate_proposal_digest != proposal.proposal_digest
        || plan.candidate_source_path != request.source_reacquisition.source_path
        || plan.candidate_source_sha256 != request.source_reacquisition.source_sha256
        || plan.activation_authority_ref != request.activation_policy.activation_authority_ref
        || plan.recovery_owner_ref != request.activation_policy.recovery_owner_ref
        || plan.write_protocol != required_write_protocol()
        || plan.atomicity != request.activation_policy.required_atomicity
        || plan.durability != request.activation_policy.required_durability
    {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidTransition,
            "registry transition correspondence differs",
        ));
    }
    validate_registry_path(&plan.registry_final_path, ".sop")?;
    validate_registry_path(&plan.registry_temp_path, ".tmp")?;
    if plan.registry_final_path == plan.registry_temp_path
        || path_parent(&plan.registry_final_path) != path_parent(&plan.registry_temp_path)
    {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidPath,
            "registry temporary path must be distinct and share the final parent",
        ));
    }
    validate_digest(&plan.transition_digest, "registry transition digest")?;
    if plan.transition_digest != succeeding_sop_registry_transition_plan_digest(plan)? {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidDigest,
            "registry transition digest differs",
        ));
    }
    Ok(())
}

fn validate_supersession(
    request: &SucceedingSopActivationTransactionRequest,
) -> Result<(), SucceedingSopActivationTransactionFault> {
    let plan = &request.supersession;
    let proposal = &request
        .review_admission
        .request
        .proposal_verification
        .proposal;
    if plan.profile != SUCCEEDING_SOP_SUPERSESSION_PLAN_PROFILE
        || plan.predecessor_revision_ref != request.current_registry.current_revision_ref
        || plan.predecessor_revision_digest != request.current_registry.current_revision_digest
        || plan.predecessor_source_path != request.current_registry.current_source_path
        || plan.predecessor_generation != request.current_registry.generation
        || plan.successor_proposal_ref != proposal.proposal_ref
        || plan.successor_proposal_digest != proposal.proposal_digest
        || plan.successor_source_path != request.source_reacquisition.source_path
        || !plan.preserve_predecessor
    {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidSupersession,
            "supersession plan correspondence differs",
        ));
    }
    validate_reason(&plan.reason)?;
    validate_source_path(&plan.predecessor_source_path)?;
    validate_source_path(&plan.successor_source_path)?;
    validate_evidence(&plan.evidence_refs, "supersession evidence")?;
    validate_digest(&plan.supersession_digest, "supersession digest")?;
    if plan.supersession_digest != succeeding_sop_supersession_plan_digest(plan)? {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidDigest,
            "supersession digest differs",
        ));
    }
    Ok(())
}

fn validate_rollback(
    request: &SucceedingSopActivationTransactionRequest,
) -> Result<(), SucceedingSopActivationTransactionFault> {
    let plan = &request.rollback;
    let proposal = &request
        .review_admission
        .request
        .proposal_verification
        .proposal;
    if plan.profile != SUCCEEDING_SOP_ROLLBACK_PLAN_PROFILE
        || plan.recovery_owner_ref != request.activation_policy.recovery_owner_ref
        || plan.rollback_revision_ref != request.current_registry.current_revision_ref
        || plan.rollback_revision_digest != request.current_registry.current_revision_digest
        || plan.rollback_source_path != request.current_registry.current_source_path
        || plan.rollback_source_bytes != request.current_registry.current_source_bytes
        || plan.failed_candidate_ref != proposal.proposal_ref
        || plan.failed_candidate_digest != proposal.proposal_digest
        || plan.expected_registry_generation != request.transition.after_generation
        || plan.triggers != required_rollback_triggers()
        || !plan.preserve_failed_candidate
        || plan.rollback_source_bytes == 0
        || plan.rollback_source_bytes
            > SUCCEEDING_SOP_ACTIVATION_TRANSACTION_MAX_MACHINE_FORM_BYTES as u64
    {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidRollback,
            "rollback plan correspondence differs",
        ));
    }
    validate_source_path(&plan.rollback_source_path)?;
    validate_evidence(&plan.evidence_refs, "rollback evidence")?;
    validate_digest(&plan.rollback_digest, "rollback digest")?;
    if plan.rollback_digest != succeeding_sop_rollback_plan_digest(plan)? {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidDigest,
            "rollback digest differs",
        ));
    }
    Ok(())
}

fn build_receipt(
    request: &SucceedingSopActivationTransactionRequest,
) -> Result<SucceedingSopActivationTransactionReceipt, SucceedingSopActivationTransactionFault> {
    let upstream_request = &request.review_admission.request;
    let proposal = &upstream_request.proposal_verification.proposal;
    let mut receipt = SucceedingSopActivationTransactionReceipt {
        profile: SUCCEEDING_SOP_ACTIVATION_TRANSACTION_RECEIPT_PROFILE.to_owned(),
        request: request.clone(),
        admission_ref: request.admission_id.clone(),
        transaction_ref: request.transition.transaction_ref.clone(),
        proposal_ref: proposal.proposal_ref.clone(),
        policy_ref: request.activation_policy.policy_ref.clone(),
        activation_authority_ref: request.activation_policy.activation_authority_ref.clone(),
        recovery_owner_ref: request.activation_policy.recovery_owner_ref.clone(),
        registry_ref: request.activation_policy.registry_ref.clone(),
        policy_use_status: request.activation_policy.use_status,
        status: SucceedingSopActivationTransactionStatus::TransactionCorrespondenceVerifiedAwaitingPhysicalExecution,
        authority: SucceedingSopActivationTransactionAuthority::SuppliedActivationPlanCorrespondenceOnly,
        upstream_review_verified: true,
        transaction_correspondence_verified: true,
        physical_contact: false,
        source_reacquired: false,
        registry_observed: false,
        registry_persisted: false,
        current_sop_selected: false,
        boot_activation_verified: false,
        rollback_executed: false,
        physical_execution_eligible: false,
        verified_checks: required_verified_checks(),
        activation_obligations: required_activation_obligations(),
        policy_digest: request.activation_policy.policy_digest.clone(),
        source_plan_digest: request.source_reacquisition.plan_digest.clone(),
        registry_snapshot_digest: request.current_registry.snapshot_digest.clone(),
        transition_digest: request.transition.transition_digest.clone(),
        supersession_digest: request.supersession.supersession_digest.clone(),
        rollback_digest: request.rollback.rollback_digest.clone(),
        upstream_review_receipt_digest: request.review_admission.receipt_digest.clone(),
        upstream_review_request_digest: request.review_admission.request_digest.clone(),
        proposal_digest: proposal.proposal_digest.clone(),
        proposal_verification_digest: upstream_request
            .proposal_verification
            .verification_digest
            .clone(),
        review_payload_digest: upstream_request
            .satisfaction_signature
            .payload
            .payload_digest
            .clone(),
        request_digest: succeeding_sop_activation_transaction_request_digest(request)?,
        non_authority: SUCCEEDING_SOP_ACTIVATION_TRANSACTION_NON_AUTHORITY.to_owned(),
        receipt_digest: empty_digest(),
    };
    receipt.receipt_digest = succeeding_sop_activation_transaction_receipt_digest(&receipt)?;
    Ok(receipt)
}

fn validate_source_path(value: &str) -> Result<(), SucceedingSopActivationTransactionFault> {
    validate_typed_path(value, &["source_documents"], ".sop")
}

fn validate_registry_path(
    value: &str,
    suffix: &str,
) -> Result<(), SucceedingSopActivationTransactionFault> {
    validate_typed_path(value, &["narrative", "registries"], suffix)
}

fn validate_typed_path(
    value: &str,
    prefix: &[&str],
    suffix: &str,
) -> Result<(), SucceedingSopActivationTransactionFault> {
    let segments = value.split('/').collect::<Vec<_>>();
    let invalid = value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.starts_with('/')
        || value.contains('\\')
        || value.contains(':')
        || value.chars().any(char::is_control)
        || !value.ends_with(suffix)
        || segments.len() <= prefix.len()
        || !segments
            .iter()
            .take(prefix.len())
            .copied()
            .eq(prefix.iter().copied())
        || segments
            .iter()
            .any(|segment| segment.is_empty() || *segment == "." || *segment == "..");
    if invalid {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidPath,
            "activation transaction repository-relative path differs",
        ));
    }
    Ok(())
}

fn path_parent(value: &str) -> Option<&str> {
    value.rsplit_once('/').map(|(parent, _)| parent)
}

fn validate_reason(value: &str) -> Result<(), SucceedingSopActivationTransactionFault> {
    if value.is_empty()
        || value.len() > MAX_REASON_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidSupersession,
            "supersession reason differs",
        ));
    }
    Ok(())
}

fn validate_evidence(
    values: &BTreeSet<SemanticId>,
    label: &str,
) -> Result<(), SucceedingSopActivationTransactionFault> {
    if values.is_empty() || values.len() > MAX_EVIDENCE_REFS {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidEvidence,
            format!("{label} count differs"),
        ));
    }
    Ok(())
}

fn required_activation_obligations() -> BTreeSet<String> {
    SUCCEEDING_SOP_ACTIVATION_OBLIGATIONS
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn required_write_protocol() -> Vec<String> {
    SUCCEEDING_SOP_ACTIVATION_WRITE_PROTOCOL
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn required_rollback_triggers() -> BTreeSet<String> {
    SUCCEEDING_SOP_ACTIVATION_ROLLBACK_TRIGGERS
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn required_verified_checks() -> BTreeSet<String> {
    SUCCEEDING_SOP_ACTIVATION_TRANSACTION_VERIFIED_CHECKS
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn validate_digest(
    digest: &ContentDigest,
    label: &str,
) -> Result<(), SucceedingSopActivationTransactionFault> {
    let valid = digest.algorithm == "sha256"
        && digest.value.len() == 64
        && digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidDigest,
            format!("{label} must be lower-case SHA256"),
        ));
    }
    Ok(())
}

fn sha256_form<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<ContentDigest, SucceedingSopActivationTransactionFault> {
    let body = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + body.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&body);
    Ok(sha256_bytes(&bytes))
}

fn machine_form<T: Serialize>(
    value: &T,
) -> Result<String, SucceedingSopActivationTransactionFault> {
    let output = serde_json::to_string(value).map_err(machine_fault)?;
    validate_machine_form_bound(&output)?;
    Ok(output)
}

fn validate_machine_form_bound(value: &str) -> Result<(), SucceedingSopActivationTransactionFault> {
    if value.is_empty()
        || value.len() > SUCCEEDING_SOP_ACTIVATION_TRANSACTION_MAX_MACHINE_FORM_BYTES
    {
        return Err(fault(
            SucceedingSopActivationTransactionFaultCode::InvalidBound,
            "activation transaction machine-form bound differs",
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

fn machine_fault(error: serde_json::Error) -> SucceedingSopActivationTransactionFault {
    fault(
        SucceedingSopActivationTransactionFaultCode::InvalidMachineForm,
        format!("succeeding SOP activation transaction machine form failed: {error}"),
    )
}

fn fault(
    code: SucceedingSopActivationTransactionFaultCode,
    message: impl Into<String>,
) -> SucceedingSopActivationTransactionFault {
    SucceedingSopActivationTransactionFault {
        code,
        message: message.into(),
    }
}
