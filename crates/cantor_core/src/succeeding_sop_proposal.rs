//! Pure SWA-06A succeeding-SOP proposal compilation and replay verification.
//!
//! The caller supplies exact lifecycle and source forms. This module performs
//! no model call, source write, semantic review, signature, activation, or
//! other physical action.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    ContentDigest, SelfWorkLifecycleCheckpoint, SelfWorkLifecycleRequest, SelfWorkLifecycleState,
    SemanticId, WorkStepClass, sha256_bytes, validate_self_work_lifecycle_checkpoint,
    validate_self_work_lifecycle_request,
};

pub const SUCCEEDING_SOP_REQUEST_PROFILE: &str = "cantor-succeeding-sop-request/0.1";
pub const SUCCEEDING_SOP_PROPOSAL_PROFILE: &str = "cantor-succeeding-sop-proposal/0.1";
pub const SUCCEEDING_SOP_VERIFICATION_PROFILE: &str = "cantor-succeeding-sop-verification/0.1";
pub const SUCCEEDING_SOP_VERIFIER_REF: &str = "cantor-verifier:succeeding-sop-p0";
pub const SUCCEEDING_SOP_NON_AUTHORITY: &str = "Pure supplied-data authorship proposal and machine verification only. Supplied lifecycle receipts and evidence references are not authenticated or interpreted as physical work proof. No model is called, no source or workspace is read or written, no process or test is run, no update is applied or verified, no semantic review is performed, no satisfaction signature is issued, no SOP is admitted or activated, no commit or push occurs, no provider or external effect is invoked, and no persistence, remote, FPGA, or Minecraft authority is granted.";
pub const SUCCEEDING_SOP_MAX_MACHINE_FORM_BYTES: usize = 8 * 1024 * 1024;

pub const SUCCEEDING_SOP_REVIEW_OBLIGATIONS: [&str; 5] = [
    "activate_only_under_separate_authority",
    "independently_review_semantics",
    "issue_satisfaction_signature_separately",
    "preserve_source_before_processing",
    "recompile_and_verify_after_review",
];

pub const SUCCEEDING_SOP_VERIFIED_CHECKS: [&str; 14] = [
    "authority_denial",
    "author_provenance",
    "dependency_completion",
    "exact_profiles",
    "exact_work_evidence",
    "lineage_projection",
    "proposal_digest",
    "ready_attempt",
    "request_digest",
    "source_canonicality",
    "source_digest",
    "step_class",
    "upstream_lifecycle_replay",
    "unresolved_frontier",
];

const REQUEST_DOMAIN: &str = "cantor.succeeding-sop.request.v1";
const PROPOSAL_DOMAIN: &str = "cantor.succeeding-sop.proposal.v1";
const VERIFICATION_DOMAIN: &str = "cantor.succeeding-sop.verification.v1";
const MAX_AUTHORSHIP_EVIDENCE_REFS: usize = 32;
const MAX_WORK_EVIDENCE_REFS: usize = 128;
const MAX_FRONTIER_ENTRIES: usize = 32;
const MAX_REVIEW_OBLIGATIONS: usize = 16;
const MAX_SUBJECT_BYTES: usize = 256;
const MAX_SOURCE_BYTES: usize = 128 * 1024;
const MAX_FRONTIER_ENTRY_BYTES: usize = 256;

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopDisposition {
    ProposedAwaitingIndependentReview,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopAuthority {
    AuthorshipProposalOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopVerificationAuthority {
    MachineCorrespondenceOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopRequest {
    pub profile: String,
    pub proposal_id: SemanticId,
    pub lifecycle_request: SelfWorkLifecycleRequest,
    pub lifecycle_checkpoint: SelfWorkLifecycleCheckpoint,
    pub selected_step_ref: SemanticId,
    pub selected_attempt_ref: SemanticId,
    pub author_ref: SemanticId,
    pub authorship_evidence_refs: BTreeSet<SemanticId>,
    pub source_subject: String,
    pub source_text: String,
    pub work_evidence_refs: BTreeSet<SemanticId>,
    pub unresolved_frontier: BTreeSet<String>,
    pub review_obligations: BTreeSet<String>,
    pub non_authority: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopProposal {
    pub profile: String,
    pub request: SucceedingSopRequest,
    pub proposal_ref: SemanticId,
    pub predecessor_canonical_sop_ref: SemanticId,
    pub predecessor_sop_revision_ref: SemanticId,
    pub predecessor_sop_revision_digest: ContentDigest,
    pub objective_ref: SemanticId,
    pub objective_digest: ContentDigest,
    pub plan_ref: SemanticId,
    pub plan_revision_digest: ContentDigest,
    pub lifecycle_ref: SemanticId,
    pub lifecycle_checkpoint_digest: ContentDigest,
    pub selected_step_ref: SemanticId,
    pub selected_attempt_ref: SemanticId,
    pub completed_dependency_refs: BTreeSet<SemanticId>,
    pub author_ref: SemanticId,
    pub authorship_evidence_refs: BTreeSet<SemanticId>,
    pub source_subject: String,
    pub source_text: String,
    pub source_sha256: ContentDigest,
    pub work_evidence_refs: BTreeSet<SemanticId>,
    pub unresolved_frontier: BTreeSet<String>,
    pub review_obligations: BTreeSet<String>,
    pub disposition: SucceedingSopDisposition,
    pub authority: SucceedingSopAuthority,
    pub non_authority: String,
    pub request_digest: ContentDigest,
    pub proposal_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopVerificationReceipt {
    pub profile: String,
    pub proposal: SucceedingSopProposal,
    pub proposal_ref: SemanticId,
    pub verifier_ref: SemanticId,
    pub verified_checks: BTreeSet<String>,
    pub verified: bool,
    pub authority: SucceedingSopVerificationAuthority,
    pub non_authority: String,
    pub request_digest: ContentDigest,
    pub proposal_digest: ContentDigest,
    pub verification_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopFaultCode {
    InvalidProfile,
    InvalidLifecycle,
    InvalidStep,
    InvalidState,
    InvalidDependency,
    InvalidEvidence,
    InvalidSource,
    InvalidAuthor,
    InvalidFrontier,
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
pub struct SucceedingSopFault {
    pub code: SucceedingSopFaultCode,
    pub message: String,
}

impl fmt::Display for SucceedingSopFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for SucceedingSopFault {}

pub fn compile_succeeding_sop(
    request: &SucceedingSopRequest,
) -> Result<SucceedingSopProposal, SucceedingSopFault> {
    let derived = validate_request_and_derive(request)?;
    let boot = &request
        .lifecycle_request
        .work_plan_proposal
        .request
        .boot_proposal
        .request;
    let plan = &request.lifecycle_request.work_plan_proposal.request.plan;
    let mut proposal = SucceedingSopProposal {
        profile: SUCCEEDING_SOP_PROPOSAL_PROFILE.to_owned(),
        request: request.clone(),
        proposal_ref: request.proposal_id.clone(),
        predecessor_canonical_sop_ref: boot.boot_sop.canonical_sop_ref.clone(),
        predecessor_sop_revision_ref: boot.boot_sop.sop_revision_ref.clone(),
        predecessor_sop_revision_digest: boot.boot_sop.sop_revision_digest.clone(),
        objective_ref: boot.objective_ref.clone(),
        objective_digest: boot.objective_digest.clone(),
        plan_ref: plan.plan_id.clone(),
        plan_revision_digest: plan.plan_revision_digest.clone(),
        lifecycle_ref: request.lifecycle_request.lifecycle_id.clone(),
        lifecycle_checkpoint_digest: request.lifecycle_checkpoint.checkpoint_digest.clone(),
        selected_step_ref: request.selected_step_ref.clone(),
        selected_attempt_ref: request.selected_attempt_ref.clone(),
        completed_dependency_refs: derived.completed_dependency_refs,
        author_ref: request.author_ref.clone(),
        authorship_evidence_refs: request.authorship_evidence_refs.clone(),
        source_subject: request.source_subject.clone(),
        source_text: request.source_text.clone(),
        source_sha256: sha256_bytes(request.source_text.as_bytes()),
        work_evidence_refs: request.work_evidence_refs.clone(),
        unresolved_frontier: request.unresolved_frontier.clone(),
        review_obligations: request.review_obligations.clone(),
        disposition: SucceedingSopDisposition::ProposedAwaitingIndependentReview,
        authority: SucceedingSopAuthority::AuthorshipProposalOnly,
        non_authority: request.non_authority.clone(),
        request_digest: succeeding_sop_request_digest(request)?,
        proposal_digest: empty_digest(),
    };
    proposal.proposal_digest = succeeding_sop_proposal_digest(&proposal)?;
    validate_succeeding_sop_proposal(request, &proposal)?;
    Ok(proposal)
}

pub fn verify_succeeding_sop_proposal(
    proposal: &SucceedingSopProposal,
) -> Result<SucceedingSopVerificationReceipt, SucceedingSopFault> {
    validate_succeeding_sop_proposal(&proposal.request, proposal)?;
    let mut receipt = SucceedingSopVerificationReceipt {
        profile: SUCCEEDING_SOP_VERIFICATION_PROFILE.to_owned(),
        proposal: proposal.clone(),
        proposal_ref: proposal.proposal_ref.clone(),
        verifier_ref: SemanticId::new(SUCCEEDING_SOP_VERIFIER_REF)
            .map_err(|error| fault(SucceedingSopFaultCode::InvalidAuthor, error.to_string()))?,
        verified_checks: required_verified_checks(),
        verified: true,
        authority: SucceedingSopVerificationAuthority::MachineCorrespondenceOnly,
        non_authority: SUCCEEDING_SOP_NON_AUTHORITY.to_owned(),
        request_digest: proposal.request_digest.clone(),
        proposal_digest: proposal.proposal_digest.clone(),
        verification_digest: empty_digest(),
    };
    receipt.verification_digest = succeeding_sop_verification_digest(&receipt)?;
    validate_succeeding_sop_verification_receipt(&receipt)?;
    Ok(receipt)
}

pub fn validate_succeeding_sop_request(
    request: &SucceedingSopRequest,
) -> Result<(), SucceedingSopFault> {
    validate_request_and_derive(request).map(|_| ())
}

fn validate_request_and_derive(
    request: &SucceedingSopRequest,
) -> Result<DerivedRequestState, SucceedingSopFault> {
    if request.profile != SUCCEEDING_SOP_REQUEST_PROFILE {
        return Err(fault(
            SucceedingSopFaultCode::InvalidProfile,
            "request profile differs",
        ));
    }
    validate_self_work_lifecycle_request(&request.lifecycle_request)
        .map_err(|error| fault(SucceedingSopFaultCode::InvalidLifecycle, error.to_string()))?;
    validate_self_work_lifecycle_checkpoint(
        &request.lifecycle_request,
        &request.lifecycle_checkpoint,
    )
    .map_err(|error| fault(SucceedingSopFaultCode::InvalidLifecycle, error.to_string()))?;

    let plan = &request.lifecycle_request.work_plan_proposal.request.plan;
    let matching = plan
        .steps
        .iter()
        .filter(|step| step.step_id == request.selected_step_ref)
        .collect::<Vec<_>>();
    if matching.len() != 1 || matching[0].class != WorkStepClass::ProposeSucceedingSop {
        return Err(fault(
            SucceedingSopFaultCode::InvalidStep,
            "selected step is not the exact succeeding-SOP plan step",
        ));
    }
    let selected_step = matching[0];
    let selected_state = request
        .lifecycle_checkpoint
        .step_states
        .get(&request.selected_step_ref)
        .ok_or_else(|| {
            fault(
                SucceedingSopFaultCode::InvalidState,
                "selected lifecycle step is absent",
            )
        })?;
    if selected_state.step_ref != request.selected_step_ref
        || selected_state.attempt_ref != request.selected_attempt_ref
        || selected_state.state != SelfWorkLifecycleState::ReadyAwaitingAdmission
    {
        return Err(fault(
            SucceedingSopFaultCode::InvalidState,
            "selected step is not the exact ready attempt",
        ));
    }

    for dependency in &selected_step.dependency_refs {
        if request
            .lifecycle_checkpoint
            .step_states
            .get(dependency)
            .is_none_or(|state| state.state != SelfWorkLifecycleState::Complete)
        {
            return Err(fault(
                SucceedingSopFaultCode::InvalidDependency,
                "selected step dependency is not complete",
            ));
        }
    }

    validate_evidence_bound(
        &request.authorship_evidence_refs,
        MAX_AUTHORSHIP_EVIDENCE_REFS,
        "authorship evidence",
    )?;
    validate_author_identity(request)?;
    validate_source_subject(&request.source_subject)?;
    validate_source_text(&request.source_text)?;
    let expected_work_evidence = derive_work_evidence(request, selected_step)?;
    if request.work_evidence_refs != expected_work_evidence {
        return Err(fault(
            SucceedingSopFaultCode::InvalidEvidence,
            "work evidence differs from the exact causal set",
        ));
    }
    validate_frontier(&request.unresolved_frontier)?;
    if request.review_obligations != required_review_obligations()
        || request.review_obligations.len() > MAX_REVIEW_OBLIGATIONS
    {
        return Err(fault(
            SucceedingSopFaultCode::InvalidObligation,
            "review obligations differ",
        ));
    }
    if request.non_authority != SUCCEEDING_SOP_NON_AUTHORITY {
        return Err(fault(
            SucceedingSopFaultCode::InvalidAuthority,
            "request non-authority differs",
        ));
    }

    Ok(DerivedRequestState {
        completed_dependency_refs: selected_step.dependency_refs.clone(),
        required_work_evidence: expected_work_evidence,
    })
}

pub fn validate_succeeding_sop_proposal(
    expected_request: &SucceedingSopRequest,
    proposal: &SucceedingSopProposal,
) -> Result<(), SucceedingSopFault> {
    let derived = validate_request_and_derive(expected_request)?;
    let boot = &expected_request
        .lifecycle_request
        .work_plan_proposal
        .request
        .boot_proposal
        .request;
    let plan = &expected_request
        .lifecycle_request
        .work_plan_proposal
        .request
        .plan;
    if proposal.profile != SUCCEEDING_SOP_PROPOSAL_PROFILE
        || &proposal.request != expected_request
        || proposal.proposal_ref != expected_request.proposal_id
        || proposal.predecessor_canonical_sop_ref != boot.boot_sop.canonical_sop_ref
        || proposal.predecessor_sop_revision_ref != boot.boot_sop.sop_revision_ref
        || proposal.predecessor_sop_revision_digest != boot.boot_sop.sop_revision_digest
        || proposal.objective_ref != boot.objective_ref
        || proposal.objective_digest != boot.objective_digest
        || proposal.plan_ref != plan.plan_id
        || proposal.plan_revision_digest != plan.plan_revision_digest
        || proposal.lifecycle_ref != expected_request.lifecycle_request.lifecycle_id
        || proposal.lifecycle_checkpoint_digest
            != expected_request.lifecycle_checkpoint.checkpoint_digest
        || proposal.selected_step_ref != expected_request.selected_step_ref
        || proposal.selected_attempt_ref != expected_request.selected_attempt_ref
        || proposal.completed_dependency_refs != derived.completed_dependency_refs
        || proposal.author_ref != expected_request.author_ref
        || proposal.authorship_evidence_refs != expected_request.authorship_evidence_refs
        || proposal.source_subject != expected_request.source_subject
        || proposal.source_text != expected_request.source_text
        || proposal.work_evidence_refs != derived.required_work_evidence
        || proposal.unresolved_frontier != expected_request.unresolved_frontier
        || proposal.review_obligations != expected_request.review_obligations
        || proposal.disposition != SucceedingSopDisposition::ProposedAwaitingIndependentReview
        || proposal.authority != SucceedingSopAuthority::AuthorshipProposalOnly
        || proposal.non_authority != SUCCEEDING_SOP_NON_AUTHORITY
    {
        return Err(fault(
            SucceedingSopFaultCode::InvalidCorrespondence,
            "proposal projection differs from the exact request",
        ));
    }
    if proposal.source_sha256 != sha256_bytes(expected_request.source_text.as_bytes()) {
        return Err(fault(
            SucceedingSopFaultCode::InvalidDigest,
            "raw source digest differs",
        ));
    }
    if proposal.request_digest != succeeding_sop_request_digest(expected_request)? {
        return Err(fault(
            SucceedingSopFaultCode::InvalidDigest,
            "request digest differs",
        ));
    }
    validate_digest(&proposal.proposal_digest, "proposal digest")?;
    if proposal.proposal_digest != succeeding_sop_proposal_digest(proposal)? {
        return Err(fault(
            SucceedingSopFaultCode::InvalidDigest,
            "proposal digest differs",
        ));
    }
    Ok(())
}

pub fn validate_succeeding_sop_verification_receipt(
    receipt: &SucceedingSopVerificationReceipt,
) -> Result<(), SucceedingSopFault> {
    validate_succeeding_sop_proposal(&receipt.proposal.request, &receipt.proposal)?;
    let verifier_ref = SemanticId::new(SUCCEEDING_SOP_VERIFIER_REF)
        .map_err(|error| fault(SucceedingSopFaultCode::InvalidAuthor, error.to_string()))?;
    if receipt.profile != SUCCEEDING_SOP_VERIFICATION_PROFILE
        || receipt.proposal_ref != receipt.proposal.proposal_ref
        || receipt.verifier_ref != verifier_ref
        || receipt.verified_checks != required_verified_checks()
        || !receipt.verified
        || receipt.authority != SucceedingSopVerificationAuthority::MachineCorrespondenceOnly
        || receipt.non_authority != SUCCEEDING_SOP_NON_AUTHORITY
        || receipt.request_digest != receipt.proposal.request_digest
        || receipt.proposal_digest != receipt.proposal.proposal_digest
    {
        return Err(fault(
            SucceedingSopFaultCode::InvalidCorrespondence,
            "verification receipt differs from the exact proposal",
        ));
    }
    validate_digest(&receipt.verification_digest, "verification digest")?;
    if receipt.verification_digest != succeeding_sop_verification_digest(receipt)? {
        return Err(fault(
            SucceedingSopFaultCode::InvalidDigest,
            "verification digest differs",
        ));
    }
    Ok(())
}

pub fn succeeding_sop_request_digest(
    request: &SucceedingSopRequest,
) -> Result<ContentDigest, SucceedingSopFault> {
    sha256_form(REQUEST_DOMAIN, request)
}

pub fn succeeding_sop_proposal_digest(
    proposal: &SucceedingSopProposal,
) -> Result<ContentDigest, SucceedingSopFault> {
    let mut body = proposal.clone();
    body.proposal_digest = empty_digest();
    sha256_form(PROPOSAL_DOMAIN, &body)
}

pub fn succeeding_sop_verification_digest(
    receipt: &SucceedingSopVerificationReceipt,
) -> Result<ContentDigest, SucceedingSopFault> {
    let mut body = receipt.clone();
    body.verification_digest = empty_digest();
    sha256_form(VERIFICATION_DOMAIN, &body)
}

pub fn to_succeeding_sop_request_machine_form(
    request: &SucceedingSopRequest,
) -> Result<String, SucceedingSopFault> {
    validate_succeeding_sop_request(request)?;
    machine_form(request)
}

pub fn from_succeeding_sop_request_machine_form(
    value: &str,
) -> Result<SucceedingSopRequest, SucceedingSopFault> {
    validate_machine_form_bound(value)?;
    let request = serde_json::from_str(value).map_err(machine_fault)?;
    validate_succeeding_sop_request(&request)?;
    Ok(request)
}

pub fn to_succeeding_sop_proposal_machine_form(
    proposal: &SucceedingSopProposal,
) -> Result<String, SucceedingSopFault> {
    validate_succeeding_sop_proposal(&proposal.request, proposal)?;
    machine_form(proposal)
}

pub fn from_succeeding_sop_proposal_machine_form(
    value: &str,
) -> Result<SucceedingSopProposal, SucceedingSopFault> {
    validate_machine_form_bound(value)?;
    let proposal: SucceedingSopProposal = serde_json::from_str(value).map_err(machine_fault)?;
    validate_succeeding_sop_proposal(&proposal.request, &proposal)?;
    Ok(proposal)
}

pub fn to_succeeding_sop_verification_machine_form(
    receipt: &SucceedingSopVerificationReceipt,
) -> Result<String, SucceedingSopFault> {
    validate_succeeding_sop_verification_receipt(receipt)?;
    machine_form(receipt)
}

pub fn from_succeeding_sop_verification_machine_form(
    value: &str,
) -> Result<SucceedingSopVerificationReceipt, SucceedingSopFault> {
    validate_machine_form_bound(value)?;
    let receipt: SucceedingSopVerificationReceipt =
        serde_json::from_str(value).map_err(machine_fault)?;
    validate_succeeding_sop_verification_receipt(&receipt)?;
    Ok(receipt)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedRequestState {
    pub completed_dependency_refs: BTreeSet<SemanticId>,
    pub required_work_evidence: BTreeSet<SemanticId>,
}

fn derive_work_evidence(
    request: &SucceedingSopRequest,
    selected_step: &crate::WorkPlanStep,
) -> Result<BTreeSet<SemanticId>, SucceedingSopFault> {
    let mut evidence = request.lifecycle_request.evidence_refs.clone();
    evidence.extend(selected_step.evidence_refs.iter().cloned());
    let plan = &request.lifecycle_request.work_plan_proposal.request.plan;
    for dependency in &selected_step.dependency_refs {
        let dependency_step = plan
            .steps
            .iter()
            .find(|step| step.step_id == *dependency)
            .ok_or_else(|| {
                fault(
                    SucceedingSopFaultCode::InvalidDependency,
                    "dependency plan step is absent",
                )
            })?;
        evidence.extend(dependency_step.evidence_refs.iter().cloned());
        for transition in request
            .lifecycle_checkpoint
            .transitions
            .iter()
            .filter(|transition| transition.step_ref == *dependency)
        {
            evidence.extend(transition.evidence_refs.iter().cloned());
        }
    }
    validate_evidence_bound(&evidence, MAX_WORK_EVIDENCE_REFS, "work evidence")?;
    Ok(evidence)
}

fn validate_author_identity(request: &SucceedingSopRequest) -> Result<(), SucceedingSopFault> {
    let boot = &request
        .lifecycle_request
        .work_plan_proposal
        .request
        .boot_proposal
        .request;
    let plan = &request.lifecycle_request.work_plan_proposal.request.plan;
    if request.proposal_id == request.lifecycle_request.lifecycle_id
        || request.proposal_id == request.selected_step_ref
        || request.proposal_id == request.selected_attempt_ref
        || request.proposal_id == plan.plan_id
        || request.proposal_id == boot.boot_sop.canonical_sop_ref
        || request.proposal_id == boot.boot_sop.sop_revision_ref
        || request.author_ref == request.proposal_id
        || request.author_ref == request.lifecycle_request.lifecycle_id
        || request.author_ref == request.selected_step_ref
        || request.author_ref == request.selected_attempt_ref
        || request.author_ref == plan.plan_id
        || request.author_ref == boot.boot_sop.canonical_sop_ref
        || request.author_ref == boot.boot_sop.sop_revision_ref
    {
        return Err(fault(
            SucceedingSopFaultCode::InvalidAuthor,
            "proposal or author identity collides with causal lineage",
        ));
    }
    Ok(())
}

fn validate_source_subject(value: &str) -> Result<(), SucceedingSopFault> {
    if value.is_empty()
        || value.len() > MAX_SUBJECT_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(fault(
            SucceedingSopFaultCode::InvalidSource,
            "source subject is empty untrimmed controlled or oversized",
        ));
    }
    Ok(())
}

fn validate_source_text(value: &str) -> Result<(), SucceedingSopFault> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_SOURCE_BYTES
        || !bytes.ends_with(b"\n")
        || (bytes.len() > 1 && bytes[bytes.len() - 2] == b'\n')
        || value
            .chars()
            .any(|ch| ch == '\0' || ch == '\r' || (ch.is_control() && ch != '\n' && ch != '\t'))
    {
        return Err(fault(
            SucceedingSopFaultCode::InvalidSource,
            "source text is empty noncanonical controlled or oversized",
        ));
    }
    Ok(())
}

fn validate_frontier(values: &BTreeSet<String>) -> Result<(), SucceedingSopFault> {
    if values.is_empty()
        || values.len() > MAX_FRONTIER_ENTRIES
        || values.iter().any(|value| {
            value.is_empty()
                || value.len() > MAX_FRONTIER_ENTRY_BYTES
                || value.trim() != value
                || value.chars().any(char::is_control)
        })
    {
        return Err(fault(
            SucceedingSopFaultCode::InvalidFrontier,
            "unresolved frontier is empty malformed or oversized",
        ));
    }
    Ok(())
}

fn validate_evidence_bound(
    values: &BTreeSet<SemanticId>,
    maximum: usize,
    label: &str,
) -> Result<(), SucceedingSopFault> {
    if values.is_empty() || values.len() > maximum {
        return Err(fault(
            SucceedingSopFaultCode::InvalidEvidence,
            format!("{label} count differs"),
        ));
    }
    Ok(())
}

fn validate_digest(digest: &ContentDigest, label: &str) -> Result<(), SucceedingSopFault> {
    let valid = digest.algorithm == "sha256"
        && digest.value.len() == 64
        && digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(fault(
            SucceedingSopFaultCode::InvalidDigest,
            format!("{label} must be lowercase SHA-256"),
        ))
    }
}

fn required_review_obligations() -> BTreeSet<String> {
    SUCCEEDING_SOP_REVIEW_OBLIGATIONS
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn required_verified_checks() -> BTreeSet<String> {
    SUCCEEDING_SOP_VERIFIED_CHECKS
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn sha256_form<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, SucceedingSopFault> {
    let body = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + body.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&body);
    Ok(sha256_bytes(&bytes))
}

fn machine_form(value: &impl Serialize) -> Result<String, SucceedingSopFault> {
    let value = serde_json::to_string(value).map_err(machine_fault)?;
    validate_machine_form_bound(&value)?;
    Ok(value)
}

fn validate_machine_form_bound(value: &str) -> Result<(), SucceedingSopFault> {
    if value.is_empty() || value.len() > SUCCEEDING_SOP_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            SucceedingSopFaultCode::InvalidBound,
            "machine form is empty or oversized",
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

fn machine_fault(error: serde_json::Error) -> SucceedingSopFault {
    fault(
        SucceedingSopFaultCode::InvalidMachineForm,
        format!("succeeding SOP machine form failed: {error}"),
    )
}

fn fault(code: SucceedingSopFaultCode, message: impl Into<String>) -> SucceedingSopFault {
    SucceedingSopFault {
        code,
        message: message.into().chars().take(512).collect(),
    }
}
