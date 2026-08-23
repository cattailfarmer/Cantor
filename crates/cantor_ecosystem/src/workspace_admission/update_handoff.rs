//! Pure preparation of a self-work update handoff from a ready lifecycle step
//! and a caller-supplied, self-consistent prior workspace admission.
//!
//! This module does not authenticate or refresh the supplied admission. It does
//! not read or change a workspace. Its only successful disposition requires a
//! later physical revalidation under a separately governed profile.

use std::{collections::BTreeSet, fmt};

use cantor_core::{
    ContentDigest, SelfWorkLifecycleCheckpoint, SelfWorkLifecycleRequest, SelfWorkLifecycleState,
    SemanticId, sha256_bytes, validate_self_work_lifecycle_checkpoint,
    validate_self_work_lifecycle_request,
};
use serde::{Deserialize, Serialize};

use crate::phase3_evidence::{CandidateChangeKind, PHASE3_MACHINE_FORMS_PROFILE};

use super::{
    AdmissionReceipt, CandidateWorkspaceRequest, validate_request_claims,
    validate_supplied_admission_integrity,
};

pub const SELF_WORK_UPDATE_HANDOFF_REQUEST_PROFILE: &str =
    "cantor-self-work-update-handoff-request/0.1";
pub const SELF_WORK_UPDATE_HANDOFF_PROPOSAL_PROFILE: &str =
    "cantor-self-work-update-handoff-proposal/0.1";
pub const SELF_WORK_UPDATE_HANDOFF_NON_AUTHORITY: &str = "Pure representation and validation of a proposed self-work update handoff only. The supplied workspace admission is checked for internal form integrity but is not authenticated, reacquired, current, or fresh. No capability is granted, no process is launched, no workspace is read or changed, no update is applied or verified, no acceptance or rollback is performed, no cleanup, commit, or push occurs, no provider or external effect is invoked, and no succeeding SOP is authored, signed, or activated.";

pub const SELF_WORK_UPDATE_HANDOFF_REQUIRED_UNRESOLVED: [&str; 9] = [
    "acceptance_not_granted",
    "cleanup_not_authorized",
    "commit_not_authorized",
    "mutation_not_performed",
    "physical_freshness_unverified",
    "push_not_authorized",
    "rollback_not_authorized",
    "succeeding_sop_not_authored_signed_or_activated",
    "update_verification_not_performed",
];

pub const SELF_WORK_UPDATE_HANDOFF_VERIFICATION_OBLIGATIONS: [&str; 8] = [
    "authorize_cleanup_separately",
    "authorize_commit_and_push_separately",
    "authorize_rollback_separately",
    "govern_succeeding_sop_separately",
    "independently_review_acceptance",
    "physically_revalidate_workspace_immediately_before_mutation",
    "run_only_a_separately_governed_bounded_writer",
    "verify_exact_post_mutation_changes",
];

const REQUEST_DOMAIN: &str = "cantor.self-work-update-handoff.request.v1";
const PROPOSAL_DOMAIN: &str = "cantor.self-work-update-handoff.proposal.v1";
const MAX_CHANGES: usize = 64;
const MAX_EVIDENCE_REFS: usize = 64;
const MAX_MACHINE_FORM_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfWorkUpdateHandoffAuthority {
    RepresentationOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfWorkUpdateHandoffDisposition {
    PreparedAwaitingPhysicalRevalidation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfWorkUpdateFaultDisposition {
    QuarantineWithoutCleanup,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposedPathChange {
    pub relative_path: String,
    pub change_kind: CandidateChangeKind,
    pub expected_base_sha256: Option<ContentDigest>,
    pub desired_content_sha256: Option<ContentDigest>,
    pub desired_mode: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfWorkUpdateHandoffRequest {
    pub profile: String,
    pub handoff_id: SemanticId,
    pub phase3_machine_forms_profile: String,
    pub lifecycle_request: SelfWorkLifecycleRequest,
    pub lifecycle_checkpoint: SelfWorkLifecycleCheckpoint,
    pub selected_step_ref: SemanticId,
    pub selected_attempt_ref: SemanticId,
    pub workspace_request: CandidateWorkspaceRequest,
    pub prior_admission_receipt: AdmissionReceipt,
    pub proposed_changes: Vec<ProposedPathChange>,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub unresolved_account: BTreeSet<String>,
    pub verification_obligations: BTreeSet<String>,
    pub non_authority: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfWorkUpdateHandoffProposal {
    pub profile: String,
    pub request: SelfWorkUpdateHandoffRequest,
    pub handoff_ref: SemanticId,
    pub lifecycle_ref: SemanticId,
    pub selected_step_ref: SemanticId,
    pub selected_attempt_ref: SemanticId,
    pub workspace_candidate_uuid: String,
    pub workspace_correlation_uuid: String,
    pub base_commit: String,
    pub branch_ref: String,
    pub proposed_changes: Vec<ProposedPathChange>,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub unresolved_account: BTreeSet<String>,
    pub verification_obligations: BTreeSet<String>,
    pub disposition: SelfWorkUpdateHandoffDisposition,
    pub authority: SelfWorkUpdateHandoffAuthority,
    pub fault_disposition: SelfWorkUpdateFaultDisposition,
    pub non_authority: String,
    pub request_digest: ContentDigest,
    pub proposal_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfWorkUpdateHandoffFaultCode {
    InvalidProfile,
    InvalidLifecycle,
    InvalidState,
    InvalidWorkspaceClaim,
    InvalidAdmissionReceipt,
    InvalidPath,
    InvalidChange,
    InvalidEvidence,
    InvalidBound,
    InvalidUnresolvedAccount,
    InvalidAuthority,
    InvalidCorrespondence,
    InvalidDigest,
    InvalidMachineForm,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfWorkUpdateHandoffFault {
    pub code: SelfWorkUpdateHandoffFaultCode,
    pub message: String,
}

impl fmt::Display for SelfWorkUpdateHandoffFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for SelfWorkUpdateHandoffFault {}

pub fn compile_self_work_update_handoff(
    request: &SelfWorkUpdateHandoffRequest,
) -> Result<SelfWorkUpdateHandoffProposal, SelfWorkUpdateHandoffFault> {
    validate_self_work_update_handoff_request(request)?;
    let request_digest = self_work_update_handoff_request_digest(request)?;
    let mut proposal = SelfWorkUpdateHandoffProposal {
        profile: SELF_WORK_UPDATE_HANDOFF_PROPOSAL_PROFILE.to_owned(),
        request: request.clone(),
        handoff_ref: request.handoff_id.clone(),
        lifecycle_ref: request.lifecycle_request.lifecycle_id.clone(),
        selected_step_ref: request.selected_step_ref.clone(),
        selected_attempt_ref: request.selected_attempt_ref.clone(),
        workspace_candidate_uuid: request.workspace_request.candidate_uuid.clone(),
        workspace_correlation_uuid: request.workspace_request.correlation_uuid.clone(),
        base_commit: request.workspace_request.expected_base_commit.clone(),
        branch_ref: request.workspace_request.expected_branch_ref.clone(),
        proposed_changes: request.proposed_changes.clone(),
        evidence_refs: request.evidence_refs.clone(),
        unresolved_account: request.unresolved_account.clone(),
        verification_obligations: request.verification_obligations.clone(),
        disposition: SelfWorkUpdateHandoffDisposition::PreparedAwaitingPhysicalRevalidation,
        authority: SelfWorkUpdateHandoffAuthority::RepresentationOnly,
        fault_disposition: SelfWorkUpdateFaultDisposition::QuarantineWithoutCleanup,
        non_authority: request.non_authority.clone(),
        request_digest,
        proposal_digest: empty_digest(),
    };
    proposal.proposal_digest = self_work_update_handoff_proposal_digest(&proposal)?;
    validate_self_work_update_handoff_proposal(request, &proposal)?;
    Ok(proposal)
}

pub fn validate_self_work_update_handoff_request(
    request: &SelfWorkUpdateHandoffRequest,
) -> Result<(), SelfWorkUpdateHandoffFault> {
    if request.profile != SELF_WORK_UPDATE_HANDOFF_REQUEST_PROFILE
        || request.phase3_machine_forms_profile != PHASE3_MACHINE_FORMS_PROFILE
    {
        return Err(fault(
            SelfWorkUpdateHandoffFaultCode::InvalidProfile,
            "handoff or Phase 3 machine-form profile differs",
        ));
    }
    validate_self_work_lifecycle_request(&request.lifecycle_request).map_err(|error| {
        fault(
            SelfWorkUpdateHandoffFaultCode::InvalidLifecycle,
            error.to_string(),
        )
    })?;
    validate_self_work_lifecycle_checkpoint(
        &request.lifecycle_request,
        &request.lifecycle_checkpoint,
    )
    .map_err(|error| {
        fault(
            SelfWorkUpdateHandoffFaultCode::InvalidLifecycle,
            error.to_string(),
        )
    })?;
    if request.handoff_id == request.lifecycle_request.lifecycle_id
        || request.handoff_id == request.selected_step_ref
        || request.handoff_id == request.selected_attempt_ref
    {
        return Err(fault(
            SelfWorkUpdateHandoffFaultCode::InvalidCorrespondence,
            "handoff identity collides with lifecycle identity",
        ));
    }
    let selected = request
        .lifecycle_checkpoint
        .step_states
        .get(&request.selected_step_ref)
        .ok_or_else(|| {
            fault(
                SelfWorkUpdateHandoffFaultCode::InvalidState,
                "selected lifecycle step is absent",
            )
        })?;
    if selected.step_ref != request.selected_step_ref
        || selected.attempt_ref != request.selected_attempt_ref
        || selected.state != SelfWorkLifecycleState::ReadyAwaitingAdmission
    {
        return Err(fault(
            SelfWorkUpdateHandoffFaultCode::InvalidState,
            "selected step is not the exact ready attempt",
        ));
    }
    validate_request_claims(&request.workspace_request).map_err(|error| {
        fault(
            SelfWorkUpdateHandoffFaultCode::InvalidWorkspaceClaim,
            error.to_string(),
        )
    })?;
    validate_supplied_admission_integrity(
        &request.workspace_request,
        &request.prior_admission_receipt,
    )
    .map_err(|error| {
        fault(
            SelfWorkUpdateHandoffFaultCode::InvalidAdmissionReceipt,
            error.to_string(),
        )
    })?;
    validate_changes(
        &request.proposed_changes,
        &request.workspace_request.allowed_relative_paths,
    )?;
    if request.evidence_refs.is_empty() || request.evidence_refs.len() > MAX_EVIDENCE_REFS {
        return Err(fault(
            SelfWorkUpdateHandoffFaultCode::InvalidEvidence,
            "evidence reference count differs",
        ));
    }
    if request.unresolved_account != required_unresolved_account() {
        return Err(fault(
            SelfWorkUpdateHandoffFaultCode::InvalidUnresolvedAccount,
            "unresolved account differs",
        ));
    }
    if request.verification_obligations != required_verification_obligations() {
        return Err(fault(
            SelfWorkUpdateHandoffFaultCode::InvalidCorrespondence,
            "verification obligations differ",
        ));
    }
    if request.non_authority != SELF_WORK_UPDATE_HANDOFF_NON_AUTHORITY {
        return Err(fault(
            SelfWorkUpdateHandoffFaultCode::InvalidAuthority,
            "non-authority differs",
        ));
    }
    Ok(())
}

pub fn validate_self_work_update_handoff_proposal(
    expected_request: &SelfWorkUpdateHandoffRequest,
    proposal: &SelfWorkUpdateHandoffProposal,
) -> Result<(), SelfWorkUpdateHandoffFault> {
    validate_self_work_update_handoff_request(expected_request)?;
    if proposal.profile != SELF_WORK_UPDATE_HANDOFF_PROPOSAL_PROFILE
        || &proposal.request != expected_request
        || proposal.handoff_ref != expected_request.handoff_id
        || proposal.lifecycle_ref != expected_request.lifecycle_request.lifecycle_id
        || proposal.selected_step_ref != expected_request.selected_step_ref
        || proposal.selected_attempt_ref != expected_request.selected_attempt_ref
        || proposal.workspace_candidate_uuid != expected_request.workspace_request.candidate_uuid
        || proposal.workspace_correlation_uuid
            != expected_request.workspace_request.correlation_uuid
        || proposal.base_commit != expected_request.workspace_request.expected_base_commit
        || proposal.branch_ref != expected_request.workspace_request.expected_branch_ref
        || proposal.proposed_changes != expected_request.proposed_changes
        || proposal.evidence_refs != expected_request.evidence_refs
        || proposal.unresolved_account != expected_request.unresolved_account
        || proposal.verification_obligations != expected_request.verification_obligations
        || proposal.disposition
            != SelfWorkUpdateHandoffDisposition::PreparedAwaitingPhysicalRevalidation
        || proposal.authority != SelfWorkUpdateHandoffAuthority::RepresentationOnly
        || proposal.fault_disposition != SelfWorkUpdateFaultDisposition::QuarantineWithoutCleanup
        || proposal.non_authority != expected_request.non_authority
    {
        return Err(fault(
            SelfWorkUpdateHandoffFaultCode::InvalidCorrespondence,
            "proposal output differs from the exact request",
        ));
    }
    if proposal.request_digest != self_work_update_handoff_request_digest(expected_request)? {
        return Err(fault(
            SelfWorkUpdateHandoffFaultCode::InvalidDigest,
            "proposal request digest differs",
        ));
    }
    validate_digest(&proposal.proposal_digest, "proposal digest")?;
    if proposal.proposal_digest != self_work_update_handoff_proposal_digest(proposal)? {
        return Err(fault(
            SelfWorkUpdateHandoffFaultCode::InvalidDigest,
            "proposal digest differs",
        ));
    }
    Ok(())
}

pub fn self_work_update_handoff_request_digest(
    request: &SelfWorkUpdateHandoffRequest,
) -> Result<ContentDigest, SelfWorkUpdateHandoffFault> {
    sha256_form(REQUEST_DOMAIN, request)
}

pub fn self_work_update_handoff_proposal_digest(
    proposal: &SelfWorkUpdateHandoffProposal,
) -> Result<ContentDigest, SelfWorkUpdateHandoffFault> {
    let mut body = proposal.clone();
    body.proposal_digest = empty_digest();
    sha256_form(PROPOSAL_DOMAIN, &body)
}

pub fn to_self_work_update_handoff_request_machine_form(
    request: &SelfWorkUpdateHandoffRequest,
) -> Result<String, SelfWorkUpdateHandoffFault> {
    validate_self_work_update_handoff_request(request)?;
    let value = serde_json::to_string(request).map_err(machine_fault)?;
    validate_machine_form_bound(&value)?;
    Ok(value)
}

pub fn from_self_work_update_handoff_request_machine_form(
    value: &str,
) -> Result<SelfWorkUpdateHandoffRequest, SelfWorkUpdateHandoffFault> {
    validate_machine_form_bound(value)?;
    let request = serde_json::from_str(value).map_err(machine_fault)?;
    validate_self_work_update_handoff_request(&request)?;
    Ok(request)
}

pub fn to_self_work_update_handoff_proposal_machine_form(
    proposal: &SelfWorkUpdateHandoffProposal,
) -> Result<String, SelfWorkUpdateHandoffFault> {
    validate_self_work_update_handoff_proposal(&proposal.request, proposal)?;
    let value = serde_json::to_string(proposal).map_err(machine_fault)?;
    validate_machine_form_bound(&value)?;
    Ok(value)
}

pub fn from_self_work_update_handoff_proposal_machine_form(
    value: &str,
) -> Result<SelfWorkUpdateHandoffProposal, SelfWorkUpdateHandoffFault> {
    validate_machine_form_bound(value)?;
    let proposal: SelfWorkUpdateHandoffProposal =
        serde_json::from_str(value).map_err(machine_fault)?;
    validate_self_work_update_handoff_proposal(&proposal.request, &proposal)?;
    Ok(proposal)
}

fn validate_changes(
    changes: &[ProposedPathChange],
    allowed_paths: &[String],
) -> Result<(), SelfWorkUpdateHandoffFault> {
    if changes.is_empty() || changes.len() > MAX_CHANGES {
        return Err(fault(
            SelfWorkUpdateHandoffFaultCode::InvalidBound,
            "proposed change count differs",
        ));
    }
    let mut prior: Option<&str> = None;
    for change in changes {
        if prior.is_some_and(|value| value >= change.relative_path.as_str()) {
            return Err(fault(
                SelfWorkUpdateHandoffFaultCode::InvalidPath,
                "proposed change paths are not strictly sorted and unique",
            ));
        }
        if allowed_paths
            .binary_search_by(|value| value.as_str().cmp(change.relative_path.as_str()))
            .is_err()
        {
            return Err(fault(
                SelfWorkUpdateHandoffFaultCode::InvalidPath,
                "proposed change path is outside the exact admission allowlist",
            ));
        }
        validate_change_shape(change)?;
        prior = Some(&change.relative_path);
    }
    Ok(())
}

fn validate_change_shape(change: &ProposedPathChange) -> Result<(), SelfWorkUpdateHandoffFault> {
    if let Some(digest) = &change.expected_base_sha256 {
        validate_digest(digest, "expected base digest")?;
    }
    if let Some(digest) = &change.desired_content_sha256 {
        validate_digest(digest, "desired content digest")?;
    }
    if change
        .desired_mode
        .as_deref()
        .is_some_and(|mode| !matches!(mode, "100644" | "100755"))
    {
        return Err(fault(
            SelfWorkUpdateHandoffFaultCode::InvalidChange,
            "desired mode is not 100644 or 100755",
        ));
    }
    let shape_is_valid = match change.change_kind {
        CandidateChangeKind::Add => {
            change.expected_base_sha256.is_none()
                && change.desired_content_sha256.is_some()
                && change.desired_mode.is_some()
        }
        CandidateChangeKind::Modify => {
            change.expected_base_sha256.is_some()
                && change.desired_content_sha256.is_some()
                && change.expected_base_sha256 != change.desired_content_sha256
                && change.desired_mode.is_some()
        }
        CandidateChangeKind::Delete => {
            change.expected_base_sha256.is_some()
                && change.desired_content_sha256.is_none()
                && change.desired_mode.is_none()
        }
        CandidateChangeKind::ModeChange => {
            change.expected_base_sha256.is_some()
                && change.expected_base_sha256 == change.desired_content_sha256
                && change.desired_mode.is_some()
        }
    };
    if shape_is_valid {
        Ok(())
    } else {
        Err(fault(
            SelfWorkUpdateHandoffFaultCode::InvalidChange,
            "proposed change shape differs from its current Phase 3 change kind",
        ))
    }
}

fn validate_digest(digest: &ContentDigest, label: &str) -> Result<(), SelfWorkUpdateHandoffFault> {
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
            SelfWorkUpdateHandoffFaultCode::InvalidDigest,
            format!("{label} must be lowercase SHA-256"),
        ))
    }
}

fn required_unresolved_account() -> BTreeSet<String> {
    SELF_WORK_UPDATE_HANDOFF_REQUIRED_UNRESOLVED
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn required_verification_obligations() -> BTreeSet<String> {
    SELF_WORK_UPDATE_HANDOFF_VERIFICATION_OBLIGATIONS
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn sha256_form<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<ContentDigest, SelfWorkUpdateHandoffFault> {
    let body = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + body.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&body);
    Ok(sha256_bytes(&bytes))
}

fn validate_machine_form_bound(value: &str) -> Result<(), SelfWorkUpdateHandoffFault> {
    if value.len() <= MAX_MACHINE_FORM_BYTES {
        Ok(())
    } else {
        Err(fault(
            SelfWorkUpdateHandoffFaultCode::InvalidBound,
            "machine form exceeds the hard byte bound",
        ))
    }
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn machine_fault(error: serde_json::Error) -> SelfWorkUpdateHandoffFault {
    fault(
        SelfWorkUpdateHandoffFaultCode::InvalidMachineForm,
        format!("self-work update handoff machine form failed: {error}"),
    )
}

fn fault(
    code: SelfWorkUpdateHandoffFaultCode,
    message: impl Into<String>,
) -> SelfWorkUpdateHandoffFault {
    SelfWorkUpdateHandoffFault {
        code,
        message: message.into().chars().take(512).collect(),
    }
}
