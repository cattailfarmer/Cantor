//! Pure lifecycle representation over an exact SWA-02 work-plan proposal.
//!
//! Transitions retain supplied receipt references but do not issue, authenticate,
//! or interpret those receipts. This module performs no work or external action.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    ContentDigest, ObjectiveWorkPlanProposal, SemanticId, WorkCapability,
    WorkCapabilityDisposition, sha256_bytes, validate_objective_work_plan_proposal,
};

pub const SELF_WORK_LIFECYCLE_REQUEST_PROFILE: &str = "cantor-self-work-lifecycle-request/0.1";
pub const SELF_WORK_LIFECYCLE_CHECKPOINT_PROFILE: &str =
    "cantor-self-work-lifecycle-checkpoint/0.1";
pub const SELF_WORK_LIFECYCLE_TRANSITION_PROFILE: &str =
    "cantor-self-work-lifecycle-transition/0.1";
pub const SELF_WORK_LIFECYCLE_PROPOSAL_PROFILE: &str = "cantor-self-work-lifecycle-proposal/0.1";
pub const SELF_WORK_LIFECYCLE_NON_AUTHORITY: &str = "Pure lifecycle representation and validation only. Supplied receipt references are not issued, authenticated, admitted, or interpreted here. No capability is granted, no process or work is started, no workspace is read or mutated, no test is run, no update is applied, no review is performed, no commit or push occurs, no provider or external effect is invoked, and no succeeding SOP is authored, signed, or activated.";

const REQUEST_DOMAIN: &str = "cantor.self-work-lifecycle.request.v1";
const CHECKPOINT_DOMAIN: &str = "cantor.self-work-lifecycle.checkpoint.v1";
const PROPOSAL_DOMAIN: &str = "cantor.self-work-lifecycle.proposal.v1";
const MAX_EVIDENCE_REFS: usize = 32;
const MAX_RECEIPT_PROFILE_BYTES: usize = 128;

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfWorkLifecycleState {
    PendingDependencies,
    ReadyAwaitingAdmission,
    Active,
    Stopped,
    Resumable,
    Failed,
    AwaitingReview,
    Complete,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfWorkTransitionKind {
    Start,
    Stop,
    MarkResumable,
    Resume,
    Fail,
    SubmitForReview,
    AcceptReview,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfWorkLifecycleAuthority {
    RepresentationOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfWorkLifecycleDisposition {
    PreparedNotExecuting,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalReceiptReference {
    pub receipt_profile: String,
    pub receipt_ref: SemanticId,
    pub receipt_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfWorkLifecycleRequest {
    pub profile: String,
    pub lifecycle_id: SemanticId,
    pub work_plan_proposal: ObjectiveWorkPlanProposal,
    pub maximum_transitions: u64,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub unresolved_account: BTreeSet<String>,
    pub non_authority: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfWorkStepLifecycle {
    pub step_ref: SemanticId,
    pub ordinal: u32,
    pub attempt_ref: SemanticId,
    pub state: SelfWorkLifecycleState,
    pub state_sequence: u64,
    pub last_transition_ref: Option<SemanticId>,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfWorkLifecycleTransition {
    pub profile: String,
    pub transition_id: SemanticId,
    pub lifecycle_ref: SemanticId,
    pub sequence: u64,
    pub predecessor_checkpoint_digest: ContentDigest,
    pub step_ref: SemanticId,
    pub attempt_ref: SemanticId,
    pub kind: SelfWorkTransitionKind,
    pub prior_state: SelfWorkLifecycleState,
    pub successor_state: SelfWorkLifecycleState,
    pub capability_receipt: Option<ExternalReceiptReference>,
    pub review_receipt: Option<ExternalReceiptReference>,
    pub evidence_refs: BTreeSet<SemanticId>,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfWorkLifecycleCheckpoint {
    pub profile: String,
    pub lifecycle_ref: SemanticId,
    pub request_digest: ContentDigest,
    pub sequence: u64,
    pub predecessor_checkpoint_digest: Option<ContentDigest>,
    pub step_states: BTreeMap<SemanticId, SelfWorkStepLifecycle>,
    pub transitions: Vec<SelfWorkLifecycleTransition>,
    pub capability_account: BTreeMap<WorkCapability, WorkCapabilityDisposition>,
    pub unresolved_account: BTreeSet<String>,
    pub checkpoint_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfWorkLifecycleProposal {
    pub profile: String,
    pub request: SelfWorkLifecycleRequest,
    pub disposition: SelfWorkLifecycleDisposition,
    pub authority: SelfWorkLifecycleAuthority,
    pub checkpoint: SelfWorkLifecycleCheckpoint,
    pub request_digest: ContentDigest,
    pub proposal_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfWorkLifecycleFaultCode {
    InvalidProfile,
    InvalidWorkPlan,
    InvalidIdentity,
    InvalidBound,
    InvalidEvidence,
    InvalidUnresolvedAccount,
    InvalidAuthority,
    InvalidState,
    InvalidTransition,
    InvalidReceiptReference,
    InvalidCorrespondence,
    InvalidDigest,
    InvalidMachineForm,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfWorkLifecycleFault {
    pub code: SelfWorkLifecycleFaultCode,
    pub message: String,
}

impl fmt::Display for SelfWorkLifecycleFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for SelfWorkLifecycleFault {}

pub fn compile_self_work_lifecycle(
    request: &SelfWorkLifecycleRequest,
) -> Result<SelfWorkLifecycleProposal, SelfWorkLifecycleFault> {
    validate_self_work_lifecycle_request(request)?;
    let request_digest = self_work_lifecycle_request_digest(request)?;
    let checkpoint = initial_checkpoint(request, &request_digest)?;
    let mut proposal = SelfWorkLifecycleProposal {
        profile: SELF_WORK_LIFECYCLE_PROPOSAL_PROFILE.to_owned(),
        request: request.clone(),
        disposition: SelfWorkLifecycleDisposition::PreparedNotExecuting,
        authority: SelfWorkLifecycleAuthority::RepresentationOnly,
        checkpoint,
        request_digest,
        proposal_digest: empty_digest(),
    };
    proposal.proposal_digest = self_work_lifecycle_proposal_digest(&proposal)?;
    validate_self_work_lifecycle_proposal(request, &proposal)?;
    Ok(proposal)
}

pub fn advance_self_work_lifecycle(
    request: &SelfWorkLifecycleRequest,
    checkpoint: &SelfWorkLifecycleCheckpoint,
    transition: &SelfWorkLifecycleTransition,
) -> Result<SelfWorkLifecycleCheckpoint, SelfWorkLifecycleFault> {
    validate_self_work_lifecycle_request(request)?;
    validate_self_work_lifecycle_checkpoint(request, checkpoint)?;
    let successor = apply_transition(request, checkpoint, transition)?;
    validate_self_work_lifecycle_checkpoint(request, &successor)?;
    Ok(successor)
}

pub fn validate_self_work_lifecycle_request(
    request: &SelfWorkLifecycleRequest,
) -> Result<(), SelfWorkLifecycleFault> {
    if request.profile != SELF_WORK_LIFECYCLE_REQUEST_PROFILE {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidProfile,
            "request profile differs",
        ));
    }
    validate_objective_work_plan_proposal(
        &request.work_plan_proposal.request,
        &request.work_plan_proposal,
    )
    .map_err(|error| {
        fault(
            SelfWorkLifecycleFaultCode::InvalidWorkPlan,
            error.to_string(),
        )
    })?;
    let boot = &request.work_plan_proposal.request.boot_proposal.request;
    if request.lifecycle_id == boot.boot_request_id
        || request.lifecycle_id == boot.proposed_session_id
        || request.lifecycle_id == request.work_plan_proposal.request.plan.plan_id
    {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidIdentity,
            "lifecycle identity collides",
        ));
    }
    if request.maximum_transitions == 0
        || request.maximum_transitions > boot.bounds.maximum_checkpoints as u64
    {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidBound,
            "transition bound differs",
        ));
    }
    validate_evidence(&request.evidence_refs)?;
    if request.unresolved_account != required_unresolved_account() {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidUnresolvedAccount,
            "unresolved account differs",
        ));
    }
    if request.non_authority != SELF_WORK_LIFECYCLE_NON_AUTHORITY {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidAuthority,
            "non-authority differs",
        ));
    }
    Ok(())
}

pub fn validate_self_work_lifecycle_checkpoint(
    request: &SelfWorkLifecycleRequest,
    checkpoint: &SelfWorkLifecycleCheckpoint,
) -> Result<(), SelfWorkLifecycleFault> {
    validate_self_work_lifecycle_request(request)?;
    if checkpoint.profile != SELF_WORK_LIFECYCLE_CHECKPOINT_PROFILE
        || checkpoint.lifecycle_ref != request.lifecycle_id
        || checkpoint.request_digest != self_work_lifecycle_request_digest(request)?
    {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidCorrespondence,
            "checkpoint header differs",
        ));
    }
    if checkpoint.sequence != checkpoint.transitions.len() as u64
        || checkpoint.sequence > request.maximum_transitions
        || checkpoint.capability_account != request.work_plan_proposal.capability_account
        || checkpoint.unresolved_account != required_unresolved_account()
    {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidState,
            "checkpoint account differs",
        ));
    }
    validate_digest(&checkpoint.checkpoint_digest, "checkpoint digest")?;
    if checkpoint.checkpoint_digest != self_work_lifecycle_checkpoint_digest(checkpoint)? {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidDigest,
            "checkpoint digest differs",
        ));
    }
    let request_digest = self_work_lifecycle_request_digest(request)?;
    let mut replay = initial_checkpoint(request, &request_digest)?;
    for transition in &checkpoint.transitions {
        replay = apply_transition(request, &replay, transition)?;
    }
    if replay != *checkpoint {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidCorrespondence,
            "checkpoint replay differs",
        ));
    }
    Ok(())
}

pub fn validate_self_work_lifecycle_proposal(
    expected_request: &SelfWorkLifecycleRequest,
    proposal: &SelfWorkLifecycleProposal,
) -> Result<(), SelfWorkLifecycleFault> {
    if proposal.profile != SELF_WORK_LIFECYCLE_PROPOSAL_PROFILE
        || &proposal.request != expected_request
        || proposal.disposition != SelfWorkLifecycleDisposition::PreparedNotExecuting
        || proposal.authority != SelfWorkLifecycleAuthority::RepresentationOnly
    {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidCorrespondence,
            "proposal output differs",
        ));
    }
    validate_self_work_lifecycle_checkpoint(expected_request, &proposal.checkpoint)?;
    if proposal.request_digest != self_work_lifecycle_request_digest(expected_request)? {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidDigest,
            "proposal request digest differs",
        ));
    }
    validate_digest(&proposal.proposal_digest, "proposal digest")?;
    if proposal.proposal_digest != self_work_lifecycle_proposal_digest(proposal)? {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidDigest,
            "proposal digest differs",
        ));
    }
    Ok(())
}

pub fn self_work_lifecycle_request_digest(
    request: &SelfWorkLifecycleRequest,
) -> Result<ContentDigest, SelfWorkLifecycleFault> {
    sha256_form(REQUEST_DOMAIN, request)
}

pub fn self_work_lifecycle_checkpoint_digest(
    checkpoint: &SelfWorkLifecycleCheckpoint,
) -> Result<ContentDigest, SelfWorkLifecycleFault> {
    let mut body = checkpoint.clone();
    body.checkpoint_digest = empty_digest();
    sha256_form(CHECKPOINT_DOMAIN, &body)
}

pub fn self_work_lifecycle_proposal_digest(
    proposal: &SelfWorkLifecycleProposal,
) -> Result<ContentDigest, SelfWorkLifecycleFault> {
    let mut body = proposal.clone();
    body.proposal_digest = empty_digest();
    sha256_form(PROPOSAL_DOMAIN, &body)
}

pub fn to_self_work_lifecycle_request_machine_form(
    request: &SelfWorkLifecycleRequest,
) -> Result<String, SelfWorkLifecycleFault> {
    validate_self_work_lifecycle_request(request)?;
    serde_json::to_string(request).map_err(machine_fault)
}

pub fn from_self_work_lifecycle_request_machine_form(
    value: &str,
) -> Result<SelfWorkLifecycleRequest, SelfWorkLifecycleFault> {
    let request = serde_json::from_str(value).map_err(machine_fault)?;
    validate_self_work_lifecycle_request(&request)?;
    Ok(request)
}

pub fn to_self_work_lifecycle_proposal_machine_form(
    proposal: &SelfWorkLifecycleProposal,
) -> Result<String, SelfWorkLifecycleFault> {
    validate_self_work_lifecycle_proposal(&proposal.request, proposal)?;
    serde_json::to_string(proposal).map_err(machine_fault)
}

pub fn from_self_work_lifecycle_proposal_machine_form(
    value: &str,
) -> Result<SelfWorkLifecycleProposal, SelfWorkLifecycleFault> {
    let proposal: SelfWorkLifecycleProposal = serde_json::from_str(value).map_err(machine_fault)?;
    validate_self_work_lifecycle_proposal(&proposal.request, &proposal)?;
    Ok(proposal)
}

fn initial_checkpoint(
    request: &SelfWorkLifecycleRequest,
    request_digest: &ContentDigest,
) -> Result<SelfWorkLifecycleCheckpoint, SelfWorkLifecycleFault> {
    let mut step_states = BTreeMap::new();
    for step in &request.work_plan_proposal.request.plan.steps {
        let state = if step.dependency_refs.is_empty() {
            SelfWorkLifecycleState::ReadyAwaitingAdmission
        } else {
            SelfWorkLifecycleState::PendingDependencies
        };
        let lifecycle = SelfWorkStepLifecycle {
            step_ref: step.step_id.clone(),
            ordinal: step.ordinal,
            attempt_ref: derived_attempt_ref(&request.lifecycle_id, &step.step_id)?,
            state,
            state_sequence: 0,
            last_transition_ref: None,
        };
        step_states.insert(step.step_id.clone(), lifecycle);
    }
    let mut checkpoint = SelfWorkLifecycleCheckpoint {
        profile: SELF_WORK_LIFECYCLE_CHECKPOINT_PROFILE.to_owned(),
        lifecycle_ref: request.lifecycle_id.clone(),
        request_digest: request_digest.clone(),
        sequence: 0,
        predecessor_checkpoint_digest: None,
        step_states,
        transitions: Vec::new(),
        capability_account: request.work_plan_proposal.capability_account.clone(),
        unresolved_account: required_unresolved_account(),
        checkpoint_digest: empty_digest(),
    };
    checkpoint.checkpoint_digest = self_work_lifecycle_checkpoint_digest(&checkpoint)?;
    Ok(checkpoint)
}

fn apply_transition(
    request: &SelfWorkLifecycleRequest,
    checkpoint: &SelfWorkLifecycleCheckpoint,
    transition: &SelfWorkLifecycleTransition,
) -> Result<SelfWorkLifecycleCheckpoint, SelfWorkLifecycleFault> {
    if checkpoint.sequence >= request.maximum_transitions {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidBound,
            "transition ceiling reached",
        ));
    }
    if transition.profile != SELF_WORK_LIFECYCLE_TRANSITION_PROFILE
        || transition.lifecycle_ref != request.lifecycle_id
        || transition.sequence != checkpoint.sequence + 1
        || transition.predecessor_checkpoint_digest != checkpoint.checkpoint_digest
        || checkpoint
            .transitions
            .iter()
            .any(|item| item.transition_id == transition.transition_id)
    {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidCorrespondence,
            "transition header differs",
        ));
    }
    validate_evidence(&transition.evidence_refs)?;
    let current = checkpoint
        .step_states
        .get(&transition.step_ref)
        .ok_or_else(|| {
            fault(
                SelfWorkLifecycleFaultCode::InvalidIdentity,
                "transition step is absent",
            )
        })?;
    if transition.attempt_ref != current.attempt_ref || transition.prior_state != current.state {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidCorrespondence,
            "transition attempt or prior state differs",
        ));
    }
    let expected_successor = transition_successor(transition.kind, current.state)?;
    if transition.successor_state != expected_successor {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidTransition,
            "transition successor differs",
        ));
    }
    validate_transition_receipts(transition)?;

    let mut successor = checkpoint.clone();
    successor.sequence += 1;
    successor.predecessor_checkpoint_digest = Some(checkpoint.checkpoint_digest.clone());
    let state = successor
        .step_states
        .get_mut(&transition.step_ref)
        .expect("validated step");
    state.state = expected_successor;
    state.state_sequence = successor.sequence;
    state.last_transition_ref = Some(transition.transition_id.clone());
    successor.transitions.push(transition.clone());

    if expected_successor == SelfWorkLifecycleState::Complete {
        release_ready_dependencies(request, &mut successor.step_states);
    }
    if successor
        .step_states
        .values()
        .filter(|state| state.state == SelfWorkLifecycleState::Active)
        .count()
        > 1
    {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidState,
            "multiple active steps",
        ));
    }
    successor.checkpoint_digest = empty_digest();
    successor.checkpoint_digest = self_work_lifecycle_checkpoint_digest(&successor)?;
    Ok(successor)
}

fn transition_successor(
    kind: SelfWorkTransitionKind,
    prior: SelfWorkLifecycleState,
) -> Result<SelfWorkLifecycleState, SelfWorkLifecycleFault> {
    use SelfWorkLifecycleState::*;
    use SelfWorkTransitionKind::*;
    match (kind, prior) {
        (Start, ReadyAwaitingAdmission) | (Resume, Resumable) => Ok(Active),
        (Stop, Active) => Ok(Stopped),
        (MarkResumable, Stopped) => Ok(Resumable),
        (Fail, Active | Stopped | Resumable | AwaitingReview) => Ok(Failed),
        (SubmitForReview, Active) => Ok(AwaitingReview),
        (AcceptReview, AwaitingReview) => Ok(Complete),
        _ => Err(fault(
            SelfWorkLifecycleFaultCode::InvalidTransition,
            "illegal lifecycle edge",
        )),
    }
}

fn validate_transition_receipts(
    transition: &SelfWorkLifecycleTransition,
) -> Result<(), SelfWorkLifecycleFault> {
    use SelfWorkTransitionKind::*;
    let needs_capability = matches!(transition.kind, Start | Resume);
    let needs_review = transition.kind == AcceptReview;
    if transition.capability_receipt.is_some() != needs_capability
        || transition.review_receipt.is_some() != needs_review
    {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidReceiptReference,
            "transition receipt shape differs",
        ));
    }
    if let Some(receipt) = &transition.capability_receipt {
        validate_receipt(receipt)?;
    }
    if let Some(receipt) = &transition.review_receipt {
        validate_receipt(receipt)?;
    }
    Ok(())
}

fn validate_receipt(receipt: &ExternalReceiptReference) -> Result<(), SelfWorkLifecycleFault> {
    if receipt.receipt_profile.is_empty()
        || receipt.receipt_profile.len() > MAX_RECEIPT_PROFILE_BYTES
        || receipt.receipt_profile.trim() != receipt.receipt_profile
        || receipt.receipt_profile.chars().any(char::is_control)
    {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidReceiptReference,
            "receipt profile differs",
        ));
    }
    validate_digest(&receipt.receipt_digest, "receipt digest")
}

fn release_ready_dependencies(
    request: &SelfWorkLifecycleRequest,
    states: &mut BTreeMap<SemanticId, SelfWorkStepLifecycle>,
) {
    for step in &request.work_plan_proposal.request.plan.steps {
        let ready = step.dependency_refs.iter().all(|dependency| {
            states
                .get(dependency)
                .is_some_and(|state| state.state == SelfWorkLifecycleState::Complete)
        });
        if ready
            && let Some(state) = states.get_mut(&step.step_id)
            && state.state == SelfWorkLifecycleState::PendingDependencies
        {
            state.state = SelfWorkLifecycleState::ReadyAwaitingAdmission;
        }
    }
}

fn derived_attempt_ref(
    lifecycle_ref: &SemanticId,
    step_ref: &SemanticId,
) -> Result<SemanticId, SelfWorkLifecycleFault> {
    let digest =
        sha256_bytes(format!("{}\0{}", lifecycle_ref.as_str(), step_ref.as_str()).as_bytes());
    SemanticId::new(format!("self-work-attempt:{}", digest.value)).map_err(|error| {
        fault(
            SelfWorkLifecycleFaultCode::InvalidIdentity,
            error.to_string(),
        )
    })
}

fn required_unresolved_account() -> BTreeSet<String> {
    [
        "capabilities_not_granted",
        "physical_work_unobserved",
        "succeeding_sop_not_authored",
        "updates_not_applied",
        "workspace_not_admitted",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn validate_evidence(values: &BTreeSet<SemanticId>) -> Result<(), SelfWorkLifecycleFault> {
    if values.is_empty() || values.len() > MAX_EVIDENCE_REFS {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidEvidence,
            "evidence count differs",
        ));
    }
    Ok(())
}

fn validate_digest(digest: &ContentDigest, label: &str) -> Result<(), SelfWorkLifecycleFault> {
    let valid = digest.algorithm == "sha256"
        && digest.value.len() == 64
        && digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid {
        return Err(fault(
            SelfWorkLifecycleFaultCode::InvalidDigest,
            format!("{label} must be lower-case SHA256"),
        ));
    }
    Ok(())
}

fn sha256_form<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<ContentDigest, SelfWorkLifecycleFault> {
    let body = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + body.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&body);
    Ok(sha256_bytes(&bytes))
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn machine_fault(error: serde_json::Error) -> SelfWorkLifecycleFault {
    fault(
        SelfWorkLifecycleFaultCode::InvalidMachineForm,
        format!("self work lifecycle machine form failed: {error}"),
    )
}

fn fault(code: SelfWorkLifecycleFaultCode, message: impl Into<String>) -> SelfWorkLifecycleFault {
    SelfWorkLifecycleFault {
        code,
        message: message.into(),
    }
}
