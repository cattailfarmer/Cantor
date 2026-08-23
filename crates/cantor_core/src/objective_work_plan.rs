//! Pure objective/work-plan admission over an exact SWA-01 proposal.
//!
//! Every requested capability remains explicitly not granted. This module
//! performs no workspace, process, provider, publication, persistence, or
//! external-effect action.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    ContentDigest, SemanticId, SopBootSessionProposal, sha256_bytes,
    validate_sop_boot_session_proposal,
};

pub const OBJECTIVE_WORK_PLAN_REQUEST_PROFILE: &str = "cantor-objective-work-plan-request/0.1";
pub const OBJECTIVE_WORK_PLAN_PROPOSAL_PROFILE: &str = "cantor-objective-work-plan-proposal/0.1";
pub const OBJECTIVE_WORK_PLAN_NON_AUTHORITY: &str = "Pure objective and work-plan proposal. No capability is granted, no session is opened, no process is launched, no workspace is admitted read or mutated, no test or work is executed, no update is applied, no commit or push occurs, no provider or external effect is invoked, and no succeeding SOP is authored or activated.";

const REQUEST_DOMAIN: &str = "cantor.objective-work-plan.request.v1";
const PROPOSAL_DOMAIN: &str = "cantor.objective-work-plan.proposal.v1";
const MAX_STEPS: usize = 64;
const MAX_EVIDENCE_REFS: usize = 32;
const MAX_LABEL_BYTES: usize = 256;

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkCapability {
    WorkspaceRead,
    WorkspaceMutation,
    TestExecution,
    Commit,
    Push,
    ProviderCall,
    ExternalEffect,
    SopActivation,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkStepClass {
    Inspect,
    Analyze,
    ProposeUpdate,
    Verify,
    ProposePublication,
    ProposeSucceedingSop,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkPlanStep {
    pub step_id: SemanticId,
    pub ordinal: u32,
    pub label: String,
    pub class: WorkStepClass,
    pub dependency_refs: BTreeSet<SemanticId>,
    pub requested_capabilities: BTreeSet<WorkCapability>,
    pub evidence_refs: BTreeSet<SemanticId>,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveWorkPlanDraft {
    pub plan_id: SemanticId,
    pub plan_revision_digest: ContentDigest,
    pub steps: Vec<WorkPlanStep>,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkCapabilityDisposition {
    NotGrantedPendingContract,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectiveWorkPlanLifecycle {
    AdmittedPlanNotExecuting,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectiveWorkPlanAuthority {
    PlanningOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveWorkPlanRequest {
    pub profile: String,
    pub boot_proposal: SopBootSessionProposal,
    pub objective_ref: SemanticId,
    pub objective_digest: ContentDigest,
    pub plan: ObjectiveWorkPlanDraft,
    pub authority_ref: SemanticId,
    pub authority_digest: ContentDigest,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub unresolved_account: BTreeSet<String>,
    pub non_authority: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveWorkPlanProposal {
    pub profile: String,
    pub request: ObjectiveWorkPlanRequest,
    pub lifecycle: ObjectiveWorkPlanLifecycle,
    pub authority: ObjectiveWorkPlanAuthority,
    pub requested_capability_union: BTreeSet<WorkCapability>,
    pub capability_account: BTreeMap<WorkCapability, WorkCapabilityDisposition>,
    pub capability_denials: BTreeSet<WorkCapability>,
    pub request_digest: ContentDigest,
    pub proposal_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectiveWorkPlanFaultCode {
    InvalidProfile,
    InvalidBootProposal,
    IdentityCollision,
    InvalidDigest,
    InvalidPlan,
    InvalidStep,
    InvalidDependency,
    InvalidCapability,
    InvalidEvidence,
    InvalidUnresolvedAccount,
    InvalidLifecycle,
    InvalidAuthority,
    InvalidCorrespondence,
    InvalidMachineForm,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveWorkPlanFault {
    pub code: ObjectiveWorkPlanFaultCode,
    pub message: String,
}

impl fmt::Display for ObjectiveWorkPlanFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for ObjectiveWorkPlanFault {}

pub fn compile_objective_work_plan(
    request: &ObjectiveWorkPlanRequest,
) -> Result<ObjectiveWorkPlanProposal, ObjectiveWorkPlanFault> {
    validate_objective_work_plan_request(request)?;
    let requested_capability_union = requested_capability_union(&request.plan);
    let mut proposal = ObjectiveWorkPlanProposal {
        profile: OBJECTIVE_WORK_PLAN_PROPOSAL_PROFILE.to_owned(),
        request: request.clone(),
        lifecycle: ObjectiveWorkPlanLifecycle::AdmittedPlanNotExecuting,
        authority: ObjectiveWorkPlanAuthority::PlanningOnly,
        requested_capability_union,
        capability_account: required_capability_account(),
        capability_denials: all_capabilities(),
        request_digest: objective_work_plan_request_digest(request)?,
        proposal_digest: empty_digest(),
    };
    proposal.proposal_digest = objective_work_plan_proposal_digest(&proposal)?;
    validate_objective_work_plan_proposal(request, &proposal)?;
    Ok(proposal)
}

pub fn validate_objective_work_plan_request(
    request: &ObjectiveWorkPlanRequest,
) -> Result<(), ObjectiveWorkPlanFault> {
    if request.profile != OBJECTIVE_WORK_PLAN_REQUEST_PROFILE {
        return Err(fault(
            ObjectiveWorkPlanFaultCode::InvalidProfile,
            "request profile differs",
        ));
    }
    validate_sop_boot_session_proposal(&request.boot_proposal.request, &request.boot_proposal)
        .map_err(|error| {
            fault(
                ObjectiveWorkPlanFaultCode::InvalidBootProposal,
                error.to_string(),
            )
        })?;
    validate_digest(&request.objective_digest, "objective digest")?;
    if request.objective_ref != request.boot_proposal.request.objective_ref
        || request.objective_digest != request.boot_proposal.request.objective_digest
    {
        return Err(fault(
            ObjectiveWorkPlanFaultCode::InvalidCorrespondence,
            "objective differs from boot proposal",
        ));
    }
    validate_digest(&request.plan.plan_revision_digest, "plan revision digest")?;
    validate_digest(&request.authority_digest, "authority digest")?;
    validate_plan(request)?;
    if request.evidence_refs.is_empty() || request.evidence_refs.len() > MAX_EVIDENCE_REFS {
        return Err(fault(
            ObjectiveWorkPlanFaultCode::InvalidEvidence,
            "request evidence count must be within 1..=32",
        ));
    }
    if request.unresolved_account != required_unresolved_account() {
        return Err(fault(
            ObjectiveWorkPlanFaultCode::InvalidUnresolvedAccount,
            "unresolved account differs",
        ));
    }
    if request.non_authority != OBJECTIVE_WORK_PLAN_NON_AUTHORITY {
        return Err(fault(
            ObjectiveWorkPlanFaultCode::InvalidAuthority,
            "request non-authority differs",
        ));
    }
    Ok(())
}

pub fn validate_objective_work_plan_proposal(
    expected_request: &ObjectiveWorkPlanRequest,
    proposal: &ObjectiveWorkPlanProposal,
) -> Result<(), ObjectiveWorkPlanFault> {
    validate_objective_work_plan_request(&proposal.request)?;
    if &proposal.request != expected_request {
        return Err(fault(
            ObjectiveWorkPlanFaultCode::InvalidCorrespondence,
            "proposal request differs",
        ));
    }
    if proposal.profile != OBJECTIVE_WORK_PLAN_PROPOSAL_PROFILE {
        return Err(fault(
            ObjectiveWorkPlanFaultCode::InvalidProfile,
            "proposal profile differs",
        ));
    }
    if proposal.lifecycle != ObjectiveWorkPlanLifecycle::AdmittedPlanNotExecuting {
        return Err(fault(
            ObjectiveWorkPlanFaultCode::InvalidLifecycle,
            "lifecycle differs",
        ));
    }
    if proposal.authority != ObjectiveWorkPlanAuthority::PlanningOnly
        || proposal.capability_account != required_capability_account()
        || proposal.capability_denials != all_capabilities()
    {
        return Err(fault(
            ObjectiveWorkPlanFaultCode::InvalidAuthority,
            "authority capability account or denials differ",
        ));
    }
    if proposal.requested_capability_union != requested_capability_union(&proposal.request.plan) {
        return Err(fault(
            ObjectiveWorkPlanFaultCode::InvalidCapability,
            "requested capability union differs",
        ));
    }
    if proposal.request_digest != objective_work_plan_request_digest(expected_request)? {
        return Err(fault(
            ObjectiveWorkPlanFaultCode::InvalidDigest,
            "request digest differs",
        ));
    }
    validate_digest(&proposal.proposal_digest, "proposal digest")?;
    if proposal.proposal_digest != objective_work_plan_proposal_digest(proposal)? {
        return Err(fault(
            ObjectiveWorkPlanFaultCode::InvalidDigest,
            "proposal digest differs",
        ));
    }
    Ok(())
}

pub fn objective_work_plan_request_digest(
    request: &ObjectiveWorkPlanRequest,
) -> Result<ContentDigest, ObjectiveWorkPlanFault> {
    sha256_form(REQUEST_DOMAIN, request)
}

pub fn objective_work_plan_proposal_digest(
    proposal: &ObjectiveWorkPlanProposal,
) -> Result<ContentDigest, ObjectiveWorkPlanFault> {
    let mut body = proposal.clone();
    body.proposal_digest = empty_digest();
    sha256_form(PROPOSAL_DOMAIN, &body)
}

pub fn to_objective_work_plan_request_machine_form(
    request: &ObjectiveWorkPlanRequest,
) -> Result<String, ObjectiveWorkPlanFault> {
    validate_objective_work_plan_request(request)?;
    serde_json::to_string(request).map_err(machine_fault)
}

pub fn from_objective_work_plan_request_machine_form(
    value: &str,
) -> Result<ObjectiveWorkPlanRequest, ObjectiveWorkPlanFault> {
    let request = serde_json::from_str(value).map_err(machine_fault)?;
    validate_objective_work_plan_request(&request)?;
    Ok(request)
}

pub fn to_objective_work_plan_proposal_machine_form(
    proposal: &ObjectiveWorkPlanProposal,
) -> Result<String, ObjectiveWorkPlanFault> {
    validate_objective_work_plan_proposal(&proposal.request, proposal)?;
    serde_json::to_string(proposal).map_err(machine_fault)
}

pub fn from_objective_work_plan_proposal_machine_form(
    value: &str,
) -> Result<ObjectiveWorkPlanProposal, ObjectiveWorkPlanFault> {
    let proposal: ObjectiveWorkPlanProposal = serde_json::from_str(value).map_err(machine_fault)?;
    validate_objective_work_plan_proposal(&proposal.request, &proposal)?;
    Ok(proposal)
}

fn validate_plan(request: &ObjectiveWorkPlanRequest) -> Result<(), ObjectiveWorkPlanFault> {
    let plan = &request.plan;
    if plan.steps.is_empty() || plan.steps.len() > MAX_STEPS {
        return Err(fault(
            ObjectiveWorkPlanFaultCode::InvalidPlan,
            "plan step count differs",
        ));
    }
    let reserved = [
        request.boot_proposal.request.boot_request_id.as_str(),
        request.boot_proposal.request.proposed_session_id.as_str(),
        request.objective_ref.as_str(),
        request.authority_ref.as_str(),
        plan.plan_id.as_str(),
    ];
    if reserved.into_iter().collect::<BTreeSet<_>>().len() != reserved.len() {
        return Err(fault(
            ObjectiveWorkPlanFaultCode::IdentityCollision,
            "reserved identities collide",
        ));
    }

    let mut prior = BTreeSet::new();
    for (index, step) in plan.steps.iter().enumerate() {
        if reserved.contains(&step.step_id.as_str()) || !prior.insert(step.step_id.clone()) {
            return Err(fault(
                ObjectiveWorkPlanFaultCode::IdentityCollision,
                "step identity collides",
            ));
        }
        if step.ordinal != index as u32 + 1 || !valid_label(&step.label) {
            return Err(fault(
                ObjectiveWorkPlanFaultCode::InvalidStep,
                "step ordinal or label differs",
            ));
        }
        if (index == 0 && !step.dependency_refs.is_empty())
            || (index > 0 && step.dependency_refs.is_empty())
            || !step.dependency_refs.is_subset(&prior)
            || step.dependency_refs.contains(&step.step_id)
        {
            return Err(fault(
                ObjectiveWorkPlanFaultCode::InvalidDependency,
                "step dependency differs",
            ));
        }
        if step.requested_capabilities != exact_capabilities(step.class) {
            return Err(fault(
                ObjectiveWorkPlanFaultCode::InvalidCapability,
                "step capability set differs",
            ));
        }
        if step.evidence_refs.is_empty() || step.evidence_refs.len() > MAX_EVIDENCE_REFS {
            return Err(fault(
                ObjectiveWorkPlanFaultCode::InvalidEvidence,
                "step evidence differs",
            ));
        }
    }
    Ok(())
}

fn exact_capabilities(class: WorkStepClass) -> BTreeSet<WorkCapability> {
    use WorkCapability::*;
    match class {
        WorkStepClass::Inspect => [WorkspaceRead].into_iter().collect(),
        WorkStepClass::Analyze => BTreeSet::new(),
        WorkStepClass::ProposeUpdate => [WorkspaceRead, WorkspaceMutation].into_iter().collect(),
        WorkStepClass::Verify => [WorkspaceRead, TestExecution].into_iter().collect(),
        WorkStepClass::ProposePublication => [Commit, Push].into_iter().collect(),
        WorkStepClass::ProposeSucceedingSop => {
            [WorkspaceRead, WorkspaceMutation].into_iter().collect()
        }
    }
}

fn requested_capability_union(plan: &ObjectiveWorkPlanDraft) -> BTreeSet<WorkCapability> {
    plan.steps
        .iter()
        .flat_map(|step| step.requested_capabilities.iter().copied())
        .collect()
}

fn all_capabilities() -> BTreeSet<WorkCapability> {
    use WorkCapability::*;
    [
        WorkspaceRead,
        WorkspaceMutation,
        TestExecution,
        Commit,
        Push,
        ProviderCall,
        ExternalEffect,
        SopActivation,
    ]
    .into_iter()
    .collect()
}

fn required_capability_account() -> BTreeMap<WorkCapability, WorkCapabilityDisposition> {
    all_capabilities()
        .into_iter()
        .map(|capability| {
            (
                capability,
                WorkCapabilityDisposition::NotGrantedPendingContract,
            )
        })
        .collect()
}

fn required_unresolved_account() -> BTreeSet<String> {
    [
        "capabilities_not_granted",
        "succeeding_sop_not_authored",
        "updates_not_applied",
        "work_not_started",
        "workspace_not_admitted",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LABEL_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn validate_digest(digest: &ContentDigest, label: &str) -> Result<(), ObjectiveWorkPlanFault> {
    let valid = digest.algorithm == "sha256"
        && digest.value.len() == 64
        && digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid {
        return Err(fault(
            ObjectiveWorkPlanFaultCode::InvalidDigest,
            format!("{label} must be lower-case SHA256"),
        ));
    }
    Ok(())
}

fn sha256_form<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<ContentDigest, ObjectiveWorkPlanFault> {
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

fn machine_fault(error: serde_json::Error) -> ObjectiveWorkPlanFault {
    fault(
        ObjectiveWorkPlanFaultCode::InvalidMachineForm,
        format!("objective work plan machine form failed: {error}"),
    )
}

fn fault(code: ObjectiveWorkPlanFaultCode, message: impl Into<String>) -> ObjectiveWorkPlanFault {
    ObjectiveWorkPlanFault {
        code,
        message: message.into(),
    }
}
