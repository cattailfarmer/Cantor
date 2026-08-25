//! Pure SWA-07 composition over published self-working supplied-data forms.
//!
//! This module joins one SWA-04A update handoff to a later SWA-06A
//! succeeding-SOP proposal. It performs no work, observation, mutation, review,
//! publication, activation, provider call, or other external effect.

use std::{collections::BTreeSet, fmt};

use cantor_core::{
    ContentDigest, SelfWorkLifecycleState, SemanticId, SucceedingSopRequest, WorkStepClass,
    compile_succeeding_sop, self_work_lifecycle_checkpoint_digest,
    self_work_lifecycle_request_digest, sha256_bytes, succeeding_sop_request_digest,
    validate_succeeding_sop_request, verify_succeeding_sop_proposal,
};
use serde::{Deserialize, Serialize};

use crate::{
    SelfWorkUpdateHandoffRequest, compile_self_work_update_handoff,
    self_work_update_handoff_request_digest, validate_self_work_update_handoff_request,
};

pub const PROVIDER_FREE_SELF_WORK_COMPOSITION_REQUEST_PROFILE: &str =
    "cantor-provider-free-self-work-composition-request/0.1";
pub const PROVIDER_FREE_SELF_WORK_COMPOSITION_RECEIPT_PROFILE: &str =
    "cantor-provider-free-self-work-composition-receipt/0.1";
pub const PROVIDER_FREE_SELF_WORK_COMPOSITION_MAX_MACHINE_FORM_BYTES: usize = 16 * 1024 * 1024;
pub const PROVIDER_FREE_SELF_WORK_COMPOSITION_NON_AUTHORITY: &str = "Pure supplied-data self-work chain correspondence only. Embedded admission, capability, review, lifecycle, and evidence receipts are revalidated as bounded machine forms but are not authenticated, reacquired, current, fresh, or interpreted as physical work proof. No SOP bytes, Git tree, workspace, provider, model, process, environment, clock, or network is observed; no work or test is run; no update is applied, verified, accepted, rolled back, cleaned, committed, or pushed; no semantic review is performed; no satisfaction signature is issued; no source is persisted or activated; and no external, remote, FPGA, or Minecraft authority is granted.";

pub const PROVIDER_FREE_SELF_WORK_COMPOSITION_STAGE_ACCOUNT: [&str; 6] = [
    "boot_session_proposal_only_not_launched",
    "objective_work_plan_prepared_not_executing",
    "lifecycle_prefix_replayed_supplied_receipts_only",
    "update_handoff_prepared_update_not_performed",
    "succeeding_sop_proposed_awaiting_independent_review",
    "publication_review_signature_activation_not_performed",
];

const REQUEST_DOMAIN: &str = "cantor.provider-free-self-work-composition.request.v1";
const RECEIPT_DOMAIN: &str = "cantor.provider-free-self-work-composition.receipt.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFreeSelfWorkCompositionStatus {
    ProviderFreeChainCorrespondenceVerified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFreeSelfWorkCompositionAuthority {
    SuppliedDataCorrespondenceOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderFreeSelfWorkCompositionRequest {
    pub profile: String,
    pub composition_id: SemanticId,
    pub update_handoff_request: SelfWorkUpdateHandoffRequest,
    pub succeeding_sop_request: SucceedingSopRequest,
    pub bridge_evidence_ref: SemanticId,
    pub non_authority: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderFreeSelfWorkCompositionReceipt {
    pub profile: String,
    pub request: ProviderFreeSelfWorkCompositionRequest,
    pub composition_ref: SemanticId,
    pub boot_proposal_digest: ContentDigest,
    pub work_plan_proposal_digest: ContentDigest,
    pub lifecycle_request_digest: ContentDigest,
    pub pre_update_checkpoint_digest: ContentDigest,
    pub update_handoff_request_digest: ContentDigest,
    pub update_handoff_proposal_digest: ContentDigest,
    pub update_step_ref: SemanticId,
    pub update_attempt_ref: SemanticId,
    pub post_update_checkpoint_digest: ContentDigest,
    pub succeeding_step_ref: SemanticId,
    pub succeeding_attempt_ref: SemanticId,
    pub succeeding_sop_request_digest: ContentDigest,
    pub succeeding_sop_proposal_digest: ContentDigest,
    pub succeeding_sop_verification_digest: ContentDigest,
    pub stage_account: BTreeSet<String>,
    pub status: ProviderFreeSelfWorkCompositionStatus,
    pub authority: ProviderFreeSelfWorkCompositionAuthority,
    pub physical_contact: bool,
    pub non_authority: String,
    pub request_digest: ContentDigest,
    pub receipt_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFreeSelfWorkCompositionFaultCode {
    InvalidProfile,
    InvalidIdentity,
    InvalidHandoff,
    InvalidSucceedingSop,
    InvalidLifecycleJoin,
    InvalidStepClass,
    InvalidBridgeEvidence,
    InvalidAuthority,
    InvalidCorrespondence,
    InvalidDigest,
    InvalidBound,
    InvalidMachineForm,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderFreeSelfWorkCompositionFault {
    pub code: ProviderFreeSelfWorkCompositionFaultCode,
    pub message: String,
}

impl fmt::Display for ProviderFreeSelfWorkCompositionFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for ProviderFreeSelfWorkCompositionFault {}

pub fn compile_provider_free_self_work_composition(
    request: &ProviderFreeSelfWorkCompositionRequest,
) -> Result<ProviderFreeSelfWorkCompositionReceipt, ProviderFreeSelfWorkCompositionFault> {
    validate_provider_free_self_work_composition_request(request)?;
    build_receipt(request)
}

pub fn verify_provider_free_self_work_composition(
    receipt: &ProviderFreeSelfWorkCompositionReceipt,
) -> Result<(), ProviderFreeSelfWorkCompositionFault> {
    validate_provider_free_self_work_composition_request(&receipt.request)?;
    if receipt.profile != PROVIDER_FREE_SELF_WORK_COMPOSITION_RECEIPT_PROFILE {
        return Err(fault(
            ProviderFreeSelfWorkCompositionFaultCode::InvalidProfile,
            "composition receipt profile differs",
        ));
    }
    if receipt.status
        != ProviderFreeSelfWorkCompositionStatus::ProviderFreeChainCorrespondenceVerified
        || receipt.authority
            != ProviderFreeSelfWorkCompositionAuthority::SuppliedDataCorrespondenceOnly
        || receipt.physical_contact
        || receipt.stage_account != required_stage_account()
        || receipt.non_authority != PROVIDER_FREE_SELF_WORK_COMPOSITION_NON_AUTHORITY
    {
        return Err(fault(
            ProviderFreeSelfWorkCompositionFaultCode::InvalidAuthority,
            "composition stage, authority, physical-contact, or non-authority account differs",
        ));
    }
    validate_digest(&receipt.request_digest, "request digest")?;
    if receipt.request_digest
        != provider_free_self_work_composition_request_digest(&receipt.request)?
    {
        return Err(fault(
            ProviderFreeSelfWorkCompositionFaultCode::InvalidDigest,
            "composition request digest differs",
        ));
    }
    validate_digest(&receipt.receipt_digest, "receipt digest")?;
    if receipt.receipt_digest != provider_free_self_work_composition_receipt_digest(receipt)? {
        return Err(fault(
            ProviderFreeSelfWorkCompositionFaultCode::InvalidDigest,
            "composition receipt digest differs",
        ));
    }
    let expected = build_receipt(&receipt.request)?;
    if *receipt != expected {
        return Err(fault(
            ProviderFreeSelfWorkCompositionFaultCode::InvalidCorrespondence,
            "composition receipt differs from complete deterministic recompilation",
        ));
    }
    Ok(())
}

pub fn validate_provider_free_self_work_composition_request(
    request: &ProviderFreeSelfWorkCompositionRequest,
) -> Result<(), ProviderFreeSelfWorkCompositionFault> {
    if request.profile != PROVIDER_FREE_SELF_WORK_COMPOSITION_REQUEST_PROFILE {
        return Err(fault(
            ProviderFreeSelfWorkCompositionFaultCode::InvalidProfile,
            "composition request profile differs",
        ));
    }
    validate_self_work_update_handoff_request(&request.update_handoff_request).map_err(
        |error| {
            fault(
                ProviderFreeSelfWorkCompositionFaultCode::InvalidHandoff,
                error.to_string(),
            )
        },
    )?;
    validate_succeeding_sop_request(&request.succeeding_sop_request).map_err(|error| {
        fault(
            ProviderFreeSelfWorkCompositionFaultCode::InvalidSucceedingSop,
            error.to_string(),
        )
    })?;

    let handoff = &request.update_handoff_request;
    let succeeding = &request.succeeding_sop_request;
    let lifecycle = &handoff.lifecycle_request;
    let plan = &lifecycle.work_plan_proposal.request.plan;
    let boot = &lifecycle.work_plan_proposal.request.boot_proposal.request;
    if lifecycle != &succeeding.lifecycle_request {
        return Err(fault(
            ProviderFreeSelfWorkCompositionFaultCode::InvalidLifecycleJoin,
            "handoff and succeeding requests carry different lifecycle requests",
        ));
    }

    let identity_collides = [
        &handoff.handoff_id,
        &handoff.selected_step_ref,
        &handoff.selected_attempt_ref,
        &succeeding.proposal_id,
        &succeeding.selected_step_ref,
        &succeeding.selected_attempt_ref,
        &lifecycle.lifecycle_id,
        &plan.plan_id,
        &boot.boot_request_id,
        &boot.proposed_session_id,
        &boot.boot_sop.canonical_sop_ref,
        &boot.boot_sop.sop_revision_ref,
    ]
    .into_iter()
    .any(|identity| identity == &request.composition_id);
    let bridge_collides = request.bridge_evidence_ref == request.composition_id
        || request.bridge_evidence_ref == lifecycle.lifecycle_id
        || request.bridge_evidence_ref == handoff.handoff_id
        || request.bridge_evidence_ref == succeeding.proposal_id
        || request.bridge_evidence_ref == handoff.selected_step_ref
        || request.bridge_evidence_ref == handoff.selected_attempt_ref
        || request.bridge_evidence_ref == succeeding.selected_step_ref
        || request.bridge_evidence_ref == succeeding.selected_attempt_ref;
    if identity_collides || bridge_collides {
        return Err(fault(
            ProviderFreeSelfWorkCompositionFaultCode::InvalidIdentity,
            "composition or bridge identity collides with causal lineage",
        ));
    }

    let prefix = &handoff.lifecycle_checkpoint;
    let later = &succeeding.lifecycle_checkpoint;
    if prefix.transitions.len() >= later.transitions.len()
        || prefix.transitions.as_slice() != &later.transitions[..prefix.transitions.len()]
    {
        return Err(fault(
            ProviderFreeSelfWorkCompositionFaultCode::InvalidLifecycleJoin,
            "handoff checkpoint is not an exact proper transition prefix",
        ));
    }

    let update_step = plan
        .steps
        .iter()
        .find(|step| step.step_id == handoff.selected_step_ref)
        .ok_or_else(|| {
            fault(
                ProviderFreeSelfWorkCompositionFaultCode::InvalidStepClass,
                "handoff selected step is absent from the common plan",
            )
        })?;
    if update_step.class != WorkStepClass::ProposeUpdate {
        return Err(fault(
            ProviderFreeSelfWorkCompositionFaultCode::InvalidStepClass,
            "handoff selected step is not propose_update",
        ));
    }
    let later_update = later
        .step_states
        .get(&handoff.selected_step_ref)
        .ok_or_else(|| {
            fault(
                ProviderFreeSelfWorkCompositionFaultCode::InvalidLifecycleJoin,
                "update step is absent from the later checkpoint",
            )
        })?;
    if later_update.attempt_ref != handoff.selected_attempt_ref
        || later_update.state != SelfWorkLifecycleState::Complete
    {
        return Err(fault(
            ProviderFreeSelfWorkCompositionFaultCode::InvalidLifecycleJoin,
            "the exact update attempt is not complete in the later checkpoint",
        ));
    }

    if !handoff.evidence_refs.contains(&request.bridge_evidence_ref) {
        return Err(fault(
            ProviderFreeSelfWorkCompositionFaultCode::InvalidBridgeEvidence,
            "bridge evidence is absent from the update handoff",
        ));
    }
    let bridge_transition_exists =
        later.transitions[prefix.transitions.len()..]
            .iter()
            .any(|transition| {
                transition.step_ref == handoff.selected_step_ref
                    && transition.attempt_ref == handoff.selected_attempt_ref
                    && transition
                        .evidence_refs
                        .contains(&request.bridge_evidence_ref)
            });
    if !bridge_transition_exists {
        return Err(fault(
            ProviderFreeSelfWorkCompositionFaultCode::InvalidBridgeEvidence,
            "bridge evidence is absent from post-prefix transitions for the exact update attempt",
        ));
    }

    let succeeding_step = plan
        .steps
        .iter()
        .find(|step| step.step_id == succeeding.selected_step_ref)
        .ok_or_else(|| {
            fault(
                ProviderFreeSelfWorkCompositionFaultCode::InvalidStepClass,
                "succeeding selected step is absent from the common plan",
            )
        })?;
    if succeeding_step.class != WorkStepClass::ProposeSucceedingSop {
        return Err(fault(
            ProviderFreeSelfWorkCompositionFaultCode::InvalidStepClass,
            "succeeding selected step is not propose_succeeding_sop",
        ));
    }
    if request.non_authority != PROVIDER_FREE_SELF_WORK_COMPOSITION_NON_AUTHORITY {
        return Err(fault(
            ProviderFreeSelfWorkCompositionFaultCode::InvalidAuthority,
            "composition non-authority differs",
        ));
    }
    Ok(())
}

pub fn provider_free_self_work_composition_request_digest(
    request: &ProviderFreeSelfWorkCompositionRequest,
) -> Result<ContentDigest, ProviderFreeSelfWorkCompositionFault> {
    sha256_form(REQUEST_DOMAIN, request)
}

pub fn provider_free_self_work_composition_receipt_digest(
    receipt: &ProviderFreeSelfWorkCompositionReceipt,
) -> Result<ContentDigest, ProviderFreeSelfWorkCompositionFault> {
    let mut body = receipt.clone();
    body.receipt_digest = empty_digest();
    sha256_form(RECEIPT_DOMAIN, &body)
}

pub fn to_provider_free_self_work_composition_request_machine_form(
    request: &ProviderFreeSelfWorkCompositionRequest,
) -> Result<String, ProviderFreeSelfWorkCompositionFault> {
    validate_provider_free_self_work_composition_request(request)?;
    machine_form(request)
}

pub fn from_provider_free_self_work_composition_request_machine_form(
    value: &str,
) -> Result<ProviderFreeSelfWorkCompositionRequest, ProviderFreeSelfWorkCompositionFault> {
    validate_machine_form_bound(value)?;
    let request = serde_json::from_str(value).map_err(machine_fault)?;
    validate_provider_free_self_work_composition_request(&request)?;
    Ok(request)
}

pub fn to_provider_free_self_work_composition_receipt_machine_form(
    receipt: &ProviderFreeSelfWorkCompositionReceipt,
) -> Result<String, ProviderFreeSelfWorkCompositionFault> {
    verify_provider_free_self_work_composition(receipt)?;
    machine_form(receipt)
}

pub fn from_provider_free_self_work_composition_receipt_machine_form(
    value: &str,
) -> Result<ProviderFreeSelfWorkCompositionReceipt, ProviderFreeSelfWorkCompositionFault> {
    validate_machine_form_bound(value)?;
    let receipt = serde_json::from_str(value).map_err(machine_fault)?;
    verify_provider_free_self_work_composition(&receipt)?;
    Ok(receipt)
}

fn build_receipt(
    request: &ProviderFreeSelfWorkCompositionRequest,
) -> Result<ProviderFreeSelfWorkCompositionReceipt, ProviderFreeSelfWorkCompositionFault> {
    let handoff_proposal = compile_self_work_update_handoff(&request.update_handoff_request)
        .map_err(|error| {
            fault(
                ProviderFreeSelfWorkCompositionFaultCode::InvalidHandoff,
                error.to_string(),
            )
        })?;
    let succeeding_proposal =
        compile_succeeding_sop(&request.succeeding_sop_request).map_err(|error| {
            fault(
                ProviderFreeSelfWorkCompositionFaultCode::InvalidSucceedingSop,
                error.to_string(),
            )
        })?;
    let succeeding_verification =
        verify_succeeding_sop_proposal(&succeeding_proposal).map_err(|error| {
            fault(
                ProviderFreeSelfWorkCompositionFaultCode::InvalidSucceedingSop,
                error.to_string(),
            )
        })?;
    let lifecycle = &request.update_handoff_request.lifecycle_request;
    let work_plan = &lifecycle.work_plan_proposal;
    let mut receipt = ProviderFreeSelfWorkCompositionReceipt {
        profile: PROVIDER_FREE_SELF_WORK_COMPOSITION_RECEIPT_PROFILE.to_owned(),
        request: request.clone(),
        composition_ref: request.composition_id.clone(),
        boot_proposal_digest: work_plan.request.boot_proposal.proposal_digest.clone(),
        work_plan_proposal_digest: work_plan.proposal_digest.clone(),
        lifecycle_request_digest: self_work_lifecycle_request_digest(lifecycle).map_err(
            |error| {
                fault(
                    ProviderFreeSelfWorkCompositionFaultCode::InvalidLifecycleJoin,
                    error.to_string(),
                )
            },
        )?,
        pre_update_checkpoint_digest: self_work_lifecycle_checkpoint_digest(
            &request.update_handoff_request.lifecycle_checkpoint,
        )
        .map_err(|error| {
            fault(
                ProviderFreeSelfWorkCompositionFaultCode::InvalidLifecycleJoin,
                error.to_string(),
            )
        })?,
        update_handoff_request_digest: self_work_update_handoff_request_digest(
            &request.update_handoff_request,
        )
        .map_err(|error| {
            fault(
                ProviderFreeSelfWorkCompositionFaultCode::InvalidHandoff,
                error.to_string(),
            )
        })?,
        update_handoff_proposal_digest: handoff_proposal.proposal_digest,
        update_step_ref: request.update_handoff_request.selected_step_ref.clone(),
        update_attempt_ref: request.update_handoff_request.selected_attempt_ref.clone(),
        post_update_checkpoint_digest: self_work_lifecycle_checkpoint_digest(
            &request.succeeding_sop_request.lifecycle_checkpoint,
        )
        .map_err(|error| {
            fault(
                ProviderFreeSelfWorkCompositionFaultCode::InvalidLifecycleJoin,
                error.to_string(),
            )
        })?,
        succeeding_step_ref: request.succeeding_sop_request.selected_step_ref.clone(),
        succeeding_attempt_ref: request.succeeding_sop_request.selected_attempt_ref.clone(),
        succeeding_sop_request_digest: succeeding_sop_request_digest(
            &request.succeeding_sop_request,
        )
        .map_err(|error| {
            fault(
                ProviderFreeSelfWorkCompositionFaultCode::InvalidSucceedingSop,
                error.to_string(),
            )
        })?,
        succeeding_sop_proposal_digest: succeeding_proposal.proposal_digest,
        succeeding_sop_verification_digest: succeeding_verification.verification_digest,
        stage_account: required_stage_account(),
        status: ProviderFreeSelfWorkCompositionStatus::ProviderFreeChainCorrespondenceVerified,
        authority: ProviderFreeSelfWorkCompositionAuthority::SuppliedDataCorrespondenceOnly,
        physical_contact: false,
        non_authority: PROVIDER_FREE_SELF_WORK_COMPOSITION_NON_AUTHORITY.to_owned(),
        request_digest: provider_free_self_work_composition_request_digest(request)?,
        receipt_digest: empty_digest(),
    };
    receipt.receipt_digest = provider_free_self_work_composition_receipt_digest(&receipt)?;
    Ok(receipt)
}

fn required_stage_account() -> BTreeSet<String> {
    PROVIDER_FREE_SELF_WORK_COMPOSITION_STAGE_ACCOUNT
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn sha256_form<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<ContentDigest, ProviderFreeSelfWorkCompositionFault> {
    let form = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + form.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&form);
    Ok(sha256_bytes(&bytes))
}

fn machine_form<T: Serialize>(value: &T) -> Result<String, ProviderFreeSelfWorkCompositionFault> {
    let form = serde_json::to_string(value).map_err(machine_fault)?;
    validate_machine_form_bound(&form)?;
    Ok(form)
}

fn validate_machine_form_bound(value: &str) -> Result<(), ProviderFreeSelfWorkCompositionFault> {
    if value.is_empty() || value.len() > PROVIDER_FREE_SELF_WORK_COMPOSITION_MAX_MACHINE_FORM_BYTES
    {
        return Err(fault(
            ProviderFreeSelfWorkCompositionFaultCode::InvalidBound,
            "composition machine form is empty or oversized",
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

fn validate_digest(
    digest: &ContentDigest,
    label: &str,
) -> Result<(), ProviderFreeSelfWorkCompositionFault> {
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
            ProviderFreeSelfWorkCompositionFaultCode::InvalidDigest,
            format!("{label} is not canonical lowercase SHA-256"),
        ))
    }
}

fn machine_fault(error: serde_json::Error) -> ProviderFreeSelfWorkCompositionFault {
    fault(
        ProviderFreeSelfWorkCompositionFaultCode::InvalidMachineForm,
        error.to_string(),
    )
}

fn fault(
    code: ProviderFreeSelfWorkCompositionFaultCode,
    message: impl Into<String>,
) -> ProviderFreeSelfWorkCompositionFault {
    ProviderFreeSelfWorkCompositionFault {
        code,
        message: message.into(),
    }
}
