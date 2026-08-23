//! Pure SOP-admission to proposed agent-session forms.
//!
//! This module validates supplied semantic receipts and proposes an identity.
//! It does not observe SOP bytes, open a session, launch a process, access a
//! workspace, execute work, contact a provider, persist, publish, or activate.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    AdmissionDecision, AdmissionDisposition, CompilationReceipt, ContentDigest, PhaseDisposition,
    ReceiptEvidence, SemanticId, ValidationReceipt, VerificationReceipt,
    compute_admission_disposition_digest, compute_compilation_receipt_digest,
    compute_validation_receipt_digest, compute_verification_receipt_digest, sha256_bytes,
};

pub const SOP_BOOT_SESSION_REQUEST_PROFILE: &str = "cantor-sop-boot-session-request/0.1";
pub const SOP_BOOT_SESSION_PROPOSAL_PROFILE: &str = "cantor-sop-boot-session-proposal/0.1";
pub const SOP_BOOT_INVOCATION_CONTEXT: &str = "cantor_sop_boot_session_proposal/0.1";
pub const SOP_BOOT_SESSION_NON_AUTHORITY: &str = "Pure admitted-SOP to proposed-session identity. No SOP bytes or signature were observed or issued, no session was opened, no process was launched, no workspace was admitted or accessed, no objective or work was executed, no update was applied, no commit or push occurred, no provider was contacted, and no SOP was activated.";

const REQUEST_DOMAIN: &str = "cantor.sop-boot-session.request.v1";
const PROPOSAL_DOMAIN: &str = "cantor.sop-boot-session.proposal.v1";
const MAX_EVIDENCE_REFS: usize = 32;
const MAX_CHECKPOINTS: u32 = 64;
const MAX_UPDATE_PROPOSALS: u32 = 32;
const MAX_TIMEOUT_SECONDS: u32 = 86_400;

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SopRevisionAdmissionBinding {
    pub canonical_sop_ref: SemanticId,
    pub sop_revision_ref: SemanticId,
    pub sop_revision_digest: ContentDigest,
    pub satisfaction_signature_ref: SemanticId,
    pub satisfaction_signature_digest: ContentDigest,
    pub procedure_candidate_ref: SemanticId,
    pub validation: ValidationReceipt,
    pub compilation: CompilationReceipt,
    pub verification: VerificationReceipt,
    pub admission: AdmissionDisposition,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SopBootSessionBounds {
    pub maximum_work_packets: u32,
    pub maximum_checkpoints: u32,
    pub maximum_update_proposals: u32,
    pub session_timeout_seconds: u32,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SopBootCapabilityDenial {
    ProcessLaunch,
    WorkspaceRead,
    WorkspaceMutation,
    Commit,
    Push,
    ProviderCall,
    Persistence,
    ExternalEffect,
    SopActivation,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SopBootSessionLifecycle {
    ProposedNotLaunched,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SopBootSessionAuthority {
    IdentityAndPlanningOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SopBootSessionRequest {
    pub profile: String,
    pub boot_request_id: SemanticId,
    pub proposed_session_id: SemanticId,
    pub outer_host_id: SemanticId,
    pub outer_host_identity_envelope_digest: ContentDigest,
    pub boot_sop: SopRevisionAdmissionBinding,
    pub objective_ref: SemanticId,
    pub objective_digest: ContentDigest,
    pub authority_ref: SemanticId,
    pub authority_digest: ContentDigest,
    pub bounds: SopBootSessionBounds,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub unresolved_account: BTreeSet<String>,
    pub non_authority: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SopBootSessionProposal {
    pub profile: String,
    pub request: SopBootSessionRequest,
    pub lifecycle: SopBootSessionLifecycle,
    pub authority: SopBootSessionAuthority,
    pub capability_denials: BTreeSet<SopBootCapabilityDenial>,
    pub request_digest: ContentDigest,
    pub proposal_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SopBootSessionFaultCode {
    InvalidProfile,
    IdentityCollision,
    InvalidDigest,
    InvalidRevisionBinding,
    InvalidAdmissionChain,
    InvalidEvidence,
    InvalidBounds,
    InvalidUnresolvedAccount,
    InvalidLifecycle,
    InvalidAuthority,
    InvalidCorrespondence,
    InvalidMachineForm,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SopBootSessionFault {
    pub code: SopBootSessionFaultCode,
    pub message: String,
}

impl fmt::Display for SopBootSessionFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for SopBootSessionFault {}

pub fn compile_sop_boot_session(
    request: &SopBootSessionRequest,
) -> Result<SopBootSessionProposal, SopBootSessionFault> {
    validate_sop_boot_session_request(request)?;
    let mut proposal = SopBootSessionProposal {
        profile: SOP_BOOT_SESSION_PROPOSAL_PROFILE.to_owned(),
        request: request.clone(),
        lifecycle: SopBootSessionLifecycle::ProposedNotLaunched,
        authority: SopBootSessionAuthority::IdentityAndPlanningOnly,
        capability_denials: required_capability_denials(),
        request_digest: sop_boot_session_request_digest(request)?,
        proposal_digest: empty_digest(),
    };
    proposal.proposal_digest = sop_boot_session_proposal_digest(&proposal)?;
    validate_sop_boot_session_proposal(request, &proposal)?;
    Ok(proposal)
}

pub fn validate_sop_boot_session_request(
    request: &SopBootSessionRequest,
) -> Result<(), SopBootSessionFault> {
    if request.profile != SOP_BOOT_SESSION_REQUEST_PROFILE {
        return Err(fault(
            SopBootSessionFaultCode::InvalidProfile,
            "request profile differs",
        ));
    }
    validate_digest(
        &request.outer_host_identity_envelope_digest,
        "outer-host envelope digest",
    )?;
    validate_digest(&request.objective_digest, "objective digest")?;
    validate_digest(&request.authority_digest, "authority digest")?;
    validate_revision_binding(&request.boot_sop)?;

    let identities = [
        request.boot_request_id.as_str(),
        request.proposed_session_id.as_str(),
        request.outer_host_id.as_str(),
        request.objective_ref.as_str(),
        request.authority_ref.as_str(),
        request.boot_sop.canonical_sop_ref.as_str(),
        request.boot_sop.sop_revision_ref.as_str(),
        request.boot_sop.satisfaction_signature_ref.as_str(),
        request.boot_sop.procedure_candidate_ref.as_str(),
    ];
    if identities.into_iter().collect::<BTreeSet<_>>().len() != identities.len() {
        return Err(fault(
            SopBootSessionFaultCode::IdentityCollision,
            "boot request session host objective authority and SOP identities must be distinct",
        ));
    }
    validate_bounds(&request.bounds)?;
    if request.evidence_refs.is_empty() || request.evidence_refs.len() > MAX_EVIDENCE_REFS {
        return Err(fault(
            SopBootSessionFaultCode::InvalidEvidence,
            "request evidence count must be within 1..=32",
        ));
    }
    if request.unresolved_account != required_unresolved_account() {
        return Err(fault(
            SopBootSessionFaultCode::InvalidUnresolvedAccount,
            "unresolved account differs from exact SWA-01 declaration",
        ));
    }
    if request.non_authority != SOP_BOOT_SESSION_NON_AUTHORITY {
        return Err(fault(
            SopBootSessionFaultCode::InvalidAuthority,
            "request non-authority statement differs",
        ));
    }
    Ok(())
}

pub fn validate_sop_boot_session_proposal(
    expected_request: &SopBootSessionRequest,
    proposal: &SopBootSessionProposal,
) -> Result<(), SopBootSessionFault> {
    validate_sop_boot_session_request(&proposal.request)?;
    if &proposal.request != expected_request {
        return Err(fault(
            SopBootSessionFaultCode::InvalidCorrespondence,
            "proposal request differs from supplied request",
        ));
    }
    if proposal.profile != SOP_BOOT_SESSION_PROPOSAL_PROFILE {
        return Err(fault(
            SopBootSessionFaultCode::InvalidProfile,
            "proposal profile differs",
        ));
    }
    if proposal.lifecycle != SopBootSessionLifecycle::ProposedNotLaunched {
        return Err(fault(
            SopBootSessionFaultCode::InvalidLifecycle,
            "proposal lifecycle differs",
        ));
    }
    if proposal.authority != SopBootSessionAuthority::IdentityAndPlanningOnly
        || proposal.capability_denials != required_capability_denials()
    {
        return Err(fault(
            SopBootSessionFaultCode::InvalidAuthority,
            "proposal authority or capability denials differ",
        ));
    }
    let expected_request_digest = sop_boot_session_request_digest(expected_request)?;
    if proposal.request_digest != expected_request_digest {
        return Err(fault(
            SopBootSessionFaultCode::InvalidDigest,
            "request digest differs",
        ));
    }
    validate_digest(&proposal.proposal_digest, "proposal digest")?;
    if proposal.proposal_digest != sop_boot_session_proposal_digest(proposal)? {
        return Err(fault(
            SopBootSessionFaultCode::InvalidDigest,
            "proposal digest differs",
        ));
    }
    Ok(())
}

pub fn sop_boot_session_request_digest(
    request: &SopBootSessionRequest,
) -> Result<ContentDigest, SopBootSessionFault> {
    sha256_form(REQUEST_DOMAIN, request)
}

pub fn sop_boot_session_proposal_digest(
    proposal: &SopBootSessionProposal,
) -> Result<ContentDigest, SopBootSessionFault> {
    let mut body = proposal.clone();
    body.proposal_digest = empty_digest();
    sha256_form(PROPOSAL_DOMAIN, &body)
}

pub fn to_sop_boot_session_request_machine_form(
    request: &SopBootSessionRequest,
) -> Result<String, SopBootSessionFault> {
    validate_sop_boot_session_request(request)?;
    serde_json::to_string(request).map_err(machine_fault)
}

pub fn from_sop_boot_session_request_machine_form(
    value: &str,
) -> Result<SopBootSessionRequest, SopBootSessionFault> {
    let request = serde_json::from_str(value).map_err(machine_fault)?;
    validate_sop_boot_session_request(&request)?;
    Ok(request)
}

pub fn to_sop_boot_session_proposal_machine_form(
    proposal: &SopBootSessionProposal,
) -> Result<String, SopBootSessionFault> {
    validate_sop_boot_session_proposal(&proposal.request, proposal)?;
    serde_json::to_string(proposal).map_err(machine_fault)
}

pub fn from_sop_boot_session_proposal_machine_form(
    value: &str,
) -> Result<SopBootSessionProposal, SopBootSessionFault> {
    let proposal: SopBootSessionProposal = serde_json::from_str(value).map_err(machine_fault)?;
    validate_sop_boot_session_proposal(&proposal.request, &proposal)?;
    Ok(proposal)
}

fn validate_revision_binding(
    binding: &SopRevisionAdmissionBinding,
) -> Result<(), SopBootSessionFault> {
    validate_digest(&binding.sop_revision_digest, "SOP revision digest")?;
    validate_digest(
        &binding.satisfaction_signature_digest,
        "satisfaction-signature digest",
    )?;

    let receipt_ids = [
        binding.validation.receipt_id.as_str(),
        binding.compilation.receipt_id.as_str(),
        binding.verification.receipt_id.as_str(),
        binding.admission.disposition_id.as_str(),
    ];
    if receipt_ids.into_iter().collect::<BTreeSet<_>>().len() != receipt_ids.len() {
        return Err(fault(
            SopBootSessionFaultCode::InvalidRevisionBinding,
            "admission-chain receipt identities must be distinct",
        ));
    }
    let candidate = &binding.procedure_candidate_ref;
    let source_digest = &binding.sop_revision_digest;
    if binding.validation.candidate_ref != *candidate
        || binding.compilation.candidate_ref != *candidate
        || binding.verification.candidate_ref != *candidate
        || binding.admission.candidate_ref != *candidate
        || binding.validation.candidate_source_digest != *source_digest
        || binding.compilation.candidate_source_digest != *source_digest
        || binding.verification.candidate_source_digest != *source_digest
        || binding.admission.candidate_source_digest != *source_digest
    {
        return Err(fault(
            SopBootSessionFaultCode::InvalidRevisionBinding,
            "SOP revision candidate or source correspondence differs",
        ));
    }

    validate_admission_chain(binding)
}

fn validate_admission_chain(
    binding: &SopRevisionAdmissionBinding,
) -> Result<(), SopBootSessionFault> {
    let validation = &binding.validation;
    let compilation = &binding.compilation;
    let verification = &binding.verification;
    let admission = &binding.admission;
    if validation.disposition != PhaseDisposition::Passed
        || compilation.disposition != PhaseDisposition::Passed
        || verification.disposition != PhaseDisposition::Passed
        || admission.decision != AdmissionDecision::Admit
    {
        return Err(admission_fault("admission-chain disposition differs"));
    }
    let compilation_ir_ref = compilation
        .ir_ref
        .as_ref()
        .ok_or_else(|| admission_fault("passed compilation lacks IR identity"))?;
    let compilation_ir_digest = compilation
        .ir_digest
        .as_ref()
        .ok_or_else(|| admission_fault("passed compilation lacks IR digest"))?;
    if compilation.validation_receipt_ref != validation.receipt_id
        || verification.compilation_receipt_ref != compilation.receipt_id
        || verification.compiler_ref != compilation.compiler_ref
        || verification.ir_ref != *compilation_ir_ref
        || verification.ir_digest != *compilation_ir_digest
        || admission.validation_receipt_ref != validation.receipt_id
        || admission.compilation_receipt_ref != compilation.receipt_id
        || admission.verification_receipt_ref != verification.receipt_id
        || admission.compiler_ref != verification.compiler_ref
        || admission.ir_ref != verification.ir_ref
        || admission.ir_digest != verification.ir_digest
        || admission.procedure_ref != verification.compiled_procedure_ref
        || admission.procedure_digest != verification.compiled_procedure_digest
        || admission.anchor_set_digest != verification.anchor_set_digest
        || admission.effect_declaration_digest != verification.effect_declaration_digest
        || admission.bound_set_ref != verification.bound_set_ref
        || admission.bounds_digest != verification.bounds_digest
    {
        return Err(admission_fault(
            "admission-chain predecessor or semantic correspondence differs",
        ));
    }
    if admission.permitted_invocation_contexts
        != [SOP_BOOT_INVOCATION_CONTEXT.to_owned()]
            .into_iter()
            .collect()
        || admission.revocation_conditions != required_revocation_conditions()
    {
        return Err(admission_fault(
            "boot context or revocation conditions differ",
        ));
    }
    for evidence in [
        &validation.evidence,
        &compilation.evidence,
        &verification.evidence,
        &admission.evidence,
    ] {
        validate_receipt_evidence(evidence)?;
    }

    validate_receipt_digests(binding)?;
    Ok(())
}

fn validate_receipt_digests(
    binding: &SopRevisionAdmissionBinding,
) -> Result<(), SopBootSessionFault> {
    let digests = [
        &binding.validation.candidate_source_digest,
        &binding.validation.receipt_digest,
        &binding.compilation.candidate_source_digest,
        &binding.compilation.receipt_digest,
        &binding.verification.candidate_source_digest,
        &binding.verification.ir_digest,
        &binding.verification.compiled_procedure_digest,
        &binding.verification.anchor_set_digest,
        &binding.verification.effect_declaration_digest,
        &binding.verification.bounds_digest,
        &binding.verification.receipt_digest,
        &binding.admission.candidate_source_digest,
        &binding.admission.ir_digest,
        &binding.admission.procedure_digest,
        &binding.admission.anchor_set_digest,
        &binding.admission.effect_declaration_digest,
        &binding.admission.bounds_digest,
        &binding.admission.policy_digest,
        &binding.admission.disposition_digest,
    ];
    for digest in digests {
        validate_digest(digest, "admission-chain digest")?;
    }
    if let Some(digest) = &binding.compilation.ir_digest {
        validate_digest(digest, "compilation IR digest")?;
    }
    if compute_validation_receipt_digest(&binding.validation).map_err(evaluation_fault)?
        != binding.validation.receipt_digest
        || compute_compilation_receipt_digest(&binding.compilation).map_err(evaluation_fault)?
            != binding.compilation.receipt_digest
        || compute_verification_receipt_digest(&binding.verification).map_err(evaluation_fault)?
            != binding.verification.receipt_digest
        || compute_admission_disposition_digest(&binding.admission).map_err(evaluation_fault)?
            != binding.admission.disposition_digest
    {
        return Err(admission_fault(
            "admission-chain digest rederivation differs",
        ));
    }
    Ok(())
}

fn validate_receipt_evidence(evidence: &ReceiptEvidence) -> Result<(), SopBootSessionFault> {
    if evidence.evidence_refs.is_empty()
        || !evidence.residuals.is_empty()
        || !evidence.diagnostics.is_empty()
    {
        return Err(fault(
            SopBootSessionFaultCode::InvalidEvidence,
            "passed admission-chain evidence must be nonempty without residuals or diagnostics",
        ));
    }
    Ok(())
}

fn validate_bounds(bounds: &SopBootSessionBounds) -> Result<(), SopBootSessionFault> {
    if bounds.maximum_work_packets != 1
        || !(1..=MAX_CHECKPOINTS).contains(&bounds.maximum_checkpoints)
        || !(1..=MAX_UPDATE_PROPOSALS).contains(&bounds.maximum_update_proposals)
        || !(1..=MAX_TIMEOUT_SECONDS).contains(&bounds.session_timeout_seconds)
    {
        return Err(fault(
            SopBootSessionFaultCode::InvalidBounds,
            "SOP boot session bounds differ from the SWA-01 ceiling",
        ));
    }
    Ok(())
}

fn validate_digest(digest: &ContentDigest, label: &str) -> Result<(), SopBootSessionFault> {
    let valid_value = digest.value.len() == 64
        && digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if digest.algorithm != "sha256" || !valid_value {
        return Err(fault(
            SopBootSessionFaultCode::InvalidDigest,
            format!("{label} must be lower-case SHA256"),
        ));
    }
    Ok(())
}

fn required_revocation_conditions() -> BTreeSet<String> {
    [
        "admission_revoked",
        "objective_changed",
        "outer_host_identity_changed",
        "sop_revision_changed",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn required_unresolved_account() -> BTreeSet<String> {
    [
        "objective_not_executed",
        "process_not_launched",
        "sop_bytes_not_observed",
        "workspace_not_admitted",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn required_capability_denials() -> BTreeSet<SopBootCapabilityDenial> {
    [
        SopBootCapabilityDenial::ProcessLaunch,
        SopBootCapabilityDenial::WorkspaceRead,
        SopBootCapabilityDenial::WorkspaceMutation,
        SopBootCapabilityDenial::Commit,
        SopBootCapabilityDenial::Push,
        SopBootCapabilityDenial::ProviderCall,
        SopBootCapabilityDenial::Persistence,
        SopBootCapabilityDenial::ExternalEffect,
        SopBootCapabilityDenial::SopActivation,
    ]
    .into_iter()
    .collect()
}

fn sha256_form<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<ContentDigest, SopBootSessionFault> {
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

fn evaluation_fault(error: impl fmt::Display) -> SopBootSessionFault {
    admission_fault(format!("existing receipt digest failed: {error}"))
}

fn admission_fault(message: impl Into<String>) -> SopBootSessionFault {
    fault(SopBootSessionFaultCode::InvalidAdmissionChain, message)
}

fn machine_fault(error: serde_json::Error) -> SopBootSessionFault {
    fault(
        SopBootSessionFaultCode::InvalidMachineForm,
        format!("SOP boot session machine form failed: {error}"),
    )
}

fn fault(code: SopBootSessionFaultCode, message: impl Into<String>) -> SopBootSessionFault {
    SopBootSessionFault {
        code,
        message: message.into(),
    }
}
