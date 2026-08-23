//! Pure identity-only forms for the proposed outer Cantor host session.
//!
//! This module performs no I/O, observes no process, loads no model, contacts
//! no provider, and grants no launch or effect authority.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{ContentDigest, SemanticId, sha256_bytes};

pub const NESTED_OUTER_HOST_IDENTITY_REQUEST_PROFILE: &str =
    "cantor-nested-outer-host-identity-request/0.1";
pub const NESTED_OUTER_HOST_IDENTITY_ENVELOPE_PROFILE: &str =
    "cantor-nested-outer-host-identity-envelope/0.1";
pub const NESTED_OUTER_HOST_IDENTITY_NON_AUTHORITY: &str = "Identity-only proposed outer Cantor host envelope. No process was observed or launched, no model was available or loaded, no provider was contacted, and no inner host, shared attention, persistence, remote access, or external effect is authorized.";

const REQUEST_DOMAIN: &str = "cantor.nested-outer-host-identity.request.v1";
const ENVELOPE_DOMAIN: &str = "cantor.nested-outer-host-identity.envelope.v1";
const MAX_TEXT_BYTES: usize = 512;
const MAX_EVIDENCE_REFS: usize = 32;
const MAX_ATTENTION_FRAME_BYTES: u64 = 33_554_432;
const MAX_ITERATIONS: u32 = 64;
const MAX_TIMEOUT_SECONDS: u32 = 86_400;

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OuterHostKind {
    SlimCantor,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OuterProcessBindingState {
    DeclaredUnobserved,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OuterModelRole {
    SopSelector,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OuterModelBindingState {
    DeclaredUnloaded,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OuterHostIdentityLifecycle {
    ProposedIdentityOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OuterHostIdentityAuthority {
    IdentityOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OuterHostCapabilityDenial {
    ProcessLaunch,
    ModelLoad,
    ProviderCall,
    Persistence,
    ExternalEffect,
    RemoteAccess,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OuterHostProcessBinding {
    pub process_id: SemanticId,
    pub host_kind: OuterHostKind,
    pub binding_state: OuterProcessBindingState,
    pub implementation_digest: ContentDigest,
    pub configuration_digest: ContentDigest,
    pub supervisor_profile: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OuterHostModelBinding {
    pub model_id: SemanticId,
    pub role: OuterModelRole,
    pub binding_state: OuterModelBindingState,
    pub provider_family: String,
    pub model_selector: String,
    pub artifact_digest: ContentDigest,
    pub runtime_digest: ContentDigest,
    pub configuration_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedHostSessionBounds {
    pub maximum_inner_processes: u32,
    pub maximum_model_instances: u32,
    pub maximum_attention_frame_bytes: u64,
    pub maximum_iterations: u32,
    pub session_timeout_seconds: u32,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedOuterHostIdentityRequest {
    pub profile: String,
    pub session_id: SemanticId,
    pub outer_host_id: SemanticId,
    pub authority_ref: SemanticId,
    pub authority_digest: ContentDigest,
    pub process: OuterHostProcessBinding,
    pub model: OuterHostModelBinding,
    pub bounds: NestedHostSessionBounds,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub unresolved_account: BTreeSet<String>,
    pub non_authority: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedOuterHostIdentityEnvelope {
    pub profile: String,
    pub request: NestedOuterHostIdentityRequest,
    pub lifecycle: OuterHostIdentityLifecycle,
    pub authority: OuterHostIdentityAuthority,
    pub capability_denials: BTreeSet<OuterHostCapabilityDenial>,
    pub request_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NestedHostIdentityFaultCode {
    InvalidProfile,
    IdentityCollision,
    InvalidDigest,
    InvalidText,
    InvalidProcessBinding,
    InvalidModelBinding,
    InvalidBounds,
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
pub struct NestedHostIdentityFault {
    pub code: NestedHostIdentityFaultCode,
    pub message: String,
}

impl fmt::Display for NestedHostIdentityFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for NestedHostIdentityFault {}

pub fn compile_nested_outer_host_identity(
    request: &NestedOuterHostIdentityRequest,
) -> Result<NestedOuterHostIdentityEnvelope, NestedHostIdentityFault> {
    validate_nested_outer_host_identity_request(request)?;
    let mut envelope = NestedOuterHostIdentityEnvelope {
        profile: NESTED_OUTER_HOST_IDENTITY_ENVELOPE_PROFILE.to_owned(),
        request: request.clone(),
        lifecycle: OuterHostIdentityLifecycle::ProposedIdentityOnly,
        authority: OuterHostIdentityAuthority::IdentityOnly,
        capability_denials: required_capability_denials(),
        request_digest: nested_outer_host_identity_request_digest(request)?,
        envelope_digest: empty_digest(),
    };
    envelope.envelope_digest = nested_outer_host_identity_envelope_digest(&envelope)?;
    validate_nested_outer_host_identity_envelope(request, &envelope)?;
    Ok(envelope)
}

pub fn validate_nested_outer_host_identity_request(
    request: &NestedOuterHostIdentityRequest,
) -> Result<(), NestedHostIdentityFault> {
    if request.profile != NESTED_OUTER_HOST_IDENTITY_REQUEST_PROFILE {
        return Err(fault(
            NestedHostIdentityFaultCode::InvalidProfile,
            "request profile differs",
        ));
    }
    validate_digest(&request.authority_digest, "authority digest")?;
    validate_process_binding(&request.process)?;
    validate_model_binding(&request.model)?;
    validate_bounds(&request.bounds)?;

    let identities = [
        request.session_id.as_str(),
        request.outer_host_id.as_str(),
        request.process.process_id.as_str(),
        request.model.model_id.as_str(),
    ];
    let distinct = identities.into_iter().collect::<BTreeSet<_>>();
    if distinct.len() != identities.len() {
        return Err(fault(
            NestedHostIdentityFaultCode::IdentityCollision,
            "session host process and model identities must be distinct",
        ));
    }

    if request.evidence_refs.is_empty() || request.evidence_refs.len() > MAX_EVIDENCE_REFS {
        return Err(fault(
            NestedHostIdentityFaultCode::InvalidEvidence,
            "evidence reference count must be within 1..=32",
        ));
    }
    if request.unresolved_account != required_unresolved_account() {
        return Err(fault(
            NestedHostIdentityFaultCode::InvalidUnresolvedAccount,
            "unresolved account differs from exact P0 declaration",
        ));
    }
    if request.non_authority != NESTED_OUTER_HOST_IDENTITY_NON_AUTHORITY {
        return Err(fault(
            NestedHostIdentityFaultCode::InvalidAuthority,
            "request non-authority statement differs",
        ));
    }
    Ok(())
}

pub fn validate_nested_outer_host_identity_envelope(
    expected_request: &NestedOuterHostIdentityRequest,
    envelope: &NestedOuterHostIdentityEnvelope,
) -> Result<(), NestedHostIdentityFault> {
    validate_nested_outer_host_identity_request(&envelope.request)?;
    if &envelope.request != expected_request {
        return Err(fault(
            NestedHostIdentityFaultCode::InvalidCorrespondence,
            "envelope request differs from supplied request",
        ));
    }
    if envelope.profile != NESTED_OUTER_HOST_IDENTITY_ENVELOPE_PROFILE {
        return Err(fault(
            NestedHostIdentityFaultCode::InvalidProfile,
            "envelope profile differs",
        ));
    }
    if envelope.lifecycle != OuterHostIdentityLifecycle::ProposedIdentityOnly {
        return Err(fault(
            NestedHostIdentityFaultCode::InvalidLifecycle,
            "envelope lifecycle differs",
        ));
    }
    if envelope.authority != OuterHostIdentityAuthority::IdentityOnly
        || envelope.capability_denials != required_capability_denials()
    {
        return Err(fault(
            NestedHostIdentityFaultCode::InvalidAuthority,
            "envelope authority or capability denials differ",
        ));
    }
    let expected_request_digest = nested_outer_host_identity_request_digest(expected_request)?;
    if envelope.request_digest != expected_request_digest {
        return Err(fault(
            NestedHostIdentityFaultCode::InvalidDigest,
            "request digest differs",
        ));
    }
    validate_digest(&envelope.envelope_digest, "envelope digest")?;
    if envelope.envelope_digest != nested_outer_host_identity_envelope_digest(envelope)? {
        return Err(fault(
            NestedHostIdentityFaultCode::InvalidDigest,
            "envelope digest differs",
        ));
    }
    Ok(())
}

pub fn nested_outer_host_identity_request_digest(
    request: &NestedOuterHostIdentityRequest,
) -> Result<ContentDigest, NestedHostIdentityFault> {
    sha256_form(REQUEST_DOMAIN, request)
}

pub fn nested_outer_host_identity_envelope_digest(
    envelope: &NestedOuterHostIdentityEnvelope,
) -> Result<ContentDigest, NestedHostIdentityFault> {
    let mut body = envelope.clone();
    body.envelope_digest = empty_digest();
    sha256_form(ENVELOPE_DOMAIN, &body)
}

pub fn to_nested_outer_host_identity_request_machine_form(
    request: &NestedOuterHostIdentityRequest,
) -> Result<String, NestedHostIdentityFault> {
    validate_nested_outer_host_identity_request(request)?;
    serde_json::to_string(request).map_err(machine_fault)
}

pub fn from_nested_outer_host_identity_request_machine_form(
    value: &str,
) -> Result<NestedOuterHostIdentityRequest, NestedHostIdentityFault> {
    let request: NestedOuterHostIdentityRequest =
        serde_json::from_str(value).map_err(machine_fault)?;
    validate_nested_outer_host_identity_request(&request)?;
    Ok(request)
}

pub fn to_nested_outer_host_identity_envelope_machine_form(
    envelope: &NestedOuterHostIdentityEnvelope,
) -> Result<String, NestedHostIdentityFault> {
    validate_nested_outer_host_identity_envelope(&envelope.request, envelope)?;
    serde_json::to_string(envelope).map_err(machine_fault)
}

pub fn from_nested_outer_host_identity_envelope_machine_form(
    value: &str,
) -> Result<NestedOuterHostIdentityEnvelope, NestedHostIdentityFault> {
    let envelope: NestedOuterHostIdentityEnvelope =
        serde_json::from_str(value).map_err(machine_fault)?;
    validate_nested_outer_host_identity_envelope(&envelope.request, &envelope)?;
    Ok(envelope)
}

fn validate_process_binding(
    binding: &OuterHostProcessBinding,
) -> Result<(), NestedHostIdentityFault> {
    if binding.host_kind != OuterHostKind::SlimCantor
        || binding.binding_state != OuterProcessBindingState::DeclaredUnobserved
    {
        return Err(fault(
            NestedHostIdentityFaultCode::InvalidProcessBinding,
            "outer process binding must remain slim-cantor declared-unobserved",
        ));
    }
    validate_digest(
        &binding.implementation_digest,
        "process implementation digest",
    )?;
    validate_digest(
        &binding.configuration_digest,
        "process configuration digest",
    )?;
    validate_text(&binding.supervisor_profile, "supervisor profile")
}

fn validate_model_binding(binding: &OuterHostModelBinding) -> Result<(), NestedHostIdentityFault> {
    if binding.role != OuterModelRole::SopSelector
        || binding.binding_state != OuterModelBindingState::DeclaredUnloaded
    {
        return Err(fault(
            NestedHostIdentityFaultCode::InvalidModelBinding,
            "outer model binding must remain SOP-selector declared-unloaded",
        ));
    }
    validate_text(&binding.provider_family, "provider family")?;
    validate_text(&binding.model_selector, "model selector")?;
    validate_digest(&binding.artifact_digest, "model artifact digest")?;
    validate_digest(&binding.runtime_digest, "model runtime digest")?;
    validate_digest(&binding.configuration_digest, "model configuration digest")
}

fn validate_bounds(bounds: &NestedHostSessionBounds) -> Result<(), NestedHostIdentityFault> {
    if bounds.maximum_inner_processes != 1
        || bounds.maximum_model_instances != 2
        || !(1..=MAX_ATTENTION_FRAME_BYTES).contains(&bounds.maximum_attention_frame_bytes)
        || !(1..=MAX_ITERATIONS).contains(&bounds.maximum_iterations)
        || !(1..=MAX_TIMEOUT_SECONDS).contains(&bounds.session_timeout_seconds)
    {
        return Err(fault(
            NestedHostIdentityFaultCode::InvalidBounds,
            "nested host session bounds differ from the P0 ceiling",
        ));
    }
    Ok(())
}

fn validate_text(value: &str, label: &str) -> Result<(), NestedHostIdentityFault> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(char::is_control)
        || value.trim() != value
    {
        return Err(fault(
            NestedHostIdentityFaultCode::InvalidText,
            format!("{label} is empty unbounded contains control text or surrounding whitespace"),
        ));
    }
    Ok(())
}

fn validate_digest(digest: &ContentDigest, label: &str) -> Result<(), NestedHostIdentityFault> {
    let valid_value = digest.value.len() == 64
        && digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if digest.algorithm != "sha256" || !valid_value {
        return Err(fault(
            NestedHostIdentityFaultCode::InvalidDigest,
            format!("{label} must be lowercase SHA256"),
        ));
    }
    Ok(())
}

fn required_unresolved_account() -> BTreeSet<String> {
    [
        "model_not_loaded",
        "physical_process_not_observed",
        "provider_not_contacted",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn required_capability_denials() -> BTreeSet<OuterHostCapabilityDenial> {
    [
        OuterHostCapabilityDenial::ProcessLaunch,
        OuterHostCapabilityDenial::ModelLoad,
        OuterHostCapabilityDenial::ProviderCall,
        OuterHostCapabilityDenial::Persistence,
        OuterHostCapabilityDenial::ExternalEffect,
        OuterHostCapabilityDenial::RemoteAccess,
    ]
    .into_iter()
    .collect()
}

fn sha256_form<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<ContentDigest, NestedHostIdentityFault> {
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

fn machine_fault(error: serde_json::Error) -> NestedHostIdentityFault {
    fault(
        NestedHostIdentityFaultCode::InvalidMachineForm,
        format!("nested outer host identity machine form failed: {error}"),
    )
}

fn fault(code: NestedHostIdentityFaultCode, message: impl Into<String>) -> NestedHostIdentityFault {
    NestedHostIdentityFault {
        code,
        message: message.into(),
    }
}
