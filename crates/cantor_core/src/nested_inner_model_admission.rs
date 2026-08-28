//! Pure provider-free forms for an inner model descriptor, proposed instance,
//! and detached model-load authorization.
//!
//! This module validates supplied data and Ed25519 correspondence only. It
//! performs no I/O, observes no artifact bytes, loads no model, contacts no
//! provider, launches no process, and grants no physical-effect authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    ContentDigest, NestedInnerProcessLineageEnvelope, NestedInnerProcessLineageRequest,
    NestedInnerProcessLineageVerification, SemanticId, sha256_bytes,
    validate_nested_inner_process_lineage_envelope, validate_nested_inner_process_lineage_request,
    validate_nested_inner_process_lineage_verification, verify_nested_inner_process_lineage,
};

pub const NESTED_INNER_MODEL_ADMISSION_REQUEST_PROFILE: &str =
    "cantor-nested-inner-model-admission-request/0.1";
pub const NESTED_INNER_MODEL_ADMISSION_ENVELOPE_PROFILE: &str =
    "cantor-nested-inner-model-admission-envelope/0.1";
pub const NESTED_INNER_MODEL_ADMISSION_VERIFICATION_PROFILE: &str =
    "cantor-nested-inner-model-admission-verification/0.1";
pub const NESTED_INNER_MODEL_ADMISSION_EVIDENCE_PROFILE: &str =
    "cantor-nested-inner-model-admission-evidence/0.1";
pub const NESTED_INNER_MODEL_ADMISSION_NON_AUTHORITY: &str = "Supplied descriptor and Ed25519 correspondence only. It does not establish artifact file presence or bytes, policy governance, key custody, revocation, freshness, model-load attempt or completion, runtime observation, provider contact, inference, process launch, custody, shared attention, workspace mutation, persistence, remote access, or external-effect authority.";
pub const NESTED_INNER_MODEL_ADMISSION_MAX_MACHINE_FORM_BYTES: usize = 1_048_576;
pub const NESTED_INNER_MODEL_ADMISSION_MAX_EVIDENCE_BUNDLE_BYTES: usize = 4_194_304;

const UPSTREAM_DOMAIN: &str = "cantor.nested-inner-model-admission.upstream.v1";
const DESCRIPTOR_DOMAIN: &str = "cantor.nested-inner-model-admission.descriptor.v1";
const AUTHORIZATION_DOMAIN: &str = "cantor.nested-inner-model-admission.authorization.v1";
const REQUEST_DOMAIN: &str = "cantor.nested-inner-model-admission.request.v1";
const ENVELOPE_DOMAIN: &str = "cantor.nested-inner-model-admission.envelope.v1";
const MAX_DEPTH: usize = 24;
const MAX_FIELDS: usize = 320;
const MAX_TEXT_BYTES: usize = 1024;
const MAX_EVIDENCE_REFS: usize = 32;
const MAX_ARTIFACT_BYTES: u64 = 549_755_813_888;
const MAX_CONTEXT_TOKENS: u32 = 1_048_576;
const MAX_THREADS: u32 = 1024;
const MAX_GPU_LAYERS: u32 = 65_535;
const REQUEST_EVIDENCE_PATH: &str = "request.json";
const ENVELOPE_EVIDENCE_PATH: &str = "envelope.json";
const VERIFICATION_EVIDENCE_PATH: &str = "verification.json";

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InnerModelArtifactState {
    SuppliedDescriptorUnobserved,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InnerModelInstanceState {
    ProposedUnloaded,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelLoadAction {
    ModelLoad,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelLoadAuthorizationDisposition {
    AuthorizedForLaterSingleAttempt,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelLoadAuthorizationConsumptionState {
    Unconsumed,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NestedInnerModelAdmissionLifecycle {
    AdmittedDescriptorAndAuthorizationOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NestedInnerModelAdmissionAuthority {
    SuppliedKeyCryptographicModelLoadAuthorizationOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NestedInnerModelAdmissionCapabilityDenial {
    ArtifactFileObservation,
    ArtifactByteReacquisition,
    ArtifactDownload,
    ArtifactInstall,
    ModelLoadAttempt,
    ModelLoadCompletion,
    RuntimeObservation,
    ProviderCall,
    Inference,
    ProcessLaunch,
    SharedAttention,
    Persistence,
    WorkspaceMutation,
    RemoteAccess,
    ExternalEffect,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InnerModelArtifactDescriptor {
    pub artifact_id: SemanticId,
    pub state: InnerModelArtifactState,
    pub content_digest: ContentDigest,
    pub bytes: u64,
    pub format: String,
    pub family_selector: String,
    pub architecture_selector: String,
    pub quantization_selector: String,
    pub provenance_ref: SemanticId,
    pub license_policy_ref: SemanticId,
    pub safety_policy_ref: SemanticId,
    pub descriptor_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposedInnerModelInstance {
    pub model_instance_id: SemanticId,
    pub state: InnerModelInstanceState,
    pub configuration_digest: ContentDigest,
    pub context_token_ceiling: u32,
    pub memory_byte_ceiling: u64,
    pub thread_ceiling: u32,
    pub gpu_layer_ceiling: u32,
    pub backend_selector: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InnerModelLoadAuthorization {
    pub authorization_id: SemanticId,
    pub issuer_ref: SemanticId,
    pub subject_inner_cantor_id: SemanticId,
    pub artifact_id: SemanticId,
    pub model_instance_id: SemanticId,
    pub action: ModelLoadAction,
    pub policy_digest: ContentDigest,
    pub nonce_digest: ContentDigest,
    pub sequence_lower_bound: u64,
    pub sequence_upper_bound: u64,
    pub attempt_limit: u32,
    pub retry_limit: u32,
    pub disposition: ModelLoadAuthorizationDisposition,
    pub consumption_state: ModelLoadAuthorizationConsumptionState,
    pub verifying_key_hex: String,
    pub signature_hex: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInnerModelAdmissionRequest {
    pub profile: String,
    pub request_id: SemanticId,
    pub upstream_request: NestedInnerProcessLineageRequest,
    pub upstream_envelope: NestedInnerProcessLineageEnvelope,
    pub upstream_verification: NestedInnerProcessLineageVerification,
    pub upstream_bundle_digest: ContentDigest,
    pub descriptor: InnerModelArtifactDescriptor,
    pub instance: ProposedInnerModelInstance,
    pub authorization: InnerModelLoadAuthorization,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub unresolved_account: BTreeSet<String>,
    pub non_authority: String,
    pub request_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInnerModelAdmissionEnvelope {
    pub profile: String,
    pub request: NestedInnerModelAdmissionRequest,
    pub lifecycle: NestedInnerModelAdmissionLifecycle,
    pub authority: NestedInnerModelAdmissionAuthority,
    pub capability_denials: BTreeSet<NestedInnerModelAdmissionCapabilityDenial>,
    pub upstream_bundle_digest: ContentDigest,
    pub descriptor_digest: ContentDigest,
    pub request_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInnerModelAdmissionEffectAccount {
    pub authorization_issued: bool,
    pub artifact_file_observed: bool,
    pub artifact_bytes_reacquired: bool,
    pub model_load_attempt_count: u32,
    pub model_load_completion_count: u32,
    pub runtime_model_observed: bool,
    pub provider_trial_count: u32,
    pub model_turn_count: u32,
    pub process_count: u32,
    pub mcp_call_count: u32,
    pub workspace_mutation_count: u32,
    pub network_contact_count: u32,
    pub remote_contact_count: u32,
    pub persistence_count: u32,
    pub activation_count: u32,
    pub cleanup_effect_count: u32,
    pub foreign_effect_count: u32,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInnerModelAdmissionVerification {
    pub profile: String,
    pub status: String,
    pub authority: NestedInnerModelAdmissionAuthority,
    pub upstream_bundle_digest: ContentDigest,
    pub descriptor_digest: ContentDigest,
    pub request_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
    pub upstream_operational_identity_count: u32,
    pub operational_identity_count: u32,
    pub bound_identity_count: u32,
    pub capability_denial_count: u32,
    pub unresolved_truth_count: u32,
    pub signature_correspondence_verified: bool,
    pub effects: NestedInnerModelAdmissionEffectAccount,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInnerModelAdmissionEvidenceFile {
    pub path: String,
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInnerModelAdmissionEvidenceManifest {
    pub profile: String,
    pub replay_count: u32,
    pub files: BTreeMap<String, NestedInnerModelAdmissionEvidenceFile>,
    pub upstream_operational_identity_count: u32,
    pub operational_identity_count: u32,
    pub bound_identity_count: u32,
    pub capability_denial_count: u32,
    pub unresolved_truth_count: u32,
    pub signature_correspondence_verified: bool,
    pub effects: NestedInnerModelAdmissionEffectAccount,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInnerModelAdmissionEvidenceBundle {
    pub request_file: String,
    pub envelope_file: String,
    pub verification_file: String,
    pub manifest_file: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NestedInnerModelAdmissionFaultCode {
    InvalidProfile,
    InvalidMachineForm,
    InvalidUpstream,
    InvalidIdentity,
    IdentityCollision,
    InvalidDescriptor,
    InvalidInstance,
    InvalidAuthorization,
    InvalidSignature,
    InvalidBounds,
    InvalidEvidence,
    InvalidUnresolvedAccount,
    InvalidAuthority,
    InvalidLifecycle,
    InvalidDigest,
    InvalidCorrespondence,
    InvalidVerification,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInnerModelAdmissionFault {
    pub code: NestedInnerModelAdmissionFaultCode,
    pub message: String,
}

impl fmt::Display for NestedInnerModelAdmissionFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for NestedInnerModelAdmissionFault {}

#[derive(Serialize)]
struct AuthorizationPayload<'a> {
    domain: &'static str,
    upstream_bundle_digest: &'a ContentDigest,
    descriptor_digest: &'a ContentDigest,
    instance: &'a ProposedInnerModelInstance,
    authorization_id: &'a SemanticId,
    issuer_ref: &'a SemanticId,
    subject_inner_cantor_id: &'a SemanticId,
    artifact_id: &'a SemanticId,
    model_instance_id: &'a SemanticId,
    action: ModelLoadAction,
    policy_digest: &'a ContentDigest,
    nonce_digest: &'a ContentDigest,
    sequence_lower_bound: u64,
    sequence_upper_bound: u64,
    attempt_limit: u32,
    retry_limit: u32,
    disposition: ModelLoadAuthorizationDisposition,
    consumption_state: ModelLoadAuthorizationConsumptionState,
    verifying_key_hex: &'a str,
}

pub fn seal_inner_model_artifact_descriptor(
    mut descriptor: InnerModelArtifactDescriptor,
) -> Result<InnerModelArtifactDescriptor, NestedInnerModelAdmissionFault> {
    descriptor.descriptor_digest = empty_digest();
    validate_descriptor_body(&descriptor)?;
    descriptor.descriptor_digest = inner_model_artifact_descriptor_digest(&descriptor)?;
    validate_descriptor(&descriptor)?;
    Ok(descriptor)
}

pub fn seal_nested_inner_model_admission_request(
    mut request: NestedInnerModelAdmissionRequest,
) -> Result<NestedInnerModelAdmissionRequest, NestedInnerModelAdmissionFault> {
    request.upstream_bundle_digest = nested_inner_model_upstream_bundle_digest(
        &request.upstream_request,
        &request.upstream_envelope,
        &request.upstream_verification,
    )?;
    request.request_digest = empty_digest();
    validate_request_body(&request)?;
    request.request_digest = nested_inner_model_admission_request_digest(&request)?;
    validate_nested_inner_model_admission_request(&request)?;
    Ok(request)
}

pub fn compile_nested_inner_model_admission(
    request: &NestedInnerModelAdmissionRequest,
) -> Result<NestedInnerModelAdmissionEnvelope, NestedInnerModelAdmissionFault> {
    validate_nested_inner_model_admission_request(request)?;
    let mut envelope = NestedInnerModelAdmissionEnvelope {
        profile: NESTED_INNER_MODEL_ADMISSION_ENVELOPE_PROFILE.to_owned(),
        request: request.clone(),
        lifecycle: NestedInnerModelAdmissionLifecycle::AdmittedDescriptorAndAuthorizationOnly,
        authority:
            NestedInnerModelAdmissionAuthority::SuppliedKeyCryptographicModelLoadAuthorizationOnly,
        capability_denials: required_capability_denials(),
        upstream_bundle_digest: request.upstream_bundle_digest.clone(),
        descriptor_digest: request.descriptor.descriptor_digest.clone(),
        request_digest: request.request_digest.clone(),
        envelope_digest: empty_digest(),
    };
    envelope.envelope_digest = nested_inner_model_admission_envelope_digest(&envelope)?;
    validate_nested_inner_model_admission_envelope(request, &envelope)?;
    Ok(envelope)
}

pub fn validate_nested_inner_model_admission_request(
    request: &NestedInnerModelAdmissionRequest,
) -> Result<(), NestedInnerModelAdmissionFault> {
    validate_request_body(request)?;
    validate_digest(&request.request_digest, "request digest")?;
    if request.request_digest != nested_inner_model_admission_request_digest(request)? {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidDigest,
            "request digest differs",
        ));
    }
    Ok(())
}

fn validate_request_body(
    request: &NestedInnerModelAdmissionRequest,
) -> Result<(), NestedInnerModelAdmissionFault> {
    if request.profile != NESTED_INNER_MODEL_ADMISSION_REQUEST_PROFILE {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidProfile,
            "request profile differs",
        ));
    }
    validate_uuid_semantic_id(&request.request_id, "model-admission-request:", "request")?;
    validate_upstream(request)?;
    validate_descriptor(&request.descriptor)?;
    validate_instance(&request.instance)?;
    validate_bound_identities(request)?;
    validate_authorization(request)?;
    if request.evidence_refs.is_empty() || request.evidence_refs.len() > MAX_EVIDENCE_REFS {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidEvidence,
            "evidence reference count must be within 1..=32",
        ));
    }
    if request.unresolved_account != required_unresolved_account() {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidUnresolvedAccount,
            "unresolved account differs",
        ));
    }
    if request.non_authority != NESTED_INNER_MODEL_ADMISSION_NON_AUTHORITY {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidAuthority,
            "request non-authority differs",
        ));
    }
    Ok(())
}

fn validate_upstream(
    request: &NestedInnerModelAdmissionRequest,
) -> Result<(), NestedInnerModelAdmissionFault> {
    validate_nested_inner_process_lineage_request(&request.upstream_request)
        .map_err(|error| upstream_fault("request", error))?;
    validate_nested_inner_process_lineage_envelope(
        &request.upstream_request,
        &request.upstream_envelope,
    )
    .map_err(|error| upstream_fault("envelope", error))?;
    validate_nested_inner_process_lineage_verification(&request.upstream_verification)
        .map_err(|error| upstream_fault("verification", error))?;
    if request.upstream_envelope.request != request.upstream_request
        || verify_nested_inner_process_lineage(&request.upstream_envelope)
            .map_err(|error| upstream_fault("replay", error))?
            != request.upstream_verification
    {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidUpstream,
            "complete NHC-02 bundle correspondence differs",
        ));
    }
    validate_digest(&request.upstream_bundle_digest, "upstream bundle digest")?;
    if request.upstream_bundle_digest
        != nested_inner_model_upstream_bundle_digest(
            &request.upstream_request,
            &request.upstream_envelope,
            &request.upstream_verification,
        )?
    {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidDigest,
            "upstream bundle digest differs",
        ));
    }
    Ok(())
}

fn validate_descriptor(
    descriptor: &InnerModelArtifactDescriptor,
) -> Result<(), NestedInnerModelAdmissionFault> {
    validate_descriptor_body(descriptor)?;
    validate_digest(&descriptor.descriptor_digest, "descriptor digest")?;
    if descriptor.descriptor_digest != inner_model_artifact_descriptor_digest(descriptor)? {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidDigest,
            "descriptor digest differs",
        ));
    }
    Ok(())
}

fn validate_descriptor_body(
    descriptor: &InnerModelArtifactDescriptor,
) -> Result<(), NestedInnerModelAdmissionFault> {
    validate_uuid_semantic_id(&descriptor.artifact_id, "model-artifact:", "artifact")?;
    if descriptor.state != InnerModelArtifactState::SuppliedDescriptorUnobserved
        || descriptor.bytes == 0
        || descriptor.bytes > MAX_ARTIFACT_BYTES
        || descriptor.format != "gguf"
    {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidDescriptor,
            "descriptor state byte bound or format differs",
        ));
    }
    validate_digest(&descriptor.content_digest, "artifact content digest")?;
    for (value, label) in [
        (&descriptor.family_selector, "family selector"),
        (&descriptor.architecture_selector, "architecture selector"),
        (&descriptor.quantization_selector, "quantization selector"),
    ] {
        if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
            return Err(fault(
                NestedInnerModelAdmissionFaultCode::InvalidDescriptor,
                format!("{label} is empty oversized or contains control text"),
            ));
        }
    }
    Ok(())
}

fn validate_instance(
    instance: &ProposedInnerModelInstance,
) -> Result<(), NestedInnerModelAdmissionFault> {
    validate_uuid_semantic_id(
        &instance.model_instance_id,
        "inner-model-instance:",
        "model instance",
    )?;
    validate_digest(
        &instance.configuration_digest,
        "instance configuration digest",
    )?;
    if instance.state != InnerModelInstanceState::ProposedUnloaded
        || !(256..=MAX_CONTEXT_TOKENS).contains(&instance.context_token_ceiling)
        || instance.memory_byte_ceiling == 0
        || instance.memory_byte_ceiling > MAX_ARTIFACT_BYTES
        || !(1..=MAX_THREADS).contains(&instance.thread_ceiling)
        || instance.gpu_layer_ceiling > MAX_GPU_LAYERS
        || instance.backend_selector.is_empty()
        || instance.backend_selector.len() > 128
        || instance.backend_selector.chars().any(char::is_control)
    {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidInstance,
            "proposed instance state or resource ceilings differ",
        ));
    }
    Ok(())
}

fn validate_authorization(
    request: &NestedInnerModelAdmissionRequest,
) -> Result<(), NestedInnerModelAdmissionFault> {
    let authorization = &request.authorization;
    validate_uuid_semantic_id(
        &authorization.authorization_id,
        "model-load-authorization:",
        "authorization",
    )?;
    if authorization.subject_inner_cantor_id != request.upstream_request.inner.inner_cantor_id
        || authorization.artifact_id != request.descriptor.artifact_id
        || authorization.model_instance_id != request.instance.model_instance_id
        || authorization.action != ModelLoadAction::ModelLoad
        || authorization.sequence_lower_bound > authorization.sequence_upper_bound
        || authorization.attempt_limit != 1
        || authorization.retry_limit != 0
        || authorization.disposition
            != ModelLoadAuthorizationDisposition::AuthorizedForLaterSingleAttempt
        || authorization.consumption_state != ModelLoadAuthorizationConsumptionState::Unconsumed
    {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidAuthorization,
            "authorization tuple range or single-attempt disposition differs",
        ));
    }
    validate_digest(&authorization.policy_digest, "authorization policy digest")?;
    validate_digest(&authorization.nonce_digest, "authorization nonce digest")?;
    let key = decode_fixed_hex::<32>(&authorization.verifying_key_hex, "verifying key")?;
    let verifying_key = VerifyingKey::from_bytes(&key).map_err(|_| {
        fault(
            NestedInnerModelAdmissionFaultCode::InvalidSignature,
            "authorization verifying key refused",
        )
    })?;
    let signature_bytes =
        decode_fixed_hex::<64>(&authorization.signature_hex, "authorization signature")?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(
            &nested_inner_model_authorization_payload_bytes(request)?,
            &signature,
        )
        .map_err(|_| {
            fault(
                NestedInnerModelAdmissionFaultCode::InvalidSignature,
                "authorization signature refused",
            )
        })
}

fn validate_bound_identities(
    request: &NestedInnerModelAdmissionRequest,
) -> Result<(), NestedInnerModelAdmissionFault> {
    let identities = [
        uuid_component(&request.upstream_request.parent.request.session_id),
        uuid_component(&request.upstream_request.parent.request.outer_host_id),
        uuid_component(&request.upstream_request.parent.request.process.process_id),
        uuid_component(&request.upstream_request.parent.request.model.model_id),
        uuid_component(&request.upstream_request.inner.inner_session_id),
        uuid_component(&request.upstream_request.inner.inner_cantor_id),
        uuid_component(&request.upstream_request.inner.inner_process_id),
        uuid_component(&request.descriptor.artifact_id),
        uuid_component(&request.instance.model_instance_id),
        uuid_component(&request.authorization.authorization_id),
    ];
    if identities.into_iter().collect::<BTreeSet<_>>().len() != identities.len() {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::IdentityCollision,
            "seven upstream plus artifact instance and authorization identities must be distinct",
        ));
    }
    Ok(())
}

fn uuid_component(id: &SemanticId) -> &str {
    id.as_str()
        .rsplit_once(':')
        .map_or(id.as_str(), |(_, uuid)| uuid)
}

pub fn validate_nested_inner_model_admission_envelope(
    expected_request: &NestedInnerModelAdmissionRequest,
    envelope: &NestedInnerModelAdmissionEnvelope,
) -> Result<(), NestedInnerModelAdmissionFault> {
    validate_nested_inner_model_admission_request(&envelope.request)?;
    if &envelope.request != expected_request {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidCorrespondence,
            "envelope request differs",
        ));
    }
    if envelope.profile != NESTED_INNER_MODEL_ADMISSION_ENVELOPE_PROFILE {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidProfile,
            "envelope profile differs",
        ));
    }
    if envelope.lifecycle
        != NestedInnerModelAdmissionLifecycle::AdmittedDescriptorAndAuthorizationOnly
    {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidLifecycle,
            "envelope lifecycle differs",
        ));
    }
    if envelope.authority
        != NestedInnerModelAdmissionAuthority::SuppliedKeyCryptographicModelLoadAuthorizationOnly
        || envelope.capability_denials != required_capability_denials()
    {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidAuthority,
            "envelope authority or denials differ",
        ));
    }
    if envelope.upstream_bundle_digest != expected_request.upstream_bundle_digest
        || envelope.descriptor_digest != expected_request.descriptor.descriptor_digest
        || envelope.request_digest != expected_request.request_digest
    {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidDigest,
            "envelope bound digest differs",
        ));
    }
    validate_digest(&envelope.envelope_digest, "envelope digest")?;
    if envelope.envelope_digest != nested_inner_model_admission_envelope_digest(envelope)? {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidDigest,
            "envelope digest differs",
        ));
    }
    Ok(())
}

pub fn verify_nested_inner_model_admission(
    envelope: &NestedInnerModelAdmissionEnvelope,
) -> Result<NestedInnerModelAdmissionVerification, NestedInnerModelAdmissionFault> {
    validate_nested_inner_model_admission_envelope(&envelope.request, envelope)?;
    Ok(NestedInnerModelAdmissionVerification {
        profile: NESTED_INNER_MODEL_ADMISSION_VERIFICATION_PROFILE.to_owned(),
        status: "verified_provider_free_descriptor_and_authorization_correspondence".to_owned(),
        authority:
            NestedInnerModelAdmissionAuthority::SuppliedKeyCryptographicModelLoadAuthorizationOnly,
        upstream_bundle_digest: envelope.upstream_bundle_digest.clone(),
        descriptor_digest: envelope.descriptor_digest.clone(),
        request_digest: envelope.request_digest.clone(),
        envelope_digest: envelope.envelope_digest.clone(),
        upstream_operational_identity_count: 7,
        operational_identity_count: 8,
        bound_identity_count: 10,
        capability_denial_count: 15,
        unresolved_truth_count: 10,
        signature_correspondence_verified: true,
        effects: zero_effect_account(),
    })
}

pub fn validate_nested_inner_model_admission_verification(
    verification: &NestedInnerModelAdmissionVerification,
) -> Result<(), NestedInnerModelAdmissionFault> {
    if verification.profile != NESTED_INNER_MODEL_ADMISSION_VERIFICATION_PROFILE
        || verification.status
            != "verified_provider_free_descriptor_and_authorization_correspondence"
        || verification.authority
            != NestedInnerModelAdmissionAuthority::SuppliedKeyCryptographicModelLoadAuthorizationOnly
        || verification.upstream_operational_identity_count != 7
        || verification.operational_identity_count != 8
        || verification.bound_identity_count != 10
        || verification.capability_denial_count != 15
        || verification.unresolved_truth_count != 10
        || !verification.signature_correspondence_verified
        || verification.effects != zero_effect_account()
    {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidVerification,
            "verification status authority counts signature or effects differ",
        ));
    }
    for (digest, label) in [
        (
            &verification.upstream_bundle_digest,
            "verified upstream digest",
        ),
        (
            &verification.descriptor_digest,
            "verified descriptor digest",
        ),
        (&verification.request_digest, "verified request digest"),
        (&verification.envelope_digest, "verified envelope digest"),
    ] {
        validate_digest(digest, label)?;
    }
    Ok(())
}

pub fn nested_inner_model_upstream_bundle_digest(
    request: &NestedInnerProcessLineageRequest,
    envelope: &NestedInnerProcessLineageEnvelope,
    verification: &NestedInnerProcessLineageVerification,
) -> Result<ContentDigest, NestedInnerModelAdmissionFault> {
    #[derive(Serialize)]
    struct UpstreamBundle<'a> {
        request: &'a NestedInnerProcessLineageRequest,
        envelope: &'a NestedInnerProcessLineageEnvelope,
        verification: &'a NestedInnerProcessLineageVerification,
    }
    sha256_form(
        UPSTREAM_DOMAIN,
        &UpstreamBundle {
            request,
            envelope,
            verification,
        },
    )
}

pub fn inner_model_artifact_descriptor_digest(
    descriptor: &InnerModelArtifactDescriptor,
) -> Result<ContentDigest, NestedInnerModelAdmissionFault> {
    let mut body = descriptor.clone();
    body.descriptor_digest = empty_digest();
    sha256_form(DESCRIPTOR_DOMAIN, &body)
}

pub fn nested_inner_model_authorization_payload_bytes(
    request: &NestedInnerModelAdmissionRequest,
) -> Result<Vec<u8>, NestedInnerModelAdmissionFault> {
    let authorization = &request.authorization;
    let body = AuthorizationPayload {
        domain: AUTHORIZATION_DOMAIN,
        upstream_bundle_digest: &request.upstream_bundle_digest,
        descriptor_digest: &request.descriptor.descriptor_digest,
        instance: &request.instance,
        authorization_id: &authorization.authorization_id,
        issuer_ref: &authorization.issuer_ref,
        subject_inner_cantor_id: &authorization.subject_inner_cantor_id,
        artifact_id: &authorization.artifact_id,
        model_instance_id: &authorization.model_instance_id,
        action: authorization.action,
        policy_digest: &authorization.policy_digest,
        nonce_digest: &authorization.nonce_digest,
        sequence_lower_bound: authorization.sequence_lower_bound,
        sequence_upper_bound: authorization.sequence_upper_bound,
        attempt_limit: authorization.attempt_limit,
        retry_limit: authorization.retry_limit,
        disposition: authorization.disposition,
        consumption_state: authorization.consumption_state,
        verifying_key_hex: &authorization.verifying_key_hex,
    };
    serde_json::to_vec(&body).map_err(|error| machine_fault("authorization payload", error))
}

pub fn nested_inner_model_admission_request_digest(
    request: &NestedInnerModelAdmissionRequest,
) -> Result<ContentDigest, NestedInnerModelAdmissionFault> {
    let mut body = request.clone();
    body.request_digest = empty_digest();
    sha256_form(REQUEST_DOMAIN, &body)
}

pub fn nested_inner_model_admission_envelope_digest(
    envelope: &NestedInnerModelAdmissionEnvelope,
) -> Result<ContentDigest, NestedInnerModelAdmissionFault> {
    let mut body = envelope.clone();
    body.envelope_digest = empty_digest();
    sha256_form(ENVELOPE_DOMAIN, &body)
}

pub fn to_nested_inner_model_admission_request_machine_form(
    request: &NestedInnerModelAdmissionRequest,
) -> Result<String, NestedInnerModelAdmissionFault> {
    validate_nested_inner_model_admission_request(request)?;
    to_machine_form(request)
}

pub fn from_nested_inner_model_admission_request_machine_form(
    value: &str,
) -> Result<NestedInnerModelAdmissionRequest, NestedInnerModelAdmissionFault> {
    let request: NestedInnerModelAdmissionRequest = parse_bounded(value)?;
    validate_nested_inner_model_admission_request(&request)?;
    Ok(request)
}

pub fn to_nested_inner_model_admission_envelope_machine_form(
    envelope: &NestedInnerModelAdmissionEnvelope,
) -> Result<String, NestedInnerModelAdmissionFault> {
    validate_nested_inner_model_admission_envelope(&envelope.request, envelope)?;
    to_machine_form(envelope)
}

pub fn from_nested_inner_model_admission_envelope_machine_form(
    value: &str,
) -> Result<NestedInnerModelAdmissionEnvelope, NestedInnerModelAdmissionFault> {
    let envelope: NestedInnerModelAdmissionEnvelope = parse_bounded(value)?;
    validate_nested_inner_model_admission_envelope(&envelope.request, &envelope)?;
    Ok(envelope)
}

pub fn to_nested_inner_model_admission_verification_machine_form(
    verification: &NestedInnerModelAdmissionVerification,
) -> Result<String, NestedInnerModelAdmissionFault> {
    validate_nested_inner_model_admission_verification(verification)?;
    to_machine_form(verification)
}

pub fn from_nested_inner_model_admission_verification_machine_form(
    value: &str,
) -> Result<NestedInnerModelAdmissionVerification, NestedInnerModelAdmissionFault> {
    let verification: NestedInnerModelAdmissionVerification = parse_bounded(value)?;
    validate_nested_inner_model_admission_verification(&verification)?;
    Ok(verification)
}

pub fn build_nested_inner_model_admission_evidence_bundle(
    request: &NestedInnerModelAdmissionRequest,
) -> Result<NestedInnerModelAdmissionEvidenceBundle, NestedInnerModelAdmissionFault> {
    let envelope = compile_nested_inner_model_admission(request)?;
    let verification = verify_nested_inner_model_admission(&envelope)?;
    let request_file = canonical_file(to_nested_inner_model_admission_request_machine_form(
        request,
    )?);
    let envelope_file = canonical_file(to_nested_inner_model_admission_envelope_machine_form(
        &envelope,
    )?);
    let verification_file = canonical_file(
        to_nested_inner_model_admission_verification_machine_form(&verification)?,
    );
    let manifest = evidence_manifest(&request_file, &envelope_file, &verification_file);
    let manifest_file = canonical_file(to_machine_form(&manifest)?);
    Ok(NestedInnerModelAdmissionEvidenceBundle {
        request_file,
        envelope_file,
        verification_file,
        manifest_file,
    })
}

pub fn verify_nested_inner_model_admission_evidence_bundle(
    bundle: &NestedInnerModelAdmissionEvidenceBundle,
) -> Result<NestedInnerModelAdmissionVerification, NestedInnerModelAdmissionFault> {
    let request_form = canonical_file_body(&bundle.request_file, "request evidence")?;
    let envelope_form = canonical_file_body(&bundle.envelope_file, "envelope evidence")?;
    let verification_form =
        canonical_file_body(&bundle.verification_file, "verification evidence")?;
    let manifest_form = canonical_file_body(&bundle.manifest_file, "manifest evidence")?;
    let request = from_nested_inner_model_admission_request_machine_form(request_form)?;
    let retained_envelope = from_nested_inner_model_admission_envelope_machine_form(envelope_form)?;
    let retained_verification =
        from_nested_inner_model_admission_verification_machine_form(verification_form)?;
    let retained_manifest: NestedInnerModelAdmissionEvidenceManifest =
        parse_bounded(manifest_form)?;

    let expected_manifest = evidence_manifest(
        &bundle.request_file,
        &bundle.envelope_file,
        &bundle.verification_file,
    );
    if retained_manifest != expected_manifest {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidEvidence,
            "retained evidence manifest differs from exact file identities or zero-effect account",
        ));
    }

    let first_envelope = compile_nested_inner_model_admission(&request)?;
    let second_envelope = compile_nested_inner_model_admission(&request)?;
    if first_envelope != retained_envelope || second_envelope != retained_envelope {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidEvidence,
            "retained envelope differs from two deterministic compilations",
        ));
    }
    let first_verification = verify_nested_inner_model_admission(&first_envelope)?;
    let second_verification = verify_nested_inner_model_admission(&second_envelope)?;
    if first_verification != retained_verification || second_verification != retained_verification {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidEvidence,
            "retained verification differs from two independent replays",
        ));
    }
    Ok(retained_verification)
}

pub fn to_nested_inner_model_admission_evidence_bundle_machine_form(
    bundle: &NestedInnerModelAdmissionEvidenceBundle,
) -> Result<String, NestedInnerModelAdmissionFault> {
    verify_nested_inner_model_admission_evidence_bundle(bundle)?;
    to_machine_form(bundle)
}

pub fn from_nested_inner_model_admission_evidence_bundle_machine_form(
    value: &str,
) -> Result<NestedInnerModelAdmissionEvidenceBundle, NestedInnerModelAdmissionFault> {
    if value.len() > NESTED_INNER_MODEL_ADMISSION_MAX_EVIDENCE_BUNDLE_BYTES {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidMachineForm,
            "evidence bundle exceeds 4194304 bytes",
        ));
    }
    let bundle: NestedInnerModelAdmissionEvidenceBundle =
        serde_json::from_str(value).map_err(|error| machine_fault("evidence bundle", error))?;
    verify_nested_inner_model_admission_evidence_bundle(&bundle)?;
    Ok(bundle)
}

fn evidence_manifest(
    request_file: &str,
    envelope_file: &str,
    verification_file: &str,
) -> NestedInnerModelAdmissionEvidenceManifest {
    let files = [
        (
            "request".to_owned(),
            evidence_file(REQUEST_EVIDENCE_PATH, request_file),
        ),
        (
            "envelope".to_owned(),
            evidence_file(ENVELOPE_EVIDENCE_PATH, envelope_file),
        ),
        (
            "verification".to_owned(),
            evidence_file(VERIFICATION_EVIDENCE_PATH, verification_file),
        ),
    ]
    .into_iter()
    .collect();
    NestedInnerModelAdmissionEvidenceManifest {
        profile: NESTED_INNER_MODEL_ADMISSION_EVIDENCE_PROFILE.to_owned(),
        replay_count: 2,
        files,
        upstream_operational_identity_count: 7,
        operational_identity_count: 8,
        bound_identity_count: 10,
        capability_denial_count: 15,
        unresolved_truth_count: 10,
        signature_correspondence_verified: true,
        effects: zero_effect_account(),
    }
}

fn evidence_file(path: &str, value: &str) -> NestedInnerModelAdmissionEvidenceFile {
    NestedInnerModelAdmissionEvidenceFile {
        path: path.to_owned(),
        bytes: value.len() as u64,
        sha256: sha256_bytes(value.as_bytes()),
    }
}

fn canonical_file(value: String) -> String {
    format!("{value}\n")
}

fn canonical_file_body<'a>(
    value: &'a str,
    label: &str,
) -> Result<&'a str, NestedInnerModelAdmissionFault> {
    let Some(body) = value.strip_suffix('\n') else {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidEvidence,
            format!("{label} lacks one canonical LF terminator"),
        ));
    };
    if body.is_empty() || body.chars().last().is_some_and(char::is_whitespace) {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidEvidence,
            format!("{label} has empty or non-canonical trailing content"),
        ));
    }
    Ok(body)
}

fn parse_bounded<T: DeserializeOwned>(value: &str) -> Result<T, NestedInnerModelAdmissionFault> {
    if value.len() > NESTED_INNER_MODEL_ADMISSION_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidMachineForm,
            "machine form exceeds 1048576 bytes",
        ));
    }
    let shape: Value =
        serde_json::from_str(value).map_err(|error| machine_fault("shape", error))?;
    let mut fields = 0;
    validate_json_shape(&shape, 1, &mut fields)?;
    serde_json::from_str(value).map_err(|error| machine_fault("form", error))
}

fn validate_json_shape(
    value: &Value,
    depth: usize,
    fields: &mut usize,
) -> Result<(), NestedInnerModelAdmissionFault> {
    if depth > MAX_DEPTH {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidMachineForm,
            "machine form exceeds depth 24",
        ));
    }
    match value {
        Value::Object(map) => {
            *fields = fields.saturating_add(map.len());
            if *fields > MAX_FIELDS {
                return Err(fault(
                    NestedInnerModelAdmissionFaultCode::InvalidMachineForm,
                    "machine form exceeds 320 fields",
                ));
            }
            for (key, child) in map {
                validate_text(key, "machine field")?;
                validate_json_shape(child, depth + 1, fields)?;
            }
        }
        Value::Array(values) => {
            if values.iter().all(Value::is_string) {
                let unique = values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>();
                if unique.len() != values.len() {
                    return Err(fault(
                        NestedInnerModelAdmissionFaultCode::InvalidMachineForm,
                        "machine form contains a duplicate string set member",
                    ));
                }
            }
            for child in values {
                validate_json_shape(child, depth + 1, fields)?;
            }
        }
        Value::String(text) => validate_text(text, "machine text")?,
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn validate_uuid_semantic_id(
    id: &SemanticId,
    prefix: &str,
    label: &str,
) -> Result<(), NestedInnerModelAdmissionFault> {
    let Some(uuid) = id.as_str().strip_prefix(prefix) else {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidIdentity,
            format!("{label} identity lacks {prefix}"),
        ));
    };
    let bytes = uuid.as_bytes();
    let valid = bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
        })
        && bytes
            .iter()
            .any(|byte| (*byte >= b'1' && *byte <= b'9') || (b'a'..=b'f').contains(byte));
    if !valid {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidIdentity,
            format!("{label} identity must contain a nonnil lowercase UUID"),
        ));
    }
    Ok(())
}

fn validate_digest(
    digest: &ContentDigest,
    label: &str,
) -> Result<(), NestedInnerModelAdmissionFault> {
    if digest.algorithm != "sha256"
        || digest.value.len() != 64
        || !digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidDigest,
            format!("{label} must be lowercase SHA256"),
        ));
    }
    Ok(())
}

fn validate_text(value: &str, label: &str) -> Result<(), NestedInnerModelAdmissionFault> {
    if value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidMachineForm,
            format!("{label} exceeds 1024 bytes or contains control text"),
        ));
    }
    Ok(())
}

fn decode_fixed_hex<const N: usize>(
    value: &str,
    label: &str,
) -> Result<[u8; N], NestedInnerModelAdmissionFault> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(fault(
            NestedInnerModelAdmissionFaultCode::InvalidSignature,
            format!("{label} must be exact lowercase hex"),
        ));
    }
    let mut output = [0_u8; N];
    for (index, output_byte) in output.iter_mut().enumerate() {
        let high = decode_hex_nibble(value.as_bytes()[index * 2]);
        let low = decode_hex_nibble(value.as_bytes()[index * 2 + 1]);
        *output_byte = (high << 4) | low;
    }
    Ok(output)
}

fn decode_hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => unreachable!("validated lowercase hex"),
    }
}

fn required_unresolved_account() -> BTreeSet<String> {
    [
        "artifact_file_presence_not_observed",
        "artifact_bytes_not_reacquired",
        "artifact_digest_not_physically_recomputed",
        "license_status_not_verified",
        "safety_status_not_verified",
        "provider_compatibility_not_verified",
        "resource_fit_not_verified",
        "signer_policy_governance_not_verified",
        "key_custody_revocation_freshness_not_verified",
        "model_not_loaded",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn required_capability_denials() -> BTreeSet<NestedInnerModelAdmissionCapabilityDenial> {
    [
        NestedInnerModelAdmissionCapabilityDenial::ArtifactFileObservation,
        NestedInnerModelAdmissionCapabilityDenial::ArtifactByteReacquisition,
        NestedInnerModelAdmissionCapabilityDenial::ArtifactDownload,
        NestedInnerModelAdmissionCapabilityDenial::ArtifactInstall,
        NestedInnerModelAdmissionCapabilityDenial::ModelLoadAttempt,
        NestedInnerModelAdmissionCapabilityDenial::ModelLoadCompletion,
        NestedInnerModelAdmissionCapabilityDenial::RuntimeObservation,
        NestedInnerModelAdmissionCapabilityDenial::ProviderCall,
        NestedInnerModelAdmissionCapabilityDenial::Inference,
        NestedInnerModelAdmissionCapabilityDenial::ProcessLaunch,
        NestedInnerModelAdmissionCapabilityDenial::SharedAttention,
        NestedInnerModelAdmissionCapabilityDenial::Persistence,
        NestedInnerModelAdmissionCapabilityDenial::WorkspaceMutation,
        NestedInnerModelAdmissionCapabilityDenial::RemoteAccess,
        NestedInnerModelAdmissionCapabilityDenial::ExternalEffect,
    ]
    .into_iter()
    .collect()
}

fn zero_effect_account() -> NestedInnerModelAdmissionEffectAccount {
    NestedInnerModelAdmissionEffectAccount {
        authorization_issued: false,
        artifact_file_observed: false,
        artifact_bytes_reacquired: false,
        model_load_attempt_count: 0,
        model_load_completion_count: 0,
        runtime_model_observed: false,
        provider_trial_count: 0,
        model_turn_count: 0,
        process_count: 0,
        mcp_call_count: 0,
        workspace_mutation_count: 0,
        network_contact_count: 0,
        remote_contact_count: 0,
        persistence_count: 0,
        activation_count: 0,
        cleanup_effect_count: 0,
        foreign_effect_count: 0,
    }
}

fn sha256_form<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<ContentDigest, NestedInnerModelAdmissionFault> {
    let body = serde_json::to_vec(value).map_err(|error| machine_fault("digest form", error))?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + body.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&body);
    Ok(sha256_bytes(&bytes))
}

fn to_machine_form<T: Serialize>(value: &T) -> Result<String, NestedInnerModelAdmissionFault> {
    serde_json::to_string(value).map_err(|error| machine_fault("machine form", error))
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn upstream_fault(label: &str, error: impl fmt::Display) -> NestedInnerModelAdmissionFault {
    fault(
        NestedInnerModelAdmissionFaultCode::InvalidUpstream,
        format!("NHC-02 {label} refused: {error}"),
    )
}

fn machine_fault(label: &str, error: serde_json::Error) -> NestedInnerModelAdmissionFault {
    fault(
        NestedInnerModelAdmissionFaultCode::InvalidMachineForm,
        format!("nested inner model admission {label} failed: {error}"),
    )
}

fn fault(
    code: NestedInnerModelAdmissionFaultCode,
    message: impl Into<String>,
) -> NestedInnerModelAdmissionFault {
    NestedInnerModelAdmissionFault {
        code,
        message: message.into(),
    }
}
