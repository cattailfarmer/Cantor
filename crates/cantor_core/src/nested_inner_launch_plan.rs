//! Pure provider-free forms for an effectless inner-model launch plan.
//!
//! This module validates supplied data and detached Ed25519 correspondence
//! only. It performs no I/O, observes no executable, launches no process,
//! loads no model, owns no stream, executes no cancellation, and grants no
//! physical-effect authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    ContentDigest, NestedInnerModelAdmissionEnvelope, NestedInnerModelAdmissionRequest,
    NestedInnerModelAdmissionVerification, SemanticId, sha256_bytes,
    validate_nested_inner_model_admission_envelope, validate_nested_inner_model_admission_request,
    validate_nested_inner_model_admission_verification, verify_nested_inner_model_admission,
};

pub const NESTED_INNER_LAUNCH_PLAN_REQUEST_PROFILE: &str =
    "cantor-nested-inner-launch-plan-request/0.1";
pub const NESTED_INNER_LAUNCH_PLAN_ENVELOPE_PROFILE: &str =
    "cantor-nested-inner-launch-plan-envelope/0.1";
pub const NESTED_INNER_LAUNCH_PLAN_VERIFICATION_PROFILE: &str =
    "cantor-nested-inner-launch-plan-verification/0.1";
pub const NESTED_INNER_LAUNCH_PLAN_NON_AUTHORITY: &str = "Supplied launch-plan and Ed25519 correspondence only. It does not establish executable or working-directory presence or bytes, policy governance, key custody, revocation, freshness, process creation, model loading, runtime observation, provider contact, inference, stream custody, cancellation execution, cleanup, shared attention, workspace mutation, persistence, remote access, or external-effect authority.";
pub const NESTED_INNER_LAUNCH_PLAN_MAX_MACHINE_FORM_BYTES: usize = 1_048_576;

const UPSTREAM_DOMAIN: &str = "cantor.nested-inner-launch-plan.upstream.v1";
const PLAN_DOMAIN: &str = "cantor.nested-inner-launch-plan.plan.v1";
const AUTHORIZATION_DOMAIN: &str = "cantor.nested-inner-launch-plan.authorization.v1";
const REQUEST_DOMAIN: &str = "cantor.nested-inner-launch-plan.request.v1";
const ENVELOPE_DOMAIN: &str = "cantor.nested-inner-launch-plan.envelope.v1";
const MAX_TEXT_BYTES: usize = 2_048;
const MAX_EVIDENCE_REFS: usize = 32;
const MAX_DEPTH: usize = 28;
const MAX_FIELDS: usize = 384;

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InnerLaunchPlanState {
    ProposedEffectless,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InnerLaunchTargetProfile {
    DirectNoShell,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InnerLaunchStdinDeclaration {
    Closed,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InnerLaunchOutputDeclaration {
    CapturedBounded,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InnerLaunchCancellationState {
    NoneRequested,
    PrelaunchCancelRequested,
    PostBoundaryCancelRequested,
    TerminalCancelled,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InnerLaunchTerminalOutcome {
    PrelaunchRefused,
    LaunchBlocked,
    LaunchFault,
    TimedOut,
    Cancelled,
    ExitSuccess,
    ExitFailure,
    UnknownAfterBoundary,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InnerLaunchPlanAction {
    InnerLaunchPlanCompile,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InnerLaunchPlanAuthorizationDisposition {
    AuthorizedForLaterSingleAttemptPlan,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InnerLaunchPlanAuthorizationConsumptionState {
    Unconsumed,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NestedInnerLaunchPlanLifecycle {
    AuthorizedEffectlessLaunchPlanOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NestedInnerLaunchPlanAuthority {
    SuppliedKeyCryptographicLaunchPlanAuthorizationOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NestedInnerLaunchPlanCapabilityDenial {
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
    LaunchPlanExecution,
    CancellationExecution,
    StreamCustody,
    SharedAttention,
    Persistence,
    WorkspaceMutation,
    RemoteAccess,
    ExternalEffect,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InnerLaunchPlan {
    pub plan_id: SemanticId,
    pub state: InnerLaunchPlanState,
    pub target_profile: InnerLaunchTargetProfile,
    pub executable_ref: SemanticId,
    pub working_directory_ref: SemanticId,
    pub argv: Vec<String>,
    pub environment: BTreeMap<String, SemanticId>,
    pub stdin: InnerLaunchStdinDeclaration,
    pub stdout: InnerLaunchOutputDeclaration,
    pub stderr: InnerLaunchOutputDeclaration,
    pub context_token_ceiling: u32,
    pub memory_byte_ceiling: u64,
    pub thread_ceiling: u32,
    pub gpu_layer_ceiling: u32,
    pub startup_millis_ceiling: u64,
    pub runtime_millis_ceiling: u64,
    pub output_byte_ceiling: u64,
    pub descendant_count_ceiling: u32,
    pub cancellation_grace_millis_ceiling: u64,
    pub cancellation_state: InnerLaunchCancellationState,
    pub terminal_outcomes: BTreeSet<InnerLaunchTerminalOutcome>,
    pub quarantine_owner_ref: SemanticId,
    pub plan_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InnerLaunchPlanAuthorization {
    pub authorization_id: SemanticId,
    pub issuer_ref: SemanticId,
    pub subject_inner_cantor_id: SemanticId,
    pub plan_id: SemanticId,
    pub action: InnerLaunchPlanAction,
    pub policy_digest: ContentDigest,
    pub nonce_digest: ContentDigest,
    pub sequence_lower_bound: u64,
    pub sequence_upper_bound: u64,
    pub attempt_limit: u32,
    pub retry_limit: u32,
    pub disposition: InnerLaunchPlanAuthorizationDisposition,
    pub consumption_state: InnerLaunchPlanAuthorizationConsumptionState,
    pub verifying_key_hex: String,
    pub signature_hex: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInnerLaunchPlanRequest {
    pub profile: String,
    pub request_id: SemanticId,
    pub upstream_request: NestedInnerModelAdmissionRequest,
    pub upstream_envelope: NestedInnerModelAdmissionEnvelope,
    pub upstream_verification: NestedInnerModelAdmissionVerification,
    pub upstream_bundle_digest: ContentDigest,
    pub plan: InnerLaunchPlan,
    pub authorization: InnerLaunchPlanAuthorization,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub unresolved_account: BTreeSet<String>,
    pub non_authority: String,
    pub request_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInnerLaunchPlanEnvelope {
    pub profile: String,
    pub request: NestedInnerLaunchPlanRequest,
    pub lifecycle: NestedInnerLaunchPlanLifecycle,
    pub authority: NestedInnerLaunchPlanAuthority,
    pub capability_denials: BTreeSet<NestedInnerLaunchPlanCapabilityDenial>,
    pub upstream_bundle_digest: ContentDigest,
    pub plan_digest: ContentDigest,
    pub request_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInnerLaunchPlanEffectAccount {
    pub authorization_issued: bool,
    pub executable_file_observed: bool,
    pub executable_bytes_reacquired: bool,
    pub process_launch_attempt_count: u32,
    pub process_created_count: u32,
    pub model_load_attempt_count: u32,
    pub model_load_completion_count: u32,
    pub runtime_model_observed: bool,
    pub provider_trial_count: u32,
    pub model_turn_count: u32,
    pub stream_custody_count: u32,
    pub cancellation_execution_count: u32,
    pub cleanup_effect_count: u32,
    pub workspace_mutation_count: u32,
    pub network_contact_count: u32,
    pub remote_contact_count: u32,
    pub persistence_count: u32,
    pub activation_count: u32,
    pub foreign_effect_count: u32,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInnerLaunchPlanVerification {
    pub profile: String,
    pub status: String,
    pub authority: NestedInnerLaunchPlanAuthority,
    pub upstream_bundle_digest: ContentDigest,
    pub plan_digest: ContentDigest,
    pub request_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
    pub upstream_operational_identity_count: u32,
    pub operational_identity_count: u32,
    pub bound_identity_count: u32,
    pub capability_denial_count: u32,
    pub upstream_unresolved_truth_count: u32,
    pub unresolved_truth_count: u32,
    pub signature_correspondence_verified: bool,
    pub effects: NestedInnerLaunchPlanEffectAccount,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NestedInnerLaunchPlanFaultCode {
    InvalidProfile,
    InvalidUpstream,
    InvalidIdentity,
    IdentityCollision,
    InvalidPlan,
    InvalidAuthorization,
    InvalidSignature,
    InvalidEvidence,
    InvalidUnresolvedAccount,
    InvalidAuthority,
    InvalidDigest,
    InvalidCorrespondence,
    InvalidVerification,
    InvalidMachineForm,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NestedInnerLaunchPlanFault {
    pub code: NestedInnerLaunchPlanFaultCode,
    pub detail: String,
}

impl fmt::Display for NestedInnerLaunchPlanFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}

impl std::error::Error for NestedInnerLaunchPlanFault {}

pub fn seal_inner_launch_plan(
    mut plan: InnerLaunchPlan,
) -> Result<InnerLaunchPlan, NestedInnerLaunchPlanFault> {
    plan.plan_digest = empty_digest();
    validate_plan_body(&plan, None)?;
    plan.plan_digest = inner_launch_plan_digest(&plan)?;
    Ok(plan)
}

pub fn seal_nested_inner_launch_plan_request(
    mut request: NestedInnerLaunchPlanRequest,
) -> Result<NestedInnerLaunchPlanRequest, NestedInnerLaunchPlanFault> {
    request.upstream_bundle_digest = nested_inner_launch_plan_upstream_digest(
        &request.upstream_request,
        &request.upstream_envelope,
        &request.upstream_verification,
    )?;
    request.request_digest = empty_digest();
    validate_request_body(&request)?;
    request.request_digest = nested_inner_launch_plan_request_digest(&request)?;
    validate_nested_inner_launch_plan_request(&request)?;
    Ok(request)
}

pub fn compile_nested_inner_launch_plan(
    request: &NestedInnerLaunchPlanRequest,
) -> Result<NestedInnerLaunchPlanEnvelope, NestedInnerLaunchPlanFault> {
    validate_nested_inner_launch_plan_request(request)?;
    let mut envelope = NestedInnerLaunchPlanEnvelope {
        profile: NESTED_INNER_LAUNCH_PLAN_ENVELOPE_PROFILE.to_owned(),
        request: request.clone(),
        lifecycle: NestedInnerLaunchPlanLifecycle::AuthorizedEffectlessLaunchPlanOnly,
        authority:
            NestedInnerLaunchPlanAuthority::SuppliedKeyCryptographicLaunchPlanAuthorizationOnly,
        capability_denials: required_capability_denials(),
        upstream_bundle_digest: request.upstream_bundle_digest.clone(),
        plan_digest: request.plan.plan_digest.clone(),
        request_digest: request.request_digest.clone(),
        envelope_digest: empty_digest(),
    };
    envelope.envelope_digest = nested_inner_launch_plan_envelope_digest(&envelope)?;
    Ok(envelope)
}

pub fn verify_nested_inner_launch_plan(
    envelope: &NestedInnerLaunchPlanEnvelope,
) -> Result<NestedInnerLaunchPlanVerification, NestedInnerLaunchPlanFault> {
    validate_nested_inner_launch_plan_request(&envelope.request)?;
    if envelope.profile != NESTED_INNER_LAUNCH_PLAN_ENVELOPE_PROFILE
        || envelope.lifecycle != NestedInnerLaunchPlanLifecycle::AuthorizedEffectlessLaunchPlanOnly
        || envelope.authority
            != NestedInnerLaunchPlanAuthority::SuppliedKeyCryptographicLaunchPlanAuthorizationOnly
        || envelope.capability_denials != required_capability_denials()
        || envelope.upstream_bundle_digest != envelope.request.upstream_bundle_digest
        || envelope.plan_digest != envelope.request.plan.plan_digest
        || envelope.request_digest != envelope.request.request_digest
    {
        return Err(fault(
            NestedInnerLaunchPlanFaultCode::InvalidCorrespondence,
            "envelope correspondence differs",
        ));
    }
    if envelope.envelope_digest != nested_inner_launch_plan_envelope_digest(envelope)? {
        return Err(fault(
            NestedInnerLaunchPlanFaultCode::InvalidDigest,
            "envelope digest differs",
        ));
    }
    Ok(NestedInnerLaunchPlanVerification {
        profile: NESTED_INNER_LAUNCH_PLAN_VERIFICATION_PROFILE.to_owned(),
        status: "verified_provider_free_effectless_launch_plan_correspondence".to_owned(),
        authority: envelope.authority,
        upstream_bundle_digest: envelope.upstream_bundle_digest.clone(),
        plan_digest: envelope.plan_digest.clone(),
        request_digest: envelope.request_digest.clone(),
        envelope_digest: envelope.envelope_digest.clone(),
        upstream_operational_identity_count: 8,
        operational_identity_count: 10,
        bound_identity_count: 12,
        capability_denial_count: 18,
        upstream_unresolved_truth_count: 10,
        unresolved_truth_count: 12,
        signature_correspondence_verified: true,
        effects: NestedInnerLaunchPlanEffectAccount::default(),
    })
}

pub fn validate_nested_inner_launch_plan_verification(
    verification: &NestedInnerLaunchPlanVerification,
) -> Result<(), NestedInnerLaunchPlanFault> {
    if verification.profile != NESTED_INNER_LAUNCH_PLAN_VERIFICATION_PROFILE
        || verification.status != "verified_provider_free_effectless_launch_plan_correspondence"
        || verification.authority
            != NestedInnerLaunchPlanAuthority::SuppliedKeyCryptographicLaunchPlanAuthorizationOnly
        || verification.upstream_operational_identity_count != 8
        || verification.operational_identity_count != 10
        || verification.bound_identity_count != 12
        || verification.capability_denial_count != 18
        || verification.upstream_unresolved_truth_count != 10
        || verification.unresolved_truth_count != 12
        || !verification.signature_correspondence_verified
        || verification.effects != NestedInnerLaunchPlanEffectAccount::default()
    {
        return Err(fault(
            NestedInnerLaunchPlanFaultCode::InvalidVerification,
            "verification status authority counts signature or effects differ",
        ));
    }
    for (digest, label) in [
        (&verification.upstream_bundle_digest, "upstream digest"),
        (&verification.plan_digest, "plan digest"),
        (&verification.request_digest, "request digest"),
        (&verification.envelope_digest, "envelope digest"),
    ] {
        validate_digest(digest, label)?;
    }
    Ok(())
}

pub fn to_inner_launch_plan_machine_form(
    plan: &InnerLaunchPlan,
) -> Result<String, NestedInnerLaunchPlanFault> {
    validate_plan(plan, None)?;
    to_machine_form(plan)
}

pub fn from_inner_launch_plan_machine_form(
    value: &str,
) -> Result<InnerLaunchPlan, NestedInnerLaunchPlanFault> {
    let plan: InnerLaunchPlan = parse_bounded(value)?;
    validate_plan(&plan, None)?;
    Ok(plan)
}

pub fn to_nested_inner_launch_plan_request_machine_form(
    request: &NestedInnerLaunchPlanRequest,
) -> Result<String, NestedInnerLaunchPlanFault> {
    validate_nested_inner_launch_plan_request(request)?;
    to_machine_form(request)
}

pub fn from_nested_inner_launch_plan_request_machine_form(
    value: &str,
) -> Result<NestedInnerLaunchPlanRequest, NestedInnerLaunchPlanFault> {
    let request: NestedInnerLaunchPlanRequest = parse_bounded(value)?;
    validate_nested_inner_launch_plan_request(&request)?;
    Ok(request)
}

pub fn to_nested_inner_launch_plan_envelope_machine_form(
    envelope: &NestedInnerLaunchPlanEnvelope,
) -> Result<String, NestedInnerLaunchPlanFault> {
    verify_nested_inner_launch_plan(envelope)?;
    to_machine_form(envelope)
}

pub fn from_nested_inner_launch_plan_envelope_machine_form(
    value: &str,
) -> Result<NestedInnerLaunchPlanEnvelope, NestedInnerLaunchPlanFault> {
    let envelope: NestedInnerLaunchPlanEnvelope = parse_bounded(value)?;
    verify_nested_inner_launch_plan(&envelope)?;
    Ok(envelope)
}

pub fn to_nested_inner_launch_plan_verification_machine_form(
    verification: &NestedInnerLaunchPlanVerification,
) -> Result<String, NestedInnerLaunchPlanFault> {
    validate_nested_inner_launch_plan_verification(verification)?;
    to_machine_form(verification)
}

pub fn from_nested_inner_launch_plan_verification_machine_form(
    value: &str,
) -> Result<NestedInnerLaunchPlanVerification, NestedInnerLaunchPlanFault> {
    let verification: NestedInnerLaunchPlanVerification = parse_bounded(value)?;
    validate_nested_inner_launch_plan_verification(&verification)?;
    Ok(verification)
}

pub fn validate_nested_inner_launch_plan_request(
    request: &NestedInnerLaunchPlanRequest,
) -> Result<(), NestedInnerLaunchPlanFault> {
    validate_request_body(request)?;
    validate_digest(&request.request_digest, "request digest")?;
    if request.request_digest != nested_inner_launch_plan_request_digest(request)? {
        return Err(fault(
            NestedInnerLaunchPlanFaultCode::InvalidDigest,
            "request digest differs",
        ));
    }
    Ok(())
}

fn validate_request_body(
    request: &NestedInnerLaunchPlanRequest,
) -> Result<(), NestedInnerLaunchPlanFault> {
    if request.profile != NESTED_INNER_LAUNCH_PLAN_REQUEST_PROFILE {
        return Err(fault(
            NestedInnerLaunchPlanFaultCode::InvalidProfile,
            "request profile differs",
        ));
    }
    validate_uuid_id(&request.request_id, "inner-launch-plan-request:", "request")?;
    validate_upstream(request)?;
    validate_plan(&request.plan, Some(&request.upstream_request))?;
    validate_bound_identities(request)?;
    validate_authorization(request)?;
    if request.evidence_refs.is_empty() || request.evidence_refs.len() > MAX_EVIDENCE_REFS {
        return Err(fault(
            NestedInnerLaunchPlanFaultCode::InvalidEvidence,
            "evidence count must be within 1..=32",
        ));
    }
    if request.unresolved_account != required_unresolved_account() {
        return Err(fault(
            NestedInnerLaunchPlanFaultCode::InvalidUnresolvedAccount,
            "unresolved account differs",
        ));
    }
    if request.non_authority != NESTED_INNER_LAUNCH_PLAN_NON_AUTHORITY {
        return Err(fault(
            NestedInnerLaunchPlanFaultCode::InvalidAuthority,
            "non-authority differs",
        ));
    }
    Ok(())
}

fn validate_upstream(
    request: &NestedInnerLaunchPlanRequest,
) -> Result<(), NestedInnerLaunchPlanFault> {
    validate_nested_inner_model_admission_request(&request.upstream_request)
        .map_err(upstream_fault)?;
    validate_nested_inner_model_admission_envelope(
        &request.upstream_request,
        &request.upstream_envelope,
    )
    .map_err(upstream_fault)?;
    validate_nested_inner_model_admission_verification(&request.upstream_verification)
        .map_err(upstream_fault)?;
    if request.upstream_envelope.request != request.upstream_request
        || verify_nested_inner_model_admission(&request.upstream_envelope)
            .map_err(upstream_fault)?
            != request.upstream_verification
        || request.upstream_bundle_digest
            != nested_inner_launch_plan_upstream_digest(
                &request.upstream_request,
                &request.upstream_envelope,
                &request.upstream_verification,
            )?
    {
        return Err(fault(
            NestedInnerLaunchPlanFaultCode::InvalidUpstream,
            "complete NHC-03 bundle differs",
        ));
    }
    Ok(())
}

fn validate_plan(
    plan: &InnerLaunchPlan,
    upstream: Option<&NestedInnerModelAdmissionRequest>,
) -> Result<(), NestedInnerLaunchPlanFault> {
    validate_plan_body(plan, upstream)?;
    validate_digest(&plan.plan_digest, "plan digest")?;
    if plan.plan_digest != inner_launch_plan_digest(plan)? {
        return Err(fault(
            NestedInnerLaunchPlanFaultCode::InvalidDigest,
            "plan digest differs",
        ));
    }
    Ok(())
}

fn validate_plan_body(
    plan: &InnerLaunchPlan,
    upstream: Option<&NestedInnerModelAdmissionRequest>,
) -> Result<(), NestedInnerLaunchPlanFault> {
    validate_uuid_id(&plan.plan_id, "inner-launch-plan:", "plan")?;
    let basic = plan.state == InnerLaunchPlanState::ProposedEffectless
        && plan.target_profile == InnerLaunchTargetProfile::DirectNoShell
        && (1..=32).contains(&plan.argv.len())
        && plan.environment.len() <= 32
        && plan.stdin == InnerLaunchStdinDeclaration::Closed
        && plan.stdout == InnerLaunchOutputDeclaration::CapturedBounded
        && plan.stderr == InnerLaunchOutputDeclaration::CapturedBounded
        && (1..=86_400_000).contains(&plan.startup_millis_ceiling)
        && (1..=86_400_000).contains(&plan.runtime_millis_ceiling)
        && (1..=1_073_741_824).contains(&plan.output_byte_ceiling)
        && plan.descendant_count_ceiling <= 64
        && (1..=600_000).contains(&plan.cancellation_grace_millis_ceiling)
        && plan.cancellation_state == InnerLaunchCancellationState::NoneRequested
        && plan.terminal_outcomes == required_terminal_outcomes();
    if !basic
        || plan
            .argv
            .iter()
            .any(|value| value.is_empty() || !valid_text(value))
    {
        return Err(fault(
            NestedInnerLaunchPlanFaultCode::InvalidPlan,
            "plan target arrays ceilings cancellation or terminal grammar differs",
        ));
    }
    for key in plan.environment.keys() {
        if key.is_empty()
            || key.len() > 64
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(fault(
                NestedInnerLaunchPlanFaultCode::InvalidPlan,
                "environment key differs",
            ));
        }
    }
    if let Some(upstream) = upstream {
        let instance = &upstream.instance;
        if plan.context_token_ceiling != instance.context_token_ceiling
            || plan.memory_byte_ceiling != instance.memory_byte_ceiling
            || plan.thread_ceiling != instance.thread_ceiling
            || plan.gpu_layer_ceiling != instance.gpu_layer_ceiling
        {
            return Err(fault(
                NestedInnerLaunchPlanFaultCode::InvalidPlan,
                "model ceilings differ from NHC-03",
            ));
        }
    }
    Ok(())
}

fn validate_authorization(
    request: &NestedInnerLaunchPlanRequest,
) -> Result<(), NestedInnerLaunchPlanFault> {
    let authorization = &request.authorization;
    validate_uuid_id(
        &authorization.authorization_id,
        "inner-launch-plan-authorization:",
        "authorization",
    )?;
    if authorization.subject_inner_cantor_id
        != request
            .upstream_request
            .authorization
            .subject_inner_cantor_id
        || authorization.plan_id != request.plan.plan_id
        || authorization.action != InnerLaunchPlanAction::InnerLaunchPlanCompile
        || authorization.sequence_lower_bound > authorization.sequence_upper_bound
        || authorization.attempt_limit != 1
        || authorization.retry_limit != 0
        || authorization.disposition
            != InnerLaunchPlanAuthorizationDisposition::AuthorizedForLaterSingleAttemptPlan
        || authorization.consumption_state
            != InnerLaunchPlanAuthorizationConsumptionState::Unconsumed
    {
        return Err(fault(
            NestedInnerLaunchPlanFaultCode::InvalidAuthorization,
            "authorization tuple differs",
        ));
    }
    validate_digest(&authorization.policy_digest, "policy digest")?;
    validate_digest(&authorization.nonce_digest, "nonce digest")?;
    let key = decode_hex::<32>(&authorization.verifying_key_hex, "verifying key")?;
    let signature_bytes = decode_hex::<64>(&authorization.signature_hex, "signature")?;
    let verifying_key = VerifyingKey::from_bytes(&key).map_err(|_| {
        fault(
            NestedInnerLaunchPlanFaultCode::InvalidSignature,
            "verifying key refused",
        )
    })?;
    verifying_key
        .verify_strict(
            &nested_inner_launch_plan_authorization_payload_bytes(request)?,
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| {
            fault(
                NestedInnerLaunchPlanFaultCode::InvalidSignature,
                "authorization signature refused",
            )
        })
}

fn validate_bound_identities(
    request: &NestedInnerLaunchPlanRequest,
) -> Result<(), NestedInnerLaunchPlanFault> {
    let upstream = &request.upstream_request;
    let identities = [
        uuid_component(&upstream.upstream_request.parent.request.session_id),
        uuid_component(&upstream.upstream_request.parent.request.outer_host_id),
        uuid_component(&upstream.upstream_request.parent.request.process.process_id),
        uuid_component(&upstream.upstream_request.parent.request.model.model_id),
        uuid_component(&upstream.upstream_request.inner.inner_session_id),
        uuid_component(&upstream.upstream_request.inner.inner_cantor_id),
        uuid_component(&upstream.upstream_request.inner.inner_process_id),
        uuid_component(&upstream.descriptor.artifact_id),
        uuid_component(&upstream.instance.model_instance_id),
        uuid_component(&upstream.authorization.authorization_id),
        uuid_component(&request.plan.plan_id),
        uuid_component(&request.authorization.authorization_id),
    ];
    if identities.into_iter().collect::<BTreeSet<_>>().len() != identities.len() {
        return Err(fault(
            NestedInnerLaunchPlanFaultCode::IdentityCollision,
            "twelve bound UUID identities must be distinct",
        ));
    }
    Ok(())
}

pub fn nested_inner_launch_plan_upstream_digest(
    request: &NestedInnerModelAdmissionRequest,
    envelope: &NestedInnerModelAdmissionEnvelope,
    verification: &NestedInnerModelAdmissionVerification,
) -> Result<ContentDigest, NestedInnerLaunchPlanFault> {
    sha256_form(UPSTREAM_DOMAIN, &(request, envelope, verification))
}

pub fn inner_launch_plan_digest(
    plan: &InnerLaunchPlan,
) -> Result<ContentDigest, NestedInnerLaunchPlanFault> {
    let mut normalized = plan.clone();
    normalized.plan_digest = empty_digest();
    sha256_form(PLAN_DOMAIN, &normalized)
}

pub fn nested_inner_launch_plan_authorization_payload_bytes(
    request: &NestedInnerLaunchPlanRequest,
) -> Result<Vec<u8>, NestedInnerLaunchPlanFault> {
    #[derive(Serialize)]
    struct Payload<'a> {
        upstream_bundle_digest: &'a ContentDigest,
        plan: &'a InnerLaunchPlan,
        authorization_id: &'a SemanticId,
        issuer_ref: &'a SemanticId,
        subject_inner_cantor_id: &'a SemanticId,
        plan_id: &'a SemanticId,
        action: InnerLaunchPlanAction,
        policy_digest: &'a ContentDigest,
        nonce_digest: &'a ContentDigest,
        sequence_lower_bound: u64,
        sequence_upper_bound: u64,
        attempt_limit: u32,
        retry_limit: u32,
        disposition: InnerLaunchPlanAuthorizationDisposition,
        consumption_state: InnerLaunchPlanAuthorizationConsumptionState,
        verifying_key_hex: &'a str,
    }
    let authorization = &request.authorization;
    let body = serde_json::to_vec(&Payload {
        upstream_bundle_digest: &request.upstream_bundle_digest,
        plan: &request.plan,
        authorization_id: &authorization.authorization_id,
        issuer_ref: &authorization.issuer_ref,
        subject_inner_cantor_id: &authorization.subject_inner_cantor_id,
        plan_id: &authorization.plan_id,
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
    })
    .map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(AUTHORIZATION_DOMAIN.len() + 1 + body.len());
    bytes.extend_from_slice(AUTHORIZATION_DOMAIN.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

pub fn nested_inner_launch_plan_request_digest(
    request: &NestedInnerLaunchPlanRequest,
) -> Result<ContentDigest, NestedInnerLaunchPlanFault> {
    let mut normalized = request.clone();
    normalized.request_digest = empty_digest();
    sha256_form(REQUEST_DOMAIN, &normalized)
}

pub fn nested_inner_launch_plan_envelope_digest(
    envelope: &NestedInnerLaunchPlanEnvelope,
) -> Result<ContentDigest, NestedInnerLaunchPlanFault> {
    let mut normalized = envelope.clone();
    normalized.envelope_digest = empty_digest();
    sha256_form(ENVELOPE_DOMAIN, &normalized)
}

pub fn nested_inner_launch_plan_required_unresolved_account() -> BTreeSet<String> {
    required_unresolved_account()
}

pub fn nested_inner_launch_plan_required_terminal_outcomes() -> BTreeSet<InnerLaunchTerminalOutcome>
{
    required_terminal_outcomes()
}

fn required_unresolved_account() -> BTreeSet<String> {
    [
        "executable_file_presence_not_observed",
        "executable_bytes_not_reacquired",
        "working_directory_not_observed",
        "host_resource_fit_not_verified",
        "policy_governance_not_verified",
        "key_custody_revocation_freshness_not_verified",
        "current_sequence_not_observed",
        "model_not_loaded",
        "process_not_launched",
        "streams_not_owned",
        "cancellation_not_executed",
        "terminal_outcome_not_observed",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn required_terminal_outcomes() -> BTreeSet<InnerLaunchTerminalOutcome> {
    [
        InnerLaunchTerminalOutcome::PrelaunchRefused,
        InnerLaunchTerminalOutcome::LaunchBlocked,
        InnerLaunchTerminalOutcome::LaunchFault,
        InnerLaunchTerminalOutcome::TimedOut,
        InnerLaunchTerminalOutcome::Cancelled,
        InnerLaunchTerminalOutcome::ExitSuccess,
        InnerLaunchTerminalOutcome::ExitFailure,
        InnerLaunchTerminalOutcome::UnknownAfterBoundary,
    ]
    .into_iter()
    .collect()
}

fn required_capability_denials() -> BTreeSet<NestedInnerLaunchPlanCapabilityDenial> {
    use NestedInnerLaunchPlanCapabilityDenial::*;
    [
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
        LaunchPlanExecution,
        CancellationExecution,
        StreamCustody,
        SharedAttention,
        Persistence,
        WorkspaceMutation,
        RemoteAccess,
        ExternalEffect,
    ]
    .into_iter()
    .collect()
}

fn validate_uuid_id(
    id: &SemanticId,
    prefix: &str,
    label: &str,
) -> Result<(), NestedInnerLaunchPlanFault> {
    let Some(uuid) = id.as_str().strip_prefix(prefix) else {
        return Err(fault(
            NestedInnerLaunchPlanFaultCode::InvalidIdentity,
            format!("{label} lacks {prefix}"),
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
            NestedInnerLaunchPlanFaultCode::InvalidIdentity,
            format!("{label} must contain a nonnil lowercase UUID"),
        ));
    }
    Ok(())
}

fn uuid_component(id: &SemanticId) -> &str {
    id.as_str()
        .rsplit_once(':')
        .map_or(id.as_str(), |(_, uuid)| uuid)
}

fn validate_digest(digest: &ContentDigest, label: &str) -> Result<(), NestedInnerLaunchPlanFault> {
    if digest.algorithm != "sha256"
        || digest.value.len() != 64
        || !digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(fault(
            NestedInnerLaunchPlanFaultCode::InvalidDigest,
            format!("{label} must be lowercase SHA256"),
        ));
    }
    Ok(())
}

fn valid_text(value: &str) -> bool {
    value.len() <= MAX_TEXT_BYTES && !value.chars().any(char::is_control)
}

fn decode_hex<const N: usize>(
    value: &str,
    label: &str,
) -> Result<[u8; N], NestedInnerLaunchPlanFault> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(fault(
            NestedInnerLaunchPlanFaultCode::InvalidSignature,
            format!("{label} must be exact lowercase hex"),
        ));
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte =
            (nibble(value.as_bytes()[index * 2]) << 4) | nibble(value.as_bytes()[index * 2 + 1]);
    }
    Ok(output)
}

fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

fn sha256_form<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<ContentDigest, NestedInnerLaunchPlanFault> {
    let body = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + body.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&body);
    Ok(sha256_bytes(&bytes))
}

fn to_machine_form<T: Serialize>(value: &T) -> Result<String, NestedInnerLaunchPlanFault> {
    serde_json::to_string(value).map_err(machine_form_fault)
}

fn parse_bounded<T: DeserializeOwned>(value: &str) -> Result<T, NestedInnerLaunchPlanFault> {
    if value.len() > NESTED_INNER_LAUNCH_PLAN_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            NestedInnerLaunchPlanFaultCode::InvalidMachineForm,
            "machine form exceeds 1048576 bytes",
        ));
    }
    let shape: Value = serde_json::from_str(value).map_err(machine_form_fault)?;
    let mut fields = 0;
    validate_json_shape(&shape, 1, &mut fields)?;
    serde_json::from_str(value).map_err(machine_form_fault)
}

fn validate_json_shape(
    value: &Value,
    depth: usize,
    fields: &mut usize,
) -> Result<(), NestedInnerLaunchPlanFault> {
    if depth > MAX_DEPTH {
        return Err(fault(
            NestedInnerLaunchPlanFaultCode::InvalidMachineForm,
            "machine form exceeds depth 28",
        ));
    }
    match value {
        Value::Object(map) => {
            *fields = fields.saturating_add(map.len());
            if *fields > MAX_FIELDS {
                return Err(fault(
                    NestedInnerLaunchPlanFaultCode::InvalidMachineForm,
                    "machine form exceeds 384 fields",
                ));
            }
            for (key, child) in map {
                if !valid_text(key) {
                    return Err(fault(
                        NestedInnerLaunchPlanFaultCode::InvalidMachineForm,
                        "machine field text differs",
                    ));
                }
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
                        NestedInnerLaunchPlanFaultCode::InvalidMachineForm,
                        "machine form contains a duplicate string set member",
                    ));
                }
            }
            for child in values {
                validate_json_shape(child, depth + 1, fields)?;
            }
        }
        Value::String(text) if !valid_text(text) => {
            return Err(fault(
                NestedInnerLaunchPlanFaultCode::InvalidMachineForm,
                "machine text differs",
            ));
        }
        Value::String(_) | Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn fault(
    code: NestedInnerLaunchPlanFaultCode,
    detail: impl Into<String>,
) -> NestedInnerLaunchPlanFault {
    NestedInnerLaunchPlanFault {
        code,
        detail: detail.into(),
    }
}
fn machine_fault(error: serde_json::Error) -> NestedInnerLaunchPlanFault {
    fault(
        NestedInnerLaunchPlanFaultCode::InvalidDigest,
        format!("canonical serialization refused: {error}"),
    )
}
fn machine_form_fault(error: serde_json::Error) -> NestedInnerLaunchPlanFault {
    fault(
        NestedInnerLaunchPlanFaultCode::InvalidMachineForm,
        format!("machine form refused: {error}"),
    )
}
fn upstream_fault(error: impl fmt::Display) -> NestedInnerLaunchPlanFault {
    fault(
        NestedInnerLaunchPlanFaultCode::InvalidUpstream,
        format!("NHC-03 replay refused: {error}"),
    )
}
