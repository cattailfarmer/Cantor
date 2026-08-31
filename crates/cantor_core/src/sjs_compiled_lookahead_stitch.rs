//! Pure provider-free compilation for SJS Compiled Lookahead Stitch P0.
//!
//! The module compiles supplied public declarations into lifecycle and
//! projection records. It performs no filesystem, environment, clock,
//! process, network, provider, model, inference, prompt, MCP, Git, workspace,
//! secret, permission, remote-hardware, or external action.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ContentDigest, SemanticId, sha256_bytes};

pub const SJS_LAS_REQUEST_PROFILE: &str = "cantor-sjs-compiled-lookahead-stitch-request/0.1";
pub const SJS_LAS_ENVELOPE_PROFILE: &str = "cantor-sjs-compiled-lookahead-stitch-envelope/0.1";
pub const SJS_LAS_VERIFICATION_PROFILE: &str =
    "cantor-sjs-compiled-lookahead-stitch-verification/0.1";
pub const SJS_LAS_EVIDENCE_PROFILE: &str = "cantor-sjs-compiled-lookahead-stitch-evidence/0.1";
pub const SJS_LAS_CANONICAL_UUID: &str = "5b57d004-0a43-4d89-9c5a-6dc671a2a05a";
pub const SJS_LAS_SIGNATURE_UUID: &str = "2b743f94-ec0a-48cb-a68c-f5cb0b62bc68";
pub const SJS_LAS_SOURCE_UUID: &str = "9a3eb07f-b5f3-4d4b-83ec-32c410deb7ec";
pub const SJS_LAS_PARENT_SOURCE_UUID: &str = "2093c2d5-e406-4a93-a393-bbed0f5922f9";
pub const SJS_LAS_NON_AUTHORITY: &str = "Supplied public stitch compilation only. A packet, lifecycle receipt, projection record, digest, or verifier result grants no prompt mutation, provider or model use, hidden-state access, hint optimality, performance truth, autonomous work, durable custody, host authority, remote-hardware state, or external-effect authority.";
pub const SJS_LAS_MAX_MACHINE_FORM_BYTES: usize = 1_048_576;
pub const SJS_LAS_MAX_EVIDENCE_BYTES: usize = 8_388_608;

const MAX_DEPTH: usize = 40;
const MAX_FIELDS: usize = 16_384;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_STITCHES: usize = 2;
const MAX_HINTS: usize = 8;
const MAX_SOURCES: usize = 8;
const MAX_INVALIDATORS: usize = 8;
const MAX_OBSERVATIONS: usize = 64;
const MAX_COORDINATES: usize = 32;
const MAX_PROJECTED_BYTES: usize = 8_192;
const MAX_REFERENCES: usize = 64;
const REQUEST_FILE: &str = "request.json";
const ENVELOPE_FILE: &str = "envelope.json";
const VERIFICATION_FILE: &str = "verification.json";

const SCOPE_DOMAIN: &str = "cantor.sjs-las.scope.v1";
const STITCH_DOMAIN: &str = "cantor.sjs-las.stitch.v1";
const REQUEST_DOMAIN: &str = "cantor.sjs-las.request.v1";
const TEMPLATE_DOMAIN: &str = "cantor.sjs-las.template.v1";
const PACKET_DOMAIN: &str = "cantor.sjs-las.packet.v1";
const RECEIPT_DOMAIN: &str = "cantor.sjs-las.receipt.v1";
const PROJECTION_DOMAIN: &str = "cantor.sjs-las.projection.v1";
const ENVELOPE_DOMAIN: &str = "cantor.sjs-las.envelope.v1";

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsLasInputClass {
    SyntheticProviderFreeFixture,
    SuppliedUnobservedDeclaration,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsLasSemanticTurnKind {
    SelectDistinction,
    ConserveInvariant,
    ExposeRelationship,
    ChangeAbstractionLevel,
    IntroduceCounterexample,
    RouteEvidenceGate,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsLasSourceBindingClass {
    GoverningAnchor,
    PlanHint,
    ObservedCoordinate,
    NonauthorityEvidence,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsLasLifecycleState {
    Proposed,
    Active,
    Fulfilled,
    Invalidated,
    Released,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsLasObservationKind {
    Activate,
    Signal,
    Checkpoint,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsLasBoundaryKind {
    Initial,
    ResumeAfterStop,
    ResumeAfterToolResult,
    Reentry,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsLasTransitionDisposition {
    TransitionAdmitted,
    TransitionRefused,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsLasAuthority {
    SuppliedPublicStitchCompilationOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLasPredicate {
    pub field: String,
    pub equals: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLasExactScope {
    pub scope_id: SemanticId,
    pub source_identities: BTreeSet<SemanticId>,
    pub objective: String,
    pub phase: String,
    pub feature: String,
    pub requirement: String,
    pub artifact: String,
    pub invocation_start: u32,
    pub invocation_end: u32,
    pub model_profile: String,
    pub provider_profile: String,
    pub tool_policy: String,
    pub authority_ceiling: String,
    pub completion_conditions: BTreeSet<String>,
    pub invalidation_conditions: BTreeSet<String>,
    pub scope_exit_cue: SjsLasPredicate,
    pub scope_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLasSemanticTurn {
    pub kind: SjsLasSemanticTurnKind,
    pub description: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLasSourceBinding {
    pub source_id: SemanticId,
    pub class: SjsLasSourceBindingClass,
    pub locator: String,
    pub authority_identity: Option<String>,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLasStitchDeclaration {
    pub stitch_id: SemanticId,
    pub predecessor_id: Option<SemanticId>,
    pub subject_anchor: String,
    pub semantic_turn: SjsLasSemanticTurn,
    pub transform: String,
    pub scope_id: SemanticId,
    pub key_hints: Vec<String>,
    pub source_bindings: Vec<SjsLasSourceBinding>,
    pub completion_cue: SjsLasPredicate,
    pub invalidators: Vec<SjsLasPredicate>,
    pub declaration_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLasObservation {
    pub observation_id: SemanticId,
    pub ordinal: u32,
    pub kind: SjsLasObservationKind,
    pub stitch_id: Option<SemanticId>,
    pub fields: BTreeMap<String, String>,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLasInvocationCoordinate {
    pub coordinate_id: SemanticId,
    pub ordinal: u32,
    pub after_observation_ordinal: u32,
    pub invocation_ordinal: u32,
    pub phase: String,
    pub objective: String,
    pub feature: String,
    pub requirement: String,
    pub artifact: String,
    pub model_profile: String,
    pub provider_profile: String,
    pub tool_policy: String,
    pub authority_ceiling: String,
    pub boundary_kind: SjsLasBoundaryKind,
    pub last_accepted_receipt_id: Option<SemanticId>,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLasRequest {
    pub profile: String,
    pub request_id: SemanticId,
    pub run_id: SemanticId,
    pub packet_id: SemanticId,
    pub policy_id: SemanticId,
    pub input_class: SjsLasInputClass,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_snapshot_uuid: String,
    pub parent_source_uuid: String,
    pub scope: SjsLasExactScope,
    pub stitches: Vec<SjsLasStitchDeclaration>,
    pub observations: Vec<SjsLasObservation>,
    pub coordinates: Vec<SjsLasInvocationCoordinate>,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub non_authority: String,
    pub request_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLasCompiledPacket {
    pub packet_id: SemanticId,
    pub scope_id: SemanticId,
    pub stitch_declarations: Vec<SjsLasStitchDeclaration>,
    pub projection_template_digest: ContentDigest,
    pub packet_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLasLifecycleReceipt {
    pub ordinal: u32,
    pub receipt_id: SemanticId,
    pub observation_id: SemanticId,
    pub stitch_id: SemanticId,
    pub before_state: SjsLasLifecycleState,
    pub after_state: SjsLasLifecycleState,
    pub disposition: SjsLasTransitionDisposition,
    pub reason: String,
    pub packet_digest: ContentDigest,
    pub receipt_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLasProjectionRecord {
    pub projection_id: SemanticId,
    pub coordinate: SjsLasInvocationCoordinate,
    pub packet_digest: ContentDigest,
    pub active_stitch_ids: Vec<SemanticId>,
    pub rendered_stitches: Vec<String>,
    pub projected_bytes: u64,
    pub projection_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLasStateRecord {
    pub stitch_id: SemanticId,
    pub state: SjsLasLifecycleState,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLasEffectAccount {
    pub filesystem_effect_count: u32,
    pub environment_effect_count: u32,
    pub clock_effect_count: u32,
    pub process_effect_count: u32,
    pub network_effect_count: u32,
    pub provider_effect_count: u32,
    pub model_effect_count: u32,
    pub inference_effect_count: u32,
    pub mcp_effect_count: u32,
    pub git_workspace_effect_count: u32,
    pub secret_effect_count: u32,
    pub permission_effect_count: u32,
    pub remote_hardware_effect_count: u32,
    pub external_effect_count: u32,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLasEnvelope {
    pub profile: String,
    pub request: SjsLasRequest,
    pub authority: SjsLasAuthority,
    pub packet: SjsLasCompiledPacket,
    pub lifecycle_receipts: Vec<SjsLasLifecycleReceipt>,
    pub projection_records: Vec<SjsLasProjectionRecord>,
    pub final_states: Vec<SjsLasStateRecord>,
    pub execution_authorized: bool,
    pub effects: SjsLasEffectAccount,
    pub envelope_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLasVerification {
    pub profile: String,
    pub status: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub input_class: SjsLasInputClass,
    pub authority: SjsLasAuthority,
    pub request_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
    pub stitch_count: u32,
    pub hint_count: u32,
    pub source_binding_count: u32,
    pub observation_count: u32,
    pub coordinate_count: u32,
    pub projection_count: u32,
    pub projected_inclusion_count: u32,
    pub activation_count: u32,
    pub fulfillment_count: u32,
    pub invalidation_count: u32,
    pub release_count: u32,
    pub refused_transition_count: u32,
    pub maximum_projected_bytes: u64,
    pub total_projected_bytes: u64,
    pub initial_boundary_count: u32,
    pub stop_boundary_count: u32,
    pub tool_result_boundary_count: u32,
    pub reentry_boundary_count: u32,
    pub evidence_reference_count: u32,
    pub execution_authorized: bool,
    pub effects: SjsLasEffectAccount,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLasEvidenceFile {
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLasEvidenceManifest {
    pub profile: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub replay_count: u32,
    pub files: BTreeMap<String, SjsLasEvidenceFile>,
    pub request_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
    pub stitch_count: u32,
    pub hint_count: u32,
    pub source_binding_count: u32,
    pub observation_count: u32,
    pub coordinate_count: u32,
    pub projected_inclusion_count: u32,
    pub activation_count: u32,
    pub fulfillment_count: u32,
    pub invalidation_count: u32,
    pub refused_transition_count: u32,
    pub execution_authorized: bool,
    pub effects: SjsLasEffectAccount,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLasEvidenceBundle {
    pub request_file: String,
    pub envelope_file: String,
    pub verification_file: String,
    pub manifest_file: String,
}

struct DerivedLasRecords {
    receipts: Vec<SjsLasLifecycleReceipt>,
    projections: Vec<SjsLasProjectionRecord>,
    final_states: Vec<SjsLasStateRecord>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SjsLasFaultCode {
    InvalidProfile,
    InvalidInputClass,
    InvalidIdentity,
    InvalidText,
    InvalidDigest,
    InvalidBound,
    InvalidScope,
    InvalidStitch,
    InvalidSource,
    InvalidObservation,
    InvalidCoordinate,
    InvalidLifecycle,
    InvalidProjection,
    InvalidAuthority,
    InvalidEvidence,
    InvalidMachineForm,
    ArithmeticOverflow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SjsLasFault {
    pub code: SjsLasFaultCode,
    pub detail: String,
}

impl fmt::Display for SjsLasFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}

impl std::error::Error for SjsLasFault {}

pub fn seal_sjs_las_request(mut request: SjsLasRequest) -> Result<SjsLasRequest, SjsLasFault> {
    request.scope.scope_digest = empty_digest();
    request.scope.scope_digest = sjs_las_scope_digest(&request.scope)?;
    for stitch in &mut request.stitches {
        stitch.declaration_digest = empty_digest();
        stitch.declaration_digest = sjs_las_stitch_digest(stitch)?;
    }
    request.request_digest = empty_digest();
    validate_request_body(&request)?;
    request.request_digest = sjs_las_request_digest(&request)?;
    validate_sjs_las_request(&request)?;
    Ok(request)
}

pub fn validate_sjs_las_request(request: &SjsLasRequest) -> Result<(), SjsLasFault> {
    validate_request_body(request)?;
    if sjs_las_request_digest(request)? != request.request_digest {
        return Err(fault(
            SjsLasFaultCode::InvalidDigest,
            "request digest differs",
        ));
    }
    Ok(())
}

pub fn compile_sjs_las(request: &SjsLasRequest) -> Result<SjsLasEnvelope, SjsLasFault> {
    validate_sjs_las_request(request)?;
    let packet = compile_packet(request)?;
    let derived = derive_runtime_records(request, &packet)?;
    let mut envelope = SjsLasEnvelope {
        profile: SJS_LAS_ENVELOPE_PROFILE.to_owned(),
        request: request.clone(),
        authority: SjsLasAuthority::SuppliedPublicStitchCompilationOnly,
        packet,
        lifecycle_receipts: derived.receipts,
        projection_records: derived.projections,
        final_states: derived.final_states,
        execution_authorized: false,
        effects: SjsLasEffectAccount::default(),
        envelope_digest: empty_digest(),
    };
    envelope.envelope_digest = sjs_las_envelope_digest(&envelope)?;
    Ok(envelope)
}

pub fn validate_sjs_las_envelope(envelope: &SjsLasEnvelope) -> Result<(), SjsLasFault> {
    validate_sjs_las_request(&envelope.request)?;
    if envelope.profile != SJS_LAS_ENVELOPE_PROFILE
        || envelope.authority != SjsLasAuthority::SuppliedPublicStitchCompilationOnly
        || envelope.execution_authorized
        || envelope.effects != SjsLasEffectAccount::default()
    {
        return Err(fault(
            SjsLasFaultCode::InvalidAuthority,
            "envelope authority or effects differ",
        ));
    }
    let expected = compile_sjs_las(&envelope.request)?;
    if expected != *envelope {
        return Err(fault(
            SjsLasFaultCode::InvalidProjection,
            "envelope differs from deterministic compilation",
        ));
    }
    Ok(())
}

pub fn verify_sjs_las(envelope: &SjsLasEnvelope) -> Result<SjsLasVerification, SjsLasFault> {
    validate_sjs_las_envelope(envelope)?;
    verification_for(envelope)
}

pub fn build_sjs_las_evidence_bundle(
    request: &SjsLasRequest,
) -> Result<SjsLasEvidenceBundle, SjsLasFault> {
    validate_sjs_las_request(request)?;
    let first = compile_sjs_las(request)?;
    let second = compile_sjs_las(request)?;
    if first != second {
        return Err(fault(
            SjsLasFaultCode::InvalidEvidence,
            "double compilation differs",
        ));
    }
    let first_verification = verify_sjs_las(&first)?;
    let second_verification = verify_sjs_las(&second)?;
    if first_verification != second_verification {
        return Err(fault(
            SjsLasFaultCode::InvalidEvidence,
            "double verification differs",
        ));
    }
    let request_file = canonical_file(to_sjs_las_request_machine_form(request)?);
    let envelope_file = canonical_file(to_sjs_las_envelope_machine_form(&first)?);
    let verification_file = canonical_file(to_machine_form(&first_verification)?);
    let manifest = evidence_manifest(
        &request_file,
        &envelope_file,
        &verification_file,
        &first_verification,
    )?;
    let manifest_file = canonical_file(to_machine_form(&manifest)?);
    let bundle = SjsLasEvidenceBundle {
        request_file,
        envelope_file,
        verification_file,
        manifest_file,
    };
    ensure_bundle_bound(&bundle)?;
    Ok(bundle)
}

pub fn verify_sjs_las_evidence_bundle(
    bundle: &SjsLasEvidenceBundle,
) -> Result<SjsLasVerification, SjsLasFault> {
    ensure_bundle_bound(bundle)?;
    let request: SjsLasRequest =
        parse_bounded(canonical_file_body(&bundle.request_file, REQUEST_FILE)?)?;
    let retained_envelope: SjsLasEnvelope =
        parse_bounded(canonical_file_body(&bundle.envelope_file, ENVELOPE_FILE)?)?;
    let retained_verification: SjsLasVerification = parse_bounded(canonical_file_body(
        &bundle.verification_file,
        VERIFICATION_FILE,
    )?)?;
    let retained_manifest: SjsLasEvidenceManifest =
        parse_bounded(canonical_file_body(&bundle.manifest_file, "manifest.json")?)?;
    validate_sjs_las_request(&request)?;
    let first = compile_sjs_las(&request)?;
    let second = compile_sjs_las(&request)?;
    if first != second || first != retained_envelope {
        return Err(fault(
            SjsLasFaultCode::InvalidEvidence,
            "retained envelope differs from independent double compilation",
        ));
    }
    let verification = verify_sjs_las(&first)?;
    if verification != retained_verification {
        return Err(fault(
            SjsLasFaultCode::InvalidEvidence,
            "retained verification differs",
        ));
    }
    let expected_manifest = evidence_manifest(
        &bundle.request_file,
        &bundle.envelope_file,
        &bundle.verification_file,
        &verification,
    )?;
    if expected_manifest != retained_manifest {
        return Err(fault(
            SjsLasFaultCode::InvalidEvidence,
            "retained manifest differs",
        ));
    }
    Ok(verification)
}

pub fn to_sjs_las_request_machine_form(request: &SjsLasRequest) -> Result<String, SjsLasFault> {
    validate_sjs_las_request(request)?;
    to_machine_form(request)
}

pub fn from_sjs_las_request_machine_form(value: &str) -> Result<SjsLasRequest, SjsLasFault> {
    let request: SjsLasRequest = parse_bounded(value)?;
    validate_sjs_las_request(&request)?;
    Ok(request)
}

pub fn to_sjs_las_envelope_machine_form(envelope: &SjsLasEnvelope) -> Result<String, SjsLasFault> {
    validate_sjs_las_envelope(envelope)?;
    to_machine_form(envelope)
}

pub fn from_sjs_las_envelope_machine_form(value: &str) -> Result<SjsLasEnvelope, SjsLasFault> {
    let envelope: SjsLasEnvelope = parse_bounded(value)?;
    validate_sjs_las_envelope(&envelope)?;
    Ok(envelope)
}

pub fn to_sjs_las_verification_machine_form(
    verification: &SjsLasVerification,
) -> Result<String, SjsLasFault> {
    to_machine_form(verification)
}

pub fn to_sjs_las_evidence_bundle_machine_form(
    bundle: &SjsLasEvidenceBundle,
) -> Result<String, SjsLasFault> {
    ensure_bundle_bound(bundle)?;
    to_machine_form(bundle)
}

pub fn from_sjs_las_evidence_bundle_machine_form(
    value: &str,
) -> Result<SjsLasEvidenceBundle, SjsLasFault> {
    let bundle: SjsLasEvidenceBundle = parse_bounded_with_limit(value, SJS_LAS_MAX_EVIDENCE_BYTES)?;
    ensure_bundle_bound(&bundle)?;
    Ok(bundle)
}

pub fn sjs_las_scope_digest(value: &SjsLasExactScope) -> Result<ContentDigest, SjsLasFault> {
    let mut body = value.clone();
    body.scope_digest = empty_digest();
    sha256_form(SCOPE_DOMAIN, &body)
}

pub fn sjs_las_stitch_digest(
    value: &SjsLasStitchDeclaration,
) -> Result<ContentDigest, SjsLasFault> {
    let mut body = value.clone();
    body.declaration_digest = empty_digest();
    sha256_form(STITCH_DOMAIN, &body)
}

pub fn sjs_las_request_digest(value: &SjsLasRequest) -> Result<ContentDigest, SjsLasFault> {
    let mut body = value.clone();
    body.request_digest = empty_digest();
    sha256_form(REQUEST_DOMAIN, &body)
}

pub fn sjs_las_envelope_digest(value: &SjsLasEnvelope) -> Result<ContentDigest, SjsLasFault> {
    let mut body = value.clone();
    body.envelope_digest = empty_digest();
    sha256_form(ENVELOPE_DOMAIN, &body)
}

pub fn synthetic_sjs_las_request() -> Result<SjsLasRequest, SjsLasFault> {
    let scope_id = semantic_id("scope:82000000-0000-4000-8000-000000000001")?;
    let source_a = semantic_id("source:82000000-0000-4000-8000-000000000010")?;
    let source_b = semantic_id("source:82000000-0000-4000-8000-000000000011")?;
    let source_c = semantic_id("source:82000000-0000-4000-8000-000000000012")?;
    let source_d = semantic_id("source:82000000-0000-4000-8000-000000000013")?;
    let scope = SjsLasExactScope {
        scope_id: scope_id.clone(),
        source_identities: [
            source_a.clone(),
            source_b.clone(),
            source_c.clone(),
            source_d.clone(),
        ]
        .into_iter()
        .collect(),
        objective: "compile a lightweight scope-persistent semantic launch surface".to_owned(),
        phase: "provider-free implementation proof".to_owned(),
        feature: "sjs compiled lookahead stitch p0".to_owned(),
        requirement: "LAS-017 through LAS-023".to_owned(),
        artifact: "provider-free retained fixture".to_owned(),
        invocation_start: 1,
        invocation_end: 4,
        model_profile: "declared-model/provider-free-fixture".to_owned(),
        provider_profile: "declared-provider/provider-free-fixture".to_owned(),
        tool_policy: "declared-tool-policy/no-effects".to_owned(),
        authority_ceiling: "supplied_public_stitch_compilation_only".to_owned(),
        completion_conditions: ["exact completion cue observed".to_owned()]
            .into_iter()
            .collect(),
        invalidation_conditions: ["exact invalidator observed".to_owned()]
            .into_iter()
            .collect(),
        scope_exit_cue: predicate("scope_state", "exited"),
        scope_digest: empty_digest(),
    };
    let stitch_a = SjsLasStitchDeclaration {
        stitch_id: semantic_id("stitch:82000000-0000-4000-8000-000000000020")?,
        predecessor_id: None,
        subject_anchor: "lookahead stitch compiler".to_owned(),
        semantic_turn: SjsLasSemanticTurn {
            kind: SjsLasSemanticTurnKind::ConserveInvariant,
            description: "keep source-class nonpromotion visible".to_owned(),
        },
        transform: "compile exact declarations before host integration".to_owned(),
        scope_id: scope_id.clone(),
        key_hints: vec![
            "source class".to_owned(),
            "exact lifecycle".to_owned(),
            "zero effects".to_owned(),
            "independent replay".to_owned(),
        ],
        source_bindings: vec![
            binding(
                source_a,
                SjsLasSourceBindingClass::GoverningAnchor,
                "specifications/Cantor_SJS_Compiled_Lookahead_Stitch_P0.sop#LAS-009",
                Some("signed-canonical-formation"),
            ),
            binding(
                source_b,
                SjsLasSourceBindingClass::PlanHint,
                "plans/Cantor_SJS_Compiled_Lookahead_Stitch_P0_Plan.sop#P2",
                None,
            ),
        ],
        completion_cue: predicate("stitch_a", "verified"),
        invalidators: vec![predicate("authority", "drifted")],
        declaration_digest: empty_digest(),
    };
    let stitch_b = SjsLasStitchDeclaration {
        stitch_id: semantic_id("stitch:82000000-0000-4000-8000-000000000021")?,
        predecessor_id: None,
        subject_anchor: "boundary continuity".to_owned(),
        semantic_turn: SjsLasSemanticTurn {
            kind: SjsLasSemanticTurnKind::RouteEvidenceGate,
            description: "carry the projection receipt across host boundaries".to_owned(),
        },
        transform: "project every active stitch at each covered coordinate".to_owned(),
        scope_id: scope_id.clone(),
        key_hints: vec![
            "initial".to_owned(),
            "stop resume".to_owned(),
            "tool result".to_owned(),
            "reentry".to_owned(),
        ],
        source_bindings: vec![
            binding(
                source_c,
                SjsLasSourceBindingClass::ObservedCoordinate,
                "synthetic-fixture/coordinates",
                None,
            ),
            binding(
                source_d,
                SjsLasSourceBindingClass::NonauthorityEvidence,
                "synthetic-fixture/replay",
                None,
            ),
        ],
        completion_cue: predicate("stitch_b", "verified"),
        invalidators: vec![predicate("scope_source", "stale")],
        declaration_digest: empty_digest(),
    };
    let observations = vec![
        observation(
            1,
            "82000000-0000-4000-8000-000000000101",
            SjsLasObservationKind::Activate,
            Some(stitch_a.stitch_id.clone()),
            &[],
        ),
        observation(
            2,
            "82000000-0000-4000-8000-000000000102",
            SjsLasObservationKind::Activate,
            Some(stitch_b.stitch_id.clone()),
            &[],
        ),
        observation(
            3,
            "82000000-0000-4000-8000-000000000103",
            SjsLasObservationKind::Checkpoint,
            None,
            &[("boundary", "stop")],
        ),
        observation(
            4,
            "82000000-0000-4000-8000-000000000104",
            SjsLasObservationKind::Signal,
            Some(stitch_a.stitch_id.clone()),
            &[("stitch_a", "verified")],
        ),
        observation(
            5,
            "82000000-0000-4000-8000-000000000105",
            SjsLasObservationKind::Checkpoint,
            None,
            &[("boundary", "tool_result")],
        ),
        observation(
            6,
            "82000000-0000-4000-8000-000000000106",
            SjsLasObservationKind::Signal,
            Some(stitch_b.stitch_id.clone()),
            &[("scope_source", "stale")],
        ),
    ];
    let coordinate_specs = [
        (
            1,
            2,
            1,
            "82000000-0000-4000-8000-000000000201",
            "82000000-0000-4000-8000-000000000102",
            SjsLasBoundaryKind::Initial,
        ),
        (
            2,
            3,
            2,
            "82000000-0000-4000-8000-000000000202",
            "82000000-0000-4000-8000-000000000102",
            SjsLasBoundaryKind::ResumeAfterStop,
        ),
        (
            3,
            5,
            3,
            "82000000-0000-4000-8000-000000000203",
            "82000000-0000-4000-8000-000000000104",
            SjsLasBoundaryKind::ResumeAfterToolResult,
        ),
        (
            4,
            6,
            4,
            "82000000-0000-4000-8000-000000000204",
            "82000000-0000-4000-8000-000000000106",
            SjsLasBoundaryKind::Reentry,
        ),
    ];
    let coordinates = coordinate_specs
        .into_iter()
        .map(
            |(ordinal, after, invocation, id, receipt_uuid, boundary_kind)| {
                SjsLasInvocationCoordinate {
                    coordinate_id: semantic_id(format!("coordinate:{id}"))
                        .expect("fixed coordinate identity"),
                    ordinal,
                    after_observation_ordinal: after,
                    invocation_ordinal: invocation,
                    phase: scope.phase.clone(),
                    objective: scope.objective.clone(),
                    feature: scope.feature.clone(),
                    requirement: scope.requirement.clone(),
                    artifact: scope.artifact.clone(),
                    model_profile: scope.model_profile.clone(),
                    provider_profile: scope.provider_profile.clone(),
                    tool_policy: scope.tool_policy.clone(),
                    authority_ceiling: scope.authority_ceiling.clone(),
                    boundary_kind,
                    last_accepted_receipt_id: Some(
                        semantic_id(format!("receipt:{receipt_uuid}"))
                            .expect("fixed receipt identity"),
                    ),
                }
            },
        )
        .collect();
    seal_sjs_las_request(SjsLasRequest {
        profile: SJS_LAS_REQUEST_PROFILE.to_owned(),
        request_id: semantic_id("request:82000000-0000-4000-8000-000000000301")?,
        run_id: semantic_id("run:82000000-0000-4000-8000-000000000302")?,
        packet_id: semantic_id("packet:82000000-0000-4000-8000-000000000303")?,
        policy_id: semantic_id("policy:82000000-0000-4000-8000-000000000304")?,
        input_class: SjsLasInputClass::SyntheticProviderFreeFixture,
        canonical_uuid: SJS_LAS_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_LAS_SIGNATURE_UUID.to_owned(),
        source_snapshot_uuid: SJS_LAS_SOURCE_UUID.to_owned(),
        parent_source_uuid: SJS_LAS_PARENT_SOURCE_UUID.to_owned(),
        scope,
        stitches: vec![stitch_a, stitch_b],
        observations,
        coordinates,
        evidence_refs: [semantic_id(
            "evidence:82000000-0000-4000-8000-000000000305",
        )?]
        .into_iter()
        .collect(),
        non_authority: SJS_LAS_NON_AUTHORITY.to_owned(),
        request_digest: empty_digest(),
    })
}

fn compile_packet(request: &SjsLasRequest) -> Result<SjsLasCompiledPacket, SjsLasFault> {
    let projection_template_digest = sha256_form(TEMPLATE_DOMAIN, &request.stitches)?;
    let mut packet = SjsLasCompiledPacket {
        packet_id: request.packet_id.clone(),
        scope_id: request.scope.scope_id.clone(),
        stitch_declarations: request.stitches.clone(),
        projection_template_digest,
        packet_digest: empty_digest(),
    };
    packet.packet_digest = sha256_form(PACKET_DOMAIN, &packet)?;
    Ok(packet)
}

fn derive_runtime_records(
    request: &SjsLasRequest,
    packet: &SjsLasCompiledPacket,
) -> Result<DerivedLasRecords, SjsLasFault> {
    let declarations = request
        .stitches
        .iter()
        .map(|s| (s.stitch_id.clone(), s))
        .collect::<BTreeMap<_, _>>();
    let mut states = request
        .stitches
        .iter()
        .map(|s| (s.stitch_id.clone(), SjsLasLifecycleState::Proposed))
        .collect::<BTreeMap<_, _>>();
    let mut receipts = Vec::new();
    let mut projections = Vec::new();
    for observation in &request.observations {
        if observation.kind != SjsLasObservationKind::Checkpoint {
            let stitch_id = observation.stitch_id.as_ref().ok_or_else(|| {
                fault(
                    SjsLasFaultCode::InvalidObservation,
                    "transition target absent",
                )
            })?;
            let declaration = declarations.get(stitch_id).ok_or_else(|| {
                fault(
                    SjsLasFaultCode::InvalidObservation,
                    "transition target unknown",
                )
            })?;
            let before = *states
                .get(stitch_id)
                .ok_or_else(|| fault(SjsLasFaultCode::InvalidLifecycle, "state target unknown"))?;
            let (after, disposition, reason) = evaluate_transition(
                observation,
                declaration,
                &request.scope.scope_exit_cue,
                before,
                &states,
            )?;
            if disposition == SjsLasTransitionDisposition::TransitionAdmitted {
                states.insert(stitch_id.clone(), after);
            }
            let mut receipt = SjsLasLifecycleReceipt {
                ordinal: count_u32(receipts.len().checked_add(1).ok_or_else(|| {
                    fault(
                        SjsLasFaultCode::ArithmeticOverflow,
                        "receipt ordinal overflow",
                    )
                })?)?,
                receipt_id: derived_id("receipt", &observation.observation_id)?,
                observation_id: observation.observation_id.clone(),
                stitch_id: stitch_id.clone(),
                before_state: before,
                after_state: if disposition == SjsLasTransitionDisposition::TransitionAdmitted {
                    after
                } else {
                    before
                },
                disposition,
                reason,
                packet_digest: packet.packet_digest.clone(),
                receipt_digest: empty_digest(),
            };
            receipt.receipt_digest = sha256_form(RECEIPT_DOMAIN, &receipt)?;
            receipts.push(receipt);
        }
        for coordinate in request
            .coordinates
            .iter()
            .filter(|coordinate| coordinate.after_observation_ordinal == observation.ordinal)
        {
            let active = states
                .iter()
                .filter_map(|(id, state)| {
                    (*state == SjsLasLifecycleState::Active).then_some(id.clone())
                })
                .collect::<Vec<_>>();
            let mut rendered = Vec::new();
            let mut projected_bytes = 0_usize;
            for id in &active {
                let declaration = declarations.get(id).ok_or_else(|| {
                    fault(
                        SjsLasFaultCode::InvalidProjection,
                        "active declaration absent",
                    )
                })?;
                let body = to_machine_form(*declaration)?;
                projected_bytes = projected_bytes.checked_add(body.len()).ok_or_else(|| {
                    fault(
                        SjsLasFaultCode::ArithmeticOverflow,
                        "projection byte count overflow",
                    )
                })?;
                rendered.push(body);
            }
            if projected_bytes > MAX_PROJECTED_BYTES {
                return Err(fault(
                    SjsLasFaultCode::InvalidBound,
                    "projection exceeds 8192 bytes",
                ));
            }
            let mut projection = SjsLasProjectionRecord {
                projection_id: derived_id("projection", &coordinate.coordinate_id)?,
                coordinate: coordinate.clone(),
                packet_digest: packet.packet_digest.clone(),
                active_stitch_ids: active,
                rendered_stitches: rendered,
                projected_bytes: count_u64(projected_bytes)?,
                projection_digest: empty_digest(),
            };
            projection.projection_digest = sha256_form(PROJECTION_DOMAIN, &projection)?;
            projections.push(projection);
        }
    }
    if projections.len() != request.coordinates.len() {
        return Err(fault(
            SjsLasFaultCode::InvalidCoordinate,
            "coordinate was not projected exactly once",
        ));
    }
    let final_states = states
        .into_iter()
        .map(|(stitch_id, state)| SjsLasStateRecord { stitch_id, state })
        .collect();
    Ok(DerivedLasRecords {
        receipts,
        projections,
        final_states,
    })
}

fn evaluate_transition(
    observation: &SjsLasObservation,
    declaration: &SjsLasStitchDeclaration,
    scope_exit_cue: &SjsLasPredicate,
    before: SjsLasLifecycleState,
    states: &BTreeMap<SemanticId, SjsLasLifecycleState>,
) -> Result<(SjsLasLifecycleState, SjsLasTransitionDisposition, String), SjsLasFault> {
    if matches!(
        before,
        SjsLasLifecycleState::Fulfilled
            | SjsLasLifecycleState::Invalidated
            | SjsLasLifecycleState::Released
    ) {
        return Ok((
            before,
            SjsLasTransitionDisposition::TransitionRefused,
            "terminal_state_cannot_transition".to_owned(),
        ));
    }
    match observation.kind {
        SjsLasObservationKind::Activate => {
            if before != SjsLasLifecycleState::Proposed {
                return Ok((
                    before,
                    SjsLasTransitionDisposition::TransitionRefused,
                    "only_proposed_may_activate".to_owned(),
                ));
            }
            if let Some(predecessor) = &declaration.predecessor_id {
                let predecessor_state = states.get(predecessor).copied().ok_or_else(|| {
                    fault(
                        SjsLasFaultCode::InvalidStitch,
                        "replacement predecessor absent",
                    )
                })?;
                if !matches!(
                    predecessor_state,
                    SjsLasLifecycleState::Fulfilled
                        | SjsLasLifecycleState::Invalidated
                        | SjsLasLifecycleState::Released
                ) {
                    return Ok((
                        before,
                        SjsLasTransitionDisposition::TransitionRefused,
                        "replacement_predecessor_not_terminal".to_owned(),
                    ));
                }
            }
            Ok((
                SjsLasLifecycleState::Active,
                SjsLasTransitionDisposition::TransitionAdmitted,
                "activation_admitted".to_owned(),
            ))
        }
        SjsLasObservationKind::Signal => {
            if declaration
                .invalidators
                .iter()
                .any(|predicate| predicate_matches(predicate, &observation.fields))
            {
                return Ok((
                    SjsLasLifecycleState::Invalidated,
                    SjsLasTransitionDisposition::TransitionAdmitted,
                    "invalidation_precedence_admitted".to_owned(),
                ));
            }
            if predicate_matches(&declaration.completion_cue, &observation.fields) {
                return if before == SjsLasLifecycleState::Active {
                    Ok((
                        SjsLasLifecycleState::Fulfilled,
                        SjsLasTransitionDisposition::TransitionAdmitted,
                        "completion_admitted".to_owned(),
                    ))
                } else {
                    Ok((
                        before,
                        SjsLasTransitionDisposition::TransitionRefused,
                        "completion_requires_active".to_owned(),
                    ))
                };
            }
            if predicate_matches(scope_exit_cue, &observation.fields) {
                return if before == SjsLasLifecycleState::Active {
                    Ok((
                        SjsLasLifecycleState::Released,
                        SjsLasTransitionDisposition::TransitionAdmitted,
                        "scope_exit_admitted".to_owned(),
                    ))
                } else {
                    Ok((
                        before,
                        SjsLasTransitionDisposition::TransitionRefused,
                        "scope_exit_requires_active".to_owned(),
                    ))
                };
            }
            Ok((
                before,
                SjsLasTransitionDisposition::TransitionRefused,
                "signal_matches_no_predicate".to_owned(),
            ))
        }
        SjsLasObservationKind::Checkpoint => Err(fault(
            SjsLasFaultCode::InvalidObservation,
            "checkpoint is not a transition",
        )),
    }
}

fn validate_request_body(request: &SjsLasRequest) -> Result<(), SjsLasFault> {
    if request.profile != SJS_LAS_REQUEST_PROFILE {
        return Err(fault(
            SjsLasFaultCode::InvalidProfile,
            "request profile differs",
        ));
    }
    if request.canonical_uuid != SJS_LAS_CANONICAL_UUID
        || request.signature_uuid != SJS_LAS_SIGNATURE_UUID
        || request.source_snapshot_uuid != SJS_LAS_SOURCE_UUID
        || request.parent_source_uuid != SJS_LAS_PARENT_SOURCE_UUID
    {
        return Err(fault(
            SjsLasFaultCode::InvalidIdentity,
            "governing identity differs",
        ));
    }
    for (id, label) in [
        (&request.request_id, "request"),
        (&request.run_id, "run"),
        (&request.packet_id, "packet"),
        (&request.policy_id, "policy"),
    ] {
        validate_uuid_id(id, label)?;
    }
    let distinct = [
        &request.request_id,
        &request.run_id,
        &request.packet_id,
        &request.policy_id,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if distinct.len() != 4 {
        return Err(fault(
            SjsLasFaultCode::InvalidIdentity,
            "request identities are not distinct",
        ));
    }
    validate_scope(&request.scope)?;
    if request.stitches.is_empty()
        || request.stitches.len() > MAX_STITCHES
        || !strictly_sorted_by(&request.stitches, |s| &s.stitch_id)
    {
        return Err(fault(
            SjsLasFaultCode::InvalidStitch,
            "stitch bounds or order differ",
        ));
    }
    let stitch_ids = request
        .stitches
        .iter()
        .map(|s| s.stitch_id.clone())
        .collect::<BTreeSet<_>>();
    for stitch in &request.stitches {
        validate_stitch(stitch, &request.scope, &stitch_ids)?;
    }
    validate_observations(&request.observations, &stitch_ids)?;
    validate_coordinates(&request.coordinates, &request.scope, &request.observations)?;
    validate_reference_set(
        &request.evidence_refs,
        1,
        MAX_REFERENCES,
        "evidence references",
    )?;
    if request.non_authority != SJS_LAS_NON_AUTHORITY {
        return Err(fault(
            SjsLasFaultCode::InvalidAuthority,
            "nonauthority differs",
        ));
    }
    let fixed_fixture =
        request.request_id.as_str() == "request:82000000-0000-4000-8000-000000000301";
    if fixed_fixture && request.input_class != SjsLasInputClass::SyntheticProviderFreeFixture {
        return Err(fault(
            SjsLasFaultCode::InvalidInputClass,
            "known synthetic fixture cannot be relabeled",
        ));
    }
    if request.input_class == SjsLasInputClass::SyntheticProviderFreeFixture {
        validate_synthetic_shape(request)?;
    }
    Ok(())
}

fn validate_scope(scope: &SjsLasExactScope) -> Result<(), SjsLasFault> {
    validate_uuid_id(&scope.scope_id, "scope")?;
    validate_reference_set(&scope.source_identities, 1, MAX_REFERENCES, "scope sources")?;
    for (text, label) in [
        (&scope.objective, "objective"),
        (&scope.phase, "phase"),
        (&scope.feature, "feature"),
        (&scope.requirement, "requirement"),
        (&scope.artifact, "artifact"),
        (&scope.model_profile, "model"),
        (&scope.provider_profile, "provider"),
        (&scope.tool_policy, "tool policy"),
        (&scope.authority_ceiling, "authority ceiling"),
    ] {
        validate_text(text, label)?;
    }
    validate_text_set(
        &scope.completion_conditions,
        1,
        MAX_REFERENCES,
        "completion conditions",
    )?;
    validate_text_set(
        &scope.invalidation_conditions,
        1,
        MAX_REFERENCES,
        "invalidation conditions",
    )?;
    validate_predicate(&scope.scope_exit_cue)?;
    if scope.invocation_start == 0 || scope.invocation_start > scope.invocation_end {
        return Err(fault(
            SjsLasFaultCode::InvalidScope,
            "invocation interval differs",
        ));
    }
    validate_digest(&scope.scope_digest, "scope digest")?;
    if sjs_las_scope_digest(scope)? != scope.scope_digest {
        return Err(fault(
            SjsLasFaultCode::InvalidDigest,
            "scope digest differs",
        ));
    }
    Ok(())
}

fn validate_stitch(
    stitch: &SjsLasStitchDeclaration,
    scope: &SjsLasExactScope,
    stitch_ids: &BTreeSet<SemanticId>,
) -> Result<(), SjsLasFault> {
    validate_uuid_id(&stitch.stitch_id, "stitch")?;
    if stitch.scope_id != scope.scope_id {
        return Err(fault(
            SjsLasFaultCode::InvalidStitch,
            "stitch scope differs",
        ));
    }
    if let Some(predecessor) = &stitch.predecessor_id {
        validate_uuid_id(predecessor, "predecessor")?;
        if predecessor == &stitch.stitch_id || !stitch_ids.contains(predecessor) {
            return Err(fault(
                SjsLasFaultCode::InvalidStitch,
                "replacement predecessor differs",
            ));
        }
    }
    validate_text(&stitch.subject_anchor, "subject anchor")?;
    validate_text(&stitch.semantic_turn.description, "semantic turn")?;
    validate_text(&stitch.transform, "transform")?;
    if stitch.key_hints.is_empty()
        || stitch.key_hints.len() > MAX_HINTS
        || !ordered_unique_text(&stitch.key_hints)
    {
        return Err(fault(
            SjsLasFaultCode::InvalidStitch,
            "key hint bounds or uniqueness differ",
        ));
    }
    if stitch.source_bindings.is_empty()
        || stitch.source_bindings.len() > MAX_SOURCES
        || !strictly_sorted_by(&stitch.source_bindings, |b| &b.source_id)
    {
        return Err(fault(
            SjsLasFaultCode::InvalidSource,
            "source binding bounds or order differ",
        ));
    }
    for binding in &stitch.source_bindings {
        validate_uuid_id(&binding.source_id, "source binding")?;
        validate_text(&binding.locator, "source locator")?;
        if !scope.source_identities.contains(&binding.source_id) {
            return Err(fault(
                SjsLasFaultCode::InvalidSource,
                "source binding outside scope",
            ));
        }
        match binding.class {
            SjsLasSourceBindingClass::GoverningAnchor => {
                let authority = binding.authority_identity.as_ref().ok_or_else(|| {
                    fault(
                        SjsLasFaultCode::InvalidSource,
                        "governing source lacks authority identity",
                    )
                })?;
                validate_text(authority, "source authority")?;
            }
            _ if binding.authority_identity.is_some() => {
                return Err(fault(
                    SjsLasFaultCode::InvalidAuthority,
                    "nonauthority source was promoted",
                ));
            }
            _ => {}
        }
    }
    validate_predicate(&stitch.completion_cue)?;
    if stitch.invalidators.is_empty()
        || stitch.invalidators.len() > MAX_INVALIDATORS
        || !strictly_sorted_predicates(&stitch.invalidators)
    {
        return Err(fault(
            SjsLasFaultCode::InvalidStitch,
            "invalidator bounds or order differ",
        ));
    }
    for invalidator in &stitch.invalidators {
        validate_predicate(invalidator)?;
    }
    validate_digest(&stitch.declaration_digest, "stitch digest")?;
    if sjs_las_stitch_digest(stitch)? != stitch.declaration_digest {
        return Err(fault(
            SjsLasFaultCode::InvalidDigest,
            "stitch digest differs",
        ));
    }
    Ok(())
}

fn validate_observations(
    observations: &[SjsLasObservation],
    stitch_ids: &BTreeSet<SemanticId>,
) -> Result<(), SjsLasFault> {
    if observations.is_empty() || observations.len() > MAX_OBSERVATIONS {
        return Err(fault(
            SjsLasFaultCode::InvalidObservation,
            "observation bounds differ",
        ));
    }
    let mut ids = BTreeSet::new();
    for (index, observation) in observations.iter().enumerate() {
        validate_uuid_id(&observation.observation_id, "observation")?;
        if !ids.insert(observation.observation_id.clone())
            || observation.ordinal != count_u32(index + 1)?
        {
            return Err(fault(
                SjsLasFaultCode::InvalidObservation,
                "observation identity or order differs",
            ));
        }
        for (key, value) in &observation.fields {
            validate_text(key, "observation field")?;
            validate_text(value, "observation value")?;
        }
        match observation.kind {
            SjsLasObservationKind::Checkpoint
                if observation.stitch_id.is_some() || observation.fields.is_empty() =>
            {
                return Err(fault(
                    SjsLasFaultCode::InvalidObservation,
                    "checkpoint shape differs",
                ));
            }
            SjsLasObservationKind::Checkpoint => {}
            _ => {
                let target = observation.stitch_id.as_ref().ok_or_else(|| {
                    fault(
                        SjsLasFaultCode::InvalidObservation,
                        "transition target absent",
                    )
                })?;
                if !stitch_ids.contains(target) {
                    return Err(fault(
                        SjsLasFaultCode::InvalidObservation,
                        "transition target unknown",
                    ));
                }
                if observation.kind == SjsLasObservationKind::Activate
                    && !observation.fields.is_empty()
                {
                    return Err(fault(
                        SjsLasFaultCode::InvalidObservation,
                        "activation fields must be empty",
                    ));
                }
                if observation.kind == SjsLasObservationKind::Signal
                    && observation.fields.is_empty()
                {
                    return Err(fault(
                        SjsLasFaultCode::InvalidObservation,
                        "signal fields absent",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_coordinates(
    coordinates: &[SjsLasInvocationCoordinate],
    scope: &SjsLasExactScope,
    observations: &[SjsLasObservation],
) -> Result<(), SjsLasFault> {
    if coordinates.is_empty() || coordinates.len() > MAX_COORDINATES {
        return Err(fault(
            SjsLasFaultCode::InvalidCoordinate,
            "coordinate bounds differ",
        ));
    }
    let mut ids = BTreeSet::new();
    for (index, coordinate) in coordinates.iter().enumerate() {
        validate_uuid_id(&coordinate.coordinate_id, "coordinate")?;
        if !ids.insert(coordinate.coordinate_id.clone())
            || coordinate.ordinal != count_u32(index + 1)?
            || coordinate.after_observation_ordinal == 0
            || usize::try_from(coordinate.after_observation_ordinal)
                .map_err(|_| fault(SjsLasFaultCode::ArithmeticOverflow, "coordinate conversion"))?
                > observations.len()
        {
            return Err(fault(
                SjsLasFaultCode::InvalidCoordinate,
                "coordinate identity order or observation link differs",
            ));
        }
        if coordinate.invocation_ordinal < scope.invocation_start
            || coordinate.invocation_ordinal > scope.invocation_end
            || coordinate.phase != scope.phase
            || coordinate.objective != scope.objective
            || coordinate.feature != scope.feature
            || coordinate.requirement != scope.requirement
            || coordinate.artifact != scope.artifact
            || coordinate.model_profile != scope.model_profile
            || coordinate.provider_profile != scope.provider_profile
            || coordinate.tool_policy != scope.tool_policy
            || coordinate.authority_ceiling != scope.authority_ceiling
        {
            return Err(fault(
                SjsLasFaultCode::InvalidCoordinate,
                "coordinate scope correspondence differs",
            ));
        }
        let latest_transition = observations
            .iter()
            .rev()
            .find(|observation| {
                observation.ordinal <= coordinate.after_observation_ordinal
                    && observation.kind != SjsLasObservationKind::Checkpoint
            })
            .ok_or_else(|| {
                fault(
                    SjsLasFaultCode::InvalidCoordinate,
                    "coordinate precedes every lifecycle receipt",
                )
            })?;
        let expected_receipt = derived_id("receipt", &latest_transition.observation_id)?;
        if coordinate.last_accepted_receipt_id.as_ref() != Some(&expected_receipt) {
            return Err(fault(
                SjsLasFaultCode::InvalidCoordinate,
                "coordinate latest receipt correspondence differs",
            ));
        }
    }
    Ok(())
}

fn validate_synthetic_shape(request: &SjsLasRequest) -> Result<(), SjsLasFault> {
    let hints = request
        .stitches
        .iter()
        .map(|s| s.key_hints.len())
        .sum::<usize>();
    let sources = request
        .stitches
        .iter()
        .map(|s| s.source_bindings.len())
        .sum::<usize>();
    if request.request_id.as_str() != "request:82000000-0000-4000-8000-000000000301"
        || request.run_id.as_str() != "run:82000000-0000-4000-8000-000000000302"
        || request.packet_id.as_str() != "packet:82000000-0000-4000-8000-000000000303"
        || request.policy_id.as_str() != "policy:82000000-0000-4000-8000-000000000304"
        || request.stitches.len() != 2
        || hints != 8
        || sources != 4
        || request.observations.len() != 6
        || request.coordinates.len() != 4
        || (request.request_digest != empty_digest()
            && request.request_digest.value
                != "30bcc700629b7855608d21198bffa6b81ba44001c9c40987696dcbed94efa8d3")
    {
        return Err(fault(
            SjsLasFaultCode::InvalidInputClass,
            "synthetic fixture semantics differ",
        ));
    }
    Ok(())
}

fn verification_for(envelope: &SjsLasEnvelope) -> Result<SjsLasVerification, SjsLasFault> {
    let hint_count = envelope
        .request
        .stitches
        .iter()
        .try_fold(0_usize, |total, s| {
            total
                .checked_add(s.key_hints.len())
                .ok_or_else(|| fault(SjsLasFaultCode::ArithmeticOverflow, "hint count overflow"))
        })?;
    let source_binding_count = envelope
        .request
        .stitches
        .iter()
        .try_fold(0_usize, |total, s| {
            total
                .checked_add(s.source_bindings.len())
                .ok_or_else(|| fault(SjsLasFaultCode::ArithmeticOverflow, "source count overflow"))
        })?;
    let admitted = envelope
        .lifecycle_receipts
        .iter()
        .filter(|r| r.disposition == SjsLasTransitionDisposition::TransitionAdmitted)
        .collect::<Vec<_>>();
    let projected_inclusions =
        envelope
            .projection_records
            .iter()
            .try_fold(0_usize, |total, p| {
                total.checked_add(p.active_stitch_ids.len()).ok_or_else(|| {
                    fault(
                        SjsLasFaultCode::ArithmeticOverflow,
                        "projection count overflow",
                    )
                })
            })?;
    let max_bytes = envelope
        .projection_records
        .iter()
        .map(|p| p.projected_bytes)
        .max()
        .unwrap_or(0);
    let total_bytes = envelope
        .projection_records
        .iter()
        .try_fold(0_u64, |total, p| {
            total.checked_add(p.projected_bytes).ok_or_else(|| {
                fault(
                    SjsLasFaultCode::ArithmeticOverflow,
                    "projection bytes overflow",
                )
            })
        })?;
    let transition_count =
        |state| count_u32(admitted.iter().filter(|r| r.after_state == state).count());
    let boundary_count = |kind| {
        count_u32(
            envelope
                .projection_records
                .iter()
                .filter(|p| p.coordinate.boundary_kind == kind)
                .count(),
        )
    };
    Ok(SjsLasVerification {
        profile: SJS_LAS_VERIFICATION_PROFILE.to_owned(),
        status: "verified_provider_free".to_owned(),
        canonical_uuid: SJS_LAS_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_LAS_SIGNATURE_UUID.to_owned(),
        input_class: envelope.request.input_class,
        authority: envelope.authority,
        request_digest: envelope.request.request_digest.clone(),
        envelope_digest: envelope.envelope_digest.clone(),
        stitch_count: count_u32(envelope.request.stitches.len())?,
        hint_count: count_u32(hint_count)?,
        source_binding_count: count_u32(source_binding_count)?,
        observation_count: count_u32(envelope.request.observations.len())?,
        coordinate_count: count_u32(envelope.request.coordinates.len())?,
        projection_count: count_u32(envelope.projection_records.len())?,
        projected_inclusion_count: count_u32(projected_inclusions)?,
        activation_count: transition_count(SjsLasLifecycleState::Active)?,
        fulfillment_count: transition_count(SjsLasLifecycleState::Fulfilled)?,
        invalidation_count: transition_count(SjsLasLifecycleState::Invalidated)?,
        release_count: transition_count(SjsLasLifecycleState::Released)?,
        refused_transition_count: count_u32(
            envelope
                .lifecycle_receipts
                .iter()
                .filter(|r| r.disposition == SjsLasTransitionDisposition::TransitionRefused)
                .count(),
        )?,
        maximum_projected_bytes: max_bytes,
        total_projected_bytes: total_bytes,
        initial_boundary_count: boundary_count(SjsLasBoundaryKind::Initial)?,
        stop_boundary_count: boundary_count(SjsLasBoundaryKind::ResumeAfterStop)?,
        tool_result_boundary_count: boundary_count(SjsLasBoundaryKind::ResumeAfterToolResult)?,
        reentry_boundary_count: boundary_count(SjsLasBoundaryKind::Reentry)?,
        evidence_reference_count: count_u32(envelope.request.evidence_refs.len())?,
        execution_authorized: false,
        effects: SjsLasEffectAccount::default(),
    })
}

fn evidence_manifest(
    request_file: &str,
    envelope_file: &str,
    verification_file: &str,
    verification: &SjsLasVerification,
) -> Result<SjsLasEvidenceManifest, SjsLasFault> {
    let mut files = BTreeMap::new();
    for (path, body) in [
        (REQUEST_FILE, request_file),
        (ENVELOPE_FILE, envelope_file),
        (VERIFICATION_FILE, verification_file),
    ] {
        files.insert(
            path.to_owned(),
            SjsLasEvidenceFile {
                bytes: count_u64(body.len())?,
                sha256: sha256_bytes(body.as_bytes()),
            },
        );
    }
    Ok(SjsLasEvidenceManifest {
        profile: SJS_LAS_EVIDENCE_PROFILE.to_owned(),
        canonical_uuid: SJS_LAS_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_LAS_SIGNATURE_UUID.to_owned(),
        replay_count: 2,
        files,
        request_digest: verification.request_digest.clone(),
        envelope_digest: verification.envelope_digest.clone(),
        stitch_count: verification.stitch_count,
        hint_count: verification.hint_count,
        source_binding_count: verification.source_binding_count,
        observation_count: verification.observation_count,
        coordinate_count: verification.coordinate_count,
        projected_inclusion_count: verification.projected_inclusion_count,
        activation_count: verification.activation_count,
        fulfillment_count: verification.fulfillment_count,
        invalidation_count: verification.invalidation_count,
        refused_transition_count: verification.refused_transition_count,
        execution_authorized: false,
        effects: SjsLasEffectAccount::default(),
    })
}

fn ensure_bundle_bound(bundle: &SjsLasEvidenceBundle) -> Result<(), SjsLasFault> {
    for (name, value) in [
        (REQUEST_FILE, &bundle.request_file),
        (ENVELOPE_FILE, &bundle.envelope_file),
        (VERIFICATION_FILE, &bundle.verification_file),
        ("manifest.json", &bundle.manifest_file),
    ] {
        if value.len() > SJS_LAS_MAX_EVIDENCE_BYTES
            || !value.ends_with('\n')
            || value[..value.len() - 1].contains('\n')
            || value.contains('\r')
        {
            return Err(fault(
                SjsLasFaultCode::InvalidEvidence,
                format!("{name} framing differs"),
            ));
        }
    }
    let manifest: SjsLasEvidenceManifest =
        parse_bounded(canonical_file_body(&bundle.manifest_file, "manifest.json")?)?;
    for (name, value) in [
        (REQUEST_FILE, &bundle.request_file),
        (ENVELOPE_FILE, &bundle.envelope_file),
        (VERIFICATION_FILE, &bundle.verification_file),
    ] {
        let file = manifest.files.get(name).ok_or_else(|| {
            fault(
                SjsLasFaultCode::InvalidEvidence,
                format!("manifest omits {name}"),
            )
        })?;
        if file.bytes != count_u64(value.len())? || file.sha256 != sha256_bytes(value.as_bytes()) {
            return Err(fault(
                SjsLasFaultCode::InvalidEvidence,
                format!("manifest identity differs for {name}"),
            ));
        }
    }
    Ok(())
}

fn predicate(field: &str, equals: &str) -> SjsLasPredicate {
    SjsLasPredicate {
        field: field.to_owned(),
        equals: equals.to_owned(),
    }
}

fn binding(
    source_id: SemanticId,
    class: SjsLasSourceBindingClass,
    locator: &str,
    authority: Option<&str>,
) -> SjsLasSourceBinding {
    SjsLasSourceBinding {
        source_id,
        class,
        locator: locator.to_owned(),
        authority_identity: authority.map(str::to_owned),
    }
}

fn observation(
    ordinal: u32,
    uuid: &str,
    kind: SjsLasObservationKind,
    stitch_id: Option<SemanticId>,
    fields: &[(&str, &str)],
) -> SjsLasObservation {
    SjsLasObservation {
        observation_id: semantic_id(format!("observation:{uuid}"))
            .expect("fixed observation identity"),
        ordinal,
        kind,
        stitch_id,
        fields: fields
            .iter()
            .map(|(k, v)| (String::from(*k), String::from(*v)))
            .collect(),
    }
}

fn predicate_matches(predicate: &SjsLasPredicate, fields: &BTreeMap<String, String>) -> bool {
    fields
        .get(&predicate.field)
        .is_some_and(|value| value == &predicate.equals)
}

fn validate_predicate(predicate: &SjsLasPredicate) -> Result<(), SjsLasFault> {
    validate_text(&predicate.field, "predicate field")?;
    validate_text(&predicate.equals, "predicate value")
}

fn derived_id(prefix: &str, source: &SemanticId) -> Result<SemanticId, SjsLasFault> {
    let suffix = source
        .as_str()
        .rsplit(':')
        .next()
        .ok_or_else(|| fault(SjsLasFaultCode::InvalidIdentity, "identity suffix absent"))?;
    semantic_id(format!("{prefix}:{suffix}"))
}

fn strictly_sorted_by<T, K: Ord>(values: &[T], key: impl Fn(&T) -> &K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}
fn strictly_sorted_predicates(values: &[SjsLasPredicate]) -> bool {
    values
        .windows(2)
        .all(|p| (&p[0].field, &p[0].equals) < (&p[1].field, &p[1].equals))
}
fn ordered_unique_text(values: &[String]) -> bool {
    values.iter().all(|v| valid_text(v) && v.trim() == v)
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn validate_reference_set(
    values: &BTreeSet<SemanticId>,
    min: usize,
    max: usize,
    label: &str,
) -> Result<(), SjsLasFault> {
    if values.len() < min || values.len() > max {
        return Err(fault(
            SjsLasFaultCode::InvalidBound,
            format!("{label} bounds differ"),
        ));
    }
    for value in values {
        validate_uuid_id(value, label)?;
    }
    Ok(())
}

fn validate_text_set(
    values: &BTreeSet<String>,
    min: usize,
    max: usize,
    label: &str,
) -> Result<(), SjsLasFault> {
    if values.len() < min || values.len() > max {
        return Err(fault(
            SjsLasFaultCode::InvalidBound,
            format!("{label} bounds differ"),
        ));
    }
    for value in values {
        validate_text(value, label)?;
    }
    Ok(())
}

fn validate_uuid_id(id: &SemanticId, label: &str) -> Result<(), SjsLasFault> {
    let value = id.as_str();
    let suffix = value.rsplit(':').next().unwrap_or_default();
    let bytes = suffix.as_bytes();
    let valid = bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *b == b'-'
            } else {
                b.is_ascii_digit() || matches!(b, b'a'..=b'f')
            }
        })
        && suffix != "00000000-0000-0000-0000-000000000000";
    if !valid {
        return Err(fault(
            SjsLasFaultCode::InvalidIdentity,
            format!("{label} is not a lowercase nonnil UUID-bearing identity"),
        ));
    }
    Ok(())
}

fn validate_text(value: &str, label: &str) -> Result<(), SjsLasFault> {
    if !valid_text(value) || value.trim() != value {
        return Err(fault(
            SjsLasFaultCode::InvalidText,
            format!("{label} differs"),
        ));
    }
    Ok(())
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && value.chars().all(|c| !c.is_control() && c != '\u{7f}')
}

fn validate_digest(digest: &ContentDigest, label: &str) -> Result<(), SjsLasFault> {
    if digest.algorithm != "sha256"
        || digest.value.len() != 64
        || !digest
            .value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    {
        return Err(fault(
            SjsLasFaultCode::InvalidDigest,
            format!("{label} differs"),
        ));
    }
    Ok(())
}

fn semantic_id(value: impl Into<String>) -> Result<SemanticId, SjsLasFault> {
    SemanticId::new(value).map_err(|e| fault(SjsLasFaultCode::InvalidIdentity, e.to_string()))
}
fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}
fn count_u32(value: usize) -> Result<u32, SjsLasFault> {
    u32::try_from(value).map_err(|_| {
        fault(
            SjsLasFaultCode::ArithmeticOverflow,
            "usize to u32 conversion failed",
        )
    })
}
fn count_u64(value: usize) -> Result<u64, SjsLasFault> {
    u64::try_from(value).map_err(|_| {
        fault(
            SjsLasFaultCode::ArithmeticOverflow,
            "usize to u64 conversion failed",
        )
    })
}

fn sha256_form<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, SjsLasFault> {
    let body = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + body.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&body);
    Ok(sha256_bytes(&bytes))
}
fn to_machine_form<T: Serialize>(value: &T) -> Result<String, SjsLasFault> {
    serde_json::to_string(value).map_err(machine_fault)
}
fn canonical_file(value: String) -> String {
    format!("{value}\n")
}
fn canonical_file_body<'a>(value: &'a str, label: &str) -> Result<&'a str, SjsLasFault> {
    value.strip_suffix('\n').ok_or_else(|| {
        fault(
            SjsLasFaultCode::InvalidEvidence,
            format!("{label} lacks one LF"),
        )
    })
}

fn parse_bounded<T: DeserializeOwned + Serialize>(value: &str) -> Result<T, SjsLasFault> {
    parse_bounded_with_limit(value, SJS_LAS_MAX_MACHINE_FORM_BYTES)
}
fn parse_bounded_with_limit<T: DeserializeOwned + Serialize>(
    value: &str,
    limit: usize,
) -> Result<T, SjsLasFault> {
    if value.len() > limit {
        return Err(fault(
            SjsLasFaultCode::InvalidBound,
            format!("machine form exceeds {limit} bytes"),
        ));
    }
    let mut duplicate_check = serde_json::Deserializer::from_str(value);
    NoDuplicateJson::deserialize(&mut duplicate_check).map_err(machine_fault)?;
    duplicate_check.end().map_err(machine_fault)?;
    let shape: Value = serde_json::from_str(value).map_err(machine_fault)?;
    let mut fields = 0;
    validate_json_shape(&shape, 1, &mut fields, None)?;
    let parsed: T = serde_json::from_str(value).map_err(machine_fault)?;
    if to_machine_form(&parsed)? != value {
        return Err(fault(
            SjsLasFaultCode::InvalidMachineForm,
            "machine form is not canonical compact JSON",
        ));
    }
    Ok(parsed)
}

struct NoDuplicateJson;
impl<'de> Deserialize<'de> for NoDuplicateJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NoDuplicateJsonVisitor)?;
        Ok(Self)
    }
}
struct NoDuplicateJsonVisitor;
impl<'de> Visitor<'de> for NoDuplicateJsonVisitor {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("strict JSON without duplicate keys")
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_string<E>(self, _: String) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element::<NoDuplicateJson>()?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate JSON object key {key:?}"
                )));
            }
            map.next_value::<NoDuplicateJson>()?;
        }
        Ok(())
    }
}

fn validate_json_shape(
    value: &Value,
    depth: usize,
    fields: &mut usize,
    parent_key: Option<&str>,
) -> Result<(), SjsLasFault> {
    if depth > MAX_DEPTH {
        return Err(fault(
            SjsLasFaultCode::InvalidMachineForm,
            "machine form exceeds depth 40",
        ));
    }
    match value {
        Value::Object(map) => {
            *fields = fields.checked_add(map.len()).ok_or_else(|| {
                fault(SjsLasFaultCode::ArithmeticOverflow, "field count overflow")
            })?;
            if *fields > MAX_FIELDS {
                return Err(fault(
                    SjsLasFaultCode::InvalidMachineForm,
                    "machine form exceeds 16384 fields",
                ));
            }
            for (k, v) in map {
                if !valid_text(k) {
                    return Err(fault(
                        SjsLasFaultCode::InvalidMachineForm,
                        "field text differs",
                    ));
                }
                validate_json_shape(v, depth + 1, fields, Some(k))?;
            }
        }
        Value::Array(items) => {
            for item in items {
                validate_json_shape(item, depth + 1, fields, None)?
            }
        }
        Value::String(text) => {
            let file_body = matches!(
                parent_key,
                Some("request_file" | "envelope_file" | "verification_file" | "manifest_file")
            );
            if (!file_body && !valid_text(text))
                || (file_body && text.len() > SJS_LAS_MAX_EVIDENCE_BYTES)
            {
                return Err(fault(
                    SjsLasFaultCode::InvalidMachineForm,
                    "machine text differs",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn machine_fault(error: impl fmt::Display) -> SjsLasFault {
    fault(SjsLasFaultCode::InvalidMachineForm, error.to_string())
}
fn fault(code: SjsLasFaultCode, detail: impl Into<String>) -> SjsLasFault {
    SjsLasFault {
        code,
        detail: detail.into(),
    }
}
