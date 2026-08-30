//! Pure provider-free compilation for the SJS Minimum Recoverable Frame P0.
//!
//! Exact supplied scope, hint, frame, recovery-source, and policy values are
//! reduced only through deterministic restoration tests. This module performs
//! no filesystem, environment, clock, process, network, provider, model,
//! inference, MCP, Git, workspace, secret, permission, activation, remote,
//! hardware, or external action.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ContentDigest, SemanticId, sha256_bytes};

pub const SJS_MRF_REQUEST_PROFILE: &str = "cantor-sjs-minimum-recoverable-frame-request/0.1";
pub const SJS_MRF_ENVELOPE_PROFILE: &str = "cantor-sjs-minimum-recoverable-frame-envelope/0.1";
pub const SJS_MRF_VERIFICATION_PROFILE: &str =
    "cantor-sjs-minimum-recoverable-frame-verification/0.1";
pub const SJS_MRF_EVIDENCE_PROFILE: &str = "cantor-sjs-minimum-recoverable-frame-evidence/0.1";
pub const SJS_MRF_CANONICAL_UUID: &str = "3fd17e47-0277-4856-85be-ac275690aa56";
pub const SJS_MRF_SIGNATURE_UUID: &str = "5b367535-6a6d-47bf-abb3-356884a737ab";
pub const SJS_MRF_SOURCE_SNAPSHOT_UUID: &str = "93fca9d7-12d5-4e50-849d-867b0b92be03";
pub const SJS_MRF_PARENT_SOURCE_UUID: &str = "a31d4fcd-3d56-4f88-875e-4bcb0ff244e9";
pub const SJS_MRF_SUBSTRATE_AUDIT_UUID: &str = "b556eade-b240-477d-8a10-cac53c3c3ce2";
pub const SJS_MRF_NON_AUTHORITY: &str = "Supplied-data restoration testing only. A compiled basis, witness, digest, public narrative event, or local-irreducibility disposition grants no hidden-state access, semantic-confidence authority, prompt mutation, provider or model use, performance truth, destructive forgetting, durable custody, autonomous continuation, successor-SOP admission, host state, remote state, hardware state, or external-effect authority.";
pub const SJS_MRF_MAX_MACHINE_FORM_BYTES: usize = 2_097_152;
pub const SJS_MRF_MAX_EVIDENCE_BYTES: usize = 8_388_608;

const MAX_DEPTH: usize = 48;
const MAX_FIELDS: usize = 32_768;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_JOBS: usize = 32;
const MAX_HINTS: usize = 64;
const MAX_RECOVERY_SOURCES: usize = 16;
const MAX_REFERENCES: usize = 64;
const MAX_SET_MEMBERS: usize = 128;
const MAX_RECEIPTS: usize = 64;
const MAX_GROUP_SIZE: u8 = 4;
const MAX_PASS_BUDGET: u16 = 256;
const REQUEST_FILE: &str = "request.json";
const ENVELOPE_FILE: &str = "envelope.json";
const VERIFICATION_FILE: &str = "verification.json";

const SCOPE_DOMAIN: &str = "cantor.sjs-mrf.scope.v1";
const FRAME_DOMAIN: &str = "cantor.sjs-mrf.frame.v1";
const HINT_DOMAIN: &str = "cantor.sjs-mrf.hint.v1";
const COVENANT_DOMAIN: &str = "cantor.sjs-mrf.covenant.v1";
const RECOVERY_SOURCE_DOMAIN: &str = "cantor.sjs-mrf.recovery-source.v1";
const POLICY_DOMAIN: &str = "cantor.sjs-mrf.policy.v1";
const REQUEST_DOMAIN: &str = "cantor.sjs-mrf.request.v1";
const BASIS_ID_DOMAIN: &str = "cantor.sjs-mrf.basis-id.v1";
const WITNESS_ID_DOMAIN: &str = "cantor.sjs-mrf.witness-id.v1";
const WITNESS_DOMAIN: &str = "cantor.sjs-mrf.witness.v1";
const ENVELOPE_DOMAIN: &str = "cantor.sjs-mrf.envelope.v1";

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsMrfInputClass {
    SyntheticProviderFreeFixture,
    SuppliedUnobservedDeclaration,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsMrfHintClass {
    MandatoryGoverningAnchor,
    MandatoryDenial,
    MandatoryOpenObligation,
    StableRelation,
    RecoverableCoordinate,
    OptionalTrajectoryCue,
    ExpiredItem,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsMrfRecoverySourceKind {
    ExactCheckpoint,
    ExactEventLedger,
    ExactSourceArtifact,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsMrfComparisonOutcome {
    Anchored,
    Drifted,
    Underdetermined,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsMrfWitnessDisposition {
    ReleaseAdmitted,
    ReleaseRefusedDrifted,
    ReleaseRefusedUnderdetermined,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsMrfCandidateStrategy {
    LexicographicSingleThenGrouped,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsMrfCompilationDisposition {
    LocallyIrreducible,
    BoundedPassBudgetExhausted,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsMrfLifecycle {
    RestorationTestedBasisCompiledProviderFree,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsMrfAuthority {
    SuppliedDataRestorationTestingOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsMrfJustificationScope {
    pub scope_id: SemanticId,
    pub source_identities: BTreeSet<SemanticId>,
    pub subject: String,
    pub purpose: String,
    pub job_ids: BTreeSet<SemanticId>,
    pub turn_start: u64,
    pub turn_end: u64,
    pub model_profile: String,
    pub provider_profile: String,
    pub tool_policy: String,
    pub authority_ceiling: String,
    pub completion_conditions: BTreeSet<String>,
    pub invalidation_conditions: BTreeSet<String>,
    pub scope_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsMrfOperativeFrame {
    pub frame_id: SemanticId,
    pub scope_id: SemanticId,
    pub source_identities: BTreeSet<SemanticId>,
    pub authority_identity: String,
    pub policy_identity: SemanticId,
    pub model_profile: String,
    pub provider_profile: String,
    pub tool_policy: String,
    pub job_ids: BTreeSet<SemanticId>,
    pub latest_receipt_ids: BTreeSet<SemanticId>,
    pub checkpoint_ids: BTreeSet<SemanticId>,
    pub constraints: BTreeSet<String>,
    pub denials: BTreeSet<String>,
    pub open_requirements: BTreeSet<String>,
    pub dependencies: BTreeSet<String>,
    pub evidence_obligations: BTreeSet<String>,
    pub unresolved_frontier: BTreeSet<String>,
    pub stop_conditions: BTreeSet<String>,
    pub subject: String,
    pub purpose: String,
    pub intended_transform: String,
    pub frame_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsMrfHint {
    pub hint_id: SemanticId,
    pub scope_id: SemanticId,
    pub class: SjsMrfHintClass,
    pub term: String,
    pub intended_transform: String,
    pub applicability: String,
    pub completion: String,
    pub invalidation: String,
    pub restoration_role: String,
    pub source_refs: BTreeSet<SemanticId>,
    pub recovery_source_ids: BTreeSet<SemanticId>,
    pub release_eligible: bool,
    pub retention_floor: u8,
    pub hint_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsMrfHintCovenant {
    pub covenant_id: SemanticId,
    pub scope_id: SemanticId,
    pub job_ids: BTreeSet<SemanticId>,
    pub hints: Vec<SjsMrfHint>,
    pub covenant_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsMrfRecoverySource {
    pub source_id: SemanticId,
    pub kind: SjsMrfRecoverySourceKind,
    pub route_hint_ids: BTreeSet<SemanticId>,
    pub frame: SjsMrfOperativeFrame,
    pub source_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsMrfCandidatePolicy {
    pub policy_id: SemanticId,
    pub strategy: SjsMrfCandidateStrategy,
    pub max_group_size: u8,
    pub pass_budget: u16,
    pub monotone_zero_source_pruning: bool,
    pub policy_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsMrfRequest {
    pub profile: String,
    pub request_id: SemanticId,
    pub run_id: SemanticId,
    pub input_class: SjsMrfInputClass,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_snapshot_uuid: String,
    pub parent_source_uuid: String,
    pub substrate_audit_uuid: String,
    pub scope: SjsMrfJustificationScope,
    pub covenant: SjsMrfHintCovenant,
    pub operative_frame: SjsMrfOperativeFrame,
    pub recovery_sources: Vec<SjsMrfRecoverySource>,
    pub initial_basis: Vec<SemanticId>,
    pub policy: SjsMrfCandidatePolicy,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub non_authority: String,
    pub request_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsMrfRestorationWitness {
    pub ordinal: u32,
    pub witness_id: SemanticId,
    pub before_basis_id: SemanticId,
    pub candidate_basis_id: SemanticId,
    pub released_hint_ids: Vec<SemanticId>,
    pub reachable_source_ids: Vec<SemanticId>,
    pub reconstructed_frame_digest: Option<ContentDigest>,
    pub outcome: SjsMrfComparisonOutcome,
    pub disposition: SjsMrfWitnessDisposition,
    pub reason: String,
    pub before_hint_count: u32,
    pub candidate_hint_count: u32,
    pub before_canonical_bytes: u64,
    pub candidate_canonical_bytes: u64,
    pub witness_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsMrfNarrativeEvent {
    pub ordinal: u32,
    pub witness_id: SemanticId,
    pub statement: String,
    pub authority_asserted: bool,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsMrfEffectAccount {
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
pub struct SjsMrfEnvelope {
    pub profile: String,
    pub request: SjsMrfRequest,
    pub lifecycle: SjsMrfLifecycle,
    pub authority: SjsMrfAuthority,
    pub initial_basis_id: SemanticId,
    pub final_basis_id: SemanticId,
    pub final_basis: Vec<SemanticId>,
    pub witnesses: Vec<SjsMrfRestorationWitness>,
    pub narrative_projection: Vec<SjsMrfNarrativeEvent>,
    pub disposition: SjsMrfCompilationDisposition,
    pub locally_irreducible: bool,
    pub pass_budget_exhausted: bool,
    pub execution_authorized: bool,
    pub effects: SjsMrfEffectAccount,
    pub envelope_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsMrfVerification {
    pub profile: String,
    pub status: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub input_class: SjsMrfInputClass,
    pub authority: SjsMrfAuthority,
    pub request_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
    pub job_count: u32,
    pub hint_count: u32,
    pub mandatory_hint_count: u32,
    pub recovery_source_count: u32,
    pub initial_basis_count: u32,
    pub final_basis_count: u32,
    pub attempt_count: u32,
    pub admitted_release_count: u32,
    pub drift_refusal_count: u32,
    pub underdetermined_refusal_count: u32,
    pub narrative_event_count: u32,
    pub evidence_reference_count: u32,
    pub locally_irreducible: bool,
    pub pass_budget_exhausted: bool,
    pub execution_authorized: bool,
    pub effects: SjsMrfEffectAccount,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsMrfEvidenceFile {
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsMrfEvidenceManifest {
    pub profile: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub replay_count: u32,
    pub files: BTreeMap<String, SjsMrfEvidenceFile>,
    pub request_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
    pub job_count: u32,
    pub hint_count: u32,
    pub recovery_source_count: u32,
    pub attempt_count: u32,
    pub admitted_release_count: u32,
    pub drift_refusal_count: u32,
    pub underdetermined_refusal_count: u32,
    pub final_basis_count: u32,
    pub locally_irreducible: bool,
    pub pass_budget_exhausted: bool,
    pub execution_authorized: bool,
    pub effects: SjsMrfEffectAccount,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsMrfEvidenceBundle {
    pub request_file: String,
    pub envelope_file: String,
    pub verification_file: String,
    pub manifest_file: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SjsMrfFaultCode {
    InvalidProfile,
    InvalidInputClass,
    InvalidIdentity,
    InvalidText,
    InvalidDigest,
    InvalidBound,
    InvalidScope,
    InvalidFrame,
    InvalidHint,
    InvalidRecovery,
    InvalidBasis,
    InvalidPolicy,
    InvalidWitness,
    InvalidMinimum,
    InvalidAuthority,
    InvalidVerification,
    InvalidEvidence,
    InvalidMachineForm,
    ArithmeticOverflow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SjsMrfFault {
    pub code: SjsMrfFaultCode,
    pub detail: String,
}

impl fmt::Display for SjsMrfFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}

impl std::error::Error for SjsMrfFault {}

pub fn seal_sjs_mrf_request(mut request: SjsMrfRequest) -> Result<SjsMrfRequest, SjsMrfFault> {
    request.scope.scope_digest = empty_digest();
    request.scope.scope_digest = sjs_mrf_scope_digest(&request.scope)?;
    request.operative_frame.frame_digest = empty_digest();
    request.operative_frame.frame_digest = sjs_mrf_frame_digest(&request.operative_frame)?;
    for hint in &mut request.covenant.hints {
        hint.hint_digest = empty_digest();
        hint.hint_digest = sjs_mrf_hint_digest(hint)?;
    }
    request.covenant.covenant_digest = empty_digest();
    request.covenant.covenant_digest = sjs_mrf_covenant_digest(&request.covenant)?;
    for source in &mut request.recovery_sources {
        source.frame.frame_digest = empty_digest();
        source.frame.frame_digest = sjs_mrf_frame_digest(&source.frame)?;
        source.source_digest = empty_digest();
        source.source_digest = sjs_mrf_recovery_source_digest(source)?;
    }
    request.policy.policy_digest = empty_digest();
    request.policy.policy_digest = sjs_mrf_policy_digest(&request.policy)?;
    request.request_digest = empty_digest();
    validate_request_body(&request)?;
    request.request_digest = sjs_mrf_request_digest(&request)?;
    validate_sjs_mrf_request(&request)?;
    Ok(request)
}

pub fn validate_sjs_mrf_request(request: &SjsMrfRequest) -> Result<(), SjsMrfFault> {
    validate_request_body(request)?;
    if sjs_mrf_request_digest(request)? != request.request_digest {
        return Err(fault(
            SjsMrfFaultCode::InvalidDigest,
            "request digest differs",
        ));
    }
    Ok(())
}

pub fn compile_sjs_mrf(request: &SjsMrfRequest) -> Result<SjsMrfEnvelope, SjsMrfFault> {
    validate_sjs_mrf_request(request)?;
    let derived = derive_compilation(request)?;
    let mut envelope = SjsMrfEnvelope {
        profile: SJS_MRF_ENVELOPE_PROFILE.to_owned(),
        request: request.clone(),
        lifecycle: SjsMrfLifecycle::RestorationTestedBasisCompiledProviderFree,
        authority: SjsMrfAuthority::SuppliedDataRestorationTestingOnly,
        initial_basis_id: basis_id(&request.run_id, &request.initial_basis)?,
        final_basis_id: basis_id(&request.run_id, &derived.final_basis)?,
        final_basis: derived.final_basis,
        witnesses: derived.witnesses,
        narrative_projection: derived.narrative,
        disposition: derived.disposition,
        locally_irreducible: derived.locally_irreducible,
        pass_budget_exhausted: derived.pass_budget_exhausted,
        execution_authorized: false,
        effects: SjsMrfEffectAccount::default(),
        envelope_digest: empty_digest(),
    };
    envelope.envelope_digest = sjs_mrf_envelope_digest(&envelope)?;
    validate_sjs_mrf_envelope(&envelope)?;
    Ok(envelope)
}

pub fn validate_sjs_mrf_envelope(envelope: &SjsMrfEnvelope) -> Result<(), SjsMrfFault> {
    validate_sjs_mrf_request(&envelope.request)?;
    if envelope.profile != SJS_MRF_ENVELOPE_PROFILE
        || envelope.lifecycle != SjsMrfLifecycle::RestorationTestedBasisCompiledProviderFree
        || envelope.authority != SjsMrfAuthority::SuppliedDataRestorationTestingOnly
        || envelope.execution_authorized
        || envelope.effects != SjsMrfEffectAccount::default()
    {
        return Err(fault(
            SjsMrfFaultCode::InvalidAuthority,
            "envelope profile lifecycle authority or effects differ",
        ));
    }
    let derived = derive_compilation(&envelope.request)?;
    let expected_initial = basis_id(&envelope.request.run_id, &envelope.request.initial_basis)?;
    let expected_final = basis_id(&envelope.request.run_id, &derived.final_basis)?;
    if envelope.initial_basis_id != expected_initial
        || envelope.final_basis_id != expected_final
        || envelope.final_basis != derived.final_basis
        || envelope.witnesses != derived.witnesses
        || envelope.narrative_projection != derived.narrative
        || envelope.disposition != derived.disposition
        || envelope.locally_irreducible != derived.locally_irreducible
        || envelope.pass_budget_exhausted != derived.pass_budget_exhausted
    {
        return Err(fault(
            SjsMrfFaultCode::InvalidWitness,
            "envelope differs from deterministic compilation",
        ));
    }
    if sjs_mrf_envelope_digest(envelope)? != envelope.envelope_digest {
        return Err(fault(
            SjsMrfFaultCode::InvalidDigest,
            "envelope digest differs",
        ));
    }
    Ok(())
}

pub fn verify_sjs_mrf(envelope: &SjsMrfEnvelope) -> Result<SjsMrfVerification, SjsMrfFault> {
    validate_sjs_mrf_envelope(envelope)?;
    verification_for(envelope)
}

pub fn build_sjs_mrf_evidence_bundle(
    request: &SjsMrfRequest,
) -> Result<SjsMrfEvidenceBundle, SjsMrfFault> {
    validate_sjs_mrf_request(request)?;
    let first = compile_sjs_mrf(request)?;
    let second = compile_sjs_mrf(request)?;
    if first != second {
        return Err(fault(
            SjsMrfFaultCode::InvalidEvidence,
            "double compilation differs",
        ));
    }
    let first_verification = verify_sjs_mrf(&first)?;
    let second_verification = verify_sjs_mrf(&second)?;
    if first_verification != second_verification {
        return Err(fault(
            SjsMrfFaultCode::InvalidEvidence,
            "double verification differs",
        ));
    }
    let request_file = canonical_file(to_sjs_mrf_request_machine_form(request)?);
    let envelope_file = canonical_file(to_sjs_mrf_envelope_machine_form(&first)?);
    let verification_file =
        canonical_file(to_sjs_mrf_verification_machine_form(&first_verification)?);
    let manifest = evidence_manifest(
        &request_file,
        &envelope_file,
        &verification_file,
        &first_verification,
    )?;
    let manifest_file = canonical_file(to_machine_form(&manifest)?);
    let bundle = SjsMrfEvidenceBundle {
        request_file,
        envelope_file,
        verification_file,
        manifest_file,
    };
    ensure_bundle_bound(&bundle)?;
    Ok(bundle)
}

pub fn verify_sjs_mrf_evidence_bundle(
    bundle: &SjsMrfEvidenceBundle,
) -> Result<SjsMrfVerification, SjsMrfFault> {
    ensure_bundle_bound(bundle)?;
    let request_body = canonical_file_body(&bundle.request_file, REQUEST_FILE)?;
    let envelope_body = canonical_file_body(&bundle.envelope_file, ENVELOPE_FILE)?;
    let verification_body = canonical_file_body(&bundle.verification_file, VERIFICATION_FILE)?;
    let manifest_body = canonical_file_body(&bundle.manifest_file, "manifest.json")?;
    let request = from_sjs_mrf_request_machine_form(request_body)?;
    let retained_envelope = from_sjs_mrf_envelope_machine_form(envelope_body)?;
    let retained_verification: SjsMrfVerification = parse_bounded(verification_body)?;
    let retained_manifest: SjsMrfEvidenceManifest = parse_bounded(manifest_body)?;
    let first = compile_sjs_mrf(&request)?;
    let second = compile_sjs_mrf(&request)?;
    if first != second || first != retained_envelope {
        return Err(fault(
            SjsMrfFaultCode::InvalidEvidence,
            "retained envelope differs from independent double compilation",
        ));
    }
    let verification = verify_sjs_mrf(&first)?;
    if verification != retained_verification {
        return Err(fault(
            SjsMrfFaultCode::InvalidEvidence,
            "retained verification differs",
        ));
    }
    let expected_manifest = evidence_manifest(
        &bundle.request_file,
        &bundle.envelope_file,
        &bundle.verification_file,
        &verification,
    )?;
    if retained_manifest != expected_manifest {
        return Err(fault(
            SjsMrfFaultCode::InvalidEvidence,
            "retained manifest differs",
        ));
    }
    Ok(verification)
}

pub fn to_sjs_mrf_request_machine_form(request: &SjsMrfRequest) -> Result<String, SjsMrfFault> {
    validate_sjs_mrf_request(request)?;
    to_machine_form(request)
}

pub fn from_sjs_mrf_request_machine_form(value: &str) -> Result<SjsMrfRequest, SjsMrfFault> {
    let request: SjsMrfRequest = parse_bounded(value)?;
    validate_sjs_mrf_request(&request)?;
    Ok(request)
}

pub fn to_sjs_mrf_envelope_machine_form(envelope: &SjsMrfEnvelope) -> Result<String, SjsMrfFault> {
    validate_sjs_mrf_envelope(envelope)?;
    to_machine_form(envelope)
}

pub fn from_sjs_mrf_envelope_machine_form(value: &str) -> Result<SjsMrfEnvelope, SjsMrfFault> {
    let envelope: SjsMrfEnvelope = parse_bounded(value)?;
    validate_sjs_mrf_envelope(&envelope)?;
    Ok(envelope)
}

pub fn to_sjs_mrf_verification_machine_form(
    verification: &SjsMrfVerification,
) -> Result<String, SjsMrfFault> {
    to_machine_form(verification)
}

pub fn to_sjs_mrf_evidence_bundle_machine_form(
    bundle: &SjsMrfEvidenceBundle,
) -> Result<String, SjsMrfFault> {
    ensure_bundle_bound(bundle)?;
    to_machine_form(bundle)
}

pub fn from_sjs_mrf_evidence_bundle_machine_form(
    value: &str,
) -> Result<SjsMrfEvidenceBundle, SjsMrfFault> {
    let bundle: SjsMrfEvidenceBundle = parse_bounded_with_limit(value, SJS_MRF_MAX_EVIDENCE_BYTES)?;
    ensure_bundle_bound(&bundle)?;
    Ok(bundle)
}

pub fn sjs_mrf_scope_digest(
    value: &SjsMrfJustificationScope,
) -> Result<ContentDigest, SjsMrfFault> {
    let mut body = value.clone();
    body.scope_digest = empty_digest();
    sha256_form(SCOPE_DOMAIN, &body)
}

pub fn sjs_mrf_frame_digest(value: &SjsMrfOperativeFrame) -> Result<ContentDigest, SjsMrfFault> {
    let mut body = value.clone();
    body.frame_digest = empty_digest();
    sha256_form(FRAME_DOMAIN, &body)
}

pub fn sjs_mrf_hint_digest(value: &SjsMrfHint) -> Result<ContentDigest, SjsMrfFault> {
    let mut body = value.clone();
    body.hint_digest = empty_digest();
    sha256_form(HINT_DOMAIN, &body)
}

pub fn sjs_mrf_covenant_digest(value: &SjsMrfHintCovenant) -> Result<ContentDigest, SjsMrfFault> {
    let mut body = value.clone();
    body.covenant_digest = empty_digest();
    sha256_form(COVENANT_DOMAIN, &body)
}

pub fn sjs_mrf_recovery_source_digest(
    value: &SjsMrfRecoverySource,
) -> Result<ContentDigest, SjsMrfFault> {
    let mut body = value.clone();
    body.source_digest = empty_digest();
    sha256_form(RECOVERY_SOURCE_DOMAIN, &body)
}

pub fn sjs_mrf_policy_digest(value: &SjsMrfCandidatePolicy) -> Result<ContentDigest, SjsMrfFault> {
    let mut body = value.clone();
    body.policy_digest = empty_digest();
    sha256_form(POLICY_DOMAIN, &body)
}

pub fn sjs_mrf_request_digest(value: &SjsMrfRequest) -> Result<ContentDigest, SjsMrfFault> {
    let mut body = value.clone();
    body.request_digest = empty_digest();
    sha256_form(REQUEST_DOMAIN, &body)
}

pub fn sjs_mrf_witness_digest(
    value: &SjsMrfRestorationWitness,
) -> Result<ContentDigest, SjsMrfFault> {
    let mut body = value.clone();
    body.witness_digest = empty_digest();
    sha256_form(WITNESS_DOMAIN, &body)
}

pub fn sjs_mrf_envelope_digest(value: &SjsMrfEnvelope) -> Result<ContentDigest, SjsMrfFault> {
    let mut body = value.clone();
    body.envelope_digest = empty_digest();
    sha256_form(ENVELOPE_DOMAIN, &body)
}

pub fn synthetic_sjs_mrf_request() -> Result<SjsMrfRequest, SjsMrfFault> {
    let scope_id = semantic_id("scope:81000000-0000-4000-8000-000000000001")?;
    let policy_id = semantic_id("policy:81000000-0000-4000-8000-000000000002")?;
    let job_a = semantic_id("job:81000000-0000-4000-8000-000000000003")?;
    let job_b = semantic_id("job:81000000-0000-4000-8000-000000000004")?;
    let source_identity = semantic_id("source:81000000-0000-4000-8000-000000000005")?;
    let scope = SjsMrfJustificationScope {
        scope_id: scope_id.clone(),
        source_identities: [source_identity.clone()].into_iter().collect(),
        subject: "compiled minimum recoverable frame".to_owned(),
        purpose: "retain the exact governed work frame across interdependent jobs".to_owned(),
        job_ids: [job_a.clone(), job_b.clone()].into_iter().collect(),
        turn_start: 1,
        turn_end: 8,
        model_profile: "declared-model/provider-free-fixture".to_owned(),
        provider_profile: "declared-provider/provider-free-fixture".to_owned(),
        tool_policy: "declared-tool-policy/read-only-fixture".to_owned(),
        authority_ceiling: "supplied_data_restoration_testing_only".to_owned(),
        completion_conditions: ["locally irreducible or bounded budget exhausted".to_owned()]
            .into_iter()
            .collect(),
        invalidation_conditions: [
            "scope source authority policy model provider tool job receipt or checkpoint drift"
                .to_owned(),
        ]
        .into_iter()
        .collect(),
        scope_digest: empty_digest(),
    };
    let frame_id = semantic_id("frame:81000000-0000-4000-8000-000000000006")?;
    let checkpoint_id = semantic_id("checkpoint:81000000-0000-4000-8000-000000000007")?;
    let receipt_id = semantic_id("receipt:81000000-0000-4000-8000-000000000008")?;
    let baseline = SjsMrfOperativeFrame {
        frame_id,
        scope_id: scope_id.clone(),
        source_identities: [source_identity].into_iter().collect(),
        authority_identity: "supplied_data_restoration_testing_only".to_owned(),
        policy_identity: policy_id.clone(),
        model_profile: scope.model_profile.clone(),
        provider_profile: scope.provider_profile.clone(),
        tool_policy: scope.tool_policy.clone(),
        job_ids: [job_a.clone(), job_b.clone()].into_iter().collect(),
        latest_receipt_ids: [receipt_id].into_iter().collect(),
        checkpoint_ids: [checkpoint_id].into_iter().collect(),
        constraints: ["exact supplied comparison".to_owned()]
            .into_iter()
            .collect(),
        denials: ["no provider or effect".to_owned()].into_iter().collect(),
        open_requirements: ["publish provider-free proof".to_owned()]
            .into_iter()
            .collect(),
        dependencies: ["formation remote equal".to_owned()].into_iter().collect(),
        evidence_obligations: ["independent replay".to_owned()].into_iter().collect(),
        unresolved_frontier: ["live projection remains gated".to_owned()]
            .into_iter()
            .collect(),
        stop_conditions: ["anchor drift or underdetermination".to_owned()]
            .into_iter()
            .collect(),
        subject: scope.subject.clone(),
        purpose: scope.purpose.clone(),
        intended_transform: "reduce active hints without losing the operative frame".to_owned(),
        frame_digest: empty_digest(),
    };
    let mandatory_anchor = fixture_hint(
        "hint:81000000-0000-4000-8000-000000000010",
        &scope_id,
        SjsMrfHintClass::MandatoryGoverningAnchor,
        "governing source and purpose",
        false,
        1,
        &[],
    )?;
    let mandatory_denial = fixture_hint(
        "hint:81000000-0000-4000-8000-000000000011",
        &scope_id,
        SjsMrfHintClass::MandatoryDenial,
        "no provider effect or self authorization",
        false,
        1,
        &[],
    )?;
    let mandatory_open = fixture_hint(
        "hint:81000000-0000-4000-8000-000000000012",
        &scope_id,
        SjsMrfHintClass::MandatoryOpenObligation,
        "independent replay remains open",
        false,
        1,
        &[],
    )?;
    let exact_source_id = semantic_id("recovery:81000000-0000-4000-8000-000000000030")?;
    let drift_source_id = semantic_id("recovery:81000000-0000-4000-8000-000000000031")?;
    let coordinate = fixture_hint(
        "hint:81000000-0000-4000-8000-000000000020",
        &scope_id,
        SjsMrfHintClass::RecoverableCoordinate,
        "exact checkpoint coordinate",
        true,
        0,
        std::slice::from_ref(&exact_source_id),
    )?;
    let drift_route = fixture_hint(
        "hint:81000000-0000-4000-8000-000000000021",
        &scope_id,
        SjsMrfHintClass::StableRelation,
        "stale alternate checkpoint route",
        true,
        0,
        std::slice::from_ref(&drift_source_id),
    )?;
    let optional_a = fixture_hint(
        "hint:81000000-0000-4000-8000-000000000022",
        &scope_id,
        SjsMrfHintClass::OptionalTrajectoryCue,
        "next test command cue",
        true,
        0,
        &[],
    )?;
    let optional_b = fixture_hint(
        "hint:81000000-0000-4000-8000-000000000023",
        &scope_id,
        SjsMrfHintClass::OptionalTrajectoryCue,
        "documentation wording cue",
        true,
        0,
        &[],
    )?;
    let optional_c = fixture_hint(
        "hint:81000000-0000-4000-8000-000000000024",
        &scope_id,
        SjsMrfHintClass::OptionalTrajectoryCue,
        "publication sequencing cue",
        true,
        0,
        &[],
    )?;
    let hints = vec![
        mandatory_anchor,
        mandatory_denial,
        mandatory_open,
        coordinate.clone(),
        drift_route.clone(),
        optional_a,
        optional_b,
        optional_c,
    ];
    let initial_basis = hints.iter().map(|hint| hint.hint_id.clone()).collect();
    let covenant = SjsMrfHintCovenant {
        covenant_id: semantic_id("covenant:81000000-0000-4000-8000-000000000040")?,
        scope_id: scope_id.clone(),
        job_ids: [job_a, job_b].into_iter().collect(),
        hints,
        covenant_digest: empty_digest(),
    };
    let mut drifted = baseline.clone();
    drifted.unresolved_frontier = ["live projection incorrectly declared complete".to_owned()]
        .into_iter()
        .collect();
    let recovery_sources = vec![
        SjsMrfRecoverySource {
            source_id: exact_source_id,
            kind: SjsMrfRecoverySourceKind::ExactCheckpoint,
            route_hint_ids: [coordinate.hint_id].into_iter().collect(),
            frame: baseline.clone(),
            source_digest: empty_digest(),
        },
        SjsMrfRecoverySource {
            source_id: drift_source_id,
            kind: SjsMrfRecoverySourceKind::ExactEventLedger,
            route_hint_ids: [drift_route.hint_id].into_iter().collect(),
            frame: drifted,
            source_digest: empty_digest(),
        },
    ];
    seal_sjs_mrf_request(SjsMrfRequest {
        profile: SJS_MRF_REQUEST_PROFILE.to_owned(),
        request_id: semantic_id("request:81000000-0000-4000-8000-000000000050")?,
        run_id: semantic_id("run:81000000-0000-4000-8000-000000000051")?,
        input_class: SjsMrfInputClass::SyntheticProviderFreeFixture,
        canonical_uuid: SJS_MRF_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_MRF_SIGNATURE_UUID.to_owned(),
        source_snapshot_uuid: SJS_MRF_SOURCE_SNAPSHOT_UUID.to_owned(),
        parent_source_uuid: SJS_MRF_PARENT_SOURCE_UUID.to_owned(),
        substrate_audit_uuid: SJS_MRF_SUBSTRATE_AUDIT_UUID.to_owned(),
        scope,
        covenant,
        operative_frame: baseline,
        recovery_sources,
        initial_basis,
        policy: SjsMrfCandidatePolicy {
            policy_id,
            strategy: SjsMrfCandidateStrategy::LexicographicSingleThenGrouped,
            max_group_size: 2,
            pass_budget: 64,
            monotone_zero_source_pruning: true,
            policy_digest: empty_digest(),
        },
        evidence_refs: [semantic_id(
            "evidence:81000000-0000-4000-8000-000000000052",
        )?]
        .into_iter()
        .collect(),
        non_authority: SJS_MRF_NON_AUTHORITY.to_owned(),
        request_digest: empty_digest(),
    })
}

fn fixture_hint(
    id: &str,
    scope_id: &SemanticId,
    class: SjsMrfHintClass,
    term: &str,
    release_eligible: bool,
    retention_floor: u8,
    recovery_source_ids: &[SemanticId],
) -> Result<SjsMrfHint, SjsMrfFault> {
    Ok(SjsMrfHint {
        hint_id: semantic_id(id)?,
        scope_id: scope_id.clone(),
        class,
        term: term.to_owned(),
        intended_transform: "reduce active hints without losing the operative frame".to_owned(),
        applicability: "all declared jobs and turns in scope".to_owned(),
        completion: "scope completion or invalidation".to_owned(),
        invalidation: "scope or governing identity drift".to_owned(),
        restoration_role: "public source-bound trajectory or recovery cue".to_owned(),
        source_refs: [semantic_id(
            "source-ref:81000000-0000-4000-8000-000000000060",
        )?]
        .into_iter()
        .collect(),
        recovery_source_ids: recovery_source_ids.iter().cloned().collect(),
        release_eligible,
        retention_floor,
        hint_digest: empty_digest(),
    })
}

struct DerivedCompilation {
    final_basis: Vec<SemanticId>,
    witnesses: Vec<SjsMrfRestorationWitness>,
    narrative: Vec<SjsMrfNarrativeEvent>,
    disposition: SjsMrfCompilationDisposition,
    locally_irreducible: bool,
    pass_budget_exhausted: bool,
}

fn derive_compilation(request: &SjsMrfRequest) -> Result<DerivedCompilation, SjsMrfFault> {
    let hints = request
        .covenant
        .hints
        .iter()
        .map(|hint| (hint.hint_id.clone(), hint))
        .collect::<BTreeMap<_, _>>();
    let mut current = request.initial_basis.clone();
    let mut witnesses = Vec::new();
    let mut narrative = Vec::new();
    let mut monotone_zero_source_pruned = BTreeSet::new();
    loop {
        let eligible = current
            .iter()
            .filter(|id| {
                hints
                    .get(*id)
                    .is_some_and(|hint| hint.release_eligible && hint.retention_floor == 0)
                    && !monotone_zero_source_pruned.contains(*id)
            })
            .cloned()
            .collect::<Vec<_>>();
        let candidates = candidate_groups(&eligible, request.policy.max_group_size)?;
        let mut admitted = false;
        for released in candidates {
            if witnesses.len() >= usize::from(request.policy.pass_budget) {
                return Ok(DerivedCompilation {
                    final_basis: current,
                    witnesses,
                    narrative,
                    disposition: SjsMrfCompilationDisposition::BoundedPassBudgetExhausted,
                    locally_irreducible: false,
                    pass_budget_exhausted: true,
                });
            }
            let candidate = current
                .iter()
                .filter(|id| !released.contains(*id))
                .cloned()
                .collect::<Vec<_>>();
            let evaluation = evaluate_candidate(request, &candidate)?;
            let ordinal = count_u32(witnesses.len() + 1)?;
            let before_basis_id = basis_id(&request.run_id, &current)?;
            let candidate_basis_id = basis_id(&request.run_id, &candidate)?;
            let (disposition, reason) = match evaluation.outcome {
                SjsMrfComparisonOutcome::Anchored => (
                    SjsMrfWitnessDisposition::ReleaseAdmitted,
                    "one reachable exact frame is byte-identical to the operative frame",
                ),
                SjsMrfComparisonOutcome::Drifted => (
                    SjsMrfWitnessDisposition::ReleaseRefusedDrifted,
                    "one reachable exact frame differs from the operative frame",
                ),
                SjsMrfComparisonOutcome::Underdetermined => (
                    SjsMrfWitnessDisposition::ReleaseRefusedUnderdetermined,
                    if evaluation.reachable_source_ids.is_empty() {
                        "no exact recovery frame remains reachable"
                    } else {
                        "multiple distinct exact recovery frames remain reachable"
                    },
                ),
            };
            let mut witness = SjsMrfRestorationWitness {
                ordinal,
                witness_id: witness_id(&request.run_id, ordinal, &released)?,
                before_basis_id,
                candidate_basis_id,
                released_hint_ids: released.clone(),
                reachable_source_ids: evaluation.reachable_source_ids,
                reconstructed_frame_digest: evaluation.reconstructed_frame_digest,
                outcome: evaluation.outcome,
                disposition,
                reason: reason.to_owned(),
                before_hint_count: count_u32(current.len())?,
                candidate_hint_count: count_u32(candidate.len())?,
                before_canonical_bytes: basis_bytes(&current)?,
                candidate_canonical_bytes: basis_bytes(&candidate)?,
                witness_digest: empty_digest(),
            };
            validate_witness_body(&witness)?;
            witness.witness_digest = sjs_mrf_witness_digest(&witness)?;
            narrative.push(SjsMrfNarrativeEvent {
                ordinal,
                witness_id: witness.witness_id.clone(),
                statement: format!(
                    "restoration witness {} {:?} {:?} for {} released hint(s)",
                    ordinal,
                    witness.outcome,
                    witness.disposition,
                    witness.released_hint_ids.len()
                ),
                authority_asserted: false,
            });
            if evaluation.outcome == SjsMrfComparisonOutcome::Underdetermined
                && witness.reachable_source_ids.is_empty()
                && released.len() == 1
                && request.policy.monotone_zero_source_pruning
            {
                monotone_zero_source_pruned.insert(released[0].clone());
            }
            let accepted = evaluation.outcome == SjsMrfComparisonOutcome::Anchored;
            witnesses.push(witness);
            if accepted {
                current = candidate;
                admitted = true;
                break;
            }
        }
        if !admitted {
            return Ok(DerivedCompilation {
                final_basis: current,
                witnesses,
                narrative,
                disposition: SjsMrfCompilationDisposition::LocallyIrreducible,
                locally_irreducible: true,
                pass_budget_exhausted: false,
            });
        }
    }
}

struct CandidateEvaluation {
    reachable_source_ids: Vec<SemanticId>,
    reconstructed_frame_digest: Option<ContentDigest>,
    outcome: SjsMrfComparisonOutcome,
}

fn evaluate_candidate(
    request: &SjsMrfRequest,
    candidate: &[SemanticId],
) -> Result<CandidateEvaluation, SjsMrfFault> {
    let retained = candidate.iter().cloned().collect::<BTreeSet<_>>();
    let reachable = request
        .recovery_sources
        .iter()
        .filter(|source| source.route_hint_ids.is_subset(&retained))
        .collect::<Vec<_>>();
    let ids = reachable
        .iter()
        .map(|source| source.source_id.clone())
        .collect::<Vec<_>>();
    let distinct = reachable
        .iter()
        .map(|source| {
            (
                source.frame.frame_digest.value.clone(),
                source.frame.frame_digest.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if distinct.len() != 1 {
        return Ok(CandidateEvaluation {
            reachable_source_ids: ids,
            reconstructed_frame_digest: None,
            outcome: SjsMrfComparisonOutcome::Underdetermined,
        });
    }
    let digest = distinct.values().next().cloned().ok_or_else(|| {
        fault(
            SjsMrfFaultCode::InvalidRecovery,
            "unique recovery digest missing",
        )
    })?;
    let outcome = if digest == request.operative_frame.frame_digest {
        SjsMrfComparisonOutcome::Anchored
    } else {
        SjsMrfComparisonOutcome::Drifted
    };
    Ok(CandidateEvaluation {
        reachable_source_ids: ids,
        reconstructed_frame_digest: Some(digest),
        outcome,
    })
}

fn candidate_groups(
    eligible: &[SemanticId],
    max_group_size: u8,
) -> Result<Vec<Vec<SemanticId>>, SjsMrfFault> {
    let mut result = Vec::new();
    let limit = usize::from(max_group_size).min(eligible.len());
    for size in 1..=limit {
        let mut current = Vec::with_capacity(size);
        combinations(eligible, size, 0, &mut current, &mut result)?;
    }
    Ok(result)
}

fn combinations(
    values: &[SemanticId],
    remaining: usize,
    start: usize,
    current: &mut Vec<SemanticId>,
    output: &mut Vec<Vec<SemanticId>>,
) -> Result<(), SjsMrfFault> {
    if remaining == 0 {
        output.push(current.clone());
        return Ok(());
    }
    let last_start = values.len().checked_sub(remaining).ok_or_else(|| {
        fault(
            SjsMrfFaultCode::ArithmeticOverflow,
            "candidate combination underflow",
        )
    })?;
    for index in start..=last_start {
        current.push(values[index].clone());
        combinations(values, remaining - 1, index + 1, current, output)?;
        current.pop();
    }
    Ok(())
}

fn verification_for(envelope: &SjsMrfEnvelope) -> Result<SjsMrfVerification, SjsMrfFault> {
    let admitted = envelope
        .witnesses
        .iter()
        .filter(|w| w.disposition == SjsMrfWitnessDisposition::ReleaseAdmitted)
        .count();
    let drift = envelope
        .witnesses
        .iter()
        .filter(|w| w.disposition == SjsMrfWitnessDisposition::ReleaseRefusedDrifted)
        .count();
    let under = envelope
        .witnesses
        .iter()
        .filter(|w| w.disposition == SjsMrfWitnessDisposition::ReleaseRefusedUnderdetermined)
        .count();
    let mandatory = envelope
        .request
        .covenant
        .hints
        .iter()
        .filter(|hint| is_mandatory(hint.class))
        .count();
    Ok(SjsMrfVerification {
        profile: SJS_MRF_VERIFICATION_PROFILE.to_owned(),
        status: "minimum_recoverable_frame_verified_provider_free".to_owned(),
        canonical_uuid: SJS_MRF_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_MRF_SIGNATURE_UUID.to_owned(),
        input_class: envelope.request.input_class,
        authority: SjsMrfAuthority::SuppliedDataRestorationTestingOnly,
        request_digest: envelope.request.request_digest.clone(),
        envelope_digest: envelope.envelope_digest.clone(),
        job_count: count_u32(envelope.request.scope.job_ids.len())?,
        hint_count: count_u32(envelope.request.covenant.hints.len())?,
        mandatory_hint_count: count_u32(mandatory)?,
        recovery_source_count: count_u32(envelope.request.recovery_sources.len())?,
        initial_basis_count: count_u32(envelope.request.initial_basis.len())?,
        final_basis_count: count_u32(envelope.final_basis.len())?,
        attempt_count: count_u32(envelope.witnesses.len())?,
        admitted_release_count: count_u32(admitted)?,
        drift_refusal_count: count_u32(drift)?,
        underdetermined_refusal_count: count_u32(under)?,
        narrative_event_count: count_u32(envelope.narrative_projection.len())?,
        evidence_reference_count: count_u32(envelope.request.evidence_refs.len())?,
        locally_irreducible: envelope.locally_irreducible,
        pass_budget_exhausted: envelope.pass_budget_exhausted,
        execution_authorized: false,
        effects: SjsMrfEffectAccount::default(),
    })
}

fn validate_request_body(request: &SjsMrfRequest) -> Result<(), SjsMrfFault> {
    if request.profile != SJS_MRF_REQUEST_PROFILE {
        return Err(fault(
            SjsMrfFaultCode::InvalidProfile,
            "request profile differs",
        ));
    }
    validate_uuid_id(&request.request_id, "request identity")?;
    validate_uuid_id(&request.run_id, "run identity")?;
    if request.request_id == request.run_id {
        return Err(fault(
            SjsMrfFaultCode::InvalidIdentity,
            "request and run identities collide",
        ));
    }
    if request.canonical_uuid != SJS_MRF_CANONICAL_UUID
        || request.signature_uuid != SJS_MRF_SIGNATURE_UUID
        || request.source_snapshot_uuid != SJS_MRF_SOURCE_SNAPSHOT_UUID
        || request.parent_source_uuid != SJS_MRF_PARENT_SOURCE_UUID
        || request.substrate_audit_uuid != SJS_MRF_SUBSTRATE_AUDIT_UUID
    {
        return Err(fault(
            SjsMrfFaultCode::InvalidIdentity,
            "governing identity differs",
        ));
    }
    if request.input_class == SjsMrfInputClass::SuppliedUnobservedDeclaration
        && request.request_id.as_str() == "request:81000000-0000-4000-8000-000000000050"
    {
        return Err(fault(
            SjsMrfFaultCode::InvalidInputClass,
            "known synthetic fixture cannot be relabeled",
        ));
    }
    if request.input_class == SjsMrfInputClass::SyntheticProviderFreeFixture {
        validate_synthetic_fixture_shape(request)?;
    }
    validate_scope(&request.scope)?;
    validate_frame(&request.operative_frame)?;
    validate_policy(&request.policy)?;
    if request.operative_frame.scope_id != request.scope.scope_id
        || request.operative_frame.source_identities != request.scope.source_identities
        || request.operative_frame.job_ids != request.scope.job_ids
        || request.operative_frame.subject != request.scope.subject
        || request.operative_frame.purpose != request.scope.purpose
        || request.operative_frame.model_profile != request.scope.model_profile
        || request.operative_frame.provider_profile != request.scope.provider_profile
        || request.operative_frame.tool_policy != request.scope.tool_policy
        || request.operative_frame.authority_identity != request.scope.authority_ceiling
        || request.operative_frame.policy_identity != request.policy.policy_id
    {
        return Err(fault(
            SjsMrfFaultCode::InvalidFrame,
            "operative frame differs from scope",
        ));
    }
    validate_covenant(&request.covenant, &request.scope, &request.operative_frame)?;
    if request.recovery_sources.is_empty()
        || request.recovery_sources.len() > MAX_RECOVERY_SOURCES
        || !strictly_sorted_by(&request.recovery_sources, |source| &source.source_id)
    {
        return Err(fault(
            SjsMrfFaultCode::InvalidRecovery,
            "recovery source bounds or order differ",
        ));
    }
    let hint_ids = request
        .covenant
        .hints
        .iter()
        .map(|hint| hint.hint_id.clone())
        .collect::<BTreeSet<_>>();
    let source_ids = request
        .recovery_sources
        .iter()
        .map(|source| source.source_id.clone())
        .collect::<BTreeSet<_>>();
    for source in &request.recovery_sources {
        validate_recovery_source(source)?;
        if !source.route_hint_ids.is_subset(&hint_ids) {
            return Err(fault(
                SjsMrfFaultCode::InvalidRecovery,
                "recovery route references unknown hint",
            ));
        }
    }
    for hint in &request.covenant.hints {
        if !hint.recovery_source_ids.is_subset(&source_ids) {
            return Err(fault(
                SjsMrfFaultCode::InvalidHint,
                "hint references unknown recovery source",
            ));
        }
        let reciprocal = request
            .recovery_sources
            .iter()
            .filter(|source| source.route_hint_ids.contains(&hint.hint_id))
            .map(|source| source.source_id.clone())
            .collect::<BTreeSet<_>>();
        if reciprocal != hint.recovery_source_ids {
            return Err(fault(
                SjsMrfFaultCode::InvalidRecovery,
                "hint and recovery routes are not reciprocal",
            ));
        }
    }
    if request.initial_basis.is_empty()
        || request.initial_basis.len() > MAX_HINTS
        || !strictly_sorted(&request.initial_basis)
        || request
            .initial_basis
            .iter()
            .any(|id| !hint_ids.contains(id))
    {
        return Err(fault(
            SjsMrfFaultCode::InvalidBasis,
            "initial basis bounds order or membership differ",
        ));
    }
    let basis = request
        .initial_basis
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    for hint in &request.covenant.hints {
        if is_mandatory(hint.class) && !basis.contains(&hint.hint_id) {
            return Err(fault(
                SjsMrfFaultCode::InvalidBasis,
                "mandatory hint omitted",
            ));
        }
        if hint.class == SjsMrfHintClass::ExpiredItem && basis.contains(&hint.hint_id) {
            return Err(fault(
                SjsMrfFaultCode::InvalidBasis,
                "expired hint retained",
            ));
        }
    }
    validate_reference_set(
        &request.evidence_refs,
        1,
        MAX_REFERENCES,
        "evidence references",
    )?;
    if request.non_authority != SJS_MRF_NON_AUTHORITY {
        return Err(fault(
            SjsMrfFaultCode::InvalidAuthority,
            "nonauthority differs",
        ));
    }
    Ok(())
}

fn validate_synthetic_fixture_shape(request: &SjsMrfRequest) -> Result<(), SjsMrfFault> {
    let expected_hint_ids = (10_u32..=12)
        .map(|value| format!("hint:81000000-0000-4000-8000-{value:012}"))
        .chain((20_u32..=24).map(|value| format!("hint:81000000-0000-4000-8000-{value:012}")))
        .collect::<Vec<_>>();
    let actual_hint_ids = request
        .covenant
        .hints
        .iter()
        .map(|hint| hint.hint_id.as_str())
        .collect::<Vec<_>>();
    let expected_frontier = ["live projection remains gated".to_owned()]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let exact_route = [semantic_id("hint:81000000-0000-4000-8000-000000000020")?]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let drift_route = [semantic_id("hint:81000000-0000-4000-8000-000000000021")?]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let exact_source = request.recovery_sources.first();
    let drift_source = request.recovery_sources.get(1);
    if request.request_id.as_str() != "request:81000000-0000-4000-8000-000000000050"
        || request.run_id.as_str() != "run:81000000-0000-4000-8000-000000000051"
        || request.scope.scope_id.as_str() != "scope:81000000-0000-4000-8000-000000000001"
        || request.covenant.covenant_id.as_str() != "covenant:81000000-0000-4000-8000-000000000040"
        || request.operative_frame.frame_id.as_str() != "frame:81000000-0000-4000-8000-000000000006"
        || request.policy.policy_id.as_str() != "policy:81000000-0000-4000-8000-000000000002"
        || request.policy.max_group_size != 2
        || request.policy.pass_budget != 64
        || request.covenant.hints.len() != 8
        || request.recovery_sources.len() != 2
        || request.initial_basis.len() != 8
        || actual_hint_ids
            != expected_hint_ids
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        || request.operative_frame.unresolved_frontier != expected_frontier
        || exact_source.is_none_or(|source| {
            source.source_id.as_str() != "recovery:81000000-0000-4000-8000-000000000030"
                || source.route_hint_ids != exact_route
                || source.frame != request.operative_frame
        })
        || drift_source.is_none_or(|source| {
            source.source_id.as_str() != "recovery:81000000-0000-4000-8000-000000000031"
                || source.route_hint_ids != drift_route
        })
    {
        return Err(fault(
            SjsMrfFaultCode::InvalidInputClass,
            "synthetic fixture semantics differ from the retained fixture",
        ));
    }
    Ok(())
}

fn validate_scope(scope: &SjsMrfJustificationScope) -> Result<(), SjsMrfFault> {
    validate_uuid_id(&scope.scope_id, "scope identity")?;
    validate_reference_set(&scope.source_identities, 1, MAX_REFERENCES, "scope sources")?;
    validate_reference_set(&scope.job_ids, 1, MAX_JOBS, "scope jobs")?;
    validate_text(&scope.subject, "scope subject")?;
    validate_text(&scope.purpose, "scope purpose")?;
    validate_text(&scope.model_profile, "model profile")?;
    validate_text(&scope.provider_profile, "provider profile")?;
    validate_text(&scope.tool_policy, "tool policy")?;
    validate_text(&scope.authority_ceiling, "authority ceiling")?;
    validate_text_set(
        &scope.completion_conditions,
        1,
        MAX_SET_MEMBERS,
        "completion conditions",
    )?;
    validate_text_set(
        &scope.invalidation_conditions,
        1,
        MAX_SET_MEMBERS,
        "invalidation conditions",
    )?;
    if scope.turn_start > scope.turn_end {
        return Err(fault(
            SjsMrfFaultCode::InvalidScope,
            "scope turn interval differs",
        ));
    }
    validate_digest(&scope.scope_digest, "scope digest")?;
    if sjs_mrf_scope_digest(scope)? != scope.scope_digest {
        return Err(fault(
            SjsMrfFaultCode::InvalidDigest,
            "scope digest differs",
        ));
    }
    Ok(())
}

fn validate_frame(frame: &SjsMrfOperativeFrame) -> Result<(), SjsMrfFault> {
    validate_uuid_id(&frame.frame_id, "frame identity")?;
    validate_uuid_id(&frame.scope_id, "frame scope identity")?;
    validate_uuid_id(&frame.policy_identity, "frame policy identity")?;
    validate_reference_set(&frame.source_identities, 1, MAX_REFERENCES, "frame sources")?;
    validate_reference_set(&frame.job_ids, 1, MAX_JOBS, "frame jobs")?;
    validate_reference_set(&frame.latest_receipt_ids, 0, MAX_RECEIPTS, "frame receipts")?;
    validate_reference_set(
        &frame.checkpoint_ids,
        1,
        MAX_REFERENCES,
        "frame checkpoints",
    )?;
    for (set, label) in [
        (&frame.constraints, "constraints"),
        (&frame.denials, "denials"),
        (&frame.open_requirements, "open requirements"),
        (&frame.dependencies, "dependencies"),
        (&frame.evidence_obligations, "evidence obligations"),
        (&frame.unresolved_frontier, "unresolved frontier"),
        (&frame.stop_conditions, "stop conditions"),
    ] {
        validate_text_set(set, 1, MAX_SET_MEMBERS, label)?;
    }
    for (text, label) in [
        (&frame.authority_identity, "frame authority"),
        (&frame.model_profile, "frame model"),
        (&frame.provider_profile, "frame provider"),
        (&frame.tool_policy, "frame tool policy"),
        (&frame.subject, "frame subject"),
        (&frame.purpose, "frame purpose"),
        (&frame.intended_transform, "frame transform"),
    ] {
        validate_text(text, label)?;
    }
    validate_digest(&frame.frame_digest, "frame digest")?;
    if sjs_mrf_frame_digest(frame)? != frame.frame_digest {
        return Err(fault(
            SjsMrfFaultCode::InvalidDigest,
            "frame digest differs",
        ));
    }
    Ok(())
}

fn validate_covenant(
    covenant: &SjsMrfHintCovenant,
    scope: &SjsMrfJustificationScope,
    frame: &SjsMrfOperativeFrame,
) -> Result<(), SjsMrfFault> {
    validate_uuid_id(&covenant.covenant_id, "covenant identity")?;
    if covenant.scope_id != scope.scope_id || covenant.job_ids != scope.job_ids {
        return Err(fault(
            SjsMrfFaultCode::InvalidHint,
            "covenant scope or jobs differ",
        ));
    }
    if covenant.hints.is_empty()
        || covenant.hints.len() > MAX_HINTS
        || !strictly_sorted_by(&covenant.hints, |hint| &hint.hint_id)
    {
        return Err(fault(
            SjsMrfFaultCode::InvalidHint,
            "hint bounds or order differ",
        ));
    }
    for hint in &covenant.hints {
        validate_hint(hint)?;
        if hint.scope_id != scope.scope_id || hint.intended_transform != frame.intended_transform {
            return Err(fault(
                SjsMrfFaultCode::InvalidHint,
                "hint scope or transform differs",
            ));
        }
    }
    validate_digest(&covenant.covenant_digest, "covenant digest")?;
    if sjs_mrf_covenant_digest(covenant)? != covenant.covenant_digest {
        return Err(fault(
            SjsMrfFaultCode::InvalidDigest,
            "covenant digest differs",
        ));
    }
    Ok(())
}

fn validate_hint(hint: &SjsMrfHint) -> Result<(), SjsMrfFault> {
    validate_uuid_id(&hint.hint_id, "hint identity")?;
    validate_uuid_id(&hint.scope_id, "hint scope identity")?;
    for (text, label) in [
        (&hint.term, "hint term"),
        (&hint.intended_transform, "hint transform"),
        (&hint.applicability, "hint applicability"),
        (&hint.completion, "hint completion"),
        (&hint.invalidation, "hint invalidation"),
        (&hint.restoration_role, "hint restoration role"),
    ] {
        validate_text(text, label)?;
    }
    validate_reference_set(&hint.source_refs, 1, MAX_REFERENCES, "hint sources")?;
    validate_reference_set(
        &hint.recovery_source_ids,
        0,
        MAX_RECOVERY_SOURCES,
        "hint recovery sources",
    )?;
    if is_mandatory(hint.class) {
        if hint.release_eligible || hint.retention_floor != 1 {
            return Err(fault(
                SjsMrfFaultCode::InvalidHint,
                "mandatory hint floor differs",
            ));
        }
    } else if hint.retention_floor != 0 {
        return Err(fault(
            SjsMrfFaultCode::InvalidHint,
            "nonmandatory hint floor differs",
        ));
    }
    if hint.class == SjsMrfHintClass::ExpiredItem && hint.release_eligible {
        return Err(fault(
            SjsMrfFaultCode::InvalidHint,
            "expired hint cannot be release candidate",
        ));
    }
    validate_digest(&hint.hint_digest, "hint digest")?;
    if sjs_mrf_hint_digest(hint)? != hint.hint_digest {
        return Err(fault(SjsMrfFaultCode::InvalidDigest, "hint digest differs"));
    }
    Ok(())
}

fn validate_recovery_source(source: &SjsMrfRecoverySource) -> Result<(), SjsMrfFault> {
    validate_uuid_id(&source.source_id, "recovery source identity")?;
    validate_reference_set(&source.route_hint_ids, 1, MAX_HINTS, "recovery route hints")?;
    validate_frame(&source.frame)?;
    validate_digest(&source.source_digest, "recovery source digest")?;
    if sjs_mrf_recovery_source_digest(source)? != source.source_digest {
        return Err(fault(
            SjsMrfFaultCode::InvalidDigest,
            "recovery source digest differs",
        ));
    }
    Ok(())
}

fn validate_policy(policy: &SjsMrfCandidatePolicy) -> Result<(), SjsMrfFault> {
    validate_uuid_id(&policy.policy_id, "policy identity")?;
    if policy.strategy != SjsMrfCandidateStrategy::LexicographicSingleThenGrouped
        || policy.max_group_size == 0
        || policy.max_group_size > MAX_GROUP_SIZE
        || policy.pass_budget == 0
        || policy.pass_budget > MAX_PASS_BUDGET
        || !policy.monotone_zero_source_pruning
    {
        return Err(fault(
            SjsMrfFaultCode::InvalidPolicy,
            "candidate policy differs",
        ));
    }
    validate_digest(&policy.policy_digest, "policy digest")?;
    if sjs_mrf_policy_digest(policy)? != policy.policy_digest {
        return Err(fault(
            SjsMrfFaultCode::InvalidDigest,
            "policy digest differs",
        ));
    }
    Ok(())
}

fn validate_witness_body(witness: &SjsMrfRestorationWitness) -> Result<(), SjsMrfFault> {
    if witness.ordinal == 0
        || witness.released_hint_ids.is_empty()
        || witness.released_hint_ids.len() > usize::from(MAX_GROUP_SIZE)
        || !strictly_sorted(&witness.released_hint_ids)
        || !strictly_sorted(&witness.reachable_source_ids)
        || witness.candidate_hint_count >= witness.before_hint_count
        || witness.candidate_canonical_bytes >= witness.before_canonical_bytes
    {
        return Err(fault(
            SjsMrfFaultCode::InvalidWitness,
            "witness ordering or monotonicity differs",
        ));
    }
    let coherent = matches!(
        (witness.outcome, witness.disposition),
        (
            SjsMrfComparisonOutcome::Anchored,
            SjsMrfWitnessDisposition::ReleaseAdmitted
        ) | (
            SjsMrfComparisonOutcome::Drifted,
            SjsMrfWitnessDisposition::ReleaseRefusedDrifted
        ) | (
            SjsMrfComparisonOutcome::Underdetermined,
            SjsMrfWitnessDisposition::ReleaseRefusedUnderdetermined
        )
    );
    if !coherent {
        return Err(fault(
            SjsMrfFaultCode::InvalidWitness,
            "witness outcome and disposition differ",
        ));
    }
    validate_text(&witness.reason, "witness reason")?;
    Ok(())
}

fn evidence_manifest(
    request_file: &str,
    envelope_file: &str,
    verification_file: &str,
    verification: &SjsMrfVerification,
) -> Result<SjsMrfEvidenceManifest, SjsMrfFault> {
    let mut files = BTreeMap::new();
    for (path, body) in [
        (REQUEST_FILE, request_file),
        (ENVELOPE_FILE, envelope_file),
        (VERIFICATION_FILE, verification_file),
    ] {
        files.insert(
            path.to_owned(),
            SjsMrfEvidenceFile {
                bytes: count_u64(body.len())?,
                sha256: sha256_bytes(body.as_bytes()),
            },
        );
    }
    Ok(SjsMrfEvidenceManifest {
        profile: SJS_MRF_EVIDENCE_PROFILE.to_owned(),
        canonical_uuid: SJS_MRF_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_MRF_SIGNATURE_UUID.to_owned(),
        replay_count: 2,
        files,
        request_digest: verification.request_digest.clone(),
        envelope_digest: verification.envelope_digest.clone(),
        job_count: verification.job_count,
        hint_count: verification.hint_count,
        recovery_source_count: verification.recovery_source_count,
        attempt_count: verification.attempt_count,
        admitted_release_count: verification.admitted_release_count,
        drift_refusal_count: verification.drift_refusal_count,
        underdetermined_refusal_count: verification.underdetermined_refusal_count,
        final_basis_count: verification.final_basis_count,
        locally_irreducible: verification.locally_irreducible,
        pass_budget_exhausted: verification.pass_budget_exhausted,
        execution_authorized: false,
        effects: SjsMrfEffectAccount::default(),
    })
}

fn ensure_bundle_bound(bundle: &SjsMrfEvidenceBundle) -> Result<(), SjsMrfFault> {
    for (body, label) in [
        (&bundle.request_file, REQUEST_FILE),
        (&bundle.envelope_file, ENVELOPE_FILE),
        (&bundle.verification_file, VERIFICATION_FILE),
        (&bundle.manifest_file, "manifest.json"),
    ] {
        canonical_file_body(body, label)?;
        if body.len() > SJS_MRF_MAX_EVIDENCE_BYTES {
            return Err(fault(
                SjsMrfFaultCode::InvalidBound,
                "evidence file exceeds bound",
            ));
        }
    }
    Ok(())
}

fn basis_id(run_id: &SemanticId, basis: &[SemanticId]) -> Result<SemanticId, SjsMrfFault> {
    derived_id("basis", BASIS_ID_DOMAIN, &(run_id, basis))
}

fn witness_id(
    run_id: &SemanticId,
    ordinal: u32,
    released: &[SemanticId],
) -> Result<SemanticId, SjsMrfFault> {
    derived_id("witness", WITNESS_ID_DOMAIN, &(run_id, ordinal, released))
}

fn derived_id<T: Serialize>(
    prefix: &str,
    domain: &str,
    value: &T,
) -> Result<SemanticId, SjsMrfFault> {
    let digest = sha256_form(domain, value)?.value;
    semantic_id(format!(
        "{prefix}:{}-{}-5{}-8{}-{}",
        &digest[0..8],
        &digest[8..12],
        &digest[13..16],
        &digest[17..20],
        &digest[20..32]
    ))
}

fn basis_bytes(basis: &[SemanticId]) -> Result<u64, SjsMrfFault> {
    count_u64(serde_json::to_vec(basis).map_err(machine_fault)?.len())
}

fn is_mandatory(class: SjsMrfHintClass) -> bool {
    matches!(
        class,
        SjsMrfHintClass::MandatoryGoverningAnchor
            | SjsMrfHintClass::MandatoryDenial
            | SjsMrfHintClass::MandatoryOpenObligation
    )
}

fn validate_reference_set(
    values: &BTreeSet<SemanticId>,
    minimum: usize,
    maximum: usize,
    label: &str,
) -> Result<(), SjsMrfFault> {
    if values.len() < minimum || values.len() > maximum {
        return Err(fault(
            SjsMrfFaultCode::InvalidBound,
            format!("{label} bounds differ"),
        ));
    }
    for value in values {
        validate_reference(value, label)?;
    }
    Ok(())
}

fn validate_text_set(
    values: &BTreeSet<String>,
    minimum: usize,
    maximum: usize,
    label: &str,
) -> Result<(), SjsMrfFault> {
    if values.len() < minimum || values.len() > maximum {
        return Err(fault(
            SjsMrfFaultCode::InvalidBound,
            format!("{label} bounds differ"),
        ));
    }
    for value in values {
        validate_text(value, label)?;
    }
    Ok(())
}

fn strictly_sorted(values: &[SemanticId]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_sorted_by<T, F>(values: &[T], key: F) -> bool
where
    F: Fn(&T) -> &SemanticId,
{
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn validate_uuid_id(identity: &SemanticId, label: &str) -> Result<(), SjsMrfFault> {
    let value = identity.as_str();
    let component = value.rsplit(':').next().unwrap_or(value);
    let valid = value == value.to_ascii_lowercase()
        && component.len() == 36
        && component
            .bytes()
            .enumerate()
            .all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => byte == b'-',
                _ => byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'),
            })
        && component != "00000000-0000-0000-0000-000000000000";
    if !valid {
        return Err(fault(
            SjsMrfFaultCode::InvalidIdentity,
            format!("{label} is not a nonnil lowercase UUID-bearing identity"),
        ));
    }
    Ok(())
}

fn validate_reference(reference: &SemanticId, label: &str) -> Result<(), SjsMrfFault> {
    let value = reference.as_str();
    if value.is_empty()
        || value.len() > 512
        || value != value.to_ascii_lowercase()
        || value.contains("latest")
    {
        return Err(fault(
            SjsMrfFaultCode::InvalidIdentity,
            format!("{label} is not a bounded immutable lowercase reference"),
        ));
    }
    Ok(())
}

fn validate_text(value: &str, label: &str) -> Result<(), SjsMrfFault> {
    if !valid_text(value) || value.trim() != value {
        return Err(fault(
            SjsMrfFaultCode::InvalidText,
            format!("{label} differs"),
        ));
    }
    Ok(())
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && value
            .chars()
            .all(|character| !character.is_control() && character != '\u{7f}')
}

fn validate_digest(digest: &ContentDigest, label: &str) -> Result<(), SjsMrfFault> {
    if digest.algorithm != "sha256"
        || digest.value.len() != 64
        || !digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(fault(
            SjsMrfFaultCode::InvalidDigest,
            format!("{label} differs"),
        ));
    }
    Ok(())
}

fn semantic_id(value: impl Into<String>) -> Result<SemanticId, SjsMrfFault> {
    SemanticId::new(value)
        .map_err(|error| fault(SjsMrfFaultCode::InvalidIdentity, error.to_string()))
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn count_u32(value: usize) -> Result<u32, SjsMrfFault> {
    u32::try_from(value).map_err(|_| {
        fault(
            SjsMrfFaultCode::ArithmeticOverflow,
            "usize to u32 conversion failed",
        )
    })
}

fn count_u64(value: usize) -> Result<u64, SjsMrfFault> {
    u64::try_from(value).map_err(|_| {
        fault(
            SjsMrfFaultCode::ArithmeticOverflow,
            "usize to u64 conversion failed",
        )
    })
}

fn sha256_form<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, SjsMrfFault> {
    let body = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + body.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&body);
    Ok(sha256_bytes(&bytes))
}

fn to_machine_form<T: Serialize>(value: &T) -> Result<String, SjsMrfFault> {
    serde_json::to_string(value).map_err(machine_fault)
}

fn parse_bounded<T: DeserializeOwned + Serialize>(value: &str) -> Result<T, SjsMrfFault> {
    parse_bounded_with_limit(value, SJS_MRF_MAX_MACHINE_FORM_BYTES)
}

fn parse_bounded_with_limit<T: DeserializeOwned + Serialize>(
    value: &str,
    limit: usize,
) -> Result<T, SjsMrfFault> {
    if value.len() > limit {
        return Err(fault(
            SjsMrfFaultCode::InvalidBound,
            format!("machine form exceeds {limit} bytes"),
        ));
    }
    let mut duplicate_check = serde_json::Deserializer::from_str(value);
    NoDuplicateJson::deserialize(&mut duplicate_check).map_err(machine_fault)?;
    duplicate_check.end().map_err(machine_fault)?;
    let shape: Value = serde_json::from_str(value).map_err(machine_fault)?;
    let mut fields = 0_usize;
    validate_json_shape(&shape, 1, &mut fields, None)?;
    let parsed: T = serde_json::from_str(value).map_err(machine_fault)?;
    if to_machine_form(&parsed)? != value {
        return Err(fault(
            SjsMrfFaultCode::InvalidMachineForm,
            "machine form is not canonical compact JSON",
        ));
    }
    Ok(parsed)
}

struct NoDuplicateJson;

impl<'de> Deserialize<'de> for NoDuplicateJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateJsonVisitor)?;
        Ok(Self)
    }
}

struct NoDuplicateJsonVisitor;

impl<'de> Visitor<'de> for NoDuplicateJsonVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON without duplicate object keys")
    }
    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }
    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<NoDuplicateJson>()?.is_some() {}
        Ok(())
    }
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
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
) -> Result<(), SjsMrfFault> {
    if depth > MAX_DEPTH {
        return Err(fault(
            SjsMrfFaultCode::InvalidMachineForm,
            "machine form exceeds depth 48",
        ));
    }
    match value {
        Value::Object(map) => {
            *fields = fields.checked_add(map.len()).ok_or_else(|| {
                fault(SjsMrfFaultCode::ArithmeticOverflow, "field count overflow")
            })?;
            if *fields > MAX_FIELDS {
                return Err(fault(
                    SjsMrfFaultCode::InvalidMachineForm,
                    "machine form exceeds 32768 fields",
                ));
            }
            for (key, child) in map {
                if !valid_text(key) {
                    return Err(fault(
                        SjsMrfFaultCode::InvalidMachineForm,
                        "machine field text differs",
                    ));
                }
                validate_json_shape(child, depth + 1, fields, Some(key))?;
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_json_shape(child, depth + 1, fields, None)?;
            }
        }
        Value::String(text) => {
            let file_body = matches!(
                parent_key,
                Some("request_file" | "envelope_file" | "verification_file" | "manifest_file")
            );
            if (!file_body && !valid_text(text))
                || (file_body && text.len() > SJS_MRF_MAX_EVIDENCE_BYTES)
            {
                return Err(fault(
                    SjsMrfFaultCode::InvalidMachineForm,
                    "machine text differs",
                ));
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn canonical_file(value: String) -> String {
    format!("{value}\n")
}

fn canonical_file_body<'a>(value: &'a str, label: &str) -> Result<&'a str, SjsMrfFault> {
    let body = value.strip_suffix('\n').ok_or_else(|| {
        fault(
            SjsMrfFaultCode::InvalidEvidence,
            format!("{label} lacks one LF terminator"),
        )
    })?;
    if body.contains('\n') || body.contains('\r') {
        return Err(fault(
            SjsMrfFaultCode::InvalidEvidence,
            format!("{label} contains embedded line terminator"),
        ));
    }
    Ok(body)
}

fn machine_fault(error: impl fmt::Display) -> SjsMrfFault {
    fault(SjsMrfFaultCode::InvalidMachineForm, error.to_string())
}

fn fault(code: SjsMrfFaultCode, detail: impl Into<String>) -> SjsMrfFault {
    SjsMrfFault {
        code,
        detail: detail.into(),
    }
}
