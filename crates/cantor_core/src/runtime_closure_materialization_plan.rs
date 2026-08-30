//! Pure provider-free materialization-plan compilation for RMP-P0.
//!
//! This module accepts exact supplied runtime-closure envelope bytes, replays
//! RIS-P0 Revision 0.2, and derives an effectless proposed operation DAG. It
//! performs no filesystem, environment, clock, process, network, provider,
//! model, MCP, Git, workspace, secret, permission, activation, rollback,
//! remote, hardware, or external action.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ContentDigest, SemanticId, sha256_bytes};
use crate::{
    RUNTIME_CLOSURE_CANONICAL_UUID, RUNTIME_CLOSURE_SIGNATURE_UUID, RuntimeClosureCapabilityDenial,
    RuntimeClosureEffectAccount, RuntimeClosureEnvelope, RuntimeClosureExecutableDisposition,
    RuntimeClosureMaterialKind, RuntimeClosurePrerequisite, RuntimeClosurePrerequisiteKind,
    RuntimeClosureSourceKind, compile_runtime_closure, expected_installation_receipt_digest,
    from_runtime_closure_envelope_machine_form, runtime_closure_required_capability_denials,
    synthetic_runtime_closure_request, to_runtime_closure_envelope_machine_form,
    verify_runtime_closure,
};

pub const RUNTIME_CLOSURE_MATERIALIZATION_REQUEST_PROFILE: &str =
    "cantor-runtime-closure-materialization-plan-request/0.1";
pub const RUNTIME_CLOSURE_MATERIALIZATION_ENVELOPE_PROFILE: &str =
    "cantor-runtime-closure-materialization-plan-envelope/0.1";
pub const RUNTIME_CLOSURE_MATERIALIZATION_VERIFICATION_PROFILE: &str =
    "cantor-runtime-closure-materialization-plan-verification/0.1";
pub const RUNTIME_CLOSURE_MATERIALIZATION_EVIDENCE_PROFILE: &str =
    "cantor-runtime-closure-materialization-plan-evidence/0.1";
pub const RUNTIME_CLOSURE_MATERIALIZATION_CANONICAL_UUID: &str =
    "1ec5159a-cddd-4061-a316-4dace13d2e06";
pub const RUNTIME_CLOSURE_MATERIALIZATION_SIGNATURE_UUID: &str =
    "90be7b47-10d2-47a5-989e-8c40120bd60b";
pub const RUNTIME_CLOSURE_MATERIALIZATION_NON_AUTHORITY: &str = "Supplied-data materialization-plan compilation only. Hashes and proposed operations establish no byte presence, provenance, license, policy, trust, compatibility, safety, suitability, availability, acquisition, build, target preparation, staging, verification result, rollback readiness, installation, activation, receipt observation, successor recognition, provider or model state, secret custody, remote state, hardware state, or external-effect authority.";
pub const RUNTIME_CLOSURE_MATERIALIZATION_MAX_MACHINE_FORM_BYTES: usize = 2_097_152;
pub const RUNTIME_CLOSURE_MATERIALIZATION_MAX_UPSTREAM_BYTES: usize = 1_048_576;
pub const RUNTIME_CLOSURE_MATERIALIZATION_MAX_EVIDENCE_BYTES: usize = 8_388_608;

const REQUEST_DOMAIN: &str = "cantor.runtime-closure-materialization.request.v1";
const OPERATION_ID_DOMAIN: &str = "cantor.runtime-closure-materialization.operation-id.v1";
const OPERATION_DOMAIN: &str = "cantor.runtime-closure-materialization.operation.v1";
const ORDERED_OPERATION_DOMAIN: &str =
    "cantor.runtime-closure-materialization.ordered-operations.v1";
const RECEIPT_DOMAIN: &str = "cantor.runtime-closure-materialization.receipt-candidate.v1";
const PLAN_DOMAIN: &str = "cantor.runtime-closure-materialization.plan.v1";
const ENVELOPE_DOMAIN: &str = "cantor.runtime-closure-materialization.envelope.v1";
const MAX_DEPTH: usize = 48;
const MAX_FIELDS: usize = 32_768;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_EVIDENCE_REFS: usize = 64;
const MAX_OPERATION_DEPENDENCIES: usize = 256;
const REQUEST_EVIDENCE_PATH: &str = "request.json";
const ENVELOPE_EVIDENCE_PATH: &str = "envelope.json";
const VERIFICATION_EVIDENCE_PATH: &str = "verification.json";

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeClosureMaterializationInputClass {
    SyntheticProviderFreeFixture,
    SuppliedUnobservedDeclaration,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeClosureMaterializationPhase {
    SeedValidation,
    PrerequisiteResolution,
    MaterialProduction,
    TargetPreparation,
    MaterialStaging,
    MaterialVerification,
    RollbackPreparation,
    ClosureVerification,
    ReceiptCandidate,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeClosureMaterializationOperationKind {
    ValidateSeedRoot,
    ResolvePrerequisite,
    ApplyDeterministicTransform,
    RunSourceBuild,
    AcquireContentAddressedArtifact,
    AcceptExplicitlySuppliedMaterial,
    GenerateConfiguration,
    PrepareTarget,
    StageMaterial,
    VerifyMaterial,
    PrepareRollback,
    VerifyClosure,
    EmitReceiptCandidate,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeClosureMaterializationDisposition {
    ProposedAwaitingSeparateCommission,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeClosureMaterializationLifecycle {
    MaterializationPlanCompiledEffectlessAwaitingSeparateCommission,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeClosureMaterializationAuthority {
    SuppliedDataMaterializationPlanningOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosureMaterializationRequest {
    pub profile: String,
    pub request_id: SemanticId,
    pub materialization_id: SemanticId,
    pub input_class: RuntimeClosureMaterializationInputClass,
    pub upstream_canonical_uuid: String,
    pub upstream_signature_uuid: String,
    pub upstream_envelope: String,
    pub upstream_envelope_bytes: u64,
    pub upstream_envelope_sha256: ContentDigest,
    pub upstream_request_digest: ContentDigest,
    pub upstream_plan_digest: ContentDigest,
    pub upstream_envelope_digest: ContentDigest,
    pub upstream_expected_receipt_digest: ContentDigest,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub non_authority: String,
    pub request_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosureMaterializationOperation {
    pub ordinal: u32,
    pub operation_id: SemanticId,
    pub phase: RuntimeClosureMaterializationPhase,
    pub kind: RuntimeClosureMaterializationOperationKind,
    pub subject_id: SemanticId,
    pub p0_node_id: Option<SemanticId>,
    pub p0_prerequisite_id: Option<SemanticId>,
    pub p0_edge_id: Option<SemanticId>,
    pub p0_source_id: Option<SemanticId>,
    pub dependencies: Vec<SemanticId>,
    pub target: Option<String>,
    pub expected_sha256: Option<ContentDigest>,
    pub expected_bytes: Option<u64>,
    pub verifier_profile: Option<String>,
    pub executable: Option<RuntimeClosureExecutableDisposition>,
    pub required_denied_capabilities: BTreeSet<RuntimeClosureCapabilityDenial>,
    pub unresolved_reason: String,
    pub disposition: RuntimeClosureMaterializationDisposition,
    pub execution_authorized: bool,
    pub observed: bool,
    pub executed: bool,
    pub operation_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosureMaterializationReceiptCandidate {
    pub materialization_id: SemanticId,
    pub upstream_expected_receipt_digest: ContentDigest,
    pub operation_count: u32,
    pub ordered_operation_digest: ContentDigest,
    pub observation_count: u32,
    pub executed_operation_count: u32,
    pub materialized_node_count: u32,
    pub verified_node_count: u32,
    pub filesystem_result_count: u32,
    pub verifier_result_count: u32,
    pub installation_state_asserted: bool,
    pub activation_state_asserted: bool,
    pub rollback_ready_asserted: bool,
    pub successor_recognition_authority: bool,
    pub receipt_candidate_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosureMaterializationPlan {
    pub status: String,
    pub materialization_id: SemanticId,
    pub input_class: RuntimeClosureMaterializationInputClass,
    pub upstream_canonical_uuid: String,
    pub upstream_signature_uuid: String,
    pub upstream_request_id: SemanticId,
    pub upstream_closure_id: SemanticId,
    pub upstream_request_digest: ContentDigest,
    pub upstream_plan_digest: ContentDigest,
    pub upstream_envelope_digest: ContentDigest,
    pub phases: Vec<RuntimeClosureMaterializationPhase>,
    pub operations: Vec<RuntimeClosureMaterializationOperation>,
    pub unresolved_operation_digests: Vec<ContentDigest>,
    pub capability_denials: BTreeSet<RuntimeClosureCapabilityDenial>,
    pub receipt_candidate: RuntimeClosureMaterializationReceiptCandidate,
    pub execution_authorized: bool,
    pub request_digest: ContentDigest,
    pub plan_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosureMaterializationEnvelope {
    pub profile: String,
    pub request: RuntimeClosureMaterializationRequest,
    pub lifecycle: RuntimeClosureMaterializationLifecycle,
    pub authority: RuntimeClosureMaterializationAuthority,
    pub plan: RuntimeClosureMaterializationPlan,
    pub envelope_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosureMaterializationVerification {
    pub profile: String,
    pub status: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub upstream_canonical_uuid: String,
    pub upstream_signature_uuid: String,
    pub input_class: RuntimeClosureMaterializationInputClass,
    pub authority: RuntimeClosureMaterializationAuthority,
    pub request_digest: ContentDigest,
    pub plan_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
    pub upstream_request_digest: ContentDigest,
    pub upstream_plan_digest: ContentDigest,
    pub upstream_envelope_digest: ContentDigest,
    pub upstream_root_count: u32,
    pub upstream_material_node_count: u32,
    pub upstream_producer_edge_count: u32,
    pub upstream_prerequisite_count: u32,
    pub phase_count: u32,
    pub operation_kind_count: u32,
    pub operation_count: u32,
    pub unresolved_operation_count: u32,
    pub capability_denial_count: u32,
    pub evidence_reference_count: u32,
    pub receipt_zero_field_count: u32,
    pub upstream_recompiled_byte_identical: bool,
    pub deterministic_double_compilation_verified: bool,
    pub execution_authorized: bool,
    pub effects: RuntimeClosureEffectAccount,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosureMaterializationEvidenceFile {
    pub path: String,
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosureMaterializationEvidenceManifest {
    pub profile: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub replay_count: u32,
    pub files: BTreeMap<String, RuntimeClosureMaterializationEvidenceFile>,
    pub request_digest: ContentDigest,
    pub plan_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
    pub upstream_request_digest: ContentDigest,
    pub upstream_plan_digest: ContentDigest,
    pub upstream_envelope_digest: ContentDigest,
    pub phase_count: u32,
    pub operation_kind_count: u32,
    pub operation_count: u32,
    pub unresolved_operation_count: u32,
    pub capability_denial_count: u32,
    pub evidence_reference_count: u32,
    pub receipt_zero_field_count: u32,
    pub execution_authorized: bool,
    pub effects: RuntimeClosureEffectAccount,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosureMaterializationEvidenceBundle {
    pub request_file: String,
    pub envelope_file: String,
    pub verification_file: String,
    pub manifest_file: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeClosureMaterializationFaultCode {
    InvalidProfile,
    InvalidInputClass,
    InvalidIdentity,
    InvalidDigest,
    InvalidBound,
    InvalidUpstream,
    InvalidPhase,
    InvalidOperation,
    InvalidDependency,
    InvalidDenial,
    InvalidAuthority,
    InvalidReceipt,
    InvalidVerification,
    InvalidEvidence,
    InvalidMachineForm,
    ArithmeticOverflow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeClosureMaterializationFault {
    pub code: RuntimeClosureMaterializationFaultCode,
    pub detail: String,
}

impl fmt::Display for RuntimeClosureMaterializationFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}

impl std::error::Error for RuntimeClosureMaterializationFault {}

pub fn seal_runtime_closure_materialization_request(
    mut request: RuntimeClosureMaterializationRequest,
) -> Result<RuntimeClosureMaterializationRequest, RuntimeClosureMaterializationFault> {
    request.request_digest = empty_digest();
    validate_materialization_request_body(&request)?;
    request.request_digest = runtime_closure_materialization_request_digest(&request)?;
    validate_runtime_closure_materialization_request(&request)?;
    Ok(request)
}

pub fn validate_runtime_closure_materialization_request(
    request: &RuntimeClosureMaterializationRequest,
) -> Result<(), RuntimeClosureMaterializationFault> {
    validate_materialization_request_body(request)?;
    if runtime_closure_materialization_request_digest(request)? != request.request_digest {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidDigest,
            "materialization request digest differs",
        ));
    }
    Ok(())
}

pub fn compile_runtime_closure_materialization_plan(
    request: &RuntimeClosureMaterializationRequest,
) -> Result<RuntimeClosureMaterializationEnvelope, RuntimeClosureMaterializationFault> {
    validate_runtime_closure_materialization_request(request)?;
    let upstream = replay_upstream(request)?;
    let plan = derive_plan(request, &upstream)?;
    let mut envelope = RuntimeClosureMaterializationEnvelope {
        profile: RUNTIME_CLOSURE_MATERIALIZATION_ENVELOPE_PROFILE.to_owned(),
        request: request.clone(),
        lifecycle: RuntimeClosureMaterializationLifecycle::MaterializationPlanCompiledEffectlessAwaitingSeparateCommission,
        authority: RuntimeClosureMaterializationAuthority::SuppliedDataMaterializationPlanningOnly,
        plan,
        envelope_digest: empty_digest(),
    };
    envelope.envelope_digest = runtime_closure_materialization_envelope_digest(&envelope)?;
    validate_runtime_closure_materialization_envelope(&envelope)?;
    Ok(envelope)
}

pub fn validate_runtime_closure_materialization_envelope(
    envelope: &RuntimeClosureMaterializationEnvelope,
) -> Result<(), RuntimeClosureMaterializationFault> {
    validate_runtime_closure_materialization_request(&envelope.request)?;
    if envelope.profile != RUNTIME_CLOSURE_MATERIALIZATION_ENVELOPE_PROFILE
        || envelope.lifecycle
            != RuntimeClosureMaterializationLifecycle::MaterializationPlanCompiledEffectlessAwaitingSeparateCommission
        || envelope.authority
            != RuntimeClosureMaterializationAuthority::SuppliedDataMaterializationPlanningOnly
    {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidAuthority,
            "materialization envelope profile lifecycle or authority differs",
        ));
    }
    let upstream = replay_upstream(&envelope.request)?;
    validate_plan(&envelope.plan, &envelope.request, &upstream)?;
    let expected = derive_plan(&envelope.request, &upstream)?;
    if envelope.plan != expected {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidOperation,
            "materialization plan differs from deterministic derivation",
        ));
    }
    if runtime_closure_materialization_envelope_digest(envelope)? != envelope.envelope_digest {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidDigest,
            "materialization envelope digest differs",
        ));
    }
    Ok(())
}

pub fn verify_runtime_closure_materialization_plan(
    envelope: &RuntimeClosureMaterializationEnvelope,
) -> Result<RuntimeClosureMaterializationVerification, RuntimeClosureMaterializationFault> {
    validate_runtime_closure_materialization_envelope(envelope)?;
    let verification = verification_without_validation(envelope)?;
    validate_runtime_closure_materialization_verification(&verification, envelope)?;
    Ok(verification)
}

pub fn validate_runtime_closure_materialization_verification(
    verification: &RuntimeClosureMaterializationVerification,
    envelope: &RuntimeClosureMaterializationEnvelope,
) -> Result<(), RuntimeClosureMaterializationFault> {
    let expected = verification_without_validation(envelope)?;
    if verification != &expected {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidVerification,
            "materialization verification differs from deterministic account",
        ));
    }
    if verification.execution_authorized
        || verification.effects != RuntimeClosureEffectAccount::default()
    {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidAuthority,
            "materialization verification asserts authority or an effect",
        ));
    }
    Ok(())
}

pub fn build_runtime_closure_materialization_evidence_bundle(
    request: &RuntimeClosureMaterializationRequest,
) -> Result<RuntimeClosureMaterializationEvidenceBundle, RuntimeClosureMaterializationFault> {
    validate_runtime_closure_materialization_request(request)?;
    let first_envelope = compile_runtime_closure_materialization_plan(request)?;
    let second_envelope = compile_runtime_closure_materialization_plan(request)?;
    if first_envelope != second_envelope {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidEvidence,
            "two materialization compilations differ",
        ));
    }
    let first_verification = verify_runtime_closure_materialization_plan(&first_envelope)?;
    let second_verification = verify_runtime_closure_materialization_plan(&second_envelope)?;
    if first_verification != second_verification {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidEvidence,
            "two materialization verification passes differ",
        ));
    }
    let request_file = canonical_file(to_runtime_closure_materialization_request_machine_form(
        request,
    )?);
    let envelope_file = canonical_file(to_runtime_closure_materialization_envelope_machine_form(
        &first_envelope,
    )?);
    let verification_file = canonical_file(
        to_runtime_closure_materialization_verification_machine_form(&first_verification)?,
    );
    let manifest = evidence_manifest(
        &request_file,
        &envelope_file,
        &verification_file,
        &first_verification,
    )?;
    let manifest_file = canonical_file(to_machine_form(&manifest)?);
    let bundle = RuntimeClosureMaterializationEvidenceBundle {
        request_file,
        envelope_file,
        verification_file,
        manifest_file,
    };
    ensure_evidence_bundle_bound(&bundle)?;
    Ok(bundle)
}

pub fn verify_runtime_closure_materialization_evidence_bundle(
    bundle: &RuntimeClosureMaterializationEvidenceBundle,
) -> Result<RuntimeClosureMaterializationVerification, RuntimeClosureMaterializationFault> {
    ensure_evidence_bundle_bound(bundle)?;
    let request_body = canonical_file_body(&bundle.request_file, REQUEST_EVIDENCE_PATH)?;
    let envelope_body = canonical_file_body(&bundle.envelope_file, ENVELOPE_EVIDENCE_PATH)?;
    let verification_body =
        canonical_file_body(&bundle.verification_file, VERIFICATION_EVIDENCE_PATH)?;
    let manifest_body = canonical_file_body(&bundle.manifest_file, "manifest.json")?;
    let request = from_runtime_closure_materialization_request_machine_form(request_body)?;
    let retained_envelope =
        from_runtime_closure_materialization_envelope_machine_form(envelope_body)?;
    let retained_verification =
        from_runtime_closure_materialization_verification_machine_form(verification_body)?;
    let retained_manifest: RuntimeClosureMaterializationEvidenceManifest =
        parse_bounded(manifest_body)?;

    let first_envelope = compile_runtime_closure_materialization_plan(&request)?;
    let second_envelope = compile_runtime_closure_materialization_plan(&request)?;
    if first_envelope != second_envelope || first_envelope != retained_envelope {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidEvidence,
            "retained envelope differs from independent double compilation",
        ));
    }
    let first_verification = verify_runtime_closure_materialization_plan(&first_envelope)?;
    let second_verification = verify_runtime_closure_materialization_plan(&second_envelope)?;
    if first_verification != second_verification || first_verification != retained_verification {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidEvidence,
            "retained verification differs from independent double replay",
        ));
    }
    let expected_manifest = evidence_manifest(
        &bundle.request_file,
        &bundle.envelope_file,
        &bundle.verification_file,
        &first_verification,
    )?;
    if retained_manifest != expected_manifest {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidEvidence,
            "retained manifest differs from reconstructed evidence",
        ));
    }
    Ok(first_verification)
}

pub fn to_runtime_closure_materialization_request_machine_form(
    request: &RuntimeClosureMaterializationRequest,
) -> Result<String, RuntimeClosureMaterializationFault> {
    validate_runtime_closure_materialization_request(request)?;
    to_machine_form(request)
}

pub fn from_runtime_closure_materialization_request_machine_form(
    value: &str,
) -> Result<RuntimeClosureMaterializationRequest, RuntimeClosureMaterializationFault> {
    let request: RuntimeClosureMaterializationRequest = parse_bounded(value)?;
    validate_runtime_closure_materialization_request(&request)?;
    Ok(request)
}

pub fn to_runtime_closure_materialization_envelope_machine_form(
    envelope: &RuntimeClosureMaterializationEnvelope,
) -> Result<String, RuntimeClosureMaterializationFault> {
    validate_runtime_closure_materialization_envelope(envelope)?;
    to_machine_form(envelope)
}

pub fn from_runtime_closure_materialization_envelope_machine_form(
    value: &str,
) -> Result<RuntimeClosureMaterializationEnvelope, RuntimeClosureMaterializationFault> {
    let envelope: RuntimeClosureMaterializationEnvelope = parse_bounded(value)?;
    validate_runtime_closure_materialization_envelope(&envelope)?;
    Ok(envelope)
}

pub fn to_runtime_closure_materialization_verification_machine_form(
    verification: &RuntimeClosureMaterializationVerification,
) -> Result<String, RuntimeClosureMaterializationFault> {
    to_machine_form(verification)
}

pub fn from_runtime_closure_materialization_verification_machine_form(
    value: &str,
) -> Result<RuntimeClosureMaterializationVerification, RuntimeClosureMaterializationFault> {
    parse_bounded(value)
}

pub fn to_runtime_closure_materialization_evidence_bundle_machine_form(
    bundle: &RuntimeClosureMaterializationEvidenceBundle,
) -> Result<String, RuntimeClosureMaterializationFault> {
    ensure_evidence_bundle_bound(bundle)?;
    to_machine_form(bundle)
}

pub fn from_runtime_closure_materialization_evidence_bundle_machine_form(
    value: &str,
) -> Result<RuntimeClosureMaterializationEvidenceBundle, RuntimeClosureMaterializationFault> {
    let bundle: RuntimeClosureMaterializationEvidenceBundle =
        parse_bounded_with_limit(value, RUNTIME_CLOSURE_MATERIALIZATION_MAX_EVIDENCE_BYTES)?;
    ensure_evidence_bundle_bound(&bundle)?;
    Ok(bundle)
}

pub fn runtime_closure_materialization_request_digest(
    request: &RuntimeClosureMaterializationRequest,
) -> Result<ContentDigest, RuntimeClosureMaterializationFault> {
    let mut body = request.clone();
    body.request_digest = empty_digest();
    sha256_form(REQUEST_DOMAIN, &body)
}

pub fn runtime_closure_materialization_operation_digest(
    operation: &RuntimeClosureMaterializationOperation,
) -> Result<ContentDigest, RuntimeClosureMaterializationFault> {
    let mut body = operation.clone();
    body.operation_digest = empty_digest();
    sha256_form(OPERATION_DOMAIN, &body)
}

pub fn runtime_closure_materialization_receipt_candidate_digest(
    receipt: &RuntimeClosureMaterializationReceiptCandidate,
) -> Result<ContentDigest, RuntimeClosureMaterializationFault> {
    let mut body = receipt.clone();
    body.receipt_candidate_digest = empty_digest();
    sha256_form(RECEIPT_DOMAIN, &body)
}

pub fn runtime_closure_materialization_ordered_operation_digest(
    operations: &[RuntimeClosureMaterializationOperation],
) -> Result<ContentDigest, RuntimeClosureMaterializationFault> {
    let digests = operations
        .iter()
        .map(|operation| operation.operation_digest.clone())
        .collect::<Vec<_>>();
    sha256_form(ORDERED_OPERATION_DOMAIN, &digests)
}

pub fn runtime_closure_materialization_plan_digest(
    plan: &RuntimeClosureMaterializationPlan,
) -> Result<ContentDigest, RuntimeClosureMaterializationFault> {
    let mut body = plan.clone();
    body.plan_digest = empty_digest();
    sha256_form(PLAN_DOMAIN, &body)
}

pub fn runtime_closure_materialization_envelope_digest(
    envelope: &RuntimeClosureMaterializationEnvelope,
) -> Result<ContentDigest, RuntimeClosureMaterializationFault> {
    let mut body = envelope.clone();
    body.envelope_digest = empty_digest();
    sha256_form(ENVELOPE_DOMAIN, &body)
}

pub fn runtime_closure_materialization_phases() -> Vec<RuntimeClosureMaterializationPhase> {
    vec![
        RuntimeClosureMaterializationPhase::SeedValidation,
        RuntimeClosureMaterializationPhase::PrerequisiteResolution,
        RuntimeClosureMaterializationPhase::MaterialProduction,
        RuntimeClosureMaterializationPhase::TargetPreparation,
        RuntimeClosureMaterializationPhase::MaterialStaging,
        RuntimeClosureMaterializationPhase::MaterialVerification,
        RuntimeClosureMaterializationPhase::RollbackPreparation,
        RuntimeClosureMaterializationPhase::ClosureVerification,
        RuntimeClosureMaterializationPhase::ReceiptCandidate,
    ]
}

pub fn runtime_closure_materialization_operation_kinds()
-> BTreeSet<RuntimeClosureMaterializationOperationKind> {
    [
        RuntimeClosureMaterializationOperationKind::ValidateSeedRoot,
        RuntimeClosureMaterializationOperationKind::ResolvePrerequisite,
        RuntimeClosureMaterializationOperationKind::ApplyDeterministicTransform,
        RuntimeClosureMaterializationOperationKind::RunSourceBuild,
        RuntimeClosureMaterializationOperationKind::AcquireContentAddressedArtifact,
        RuntimeClosureMaterializationOperationKind::AcceptExplicitlySuppliedMaterial,
        RuntimeClosureMaterializationOperationKind::GenerateConfiguration,
        RuntimeClosureMaterializationOperationKind::PrepareTarget,
        RuntimeClosureMaterializationOperationKind::StageMaterial,
        RuntimeClosureMaterializationOperationKind::VerifyMaterial,
        RuntimeClosureMaterializationOperationKind::PrepareRollback,
        RuntimeClosureMaterializationOperationKind::VerifyClosure,
        RuntimeClosureMaterializationOperationKind::EmitReceiptCandidate,
    ]
    .into_iter()
    .collect()
}

pub fn synthetic_runtime_closure_materialization_request()
-> Result<RuntimeClosureMaterializationRequest, RuntimeClosureMaterializationFault> {
    let upstream_request = synthetic_runtime_closure_request().map_err(upstream_fault)?;
    let upstream = compile_runtime_closure(&upstream_request).map_err(upstream_fault)?;
    let upstream_envelope =
        to_runtime_closure_envelope_machine_form(&upstream).map_err(upstream_fault)?;
    let expected_receipt = expected_installation_receipt_digest(&upstream.plan.expected_receipt)
        .map_err(upstream_fault)?;
    seal_runtime_closure_materialization_request(RuntimeClosureMaterializationRequest {
        profile: RUNTIME_CLOSURE_MATERIALIZATION_REQUEST_PROFILE.to_owned(),
        request_id: semantic_id("materialization-request:70000000-0000-4000-8000-000000000001")?,
        materialization_id: semantic_id("materialization:70000000-0000-4000-8000-000000000002")?,
        input_class: RuntimeClosureMaterializationInputClass::SyntheticProviderFreeFixture,
        upstream_canonical_uuid: RUNTIME_CLOSURE_CANONICAL_UUID.to_owned(),
        upstream_signature_uuid: RUNTIME_CLOSURE_SIGNATURE_UUID.to_owned(),
        upstream_envelope_bytes: count_u64(upstream_envelope.len())?,
        upstream_envelope_sha256: sha256_bytes(upstream_envelope.as_bytes()),
        upstream_envelope,
        upstream_request_digest: upstream.request.request_digest.clone(),
        upstream_plan_digest: upstream.plan.plan_digest.clone(),
        upstream_envelope_digest: upstream.envelope_digest,
        upstream_expected_receipt_digest: expected_receipt,
        evidence_refs: [semantic_id(
            "evidence:70000000-0000-4000-8000-000000000003",
        )?]
        .into_iter()
        .collect(),
        non_authority: RUNTIME_CLOSURE_MATERIALIZATION_NON_AUTHORITY.to_owned(),
        request_digest: empty_digest(),
    })
}

fn validate_materialization_request_body(
    request: &RuntimeClosureMaterializationRequest,
) -> Result<(), RuntimeClosureMaterializationFault> {
    if request.profile != RUNTIME_CLOSURE_MATERIALIZATION_REQUEST_PROFILE {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidProfile,
            "materialization request profile differs",
        ));
    }
    validate_uuid_id(&request.request_id, "materialization request identity")?;
    validate_uuid_id(&request.materialization_id, "materialization identity")?;
    if request.request_id == request.materialization_id {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidIdentity,
            "materialization request and materialization identities collide",
        ));
    }
    if request.upstream_canonical_uuid != RUNTIME_CLOSURE_CANONICAL_UUID
        || request.upstream_signature_uuid != RUNTIME_CLOSURE_SIGNATURE_UUID
    {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidUpstream,
            "upstream canonical or signature identity differs",
        ));
    }
    if request.upstream_envelope.is_empty()
        || request.upstream_envelope.len() > RUNTIME_CLOSURE_MATERIALIZATION_MAX_UPSTREAM_BYTES
        || request.upstream_envelope_bytes != count_u64(request.upstream_envelope.len())?
    {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidBound,
            "upstream envelope byte bound or account differs",
        ));
    }
    validate_digest(&request.upstream_envelope_sha256, "upstream byte digest")?;
    for (digest, label) in [
        (&request.upstream_request_digest, "upstream request digest"),
        (&request.upstream_plan_digest, "upstream plan digest"),
        (
            &request.upstream_envelope_digest,
            "upstream envelope digest",
        ),
        (
            &request.upstream_expected_receipt_digest,
            "upstream expected-receipt digest",
        ),
    ] {
        validate_digest(digest, label)?;
    }
    if request.upstream_envelope_sha256 != sha256_bytes(request.upstream_envelope.as_bytes()) {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidDigest,
            "upstream raw-byte digest differs",
        ));
    }
    if request.evidence_refs.is_empty() || request.evidence_refs.len() > MAX_EVIDENCE_REFS {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidBound,
            "materialization evidence references must contain 1 through 64 members",
        ));
    }
    for reference in &request.evidence_refs {
        validate_reference(reference, "materialization evidence reference")?;
    }
    if request.non_authority != RUNTIME_CLOSURE_MATERIALIZATION_NON_AUTHORITY {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidAuthority,
            "materialization nonauthority differs",
        ));
    }
    let upstream = replay_upstream_unchecked(request)?;
    let synthetic = synthetic_upstream_envelope_form()?;
    match request.input_class {
        RuntimeClosureMaterializationInputClass::SyntheticProviderFreeFixture
            if request.upstream_envelope != synthetic =>
        {
            return Err(fault(
                RuntimeClosureMaterializationFaultCode::InvalidInputClass,
                "synthetic input class does not contain the exact governed fixture",
            ));
        }
        RuntimeClosureMaterializationInputClass::SuppliedUnobservedDeclaration
            if request.upstream_envelope == synthetic =>
        {
            return Err(fault(
                RuntimeClosureMaterializationFaultCode::InvalidInputClass,
                "known synthetic fixture cannot be relabeled supplied unobserved",
            ));
        }
        _ => {}
    }
    validate_request_upstream_accounts(request, &upstream)?;
    Ok(())
}

fn replay_upstream(
    request: &RuntimeClosureMaterializationRequest,
) -> Result<RuntimeClosureEnvelope, RuntimeClosureMaterializationFault> {
    let upstream = replay_upstream_unchecked(request)?;
    validate_request_upstream_accounts(request, &upstream)?;
    Ok(upstream)
}

fn replay_upstream_unchecked(
    request: &RuntimeClosureMaterializationRequest,
) -> Result<RuntimeClosureEnvelope, RuntimeClosureMaterializationFault> {
    let upstream = from_runtime_closure_envelope_machine_form(&request.upstream_envelope)
        .map_err(upstream_fault)?;
    let replayed = compile_runtime_closure(&upstream.request).map_err(upstream_fault)?;
    let replayed_form =
        to_runtime_closure_envelope_machine_form(&replayed).map_err(upstream_fault)?;
    if replayed != upstream || replayed_form != request.upstream_envelope {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidUpstream,
            "upstream envelope differs from exact deterministic P0 replay",
        ));
    }
    let verification = verify_runtime_closure(&upstream).map_err(upstream_fault)?;
    if verification.canonical_uuid != RUNTIME_CLOSURE_CANONICAL_UUID
        || verification.signature_uuid != RUNTIME_CLOSURE_SIGNATURE_UUID
        || verification.root_count != 2
        || verification.capability_denial_count != 25
        || verification.expected_receipt_has_observations
        || verification.effects != RuntimeClosureEffectAccount::default()
    {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidUpstream,
            "upstream verification identity authority or zero-state account differs",
        ));
    }
    Ok(upstream)
}

fn validate_request_upstream_accounts(
    request: &RuntimeClosureMaterializationRequest,
    upstream: &RuntimeClosureEnvelope,
) -> Result<(), RuntimeClosureMaterializationFault> {
    let receipt_digest = expected_installation_receipt_digest(&upstream.plan.expected_receipt)
        .map_err(upstream_fault)?;
    if request.upstream_request_digest != upstream.request.request_digest
        || request.upstream_plan_digest != upstream.plan.plan_digest
        || request.upstream_envelope_digest != upstream.envelope_digest
        || request.upstream_expected_receipt_digest != receipt_digest
    {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidDigest,
            "request upstream semantic digest account differs",
        ));
    }
    Ok(())
}

fn derive_plan(
    request: &RuntimeClosureMaterializationRequest,
    upstream: &RuntimeClosureEnvelope,
) -> Result<RuntimeClosureMaterializationPlan, RuntimeClosureMaterializationFault> {
    let nodes = upstream
        .plan
        .material_nodes
        .iter()
        .map(|node| (node.node_id.clone(), node))
        .collect::<BTreeMap<_, _>>();
    let edges = upstream
        .plan
        .producer_edges
        .iter()
        .map(|edge| (edge.output.clone(), edge))
        .collect::<BTreeMap<_, _>>();
    let roots = [
        upstream.plan.bootstrap_node_id.clone(),
        upstream.plan.installation_sop_node_id.clone(),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if roots.len() != 2 || upstream.plan.material_nodes.len() < 2 {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidUpstream,
            "upstream root account differs",
        ));
    }

    let mut operations = Vec::new();
    let mut root_operations = BTreeMap::new();
    let mut prerequisite_operations = BTreeMap::new();
    let mut production_operations = BTreeMap::new();
    let mut target_operations = BTreeMap::new();
    let mut stage_operations = BTreeMap::new();
    let mut verify_operations = BTreeMap::new();

    for root_id in &roots {
        let node = nodes.get(root_id).ok_or_else(|| {
            fault(
                RuntimeClosureMaterializationFaultCode::InvalidUpstream,
                "upstream root lacks material node",
            )
        })?;
        let operation = make_operation(
            request,
            next_ordinal(&operations)?,
            RuntimeClosureMaterializationPhase::SeedValidation,
            RuntimeClosureMaterializationOperationKind::ValidateSeedRoot,
            root_id.clone(),
            Some(root_id.clone()),
            None,
            None,
            None,
            BTreeSet::new(),
            Some(node.target.clone()),
            Some(node.expected_sha256.clone()),
            Some(node.expected_bytes),
            Some(node.verifier_profile.clone()),
            Some(node.executable),
        )?;
        root_operations.insert(root_id.clone(), operation.operation_id.clone());
        operations.push(operation);
    }

    let mut prerequisites = upstream.plan.prerequisites.iter().collect::<Vec<_>>();
    prerequisites.sort_by(|left, right| left.prerequisite_id.cmp(&right.prerequisite_id));
    for prerequisite in prerequisites {
        let mut operation = make_operation(
            request,
            next_ordinal(&operations)?,
            RuntimeClosureMaterializationPhase::PrerequisiteResolution,
            RuntimeClosureMaterializationOperationKind::ResolvePrerequisite,
            prerequisite.prerequisite_id.clone(),
            None,
            Some(prerequisite.prerequisite_id.clone()),
            None,
            None,
            BTreeSet::new(),
            None,
            None,
            None,
            None,
            None,
        )?;
        operation.required_denied_capabilities = required_capabilities(
            RuntimeClosureMaterializationOperationKind::ResolvePrerequisite,
            Some(prerequisite),
        );
        operation.operation_digest = runtime_closure_materialization_operation_digest(&operation)?;
        prerequisite_operations.insert(
            prerequisite.prerequisite_id.clone(),
            operation.operation_id.clone(),
        );
        operations.push(operation);
    }
    let all_prerequisite_dependencies = prerequisite_operations
        .values()
        .cloned()
        .collect::<BTreeSet<_>>();

    for node_id in &upstream.plan.topological_order {
        if roots.contains(node_id) {
            continue;
        }
        let node = nodes.get(node_id).ok_or_else(|| {
            fault(
                RuntimeClosureMaterializationFaultCode::InvalidUpstream,
                "topological node lacks material account",
            )
        })?;
        let edge = edges.get(node_id).ok_or_else(|| {
            fault(
                RuntimeClosureMaterializationFaultCode::InvalidUpstream,
                "nonroot node lacks producer edge",
            )
        })?;
        let kind = production_kind(node.kind, edge.source.kind)?;
        let mut dependencies = all_prerequisite_dependencies.clone();
        for input in &edge.inputs {
            let dependency = if roots.contains(input) {
                root_operations.get(input)
            } else {
                production_operations.get(input)
            }
            .ok_or_else(|| {
                fault(
                    RuntimeClosureMaterializationFaultCode::InvalidDependency,
                    "producer input operation is unavailable or forward",
                )
            })?;
            dependencies.insert(dependency.clone());
        }
        let operation = make_operation(
            request,
            next_ordinal(&operations)?,
            RuntimeClosureMaterializationPhase::MaterialProduction,
            kind,
            node_id.clone(),
            Some(node_id.clone()),
            None,
            Some(edge.edge_id.clone()),
            Some(edge.source.source_id.clone()),
            dependencies,
            Some(node.target.clone()),
            Some(node.expected_sha256.clone()),
            Some(node.expected_bytes),
            Some(node.verifier_profile.clone()),
            Some(node.executable),
        )?;
        production_operations.insert(node_id.clone(), operation.operation_id.clone());
        operations.push(operation);
    }

    for node_id in &upstream.plan.topological_order {
        let node = nodes.get(node_id).ok_or_else(|| {
            fault(
                RuntimeClosureMaterializationFaultCode::InvalidUpstream,
                "target node lacks material account",
            )
        })?;
        let operation = make_operation(
            request,
            next_ordinal(&operations)?,
            RuntimeClosureMaterializationPhase::TargetPreparation,
            RuntimeClosureMaterializationOperationKind::PrepareTarget,
            node_id.clone(),
            Some(node_id.clone()),
            None,
            None,
            None,
            all_prerequisite_dependencies.clone(),
            Some(node.target.clone()),
            Some(node.expected_sha256.clone()),
            Some(node.expected_bytes),
            Some(node.verifier_profile.clone()),
            Some(node.executable),
        )?;
        target_operations.insert(node_id.clone(), operation.operation_id.clone());
        operations.push(operation);
    }

    for node_id in &upstream.plan.topological_order {
        let node = nodes.get(node_id).ok_or_else(|| {
            fault(
                RuntimeClosureMaterializationFaultCode::InvalidUpstream,
                "stage node lacks material account",
            )
        })?;
        let producer = if roots.contains(node_id) {
            root_operations.get(node_id)
        } else {
            production_operations.get(node_id)
        }
        .ok_or_else(|| {
            fault(
                RuntimeClosureMaterializationFaultCode::InvalidDependency,
                "stage producer operation is unavailable",
            )
        })?;
        let dependencies = [
            target_operations.get(node_id).cloned().ok_or_else(|| {
                fault(
                    RuntimeClosureMaterializationFaultCode::InvalidDependency,
                    "stage target operation is unavailable",
                )
            })?,
            producer.clone(),
        ]
        .into_iter()
        .collect();
        let operation = make_operation(
            request,
            next_ordinal(&operations)?,
            RuntimeClosureMaterializationPhase::MaterialStaging,
            RuntimeClosureMaterializationOperationKind::StageMaterial,
            node_id.clone(),
            Some(node_id.clone()),
            None,
            None,
            None,
            dependencies,
            Some(node.target.clone()),
            Some(node.expected_sha256.clone()),
            Some(node.expected_bytes),
            Some(node.verifier_profile.clone()),
            Some(node.executable),
        )?;
        stage_operations.insert(node_id.clone(), operation.operation_id.clone());
        operations.push(operation);
    }

    for node_id in &upstream.plan.topological_order {
        let node = nodes.get(node_id).ok_or_else(|| {
            fault(
                RuntimeClosureMaterializationFaultCode::InvalidUpstream,
                "verification node lacks material account",
            )
        })?;
        let dependencies = [stage_operations.get(node_id).cloned().ok_or_else(|| {
            fault(
                RuntimeClosureMaterializationFaultCode::InvalidDependency,
                "verification stage operation is unavailable",
            )
        })?]
        .into_iter()
        .collect();
        let operation = make_operation(
            request,
            next_ordinal(&operations)?,
            RuntimeClosureMaterializationPhase::MaterialVerification,
            RuntimeClosureMaterializationOperationKind::VerifyMaterial,
            node_id.clone(),
            Some(node_id.clone()),
            None,
            None,
            None,
            dependencies,
            Some(node.target.clone()),
            Some(node.expected_sha256.clone()),
            Some(node.expected_bytes),
            Some(node.verifier_profile.clone()),
            Some(node.executable),
        )?;
        verify_operations.insert(node_id.clone(), operation.operation_id.clone());
        operations.push(operation);
    }

    let rollback = make_operation(
        request,
        next_ordinal(&operations)?,
        RuntimeClosureMaterializationPhase::RollbackPreparation,
        RuntimeClosureMaterializationOperationKind::PrepareRollback,
        request.materialization_id.clone(),
        None,
        None,
        None,
        None,
        verify_operations.values().cloned().collect(),
        None,
        None,
        None,
        None,
        None,
    )?;
    let rollback_id = rollback.operation_id.clone();
    operations.push(rollback);

    let closure = make_operation(
        request,
        next_ordinal(&operations)?,
        RuntimeClosureMaterializationPhase::ClosureVerification,
        RuntimeClosureMaterializationOperationKind::VerifyClosure,
        request.materialization_id.clone(),
        None,
        None,
        None,
        None,
        [rollback_id].into_iter().collect(),
        None,
        None,
        None,
        None,
        None,
    )?;
    let closure_id = closure.operation_id.clone();
    operations.push(closure);

    let receipt_operation = make_operation(
        request,
        next_ordinal(&operations)?,
        RuntimeClosureMaterializationPhase::ReceiptCandidate,
        RuntimeClosureMaterializationOperationKind::EmitReceiptCandidate,
        request.materialization_id.clone(),
        None,
        None,
        None,
        None,
        [closure_id].into_iter().collect(),
        None,
        None,
        None,
        None,
        None,
    )?;
    operations.push(receipt_operation);

    let node_count = upstream.plan.material_nodes.len();
    let prerequisite_count = upstream.plan.prerequisites.len();
    let expected_count = node_count
        .checked_mul(4)
        .and_then(|value| value.checked_add(prerequisite_count))
        .and_then(|value| value.checked_add(3))
        .ok_or_else(|| {
            fault(
                RuntimeClosureMaterializationFaultCode::ArithmeticOverflow,
                "operation formula overflow",
            )
        })?;
    if operations.len() != expected_count || !(11..=1_155).contains(&operations.len()) {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidOperation,
            "operation count formula or imported bound differs",
        ));
    }
    let operation_digests = operations
        .iter()
        .map(|operation| operation.operation_digest.clone())
        .collect::<Vec<_>>();
    let ordered_operation_digest =
        runtime_closure_materialization_ordered_operation_digest(&operations)?;
    let mut receipt_candidate = RuntimeClosureMaterializationReceiptCandidate {
        materialization_id: request.materialization_id.clone(),
        upstream_expected_receipt_digest: request.upstream_expected_receipt_digest.clone(),
        operation_count: count_u32(operations.len())?,
        ordered_operation_digest,
        observation_count: 0,
        executed_operation_count: 0,
        materialized_node_count: 0,
        verified_node_count: 0,
        filesystem_result_count: 0,
        verifier_result_count: 0,
        installation_state_asserted: false,
        activation_state_asserted: false,
        rollback_ready_asserted: false,
        successor_recognition_authority: false,
        receipt_candidate_digest: empty_digest(),
    };
    receipt_candidate.receipt_candidate_digest =
        runtime_closure_materialization_receipt_candidate_digest(&receipt_candidate)?;
    let mut plan = RuntimeClosureMaterializationPlan {
        status: "materialization_plan_compiled_effectless_awaiting_separate_commission".to_owned(),
        materialization_id: request.materialization_id.clone(),
        input_class: request.input_class,
        upstream_canonical_uuid: RUNTIME_CLOSURE_CANONICAL_UUID.to_owned(),
        upstream_signature_uuid: RUNTIME_CLOSURE_SIGNATURE_UUID.to_owned(),
        upstream_request_id: upstream.request.request_id.clone(),
        upstream_closure_id: upstream.request.closure_id.clone(),
        upstream_request_digest: request.upstream_request_digest.clone(),
        upstream_plan_digest: request.upstream_plan_digest.clone(),
        upstream_envelope_digest: request.upstream_envelope_digest.clone(),
        phases: runtime_closure_materialization_phases(),
        operations,
        unresolved_operation_digests: operation_digests,
        capability_denials: runtime_closure_required_capability_denials(),
        receipt_candidate,
        execution_authorized: false,
        request_digest: request.request_digest.clone(),
        plan_digest: empty_digest(),
    };
    plan.plan_digest = runtime_closure_materialization_plan_digest(&plan)?;
    validate_plan(&plan, request, upstream)?;
    Ok(plan)
}

#[allow(clippy::too_many_arguments)]
fn make_operation(
    request: &RuntimeClosureMaterializationRequest,
    ordinal: u32,
    phase: RuntimeClosureMaterializationPhase,
    kind: RuntimeClosureMaterializationOperationKind,
    subject_id: SemanticId,
    p0_node_id: Option<SemanticId>,
    p0_prerequisite_id: Option<SemanticId>,
    p0_edge_id: Option<SemanticId>,
    p0_source_id: Option<SemanticId>,
    dependencies: BTreeSet<SemanticId>,
    target: Option<String>,
    expected_sha256: Option<ContentDigest>,
    expected_bytes: Option<u64>,
    verifier_profile: Option<String>,
    executable: Option<RuntimeClosureExecutableDisposition>,
) -> Result<RuntimeClosureMaterializationOperation, RuntimeClosureMaterializationFault> {
    let operation_id = derive_operation_id(&request.materialization_id, phase, kind, &subject_id)?;
    let mut operation = RuntimeClosureMaterializationOperation {
        ordinal,
        operation_id,
        phase,
        kind,
        subject_id: subject_id.clone(),
        p0_node_id,
        p0_prerequisite_id,
        p0_edge_id,
        p0_source_id,
        dependencies: dependencies.into_iter().collect(),
        target,
        expected_sha256,
        expected_bytes,
        verifier_profile,
        executable,
        required_denied_capabilities: required_capabilities(kind, None),
        unresolved_reason: format!(
            "separate commission required before {} for {}",
            operation_kind_token(kind),
            subject_id
        ),
        disposition: RuntimeClosureMaterializationDisposition::ProposedAwaitingSeparateCommission,
        execution_authorized: false,
        observed: false,
        executed: false,
        operation_digest: empty_digest(),
    };
    operation.operation_digest = runtime_closure_materialization_operation_digest(&operation)?;
    Ok(operation)
}

fn derive_operation_id(
    materialization_id: &SemanticId,
    phase: RuntimeClosureMaterializationPhase,
    kind: RuntimeClosureMaterializationOperationKind,
    subject_id: &SemanticId,
) -> Result<SemanticId, RuntimeClosureMaterializationFault> {
    let components = (
        materialization_id.as_str(),
        phase_token(phase),
        operation_kind_token(kind),
        subject_id.as_str(),
    );
    let digest = sha256_form(OPERATION_ID_DOMAIN, &components)?;
    let value = digest.value;
    semantic_id(format!(
        "operation:{}-{}-5{}-8{}-{}",
        &value[0..8],
        &value[8..12],
        &value[13..16],
        &value[17..20],
        &value[20..32]
    ))
}

fn production_kind(
    material: RuntimeClosureMaterialKind,
    source: RuntimeClosureSourceKind,
) -> Result<RuntimeClosureMaterializationOperationKind, RuntimeClosureMaterializationFault> {
    match (material, source) {
        (RuntimeClosureMaterialKind::Derived, RuntimeClosureSourceKind::DeterministicTransform) => {
            Ok(RuntimeClosureMaterializationOperationKind::ApplyDeterministicTransform)
        }
        (RuntimeClosureMaterialKind::Built, RuntimeClosureSourceKind::SourceBuild) => {
            Ok(RuntimeClosureMaterializationOperationKind::RunSourceBuild)
        }
        (
            RuntimeClosureMaterialKind::Acquired,
            RuntimeClosureSourceKind::ContentAddressedArtifact,
        ) => Ok(RuntimeClosureMaterializationOperationKind::AcquireContentAddressedArtifact),
        (
            RuntimeClosureMaterialKind::ExplicitlySupplied,
            RuntimeClosureSourceKind::SuppliedDescriptor,
        ) => Ok(RuntimeClosureMaterializationOperationKind::AcceptExplicitlySuppliedMaterial),
        (
            RuntimeClosureMaterialKind::GeneratedConfiguration,
            RuntimeClosureSourceKind::GeneratedConfiguration,
        ) => Ok(RuntimeClosureMaterializationOperationKind::GenerateConfiguration),
        _ => Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidOperation,
            "material and source kinds do not select one production operation",
        )),
    }
}

fn required_capabilities(
    kind: RuntimeClosureMaterializationOperationKind,
    prerequisite: Option<&RuntimeClosurePrerequisite>,
) -> BTreeSet<RuntimeClosureCapabilityDenial> {
    use RuntimeClosureCapabilityDenial as D;
    use RuntimeClosureMaterializationOperationKind as K;
    let values: &[D] = match kind {
        K::ValidateSeedRoot => &[D::FilesystemRead],
        K::ResolvePrerequisite => match prerequisite.map(|item| item.kind) {
            Some(
                RuntimeClosurePrerequisiteKind::Network
                | RuntimeClosurePrerequisiteKind::ArtifactReservoir,
            ) => &[D::NetworkContact],
            Some(RuntimeClosurePrerequisiteKind::ExternalCustody) => &[D::RemoteAccess],
            Some(RuntimeClosurePrerequisiteKind::Hardware) => &[D::HardwareEffect],
            Some(RuntimeClosurePrerequisiteKind::OperatorAcceptance) => &[D::ExternalEffect],
            _ => &[D::EnvironmentRead],
        },
        K::ApplyDeterministicTransform => &[D::FilesystemRead, D::FilesystemWrite],
        K::RunSourceBuild => &[
            D::FilesystemRead,
            D::FilesystemWrite,
            D::ProcessSpawn,
            D::CompilerExec,
        ],
        K::AcquireContentAddressedArtifact => {
            &[D::NetworkContact, D::ArtifactDownload, D::FilesystemWrite]
        }
        K::AcceptExplicitlySuppliedMaterial => &[D::FilesystemRead, D::FilesystemWrite],
        K::GenerateConfiguration => &[D::FilesystemWrite],
        K::PrepareTarget => &[D::FilesystemWrite, D::PermissionChange],
        K::StageMaterial => &[D::FilesystemRead, D::FilesystemWrite],
        K::VerifyMaterial | K::VerifyClosure => &[D::FilesystemRead],
        K::PrepareRollback => &[
            D::FilesystemRead,
            D::FilesystemWrite,
            D::FilesystemDelete,
            D::Rollback,
        ],
        K::EmitReceiptCandidate => &[D::FilesystemWrite],
    };
    values.iter().copied().collect()
}

fn validate_plan(
    plan: &RuntimeClosureMaterializationPlan,
    request: &RuntimeClosureMaterializationRequest,
    upstream: &RuntimeClosureEnvelope,
) -> Result<(), RuntimeClosureMaterializationFault> {
    if plan.status != "materialization_plan_compiled_effectless_awaiting_separate_commission"
        || plan.materialization_id != request.materialization_id
        || plan.input_class != request.input_class
        || plan.upstream_canonical_uuid != RUNTIME_CLOSURE_CANONICAL_UUID
        || plan.upstream_signature_uuid != RUNTIME_CLOSURE_SIGNATURE_UUID
        || plan.upstream_request_id != upstream.request.request_id
        || plan.upstream_closure_id != upstream.request.closure_id
        || plan.upstream_request_digest != request.upstream_request_digest
        || plan.upstream_plan_digest != request.upstream_plan_digest
        || plan.upstream_envelope_digest != request.upstream_envelope_digest
        || plan.request_digest != request.request_digest
    {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidOperation,
            "materialization plan identity or upstream account differs",
        ));
    }
    if plan.phases != runtime_closure_materialization_phases() {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidPhase,
            "materialization phase order differs",
        ));
    }
    let expected_count = upstream
        .plan
        .material_nodes
        .len()
        .checked_mul(4)
        .and_then(|value| value.checked_add(upstream.plan.prerequisites.len()))
        .and_then(|value| value.checked_add(3))
        .ok_or_else(|| {
            fault(
                RuntimeClosureMaterializationFaultCode::ArithmeticOverflow,
                "operation count validation overflow",
            )
        })?;
    if plan.operations.len() != expected_count || !(11..=1_155).contains(&plan.operations.len()) {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidOperation,
            "materialization operation count differs",
        ));
    }
    let denied = runtime_closure_required_capability_denials();
    if plan.capability_denials != denied || plan.capability_denials.len() != 25 {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidDenial,
            "materialization capability denial set differs",
        ));
    }
    let mut identities = BTreeSet::new();
    let mut operation_digests = Vec::new();
    for (index, operation) in plan.operations.iter().enumerate() {
        if operation.ordinal
            != count_u32(index.checked_add(1).ok_or_else(|| {
                fault(
                    RuntimeClosureMaterializationFaultCode::ArithmeticOverflow,
                    "operation ordinal overflow",
                )
            })?)?
        {
            return Err(fault(
                RuntimeClosureMaterializationFaultCode::InvalidOperation,
                "operation ordinal differs",
            ));
        }
        validate_uuid_id(&operation.operation_id, "operation identity")?;
        if !identities.insert(operation.operation_id.clone()) {
            return Err(fault(
                RuntimeClosureMaterializationFaultCode::InvalidIdentity,
                "operation identity collision",
            ));
        }
        let canonical_dependencies = operation
            .dependencies
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if operation.dependencies.len() > MAX_OPERATION_DEPENDENCIES
            || canonical_dependencies.len() != operation.dependencies.len()
            || operation.dependencies.iter().any(|dependency| {
                !plan.operations[..index]
                    .iter()
                    .any(|prior| &prior.operation_id == dependency)
            })
        {
            return Err(fault(
                RuntimeClosureMaterializationFaultCode::InvalidDependency,
                "operation dependency is duplicate self missing or forward",
            ));
        }
        if canonical_dependencies != operation.dependencies {
            return Err(fault(
                RuntimeClosureMaterializationFaultCode::InvalidDependency,
                "operation dependencies are not in canonical identity order",
            ));
        }
        if operation.required_denied_capabilities.is_empty()
            || !operation.required_denied_capabilities.is_subset(&denied)
            || operation.disposition
                != RuntimeClosureMaterializationDisposition::ProposedAwaitingSeparateCommission
            || operation.execution_authorized
            || operation.observed
            || operation.executed
            || !valid_text(&operation.unresolved_reason)
        {
            return Err(fault(
                RuntimeClosureMaterializationFaultCode::InvalidAuthority,
                "operation denial unresolved disposition or zero-state account differs",
            ));
        }
        if let Some(digest) = &operation.expected_sha256 {
            validate_digest(digest, "operation expected digest")?;
        }
        if runtime_closure_materialization_operation_digest(operation)?
            != operation.operation_digest
        {
            return Err(fault(
                RuntimeClosureMaterializationFaultCode::InvalidDigest,
                "operation digest differs",
            ));
        }
        operation_digests.push(operation.operation_digest.clone());
    }
    if plan.unresolved_operation_digests != operation_digests {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidOperation,
            "unresolved operation digest account differs",
        ));
    }
    validate_receipt_candidate(&plan.receipt_candidate, request, &operation_digests)?;
    if plan.execution_authorized {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidAuthority,
            "materialization plan authorizes execution",
        ));
    }
    if runtime_closure_materialization_plan_digest(plan)? != plan.plan_digest {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidDigest,
            "materialization plan digest differs",
        ));
    }
    Ok(())
}

fn validate_receipt_candidate(
    receipt: &RuntimeClosureMaterializationReceiptCandidate,
    request: &RuntimeClosureMaterializationRequest,
    operation_digests: &[ContentDigest],
) -> Result<(), RuntimeClosureMaterializationFault> {
    let expected_ordered = sha256_form(ORDERED_OPERATION_DOMAIN, &operation_digests)?;
    if receipt.materialization_id != request.materialization_id
        || receipt.upstream_expected_receipt_digest != request.upstream_expected_receipt_digest
        || receipt.operation_count != count_u32(operation_digests.len())?
        || receipt.ordered_operation_digest != expected_ordered
        || receipt.observation_count != 0
        || receipt.executed_operation_count != 0
        || receipt.materialized_node_count != 0
        || receipt.verified_node_count != 0
        || receipt.filesystem_result_count != 0
        || receipt.verifier_result_count != 0
        || receipt.installation_state_asserted
        || receipt.activation_state_asserted
        || receipt.rollback_ready_asserted
        || receipt.successor_recognition_authority
    {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidReceipt,
            "receipt candidate identity or zero-state account differs",
        ));
    }
    if runtime_closure_materialization_receipt_candidate_digest(receipt)?
        != receipt.receipt_candidate_digest
    {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidDigest,
            "receipt candidate digest differs",
        ));
    }
    Ok(())
}

fn verification_without_validation(
    envelope: &RuntimeClosureMaterializationEnvelope,
) -> Result<RuntimeClosureMaterializationVerification, RuntimeClosureMaterializationFault> {
    let upstream = replay_upstream(&envelope.request)?;
    Ok(RuntimeClosureMaterializationVerification {
        profile: RUNTIME_CLOSURE_MATERIALIZATION_VERIFICATION_PROFILE.to_owned(),
        status: "materialization_plan_compiled_effectless_verified_awaiting_separate_commission"
            .to_owned(),
        canonical_uuid: RUNTIME_CLOSURE_MATERIALIZATION_CANONICAL_UUID.to_owned(),
        signature_uuid: RUNTIME_CLOSURE_MATERIALIZATION_SIGNATURE_UUID.to_owned(),
        upstream_canonical_uuid: RUNTIME_CLOSURE_CANONICAL_UUID.to_owned(),
        upstream_signature_uuid: RUNTIME_CLOSURE_SIGNATURE_UUID.to_owned(),
        input_class: envelope.request.input_class,
        authority: RuntimeClosureMaterializationAuthority::SuppliedDataMaterializationPlanningOnly,
        request_digest: envelope.request.request_digest.clone(),
        plan_digest: envelope.plan.plan_digest.clone(),
        envelope_digest: envelope.envelope_digest.clone(),
        upstream_request_digest: envelope.request.upstream_request_digest.clone(),
        upstream_plan_digest: envelope.request.upstream_plan_digest.clone(),
        upstream_envelope_digest: envelope.request.upstream_envelope_digest.clone(),
        upstream_root_count: 2,
        upstream_material_node_count: count_u32(upstream.plan.material_nodes.len())?,
        upstream_producer_edge_count: count_u32(upstream.plan.producer_edges.len())?,
        upstream_prerequisite_count: count_u32(upstream.plan.prerequisites.len())?,
        phase_count: 9,
        operation_kind_count: 13,
        operation_count: count_u32(envelope.plan.operations.len())?,
        unresolved_operation_count: count_u32(envelope.plan.unresolved_operation_digests.len())?,
        capability_denial_count: count_u32(envelope.plan.capability_denials.len())?,
        evidence_reference_count: count_u32(envelope.request.evidence_refs.len())?,
        receipt_zero_field_count: 10,
        upstream_recompiled_byte_identical: true,
        deterministic_double_compilation_verified: true,
        execution_authorized: false,
        effects: RuntimeClosureEffectAccount::default(),
    })
}

fn evidence_manifest(
    request_file: &str,
    envelope_file: &str,
    verification_file: &str,
    verification: &RuntimeClosureMaterializationVerification,
) -> Result<RuntimeClosureMaterializationEvidenceManifest, RuntimeClosureMaterializationFault> {
    let files = BTreeMap::from([
        (
            "envelope".to_owned(),
            evidence_file(ENVELOPE_EVIDENCE_PATH, envelope_file)?,
        ),
        (
            "request".to_owned(),
            evidence_file(REQUEST_EVIDENCE_PATH, request_file)?,
        ),
        (
            "verification".to_owned(),
            evidence_file(VERIFICATION_EVIDENCE_PATH, verification_file)?,
        ),
    ]);
    Ok(RuntimeClosureMaterializationEvidenceManifest {
        profile: RUNTIME_CLOSURE_MATERIALIZATION_EVIDENCE_PROFILE.to_owned(),
        canonical_uuid: RUNTIME_CLOSURE_MATERIALIZATION_CANONICAL_UUID.to_owned(),
        signature_uuid: RUNTIME_CLOSURE_MATERIALIZATION_SIGNATURE_UUID.to_owned(),
        replay_count: 2,
        files,
        request_digest: verification.request_digest.clone(),
        plan_digest: verification.plan_digest.clone(),
        envelope_digest: verification.envelope_digest.clone(),
        upstream_request_digest: verification.upstream_request_digest.clone(),
        upstream_plan_digest: verification.upstream_plan_digest.clone(),
        upstream_envelope_digest: verification.upstream_envelope_digest.clone(),
        phase_count: verification.phase_count,
        operation_kind_count: verification.operation_kind_count,
        operation_count: verification.operation_count,
        unresolved_operation_count: verification.unresolved_operation_count,
        capability_denial_count: verification.capability_denial_count,
        evidence_reference_count: verification.evidence_reference_count,
        receipt_zero_field_count: verification.receipt_zero_field_count,
        execution_authorized: false,
        effects: verification.effects.clone(),
    })
}

fn evidence_file(
    path: &str,
    value: &str,
) -> Result<RuntimeClosureMaterializationEvidenceFile, RuntimeClosureMaterializationFault> {
    Ok(RuntimeClosureMaterializationEvidenceFile {
        path: path.to_owned(),
        bytes: count_u64(value.len())?,
        sha256: sha256_bytes(value.as_bytes()),
    })
}

fn ensure_evidence_bundle_bound(
    bundle: &RuntimeClosureMaterializationEvidenceBundle,
) -> Result<(), RuntimeClosureMaterializationFault> {
    let total = [
        bundle.request_file.len(),
        bundle.envelope_file.len(),
        bundle.verification_file.len(),
        bundle.manifest_file.len(),
    ]
    .into_iter()
    .try_fold(0_usize, |total, next| total.checked_add(next))
    .ok_or_else(|| {
        fault(
            RuntimeClosureMaterializationFaultCode::ArithmeticOverflow,
            "materialization evidence byte total overflow",
        )
    })?;
    if total > RUNTIME_CLOSURE_MATERIALIZATION_MAX_EVIDENCE_BYTES {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidBound,
            "materialization evidence exceeds 8388608 bytes",
        ));
    }
    for (name, body) in [
        (REQUEST_EVIDENCE_PATH, bundle.request_file.as_str()),
        (ENVELOPE_EVIDENCE_PATH, bundle.envelope_file.as_str()),
        (
            VERIFICATION_EVIDENCE_PATH,
            bundle.verification_file.as_str(),
        ),
        ("manifest.json", bundle.manifest_file.as_str()),
    ] {
        canonical_file_body(body, name)?;
    }
    Ok(())
}

fn canonical_file(value: String) -> String {
    format!("{value}\n")
}

fn canonical_file_body<'a>(
    value: &'a str,
    label: &str,
) -> Result<&'a str, RuntimeClosureMaterializationFault> {
    let Some(body) = value.strip_suffix('\n') else {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidEvidence,
            format!("{label} lacks one LF terminator"),
        ));
    };
    if body.contains('\r') || body.contains('\n') {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidEvidence,
            format!("{label} contains embedded line terminators"),
        ));
    }
    Ok(body)
}

fn synthetic_upstream_envelope_form() -> Result<String, RuntimeClosureMaterializationFault> {
    let request = synthetic_runtime_closure_request().map_err(upstream_fault)?;
    let envelope = compile_runtime_closure(&request).map_err(upstream_fault)?;
    to_runtime_closure_envelope_machine_form(&envelope).map_err(upstream_fault)
}

fn next_ordinal(
    operations: &[RuntimeClosureMaterializationOperation],
) -> Result<u32, RuntimeClosureMaterializationFault> {
    count_u32(operations.len().checked_add(1).ok_or_else(|| {
        fault(
            RuntimeClosureMaterializationFaultCode::ArithmeticOverflow,
            "operation ordinal overflow",
        )
    })?)
}

fn phase_token(phase: RuntimeClosureMaterializationPhase) -> &'static str {
    use RuntimeClosureMaterializationPhase as P;
    match phase {
        P::SeedValidation => "seed_validation",
        P::PrerequisiteResolution => "prerequisite_resolution",
        P::MaterialProduction => "material_production",
        P::TargetPreparation => "target_preparation",
        P::MaterialStaging => "material_staging",
        P::MaterialVerification => "material_verification",
        P::RollbackPreparation => "rollback_preparation",
        P::ClosureVerification => "closure_verification",
        P::ReceiptCandidate => "receipt_candidate",
    }
}

fn operation_kind_token(kind: RuntimeClosureMaterializationOperationKind) -> &'static str {
    use RuntimeClosureMaterializationOperationKind as K;
    match kind {
        K::ValidateSeedRoot => "validate_seed_root",
        K::ResolvePrerequisite => "resolve_prerequisite",
        K::ApplyDeterministicTransform => "apply_deterministic_transform",
        K::RunSourceBuild => "run_source_build",
        K::AcquireContentAddressedArtifact => "acquire_content_addressed_artifact",
        K::AcceptExplicitlySuppliedMaterial => "accept_explicitly_supplied_material",
        K::GenerateConfiguration => "generate_configuration",
        K::PrepareTarget => "prepare_target",
        K::StageMaterial => "stage_material",
        K::VerifyMaterial => "verify_material",
        K::PrepareRollback => "prepare_rollback",
        K::VerifyClosure => "verify_closure",
        K::EmitReceiptCandidate => "emit_receipt_candidate",
    }
}

fn validate_uuid_id(
    identity: &SemanticId,
    label: &str,
) -> Result<(), RuntimeClosureMaterializationFault> {
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
            RuntimeClosureMaterializationFaultCode::InvalidIdentity,
            format!("{label} is not a nonnil lowercase UUID-bearing identity"),
        ));
    }
    Ok(())
}

fn validate_reference(
    reference: &SemanticId,
    label: &str,
) -> Result<(), RuntimeClosureMaterializationFault> {
    let value = reference.as_str();
    if value.is_empty()
        || value.len() > 512
        || value != value.to_ascii_lowercase()
        || value.contains("latest")
    {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidIdentity,
            format!("{label} is not a bounded immutable lowercase reference"),
        ));
    }
    Ok(())
}

fn validate_digest(
    digest: &ContentDigest,
    label: &str,
) -> Result<(), RuntimeClosureMaterializationFault> {
    if digest.algorithm != "sha256"
        || digest.value.len() != 64
        || !digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidDigest,
            format!("{label} is not lowercase SHA256"),
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

fn semantic_id(value: impl Into<String>) -> Result<SemanticId, RuntimeClosureMaterializationFault> {
    SemanticId::new(value).map_err(|error| {
        fault(
            RuntimeClosureMaterializationFaultCode::InvalidIdentity,
            error.to_string(),
        )
    })
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn count_u32(value: usize) -> Result<u32, RuntimeClosureMaterializationFault> {
    u32::try_from(value).map_err(|_| {
        fault(
            RuntimeClosureMaterializationFaultCode::ArithmeticOverflow,
            "usize to u32 count conversion failed",
        )
    })
}

fn count_u64(value: usize) -> Result<u64, RuntimeClosureMaterializationFault> {
    u64::try_from(value).map_err(|_| {
        fault(
            RuntimeClosureMaterializationFaultCode::ArithmeticOverflow,
            "usize to u64 byte conversion failed",
        )
    })
}

fn sha256_form<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<ContentDigest, RuntimeClosureMaterializationFault> {
    let body = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + body.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&body);
    Ok(sha256_bytes(&bytes))
}

fn to_machine_form<T: Serialize>(value: &T) -> Result<String, RuntimeClosureMaterializationFault> {
    serde_json::to_string(value).map_err(machine_fault)
}

fn parse_bounded<T: DeserializeOwned + Serialize>(
    value: &str,
) -> Result<T, RuntimeClosureMaterializationFault> {
    parse_bounded_with_limit(
        value,
        RUNTIME_CLOSURE_MATERIALIZATION_MAX_MACHINE_FORM_BYTES,
    )
}

fn parse_bounded_with_limit<T: DeserializeOwned + Serialize>(
    value: &str,
    limit: usize,
) -> Result<T, RuntimeClosureMaterializationFault> {
    if value.len() > limit {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidBound,
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
            RuntimeClosureMaterializationFaultCode::InvalidMachineForm,
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
) -> Result<(), RuntimeClosureMaterializationFault> {
    if depth > MAX_DEPTH {
        return Err(fault(
            RuntimeClosureMaterializationFaultCode::InvalidMachineForm,
            "machine form exceeds depth 48",
        ));
    }
    match value {
        Value::Object(map) => {
            *fields = fields.checked_add(map.len()).ok_or_else(|| {
                fault(
                    RuntimeClosureMaterializationFaultCode::ArithmeticOverflow,
                    "machine form field count overflow",
                )
            })?;
            if *fields > MAX_FIELDS {
                return Err(fault(
                    RuntimeClosureMaterializationFaultCode::InvalidMachineForm,
                    "machine form exceeds 32768 fields",
                ));
            }
            for (key, child) in map {
                if !valid_text(key) {
                    return Err(fault(
                        RuntimeClosureMaterializationFaultCode::InvalidMachineForm,
                        "machine field text differs",
                    ));
                }
                validate_json_shape(child, depth + 1, fields, Some(key))?;
            }
        }
        Value::Array(values) => {
            let is_set = matches!(
                parent_key,
                Some(
                    "evidence_refs"
                        | "dependencies"
                        | "required_denied_capabilities"
                        | "capability_denials"
                )
            );
            if is_set && values.iter().all(Value::is_string) {
                let unique = values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>();
                if unique.len() != values.len() {
                    return Err(fault(
                        RuntimeClosureMaterializationFaultCode::InvalidMachineForm,
                        "machine form contains duplicate set member",
                    ));
                }
            }
            for child in values {
                validate_json_shape(child, depth + 1, fields, None)?;
            }
        }
        Value::String(text) => {
            let file_body = matches!(
                parent_key,
                Some(
                    "upstream_envelope"
                        | "request_file"
                        | "envelope_file"
                        | "verification_file"
                        | "manifest_file"
                )
            );
            if (!file_body && !valid_text(text))
                || (file_body && text.len() > RUNTIME_CLOSURE_MATERIALIZATION_MAX_EVIDENCE_BYTES)
            {
                return Err(fault(
                    RuntimeClosureMaterializationFaultCode::InvalidMachineForm,
                    "machine text differs",
                ));
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn fault(
    code: RuntimeClosureMaterializationFaultCode,
    detail: impl Into<String>,
) -> RuntimeClosureMaterializationFault {
    RuntimeClosureMaterializationFault {
        code,
        detail: detail.into(),
    }
}

fn upstream_fault(error: crate::RuntimeClosureFault) -> RuntimeClosureMaterializationFault {
    fault(
        RuntimeClosureMaterializationFaultCode::InvalidUpstream,
        error.to_string(),
    )
}

fn machine_fault(error: serde_json::Error) -> RuntimeClosureMaterializationFault {
    fault(
        RuntimeClosureMaterializationFaultCode::InvalidMachineForm,
        error.to_string(),
    )
}
