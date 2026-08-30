//! Pure provider-free runtime-closure compilation for RIS-P0 Revision 0.2.
//!
//! The module validates supplied data, normalizes a closed material graph,
//! derives an effectless plan, and independently replays retained evidence.
//! It performs no filesystem, environment, clock, process, network, provider,
//! model, MCP, Git, workspace, secret, remote, hardware, or external action.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ContentDigest, SemanticId, sha256_bytes};

pub const RUNTIME_CLOSURE_REQUEST_PROFILE: &str = "cantor-runtime-closure-request/0.2";
pub const RUNTIME_CLOSURE_ENVELOPE_PROFILE: &str = "cantor-runtime-closure-envelope/0.2";
pub const RUNTIME_CLOSURE_VERIFICATION_PROFILE: &str = "cantor-runtime-closure-verification/0.2";
pub const RUNTIME_CLOSURE_EVIDENCE_PROFILE: &str = "cantor-runtime-closure-evidence/0.2";
pub const RUNTIME_CLOSURE_CANONICAL_UUID: &str = "9f2b4613-353f-4cf2-ab66-a3bb3b97feb3";
pub const RUNTIME_CLOSURE_SIGNATURE_UUID: &str = "8f34fed3-755e-4ae5-a129-9a09ad6dd94b";
pub const RUNTIME_CLOSURE_NON_AUTHORITY: &str = "Supplied-data runtime-closure compilation only. It does not establish material presence, provenance, license, policy, trust, compatibility, safety, semantic suitability, availability, acquisition, build, filesystem layout, installation, activation, receipt observation, successor recognition, secret custody, provider or model state, remote state, hardware state, or external-effect authority.";
pub const RUNTIME_CLOSURE_MAX_MACHINE_FORM_BYTES: usize = 1_048_576;
pub const RUNTIME_CLOSURE_MAX_EVIDENCE_BUNDLE_BYTES: usize = 4_194_304;

const REQUEST_DOMAIN: &str = "cantor.runtime-closure.request.v2";
const RECEIPT_DOMAIN: &str = "cantor.runtime-closure.expected-receipt.v2";
const PLAN_DOMAIN: &str = "cantor.runtime-closure.plan.v2";
const ENVELOPE_DOMAIN: &str = "cantor.runtime-closure.envelope.v2";
const ORDERED_NODE_DOMAIN: &str = "cantor.runtime-closure.ordered-nodes.v2";
const ORDERED_TARGET_DOMAIN: &str = "cantor.runtime-closure.ordered-targets.v2";
const MAX_DEPTH: usize = 32;
const MAX_FIELDS: usize = 4_096;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_NODES: usize = 256;
const MAX_EDGES: usize = 254;
const MAX_EDGE_INPUTS: usize = 16;
const MAX_PREREQUISITES: usize = 128;
const MAX_EVIDENCE_REFS: usize = 64;
const MAX_COMPATIBILITY_REFS: usize = 32;
const MAX_TARGET_BYTES: usize = 240;
const MAX_TARGET_SEGMENTS: usize = 16;
const MAX_TOTAL_MATERIAL_BYTES: u64 = 1_099_511_627_776;
const REQUEST_EVIDENCE_PATH: &str = "request.json";
const ENVELOPE_EVIDENCE_PATH: &str = "envelope.json";
const VERIFICATION_EVIDENCE_PATH: &str = "verification.json";

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeClosureMaterialKind {
    BootstrapRuntime,
    InstallationSop,
    Derived,
    Built,
    Acquired,
    ExplicitlySupplied,
    GeneratedConfiguration,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeClosurePrerequisiteKind {
    HostOperatingSystem,
    Architecture,
    Hardware,
    Driver,
    Firmware,
    Toolchain,
    Transport,
    Network,
    ArtifactReservoir,
    ExternalCustody,
    OperatorAcceptance,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeClosureSourceKind {
    SuppliedDescriptor,
    DeterministicTransform,
    ContentAddressedArtifact,
    SourceBuild,
    GeneratedConfiguration,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeClosureExecutableDisposition {
    NonExecutable,
    ExecutableExpected,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeClosurePrerequisiteDisposition {
    RequiredUnresolved,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeClosureLifecycle {
    CompiledEffectlessRuntimeClosurePlanOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeClosureAuthority {
    SuppliedDataRuntimeClosureCompilationOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeClosureCapabilityDenial {
    FilesystemRead,
    FilesystemWrite,
    FilesystemDelete,
    EnvironmentRead,
    ClockRead,
    ProcessSpawn,
    ShellExec,
    CompilerExec,
    PackageManagerExec,
    NetworkContact,
    ArtifactDownload,
    ProviderContact,
    ModelLoad,
    Inference,
    McpContact,
    GitMutation,
    WorkspaceMutation,
    SecretAccess,
    PermissionChange,
    ServiceActivation,
    Cleanup,
    Rollback,
    RemoteAccess,
    HardwareEffect,
    ExternalEffect,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRuntimeIdentity {
    pub node_id: SemanticId,
    pub executable_sha256: ContentDigest,
    pub expected_bytes: u64,
    pub interface_profile: String,
    pub parser_profile: String,
    pub verifier_profile: String,
    pub planner_profile: String,
    pub materializer_profile: String,
    pub receipt_capability_profile: String,
    pub admitted_host_tuple_ref: SemanticId,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationSopIdentity {
    pub node_id: SemanticId,
    pub canonical_source_sha256: ContentDigest,
    pub expected_bytes: u64,
    pub satisfaction_signature_id: SemanticId,
    pub selected_runtime_profile: String,
    pub closure_root_id: SemanticId,
    pub capability_ceiling: BTreeSet<RuntimeClosureCapabilityDenial>,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosureMaterialNode {
    pub node_id: SemanticId,
    pub kind: RuntimeClosureMaterialKind,
    pub expected_sha256: ContentDigest,
    pub expected_bytes: u64,
    pub provenance_ref: SemanticId,
    pub compatibility_refs: BTreeSet<SemanticId>,
    pub target: String,
    pub verifier_profile: String,
    pub executable: RuntimeClosureExecutableDisposition,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosurePrerequisite {
    pub prerequisite_id: SemanticId,
    pub kind: RuntimeClosurePrerequisiteKind,
    pub reference: SemanticId,
    pub disposition: RuntimeClosurePrerequisiteDisposition,
    pub unresolved_reason: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosureSourceDescriptor {
    pub source_id: SemanticId,
    pub kind: RuntimeClosureSourceKind,
    pub immutable_ref: SemanticId,
    pub expected_sha256: ContentDigest,
    pub expected_bytes: u64,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosureProducerEdge {
    pub edge_id: SemanticId,
    pub inputs: BTreeSet<SemanticId>,
    pub output: SemanticId,
    pub source: RuntimeClosureSourceDescriptor,
    pub transform_profile: String,
    pub expected_sha256: ContentDigest,
    pub expected_bytes: u64,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosureRequest {
    pub profile: String,
    pub request_id: SemanticId,
    pub closure_id: SemanticId,
    pub bootstrap_runtime: BootstrapRuntimeIdentity,
    pub installation_sop: InstallationSopIdentity,
    pub material_nodes: Vec<RuntimeClosureMaterialNode>,
    pub prerequisites: Vec<RuntimeClosurePrerequisite>,
    pub producer_edges: Vec<RuntimeClosureProducerEdge>,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub non_authority: String,
    pub request_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedInstallationReceiptTemplate {
    pub closure_id: SemanticId,
    pub material_node_count: u32,
    pub target_count: u32,
    pub ordered_node_digest: ContentDigest,
    pub ordered_target_digest: ContentDigest,
    pub observation_count: u32,
    pub verifier_result_count: u32,
    pub materialization_action_count: u32,
    pub installation_state_asserted: bool,
    pub activation_state_asserted: bool,
    pub successor_recognition_authority: bool,
    pub receipt_template_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosurePlan {
    pub closure_id: SemanticId,
    pub bootstrap_node_id: SemanticId,
    pub installation_sop_node_id: SemanticId,
    pub material_nodes: Vec<RuntimeClosureMaterialNode>,
    pub prerequisites: Vec<RuntimeClosurePrerequisite>,
    pub producer_edges: Vec<RuntimeClosureProducerEdge>,
    pub topological_order: Vec<SemanticId>,
    pub unresolved_prerequisite_ids: Vec<SemanticId>,
    pub capability_denials: BTreeSet<RuntimeClosureCapabilityDenial>,
    pub expected_receipt: ExpectedInstallationReceiptTemplate,
    pub request_digest: ContentDigest,
    pub plan_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosureEnvelope {
    pub profile: String,
    pub request: RuntimeClosureRequest,
    pub lifecycle: RuntimeClosureLifecycle,
    pub authority: RuntimeClosureAuthority,
    pub plan: RuntimeClosurePlan,
    pub envelope_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosureEffectAccount {
    pub filesystem_effect_count: u32,
    pub process_effect_count: u32,
    pub network_effect_count: u32,
    pub provider_effect_count: u32,
    pub model_effect_count: u32,
    pub mcp_effect_count: u32,
    pub git_effect_count: u32,
    pub workspace_effect_count: u32,
    pub secret_effect_count: u32,
    pub permission_effect_count: u32,
    pub activation_effect_count: u32,
    pub cleanup_effect_count: u32,
    pub rollback_effect_count: u32,
    pub remote_effect_count: u32,
    pub hardware_effect_count: u32,
    pub foreign_effect_count: u32,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosureVerification {
    pub profile: String,
    pub status: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub authority: RuntimeClosureAuthority,
    pub request_digest: ContentDigest,
    pub plan_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
    pub root_count: u32,
    pub material_node_count: u32,
    pub producer_edge_count: u32,
    pub prerequisite_count: u32,
    pub unresolved_prerequisite_count: u32,
    pub target_count: u32,
    pub evidence_reference_count: u32,
    pub material_kind_count: u32,
    pub prerequisite_kind_count: u32,
    pub source_kind_count: u32,
    pub capability_denial_count: u32,
    pub deterministic_normalization_verified: bool,
    pub expected_receipt_has_observations: bool,
    pub effects: RuntimeClosureEffectAccount,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosureEvidenceFile {
    pub path: String,
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosureEvidenceManifest {
    pub profile: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub replay_count: u32,
    pub files: BTreeMap<String, RuntimeClosureEvidenceFile>,
    pub request_digest: ContentDigest,
    pub plan_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
    pub root_count: u32,
    pub material_node_count: u32,
    pub producer_edge_count: u32,
    pub prerequisite_count: u32,
    pub unresolved_prerequisite_count: u32,
    pub target_count: u32,
    pub evidence_reference_count: u32,
    pub material_kind_count: u32,
    pub prerequisite_kind_count: u32,
    pub source_kind_count: u32,
    pub capability_denial_count: u32,
    pub deterministic_normalization_verified: bool,
    pub expected_receipt_has_observations: bool,
    pub effects: RuntimeClosureEffectAccount,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosureEvidenceBundle {
    pub request_file: String,
    pub envelope_file: String,
    pub verification_file: String,
    pub manifest_file: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeClosureFaultCode {
    InvalidProfile,
    InvalidIdentity,
    IdentityCollision,
    InvalidDigest,
    InvalidBound,
    InvalidRoot,
    InvalidMaterial,
    InvalidPrerequisite,
    InvalidSource,
    InvalidProducer,
    InvalidGraph,
    InvalidTarget,
    InvalidAuthority,
    InvalidReceipt,
    InvalidVerification,
    InvalidEvidence,
    InvalidMachineForm,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeClosureFault {
    pub code: RuntimeClosureFaultCode,
    pub detail: String,
}

impl fmt::Display for RuntimeClosureFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}

impl std::error::Error for RuntimeClosureFault {}

pub fn seal_runtime_closure_request(
    mut request: RuntimeClosureRequest,
) -> Result<RuntimeClosureRequest, RuntimeClosureFault> {
    normalize_request(&mut request);
    request.request_digest = empty_digest();
    validate_request_body(&request)?;
    request.request_digest = runtime_closure_request_digest(&request)?;
    validate_runtime_closure_request(&request)?;
    Ok(request)
}

pub fn validate_runtime_closure_request(
    request: &RuntimeClosureRequest,
) -> Result<(), RuntimeClosureFault> {
    let mut normalized = request.clone();
    normalize_request(&mut normalized);
    if &normalized != request {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidGraph,
            "request collections are not in canonical order",
        ));
    }
    validate_request_body(request)?;
    if runtime_closure_request_digest(request)? != request.request_digest {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidDigest,
            "request digest differs",
        ));
    }
    Ok(())
}

pub fn compile_runtime_closure(
    request: &RuntimeClosureRequest,
) -> Result<RuntimeClosureEnvelope, RuntimeClosureFault> {
    validate_runtime_closure_request(request)?;
    let topological_order = derive_topological_order(request)?;
    let unresolved_prerequisite_ids = request
        .prerequisites
        .iter()
        .map(|item| item.prerequisite_id.clone())
        .collect::<Vec<_>>();
    let expected_receipt = expected_receipt_template(request, &topological_order)?;
    let mut plan = RuntimeClosurePlan {
        closure_id: request.closure_id.clone(),
        bootstrap_node_id: request.bootstrap_runtime.node_id.clone(),
        installation_sop_node_id: request.installation_sop.node_id.clone(),
        material_nodes: request.material_nodes.clone(),
        prerequisites: request.prerequisites.clone(),
        producer_edges: request.producer_edges.clone(),
        topological_order,
        unresolved_prerequisite_ids,
        capability_denials: required_capability_denials(),
        expected_receipt,
        request_digest: request.request_digest.clone(),
        plan_digest: empty_digest(),
    };
    plan.plan_digest = runtime_closure_plan_digest(&plan)?;
    validate_runtime_closure_plan(&plan, request)?;
    let mut envelope = RuntimeClosureEnvelope {
        profile: RUNTIME_CLOSURE_ENVELOPE_PROFILE.to_owned(),
        request: request.clone(),
        lifecycle: RuntimeClosureLifecycle::CompiledEffectlessRuntimeClosurePlanOnly,
        authority: RuntimeClosureAuthority::SuppliedDataRuntimeClosureCompilationOnly,
        plan,
        envelope_digest: empty_digest(),
    };
    envelope.envelope_digest = runtime_closure_envelope_digest(&envelope)?;
    validate_runtime_closure_envelope(&envelope)?;
    Ok(envelope)
}

pub fn validate_runtime_closure_envelope(
    envelope: &RuntimeClosureEnvelope,
) -> Result<(), RuntimeClosureFault> {
    validate_runtime_closure_request(&envelope.request)?;
    if envelope.profile != RUNTIME_CLOSURE_ENVELOPE_PROFILE
        || envelope.lifecycle != RuntimeClosureLifecycle::CompiledEffectlessRuntimeClosurePlanOnly
        || envelope.authority != RuntimeClosureAuthority::SuppliedDataRuntimeClosureCompilationOnly
    {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidAuthority,
            "envelope profile lifecycle or authority differs",
        ));
    }
    validate_runtime_closure_plan(&envelope.plan, &envelope.request)?;
    let expected = compile_envelope_without_recursion(&envelope.request)?;
    if expected.plan != envelope.plan {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidGraph,
            "envelope plan differs from deterministic compilation",
        ));
    }
    if runtime_closure_envelope_digest(envelope)? != envelope.envelope_digest {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidDigest,
            "envelope digest differs",
        ));
    }
    Ok(())
}

pub fn verify_runtime_closure(
    envelope: &RuntimeClosureEnvelope,
) -> Result<RuntimeClosureVerification, RuntimeClosureFault> {
    validate_runtime_closure_envelope(envelope)?;
    let verification = RuntimeClosureVerification {
        profile: RUNTIME_CLOSURE_VERIFICATION_PROFILE.to_owned(),
        status: "runtime_closure_compiled_effectless_verified".to_owned(),
        canonical_uuid: RUNTIME_CLOSURE_CANONICAL_UUID.to_owned(),
        signature_uuid: RUNTIME_CLOSURE_SIGNATURE_UUID.to_owned(),
        authority: RuntimeClosureAuthority::SuppliedDataRuntimeClosureCompilationOnly,
        request_digest: envelope.request.request_digest.clone(),
        plan_digest: envelope.plan.plan_digest.clone(),
        envelope_digest: envelope.envelope_digest.clone(),
        root_count: 2,
        material_node_count: count_u32(envelope.plan.material_nodes.len())?,
        producer_edge_count: count_u32(envelope.plan.producer_edges.len())?,
        prerequisite_count: count_u32(envelope.plan.prerequisites.len())?,
        unresolved_prerequisite_count: count_u32(envelope.plan.unresolved_prerequisite_ids.len())?,
        target_count: count_u32(envelope.plan.material_nodes.len())?,
        evidence_reference_count: count_u32(envelope.request.evidence_refs.len())?,
        material_kind_count: 7,
        prerequisite_kind_count: 11,
        source_kind_count: 5,
        capability_denial_count: count_u32(envelope.plan.capability_denials.len())?,
        deterministic_normalization_verified: true,
        expected_receipt_has_observations: false,
        effects: RuntimeClosureEffectAccount::default(),
    };
    validate_runtime_closure_verification(&verification, envelope)?;
    Ok(verification)
}

pub fn validate_runtime_closure_verification(
    verification: &RuntimeClosureVerification,
    envelope: &RuntimeClosureEnvelope,
) -> Result<(), RuntimeClosureFault> {
    let expected = verification_without_validation(envelope)?;
    if verification != &expected {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidVerification,
            "verification differs from deterministic account",
        ));
    }
    if verification.effects != RuntimeClosureEffectAccount::default()
        || verification.expected_receipt_has_observations
    {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidAuthority,
            "verification asserts an observation or effect",
        ));
    }
    Ok(())
}

pub fn build_runtime_closure_evidence_bundle(
    request: &RuntimeClosureRequest,
) -> Result<RuntimeClosureEvidenceBundle, RuntimeClosureFault> {
    validate_runtime_closure_request(request)?;
    let first_envelope = compile_runtime_closure(request)?;
    let second_envelope = compile_runtime_closure(request)?;
    if first_envelope != second_envelope {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidEvidence,
            "two compilations differ",
        ));
    }
    let first_verification = verify_runtime_closure(&first_envelope)?;
    let second_verification = verify_runtime_closure(&second_envelope)?;
    if first_verification != second_verification {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidEvidence,
            "two verification passes differ",
        ));
    }
    let request_file = canonical_file(to_runtime_closure_request_machine_form(request)?);
    let envelope_file = canonical_file(to_runtime_closure_envelope_machine_form(&first_envelope)?);
    let verification_file = canonical_file(to_runtime_closure_verification_machine_form(
        &first_verification,
    )?);
    let manifest = evidence_manifest(
        &request_file,
        &envelope_file,
        &verification_file,
        &first_verification,
    )?;
    let manifest_file = canonical_file(to_machine_form(&manifest)?);
    let bundle = RuntimeClosureEvidenceBundle {
        request_file,
        envelope_file,
        verification_file,
        manifest_file,
    };
    ensure_evidence_bundle_bound(&bundle)?;
    Ok(bundle)
}

pub fn verify_runtime_closure_evidence_bundle(
    bundle: &RuntimeClosureEvidenceBundle,
) -> Result<RuntimeClosureVerification, RuntimeClosureFault> {
    ensure_evidence_bundle_bound(bundle)?;
    let request_body = canonical_file_body(&bundle.request_file, REQUEST_EVIDENCE_PATH)?;
    let envelope_body = canonical_file_body(&bundle.envelope_file, ENVELOPE_EVIDENCE_PATH)?;
    let verification_body =
        canonical_file_body(&bundle.verification_file, VERIFICATION_EVIDENCE_PATH)?;
    let manifest_body = canonical_file_body(&bundle.manifest_file, "manifest.json")?;
    let request = from_runtime_closure_request_machine_form(request_body)?;
    let retained_envelope = from_runtime_closure_envelope_machine_form(envelope_body)?;
    let retained_verification = from_runtime_closure_verification_machine_form(verification_body)?;
    let retained_manifest: RuntimeClosureEvidenceManifest = parse_bounded(manifest_body)?;

    let first_envelope = compile_runtime_closure(&request)?;
    let second_envelope = compile_runtime_closure(&request)?;
    if first_envelope != second_envelope || first_envelope != retained_envelope {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidEvidence,
            "retained envelope differs from independent double compilation",
        ));
    }
    let first_verification = verify_runtime_closure(&first_envelope)?;
    let second_verification = verify_runtime_closure(&second_envelope)?;
    if first_verification != second_verification || first_verification != retained_verification {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidEvidence,
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
            RuntimeClosureFaultCode::InvalidEvidence,
            "retained manifest differs from reconstructed evidence",
        ));
    }
    Ok(first_verification)
}

pub fn to_runtime_closure_request_machine_form(
    request: &RuntimeClosureRequest,
) -> Result<String, RuntimeClosureFault> {
    validate_runtime_closure_request(request)?;
    to_machine_form(request)
}

pub fn from_runtime_closure_request_machine_form(
    value: &str,
) -> Result<RuntimeClosureRequest, RuntimeClosureFault> {
    let request: RuntimeClosureRequest = parse_bounded(value)?;
    validate_runtime_closure_request(&request)?;
    Ok(request)
}

pub fn to_runtime_closure_envelope_machine_form(
    envelope: &RuntimeClosureEnvelope,
) -> Result<String, RuntimeClosureFault> {
    validate_runtime_closure_envelope(envelope)?;
    to_machine_form(envelope)
}

pub fn from_runtime_closure_envelope_machine_form(
    value: &str,
) -> Result<RuntimeClosureEnvelope, RuntimeClosureFault> {
    let envelope: RuntimeClosureEnvelope = parse_bounded(value)?;
    validate_runtime_closure_envelope(&envelope)?;
    Ok(envelope)
}

pub fn to_runtime_closure_verification_machine_form(
    verification: &RuntimeClosureVerification,
) -> Result<String, RuntimeClosureFault> {
    to_machine_form(verification)
}

pub fn from_runtime_closure_verification_machine_form(
    value: &str,
) -> Result<RuntimeClosureVerification, RuntimeClosureFault> {
    parse_bounded(value)
}

pub fn to_runtime_closure_evidence_bundle_machine_form(
    bundle: &RuntimeClosureEvidenceBundle,
) -> Result<String, RuntimeClosureFault> {
    ensure_evidence_bundle_bound(bundle)?;
    to_machine_form(bundle)
}

pub fn from_runtime_closure_evidence_bundle_machine_form(
    value: &str,
) -> Result<RuntimeClosureEvidenceBundle, RuntimeClosureFault> {
    if value.len() > RUNTIME_CLOSURE_MAX_EVIDENCE_BUNDLE_BYTES {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidMachineForm,
            "evidence bundle exceeds 4194304 bytes",
        ));
    }
    let bundle: RuntimeClosureEvidenceBundle =
        parse_bounded_with_limit(value, RUNTIME_CLOSURE_MAX_EVIDENCE_BUNDLE_BYTES)?;
    ensure_evidence_bundle_bound(&bundle)?;
    Ok(bundle)
}

pub fn runtime_closure_request_digest(
    request: &RuntimeClosureRequest,
) -> Result<ContentDigest, RuntimeClosureFault> {
    let mut body = request.clone();
    body.request_digest = empty_digest();
    sha256_form(REQUEST_DOMAIN, &body)
}

pub fn runtime_closure_plan_digest(
    plan: &RuntimeClosurePlan,
) -> Result<ContentDigest, RuntimeClosureFault> {
    let mut body = plan.clone();
    body.plan_digest = empty_digest();
    sha256_form(PLAN_DOMAIN, &body)
}

pub fn runtime_closure_envelope_digest(
    envelope: &RuntimeClosureEnvelope,
) -> Result<ContentDigest, RuntimeClosureFault> {
    let mut body = envelope.clone();
    body.envelope_digest = empty_digest();
    sha256_form(ENVELOPE_DOMAIN, &body)
}

pub fn expected_installation_receipt_digest(
    receipt: &ExpectedInstallationReceiptTemplate,
) -> Result<ContentDigest, RuntimeClosureFault> {
    let mut body = receipt.clone();
    body.receipt_template_digest = empty_digest();
    sha256_form(RECEIPT_DOMAIN, &body)
}

pub fn runtime_closure_required_capability_denials() -> BTreeSet<RuntimeClosureCapabilityDenial> {
    required_capability_denials()
}

pub fn synthetic_runtime_closure_request() -> Result<RuntimeClosureRequest, RuntimeClosureFault> {
    let bootstrap_id = sid("material:10000000-0000-4000-8000-000000000001")?;
    let sop_id = sid("material:10000000-0000-4000-8000-000000000002")?;
    let library_id = sid("material:10000000-0000-4000-8000-000000000003")?;
    let config_id = sid("material:10000000-0000-4000-8000-000000000004")?;
    let launcher_id = sid("material:10000000-0000-4000-8000-000000000005")?;
    let bootstrap_digest = digest('1');
    let sop_digest = digest('2');
    let library_digest = digest('3');
    let config_digest = digest('4');
    let launcher_digest = digest('5');
    let bootstrap_runtime = BootstrapRuntimeIdentity {
        node_id: bootstrap_id.clone(),
        executable_sha256: bootstrap_digest.clone(),
        expected_bytes: 65_536,
        interface_profile: "cantor-bootstrap-interface/0.2".to_owned(),
        parser_profile: "cantor-sop-parser/0.2".to_owned(),
        verifier_profile: "cantor-bootstrap-verifier/0.2".to_owned(),
        planner_profile: "cantor-runtime-closure-planner/0.2".to_owned(),
        materializer_profile: "cantor-materializer-interface/0.2".to_owned(),
        receipt_capability_profile: "cantor-installation-receipt-interface/0.2".to_owned(),
        admitted_host_tuple_ref: sid("host-tuple:synthetic-platform-neutral")?,
    };
    let installation_sop = InstallationSopIdentity {
        node_id: sop_id.clone(),
        canonical_source_sha256: sop_digest.clone(),
        expected_bytes: 4_096,
        satisfaction_signature_id: sid("signature:20000000-0000-4000-8000-000000000001")?,
        selected_runtime_profile: "cantor-synthetic-runtime/0.2".to_owned(),
        closure_root_id: sid("closure-root:20000000-0000-4000-8000-000000000002")?,
        capability_ceiling: required_capability_denials(),
    };
    let material_nodes = vec![
        material_node(
            bootstrap_id.clone(),
            RuntimeClosureMaterialKind::BootstrapRuntime,
            bootstrap_digest,
            65_536,
            "seed:bootstrap-runtime",
            "bin/cantor-bootstrap.exe",
            RuntimeClosureExecutableDisposition::ExecutableExpected,
        )?,
        material_node(
            sop_id.clone(),
            RuntimeClosureMaterialKind::InstallationSop,
            sop_digest,
            4_096,
            "seed:installation-sop",
            "sop/install.sop",
            RuntimeClosureExecutableDisposition::NonExecutable,
        )?,
        material_node(
            library_id.clone(),
            RuntimeClosureMaterialKind::Built,
            library_digest.clone(),
            131_072,
            "provenance:synthetic-source-build",
            "lib/cantor-core.dll",
            RuntimeClosureExecutableDisposition::NonExecutable,
        )?,
        material_node(
            config_id.clone(),
            RuntimeClosureMaterialKind::GeneratedConfiguration,
            config_digest.clone(),
            1_024,
            "provenance:synthetic-config-generator",
            "config/cantor.json",
            RuntimeClosureExecutableDisposition::NonExecutable,
        )?,
        material_node(
            launcher_id.clone(),
            RuntimeClosureMaterialKind::Derived,
            launcher_digest.clone(),
            32_768,
            "provenance:synthetic-link-plan",
            "bin/cantor-agent.exe",
            RuntimeClosureExecutableDisposition::ExecutableExpected,
        )?,
    ];
    let producer_edges = vec![
        producer_edge(
            "producer:30000000-0000-4000-8000-000000000001",
            [bootstrap_id.clone(), sop_id.clone()].into_iter().collect(),
            library_id.clone(),
            RuntimeClosureSourceKind::SourceBuild,
            "source:30000000-0000-4000-8000-000000000011",
            format!("source:sha256:{}", "a".repeat(64)),
            "synthetic-source-build/0.2",
            library_digest,
            131_072,
        )?,
        producer_edge(
            "producer:30000000-0000-4000-8000-000000000002",
            [sop_id.clone()].into_iter().collect(),
            config_id.clone(),
            RuntimeClosureSourceKind::GeneratedConfiguration,
            "source:30000000-0000-4000-8000-000000000012",
            format!("generator:sha256:{}", "b".repeat(64)),
            "synthetic-config-generation/0.2",
            config_digest,
            1_024,
        )?,
        producer_edge(
            "producer:30000000-0000-4000-8000-000000000003",
            [bootstrap_id, library_id, config_id].into_iter().collect(),
            launcher_id,
            RuntimeClosureSourceKind::DeterministicTransform,
            "source:30000000-0000-4000-8000-000000000013",
            format!("transform:sha256:{}", "c".repeat(64)),
            "synthetic-link-transform/0.2",
            launcher_digest,
            32_768,
        )?,
    ];
    let request = RuntimeClosureRequest {
        profile: RUNTIME_CLOSURE_REQUEST_PROFILE.to_owned(),
        request_id: sid("request:40000000-0000-4000-8000-000000000001")?,
        closure_id: sid("closure:40000000-0000-4000-8000-000000000002")?,
        bootstrap_runtime,
        installation_sop,
        material_nodes,
        prerequisites: vec![
            RuntimeClosurePrerequisite {
                prerequisite_id: sid("prerequisite:50000000-0000-4000-8000-000000000001")?,
                kind: RuntimeClosurePrerequisiteKind::HostOperatingSystem,
                reference: sid("host-os:synthetic-declared")?,
                disposition: RuntimeClosurePrerequisiteDisposition::RequiredUnresolved,
                unresolved_reason: "synthetic fixture performs no host observation".to_owned(),
            },
            RuntimeClosurePrerequisite {
                prerequisite_id: sid("prerequisite:50000000-0000-4000-8000-000000000002")?,
                kind: RuntimeClosurePrerequisiteKind::Toolchain,
                reference: sid("toolchain:synthetic-declared")?,
                disposition: RuntimeClosurePrerequisiteDisposition::RequiredUnresolved,
                unresolved_reason: "synthetic fixture performs no toolchain observation".to_owned(),
            },
        ],
        producer_edges,
        evidence_refs: [sid("evidence:60000000-0000-4000-8000-000000000001")?]
            .into_iter()
            .collect(),
        non_authority: RUNTIME_CLOSURE_NON_AUTHORITY.to_owned(),
        request_digest: empty_digest(),
    };
    seal_runtime_closure_request(request)
}

fn validate_request_body(request: &RuntimeClosureRequest) -> Result<(), RuntimeClosureFault> {
    if request.profile != RUNTIME_CLOSURE_REQUEST_PROFILE {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidProfile,
            "request profile differs from Revision 0.2",
        ));
    }
    validate_uuid_id(&request.request_id, "request identity")?;
    validate_uuid_id(&request.closure_id, "closure identity")?;
    validate_bootstrap_identity(&request.bootstrap_runtime)?;
    validate_installation_sop_identity(&request.installation_sop)?;
    if request.bootstrap_runtime.node_id == request.installation_sop.node_id {
        return Err(fault(
            RuntimeClosureFaultCode::IdentityCollision,
            "bootstrap and installation SOP roots collide",
        ));
    }
    if request.material_nodes.len() < 2 || request.material_nodes.len() > MAX_NODES {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidBound,
            "material node count must be 2 through 256",
        ));
    }
    if request.producer_edges.len() > MAX_EDGES
        || request.producer_edges.len() != request.material_nodes.len() - 2
    {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidBound,
            "producer edge count must equal nonroot node count and not exceed 254",
        ));
    }
    if request.prerequisites.len() > MAX_PREREQUISITES {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidBound,
            "prerequisite count exceeds 128",
        ));
    }
    if request.evidence_refs.is_empty() || request.evidence_refs.len() > MAX_EVIDENCE_REFS {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidBound,
            "evidence reference count must be 1 through 64",
        ));
    }
    if request.non_authority != RUNTIME_CLOSURE_NON_AUTHORITY {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidAuthority,
            "non-authority statement differs",
        ));
    }

    let mut identities = BTreeSet::new();
    for identity in [
        &request.request_id,
        &request.closure_id,
        &request.installation_sop.satisfaction_signature_id,
        &request.installation_sop.closure_root_id,
    ] {
        insert_identity(&mut identities, identity, "top-level identity")?;
    }

    let mut nodes = BTreeMap::new();
    let mut targets = BTreeSet::new();
    let mut total_material_bytes = 0_u64;
    for node in &request.material_nodes {
        validate_material_node(node)?;
        insert_identity(&mut identities, &node.node_id, "material node identity")?;
        if nodes.insert(node.node_id.clone(), node).is_some() {
            return Err(fault(
                RuntimeClosureFaultCode::IdentityCollision,
                "duplicate material node identity",
            ));
        }
        if !targets.insert(node.target.clone()) {
            return Err(fault(
                RuntimeClosureFaultCode::InvalidTarget,
                "duplicate logical target",
            ));
        }
        total_material_bytes = total_material_bytes
            .checked_add(node.expected_bytes)
            .ok_or_else(|| {
                fault(
                    RuntimeClosureFaultCode::InvalidBound,
                    "declared material bytes overflow",
                )
            })?;
    }
    if total_material_bytes > MAX_TOTAL_MATERIAL_BYTES {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidBound,
            "declared material bytes exceed 1099511627776",
        ));
    }
    validate_root_node_correspondence(request, &nodes)?;

    let mut prerequisite_ids = BTreeSet::new();
    for prerequisite in &request.prerequisites {
        validate_prerequisite(prerequisite)?;
        insert_identity(
            &mut identities,
            &prerequisite.prerequisite_id,
            "prerequisite identity",
        )?;
        if !prerequisite_ids.insert(prerequisite.prerequisite_id.clone()) {
            return Err(fault(
                RuntimeClosureFaultCode::IdentityCollision,
                "duplicate prerequisite identity",
            ));
        }
    }
    for evidence_ref in &request.evidence_refs {
        validate_uuid_id(evidence_ref, "evidence reference")?;
        insert_identity(&mut identities, evidence_ref, "evidence reference")?;
    }

    let roots = BTreeSet::from([
        request.bootstrap_runtime.node_id.clone(),
        request.installation_sop.node_id.clone(),
    ]);
    let mut produced = BTreeSet::new();
    for edge in &request.producer_edges {
        validate_producer_edge(edge, &nodes, &roots)?;
        insert_identity(&mut identities, &edge.edge_id, "producer edge identity")?;
        insert_identity(&mut identities, &edge.source.source_id, "source identity")?;
        if !produced.insert(edge.output.clone()) {
            return Err(fault(
                RuntimeClosureFaultCode::InvalidProducer,
                "multiple producers target one output",
            ));
        }
    }
    for node_id in nodes.keys() {
        if roots.contains(node_id) == produced.contains(node_id) {
            return Err(fault(
                RuntimeClosureFaultCode::InvalidProducer,
                "root production or nonroot producer cardinality differs",
            ));
        }
    }
    derive_topological_order(request)?;
    validate_digest(&request.request_digest, "request digest")?;
    Ok(())
}

fn validate_bootstrap_identity(
    identity: &BootstrapRuntimeIdentity,
) -> Result<(), RuntimeClosureFault> {
    validate_uuid_id(&identity.node_id, "bootstrap node identity")?;
    validate_digest(&identity.executable_sha256, "bootstrap executable digest")?;
    for (value, label) in [
        (&identity.interface_profile, "bootstrap interface profile"),
        (&identity.parser_profile, "bootstrap parser profile"),
        (&identity.verifier_profile, "bootstrap verifier profile"),
        (&identity.planner_profile, "bootstrap planner profile"),
        (
            &identity.materializer_profile,
            "bootstrap materializer profile",
        ),
        (
            &identity.receipt_capability_profile,
            "bootstrap receipt capability profile",
        ),
    ] {
        validate_token(value, label)?;
    }
    validate_reference(
        &identity.admitted_host_tuple_ref,
        "admitted host tuple reference",
        false,
    )
}

fn validate_installation_sop_identity(
    identity: &InstallationSopIdentity,
) -> Result<(), RuntimeClosureFault> {
    validate_uuid_id(&identity.node_id, "installation SOP node identity")?;
    validate_digest(
        &identity.canonical_source_sha256,
        "installation SOP canonical digest",
    )?;
    validate_uuid_id(
        &identity.satisfaction_signature_id,
        "satisfaction signature identity",
    )?;
    validate_token(
        &identity.selected_runtime_profile,
        "selected runtime profile",
    )?;
    validate_uuid_id(&identity.closure_root_id, "closure root identity")?;
    if identity.capability_ceiling != required_capability_denials() {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidAuthority,
            "installation SOP capability ceiling differs from exact denials",
        ));
    }
    Ok(())
}

fn validate_material_node(node: &RuntimeClosureMaterialNode) -> Result<(), RuntimeClosureFault> {
    validate_uuid_id(&node.node_id, "material node identity")?;
    validate_digest(&node.expected_sha256, "material node digest")?;
    validate_reference(&node.provenance_ref, "material provenance reference", false)?;
    if node.compatibility_refs.len() > MAX_COMPATIBILITY_REFS {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidBound,
            "compatibility reference count exceeds 32",
        ));
    }
    for reference in &node.compatibility_refs {
        validate_reference(reference, "compatibility reference", false)?;
    }
    validate_logical_target(&node.target)?;
    validate_token(&node.verifier_profile, "material verifier profile")
}

fn validate_prerequisite(
    prerequisite: &RuntimeClosurePrerequisite,
) -> Result<(), RuntimeClosureFault> {
    validate_uuid_id(&prerequisite.prerequisite_id, "prerequisite identity")?;
    validate_reference(&prerequisite.reference, "prerequisite reference", true)?;
    if prerequisite.disposition != RuntimeClosurePrerequisiteDisposition::RequiredUnresolved {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidPrerequisite,
            "prerequisite disposition differs",
        ));
    }
    if !valid_text(&prerequisite.unresolved_reason)
        || prerequisite.unresolved_reason.trim() != prerequisite.unresolved_reason
        || prerequisite.unresolved_reason.is_empty()
    {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidPrerequisite,
            "prerequisite unresolved reason differs",
        ));
    }
    Ok(())
}

fn validate_producer_edge(
    edge: &RuntimeClosureProducerEdge,
    nodes: &BTreeMap<SemanticId, &RuntimeClosureMaterialNode>,
    roots: &BTreeSet<SemanticId>,
) -> Result<(), RuntimeClosureFault> {
    validate_uuid_id(&edge.edge_id, "producer edge identity")?;
    validate_uuid_id(&edge.source.source_id, "source identity")?;
    if edge.inputs.is_empty() || edge.inputs.len() > MAX_EDGE_INPUTS {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidBound,
            "producer input count must be 1 through 16",
        ));
    }
    if roots.contains(&edge.output) || !nodes.contains_key(&edge.output) {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidProducer,
            "producer output is missing or is a root",
        ));
    }
    for input in &edge.inputs {
        if !nodes.contains_key(input) || input == &edge.output {
            return Err(fault(
                RuntimeClosureFaultCode::InvalidProducer,
                "producer input is missing or self-referential",
            ));
        }
    }
    let output = nodes[&edge.output];
    validate_digest(&edge.expected_sha256, "producer expected digest")?;
    validate_digest(&edge.source.expected_sha256, "source expected digest")?;
    if edge.expected_sha256 != output.expected_sha256
        || edge.expected_bytes != output.expected_bytes
        || edge.source.expected_sha256 != output.expected_sha256
        || edge.source.expected_bytes != output.expected_bytes
    {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidProducer,
            "producer or source expected output differs from material node",
        ));
    }
    validate_source_descriptor(&edge.source, output.kind)?;
    validate_token(&edge.transform_profile, "transform profile")
}

fn validate_source_descriptor(
    source: &RuntimeClosureSourceDescriptor,
    output_kind: RuntimeClosureMaterialKind,
) -> Result<(), RuntimeClosureFault> {
    let expected_kind = match output_kind {
        RuntimeClosureMaterialKind::Derived => RuntimeClosureSourceKind::DeterministicTransform,
        RuntimeClosureMaterialKind::Built => RuntimeClosureSourceKind::SourceBuild,
        RuntimeClosureMaterialKind::Acquired => RuntimeClosureSourceKind::ContentAddressedArtifact,
        RuntimeClosureMaterialKind::ExplicitlySupplied => {
            RuntimeClosureSourceKind::SuppliedDescriptor
        }
        RuntimeClosureMaterialKind::GeneratedConfiguration => {
            RuntimeClosureSourceKind::GeneratedConfiguration
        }
        RuntimeClosureMaterialKind::BootstrapRuntime
        | RuntimeClosureMaterialKind::InstallationSop => {
            return Err(fault(
                RuntimeClosureFaultCode::InvalidSource,
                "root material cannot have a source descriptor",
            ));
        }
    };
    if source.kind != expected_kind {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidSource,
            "source kind differs from output material kind",
        ));
    }
    validate_reference(&source.immutable_ref, "immutable source reference", false)
        .map_err(|error| fault(RuntimeClosureFaultCode::InvalidSource, error.detail))?;
    let reference = source.immutable_ref.as_str();
    let Some((_, digest_text)) = reference.rsplit_once(":sha256:") else {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidSource,
            "immutable source reference lacks content identity",
        ));
    };
    if !is_lower_sha256(digest_text)
        || [
            "latest",
            "ambient",
            "current-directory",
            "cache",
            "path-lookup",
        ]
        .iter()
        .any(|term| reference.contains(term))
    {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidSource,
            "source reference is mutable or ambient",
        ));
    }
    Ok(())
}

fn validate_root_node_correspondence(
    request: &RuntimeClosureRequest,
    nodes: &BTreeMap<SemanticId, &RuntimeClosureMaterialNode>,
) -> Result<(), RuntimeClosureFault> {
    let bootstrap = nodes
        .get(&request.bootstrap_runtime.node_id)
        .ok_or_else(|| {
            fault(
                RuntimeClosureFaultCode::InvalidRoot,
                "bootstrap root node is absent",
            )
        })?;
    if bootstrap.kind != RuntimeClosureMaterialKind::BootstrapRuntime
        || bootstrap.expected_sha256 != request.bootstrap_runtime.executable_sha256
        || bootstrap.expected_bytes != request.bootstrap_runtime.expected_bytes
    {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidRoot,
            "bootstrap root node differs from descriptor",
        ));
    }
    let sop = nodes
        .get(&request.installation_sop.node_id)
        .ok_or_else(|| {
            fault(
                RuntimeClosureFaultCode::InvalidRoot,
                "installation SOP root node is absent",
            )
        })?;
    if sop.kind != RuntimeClosureMaterialKind::InstallationSop
        || sop.expected_sha256 != request.installation_sop.canonical_source_sha256
        || sop.expected_bytes != request.installation_sop.expected_bytes
    {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidRoot,
            "installation SOP root node differs from descriptor",
        ));
    }
    Ok(())
}

fn derive_topological_order(
    request: &RuntimeClosureRequest,
) -> Result<Vec<SemanticId>, RuntimeClosureFault> {
    let roots = BTreeSet::from([
        request.bootstrap_runtime.node_id.clone(),
        request.installation_sop.node_id.clone(),
    ]);
    let producers = request
        .producer_edges
        .iter()
        .map(|edge| (edge.output.clone(), edge))
        .collect::<BTreeMap<_, _>>();
    let mut remaining = request
        .material_nodes
        .iter()
        .map(|node| node.node_id.clone())
        .collect::<BTreeSet<_>>();
    let mut admitted = BTreeSet::new();
    let mut ordered = Vec::with_capacity(remaining.len());
    while !remaining.is_empty() {
        let next = remaining.iter().find(|node_id| {
            if roots.contains(*node_id) {
                return true;
            }
            producers
                .get(*node_id)
                .is_some_and(|edge| edge.inputs.iter().all(|input| admitted.contains(input)))
        });
        let Some(next) = next.cloned() else {
            return Err(fault(
                RuntimeClosureFaultCode::InvalidGraph,
                "graph is cyclic or contains an unreachable dependency",
            ));
        };
        remaining.remove(&next);
        admitted.insert(next.clone());
        ordered.push(next);
    }
    Ok(ordered)
}

fn expected_receipt_template(
    request: &RuntimeClosureRequest,
    topological_order: &[SemanticId],
) -> Result<ExpectedInstallationReceiptTemplate, RuntimeClosureFault> {
    let nodes = request
        .material_nodes
        .iter()
        .map(|node| (node.node_id.clone(), node))
        .collect::<BTreeMap<_, _>>();
    let ordered_nodes = topological_order
        .iter()
        .map(|node_id| {
            let node = nodes[node_id];
            (
                node.node_id.clone(),
                node.expected_sha256.clone(),
                node.expected_bytes,
            )
        })
        .collect::<Vec<_>>();
    let mut ordered_targets = request
        .material_nodes
        .iter()
        .map(|node| {
            (
                node.target.clone(),
                node.node_id.clone(),
                node.expected_sha256.clone(),
            )
        })
        .collect::<Vec<_>>();
    ordered_targets.sort_by(|left, right| left.0.cmp(&right.0));
    let mut receipt = ExpectedInstallationReceiptTemplate {
        closure_id: request.closure_id.clone(),
        material_node_count: count_u32(request.material_nodes.len())?,
        target_count: count_u32(request.material_nodes.len())?,
        ordered_node_digest: sha256_form(ORDERED_NODE_DOMAIN, &ordered_nodes)?,
        ordered_target_digest: sha256_form(ORDERED_TARGET_DOMAIN, &ordered_targets)?,
        observation_count: 0,
        verifier_result_count: 0,
        materialization_action_count: 0,
        installation_state_asserted: false,
        activation_state_asserted: false,
        successor_recognition_authority: false,
        receipt_template_digest: empty_digest(),
    };
    receipt.receipt_template_digest = expected_installation_receipt_digest(&receipt)?;
    Ok(receipt)
}

fn validate_expected_receipt(
    receipt: &ExpectedInstallationReceiptTemplate,
    request: &RuntimeClosureRequest,
    topological_order: &[SemanticId],
) -> Result<(), RuntimeClosureFault> {
    let expected = expected_receipt_template(request, topological_order)?;
    if receipt != &expected {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidReceipt,
            "expected receipt template differs",
        ));
    }
    if receipt.observation_count != 0
        || receipt.verifier_result_count != 0
        || receipt.materialization_action_count != 0
        || receipt.installation_state_asserted
        || receipt.activation_state_asserted
        || receipt.successor_recognition_authority
    {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidReceipt,
            "expected receipt asserts an observation action or authority",
        ));
    }
    Ok(())
}

fn validate_runtime_closure_plan(
    plan: &RuntimeClosurePlan,
    request: &RuntimeClosureRequest,
) -> Result<(), RuntimeClosureFault> {
    if plan.closure_id != request.closure_id
        || plan.bootstrap_node_id != request.bootstrap_runtime.node_id
        || plan.installation_sop_node_id != request.installation_sop.node_id
        || plan.material_nodes != request.material_nodes
        || plan.prerequisites != request.prerequisites
        || plan.producer_edges != request.producer_edges
        || plan.request_digest != request.request_digest
        || plan.capability_denials != required_capability_denials()
    {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidAuthority,
            "plan binding or capability denials differ",
        ));
    }
    let topological_order = derive_topological_order(request)?;
    if plan.topological_order != topological_order {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidGraph,
            "plan topological order differs",
        ));
    }
    let unresolved = request
        .prerequisites
        .iter()
        .map(|item| item.prerequisite_id.clone())
        .collect::<Vec<_>>();
    if plan.unresolved_prerequisite_ids != unresolved {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidPrerequisite,
            "unresolved prerequisite account differs",
        ));
    }
    validate_expected_receipt(&plan.expected_receipt, request, &topological_order)?;
    validate_digest(&plan.plan_digest, "plan digest")?;
    if runtime_closure_plan_digest(plan)? != plan.plan_digest {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidDigest,
            "plan digest differs",
        ));
    }
    Ok(())
}

fn compile_envelope_without_recursion(
    request: &RuntimeClosureRequest,
) -> Result<RuntimeClosureEnvelope, RuntimeClosureFault> {
    validate_runtime_closure_request(request)?;
    let topological_order = derive_topological_order(request)?;
    let expected_receipt = expected_receipt_template(request, &topological_order)?;
    let mut plan = RuntimeClosurePlan {
        closure_id: request.closure_id.clone(),
        bootstrap_node_id: request.bootstrap_runtime.node_id.clone(),
        installation_sop_node_id: request.installation_sop.node_id.clone(),
        material_nodes: request.material_nodes.clone(),
        prerequisites: request.prerequisites.clone(),
        producer_edges: request.producer_edges.clone(),
        topological_order,
        unresolved_prerequisite_ids: request
            .prerequisites
            .iter()
            .map(|item| item.prerequisite_id.clone())
            .collect(),
        capability_denials: required_capability_denials(),
        expected_receipt,
        request_digest: request.request_digest.clone(),
        plan_digest: empty_digest(),
    };
    plan.plan_digest = runtime_closure_plan_digest(&plan)?;
    let mut envelope = RuntimeClosureEnvelope {
        profile: RUNTIME_CLOSURE_ENVELOPE_PROFILE.to_owned(),
        request: request.clone(),
        lifecycle: RuntimeClosureLifecycle::CompiledEffectlessRuntimeClosurePlanOnly,
        authority: RuntimeClosureAuthority::SuppliedDataRuntimeClosureCompilationOnly,
        plan,
        envelope_digest: empty_digest(),
    };
    envelope.envelope_digest = runtime_closure_envelope_digest(&envelope)?;
    Ok(envelope)
}

fn verification_without_validation(
    envelope: &RuntimeClosureEnvelope,
) -> Result<RuntimeClosureVerification, RuntimeClosureFault> {
    Ok(RuntimeClosureVerification {
        profile: RUNTIME_CLOSURE_VERIFICATION_PROFILE.to_owned(),
        status: "runtime_closure_compiled_effectless_verified".to_owned(),
        canonical_uuid: RUNTIME_CLOSURE_CANONICAL_UUID.to_owned(),
        signature_uuid: RUNTIME_CLOSURE_SIGNATURE_UUID.to_owned(),
        authority: RuntimeClosureAuthority::SuppliedDataRuntimeClosureCompilationOnly,
        request_digest: envelope.request.request_digest.clone(),
        plan_digest: envelope.plan.plan_digest.clone(),
        envelope_digest: envelope.envelope_digest.clone(),
        root_count: 2,
        material_node_count: count_u32(envelope.plan.material_nodes.len())?,
        producer_edge_count: count_u32(envelope.plan.producer_edges.len())?,
        prerequisite_count: count_u32(envelope.plan.prerequisites.len())?,
        unresolved_prerequisite_count: count_u32(envelope.plan.unresolved_prerequisite_ids.len())?,
        target_count: count_u32(envelope.plan.material_nodes.len())?,
        evidence_reference_count: count_u32(envelope.request.evidence_refs.len())?,
        material_kind_count: 7,
        prerequisite_kind_count: 11,
        source_kind_count: 5,
        capability_denial_count: count_u32(envelope.plan.capability_denials.len())?,
        deterministic_normalization_verified: true,
        expected_receipt_has_observations: false,
        effects: RuntimeClosureEffectAccount::default(),
    })
}

fn normalize_request(request: &mut RuntimeClosureRequest) {
    request
        .material_nodes
        .sort_by(|left, right| left.node_id.cmp(&right.node_id));
    request
        .prerequisites
        .sort_by(|left, right| left.prerequisite_id.cmp(&right.prerequisite_id));
    request.producer_edges.sort_by(|left, right| {
        left.output
            .cmp(&right.output)
            .then_with(|| left.edge_id.cmp(&right.edge_id))
    });
}

fn evidence_manifest(
    request_file: &str,
    envelope_file: &str,
    verification_file: &str,
    verification: &RuntimeClosureVerification,
) -> Result<RuntimeClosureEvidenceManifest, RuntimeClosureFault> {
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
    Ok(RuntimeClosureEvidenceManifest {
        profile: RUNTIME_CLOSURE_EVIDENCE_PROFILE.to_owned(),
        canonical_uuid: RUNTIME_CLOSURE_CANONICAL_UUID.to_owned(),
        signature_uuid: RUNTIME_CLOSURE_SIGNATURE_UUID.to_owned(),
        replay_count: 2,
        files,
        request_digest: verification.request_digest.clone(),
        plan_digest: verification.plan_digest.clone(),
        envelope_digest: verification.envelope_digest.clone(),
        root_count: verification.root_count,
        material_node_count: verification.material_node_count,
        producer_edge_count: verification.producer_edge_count,
        prerequisite_count: verification.prerequisite_count,
        unresolved_prerequisite_count: verification.unresolved_prerequisite_count,
        target_count: verification.target_count,
        evidence_reference_count: verification.evidence_reference_count,
        material_kind_count: verification.material_kind_count,
        prerequisite_kind_count: verification.prerequisite_kind_count,
        source_kind_count: verification.source_kind_count,
        capability_denial_count: verification.capability_denial_count,
        deterministic_normalization_verified: verification.deterministic_normalization_verified,
        expected_receipt_has_observations: verification.expected_receipt_has_observations,
        effects: verification.effects.clone(),
    })
}

fn evidence_file(
    path: &str,
    value: &str,
) -> Result<RuntimeClosureEvidenceFile, RuntimeClosureFault> {
    Ok(RuntimeClosureEvidenceFile {
        path: path.to_owned(),
        bytes: u64::try_from(value.len()).map_err(|_| {
            fault(
                RuntimeClosureFaultCode::InvalidBound,
                "evidence file length conversion failed",
            )
        })?,
        sha256: sha256_bytes(value.as_bytes()),
    })
}

fn ensure_evidence_bundle_bound(
    bundle: &RuntimeClosureEvidenceBundle,
) -> Result<(), RuntimeClosureFault> {
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
            RuntimeClosureFaultCode::InvalidBound,
            "evidence bundle length overflow",
        )
    })?;
    if total > RUNTIME_CLOSURE_MAX_EVIDENCE_BUNDLE_BYTES {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidBound,
            "evidence bundle exceeds 4194304 bytes",
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

fn canonical_file_body<'a>(value: &'a str, label: &str) -> Result<&'a str, RuntimeClosureFault> {
    let Some(body) = value.strip_suffix('\n') else {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidEvidence,
            format!("{label} lacks one LF terminator"),
        ));
    };
    if body.contains('\r') || body.contains('\n') {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidEvidence,
            format!("{label} contains embedded line terminators"),
        ));
    }
    Ok(body)
}

fn required_capability_denials() -> BTreeSet<RuntimeClosureCapabilityDenial> {
    [
        RuntimeClosureCapabilityDenial::FilesystemRead,
        RuntimeClosureCapabilityDenial::FilesystemWrite,
        RuntimeClosureCapabilityDenial::FilesystemDelete,
        RuntimeClosureCapabilityDenial::EnvironmentRead,
        RuntimeClosureCapabilityDenial::ClockRead,
        RuntimeClosureCapabilityDenial::ProcessSpawn,
        RuntimeClosureCapabilityDenial::ShellExec,
        RuntimeClosureCapabilityDenial::CompilerExec,
        RuntimeClosureCapabilityDenial::PackageManagerExec,
        RuntimeClosureCapabilityDenial::NetworkContact,
        RuntimeClosureCapabilityDenial::ArtifactDownload,
        RuntimeClosureCapabilityDenial::ProviderContact,
        RuntimeClosureCapabilityDenial::ModelLoad,
        RuntimeClosureCapabilityDenial::Inference,
        RuntimeClosureCapabilityDenial::McpContact,
        RuntimeClosureCapabilityDenial::GitMutation,
        RuntimeClosureCapabilityDenial::WorkspaceMutation,
        RuntimeClosureCapabilityDenial::SecretAccess,
        RuntimeClosureCapabilityDenial::PermissionChange,
        RuntimeClosureCapabilityDenial::ServiceActivation,
        RuntimeClosureCapabilityDenial::Cleanup,
        RuntimeClosureCapabilityDenial::Rollback,
        RuntimeClosureCapabilityDenial::RemoteAccess,
        RuntimeClosureCapabilityDenial::HardwareEffect,
        RuntimeClosureCapabilityDenial::ExternalEffect,
    ]
    .into_iter()
    .collect()
}

fn validate_logical_target(target: &str) -> Result<(), RuntimeClosureFault> {
    if target.is_empty()
        || target.len() > MAX_TARGET_BYTES
        || !target.is_ascii()
        || target.starts_with('/')
        || target.ends_with('/')
    {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidTarget,
            "logical target root or byte bound differs",
        ));
    }
    let segments = target.split('/').collect::<Vec<_>>();
    if segments.is_empty() || segments.len() > MAX_TARGET_SEGMENTS {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidTarget,
            "logical target segment count differs",
        ));
    }
    for segment in segments {
        if segment.is_empty()
            || matches!(segment, "." | "..")
            || !segment.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
            || is_device_segment(segment)
        {
            return Err(fault(
                RuntimeClosureFaultCode::InvalidTarget,
                format!("logical target segment differs: {segment:?}"),
            ));
        }
    }
    Ok(())
}

fn is_device_segment(segment: &str) -> bool {
    let base = segment.split('.').next().unwrap_or(segment);
    matches!(base, "con" | "prn" | "aux" | "nul")
        || (base.len() == 4
            && (base.starts_with("com") || base.starts_with("lpt"))
            && matches!(base.as_bytes()[3], b'1'..=b'9'))
}

fn validate_reference(
    reference: &SemanticId,
    label: &str,
    secret_sensitive: bool,
) -> Result<(), RuntimeClosureFault> {
    let value = reference.as_str();
    if value != value.to_ascii_lowercase()
        || value.len() > 512
        || value.is_empty()
        || value.contains("latest")
    {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidIdentity,
            format!("{label} is not a bounded immutable lower-case reference"),
        ));
    }
    if secret_sensitive
        && [
            "secret-value",
            "private-key-value",
            "credential-value",
            "token-value",
            "password-value",
        ]
        .iter()
        .any(|term| value.contains(term))
    {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidPrerequisite,
            format!("{label} appears to embed protected material"),
        ));
    }
    Ok(())
}

fn validate_token(value: &str, label: &str) -> Result<(), RuntimeClosureFault> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value != value.to_ascii_lowercase()
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
        || ["latest", "ambient", "current-directory", "path-lookup"]
            .iter()
            .any(|term| value.contains(term))
    {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidProfile,
            format!("{label} differs from bounded immutable token grammar"),
        ));
    }
    Ok(())
}

fn validate_uuid_id(identity: &SemanticId, label: &str) -> Result<(), RuntimeClosureFault> {
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
            RuntimeClosureFaultCode::InvalidIdentity,
            format!("{label} is not a nonnil lowercase UUID-bearing identity"),
        ));
    }
    Ok(())
}

fn insert_identity(
    identities: &mut BTreeSet<SemanticId>,
    identity: &SemanticId,
    label: &str,
) -> Result<(), RuntimeClosureFault> {
    if !identities.insert(identity.clone()) {
        return Err(fault(
            RuntimeClosureFaultCode::IdentityCollision,
            format!("{label} collides with another bound identity"),
        ));
    }
    Ok(())
}

fn validate_digest(digest: &ContentDigest, label: &str) -> Result<(), RuntimeClosureFault> {
    if digest.algorithm != "sha256" || !is_lower_sha256(&digest.value) {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidDigest,
            format!("{label} is not lower-case SHA256"),
        ));
    }
    Ok(())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && value
            .chars()
            .all(|character| !character.is_control() && character != '\u{7f}')
}

fn sha256_form<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<ContentDigest, RuntimeClosureFault> {
    let body = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + body.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&body);
    Ok(sha256_bytes(&bytes))
}

fn to_machine_form<T: Serialize>(value: &T) -> Result<String, RuntimeClosureFault> {
    serde_json::to_string(value).map_err(machine_form_fault)
}

fn parse_bounded<T: DeserializeOwned + Serialize>(value: &str) -> Result<T, RuntimeClosureFault> {
    parse_bounded_with_limit(value, RUNTIME_CLOSURE_MAX_MACHINE_FORM_BYTES)
}

fn parse_bounded_with_limit<T: DeserializeOwned + Serialize>(
    value: &str,
    limit: usize,
) -> Result<T, RuntimeClosureFault> {
    if value.len() > limit {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidMachineForm,
            format!("machine form exceeds {limit} bytes"),
        ));
    }
    let mut duplicate_check = serde_json::Deserializer::from_str(value);
    NoDuplicateJson::deserialize(&mut duplicate_check).map_err(machine_form_fault)?;
    duplicate_check.end().map_err(machine_form_fault)?;
    let shape: Value = serde_json::from_str(value).map_err(machine_form_fault)?;
    let mut fields = 0_usize;
    validate_json_shape(&shape, 1, &mut fields, None)?;
    let parsed: T = serde_json::from_str(value).map_err(machine_form_fault)?;
    if to_machine_form(&parsed)? != value {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidMachineForm,
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
) -> Result<(), RuntimeClosureFault> {
    if depth > MAX_DEPTH {
        return Err(fault(
            RuntimeClosureFaultCode::InvalidMachineForm,
            "machine form exceeds depth 32",
        ));
    }
    match value {
        Value::Object(map) => {
            *fields = fields.checked_add(map.len()).ok_or_else(|| {
                fault(
                    RuntimeClosureFaultCode::InvalidMachineForm,
                    "machine form field count overflow",
                )
            })?;
            if *fields > MAX_FIELDS {
                return Err(fault(
                    RuntimeClosureFaultCode::InvalidMachineForm,
                    "machine form exceeds 4096 fields",
                ));
            }
            for (key, child) in map {
                if !valid_text(key) {
                    return Err(fault(
                        RuntimeClosureFaultCode::InvalidMachineForm,
                        "machine field text differs",
                    ));
                }
                validate_json_shape(child, depth + 1, fields, Some(key))?;
            }
        }
        Value::Array(values) => {
            let is_string_set = matches!(
                parent_key,
                Some(
                    "capability_ceiling"
                        | "compatibility_refs"
                        | "inputs"
                        | "evidence_refs"
                        | "capability_denials"
                )
            );
            if is_string_set && values.iter().all(Value::is_string) {
                let unique = values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>();
                if unique.len() != values.len() {
                    return Err(fault(
                        RuntimeClosureFaultCode::InvalidMachineForm,
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
                Some("request_file" | "envelope_file" | "verification_file" | "manifest_file")
            );
            if (!file_body && !valid_text(text))
                || (file_body && text.len() > RUNTIME_CLOSURE_MAX_MACHINE_FORM_BYTES)
            {
                return Err(fault(
                    RuntimeClosureFaultCode::InvalidMachineForm,
                    "machine text differs",
                ));
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn material_node(
    node_id: SemanticId,
    kind: RuntimeClosureMaterialKind,
    expected_sha256: ContentDigest,
    expected_bytes: u64,
    provenance_ref: &str,
    target: &str,
    executable: RuntimeClosureExecutableDisposition,
) -> Result<RuntimeClosureMaterialNode, RuntimeClosureFault> {
    Ok(RuntimeClosureMaterialNode {
        node_id,
        kind,
        expected_sha256,
        expected_bytes,
        provenance_ref: sid(provenance_ref)?,
        compatibility_refs: BTreeSet::new(),
        target: target.to_owned(),
        verifier_profile: "sha256-exact/0.2".to_owned(),
        executable,
    })
}

#[allow(clippy::too_many_arguments)]
fn producer_edge(
    edge_id: &str,
    inputs: BTreeSet<SemanticId>,
    output: SemanticId,
    source_kind: RuntimeClosureSourceKind,
    source_id: &str,
    immutable_ref: String,
    transform_profile: &str,
    expected_sha256: ContentDigest,
    expected_bytes: u64,
) -> Result<RuntimeClosureProducerEdge, RuntimeClosureFault> {
    Ok(RuntimeClosureProducerEdge {
        edge_id: sid(edge_id)?,
        inputs,
        output,
        source: RuntimeClosureSourceDescriptor {
            source_id: sid(source_id)?,
            kind: source_kind,
            immutable_ref: sid(&immutable_ref)?,
            expected_sha256: expected_sha256.clone(),
            expected_bytes,
        },
        transform_profile: transform_profile.to_owned(),
        expected_sha256,
        expected_bytes,
    })
}

fn sid(value: &str) -> Result<SemanticId, RuntimeClosureFault> {
    SemanticId::new(value).map_err(|error| {
        fault(
            RuntimeClosureFaultCode::InvalidIdentity,
            format!("fixture semantic identity refused: {error}"),
        )
    })
}

fn digest(character: char) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: character.to_string().repeat(64),
    }
}

fn empty_digest() -> ContentDigest {
    digest('0')
}

fn count_u32(value: usize) -> Result<u32, RuntimeClosureFault> {
    u32::try_from(value).map_err(|_| {
        fault(
            RuntimeClosureFaultCode::InvalidBound,
            "count conversion exceeds u32",
        )
    })
}

fn fault(code: RuntimeClosureFaultCode, detail: impl Into<String>) -> RuntimeClosureFault {
    RuntimeClosureFault {
        code,
        detail: detail.into(),
    }
}

fn machine_fault(error: serde_json::Error) -> RuntimeClosureFault {
    fault(
        RuntimeClosureFaultCode::InvalidDigest,
        format!("canonical serialization refused: {error}"),
    )
}

fn machine_form_fault(error: serde_json::Error) -> RuntimeClosureFault {
    fault(
        RuntimeClosureFaultCode::InvalidMachineForm,
        format!("machine form refused: {error}"),
    )
}
