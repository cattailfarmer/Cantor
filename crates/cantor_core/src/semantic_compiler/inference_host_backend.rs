//! Pure candidate projection for an external inference-host integration.
//!
//! The forms describe a future host seam. Projection performs no I/O, launches
//! no process, calls no model, and grants none of the runtime requirements it
//! records.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{
    COMPILER_NON_AUTHORITY, CandidateCompilationPlan, CompilerBackendKind, CompilerCapability,
    SemanticCompilerFormFaultKind, SemanticCompilerValidation, SopSeed, TypedSopIr, bounded_set,
    bounded_text, digest_form, exact_non_authority, exact_profile, form_fault, normalize,
    require_digest, validate_candidate_compilation_plan, validate_digest,
};
use crate::{ContentDigest, SemanticId};

pub const INFERENCE_HOST_BACKEND_REQUEST_PROFILE: &str =
    "cantor-inference-host-backend-request/0.1";
pub const INFERENCE_HOST_INTEGRATION_CANDIDATE_PROFILE: &str =
    "cantor-inference-host-integration-candidate/0.1";
pub const INFERENCE_HOST_BACKEND_PROJECTION_PROFILE: &str =
    "cantor-inference-host-backend-projection/0.1";
pub const LLAMA_CPP_PROVIDER_FAMILY: &str = "llama.cpp";
pub const OPENAI_CHAT_COMPLETIONS_PROTOCOL: &str = "openai-compatible-chat-completions/0.1";
pub const MID_COMPLETION_LIMITATION: &str = "mid_completion_semantic_insertion_not_supported";

const CANDIDATE_DOMAIN: &str = "cantor.semantic-compiler.inference-host-candidate.v1";
const PROJECTION_DOMAIN: &str = "cantor.semantic-compiler.inference-host-projection.v1";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceHostTargetKind {
    ExternalProcessAdapter,
    InternalLlamaCppAddon,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCapabilityObservation {
    StructuredToolCall,
    BufferedCompletion,
    Cancellation,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostRuntimeRequirement {
    LoopbackNetwork,
    ProviderProcess,
    McpProcess,
    ModelInvocation,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTransportKind {
    Stdio,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostFlowStage {
    InitialInferenceRequested,
    ToolCallReceived,
    ToolCallValidated,
    ToolDispatched,
    ToolResultReceived,
    ReflectionInferenceRequested,
    FinalResponseValidated,
    Terminal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamingMode {
    BufferedOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationMode {
    Required,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityCaseKind {
    Positive,
    Refusal,
    Control,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationCandidateLifecycle {
    Proposed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostImplementationPin {
    pub implementation_id: SemanticId,
    pub source_revision: String,
    pub source_digest: ContentDigest,
    pub artifact_digest: ContentDigest,
    pub configuration_profile: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderProtocolBinding {
    pub provider_family: String,
    pub protocol_profile: String,
    pub base_url: String,
    pub model_selector: String,
    pub request_contract_digest: ContentDigest,
    pub observed_capabilities: BTreeSet<ProviderCapabilityObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelToolBinding {
    pub tool_name: String,
    pub tool_description: String,
    pub input_schema_digest: ContentDigest,
    pub output_schema_digest: ContentDigest,
    pub annotations_digest: ContentDigest,
    pub result_contract_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpProcessBinding {
    pub process_id: SemanticId,
    pub executable_digest: ContentDigest,
    pub configuration_digest: ContentDigest,
    pub transport: McpTransportKind,
    pub operation_name: String,
    pub result_contract_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostFlowContract {
    pub stages: Vec<HostFlowStage>,
    pub maximum_provider_passes: u32,
    pub maximum_tool_calls: u32,
    pub parallel_tool_calls: bool,
    pub timeout_seconds: u32,
    pub cancellation: CancellationMode,
    pub streaming: StreamingMode,
    pub maximum_request_bytes: u64,
    pub maximum_response_bytes: u64,
    pub maximum_completion_tokens: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityAccount {
    pub case_kinds: BTreeSet<CompatibilityCaseKind>,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub known_limitations: BTreeSet<String>,
    pub rollback_ref: SemanticId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceHostBackendRequest {
    pub profile: String,
    pub request_id: SemanticId,
    pub candidate_id: SemanticId,
    pub plan_ref: SemanticId,
    pub plan_digest: ContentDigest,
    pub ir_ref: SemanticId,
    pub ir_digest: ContentDigest,
    pub purpose: String,
    pub target: InferenceHostTargetKind,
    pub semantic_node_refs: BTreeSet<SemanticId>,
    pub host: HostImplementationPin,
    pub provider: ProviderProtocolBinding,
    pub tool: ModelToolBinding,
    pub mcp: McpProcessBinding,
    pub flow: HostFlowContract,
    pub runtime_requirements: BTreeSet<HostRuntimeRequirement>,
    pub compatibility: CompatibilityAccount,
    pub unresolved_account: BTreeSet<String>,
    pub non_authority: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceHostIntegrationCandidate {
    pub profile: String,
    pub candidate_id: SemanticId,
    pub seed_ref: SemanticId,
    pub seed_digest: ContentDigest,
    pub plan_ref: SemanticId,
    pub plan_digest: ContentDigest,
    pub ir_ref: SemanticId,
    pub ir_digest: ContentDigest,
    pub purpose: String,
    pub target: InferenceHostTargetKind,
    pub semantic_node_refs: BTreeSet<SemanticId>,
    pub host: HostImplementationPin,
    pub provider: ProviderProtocolBinding,
    pub tool: ModelToolBinding,
    pub mcp: McpProcessBinding,
    pub flow: HostFlowContract,
    pub runtime_requirements: BTreeSet<HostRuntimeRequirement>,
    pub compatibility: CompatibilityAccount,
    pub lifecycle: IntegrationCandidateLifecycle,
    pub unresolved_account: BTreeSet<String>,
    pub non_authority: String,
    pub candidate_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceHostBackendProjection {
    pub profile: String,
    pub request_id: SemanticId,
    pub candidate: InferenceHostIntegrationCandidate,
    pub projection_digest: ContentDigest,
}

pub fn inference_host_integration_candidate_digest(
    candidate: &InferenceHostIntegrationCandidate,
) -> SemanticCompilerValidation<ContentDigest> {
    let mut body = candidate.clone();
    body.candidate_digest = empty_digest();
    digest_form(CANDIDATE_DOMAIN, &body)
}

pub fn inference_host_backend_projection_digest(
    projection: &InferenceHostBackendProjection,
) -> SemanticCompilerValidation<ContentDigest> {
    let mut body = projection.clone();
    body.projection_digest = empty_digest();
    digest_form(PROJECTION_DOMAIN, &body)
}

pub fn project_inference_host_backend(
    seed: &SopSeed,
    ir: &TypedSopIr,
    plan: &CandidateCompilationPlan,
    request: &InferenceHostBackendRequest,
) -> SemanticCompilerValidation<InferenceHostBackendProjection> {
    validate_inference_host_backend_request(seed, ir, plan, request)?;
    let candidate = project_candidate(seed, ir, plan, request)?;
    let mut projection = InferenceHostBackendProjection {
        profile: INFERENCE_HOST_BACKEND_PROJECTION_PROFILE.to_owned(),
        request_id: request.request_id.clone(),
        candidate,
        projection_digest: empty_digest(),
    };
    projection.projection_digest = inference_host_backend_projection_digest(&projection)?;
    validate_inference_host_backend_projection(seed, ir, plan, request, &projection)?;
    Ok(projection)
}

pub fn validate_inference_host_backend_projection(
    seed: &SopSeed,
    ir: &TypedSopIr,
    plan: &CandidateCompilationPlan,
    request: &InferenceHostBackendRequest,
    projection: &InferenceHostBackendProjection,
) -> SemanticCompilerValidation {
    validate_inference_host_backend_request(seed, ir, plan, request)?;
    exact_profile(
        &projection.profile,
        INFERENCE_HOST_BACKEND_PROJECTION_PROFILE,
        "projection.profile",
    )?;
    let expected = project_candidate(seed, ir, plan, request)?;
    if projection.request_id != request.request_id || projection.candidate != expected {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "projection.lineage",
            "projection candidate differs from exact request and upstream lineage",
        );
    }
    validate_digest(
        &projection.projection_digest,
        "projection.projection_digest",
    )?;
    require_digest(
        &projection.projection_digest,
        inference_host_backend_projection_digest(projection)?,
        "projection.projection_digest",
    )
}

fn project_candidate(
    seed: &SopSeed,
    ir: &TypedSopIr,
    plan: &CandidateCompilationPlan,
    request: &InferenceHostBackendRequest,
) -> SemanticCompilerValidation<InferenceHostIntegrationCandidate> {
    let mut candidate = InferenceHostIntegrationCandidate {
        profile: INFERENCE_HOST_INTEGRATION_CANDIDATE_PROFILE.to_owned(),
        candidate_id: request.candidate_id.clone(),
        seed_ref: seed.seed_id.clone(),
        seed_digest: seed.seed_digest.clone(),
        plan_ref: plan.plan_id.clone(),
        plan_digest: plan.plan_digest.clone(),
        ir_ref: ir.ir_id.clone(),
        ir_digest: ir.ir_digest.clone(),
        purpose: request.purpose.clone(),
        target: request.target.clone(),
        semantic_node_refs: request.semantic_node_refs.clone(),
        host: request.host.clone(),
        provider: request.provider.clone(),
        tool: request.tool.clone(),
        mcp: request.mcp.clone(),
        flow: request.flow.clone(),
        runtime_requirements: request.runtime_requirements.clone(),
        compatibility: request.compatibility.clone(),
        lifecycle: IntegrationCandidateLifecycle::Proposed,
        unresolved_account: request.unresolved_account.clone(),
        non_authority: COMPILER_NON_AUTHORITY.to_owned(),
        candidate_digest: empty_digest(),
    };
    candidate.candidate_digest = inference_host_integration_candidate_digest(&candidate)?;
    Ok(candidate)
}

fn validate_inference_host_backend_request(
    seed: &SopSeed,
    ir: &TypedSopIr,
    plan: &CandidateCompilationPlan,
    request: &InferenceHostBackendRequest,
) -> SemanticCompilerValidation {
    validate_candidate_compilation_plan(seed, ir, plan)?;
    exact_profile(
        &request.profile,
        INFERENCE_HOST_BACKEND_REQUEST_PROFILE,
        "request.profile",
    )?;
    if plan.backend != CompilerBackendKind::InferenceHostIntegration
        || request.target != InferenceHostTargetKind::ExternalProcessAdapter
    {
        return form_fault(
            SemanticCompilerFormFaultKind::BackendMismatch,
            "request.target",
            "Slice4 permits only the external process inference-host target",
        );
    }
    if request.plan_ref != plan.plan_id
        || request.plan_digest != plan.plan_digest
        || request.ir_ref != ir.ir_id
        || request.ir_digest != ir.ir_digest
        || request.semantic_node_refs != ir.nodes.keys().cloned().collect()
        || normalize(&request.purpose) != normalize(&plan.purpose)
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "request.lineage",
            "request plan IR node set or purpose differs",
        );
    }
    let pure_capabilities = BTreeSet::from([
        CompilerCapability::SemanticRead,
        CompilerCapability::SourceRead,
    ]);
    if !plan.requested_capabilities.is_subset(&pure_capabilities) {
        return form_fault(
            SemanticCompilerFormFaultKind::CapabilityExceeded,
            "plan.requested_capabilities",
            "inference-host candidate projection permits semantic_read and source_read only",
        );
    }
    bounded_text(&request.purpose, "request.purpose")?;
    validate_host(&request.host)?;
    validate_provider(&request.provider)?;
    validate_tool(&request.tool)?;
    validate_mcp(&request.mcp)?;
    validate_flow(&request.flow)?;
    let requirements = BTreeSet::from([
        HostRuntimeRequirement::LoopbackNetwork,
        HostRuntimeRequirement::ProviderProcess,
        HostRuntimeRequirement::McpProcess,
        HostRuntimeRequirement::ModelInvocation,
    ]);
    if request.runtime_requirements != requirements {
        return form_fault(
            SemanticCompilerFormFaultKind::AccountingMismatch,
            "request.runtime_requirements",
            "runtime requirements must name the complete external seam without granting them",
        );
    }
    validate_compatibility(&request.compatibility)?;
    bounded_set(&request.unresolved_account, "request.unresolved_account")?;
    exact_non_authority(&request.non_authority, "request.non_authority")
}

fn validate_host(host: &HostImplementationPin) -> SemanticCompilerValidation {
    bounded_text(&host.source_revision, "request.host.source_revision")?;
    bounded_text(
        &host.configuration_profile,
        "request.host.configuration_profile",
    )?;
    validate_digest(&host.source_digest, "request.host.source_digest")?;
    validate_digest(&host.artifact_digest, "request.host.artifact_digest")
}

fn validate_provider(provider: &ProviderProtocolBinding) -> SemanticCompilerValidation {
    if provider.provider_family != LLAMA_CPP_PROVIDER_FAMILY
        || provider.protocol_profile != OPENAI_CHAT_COMPLETIONS_PROTOCOL
        || !is_loopback_v1(&provider.base_url)
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidProfile,
            "request.provider",
            "provider must be exact llama.cpp OpenAI-compatible loopback HTTP /v1",
        );
    }
    bounded_text(&provider.model_selector, "request.provider.model_selector")?;
    validate_digest(
        &provider.request_contract_digest,
        "request.provider.request_contract_digest",
    )?;
    let expected = BTreeSet::from([
        ProviderCapabilityObservation::StructuredToolCall,
        ProviderCapabilityObservation::BufferedCompletion,
        ProviderCapabilityObservation::Cancellation,
    ]);
    if provider.observed_capabilities != expected {
        return form_fault(
            SemanticCompilerFormFaultKind::AccountingMismatch,
            "request.provider.observed_capabilities",
            "provider observations must be the exact bounded P0 set",
        );
    }
    Ok(())
}

fn validate_tool(tool: &ModelToolBinding) -> SemanticCompilerValidation {
    bounded_text(&tool.tool_name, "request.tool.tool_name")?;
    bounded_text(&tool.tool_description, "request.tool.tool_description")?;
    for digest in [
        &tool.input_schema_digest,
        &tool.output_schema_digest,
        &tool.annotations_digest,
        &tool.result_contract_digest,
    ] {
        validate_digest(digest, "request.tool.digest")?;
    }
    Ok(())
}

fn validate_mcp(mcp: &McpProcessBinding) -> SemanticCompilerValidation {
    bounded_text(&mcp.operation_name, "request.mcp.operation_name")?;
    for digest in [
        &mcp.executable_digest,
        &mcp.configuration_digest,
        &mcp.result_contract_digest,
    ] {
        validate_digest(digest, "request.mcp.digest")?;
    }
    Ok(())
}

fn validate_flow(flow: &HostFlowContract) -> SemanticCompilerValidation {
    let expected = vec![
        HostFlowStage::InitialInferenceRequested,
        HostFlowStage::ToolCallReceived,
        HostFlowStage::ToolCallValidated,
        HostFlowStage::ToolDispatched,
        HostFlowStage::ToolResultReceived,
        HostFlowStage::ReflectionInferenceRequested,
        HostFlowStage::FinalResponseValidated,
        HostFlowStage::Terminal,
    ];
    if flow.stages != expected
        || flow.maximum_provider_passes != 2
        || flow.maximum_tool_calls != 1
        || flow.parallel_tool_calls
        || !(1..=600).contains(&flow.timeout_seconds)
        || flow.maximum_request_bytes == 0
        || flow.maximum_response_bytes == 0
        || flow.maximum_completion_tokens == 0
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidBound,
            "request.flow",
            "flow must be the exact bounded buffered two-pass one-tool-call sequence",
        );
    }
    Ok(())
}

fn validate_compatibility(account: &CompatibilityAccount) -> SemanticCompilerValidation {
    let expected = BTreeSet::from([
        CompatibilityCaseKind::Positive,
        CompatibilityCaseKind::Refusal,
        CompatibilityCaseKind::Control,
    ]);
    if account.case_kinds != expected
        || account.evidence_refs.is_empty()
        || !account
            .known_limitations
            .contains(MID_COMPLETION_LIMITATION)
    {
        return form_fault(
            SemanticCompilerFormFaultKind::AccountingMismatch,
            "request.compatibility",
            "compatibility must retain all controls evidence and the buffered-stream limitation",
        );
    }
    bounded_set(
        &account.known_limitations,
        "request.compatibility.known_limitations",
    )
}

fn is_loopback_v1(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("http://") else {
        return false;
    };
    if rest.contains(['@', '?', '#']) {
        return false;
    }
    let Some((authority, path)) = rest.split_once('/') else {
        return false;
    };
    if path.trim_end_matches('/') != "v1" {
        return false;
    }
    authority == "localhost"
        || authority == "127.0.0.1"
        || authority == "[::1]"
        || authority.strip_prefix("localhost:").is_some_and(valid_port)
        || authority.strip_prefix("127.0.0.1:").is_some_and(valid_port)
        || authority.strip_prefix("[::1]:").is_some_and(valid_port)
}

fn valid_port(value: &str) -> bool {
    value
        .parse::<u16>()
        .is_ok_and(|port| port != 0 && !value.starts_with('0'))
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}
