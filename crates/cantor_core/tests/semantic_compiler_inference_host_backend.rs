use std::collections::{BTreeMap, BTreeSet};

use cantor_core::*;

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn digest(byte: char) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: byte.to_string().repeat(64),
    }
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

fn address(name: &str, kind: UnitKind, byte: char) -> SemanticAddress {
    let unit_id = id(&format!("unit:{name}"));
    let package_id = id("package:inference-host");
    SemanticAddress {
        unit_id: unit_id.clone(),
        unit_digest: digest(byte),
        package_id: package_id.clone(),
        package_digest: digest('a'),
        kind,
        context_id: id("context:inference-host"),
        version: "0.1.0".to_owned(),
        source_anchors: vec![SourceAnchor {
            package_id,
            file_id: id("file:inference-host"),
            unit_id,
            clause_id: id(&format!("clause:{name}")),
            byte_start: 1,
            byte_end: 10,
            span_digest: digest('b'),
            display_line_start: 1,
            display_line_end: 1,
        }],
    }
}

fn ir() -> TypedSopIr {
    let type_id = id("node:type");
    let input_id = id("node:input");
    let output_id = id("node:output");
    let nodes = BTreeMap::from([
        (
            type_id.clone(),
            SemanticIrNode {
                node_id: type_id.clone(),
                kind: SemanticIrNodeKind::Type,
                semantic_address: address("type", UnitKind::Term, 'c'),
                type_ref: None,
                dependency_refs: BTreeSet::new(),
                generated_derivation_refs: BTreeSet::new(),
            },
        ),
        (
            input_id.clone(),
            SemanticIrNode {
                node_id: input_id.clone(),
                kind: SemanticIrNodeKind::Input,
                semantic_address: address("input", UnitKind::Declaration, 'd'),
                type_ref: Some(type_id.clone()),
                dependency_refs: BTreeSet::from([type_id.clone()]),
                generated_derivation_refs: BTreeSet::new(),
            },
        ),
        (
            output_id.clone(),
            SemanticIrNode {
                node_id: output_id.clone(),
                kind: SemanticIrNodeKind::Output,
                semantic_address: address("output", UnitKind::Declaration, 'e'),
                type_ref: Some(type_id),
                dependency_refs: BTreeSet::from([input_id]),
                generated_derivation_refs: BTreeSet::new(),
            },
        ),
    ]);
    let source_map = nodes
        .iter()
        .map(|(node_id, node)| {
            (
                node_id.clone(),
                CompilerSourceMapEntry {
                    node_ref: node_id.clone(),
                    semantic_address: node.semantic_address.clone(),
                    derivation_refs: BTreeSet::new(),
                },
            )
        })
        .collect();
    let mut value = TypedSopIr {
        profile: TYPED_SOP_IR_PROFILE.to_owned(),
        ir_id: id("ir:inference-host"),
        source_manifest_digest: digest('f'),
        canonical_specification_ref: id("spec:seeded-compiler"),
        canonical_specification_digest: digest('1'),
        nodes,
        source_map,
        unresolved_account: BTreeSet::new(),
        non_authority: COMPILER_NON_AUTHORITY.to_owned(),
        ir_digest: empty_digest(),
    };
    value.ir_digest = typed_sop_ir_digest(&value).expect("IR digest");
    value
}

fn ceiling() -> CompilerCapabilityCeiling {
    let mut value = CompilerCapabilityCeiling {
        profile: COMPILER_CAPABILITY_CEILING_PROFILE.to_owned(),
        ceiling_id: id("ceiling:inference-host"),
        capabilities: BTreeSet::from([
            CompilerCapability::SemanticRead,
            CompilerCapability::SourceRead,
            CompilerCapability::Network,
        ]),
        resource_scopes: BTreeSet::from(["fixture-only".to_owned()]),
        maximum_artifacts: 4,
        maximum_serialized_bytes: 1_048_576,
        ceiling_digest: empty_digest(),
    };
    value.ceiling_digest = compiler_capability_ceiling_digest(&value).expect("ceiling digest");
    value
}

fn seed() -> SopSeed {
    let mut value = SopSeed {
        profile: SOP_SEED_PROFILE.to_owned(),
        seed_id: id("seed:inference-host"),
        generation_id: id("generation:inference-host:r1"),
        purpose: "project one external inference host integration".to_owned(),
        honesty_trust_root_ref: id("trust:honesty"),
        security_trust_root_ref: id("trust:security"),
        authority_trust_root_ref: id("trust:authority"),
        compiler_trust_root_ref: id("trust:compiler"),
        dependency_roots: BTreeMap::from([(id("dependency:sop-core"), digest('2'))]),
        discovery_contract_ref: id("contract:seed-discovery"),
        semantic_frontend_profile: "cantor-semantic-frontend/0.1".to_owned(),
        backend_profiles: BTreeMap::from([
            (
                CompilerBackendKind::AttentionProcedure,
                "cantor-attention-procedure-backend/0.1".to_owned(),
            ),
            (
                CompilerBackendKind::InferenceHostIntegration,
                "cantor-inference-host-backend/0.1".to_owned(),
            ),
            (
                CompilerBackendKind::NativeArtifact,
                "cantor-native-artifact-backend/0.1".to_owned(),
            ),
        ]),
        capability_ceiling: ceiling(),
        predecessor_generation_ref: Some(id("generation:inference-host:r0")),
        successor_policy_ref: id("policy:external-successor-recognition"),
        seed_digest: empty_digest(),
    };
    value.seed_digest = sop_seed_digest(&value).expect("seed digest");
    value
}

fn plan() -> CandidateCompilationPlan {
    let seed = seed();
    let ir = ir();
    let mut value = CandidateCompilationPlan {
        profile: CANDIDATE_COMPILATION_PLAN_PROFILE.to_owned(),
        plan_id: id("plan:inference-host"),
        seed_ref: seed.seed_id.clone(),
        seed_digest: seed.seed_digest,
        ir_ref: ir.ir_id.clone(),
        ir_digest: ir.ir_digest,
        backend: CompilerBackendKind::InferenceHostIntegration,
        backend_profile: seed.backend_profiles[&CompilerBackendKind::InferenceHostIntegration]
            .clone(),
        purpose: seed.purpose,
        requested_capabilities: BTreeSet::from([
            CompilerCapability::SemanticRead,
            CompilerCapability::SourceRead,
        ]),
        input_refs: BTreeSet::from([id("node:input")]),
        expected_output_refs: BTreeSet::from([id("node:output")]),
        verifier_refs: BTreeSet::from([id("verifier:inference-host")]),
        rollback_ref: id("rollback:inference-host"),
        unresolved_account: BTreeSet::new(),
        non_authority: COMPILER_NON_AUTHORITY.to_owned(),
        plan_digest: empty_digest(),
    };
    value.plan_digest = candidate_compilation_plan_digest(&value).expect("plan digest");
    value
}

fn request() -> InferenceHostBackendRequest {
    let ir = ir();
    let plan = plan();
    InferenceHostBackendRequest {
        profile: INFERENCE_HOST_BACKEND_REQUEST_PROFILE.to_owned(),
        request_id: id("request:inference-host"),
        candidate_id: id("candidate:inference-host"),
        plan_ref: plan.plan_id,
        plan_digest: plan.plan_digest,
        ir_ref: ir.ir_id,
        ir_digest: ir.ir_digest,
        purpose: plan.purpose,
        target: InferenceHostTargetKind::ExternalProcessAdapter,
        semantic_node_refs: ir.nodes.keys().cloned().collect(),
        host: HostImplementationPin {
            implementation_id: id("implementation:cantor-reflection-loop"),
            source_revision: "git:fixture-revision".to_owned(),
            source_digest: digest('3'),
            artifact_digest: digest('4'),
            configuration_profile: "cantor-reflection-loop-contract/0.1".to_owned(),
        },
        provider: ProviderProtocolBinding {
            provider_family: LLAMA_CPP_PROVIDER_FAMILY.to_owned(),
            protocol_profile: OPENAI_CHAT_COMPLETIONS_PROTOCOL.to_owned(),
            base_url: "http://127.0.0.1:8081/v1".to_owned(),
            model_selector: "sole-advertised-model".to_owned(),
            request_contract_digest: digest('5'),
            observed_capabilities: BTreeSet::from([
                ProviderCapabilityObservation::StructuredToolCall,
                ProviderCapabilityObservation::BufferedCompletion,
                ProviderCapabilityObservation::Cancellation,
            ]),
        },
        tool: ModelToolBinding {
            tool_name: "route_attention".to_owned(),
            tool_description: "route one bounded attention request".to_owned(),
            input_schema_digest: digest('6'),
            output_schema_digest: digest('7'),
            annotations_digest: digest('8'),
            result_contract_digest: digest('9'),
        },
        mcp: McpProcessBinding {
            process_id: id("process:cantor-attention-mcp"),
            executable_digest: digest('a'),
            configuration_digest: digest('b'),
            transport: McpTransportKind::Stdio,
            operation_name: "route_attention".to_owned(),
            result_contract_digest: digest('c'),
        },
        flow: HostFlowContract {
            stages: vec![
                HostFlowStage::InitialInferenceRequested,
                HostFlowStage::ToolCallReceived,
                HostFlowStage::ToolCallValidated,
                HostFlowStage::ToolDispatched,
                HostFlowStage::ToolResultReceived,
                HostFlowStage::ReflectionInferenceRequested,
                HostFlowStage::FinalResponseValidated,
                HostFlowStage::Terminal,
            ],
            maximum_provider_passes: 2,
            maximum_tool_calls: 1,
            parallel_tool_calls: false,
            timeout_seconds: 180,
            cancellation: CancellationMode::Required,
            streaming: StreamingMode::BufferedOnly,
            maximum_request_bytes: 65_536,
            maximum_response_bytes: 65_536,
            maximum_completion_tokens: 384,
        },
        runtime_requirements: BTreeSet::from([
            HostRuntimeRequirement::LoopbackNetwork,
            HostRuntimeRequirement::ProviderProcess,
            HostRuntimeRequirement::McpProcess,
            HostRuntimeRequirement::ModelInvocation,
        ]),
        compatibility: CompatibilityAccount {
            case_kinds: BTreeSet::from([
                CompatibilityCaseKind::Positive,
                CompatibilityCaseKind::Refusal,
                CompatibilityCaseKind::Control,
            ]),
            evidence_refs: BTreeSet::from([id("evidence:reflection-loop-p0")]),
            known_limitations: BTreeSet::from([MID_COMPLETION_LIMITATION.to_owned()]),
            rollback_ref: id("rollback:inference-host"),
        },
        unresolved_account: BTreeSet::from([
            "candidate compatibility has not been independently verified".to_owned(),
        ]),
        non_authority: COMPILER_NON_AUTHORITY.to_owned(),
    }
}

#[test]
fn external_inference_host_candidate_is_deterministic_strict_and_ungranted() {
    let seed = seed();
    let ir = ir();
    let plan = plan();
    let request = request();
    let first =
        project_inference_host_backend(&seed, &ir, &plan, &request).expect("first projection");
    let second =
        project_inference_host_backend(&seed, &ir, &plan, &request).expect("second projection");
    assert_eq!(first, second);
    assert_eq!(
        first.candidate.lifecycle,
        IntegrationCandidateLifecycle::Proposed
    );
    assert_eq!(first.candidate.flow.streaming, StreamingMode::BufferedOnly);
    assert!(
        first
            .candidate
            .runtime_requirements
            .contains(&HostRuntimeRequirement::ModelInvocation)
    );
    assert!(
        !plan
            .requested_capabilities
            .contains(&CompilerCapability::Network)
    );
    validate_inference_host_backend_projection(&seed, &ir, &plan, &request, &first)
        .expect("projection validates");

    let mut json = serde_json::to_value(&request).expect("request JSON");
    json["invented_execution_authority"] = serde_json::json!(true);
    assert!(serde_json::from_value::<InferenceHostBackendRequest>(json).is_err());
}

#[test]
fn internal_target_nonloopback_and_capability_laundering_refuse() {
    let seed = seed();
    let ir = ir();
    let plan = plan();

    let mut internal = request();
    internal.target = InferenceHostTargetKind::InternalLlamaCppAddon;
    assert_eq!(
        project_inference_host_backend(&seed, &ir, &plan, &internal)
            .expect_err("internal target refuses")
            .kind,
        SemanticCompilerFormFaultKind::BackendMismatch
    );

    let mut remote = request();
    remote.provider.base_url = "https://example.com/v1".to_owned();
    assert_eq!(
        project_inference_host_backend(&seed, &ir, &plan, &remote)
            .expect_err("remote provider refuses")
            .kind,
        SemanticCompilerFormFaultKind::InvalidProfile
    );

    let mut elevated_plan = plan.clone();
    elevated_plan
        .requested_capabilities
        .insert(CompilerCapability::Network);
    elevated_plan.plan_digest =
        candidate_compilation_plan_digest(&elevated_plan).expect("reseal plan");
    let mut elevated_request = request();
    elevated_request.plan_digest = elevated_plan.plan_digest.clone();
    assert_eq!(
        project_inference_host_backend(&seed, &ir, &elevated_plan, &elevated_request)
            .expect_err("network capability refuses")
            .kind,
        SemanticCompilerFormFaultKind::CapabilityExceeded
    );
}

#[test]
fn flow_compatibility_and_projection_substitution_refuse() {
    let seed = seed();
    let ir = ir();
    let plan = plan();

    let mut unbounded = request();
    unbounded.flow.maximum_tool_calls = 2;
    assert_eq!(
        project_inference_host_backend(&seed, &ir, &plan, &unbounded)
            .expect_err("second tool call refuses")
            .kind,
        SemanticCompilerFormFaultKind::InvalidBound
    );

    let mut missing_control = request();
    missing_control
        .compatibility
        .case_kinds
        .remove(&CompatibilityCaseKind::Control);
    assert_eq!(
        project_inference_host_backend(&seed, &ir, &plan, &missing_control)
            .expect_err("missing control refuses")
            .kind,
        SemanticCompilerFormFaultKind::AccountingMismatch
    );

    let request = request();
    let mut projection =
        project_inference_host_backend(&seed, &ir, &plan, &request).expect("projection");
    projection.candidate.provider.model_selector = "substituted-model".to_owned();
    projection.projection_digest =
        inference_host_backend_projection_digest(&projection).expect("reseal outer digest");
    assert_eq!(
        validate_inference_host_backend_projection(&seed, &ir, &plan, &request, &projection)
            .expect_err("resealed substitution refuses")
            .kind,
        SemanticCompilerFormFaultKind::InvalidReference
    );
}
