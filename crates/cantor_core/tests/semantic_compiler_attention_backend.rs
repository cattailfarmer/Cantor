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

fn bounds() -> ProcedureBounds {
    ProcedureBounds {
        bound_set_id: id("bounds:attention-backend"),
        maximum_source_bytes: 4_096,
        maximum_text_bytes: 512,
        maximum_value_bytes: 4_096,
        maximum_collection_items: 64,
        maximum_map_entries: 64,
        maximum_processes: 4,
        maximum_messages: 64,
        maximum_queue_depth: 16,
        maximum_events: 64,
        maximum_event_queue_depth: 16,
        maximum_call_depth: 8,
        maximum_transitions: 64,
        maximum_trace_events: 128,
        maximum_memory_units: 4_096,
    }
}

fn effects() -> ProcedureEffectDeclaration {
    use ProhibitedProcedureOperation::*;
    ProcedureEffectDeclaration {
        effect_class: ProcedureEffectClass::Effectless,
        allowed_read_classes: BTreeSet::from([
            ProcedureReadClass::TypedInvocationInput,
            ProcedureReadClass::PinnedAdmittedInMemoryArtifact,
        ]),
        allowed_write_classes: BTreeSet::from([
            ProcedureWriteClass::ReturnedValue,
            ProcedureWriteClass::Message,
            ProcedureWriteClass::StateSuccessor,
            ProcedureWriteClass::SemanticTrace,
            ProcedureWriteClass::Receipt,
            ProcedureWriteClass::Fault,
        ]),
        prohibited_operations: BTreeSet::from([
            Recursion,
            UnboundedIteration,
            UnrestrictedInheritance,
            DynamicAllocation,
            PointerAccess,
            NativeStackCapture,
            SelfModification,
            RuntimeCodeLoading,
            ExecutableReflection,
            UndeclaredStorage,
            SystemClock,
            Randomness,
            Environment,
            Filesystem,
            Network,
            Database,
            Subprocess,
            Provider,
            Notification,
            Git,
            Model,
            UnsafeCode,
            Device,
            ExternalEffect,
        ]),
    }
}

fn schema_set() -> ProcedureSchemaSet {
    let kinds = [
        SchemaKind::Input,
        SchemaKind::Output,
        SchemaKind::Message,
        SchemaKind::Event,
        SchemaKind::ProcessLocalState,
        SchemaKind::ProcedureState,
        SchemaKind::InvocationResult,
        SchemaKind::Fault,
    ];
    let schemas = kinds
        .into_iter()
        .enumerate()
        .map(|(index, kind)| {
            let schema_id = id(&format!("attention-schema:{index}"));
            (
                schema_id.clone(),
                ProcedureSchema {
                    schema_id,
                    schema_version: "0.1".to_owned(),
                    kind,
                    fields: BTreeMap::new(),
                    tagged_variants: BTreeMap::new(),
                    closed: true,
                },
            )
        })
        .collect();
    let mut value = ProcedureSchemaSet {
        schema_set_id: id("attention-schema-set:fixture"),
        schema_set_digest: empty_digest(),
        schemas,
        migration_ref: None,
    };
    value.schema_set_digest = compute_schema_set_digest(&value).expect("schema digest");
    value
}

fn process() -> ProcessDefinition {
    let entry_id = id("attention-region:entry");
    let terminal_id = id("attention-region:return");
    let entry = ControlRegion {
        region_id: entry_id.clone(),
        instructions: vec![ProcessInstruction {
            instruction_id: id("attention-instruction:inspect"),
            operation: ProcessOperation::Inspect,
            operands: vec![InstructionOperand {
                name: "subject".to_owned(),
                value: ProcedureValue::IdentityReference {
                    value: id("input:subject"),
                },
            }],
            result_binding: Some("observed".to_owned()),
            successor_region_refs: vec![terminal_id.clone()],
            bound_ref: id("bounds:attention-backend"),
            source_span_ref: id("source-span:inspect"),
        }],
        terminal: false,
    };
    let terminal = ControlRegion {
        region_id: terminal_id.clone(),
        instructions: vec![ProcessInstruction {
            instruction_id: id("attention-instruction:return"),
            operation: ProcessOperation::Return,
            operands: Vec::new(),
            result_binding: None,
            successor_region_refs: Vec::new(),
            bound_ref: id("bounds:attention-backend"),
            source_span_ref: id("source-span:return"),
        }],
        terminal: true,
    };
    ProcessDefinition {
        process_definition_id: id("attention-process:observer"),
        name: "Observer".to_owned(),
        role_ref: id("role:observer"),
        initial_state: ProcedureValue::Record {
            fields: BTreeMap::new(),
        },
        accepted_message_tags: BTreeSet::new(),
        emitted_message_tags: BTreeSet::new(),
        entry_region_ref: entry_id.clone(),
        control_regions: BTreeMap::from([(entry_id, entry), (terminal_id.clone(), terminal)]),
        terminal_region_refs: BTreeSet::from([terminal_id]),
        resource_contribution_ref: id("bounds:attention-backend"),
    }
}

fn address(node_name: &str, kind: UnitKind, byte: char) -> SemanticAddress {
    let unit_id = id(&format!("unit:{node_name}"));
    let package_id = id("package:attention-backend");
    SemanticAddress {
        unit_id: unit_id.clone(),
        unit_digest: digest(byte),
        package_id: package_id.clone(),
        package_digest: digest('a'),
        kind,
        context_id: id("context:attention-backend"),
        version: "0.1.0".to_owned(),
        source_anchors: vec![SourceAnchor {
            package_id,
            file_id: id("file:attention-backend"),
            unit_id,
            clause_id: id(&format!("clause:{node_name}")),
            byte_start: 1,
            byte_end: 12,
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
        ir_id: id("ir:attention-backend"),
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
        ceiling_id: id("ceiling:attention-backend"),
        capabilities: BTreeSet::from([
            CompilerCapability::SemanticRead,
            CompilerCapability::SourceRead,
            CompilerCapability::Build,
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
        seed_id: id("seed:attention-backend"),
        generation_id: id("generation:attention-backend:r1"),
        purpose: "compile one anchored attention procedure".to_owned(),
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
        predecessor_generation_ref: Some(id("generation:attention-backend:r0")),
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
        plan_id: id("plan:attention-backend"),
        seed_ref: seed.seed_id.clone(),
        seed_digest: seed.seed_digest,
        ir_ref: ir.ir_id.clone(),
        ir_digest: ir.ir_digest,
        backend: CompilerBackendKind::AttentionProcedure,
        backend_profile: seed.backend_profiles[&CompilerBackendKind::AttentionProcedure].clone(),
        purpose: seed.purpose,
        requested_capabilities: BTreeSet::from([
            CompilerCapability::SemanticRead,
            CompilerCapability::SourceRead,
        ]),
        input_refs: BTreeSet::from([id("node:input")]),
        expected_output_refs: BTreeSet::from([id("node:output")]),
        verifier_refs: BTreeSet::from([id("verifier:attention-backend")]),
        rollback_ref: id("rollback:attention-backend"),
        unresolved_account: BTreeSet::new(),
        non_authority: COMPILER_NON_AUTHORITY.to_owned(),
        plan_digest: empty_digest(),
    };
    value.plan_digest = candidate_compilation_plan_digest(&value).expect("plan digest");
    value
}

fn candidate(ir: &TypedSopIr, plan: &CandidateCompilationPlan) -> ProcedureCandidate {
    let process = process();
    let sop_anchors = ir
        .nodes
        .iter()
        .map(|(node_id, node)| {
            let anchor_id = id(&format!("procedure-anchor:{node_id}"));
            (
                anchor_id.clone(),
                SopAnchorBinding {
                    anchor_id,
                    artifact_id: node.semantic_address.package_id.clone(),
                    artifact_version: node.semantic_address.version.clone(),
                    artifact_digest: node.semantic_address.package_digest.clone(),
                    clause_id: Some(node.semantic_address.source_anchors[0].clause_id.clone()),
                    intended_use: format!("bind {node_id} to its exact semantic source"),
                    sensitivity: SensitivityClass::ProjectInternal,
                },
            )
        })
        .collect();
    let mut value = ProcedureCandidate {
        candidate_id: id("candidate:attention-backend"),
        author_ref: id("author:attention-backend"),
        provenance_refs: BTreeSet::from([plan.plan_id.clone(), ir.ir_id.clone()]),
        purpose: plan.purpose.clone(),
        scope: BTreeSet::from(["attention-procedure-candidate".to_owned()]),
        language_profile: CPPE_FORM_VERSION.to_owned(),
        source_text: None,
        normalized_source_form: Some(ProcedureValue::Record {
            fields: BTreeMap::from([(
                "process".to_owned(),
                ProcedureValue::IdentityReference {
                    value: process.process_definition_id.clone(),
                },
            )]),
        }),
        source_digest: empty_digest(),
        sop_anchors,
        schema_set: schema_set(),
        process_definitions: BTreeMap::from([(process.process_definition_id.clone(), process)]),
        effects: effects(),
        bounds: bounds(),
        created_logical_time: 0,
        sensitivity: SensitivityClass::ProjectInternal,
        retention_policy_ref: id("policy:retention"),
        lifecycle: ProcedureLifecycle::Proposed,
    };
    value.source_digest = compute_candidate_source_digest(&value).expect("candidate digest");
    value
}

fn request() -> AttentionProcedureBackendRequest {
    let ir = ir();
    let plan = plan();
    let candidate = candidate(&ir, &plan);
    let mut validation_receipt = ValidationReceipt {
        receipt_id: id("validation-receipt:attention-backend"),
        candidate_ref: candidate.candidate_id.clone(),
        candidate_source_digest: candidate.source_digest.clone(),
        validator_ref: id("verifier:attention-backend"),
        profile: CPPE_FORM_VERSION.to_owned(),
        disposition: PhaseDisposition::Passed,
        evidence: ReceiptEvidence {
            evidence_refs: BTreeSet::from([plan.plan_id.clone(), ir.ir_id.clone()]),
            residuals: BTreeSet::new(),
            diagnostics: BTreeSet::from(["machine form validated".to_owned()]),
        },
        receipt_digest: empty_digest(),
    };
    validation_receipt.receipt_digest =
        compute_validation_receipt_digest(&validation_receipt).expect("receipt digest");
    AttentionProcedureBackendRequest {
        profile: ATTENTION_PROCEDURE_BACKEND_REQUEST_PROFILE.to_owned(),
        request_id: id("request:attention-backend"),
        plan_ref: plan.plan_id,
        plan_digest: plan.plan_digest,
        ir_ref: ir.ir_id,
        ir_digest: ir.ir_digest,
        semantic_node_anchor_map: ir
            .nodes
            .keys()
            .map(|node_id| (node_id.clone(), id(&format!("procedure-anchor:{node_id}"))))
            .collect(),
        candidate,
        validation_receipt,
        unresolved_account: BTreeSet::new(),
        non_authority: COMPILER_NON_AUTHORITY.to_owned(),
    }
}

#[test]
fn exact_attention_backend_projection_is_deterministic_and_inert() {
    let seed = seed();
    let ir = ir();
    let plan = plan();
    let request = request();
    let first =
        project_attention_procedure_backend(&seed, &ir, &plan, &request).expect("first projection");
    let second = project_attention_procedure_backend(&seed, &ir, &plan, &request)
        .expect("second projection");
    assert_eq!(first, second);
    assert_eq!(
        first.compilation.compilation_receipt.disposition,
        PhaseDisposition::Passed
    );
    assert!(first.compilation.process_ir.is_some());
    assert!(first.compilation.compiled_procedure.is_some());
    assert!(
        first
            .compilation
            .compilation_receipt
            .evidence
            .residuals
            .contains("verification not performed")
    );
    validate_attention_procedure_backend_projection(&seed, &ir, &plan, &request, &first)
        .expect("projection replay validates");

    let mut json = serde_json::to_value(&request).expect("request serializes");
    json["invented_authority"] = serde_json::json!(true);
    assert!(serde_json::from_value::<AttentionProcedureBackendRequest>(json).is_err());
}

#[test]
fn backend_capability_anchor_and_receipt_substitution_fail_closed() {
    let seed = seed();
    let ir = ir();

    let mut wrong_backend = plan();
    wrong_backend.backend = CompilerBackendKind::NativeArtifact;
    wrong_backend.backend_profile =
        seed.backend_profiles[&CompilerBackendKind::NativeArtifact].clone();
    wrong_backend.plan_digest =
        candidate_compilation_plan_digest(&wrong_backend).expect("reseal backend plan");
    let mut wrong_request = request();
    wrong_request.plan_ref = wrong_backend.plan_id.clone();
    wrong_request.plan_digest = wrong_backend.plan_digest.clone();
    assert_eq!(
        project_attention_procedure_backend(&seed, &ir, &wrong_backend, &wrong_request)
            .expect_err("backend substitution fails")
            .kind,
        SemanticCompilerFormFaultKind::BackendMismatch
    );

    let mut capability_plan = plan();
    capability_plan
        .requested_capabilities
        .insert(CompilerCapability::Build);
    capability_plan.plan_digest =
        candidate_compilation_plan_digest(&capability_plan).expect("reseal capability plan");
    let mut capability_request = request();
    capability_request.plan_digest = capability_plan.plan_digest.clone();
    assert_eq!(
        project_attention_procedure_backend(&seed, &ir, &capability_plan, &capability_request)
            .expect_err("build capability fails")
            .kind,
        SemanticCompilerFormFaultKind::CapabilityExceeded
    );

    let plan = plan();
    let mut missing_anchor = request();
    missing_anchor
        .semantic_node_anchor_map
        .remove(&id("node:input"));
    assert_eq!(
        project_attention_procedure_backend(&seed, &ir, &plan, &missing_anchor)
            .expect_err("missing anchor fails")
            .kind,
        SemanticCompilerFormFaultKind::AccountingMismatch
    );

    let mut wrong_clause = request();
    wrong_clause
        .candidate
        .sop_anchors
        .get_mut(&id("procedure-anchor:node:input"))
        .expect("input anchor")
        .clause_id = Some(id("clause:substituted"));
    assert_eq!(
        project_attention_procedure_backend(&seed, &ir, &plan, &wrong_clause)
            .expect_err("wrong clause fails")
            .kind,
        SemanticCompilerFormFaultKind::InvalidReference
    );

    let mut missing_evidence = request();
    missing_evidence
        .validation_receipt
        .evidence
        .evidence_refs
        .remove(&ir.ir_id);
    missing_evidence.validation_receipt.receipt_digest =
        compute_validation_receipt_digest(&missing_evidence.validation_receipt)
            .expect("reseal receipt");
    assert_eq!(
        project_attention_procedure_backend(&seed, &ir, &plan, &missing_evidence)
            .expect_err("missing IR evidence fails")
            .kind,
        SemanticCompilerFormFaultKind::InvalidReference
    );
}

#[test]
fn compilation_output_tampering_fails_replay_validation() {
    let seed = seed();
    let ir = ir();
    let plan = plan();
    let request = request();
    let mut projection =
        project_attention_procedure_backend(&seed, &ir, &plan, &request).expect("projection");
    projection.compilation.compiled_procedure = None;
    assert_eq!(
        validate_attention_procedure_backend_projection(&seed, &ir, &plan, &request, &projection)
            .expect_err("partial output fails")
            .kind,
        SemanticCompilerFormFaultKind::AccountingMismatch
    );

    let mut lineage_tamper =
        project_attention_procedure_backend(&seed, &ir, &plan, &request).expect("projection");
    lineage_tamper
        .compilation
        .compiled_procedure
        .as_mut()
        .expect("compiled identity")
        .ir_digest = digest('9');
    lineage_tamper.projection_digest =
        attention_procedure_backend_projection_digest(&lineage_tamper).expect("reseal projection");
    assert_eq!(
        validate_attention_procedure_backend_projection(
            &seed,
            &ir,
            &plan,
            &request,
            &lineage_tamper,
        )
        .expect_err("compiled identity substitution fails")
        .kind,
        SemanticCompilerFormFaultKind::InvalidReference
    );
}
