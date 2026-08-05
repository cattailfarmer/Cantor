use std::collections::{BTreeMap, BTreeSet};

use cantor_core::*;

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
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

fn bounds() -> ProcedureBounds {
    ProcedureBounds {
        bound_set_id: sid("bounds:runtime-fixture"),
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
    let mut schemas = BTreeMap::new();
    for (index, kind) in kinds.into_iter().enumerate() {
        let id = sid(&format!("runtime-schema:{index}"));
        let fields = if matches!(kind, SchemaKind::Input | SchemaKind::Output) {
            BTreeMap::from([(
                "subject".to_owned(),
                SchemaField {
                    field_name: "subject".to_owned(),
                    value_type: ProcedureType::BoundedText { maximum_bytes: 64 },
                    required: true,
                    sensitivity: SensitivityClass::ProjectInternal,
                },
            )])
        } else {
            BTreeMap::new()
        };
        schemas.insert(
            id.clone(),
            ProcedureSchema {
                schema_id: id,
                schema_version: "0.1".to_owned(),
                kind,
                fields,
                tagged_variants: BTreeMap::new(),
                closed: true,
            },
        );
    }
    let mut value = ProcedureSchemaSet {
        schema_set_id: sid("runtime-schema-set:fixture"),
        schema_set_digest: empty_digest(),
        schemas,
        migration_ref: None,
    };
    value.schema_set_digest = compute_schema_set_digest(&value).expect("schema digest");
    value
}

fn instruction(
    id: &str,
    operation: ProcessOperation,
    operands: Vec<InstructionOperand>,
    result_binding: Option<&str>,
    successors: Vec<SemanticId>,
) -> ProcessInstruction {
    ProcessInstruction {
        instruction_id: sid(id),
        operation,
        operands,
        result_binding: result_binding.map(str::to_owned),
        successor_region_refs: successors,
        bound_ref: sid("bounds:runtime-fixture"),
        source_span_ref: sid(&format!("source-span:{id}")),
    }
}

fn process() -> ProcessDefinition {
    let inspect_id = sid("runtime-region:inspect");
    let compare_id = sid("runtime-region:compare");
    let branch_id = sid("runtime-region:branch");
    let return_id = sid("runtime-region:return");
    let fault_id = sid("runtime-region:fault");
    let regions = BTreeMap::from([
        (
            inspect_id.clone(),
            ControlRegion {
                region_id: inspect_id.clone(),
                instructions: vec![instruction(
                    "runtime-instruction:inspect",
                    ProcessOperation::Inspect,
                    vec![InstructionOperand {
                        name: "subject".to_owned(),
                        value: ProcedureValue::IdentityReference {
                            value: sid("input:subject"),
                        },
                    }],
                    Some("observed"),
                    vec![compare_id.clone()],
                )],
                terminal: false,
            },
        ),
        (
            compare_id.clone(),
            ControlRegion {
                region_id: compare_id.clone(),
                instructions: vec![instruction(
                    "runtime-instruction:compare",
                    ProcessOperation::Compare,
                    vec![
                        InstructionOperand {
                            name: "left".to_owned(),
                            value: ProcedureValue::IdentityReference {
                                value: sid("local:observed"),
                            },
                        },
                        InstructionOperand {
                            name: "right".to_owned(),
                            value: ProcedureValue::Text {
                                value: "hello".to_owned(),
                            },
                        },
                    ],
                    Some("matches"),
                    vec![branch_id.clone()],
                )],
                terminal: false,
            },
        ),
        (
            branch_id.clone(),
            ControlRegion {
                region_id: branch_id.clone(),
                instructions: vec![instruction(
                    "runtime-instruction:branch",
                    ProcessOperation::Branch,
                    vec![InstructionOperand {
                        name: "condition".to_owned(),
                        value: ProcedureValue::IdentityReference {
                            value: sid("local:matches"),
                        },
                    }],
                    None,
                    vec![return_id.clone(), fault_id.clone()],
                )],
                terminal: false,
            },
        ),
        (
            return_id.clone(),
            ControlRegion {
                region_id: return_id.clone(),
                instructions: vec![instruction(
                    "runtime-instruction:return",
                    ProcessOperation::Return,
                    vec![InstructionOperand {
                        name: "value".to_owned(),
                        value: ProcedureValue::IdentityReference {
                            value: sid("input:root"),
                        },
                    }],
                    None,
                    Vec::new(),
                )],
                terminal: true,
            },
        ),
        (
            fault_id.clone(),
            ControlRegion {
                region_id: fault_id.clone(),
                instructions: vec![instruction(
                    "runtime-instruction:fault",
                    ProcessOperation::Fault,
                    Vec::new(),
                    None,
                    Vec::new(),
                )],
                terminal: true,
            },
        ),
    ]);
    ProcessDefinition {
        process_definition_id: sid("runtime-process:observer"),
        name: "Observer".to_owned(),
        role_ref: sid("role:observer"),
        initial_state: ProcedureValue::Record {
            fields: BTreeMap::new(),
        },
        accepted_message_tags: BTreeSet::new(),
        emitted_message_tags: BTreeSet::new(),
        entry_region_ref: inspect_id,
        control_regions: regions,
        terminal_region_refs: BTreeSet::from([return_id, fault_id]),
        resource_contribution_ref: sid("bounds:runtime-fixture"),
    }
}

fn candidate_with_process(process: ProcessDefinition) -> ProcedureCandidate {
    let mut candidate = ProcedureCandidate {
        candidate_id: sid("runtime-candidate:fixture"),
        author_ref: sid("author:fixture"),
        provenance_refs: BTreeSet::from([sid("source:fixture")]),
        purpose: "bounded local interpreter fixture".to_owned(),
        scope: BTreeSet::from(["fixture".to_owned()]),
        language_profile: CPPE_FORM_VERSION.to_owned(),
        source_text: None,
        normalized_source_form: Some(ProcedureValue::IdentityReference {
            value: process.process_definition_id.clone(),
        }),
        source_digest: empty_digest(),
        sop_anchors: BTreeMap::new(),
        schema_set: schema_set(),
        process_definitions: BTreeMap::from([(process.process_definition_id.clone(), process)]),
        effects: effects(),
        bounds: bounds(),
        created_logical_time: 0,
        sensitivity: SensitivityClass::ProjectInternal,
        retention_policy_ref: sid("policy:retention"),
        lifecycle: ProcedureLifecycle::Proposed,
    };
    candidate.source_digest = compute_candidate_source_digest(&candidate).expect("source digest");
    candidate
}

fn validation_receipt(candidate: &ProcedureCandidate) -> ValidationReceipt {
    let mut receipt = ValidationReceipt {
        receipt_id: sid("runtime-validation-receipt:fixture"),
        candidate_ref: candidate.candidate_id.clone(),
        candidate_source_digest: candidate.source_digest.clone(),
        validator_ref: sid("validator:fixture"),
        profile: CPPE_FORM_VERSION.to_owned(),
        disposition: PhaseDisposition::Passed,
        evidence: ReceiptEvidence {
            evidence_refs: BTreeSet::from([sid("validation-evidence:fixture")]),
            residuals: BTreeSet::new(),
            diagnostics: BTreeSet::from(["machine form valid".to_owned()]),
        },
        receipt_digest: empty_digest(),
    };
    receipt.receipt_digest =
        compute_validation_receipt_digest(&receipt).expect("validation receipt digest");
    receipt
}

struct Pipeline {
    candidate: ProcedureCandidate,
    validation: ValidationReceipt,
    compilation: CompilationReceipt,
    ir: CantorProcessIr,
    procedure: CompiledProcedureIdentity,
    verification: VerificationReceipt,
    admission: AdmissionDisposition,
    catalogue_receipt: CatalogueReceipt,
    catalogue: ProcedureCatalogueState,
}

fn pipeline(process: ProcessDefinition) -> Pipeline {
    let candidate = candidate_with_process(process);
    let validation = validation_receipt(&candidate);
    let compilation = compile_procedure_candidate(&candidate, &validation).expect("compile");
    let ir = compilation.process_ir.expect("IR");
    let procedure = compilation.compiled_procedure.expect("procedure");
    let verification = verify_compiled_procedure(
        &candidate,
        &validation,
        &compilation.compilation_receipt,
        &ir,
        &procedure,
        &BTreeMap::new(),
    )
    .expect("verify");
    assert_eq!(verification.disposition, PhaseDisposition::Passed);
    let policy = build_fake_observer_policy(
        sid("policy:runtime-fixture"),
        &candidate,
        &ir,
        &procedure,
        AdmissionDecision::Admit,
        BTreeSet::from(["effectless-fixture".to_owned()]),
        BTreeSet::from(["identity changes".to_owned()]),
    )
    .expect("policy");
    let admission = fake_observer_admit(
        &candidate,
        &validation,
        &compilation.compilation_receipt,
        &ir,
        &procedure,
        &verification,
        &policy,
    )
    .expect("admission");
    assert_eq!(admission.decision, AdmissionDecision::Admit);
    let transition = insert_admitted_procedure(
        &empty_procedure_catalogue().expect("empty catalogue"),
        &procedure,
        &admission,
        BTreeSet::from(["observer-fixture".to_owned()]),
    )
    .expect("catalogue insert");
    Pipeline {
        candidate,
        validation,
        compilation: compilation.compilation_receipt,
        ir,
        procedure,
        verification,
        admission,
        catalogue_receipt: transition.receipt,
        catalogue: transition.successor.expect("catalogue successor"),
    }
}

fn request(pipeline: &Pipeline) -> InvocationRequest {
    let input_schema_ref = pipeline
        .ir
        .schema_set
        .schemas
        .values()
        .find(|schema| schema.kind == SchemaKind::Input)
        .expect("input schema")
        .schema_id
        .clone();
    let expected_output_schema_ref = pipeline
        .ir
        .schema_set
        .schemas
        .values()
        .find(|schema| schema.kind == SchemaKind::Output)
        .expect("output schema")
        .schema_id
        .clone();
    InvocationRequest {
        invocation_id: sid("invocation:runtime-fixture"),
        caller_ref: sid("caller:fixture"),
        purpose: "effectless-fixture".to_owned(),
        admitted_procedure_ref: pipeline.procedure.procedure_id.clone(),
        procedure_digest: pipeline.procedure.procedure_digest.clone(),
        admission_disposition_ref: pipeline.admission.disposition_id.clone(),
        admission_disposition_digest: pipeline.admission.disposition_digest.clone(),
        input_schema_ref,
        schema_set_digest: pipeline.ir.schema_set.schema_set_digest.clone(),
        input: ProcedureValue::Record {
            fields: BTreeMap::from([(
                "subject".to_owned(),
                ProcedureValue::Text {
                    value: "hello".to_owned(),
                },
            )]),
        },
        input_sensitivity: SensitivityClass::ProjectInternal,
        sop_generation_ref: sid("sop-generation:fixture"),
        sop_anchor_set_digest: pipeline.admission.anchor_set_digest.clone(),
        policy_ref: pipeline.admission.policy_ref.clone(),
        policy_digest: pipeline.admission.policy_digest.clone(),
        participant_refs: BTreeSet::new(),
        initial_logical_time: 10,
        budgets: InvocationBudget {
            logical_time_limit: 16,
            step_limit: 16,
            memory_unit_limit: 4_096,
            message_limit: 16,
            trace_event_limit: 32,
        },
        expected_output_schema_ref,
        catalogue_generation_digest: pipeline.catalogue.generation_digest.clone(),
        retention_policy_ref: sid("policy:retention"),
    }
}

#[test]
fn catalogue_insert_lookup_and_alias_are_deterministic_and_immutable() {
    let pipeline = pipeline(process());
    let original = empty_procedure_catalogue().expect("empty catalogue");
    assert!(original.entries.is_empty());
    assert_eq!(pipeline.catalogue.generation, 1);
    assert_eq!(
        lookup_catalogued_procedure(&pipeline.catalogue, &pipeline.procedure.procedure_id)
            .expect("lookup")
            .expect("entry")
            .procedure_digest,
        pipeline.procedure.procedure_digest
    );
    assert_eq!(
        lookup_catalogue_alias(&pipeline.catalogue, "observer-fixture").expect("alias"),
        BTreeSet::from([pipeline.procedure.procedure_id.clone()])
    );
    assert_eq!(
        compute_catalogue_receipt_digest(&pipeline.catalogue_receipt).expect("receipt digest"),
        pipeline.catalogue_receipt.receipt_digest
    );
}

#[test]
fn duplicate_or_forged_admission_never_creates_a_successor_catalogue() {
    let pipeline = pipeline(process());
    let duplicate = insert_admitted_procedure(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.admission,
        BTreeSet::new(),
    )
    .expect("duplicate refusal");
    assert_eq!(duplicate.receipt.disposition, PhaseDisposition::Refused);
    assert!(duplicate.successor.is_none());

    let mut forged = pipeline.admission.clone();
    forged.disposition_digest.value = "00".repeat(32);
    let refused = insert_admitted_procedure(
        &empty_procedure_catalogue().expect("empty"),
        &pipeline.procedure,
        &forged,
        BTreeSet::new(),
    )
    .expect("forged refusal");
    assert_eq!(refused.receipt.disposition, PhaseDisposition::Refused);
    assert!(refused.successor.is_none());
}

#[test]
fn local_interpreter_returns_deterministically_with_exact_trace_and_lineage() {
    let pipeline = pipeline(process());
    let request = request(&pipeline);
    let first = invoke_catalogued_procedure(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
    )
    .expect("first invocation");
    let second = invoke_catalogued_procedure(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
    )
    .expect("second invocation");
    assert_eq!(first, second);
    assert_eq!(first.result.disposition, InvocationDisposition::Returned);
    assert_eq!(first.result.output, Some(request.input.clone()));
    assert_eq!(first.steps.len(), 4);
    assert_eq!(first.result.semantic_trace.events.len(), 6);
    assert_eq!(first.result.consumed_budget.steps, 4);
    assert_eq!(first.result.consumed_budget.logical_time, 4);
    assert_eq!(
        compute_semantic_trace_digest(&first.result.semantic_trace).expect("trace digest"),
        first.result.semantic_trace.trace_digest
    );
    assert!(first.messages.is_empty());
    assert!(first.continuations.is_empty());

    let mut forms = ProcedureFormSet::new();
    forms
        .candidates
        .insert(pipeline.candidate.candidate_id.clone(), pipeline.candidate);
    forms
        .process_irs
        .insert(pipeline.ir.ir_id.clone(), pipeline.ir);
    forms
        .compiled_procedures
        .insert(pipeline.procedure.procedure_id.clone(), pipeline.procedure);
    forms
        .validation_receipts
        .insert(pipeline.validation.receipt_id.clone(), pipeline.validation);
    forms.compilation_receipts.insert(
        pipeline.compilation.receipt_id.clone(),
        pipeline.compilation,
    );
    forms.verification_receipts.insert(
        pipeline.verification.receipt_id.clone(),
        pipeline.verification,
    );
    forms.admission_dispositions.insert(
        pipeline.admission.disposition_id.clone(),
        pipeline.admission,
    );
    forms.catalogue_receipts.insert(
        pipeline.catalogue_receipt.receipt_id.clone(),
        pipeline.catalogue_receipt,
    );
    forms.catalogues_by_generation_digest.insert(
        format!(
            "{}:{}",
            pipeline.catalogue.generation_digest.algorithm,
            pipeline.catalogue.generation_digest.value
        ),
        pipeline.catalogue,
    );
    forms
        .invocation_requests
        .insert(request.invocation_id.clone(), request);
    forms
        .invocation_results
        .insert(first.result.invocation_ref.clone(), first.result.clone());
    forms.semantic_traces.insert(
        first.result.semantic_trace.trace_id.clone(),
        first.result.semantic_trace,
    );
    validate_procedure_forms(&forms).expect("complete local invocation lineage");
}

#[test]
fn stale_catalogue_policy_or_admission_fails_before_execution() {
    let pipeline = pipeline(process());
    let mut request = request(&pipeline);
    request.policy_digest.value = "00".repeat(32);
    let outcome = invoke_catalogued_procedure(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
    )
    .expect("stale refusal");
    assert_eq!(outcome.result.disposition, InvocationDisposition::Faulted);
    assert_eq!(outcome.steps.len(), 0);
    assert_eq!(
        outcome.result.fault.expect("fault").category,
        ProcedureFaultCategory::StaleGeneration
    );
}

#[test]
fn finite_step_budget_returns_typed_refusal_with_partial_trace() {
    let pipeline = pipeline(process());
    let mut request = request(&pipeline);
    request.budgets.step_limit = 2;
    let outcome = invoke_catalogued_procedure(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
    )
    .expect("budget refusal");
    assert_eq!(
        outcome.result.disposition,
        InvocationDisposition::BudgetRefused
    );
    assert_eq!(outcome.steps.len(), 2);
    assert_eq!(outcome.result.semantic_trace.events.len(), 3);
    assert_eq!(outcome.result.consumed_budget.steps, 2);
    assert_eq!(
        outcome.result.fault.expect("fault").category,
        ProcedureFaultCategory::ResourceExhausted
    );
}

#[test]
fn revocation_retains_history_and_prevents_future_invocation() {
    let pipeline = pipeline(process());
    let request = request(&pipeline);
    let revoked = revoke_catalogued_procedure(
        &pipeline.catalogue,
        &pipeline.procedure.procedure_id,
        CatalogueStatus::Revoked,
        sid("principal:observer"),
        "fixture policy withdrawn".to_owned(),
        BTreeSet::from([pipeline.admission.disposition_id.clone()]),
        20,
    )
    .expect("revocation");
    assert_eq!(pipeline.catalogue.entries.len(), 1);
    assert_eq!(revoked.successor.entries.len(), 1);
    assert_eq!(revoked.successor.revocations.len(), 1);
    let mut stale_request = request;
    stale_request.catalogue_generation_digest = revoked.successor.generation_digest.clone();
    let outcome = invoke_catalogued_procedure(
        &revoked.successor,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &stale_request,
    )
    .expect("revoked refusal");
    assert_eq!(outcome.result.disposition, InvocationDisposition::Faulted);
    assert!(outcome.steps.is_empty());
}

#[test]
fn coordination_operation_is_typed_as_the_next_slice_not_silently_executed() {
    let mut process = process();
    let entry = process
        .control_regions
        .get_mut(&process.entry_region_ref)
        .expect("entry");
    entry.instructions[0].operation = ProcessOperation::Yield;
    entry.instructions[0].operands.clear();
    entry.instructions[0].result_binding = None;
    let pipeline = pipeline(process);
    let request = request(&pipeline);
    let outcome = invoke_catalogued_procedure(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
    )
    .expect("coordination refusal");
    assert_eq!(outcome.result.disposition, InvocationDisposition::Faulted);
    assert_eq!(outcome.steps.len(), 1);
    let fault = outcome.result.fault.expect("fault");
    assert_eq!(fault.category, ProcedureFaultCategory::UnsupportedVersion);
    assert!(
        fault
            .safe_residuals
            .iter()
            .any(|residual| residual.contains("CPPE-I06"))
    );
}

#[test]
fn malformed_local_operand_contract_returns_typed_fault_not_host_error() {
    let mut process = process();
    let compare = process
        .control_regions
        .get_mut(&sid("runtime-region:compare"))
        .expect("compare region");
    compare.instructions[0].operands.pop();
    let pipeline = pipeline(process);
    let request = request(&pipeline);
    let outcome = invoke_catalogued_procedure(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
    )
    .expect("typed runtime fault");
    assert_eq!(outcome.result.disposition, InvocationDisposition::Faulted);
    assert_eq!(outcome.steps.len(), 2);
    assert_eq!(
        outcome.result.fault.expect("fault").category,
        ProcedureFaultCategory::TypeMismatch
    );
}
