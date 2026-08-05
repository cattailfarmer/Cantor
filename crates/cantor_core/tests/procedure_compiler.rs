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
        bound_set_id: sid("bounds:compiler-fixture"),
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
        let id = sid(&format!("compiler-schema:{index}"));
        let fields = if kind == SchemaKind::Input {
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
        schema_set_id: sid("compiler-schema-set:fixture"),
        schema_set_digest: empty_digest(),
        schemas,
        migration_ref: None,
    };
    value.schema_set_digest = compute_schema_set_digest(&value).expect("schema digest");
    value
}

fn process() -> ProcessDefinition {
    let entry_id = sid("compiler-region:entry");
    let return_id = sid("compiler-region:return");
    let entry = ControlRegion {
        region_id: entry_id.clone(),
        instructions: vec![ProcessInstruction {
            instruction_id: sid("compiler-instruction:inspect"),
            operation: ProcessOperation::Inspect,
            operands: vec![InstructionOperand {
                name: "subject".to_owned(),
                value: ProcedureValue::IdentityReference {
                    value: sid("input:subject"),
                },
            }],
            result_binding: Some("observed".to_owned()),
            successor_region_refs: vec![return_id.clone()],
            bound_ref: sid("bounds:compiler-fixture"),
            source_span_ref: sid("source-span:inspect"),
        }],
        terminal: false,
    };
    let terminal = ControlRegion {
        region_id: return_id.clone(),
        instructions: vec![ProcessInstruction {
            instruction_id: sid("compiler-instruction:return"),
            operation: ProcessOperation::Return,
            operands: Vec::new(),
            result_binding: None,
            successor_region_refs: Vec::new(),
            bound_ref: sid("bounds:compiler-fixture"),
            source_span_ref: sid("source-span:return"),
        }],
        terminal: true,
    };
    ProcessDefinition {
        process_definition_id: sid("compiler-process:observer"),
        name: "Observer".to_owned(),
        role_ref: sid("role:observer"),
        initial_state: ProcedureValue::Record {
            fields: BTreeMap::new(),
        },
        accepted_message_tags: BTreeSet::new(),
        emitted_message_tags: BTreeSet::new(),
        entry_region_ref: entry_id.clone(),
        control_regions: BTreeMap::from([(entry_id, entry), (return_id.clone(), terminal)]),
        terminal_region_refs: BTreeSet::from([return_id]),
        resource_contribution_ref: sid("bounds:compiler-fixture"),
    }
}

fn candidate() -> ProcedureCandidate {
    let process = process();
    let mut value = ProcedureCandidate {
        candidate_id: sid("compiler-candidate:fixture"),
        author_ref: sid("author:fixture"),
        provenance_refs: BTreeSet::from([sid("source:fixture")]),
        purpose: "inspect and return one supplied subject".to_owned(),
        scope: BTreeSet::from(["fixture".to_owned()]),
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
    value.source_digest = compute_candidate_source_digest(&value).expect("source digest");
    value
}

fn validation_receipt(candidate: &ProcedureCandidate) -> ValidationReceipt {
    let mut receipt = ValidationReceipt {
        receipt_id: sid("validation-receipt:fixture"),
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

#[test]
fn normalized_candidate_compiles_deterministically() {
    let candidate = candidate();
    let validation = validation_receipt(&candidate);
    let first = compile_procedure_candidate(&candidate, &validation).expect("compile first");
    let second = compile_procedure_candidate(&candidate, &validation).expect("compile second");
    assert_eq!(first, second);
    assert_eq!(
        first.compilation_receipt.disposition,
        PhaseDisposition::Passed
    );
    assert_eq!(
        compute_compilation_receipt_digest(&first.compilation_receipt)
            .expect("compilation receipt digest"),
        first.compilation_receipt.receipt_digest
    );
    assert!(first.process_ir.is_some());
    assert!(first.compiled_procedure.is_some());
}

#[test]
fn output_is_a_valid_bound_candidate_ir_lineage() {
    let candidate = candidate();
    let validation = validation_receipt(&candidate);
    let outcome = compile_procedure_candidate(&candidate, &validation).expect("compile");
    let ir = outcome.process_ir.expect("IR");
    let procedure = outcome.compiled_procedure.expect("compiled procedure");
    assert_eq!(ir.source_map.len(), 2);
    assert_eq!(ir.type_table.len(), 1);
    assert_eq!(
        outcome.compilation_receipt.cost_estimate["instruction_count"],
        2
    );
    assert!(
        outcome
            .compilation_receipt
            .evidence
            .residuals
            .contains("verification not performed")
    );

    let mut forms = ProcedureFormSet::new();
    forms
        .candidates
        .insert(candidate.candidate_id.clone(), candidate);
    forms.process_irs.insert(ir.ir_id.clone(), ir);
    forms
        .compiled_procedures
        .insert(procedure.procedure_id.clone(), procedure);
    forms
        .validation_receipts
        .insert(validation.receipt_id.clone(), validation);
    forms.compilation_receipts.insert(
        outcome.compilation_receipt.receipt_id.clone(),
        outcome.compilation_receipt,
    );
    validate_procedure_forms(&forms).expect("compiled lineage validates");
    assert!(forms.verification_receipts.is_empty());
    assert!(forms.admission_dispositions.is_empty());
}

#[test]
fn textual_source_is_refused_without_parser_authority() {
    let mut candidate = candidate();
    candidate.normalized_source_form = None;
    candidate.source_text = Some("PROCESS Observer; RETURN;".to_owned());
    candidate.source_digest = compute_candidate_source_digest(&candidate).expect("text digest");
    let validation = validation_receipt(&candidate);
    let outcome = compile_procedure_candidate(&candidate, &validation).expect("refusal outcome");
    assert_eq!(
        outcome.compilation_receipt.disposition,
        PhaseDisposition::Refused
    );
    assert!(outcome.process_ir.is_none());
    assert!(outcome.compiled_procedure.is_none());
    assert!(
        outcome
            .compilation_receipt
            .evidence
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("no parser"))
    );
}

#[test]
fn forged_stale_or_refused_validation_receipt_cannot_compile() {
    let candidate = candidate();
    let mut forged = validation_receipt(&candidate);
    forged.receipt_digest.value = "00".repeat(32);
    let outcome = compile_procedure_candidate(&candidate, &forged).expect("forged refusal");
    assert_eq!(
        outcome.compilation_receipt.disposition,
        PhaseDisposition::Refused
    );

    let mut stale = validation_receipt(&candidate);
    stale.candidate_ref = sid("compiler-candidate:other");
    stale.receipt_digest = compute_validation_receipt_digest(&stale).expect("stale digest");
    let outcome = compile_procedure_candidate(&candidate, &stale).expect("stale refusal");
    assert_eq!(
        outcome.compilation_receipt.disposition,
        PhaseDisposition::Refused
    );

    let mut refused = validation_receipt(&candidate);
    refused.disposition = PhaseDisposition::Refused;
    refused.receipt_digest = compute_validation_receipt_digest(&refused).expect("refused digest");
    let outcome = compile_procedure_candidate(&candidate, &refused).expect("prior refusal");
    assert_eq!(
        outcome.compilation_receipt.disposition,
        PhaseDisposition::Refused
    );

    let original_validation = validation_receipt(&candidate);
    let mut substituted = candidate.clone();
    substituted.normalized_source_form = Some(ProcedureValue::Text {
        value: "different but structurally valid source".to_owned(),
    });
    substituted.source_digest =
        compute_candidate_source_digest(&substituted).expect("substituted source digest");
    let outcome = compile_procedure_candidate(&substituted, &original_validation)
        .expect("content substitution refusal");
    assert_eq!(
        outcome.compilation_receipt.disposition,
        PhaseDisposition::Refused
    );
}

#[test]
fn invalid_candidate_yields_receipt_without_partial_successor() {
    let mut candidate = candidate();
    candidate
        .effects
        .prohibited_operations
        .remove(&ProhibitedProcedureOperation::Model);
    let validation = validation_receipt(&candidate);
    let outcome = compile_procedure_candidate(&candidate, &validation).expect("invalid refusal");
    assert_eq!(
        outcome.compilation_receipt.disposition,
        PhaseDisposition::Refused
    );
    assert!(outcome.compilation_receipt.ir_ref.is_none());
    assert!(outcome.process_ir.is_none());
    assert!(outcome.compiled_procedure.is_none());
}

#[test]
fn map_insertion_order_does_not_change_compiler_output() {
    let first = candidate();
    let mut second = first.clone();
    let schemas = second.schema_set.schemas.clone();
    second.schema_set.schemas.clear();
    for (key, value) in schemas.into_iter().rev() {
        second.schema_set.schemas.insert(key, value);
    }
    second.schema_set.schema_set_digest =
        compute_schema_set_digest(&second.schema_set).expect("schema digest");
    second.source_digest = compute_candidate_source_digest(&second).expect("source digest");
    let first_validation = validation_receipt(&first);
    let second_validation = validation_receipt(&second);
    assert_eq!(
        compile_procedure_candidate(&first, &first_validation).expect("first compile"),
        compile_procedure_candidate(&second, &second_validation).expect("second compile")
    );
}
