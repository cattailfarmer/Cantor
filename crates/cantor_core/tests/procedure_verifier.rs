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
        bound_set_id: sid("bounds:verifier-fixture"),
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
        let id = sid(&format!("verifier-schema:{index}"));
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
        schema_set_id: sid("verifier-schema-set:fixture"),
        schema_set_digest: empty_digest(),
        schemas,
        migration_ref: None,
    };
    value.schema_set_digest = compute_schema_set_digest(&value).expect("schema digest");
    value
}

fn process() -> ProcessDefinition {
    let entry_id = sid("verifier-region:entry");
    let return_id = sid("verifier-region:return");
    let entry = ControlRegion {
        region_id: entry_id.clone(),
        instructions: vec![ProcessInstruction {
            instruction_id: sid("verifier-instruction:inspect"),
            operation: ProcessOperation::Inspect,
            operands: vec![InstructionOperand {
                name: "subject".to_owned(),
                value: ProcedureValue::IdentityReference {
                    value: sid("input:subject"),
                },
            }],
            result_binding: Some("observed".to_owned()),
            successor_region_refs: vec![return_id.clone()],
            bound_ref: sid("bounds:verifier-fixture"),
            source_span_ref: sid("source-span:verifier-inspect"),
        }],
        terminal: false,
    };
    let terminal = ControlRegion {
        region_id: return_id.clone(),
        instructions: vec![ProcessInstruction {
            instruction_id: sid("verifier-instruction:return"),
            operation: ProcessOperation::Return,
            operands: Vec::new(),
            result_binding: None,
            successor_region_refs: Vec::new(),
            bound_ref: sid("bounds:verifier-fixture"),
            source_span_ref: sid("source-span:verifier-return"),
        }],
        terminal: true,
    };
    ProcessDefinition {
        process_definition_id: sid("verifier-process:observer"),
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
        resource_contribution_ref: sid("bounds:verifier-fixture"),
    }
}

fn candidate() -> ProcedureCandidate {
    let process = process();
    let mut value = ProcedureCandidate {
        candidate_id: sid("verifier-candidate:fixture"),
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
        receipt_id: sid("verifier-validation-receipt:fixture"),
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

type CompiledFixture = (
    ProcedureCandidate,
    ValidationReceipt,
    CompilationReceipt,
    CantorProcessIr,
    CompiledProcedureIdentity,
);

fn compiled_fixture(candidate: ProcedureCandidate) -> CompiledFixture {
    let validation = validation_receipt(&candidate);
    let outcome = compile_procedure_candidate(&candidate, &validation).expect("compile");
    (
        candidate,
        validation,
        outcome.compilation_receipt,
        outcome.process_ir.expect("IR"),
        outcome.compiled_procedure.expect("procedure"),
    )
}

fn policy(
    candidate: &ProcedureCandidate,
    ir: &CantorProcessIr,
    procedure: &CompiledProcedureIdentity,
) -> FakeObserverAdmissionPolicy {
    build_fake_observer_policy(
        sid("policy:fake-observer-fixture"),
        candidate,
        ir,
        procedure,
        AdmissionDecision::Admit,
        BTreeSet::from(["effectless-fixture".to_owned()]),
        BTreeSet::from(["anchor, policy, or procedure identity changes".to_owned()]),
    )
    .expect("policy")
}

#[test]
fn independent_verification_is_deterministic_and_content_bound() {
    let (candidate, validation, compilation, ir, procedure) = compiled_fixture(candidate());
    let first = verify_compiled_procedure(
        &candidate,
        &validation,
        &compilation,
        &ir,
        &procedure,
        &BTreeMap::new(),
    )
    .expect("first verification");
    let second = verify_compiled_procedure(
        &candidate,
        &validation,
        &compilation,
        &ir,
        &procedure,
        &BTreeMap::new(),
    )
    .expect("second verification");
    assert_eq!(first, second);
    assert_eq!(first.disposition, PhaseDisposition::Passed);
    assert_eq!(
        compute_verification_receipt_digest(&first).expect("receipt digest"),
        first.receipt_digest
    );
    assert_eq!(first.ir_digest, ir.ir_digest);
    assert_eq!(first.compiled_procedure_digest, procedure.procedure_digest);
    assert!(
        first
            .evidence
            .diagnostics
            .contains("normalized IR replay passed")
    );
}

#[test]
fn fake_observer_admits_one_exact_verified_procedure_without_cataloguing() {
    let (candidate, validation, compilation, ir, procedure) = compiled_fixture(candidate());
    let verification = verify_compiled_procedure(
        &candidate,
        &validation,
        &compilation,
        &ir,
        &procedure,
        &BTreeMap::new(),
    )
    .expect("verification");
    let policy = policy(&candidate, &ir, &procedure);
    let admission = fake_observer_admit(
        &candidate,
        &validation,
        &compilation,
        &ir,
        &procedure,
        &verification,
        &policy,
    )
    .expect("admission");
    assert_eq!(admission.decision, AdmissionDecision::Admit);
    assert_eq!(
        compute_admission_disposition_digest(&admission).expect("admission digest"),
        admission.disposition_digest
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
    forms
        .compilation_receipts
        .insert(compilation.receipt_id.clone(), compilation);
    forms
        .verification_receipts
        .insert(verification.receipt_id.clone(), verification);
    forms
        .admission_dispositions
        .insert(admission.disposition_id.clone(), admission);
    validate_procedure_forms(&forms).expect("exact admitted aggregate");
    assert!(forms.catalogues_by_generation_digest.is_empty());
    assert!(forms.invocation_requests.is_empty());
}

#[test]
fn schema_derived_type_table_is_checked_beyond_compiler_disposition() {
    let (candidate, validation, mut compilation, mut ir, mut procedure) =
        compiled_fixture(candidate());
    ir.type_table.insert(
        "forged.extra".to_owned(),
        ProcedureType::BoundedText { maximum_bytes: 8 },
    );
    ir.ir_digest = compute_process_ir_digest(&ir).expect("tampered IR digest");
    procedure.ir_digest = ir.ir_digest.clone();
    let procedure_seed = sha256_bytes(
        serde_json::to_string(&(
            &candidate.candidate_id,
            &candidate.source_digest,
            &procedure.compiler_ref,
            &ir.ir_id,
            &ir.ir_digest,
        ))
        .expect("procedure seed")
        .as_bytes(),
    );
    procedure.procedure_id = sid(&format!(
        "cppe:procedure:{}:{}",
        procedure_seed.algorithm, procedure_seed.value
    ));
    procedure.procedure_digest =
        compute_compiled_procedure_digest(&procedure).expect("procedure digest");
    compilation.ir_digest = Some(ir.ir_digest.clone());
    compilation.cost_estimate.insert("type_count".to_owned(), 2);
    compilation.receipt_digest =
        compute_compilation_receipt_digest(&compilation).expect("compilation digest");

    let verification = verify_compiled_procedure(
        &candidate,
        &validation,
        &compilation,
        &ir,
        &procedure,
        &BTreeMap::new(),
    )
    .expect("refusal receipt");
    assert_eq!(verification.disposition, PhaseDisposition::Refused);
    assert!(
        verification
            .evidence
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("schema closure"))
    );
}

#[test]
fn unreachable_process_region_is_compilable_but_not_verifiable() {
    let mut candidate = candidate();
    let process = candidate
        .process_definitions
        .values_mut()
        .next()
        .expect("process");
    let unreachable_id = sid("verifier-region:unreachable");
    process.control_regions.insert(
        unreachable_id.clone(),
        ControlRegion {
            region_id: unreachable_id.clone(),
            instructions: vec![ProcessInstruction {
                instruction_id: sid("verifier-instruction:unreachable-return"),
                operation: ProcessOperation::Return,
                operands: Vec::new(),
                result_binding: None,
                successor_region_refs: Vec::new(),
                bound_ref: candidate.bounds.bound_set_id.clone(),
                source_span_ref: sid("source-span:unreachable-return"),
            }],
            terminal: true,
        },
    );
    process.terminal_region_refs.insert(unreachable_id);
    let (candidate, validation, compilation, ir, procedure) = compiled_fixture(candidate);
    let verification = verify_compiled_procedure(
        &candidate,
        &validation,
        &compilation,
        &ir,
        &procedure,
        &BTreeMap::new(),
    )
    .expect("refusal receipt");
    assert_eq!(verification.disposition, PhaseDisposition::Refused);
    assert!(
        verification
            .evidence
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("unreachable"))
    );
}

#[test]
fn anchors_require_exact_recognition() {
    let mut candidate = candidate();
    let anchor_id = sid("anchor:recognized-fixture");
    let anchor = SopAnchorBinding {
        anchor_id: anchor_id.clone(),
        artifact_id: sid("artifact:signed-fixture"),
        artifact_version: "1".to_owned(),
        artifact_digest: sha256_bytes(b"signed fixture"),
        clause_id: Some(sid("clause:fixture")),
        intended_use: "verification fixture".to_owned(),
        sensitivity: SensitivityClass::ProjectInternal,
    };
    candidate
        .sop_anchors
        .insert(anchor_id.clone(), anchor.clone());
    let (candidate, validation, compilation, ir, procedure) = compiled_fixture(candidate);
    let refused = verify_compiled_procedure(
        &candidate,
        &validation,
        &compilation,
        &ir,
        &procedure,
        &BTreeMap::new(),
    )
    .expect("refusal");
    assert_eq!(refused.disposition, PhaseDisposition::Refused);

    let passed = verify_compiled_procedure(
        &candidate,
        &validation,
        &compilation,
        &ir,
        &procedure,
        &BTreeMap::from([(anchor_id, anchor)]),
    )
    .expect("recognized verification");
    assert_eq!(passed.disposition, PhaseDisposition::Passed);
}

#[test]
fn stale_verification_or_policy_change_is_refused_without_authority() {
    let (candidate, validation, compilation, ir, procedure) = compiled_fixture(candidate());
    let verification = verify_compiled_procedure(
        &candidate,
        &validation,
        &compilation,
        &ir,
        &procedure,
        &BTreeMap::new(),
    )
    .expect("verification");
    let policy = policy(&candidate, &ir, &procedure);

    let mut forged_verification = verification.clone();
    forged_verification.receipt_digest.value = "00".repeat(32);
    let refused = fake_observer_admit(
        &candidate,
        &validation,
        &compilation,
        &ir,
        &procedure,
        &forged_verification,
        &policy,
    )
    .expect("forged refusal");
    assert_eq!(refused.decision, AdmissionDecision::Refuse);
    assert!(refused.permitted_invocation_contexts.is_empty());

    let mut changed_policy = policy;
    changed_policy
        .permitted_invocation_contexts
        .insert("undeclared-context".to_owned());
    let refused = fake_observer_admit(
        &candidate,
        &validation,
        &compilation,
        &ir,
        &procedure,
        &verification,
        &changed_policy,
    )
    .expect("policy refusal");
    assert_eq!(refused.decision, AdmissionDecision::Refuse);
    assert!(refused.permitted_invocation_contexts.is_empty());
}

#[test]
fn explicit_refusal_policy_grants_no_invocation_context() {
    let (candidate, validation, compilation, ir, procedure) = compiled_fixture(candidate());
    let verification = verify_compiled_procedure(
        &candidate,
        &validation,
        &compilation,
        &ir,
        &procedure,
        &BTreeMap::new(),
    )
    .expect("verification");
    let refusal_policy = build_fake_observer_policy(
        sid("policy:explicit-refusal"),
        &candidate,
        &ir,
        &procedure,
        AdmissionDecision::Refuse,
        BTreeSet::new(),
        BTreeSet::new(),
    )
    .expect("refusal policy");
    let refused = fake_observer_admit(
        &candidate,
        &validation,
        &compilation,
        &ir,
        &procedure,
        &verification,
        &refusal_policy,
    )
    .expect("explicit refusal");
    assert_eq!(refused.decision, AdmissionDecision::Refuse);
    assert!(refused.permitted_invocation_contexts.is_empty());
    assert!(refused.revocation_conditions.is_empty());
}
