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
        bound_set_id: sid("bounds:coordination-fixture"),
        maximum_source_bytes: 16_384,
        maximum_text_bytes: 1_024,
        maximum_value_bytes: 16_384,
        maximum_collection_items: 128,
        maximum_map_entries: 128,
        maximum_processes: 2,
        maximum_messages: 16,
        maximum_queue_depth: 8,
        maximum_events: 128,
        maximum_event_queue_depth: 32,
        maximum_call_depth: 8,
        maximum_transitions: 64,
        maximum_trace_events: 128,
        maximum_memory_units: 16_384,
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
        let id = sid(&format!("coordination-schema:{index}"));
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
    let mut set = ProcedureSchemaSet {
        schema_set_id: sid("coordination-schema-set:fixture"),
        schema_set_digest: empty_digest(),
        schemas,
        migration_ref: None,
    };
    set.schema_set_digest = compute_schema_set_digest(&set).expect("schema digest");
    set
}

fn operand(name: &str, value: ProcedureValue) -> InstructionOperand {
    InstructionOperand {
        name: name.to_owned(),
        value,
    }
}

fn instruction(
    id: &str,
    operation: ProcessOperation,
    operands: Vec<InstructionOperand>,
    result_binding: Option<&str>,
    successor: Option<&str>,
) -> ProcessInstruction {
    ProcessInstruction {
        instruction_id: sid(id),
        operation,
        operands,
        result_binding: result_binding.map(str::to_owned),
        successor_region_refs: successor.into_iter().map(sid).collect(),
        bound_ref: sid("bounds:coordination-fixture"),
        source_span_ref: sid(&format!("span:{id}")),
    }
}

fn region(
    id: &str,
    instruction: ProcessInstruction,
    terminal: bool,
) -> (SemanticId, ControlRegion) {
    let region_id = sid(id);
    (
        region_id.clone(),
        ControlRegion {
            region_id,
            instructions: vec![instruction],
            terminal,
        },
    )
}

fn process_a() -> ProcessDefinition {
    let process_a = sid("coord-process:a");
    let process_b = sid("coord-process:b");
    let regions = BTreeMap::from([
        region(
            "coord-a:emit",
            instruction(
                "coord-a:emit-request",
                ProcessOperation::Emit,
                vec![
                    operand(
                        "receiver",
                        ProcedureValue::IdentityReference {
                            value: process_b.clone(),
                        },
                    ),
                    operand(
                        "tag",
                        ProcedureValue::Text {
                            value: "request".to_owned(),
                        },
                    ),
                    operand(
                        "kind",
                        ProcedureValue::Text {
                            value: "propose".to_owned(),
                        },
                    ),
                    operand(
                        "payload",
                        ProcedureValue::IdentityReference {
                            value: sid("input:root"),
                        },
                    ),
                ],
                None,
                Some("coord-a:yield"),
            ),
            false,
        ),
        region(
            "coord-a:yield",
            instruction(
                "coord-a:yield-turn",
                ProcessOperation::Yield,
                Vec::new(),
                None,
                Some("coord-a:receive"),
            ),
            false,
        ),
        region(
            "coord-a:receive",
            instruction(
                "coord-a:receive-response",
                ProcessOperation::Receive,
                vec![operand(
                    "tag",
                    ProcedureValue::Text {
                        value: "response".to_owned(),
                    },
                )],
                Some("response"),
                Some("coord-a:join"),
            ),
            false,
        ),
        region(
            "coord-a:join",
            instruction(
                "coord-a:join-b",
                ProcessOperation::Join,
                vec![operand(
                    "targets",
                    ProcedureValue::List {
                        members: vec![ProcedureValue::IdentityReference { value: process_b }],
                    },
                )],
                None,
                Some("coord-a:return"),
            ),
            false,
        ),
        region(
            "coord-a:return",
            instruction(
                "coord-a:return-value",
                ProcessOperation::Return,
                vec![operand(
                    "value",
                    ProcedureValue::IdentityReference {
                        value: sid("input:root"),
                    },
                )],
                None,
                None,
            ),
            true,
        ),
    ]);
    ProcessDefinition {
        process_definition_id: process_a,
        name: "Observer".to_owned(),
        role_ref: sid("role:observer"),
        initial_state: ProcedureValue::Record {
            fields: BTreeMap::new(),
        },
        accepted_message_tags: BTreeSet::from(["response".to_owned()]),
        emitted_message_tags: BTreeSet::from(["request".to_owned()]),
        entry_region_ref: sid("coord-a:emit"),
        control_regions: regions,
        terminal_region_refs: BTreeSet::from([sid("coord-a:return")]),
        resource_contribution_ref: sid("bounds:coordination-fixture"),
    }
}

fn process_b() -> ProcessDefinition {
    let process_a = sid("coord-process:a");
    let process_b = sid("coord-process:b");
    let regions = BTreeMap::from([
        region(
            "coord-b:receive",
            instruction(
                "coord-b:receive-request",
                ProcessOperation::Receive,
                vec![operand(
                    "tag",
                    ProcedureValue::Text {
                        value: "request".to_owned(),
                    },
                )],
                Some("request"),
                Some("coord-b:reactivate"),
            ),
            false,
        ),
        region(
            "coord-b:reactivate",
            instruction(
                "coord-b:reactivate-a",
                ProcessOperation::Reactivate,
                vec![operand(
                    "target",
                    ProcedureValue::IdentityReference { value: process_a },
                )],
                None,
                Some("coord-b:wait"),
            ),
            false,
        ),
        region(
            "coord-b:wait",
            instruction(
                "coord-b:wait-logical",
                ProcessOperation::WaitLogical,
                vec![operand("not_before", ProcedureValue::Integer { value: 18 })],
                None,
                Some("coord-b:emit"),
            ),
            false,
        ),
        region(
            "coord-b:emit",
            instruction(
                "coord-b:emit-response",
                ProcessOperation::Emit,
                vec![
                    operand(
                        "receiver",
                        ProcedureValue::IdentityReference {
                            value: sid("coord-process:a"),
                        },
                    ),
                    operand(
                        "tag",
                        ProcedureValue::Text {
                            value: "response".to_owned(),
                        },
                    ),
                    operand(
                        "kind",
                        ProcedureValue::Text {
                            value: "support".to_owned(),
                        },
                    ),
                    operand(
                        "payload",
                        ProcedureValue::IdentityReference {
                            value: sid("local:request"),
                        },
                    ),
                ],
                None,
                Some("coord-b:return"),
            ),
            false,
        ),
        region(
            "coord-b:return",
            instruction(
                "coord-b:return-value",
                ProcessOperation::Return,
                vec![operand(
                    "value",
                    ProcedureValue::IdentityReference {
                        value: sid("input:root"),
                    },
                )],
                None,
                None,
            ),
            true,
        ),
    ]);
    ProcessDefinition {
        process_definition_id: process_b,
        name: "Refiner".to_owned(),
        role_ref: sid("role:refiner"),
        initial_state: ProcedureValue::Record {
            fields: BTreeMap::new(),
        },
        accepted_message_tags: BTreeSet::from(["request".to_owned()]),
        emitted_message_tags: BTreeSet::from(["response".to_owned()]),
        entry_region_ref: sid("coord-b:receive"),
        control_regions: regions,
        terminal_region_refs: BTreeSet::from([sid("coord-b:return")]),
        resource_contribution_ref: sid("bounds:coordination-fixture"),
    }
}

fn candidate() -> ProcedureCandidate {
    let processes = [process_a(), process_b()]
        .into_iter()
        .map(|process| (process.process_definition_id.clone(), process))
        .collect::<BTreeMap<_, _>>();
    let mut candidate = ProcedureCandidate {
        candidate_id: sid("coord-candidate:fixture"),
        author_ref: sid("author:fixture"),
        provenance_refs: BTreeSet::from([sid("source:fixture")]),
        purpose: "effectless two-process coordination fixture".to_owned(),
        scope: BTreeSet::from(["fixture".to_owned()]),
        language_profile: CPPE_FORM_VERSION.to_owned(),
        source_text: None,
        normalized_source_form: Some(ProcedureValue::List {
            members: processes
                .keys()
                .cloned()
                .map(|value| ProcedureValue::IdentityReference { value })
                .collect(),
        }),
        source_digest: empty_digest(),
        sop_anchors: BTreeMap::new(),
        schema_set: schema_set(),
        process_definitions: processes,
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
        receipt_id: sid("coord-validation:fixture"),
        candidate_ref: candidate.candidate_id.clone(),
        candidate_source_digest: candidate.source_digest.clone(),
        validator_ref: sid("validator:fixture"),
        profile: CPPE_FORM_VERSION.to_owned(),
        disposition: PhaseDisposition::Passed,
        evidence: ReceiptEvidence {
            evidence_refs: BTreeSet::from([sid("evidence:validation")]),
            residuals: BTreeSet::new(),
            diagnostics: BTreeSet::from(["machine form valid".to_owned()]),
        },
        receipt_digest: empty_digest(),
    };
    receipt.receipt_digest =
        compute_validation_receipt_digest(&receipt).expect("validation digest");
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

fn pipeline() -> Pipeline {
    let candidate = candidate();
    let validation = validation_receipt(&candidate);
    let compiled = compile_procedure_candidate(&candidate, &validation).expect("compile");
    let ir = compiled.process_ir.expect("IR");
    let procedure = compiled.compiled_procedure.expect("procedure");
    let verification = verify_compiled_procedure(
        &candidate,
        &validation,
        &compiled.compilation_receipt,
        &ir,
        &procedure,
        &BTreeMap::new(),
    )
    .expect("verify");
    assert_eq!(verification.disposition, PhaseDisposition::Passed);
    let policy = build_fake_observer_policy(
        sid("policy:coordination-fixture"),
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
        &compiled.compilation_receipt,
        &ir,
        &procedure,
        &verification,
        &policy,
    )
    .expect("admission");
    let transition = insert_admitted_procedure(
        &empty_procedure_catalogue().expect("empty catalogue"),
        &procedure,
        &admission,
        BTreeSet::from(["coordination-fixture".to_owned()]),
    )
    .expect("catalogue insertion");
    Pipeline {
        candidate,
        validation,
        compilation: compiled.compilation_receipt,
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
    let output_schema_ref = pipeline
        .ir
        .schema_set
        .schemas
        .values()
        .find(|schema| schema.kind == SchemaKind::Output)
        .expect("output schema")
        .schema_id
        .clone();
    InvocationRequest {
        invocation_id: sid("coord-invocation:fixture"),
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
        participant_refs: pipeline.ir.process_definitions.keys().cloned().collect(),
        initial_logical_time: 10,
        budgets: InvocationBudget {
            logical_time_limit: 64,
            step_limit: 64,
            memory_unit_limit: 16_384,
            message_limit: 16,
            trace_event_limit: 128,
        },
        expected_output_schema_ref: output_schema_ref,
        catalogue_generation_digest: pipeline.catalogue.generation_digest.clone(),
        retention_policy_ref: sid("policy:retention"),
    }
}

fn session(pipeline: &Pipeline) -> NegotiationSession {
    let required = pipeline
        .ir
        .process_definitions
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let participants = pipeline
        .ir
        .process_definitions
        .values()
        .map(|definition| {
            (
                definition.process_definition_id.clone(),
                Participant {
                    participant_id: definition.process_definition_id.clone(),
                    role_ref: definition.role_ref.clone(),
                    permitted_message_kinds: BTreeSet::from([
                        ProcedureMessageKind::Propose,
                        ProcedureMessageKind::Support,
                        ProcedureMessageKind::Pass,
                    ]),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let frame = NegotiatedFrame {
        frame_id: sid("coord-frame:g1"),
        generation: 1,
        propositions: BTreeMap::new(),
        conditions: BTreeSet::from(["effectless".to_owned()]),
        constraints: BTreeSet::from(["two-process".to_owned()]),
        evidence_refs: BTreeSet::from([pipeline.admission.disposition_id.clone()]),
        objection_refs: BTreeSet::new(),
        participant_refs: required.clone(),
        policy_ref: pipeline.admission.policy_ref.clone(),
    };
    NegotiationSession {
        session_generation_id: sid("coord-session:g1"),
        session_id: sid("coord-session:fixture"),
        frame_generation: 1,
        purpose: "two-process fixture".to_owned(),
        required_participant_refs: required.clone(),
        optional_observer_refs: BTreeSet::new(),
        participants,
        pinned_sop_anchor_refs: BTreeSet::new(),
        policy_ref: pipeline.admission.policy_ref.clone(),
        frame,
        token_holder_ref: required.iter().next().expect("participant").clone(),
        pass_refs: BTreeSet::new(),
        message_frontier: BTreeSet::new(),
        status: NegotiationStatus::Opened,
    }
}

fn run_chunked(
    pipeline: &Pipeline,
    request: &InvocationRequest,
    session: &NegotiationSession,
    quotas: &[u64],
) -> CoordinationOutcome {
    let mut checkpoint = begin_coordination_checkpoint(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        request,
        session,
    )
    .expect("begin checkpoint");
    for index in 0..256 {
        let transition = advance_coordination_checkpoint(
            &pipeline.catalogue,
            &pipeline.procedure,
            &pipeline.ir,
            &pipeline.admission,
            request,
            session,
            &checkpoint,
            quotas[index % quotas.len()],
        )
        .expect("advance checkpoint");
        if let Some(outcome) = transition.outcome {
            assert!(transition.checkpoint.is_none());
            return outcome;
        }
        assert_eq!(transition.disposition, CoordinationSliceDisposition::Paused);
        checkpoint = transition.checkpoint.expect("paused checkpoint");
    }
    panic!("chunked coordination did not terminate")
}

fn resign_checkpoint(checkpoint: &mut CoordinationCheckpoint) {
    checkpoint.checkpoint_digest = empty_digest();
    checkpoint.checkpoint_digest =
        compute_coordination_checkpoint_digest(checkpoint).expect("checkpoint digest");
}

#[test]
fn checkpoint_genesis_is_strict_valid_and_byte_deterministic() {
    let pipeline = pipeline();
    let request = request(&pipeline);
    let session = session(&pipeline);
    let first = begin_coordination_checkpoint(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
        &session,
    )
    .expect("first checkpoint");
    let replay = begin_coordination_checkpoint(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
        &session,
    )
    .expect("checkpoint replay");
    assert_eq!(first, replay);
    assert_eq!(first.slice_index, 0);
    assert!(first.steps.is_empty());
    assert_eq!(first.process_states.len(), 2);
    assert_eq!(first.trace_events.len(), 1);
    validate_coordination_checkpoint(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
        &session,
        &first,
    )
    .expect("valid checkpoint");

    let mut value = serde_json::to_value(first).expect("checkpoint JSON");
    value["ambient_stack_pointer"] = serde_json::json!(1234);
    assert!(serde_json::from_value::<CoordinationCheckpoint>(value).is_err());
}

#[test]
fn quota_one_pauses_exactly_then_resumes_to_uninterrupted_outcome() {
    let pipeline = pipeline();
    let request = request(&pipeline);
    let session = session(&pipeline);
    let checkpoint = begin_coordination_checkpoint(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
        &session,
    )
    .expect("begin checkpoint");
    let first = advance_coordination_checkpoint(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
        &session,
        &checkpoint,
        1,
    )
    .expect("one step");
    assert_eq!(first.disposition, CoordinationSliceDisposition::Paused);
    assert_eq!(first.steps_advanced, 1);
    assert!(first.outcome.is_none());
    assert_eq!(
        first
            .checkpoint
            .as_ref()
            .expect("successor checkpoint")
            .predecessor_checkpoint_digest,
        Some(checkpoint.checkpoint_digest.clone())
    );
    assert_eq!(
        first
            .checkpoint
            .as_ref()
            .expect("successor checkpoint")
            .steps
            .len(),
        1
    );

    let uninterrupted = coordinate_catalogued_procedure(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
        &session,
    )
    .expect("uninterrupted coordination");
    assert_eq!(
        run_chunked(&pipeline, &request, &session, &[1]),
        uninterrupted
    );
}

#[test]
fn quota_partitions_do_not_change_terminal_semantics() {
    let pipeline = pipeline();
    let request = request(&pipeline);
    let session = session(&pipeline);
    let uninterrupted = coordinate_catalogued_procedure(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
        &session,
    )
    .expect("uninterrupted coordination");
    for quotas in [&[1][..], &[2][..], &[4][..], &[1, 2, 4][..], &[64][..]] {
        assert_eq!(
            run_chunked(&pipeline, &request, &session, quotas),
            uninterrupted,
            "quota partition {quotas:?} changed the terminal outcome"
        );
    }
}

#[test]
fn corrupt_or_cross_input_checkpoints_refuse_before_advancement() {
    let pipeline = pipeline();
    let request = request(&pipeline);
    let session = session(&pipeline);
    let mut checkpoint = begin_coordination_checkpoint(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
        &session,
    )
    .expect("begin checkpoint");

    assert!(
        advance_coordination_checkpoint(
            &pipeline.catalogue,
            &pipeline.procedure,
            &pipeline.ir,
            &pipeline.admission,
            &request,
            &session,
            &checkpoint,
            0,
        )
        .is_err()
    );

    checkpoint.checkpoint_digest.value = "00".repeat(32);
    assert!(
        advance_coordination_checkpoint(
            &pipeline.catalogue,
            &pipeline.procedure,
            &pipeline.ir,
            &pipeline.admission,
            &request,
            &session,
            &checkpoint,
            1,
        )
        .is_err()
    );

    let checkpoint = begin_coordination_checkpoint(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
        &session,
    )
    .expect("fresh checkpoint");
    let mut changed_request = request.clone();
    changed_request.caller_ref = sid("caller:substituted");
    assert!(
        advance_coordination_checkpoint(
            &pipeline.catalogue,
            &pipeline.procedure,
            &pipeline.ir,
            &pipeline.admission,
            &changed_request,
            &session,
            &checkpoint,
            1,
        )
        .is_err()
    );
    let mut changed_session = session.clone();
    changed_session
        .frame
        .conditions
        .insert("substituted".to_owned());
    assert!(
        advance_coordination_checkpoint(
            &pipeline.catalogue,
            &pipeline.procedure,
            &pipeline.ir,
            &pipeline.admission,
            &request,
            &changed_session,
            &checkpoint,
            1,
        )
        .is_err()
    );

    let mut invalid_state = checkpoint.clone();
    invalid_state
        .process_states
        .values_mut()
        .next()
        .expect("process state")
        .instruction_index = u64::MAX;
    resign_checkpoint(&mut invalid_state);
    assert!(
        validate_coordination_checkpoint(
            &pipeline.catalogue,
            &pipeline.procedure,
            &pipeline.ir,
            &pipeline.admission,
            &request,
            &session,
            &invalid_state,
        )
        .is_err()
    );
}

#[test]
fn nested_continuation_message_and_trace_tampering_cannot_be_rehashed_valid() {
    let pipeline = pipeline();
    let request = request(&pipeline);
    let session = session(&pipeline);
    let mut checkpoint = begin_coordination_checkpoint(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
        &session,
    )
    .expect("begin checkpoint");
    for _ in 0..32 {
        let transition = advance_coordination_checkpoint(
            &pipeline.catalogue,
            &pipeline.procedure,
            &pipeline.ir,
            &pipeline.admission,
            &request,
            &session,
            &checkpoint,
            1,
        )
        .expect("advance to rich checkpoint");
        checkpoint = transition.checkpoint.expect("fixture has not terminated");
        if !checkpoint.continuations.is_empty() && !checkpoint.messages.is_empty() {
            break;
        }
    }
    assert!(!checkpoint.continuations.is_empty());
    assert!(!checkpoint.messages.is_empty());

    let mut invalid_continuation = checkpoint.clone();
    invalid_continuation
        .continuations
        .values_mut()
        .next()
        .expect("continuation")
        .continuation_digest = empty_digest();
    resign_checkpoint(&mut invalid_continuation);
    let mut invalid_message = checkpoint.clone();
    invalid_message
        .messages
        .values_mut()
        .next()
        .expect("message")
        .sender_ref = sid("process:substituted");
    resign_checkpoint(&mut invalid_message);
    let mut invalid_trace = checkpoint.clone();
    invalid_trace
        .trace_events
        .last_mut()
        .expect("trace event")
        .causal_predecessor_refs
        .clear();
    resign_checkpoint(&mut invalid_trace);

    for invalid in [invalid_continuation, invalid_message, invalid_trace] {
        assert!(
            validate_coordination_checkpoint(
                &pipeline.catalogue,
                &pipeline.procedure,
                &pipeline.ir,
                &pipeline.admission,
                &request,
                &session,
                &invalid,
            )
            .is_err()
        );
    }
}

#[test]
fn global_budget_refusal_is_terminal_and_matches_compatibility_path() {
    let pipeline = pipeline();
    let mut request = request(&pipeline);
    request.budgets.step_limit = 4;
    let session = session(&pipeline);
    let checkpoint = begin_coordination_checkpoint(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
        &session,
    )
    .expect("begin checkpoint");
    let sliced = advance_coordination_checkpoint(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
        &session,
        &checkpoint,
        64,
    )
    .expect("terminal budget transition");
    assert_eq!(
        sliced.disposition,
        CoordinationSliceDisposition::BudgetRefused
    );
    assert!(sliced.checkpoint.is_none());
    let uninterrupted = coordinate_catalogued_procedure(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
        &session,
    )
    .expect("compatibility budget outcome");
    assert_eq!(sliced.outcome, Some(uninterrupted));
}

#[test]
fn two_process_coordination_is_deterministic_and_covers_the_scheduler_contract() {
    let pipeline = pipeline();
    let request = request(&pipeline);
    let session = session(&pipeline);
    let first = coordinate_catalogued_procedure(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
        &session,
    )
    .expect("coordination");
    let second = coordinate_catalogued_procedure(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
        &session,
    )
    .expect("repeated coordination");
    assert_eq!(first, second);
    assert_eq!(first.result.disposition, InvocationDisposition::Returned);
    assert_eq!(first.result.output, Some(request.input.clone()));
    assert_eq!(first.steps.len(), 15);
    assert_eq!(first.messages.len(), 2);
    assert_eq!(first.delivered_message_refs.len(), 2);
    assert_eq!(first.continuations.len(), 4);
    assert!(first.active_continuation_refs.is_empty());
    for continuation in first.continuations.values() {
        assert_eq!(
            compute_continuation_digest(continuation).expect("continuation digest"),
            continuation.continuation_digest
        );
    }
    assert_eq!(first.terminal_returns.len(), 2);
    assert_eq!(first.result.consumed_budget.logical_time, 13);
    assert_eq!(first.result.consumed_budget.steps, 15);
    assert_eq!(first.result.semantic_trace.events.len(), 28);
    assert_eq!(
        compute_semantic_trace_digest(&first.result.semantic_trace).expect("trace digest"),
        first.result.semantic_trace.trace_digest
    );
    let kinds = first
        .result
        .semantic_trace
        .events
        .iter()
        .map(|event| event.kind)
        .collect::<BTreeSet<_>>();
    for required in [
        TraceEventKind::MessageEmitted,
        TraceEventKind::MessageReceived,
        TraceEventKind::Yielded,
        TraceEventKind::Waiting,
        TraceEventKind::Reactivated,
        TraceEventKind::Joined,
    ] {
        assert!(kinds.contains(&required));
    }
    let successor = first.session_successor.expect("session successor");
    assert_eq!(
        successor.message_frontier,
        first.messages.keys().cloned().collect()
    );
    assert_eq!(successor.status, NegotiationStatus::Deliberating);
}

#[test]
fn messages_preserve_direction_tags_and_causal_predecessors() {
    let pipeline = pipeline();
    let request = request(&pipeline);
    let outcome = coordinate_catalogued_procedure(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
        &session(&pipeline),
    )
    .expect("coordination");
    let request_message = outcome
        .messages
        .values()
        .find(|message| message.sender_ref == sid("coord-process:a"))
        .expect("request message");
    let response_message = outcome
        .messages
        .values()
        .find(|message| message.sender_ref == sid("coord-process:b"))
        .expect("response message");
    assert_eq!(request_message.receiver_ref, sid("coord-process:b"));
    assert!(request_message.causal_predecessor_refs.is_empty());
    assert_eq!(response_message.receiver_ref, sid("coord-process:a"));
    assert!(
        response_message
            .causal_predecessor_refs
            .contains(&request_message.message_id)
    );
    assert!(
        outcome
            .delivered_message_refs
            .contains(&request_message.message_id)
    );
    assert!(
        outcome
            .delivered_message_refs
            .contains(&response_message.message_id)
    );
}

#[test]
fn stale_session_fails_before_any_process_step() {
    let pipeline = pipeline();
    let request = request(&pipeline);
    let mut session = session(&pipeline);
    session.frame_generation = 2;
    let outcome = coordinate_catalogued_procedure(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
        &session,
    )
    .expect("typed stale refusal");
    assert_eq!(outcome.result.disposition, InvocationDisposition::Faulted);
    assert_eq!(
        outcome.result.fault.as_ref().expect("fault").category,
        ProcedureFaultCategory::StaleGeneration
    );
    assert!(outcome.steps.is_empty());
    assert!(outcome.messages.is_empty());
    assert!(outcome.session_successor.is_none());
}

#[test]
fn finite_step_budget_refuses_without_external_effect() {
    let pipeline = pipeline();
    let mut request = request(&pipeline);
    request.budgets.step_limit = 4;
    let outcome = coordinate_catalogued_procedure(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
        &session(&pipeline),
    )
    .expect("typed budget refusal");
    assert_eq!(
        outcome.result.disposition,
        InvocationDisposition::BudgetRefused
    );
    assert_eq!(
        outcome.result.fault.as_ref().expect("fault").category,
        ProcedureFaultCategory::ResourceExhausted
    );
    assert_eq!(outcome.steps.len(), 4);
}

#[test]
fn exact_two_participant_pass_cycle_is_stable_not_true_or_admitted() {
    let pipeline = pipeline();
    let session = session(&pipeline);
    let first_participant = session.token_holder_ref.clone();
    let first = record_token_ring_pass(&session, &BTreeMap::new(), &first_participant, 1)
        .expect("first pass");
    assert_eq!(first.successor.status, NegotiationStatus::Deliberating);
    assert_ne!(first.successor.token_holder_ref, first_participant);
    let second_participant = first.successor.token_holder_ref.clone();
    let known = BTreeMap::from([(first.pass.pass_id.clone(), first.pass.clone())]);
    let second = record_token_ring_pass(&first.successor, &known, &second_participant, 2)
        .expect("second pass");
    assert_eq!(second.successor.status, NegotiationStatus::StableCandidate);
    assert_eq!(second.successor.pass_refs.len(), 2);
    assert_eq!(second.pass.predecessor_pass_ref, Some(first.pass.pass_id));
    assert_eq!(second.successor.frame_generation, 1);
}

#[test]
fn frame_change_clears_passes_and_rejects_stale_or_out_of_turn_pass() {
    let pipeline = pipeline();
    let session = session(&pipeline);
    let holder = session.token_holder_ref.clone();
    let first = record_token_ring_pass(&session, &BTreeMap::new(), &holder, 1).expect("first pass");
    let mut no_change = first.successor.frame.clone();
    no_change.frame_id = sid("coord-frame:no-op-g2");
    no_change.generation = 2;
    assert!(revise_negotiated_frame(&first.successor, no_change).is_err());
    let next_holder = first.successor.token_holder_ref.clone();
    let mut forged_pass = first.pass.clone();
    forged_pass.participant_set_digest.value = "00".repeat(32);
    assert!(
        record_token_ring_pass(
            &first.successor,
            &BTreeMap::from([(forged_pass.pass_id.clone(), forged_pass)]),
            &next_holder,
            2,
        )
        .is_err()
    );
    let mut frame = first.successor.frame.clone();
    frame.frame_id = sid("coord-frame:g2");
    frame.generation = 2;
    frame.conditions.insert("revised".to_owned());
    let revision = revise_negotiated_frame(&first.successor, frame).expect("frame revision");
    assert_eq!(
        revision.cleared_pass_refs,
        BTreeSet::from([first.pass.pass_id.clone()])
    );
    assert!(revision.successor.pass_refs.is_empty());
    assert_eq!(revision.successor.status, NegotiationStatus::Deliberating);
    let wrong_participant = first.successor.token_holder_ref;
    assert!(
        record_token_ring_pass(
            &revision.successor,
            &BTreeMap::from([(first.pass.pass_id.clone(), first.pass)]),
            &wrong_participant,
            2,
        )
        .is_err()
    );
}

#[test]
fn replay_receipt_binds_byte_equivalent_outcomes() {
    let pipeline = pipeline();
    let request = request(&pipeline);
    let receipt = verify_coordination_replay(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
        &session(&pipeline),
    )
    .expect("replay");
    assert!(receipt.matched);
    assert_eq!(receipt.first_outcome_digest, receipt.replay_outcome_digest);
    assert_eq!(
        compute_coordination_replay_receipt_digest(&receipt).expect("receipt digest"),
        receipt.receipt_digest
    );
}

#[test]
fn coordination_products_fit_the_existing_aggregate_form_contract() {
    let pipeline = pipeline();
    let request = request(&pipeline);
    let session = session(&pipeline);
    let outcome = coordinate_catalogued_procedure(
        &pipeline.catalogue,
        &pipeline.procedure,
        &pipeline.ir,
        &pipeline.admission,
        &request,
        &session,
    )
    .expect("coordination");
    let successor_session = outcome
        .session_successor
        .clone()
        .expect("session successor");
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
    forms.invocation_results.insert(
        outcome.result.invocation_ref.clone(),
        outcome.result.clone(),
    );
    forms.semantic_traces.insert(
        outcome.result.semantic_trace.trace_id.clone(),
        outcome.result.semantic_trace,
    );
    forms.process_instances.extend(
        outcome
            .result
            .final_process_states
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    forms
        .process_instances
        .extend(outcome.continuations.values().map(|continuation| {
            (
                continuation.process_state.state_id.clone(),
                continuation.process_state.clone(),
            )
        }));
    forms.continuations.extend(outcome.continuations);
    forms.process_steps.extend(
        outcome
            .steps
            .iter()
            .map(|step| (step.step_id.clone(), step.clone())),
    );
    forms.messages.extend(outcome.messages);
    forms
        .participants
        .extend(successor_session.participants.clone());
    forms.negotiated_frames.insert(
        successor_session.frame.frame_id.clone(),
        successor_session.frame.clone(),
    );
    forms.negotiation_sessions.insert(
        successor_session.session_generation_id.clone(),
        successor_session,
    );
    validate_procedure_forms(&forms).expect("aggregate coordination forms");
    forms
        .continuations
        .values_mut()
        .next()
        .expect("continuation")
        .continuation_digest
        .value = "00".repeat(32);
    assert!(validate_procedure_forms(&forms).is_err());
}
