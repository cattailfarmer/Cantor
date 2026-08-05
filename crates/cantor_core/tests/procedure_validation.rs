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

fn bounds() -> ProcedureBounds {
    ProcedureBounds {
        bound_set_id: sid("bounds:fixture"),
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

fn prohibited_operations() -> BTreeSet<ProhibitedProcedureOperation> {
    use ProhibitedProcedureOperation::*;
    BTreeSet::from([
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
    ])
}

fn effects() -> ProcedureEffectDeclaration {
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
        prohibited_operations: prohibited_operations(),
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
        let id = sid(&format!("schema:{index}"));
        schemas.insert(
            id.clone(),
            ProcedureSchema {
                schema_id: id,
                schema_version: "0.1".to_owned(),
                kind,
                fields: BTreeMap::new(),
                tagged_variants: BTreeMap::new(),
                closed: true,
            },
        );
    }
    let mut value = ProcedureSchemaSet {
        schema_set_id: sid("schema-set:fixture"),
        schema_set_digest: empty_digest(),
        schemas,
        migration_ref: None,
    };
    value.schema_set_digest = compute_schema_set_digest(&value).expect("schema digest");
    value
}

fn process() -> ProcessDefinition {
    let terminal_id = sid("region:terminal");
    let region = ControlRegion {
        region_id: terminal_id.clone(),
        instructions: vec![ProcessInstruction {
            instruction_id: sid("instruction:return"),
            operation: ProcessOperation::Return,
            operands: Vec::new(),
            result_binding: None,
            successor_region_refs: Vec::new(),
            bound_ref: sid("bounds:fixture"),
            source_span_ref: sid("source:span:return"),
        }],
        terminal: true,
    };
    ProcessDefinition {
        process_definition_id: sid("process:observer"),
        name: "Observer".to_owned(),
        role_ref: sid("role:observer"),
        initial_state: ProcedureValue::Record {
            fields: BTreeMap::new(),
        },
        accepted_message_tags: BTreeSet::new(),
        emitted_message_tags: BTreeSet::new(),
        entry_region_ref: terminal_id.clone(),
        control_regions: BTreeMap::from([(terminal_id.clone(), region)]),
        terminal_region_refs: BTreeSet::from([terminal_id]),
        resource_contribution_ref: sid("bounds:fixture"),
    }
}

fn candidate() -> ProcedureCandidate {
    let source = ProcedureValue::Record {
        fields: BTreeMap::from([(
            "purpose".to_owned(),
            ProcedureValue::Text {
                value: "return supplied value".to_owned(),
            },
        )]),
    };
    let process = process();
    let mut value = ProcedureCandidate {
        candidate_id: sid("candidate:fixture"),
        author_ref: sid("author:fixture"),
        provenance_refs: BTreeSet::from([sid("source:fixture")]),
        purpose: "return one supplied value without effects".to_owned(),
        scope: BTreeSet::from(["fixture".to_owned()]),
        language_profile: CPPE_FORM_VERSION.to_owned(),
        source_text: None,
        normalized_source_form: Some(source),
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

fn process_ir(candidate: &ProcedureCandidate) -> CantorProcessIr {
    let mut value = CantorProcessIr {
        ir_id: sid("ir:fixture"),
        ir_version: CPPE_IR_VERSION.to_owned(),
        ir_digest: empty_digest(),
        source_digest: candidate.source_digest.clone(),
        compiler_ref: sid("compiler:fixture"),
        type_table: BTreeMap::new(),
        schema_set: candidate.schema_set.clone(),
        constants: BTreeMap::new(),
        sop_anchors: candidate.sop_anchors.clone(),
        process_definitions: candidate.process_definitions.clone(),
        effects: candidate.effects.clone(),
        bounds: candidate.bounds.clone(),
        source_map: BTreeMap::new(),
    };
    value.ir_digest = compute_process_ir_digest(&value).expect("IR digest");
    value
}

fn valid_forms() -> ProcedureFormSet {
    let candidate = candidate();
    let ir = process_ir(&candidate);
    let mut forms = ProcedureFormSet::new();
    forms
        .candidates
        .insert(candidate.candidate_id.clone(), candidate);
    forms.process_irs.insert(ir.ir_id.clone(), ir);
    forms
}

#[test]
fn exact_forms_and_process_ir_normalize_and_restore() {
    let forms = valid_forms();
    validate_procedure_forms(&forms).expect("valid CPPE forms");
    let normalized = to_normalized_procedure_form(&forms).expect("normalize forms");
    assert_eq!(
        from_normalized_procedure_form(&normalized).expect("restore normalized forms"),
        forms
    );

    let ir = forms.process_irs.values().next().expect("IR");
    let normalized_ir = to_normalized_process_ir(ir).expect("normalize IR");
    assert_eq!(
        from_normalized_process_ir(&normalized_ir).expect("restore normalized IR"),
        *ir
    );
}

#[test]
fn valid_json_with_noncanonical_spacing_is_refused() {
    let normalized = to_normalized_procedure_form(&valid_forms()).expect("normalize forms");
    let noncanonical = format!(" {normalized}");
    let error = from_normalized_procedure_form(&noncanonical).expect_err("spacing must fail");
    assert!(error.message.contains("not normalized"));
}

#[test]
fn source_schema_and_ir_digest_tampering_fail_closed() {
    let mut forms = valid_forms();
    forms
        .candidates
        .get_mut(&sid("candidate:fixture"))
        .expect("candidate")
        .source_digest
        .value = "00".repeat(32);
    assert!(validate_procedure_forms(&forms).is_err());

    let mut forms = valid_forms();
    forms
        .candidates
        .get_mut(&sid("candidate:fixture"))
        .expect("candidate")
        .schema_set
        .schema_set_digest
        .value = "11".repeat(32);
    assert!(validate_procedure_forms(&forms).is_err());

    let mut forms = valid_forms();
    forms
        .process_irs
        .get_mut(&sid("ir:fixture"))
        .expect("IR")
        .ir_digest
        .value = "22".repeat(32);
    assert!(validate_procedure_forms(&forms).is_err());
}

#[test]
fn candidate_version_source_and_lifecycle_are_exact() {
    let mut forms = valid_forms();
    let candidate = forms
        .candidates
        .get_mut(&sid("candidate:fixture"))
        .expect("candidate");
    candidate.language_profile = "cantor-process-procedure-experiment/9.9".to_owned();
    assert!(validate_procedure_forms(&forms).is_err());

    let mut forms = valid_forms();
    let candidate = forms
        .candidates
        .get_mut(&sid("candidate:fixture"))
        .expect("candidate");
    candidate.source_text = Some("duplicate source".to_owned());
    assert!(validate_procedure_forms(&forms).is_err());

    let mut forms = valid_forms();
    let candidate = forms
        .candidates
        .get_mut(&sid("candidate:fixture"))
        .expect("candidate");
    candidate.lifecycle = ProcedureLifecycle::Admitted;
    assert!(validate_procedure_forms(&forms).is_err());
}

#[test]
fn incomplete_effect_wall_and_zero_bounds_are_refused() {
    let mut forms = valid_forms();
    forms
        .candidates
        .get_mut(&sid("candidate:fixture"))
        .expect("candidate")
        .effects
        .prohibited_operations
        .remove(&ProhibitedProcedureOperation::Model);
    assert!(validate_procedure_forms(&forms).is_err());

    let mut forms = valid_forms();
    forms
        .candidates
        .get_mut(&sid("candidate:fixture"))
        .expect("candidate")
        .bounds
        .maximum_transitions = 0;
    assert!(validate_procedure_forms(&forms).is_err());
}

#[test]
fn missing_regions_and_wrong_instruction_bound_are_refused() {
    let mut forms = valid_forms();
    let candidate = forms
        .candidates
        .get_mut(&sid("candidate:fixture"))
        .expect("candidate");
    let process = candidate
        .process_definitions
        .get_mut(&sid("process:observer"))
        .expect("process");
    process.entry_region_ref = sid("region:missing");
    assert!(validate_procedure_forms(&forms).is_err());

    let mut forms = valid_forms();
    let candidate = forms
        .candidates
        .get_mut(&sid("candidate:fixture"))
        .expect("candidate");
    let process = candidate
        .process_definitions
        .get_mut(&sid("process:observer"))
        .expect("process");
    process
        .control_regions
        .get_mut(&sid("region:terminal"))
        .expect("region")
        .instructions[0]
        .bound_ref = sid("bounds:substituted");
    assert!(validate_procedure_forms(&forms).is_err());
}

#[test]
fn compiled_identity_binds_exact_candidate_ir_and_digest() {
    let mut forms = valid_forms();
    let candidate = forms.candidates.values().next().expect("candidate");
    let ir = forms.process_irs.values().next().expect("IR");
    let mut identity = CompiledProcedureIdentity {
        procedure_id: sid("procedure:fixture"),
        procedure_version: "0.1".to_owned(),
        predecessor_procedure_refs: BTreeSet::new(),
        candidate_ref: candidate.candidate_id.clone(),
        canonical_source_digest: candidate.source_digest.clone(),
        compiler_ref: ir.compiler_ref.clone(),
        language_profile: CPPE_FORM_VERSION.to_owned(),
        ir_ref: ir.ir_id.clone(),
        ir_digest: ir.ir_digest.clone(),
        schema_set_digest: ir.schema_set.schema_set_digest.clone(),
        effect_class: ProcedureEffectClass::Effectless,
        bound_set_ref: ir.bounds.bound_set_id.clone(),
        procedure_digest: empty_digest(),
    };
    identity.procedure_digest =
        compute_compiled_procedure_digest(&identity).expect("procedure digest");
    forms
        .compiled_procedures
        .insert(identity.procedure_id.clone(), identity);
    validate_procedure_forms(&forms).expect("exact compiled binding");

    let identity = forms
        .compiled_procedures
        .get_mut(&sid("procedure:fixture"))
        .expect("compiled identity");
    identity.compiler_ref = sid("compiler:substituted");
    identity.procedure_digest =
        compute_compiled_procedure_digest(identity).expect("updated digest");
    assert!(validate_procedure_forms(&forms).is_err());
}

#[test]
fn aggregate_keys_are_record_identities() {
    let mut forms = valid_forms();
    let candidate = forms
        .candidates
        .remove(&sid("candidate:fixture"))
        .expect("candidate");
    forms.candidates.insert(sid("candidate:alias"), candidate);
    assert!(validate_procedure_forms(&forms).is_err());
}

#[test]
fn nested_collection_and_schema_kind_bounds_are_enforced() {
    let mut forms = valid_forms();
    let candidate = forms
        .candidates
        .get_mut(&sid("candidate:fixture"))
        .expect("candidate");
    candidate.normalized_source_form = Some(ProcedureValue::List {
        members: (0..65)
            .map(|value| ProcedureValue::Integer { value })
            .collect(),
    });
    candidate.source_digest =
        compute_candidate_source_digest(candidate).expect("updated source digest");
    assert!(validate_procedure_forms(&forms).is_err());

    let mut forms = valid_forms();
    let candidate = forms
        .candidates
        .get_mut(&sid("candidate:fixture"))
        .expect("candidate");
    candidate.schema_set.schemas.remove(&sid("schema:7"));
    candidate.schema_set.schema_set_digest =
        compute_schema_set_digest(&candidate.schema_set).expect("updated schema digest");
    assert!(validate_procedure_forms(&forms).is_err());
}

#[test]
fn exhausted_remaining_budget_is_a_valid_terminal_state() {
    let mut forms = valid_forms();
    let state = ProcessInstanceState {
        state_id: sid("state:terminal"),
        invocation_ref: sid("invocation:fixture"),
        process_instance_id: sid("process-instance:fixture"),
        generation: 1,
        definition_ref: sid("process:observer"),
        region_ref: sid("region:terminal"),
        instruction_index: 1,
        local_state: ProcedureValue::Null,
        inbox_frontier: BTreeSet::new(),
        outbox_frontier: BTreeSet::new(),
        awaited_condition: AwaitedCondition::None,
        lifecycle: ProcessLifecycle::TerminalReturn,
        logical_time: 1,
        remaining_budgets: ProcessBudgetState {
            transitions_remaining: 0,
            messages_remaining: 0,
            memory_units_remaining: 0,
            trace_events_remaining: 0,
        },
    };
    forms
        .process_instances
        .insert(state.state_id.clone(), state);
    validate_procedure_forms(&forms).expect("terminal state may exhaust remaining budget");
}

#[test]
fn standalone_projections_must_match_a_valid_source_record() {
    let mut forms = valid_forms();
    let mut projected = forms
        .candidates
        .values()
        .next()
        .expect("candidate")
        .process_definitions
        .values()
        .next()
        .expect("process")
        .clone();
    projected.name = "SubstitutedObserver".to_owned();
    forms
        .process_definitions
        .insert(projected.process_definition_id.clone(), projected);
    assert!(validate_procedure_forms(&forms).is_err());
}

#[test]
fn decimal_ranges_and_scale_are_semantically_checked() {
    let mut forms = valid_forms();
    let candidate = forms
        .candidates
        .get_mut(&sid("candidate:fixture"))
        .expect("candidate");
    let input = candidate
        .schema_set
        .schemas
        .get_mut(&sid("schema:0"))
        .expect("input schema");
    input.fields.insert(
        "amount".to_owned(),
        SchemaField {
            field_name: "amount".to_owned(),
            value_type: ProcedureType::BoundedDecimal {
                minimum: "2.00".to_owned(),
                maximum: "1.00".to_owned(),
                scale: 2,
            },
            required: true,
            sensitivity: SensitivityClass::ProjectInternal,
        },
    );
    candidate.schema_set.schema_set_digest =
        compute_schema_set_digest(&candidate.schema_set).expect("updated schema digest");
    assert!(validate_procedure_forms(&forms).is_err());

    let mut forms = valid_forms();
    let candidate = forms
        .candidates
        .get_mut(&sid("candidate:fixture"))
        .expect("candidate");
    let input = candidate
        .schema_set
        .schemas
        .get_mut(&sid("schema:0"))
        .expect("input schema");
    input.fields.insert(
        "amount".to_owned(),
        SchemaField {
            field_name: "amount".to_owned(),
            value_type: ProcedureType::BoundedDecimal {
                minimum: "0.001".to_owned(),
                maximum: "1.00".to_owned(),
                scale: 2,
            },
            required: true,
            sensitivity: SensitivityClass::ProjectInternal,
        },
    );
    candidate.schema_set.schema_set_digest =
        compute_schema_set_digest(&candidate.schema_set).expect("updated schema digest");
    assert!(validate_procedure_forms(&forms).is_err());
}

fn negotiation_forms() -> ProcedureFormSet {
    let mut forms = valid_forms();
    let first = Participant {
        participant_id: sid("participant:first"),
        role_ref: sid("role:honesty"),
        permitted_message_kinds: BTreeSet::from([
            ProcedureMessageKind::Propose,
            ProcedureMessageKind::Pass,
        ]),
    };
    let second = Participant {
        participant_id: sid("participant:second"),
        role_ref: sid("role:security"),
        permitted_message_kinds: BTreeSet::from([
            ProcedureMessageKind::Object,
            ProcedureMessageKind::Pass,
        ]),
    };
    forms
        .participants
        .insert(first.participant_id.clone(), first.clone());
    forms
        .participants
        .insert(second.participant_id.clone(), second.clone());
    let participant_refs =
        BTreeSet::from([first.participant_id.clone(), second.participant_id.clone()]);
    let frame = NegotiatedFrame {
        frame_id: sid("frame:one"),
        generation: 1,
        propositions: BTreeMap::new(),
        conditions: BTreeSet::new(),
        constraints: BTreeSet::from(["effectless".to_owned()]),
        evidence_refs: BTreeSet::new(),
        objection_refs: BTreeSet::new(),
        participant_refs: participant_refs.clone(),
        policy_ref: sid("policy:ring"),
    };
    forms
        .negotiated_frames
        .insert(frame.frame_id.clone(), frame.clone());
    let session = NegotiationSession {
        session_generation_id: sid("session-generation:one"),
        session_id: sid("session:one"),
        frame_generation: 1,
        purpose: "test exact message coordination".to_owned(),
        required_participant_refs: participant_refs,
        optional_observer_refs: BTreeSet::new(),
        participants: BTreeMap::from([
            (first.participant_id.clone(), first.clone()),
            (second.participant_id.clone(), second.clone()),
        ]),
        pinned_sop_anchor_refs: BTreeSet::new(),
        policy_ref: sid("policy:ring"),
        frame,
        token_holder_ref: first.participant_id.clone(),
        pass_refs: BTreeSet::new(),
        message_frontier: BTreeSet::new(),
        status: NegotiationStatus::Deliberating,
    };
    forms
        .negotiation_sessions
        .insert(session.session_generation_id.clone(), session);
    let message = ProcedureMessage {
        message_id: sid("message:one"),
        session_ref: sid("session:one"),
        sender_ref: first.participant_id,
        receiver_ref: second.participant_id,
        frame_generation: 1,
        sop_anchor_refs: BTreeSet::new(),
        kind: ProcedureMessageKind::Propose,
        payload: ProcedureValue::Null,
        evidence_refs: BTreeSet::new(),
        logical_time: 1,
        causal_predecessor_refs: BTreeSet::new(),
        expires_at_logical_time: 2,
    };
    forms.messages.insert(message.message_id.clone(), message);
    forms
}

#[test]
fn negotiation_requires_exact_frame_participants_and_sender_permission() {
    let forms = negotiation_forms();
    validate_procedure_forms(&forms).expect("exact negotiation forms");

    let mut forms = negotiation_forms();
    forms
        .messages
        .get_mut(&sid("message:one"))
        .expect("message")
        .frame_generation = 2;
    assert!(validate_procedure_forms(&forms).is_err());

    let mut forms = negotiation_forms();
    forms
        .messages
        .get_mut(&sid("message:one"))
        .expect("message")
        .kind = ProcedureMessageKind::Object;
    assert!(validate_procedure_forms(&forms).is_err());
}
