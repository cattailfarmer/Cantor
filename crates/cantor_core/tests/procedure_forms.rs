use std::collections::{BTreeMap, BTreeSet};

use cantor_core::*;
use serde::{Serialize, de::DeserializeOwned};

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn digest(value: &str) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: value.repeat(64 / value.len().max(1)),
    }
}

fn assert_machine_form<T: Serialize + DeserializeOwned>() {}

#[test]
fn every_i01_record_is_a_machine_form() {
    assert_machine_form::<ProcedureType>();
    assert_machine_form::<ProcedureValue>();
    assert_machine_form::<ProcedureReadClass>();
    assert_machine_form::<ProcedureWriteClass>();
    assert_machine_form::<ProhibitedProcedureOperation>();
    assert_machine_form::<ProcedurePhase>();
    assert_machine_form::<ProcedureBounds>();
    assert_machine_form::<SopAnchorBinding>();
    assert_machine_form::<SchemaField>();
    assert_machine_form::<TaggedVariant>();
    assert_machine_form::<ProcedureSchema>();
    assert_machine_form::<ProcedureSchemaSet>();
    assert_machine_form::<ProcedureEffectDeclaration>();
    assert_machine_form::<InstructionOperand>();
    assert_machine_form::<ProcessInstruction>();
    assert_machine_form::<ControlRegion>();
    assert_machine_form::<ProcessDefinition>();
    assert_machine_form::<ProcedureCandidate>();
    assert_machine_form::<CompiledProcedureIdentity>();
    assert_machine_form::<SourceMapEntry>();
    assert_machine_form::<CantorProcessIr>();
    assert_machine_form::<AwaitedCondition>();
    assert_machine_form::<ProcessBudgetState>();
    assert_machine_form::<ProcessInstanceState>();
    assert_machine_form::<SerializedContinuation>();
    assert_machine_form::<ProcessStep>();
    assert_machine_form::<Participant>();
    assert_machine_form::<ProcedureMessage>();
    assert_machine_form::<NegotiatedFrame>();
    assert_machine_form::<NegotiationSession>();
    assert_machine_form::<TokenRingPass>();
    assert_machine_form::<ReceiptEvidence>();
    assert_machine_form::<ValidationReceipt>();
    assert_machine_form::<CompilationReceipt>();
    assert_machine_form::<VerificationReceipt>();
    assert_machine_form::<AdmissionDisposition>();
    assert_machine_form::<CatalogueReceipt>();
    assert_machine_form::<RevocationRecord>();
    assert_machine_form::<ProcedurePhaseReceiptSet>();
    assert_machine_form::<ProcedureCatalogueEntry>();
    assert_machine_form::<ProcedureCatalogueState>();
    assert_machine_form::<InvocationBudget>();
    assert_machine_form::<InvocationRequest>();
    assert_machine_form::<SemanticTraceEvent>();
    assert_machine_form::<SemanticTrace>();
    assert_machine_form::<ConsumedBudget>();
    assert_machine_form::<ProcedureFault>();
    assert_machine_form::<InvocationResult>();
    assert_machine_form::<ProcedureFormSet>();
}

#[test]
fn closed_vocabularies_have_exact_machine_names() {
    let operations = [
        ProcessOperation::Bind,
        ProcessOperation::Inspect,
        ProcessOperation::Compare,
        ProcessOperation::Branch,
        ProcessOperation::Select,
        ProcessOperation::MapBounded,
        ProcessOperation::Emit,
        ProcessOperation::Receive,
        ProcessOperation::Yield,
        ProcessOperation::WaitLogical,
        ProcessOperation::Reactivate,
        ProcessOperation::Join,
        ProcessOperation::Return,
        ProcessOperation::Fault,
    ];
    assert_eq!(
        serde_json::to_string(&operations).expect("serialize operations"),
        r#"["bind","inspect","compare","branch","select","map_bounded","emit","receive","yield","wait_logical","reactivate","join","return","fault"]"#
    );

    let messages = [
        ProcedureMessageKind::Propose,
        ProcedureMessageKind::Question,
        ProcedureMessageKind::Support,
        ProcedureMessageKind::Object,
        ProcedureMessageKind::Counter,
        ProcedureMessageKind::Qualify,
        ProcedureMessageKind::Withdraw,
        ProcedureMessageKind::AdmitCandidate,
        ProcedureMessageKind::Refuse,
        ProcedureMessageKind::Yield,
        ProcedureMessageKind::Pass,
        ProcedureMessageKind::Fault,
    ];
    assert_eq!(
        serde_json::to_string(&messages).expect("serialize messages"),
        r#"["propose","question","support","object","counter","qualify","withdraw","admit_candidate","refuse","yield","pass","fault"]"#
    );
}

#[test]
fn aggregate_form_is_strict_and_round_trips() {
    let forms = ProcedureFormSet::new();
    let encoded = to_machine_form(&forms).expect("serialize CPPE form set");
    let restored: ProcedureFormSet = from_machine_form(&encoded).expect("restore CPPE form set");
    assert_eq!(restored, forms);
    assert_eq!(restored.form_version, CPPE_FORM_VERSION);

    let with_unknown = encoded.replacen(
        r#"{"form_version"#,
        r#"{"unknown_authority":true,"form_version"#,
        1,
    );
    assert!(from_machine_form::<ProcedureFormSet>(&with_unknown).is_err());
    assert!(serde_json::from_str::<ProcessOperation>(r#""execute_tool""#).is_err());
}

#[test]
fn candidate_and_ir_are_distinct_effectless_records() {
    let bounds = ProcedureBounds {
        bound_set_id: sid("bound:set"),
        maximum_source_bytes: 1024,
        maximum_text_bytes: 256,
        maximum_value_bytes: 512,
        maximum_collection_items: 16,
        maximum_map_entries: 16,
        maximum_processes: 2,
        maximum_messages: 16,
        maximum_queue_depth: 8,
        maximum_events: 32,
        maximum_event_queue_depth: 8,
        maximum_call_depth: 1,
        maximum_transitions: 32,
        maximum_trace_events: 64,
        maximum_memory_units: 256,
    };
    let effects = ProcedureEffectDeclaration {
        effect_class: ProcedureEffectClass::Effectless,
        allowed_read_classes: BTreeSet::from([
            ProcedureReadClass::TypedInvocationInput,
            ProcedureReadClass::PinnedAdmittedInMemoryArtifact,
        ]),
        allowed_write_classes: BTreeSet::from([
            ProcedureWriteClass::ReturnedValue,
            ProcedureWriteClass::SemanticTrace,
        ]),
        prohibited_operations: BTreeSet::from([
            ProhibitedProcedureOperation::Filesystem,
            ProhibitedProcedureOperation::Model,
            ProhibitedProcedureOperation::Network,
        ]),
    };
    let schema_set = ProcedureSchemaSet {
        schema_set_id: sid("schema:set"),
        schema_set_digest: digest("a"),
        schemas: BTreeMap::new(),
        migration_ref: None,
    };
    let region = ControlRegion {
        region_id: sid("region:return"),
        instructions: vec![ProcessInstruction {
            instruction_id: sid("instruction:return"),
            operation: ProcessOperation::Return,
            operands: Vec::new(),
            result_binding: None,
            successor_region_refs: Vec::new(),
            bound_ref: bounds.bound_set_id.clone(),
            source_span_ref: sid("source:span"),
        }],
        terminal: true,
    };
    let process = ProcessDefinition {
        process_definition_id: sid("process:observer"),
        name: "Observer".to_owned(),
        role_ref: sid("role:observer"),
        initial_state: ProcedureValue::Record {
            fields: BTreeMap::new(),
        },
        accepted_message_tags: BTreeSet::new(),
        emitted_message_tags: BTreeSet::new(),
        entry_region_ref: region.region_id.clone(),
        control_regions: BTreeMap::from([(region.region_id.clone(), region)]),
        terminal_region_refs: BTreeSet::from([sid("region:return")]),
        resource_contribution_ref: bounds.bound_set_id.clone(),
    };
    let candidate = ProcedureCandidate {
        candidate_id: sid("candidate:one"),
        author_ref: sid("author:human"),
        provenance_refs: BTreeSet::from([sid("source:dictation")]),
        purpose: "return one supplied value without effects".to_owned(),
        scope: BTreeSet::from(["fixture".to_owned()]),
        language_profile: CPPE_FORM_VERSION.to_owned(),
        source_text: None,
        normalized_source_form: Some(ProcedureValue::Record {
            fields: BTreeMap::new(),
        }),
        source_digest: digest("b"),
        sop_anchors: BTreeMap::new(),
        schema_set: schema_set.clone(),
        process_definitions: BTreeMap::from([(
            process.process_definition_id.clone(),
            process.clone(),
        )]),
        effects: effects.clone(),
        bounds: bounds.clone(),
        created_logical_time: 0,
        sensitivity: SensitivityClass::ProjectInternal,
        retention_policy_ref: sid("policy:retention"),
        lifecycle: ProcedureLifecycle::Proposed,
    };
    let ir = CantorProcessIr {
        ir_id: sid("ir:one"),
        ir_version: CPPE_IR_VERSION.to_owned(),
        ir_digest: digest("c"),
        source_digest: candidate.source_digest.clone(),
        compiler_ref: sid("compiler:fixture"),
        type_table: BTreeMap::new(),
        schema_set,
        constants: BTreeMap::new(),
        sop_anchors: BTreeMap::new(),
        process_definitions: BTreeMap::from([(process.process_definition_id.clone(), process)]),
        effects,
        bounds,
        source_map: BTreeMap::new(),
    };

    let candidate_json = to_machine_form(&candidate).expect("serialize candidate");
    let ir_json = to_machine_form(&ir).expect("serialize IR");
    assert_ne!(candidate_json, ir_json);
    assert!(candidate_json.contains(r#""lifecycle":"proposed""#));
    assert!(ir_json.contains(CPPE_IR_VERSION));
    assert!(!candidate_json.contains("admission_disposition"));
    assert!(!ir_json.contains("admission_disposition"));
}

#[test]
fn ordered_maps_make_machine_output_insertion_independent() {
    let mut left = ProcedureFormSet::new();
    let mut right = ProcedureFormSet::new();
    let first = Participant {
        participant_id: sid("participant:a"),
        role_ref: sid("role:a"),
        permitted_message_kinds: BTreeSet::from([ProcedureMessageKind::Object]),
    };
    let second = Participant {
        participant_id: sid("participant:b"),
        role_ref: sid("role:b"),
        permitted_message_kinds: BTreeSet::from([ProcedureMessageKind::Pass]),
    };
    left.participants
        .insert(second.participant_id.clone(), second.clone());
    left.participants
        .insert(first.participant_id.clone(), first.clone());
    right
        .participants
        .insert(first.participant_id.clone(), first);
    right
        .participants
        .insert(second.participant_id.clone(), second);

    assert_eq!(
        to_machine_form(&left).expect("serialize left"),
        to_machine_form(&right).expect("serialize right")
    );
}
