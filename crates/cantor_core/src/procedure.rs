//! Pure machine forms for the CPPE effectless process-procedure experiment.
//!
//! This module owns serializable data shapes only. Validation, normalization,
//! compilation, verification, admission, interpretation, scheduling, tool
//! calling, persistence, providers, and effects belong to later slices.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{ContentDigest, SemanticId, SensitivityClass};

pub const CPPE_FORM_VERSION: &str = "cantor-process-procedure-experiment/0.1";
pub const CPPE_IR_VERSION: &str = "cantor-process-ir/0.1";

macro_rules! closed_enum {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }
    };
}

closed_enum!(ProcedureEffectClass { Effectless });

closed_enum!(ProcedureReadClass {
    TypedInvocationInput,
    PinnedAdmittedInMemoryArtifact,
});

closed_enum!(ProcedureWriteClass {
    ReturnedValue,
    Message,
    StateSuccessor,
    SemanticTrace,
    Receipt,
    Fault,
});

closed_enum!(ProhibitedProcedureOperation {
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
});

closed_enum!(SchemaKind {
    Input,
    Output,
    Message,
    Event,
    ProcessLocalState,
    ProcedureState,
    InvocationResult,
    Fault,
});

closed_enum!(ProcessOperation {
    Bind,
    Inspect,
    Compare,
    Branch,
    Select,
    MapBounded,
    Emit,
    Receive,
    Yield,
    WaitLogical,
    Reactivate,
    Join,
    Return,
    Fault,
});

closed_enum!(ProcessLifecycle {
    Ready,
    Operating,
    Yielded,
    Waiting,
    Passivated,
    TerminalReturn,
    TerminalFault,
    Cancelled,
});

closed_enum!(ProcedureLifecycle {
    Proposed,
    ParseRejected,
    Validated,
    Compiled,
    VerificationFailed,
    VerificationPassed,
    AdmissionRefused,
    Admitted,
    Suspended,
    Revoked,
    Superseded,
});

closed_enum!(PhaseDisposition {
    Passed,
    Refused,
    Faulted
});

closed_enum!(ProcedurePhase {
    Proposal,
    Parse,
    Validation,
    Compilation,
    Verification,
    Admission,
    Catalogue,
    Invocation,
    Revocation,
    Replay,
});

closed_enum!(AdmissionDecision {
    Admit,
    Qualify,
    Refuse
});

closed_enum!(CatalogueStatus {
    Active,
    Suspended,
    Revoked,
    Superseded,
});

closed_enum!(InvocationDisposition {
    Returned,
    Faulted,
    BudgetRefused,
    Cancelled,
});

closed_enum!(ProcedureMessageKind {
    Propose,
    Question,
    Support,
    Object,
    Counter,
    Qualify,
    Withdraw,
    AdmitCandidate,
    Refuse,
    Yield,
    Pass,
    Fault,
});

closed_enum!(NegotiationStatus {
    Opened,
    Deliberating,
    StableCandidate,
    Admitted,
    Refused,
    TimedOut,
    Cancelled,
    Faulted,
});

closed_enum!(TraceEventKind {
    InvocationStarted,
    ProcessSelected,
    StateReplaced,
    MessageEmitted,
    MessageReceived,
    Yielded,
    Waiting,
    Reactivated,
    Joined,
    FrameRevised,
    ParticipantPassed,
    Returned,
    Faulted,
    BudgetRefused,
    InvocationCompleted,
});

closed_enum!(ProcedureFaultCategory {
    InvalidForm,
    UnsupportedVersion,
    UnknownField,
    TypeMismatch,
    SchemaMismatch,
    UnboundedConstruct,
    BoundExceeded,
    ForbiddenOperation,
    ForbiddenEffect,
    InvalidAnchor,
    StaleGeneration,
    MissingReference,
    DuplicateIdentity,
    IllegalLifecycle,
    Nondeterminism,
    SelfAuthority,
    ResourceExhausted,
    UnstableNegotiation,
    InternalInvariant,
});

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProcedureType {
    Null,
    Boolean,
    BoundedInteger {
        minimum: i64,
        maximum: i64,
    },
    BoundedDecimal {
        minimum: String,
        maximum: String,
        scale: u32,
    },
    BoundedText {
        maximum_bytes: u64,
    },
    BytesDigest,
    IdentityReference {
        expected_kind: String,
    },
    List {
        member: Box<ProcedureType>,
        maximum_items: u64,
    },
    OrderedMap {
        value: Box<ProcedureType>,
        maximum_entries: u64,
    },
    Record {
        schema_ref: SemanticId,
    },
    TaggedUnion {
        schema_ref: SemanticId,
    },
    TypedFault {
        schema_ref: SemanticId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProcedureValue {
    Null,
    Boolean {
        value: bool,
    },
    Integer {
        value: i64,
    },
    Decimal {
        canonical: String,
    },
    Text {
        value: String,
    },
    BytesDigest {
        value: ContentDigest,
    },
    IdentityReference {
        value: SemanticId,
    },
    List {
        members: Vec<ProcedureValue>,
    },
    OrderedMap {
        entries: BTreeMap<String, ProcedureValue>,
    },
    Record {
        fields: BTreeMap<String, ProcedureValue>,
    },
    TaggedUnion {
        tag: String,
        value: Box<ProcedureValue>,
    },
    TypedFault {
        fault_ref: SemanticId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureBounds {
    pub bound_set_id: SemanticId,
    pub maximum_source_bytes: u64,
    pub maximum_text_bytes: u64,
    pub maximum_value_bytes: u64,
    pub maximum_collection_items: u64,
    pub maximum_map_entries: u64,
    pub maximum_processes: u64,
    pub maximum_messages: u64,
    pub maximum_queue_depth: u64,
    pub maximum_events: u64,
    pub maximum_event_queue_depth: u64,
    pub maximum_call_depth: u64,
    pub maximum_transitions: u64,
    pub maximum_trace_events: u64,
    pub maximum_memory_units: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SopAnchorBinding {
    pub anchor_id: SemanticId,
    pub artifact_id: SemanticId,
    pub artifact_version: String,
    pub artifact_digest: ContentDigest,
    pub clause_id: Option<SemanticId>,
    pub intended_use: String,
    pub sensitivity: SensitivityClass,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaField {
    pub field_name: String,
    pub value_type: ProcedureType,
    pub required: bool,
    pub sensitivity: SensitivityClass,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaggedVariant {
    pub tag: String,
    pub value_type: ProcedureType,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureSchema {
    pub schema_id: SemanticId,
    pub schema_version: String,
    pub kind: SchemaKind,
    pub fields: BTreeMap<String, SchemaField>,
    pub tagged_variants: BTreeMap<String, TaggedVariant>,
    pub closed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureSchemaSet {
    pub schema_set_id: SemanticId,
    pub schema_set_digest: ContentDigest,
    pub schemas: BTreeMap<SemanticId, ProcedureSchema>,
    pub migration_ref: Option<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureEffectDeclaration {
    pub effect_class: ProcedureEffectClass,
    pub allowed_read_classes: BTreeSet<ProcedureReadClass>,
    pub allowed_write_classes: BTreeSet<ProcedureWriteClass>,
    pub prohibited_operations: BTreeSet<ProhibitedProcedureOperation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionOperand {
    pub name: String,
    pub value: ProcedureValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessInstruction {
    pub instruction_id: SemanticId,
    pub operation: ProcessOperation,
    pub operands: Vec<InstructionOperand>,
    pub result_binding: Option<String>,
    pub successor_region_refs: Vec<SemanticId>,
    pub bound_ref: SemanticId,
    pub source_span_ref: SemanticId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRegion {
    pub region_id: SemanticId,
    pub instructions: Vec<ProcessInstruction>,
    pub terminal: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessDefinition {
    pub process_definition_id: SemanticId,
    pub name: String,
    pub role_ref: SemanticId,
    pub initial_state: ProcedureValue,
    pub accepted_message_tags: BTreeSet<String>,
    pub emitted_message_tags: BTreeSet<String>,
    pub entry_region_ref: SemanticId,
    pub control_regions: BTreeMap<SemanticId, ControlRegion>,
    pub terminal_region_refs: BTreeSet<SemanticId>,
    pub resource_contribution_ref: SemanticId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureCandidate {
    pub candidate_id: SemanticId,
    pub author_ref: SemanticId,
    pub provenance_refs: BTreeSet<SemanticId>,
    pub purpose: String,
    pub scope: BTreeSet<String>,
    pub language_profile: String,
    pub source_text: Option<String>,
    pub normalized_source_form: Option<ProcedureValue>,
    pub source_digest: ContentDigest,
    pub sop_anchors: BTreeMap<SemanticId, SopAnchorBinding>,
    pub schema_set: ProcedureSchemaSet,
    pub process_definitions: BTreeMap<SemanticId, ProcessDefinition>,
    pub effects: ProcedureEffectDeclaration,
    pub bounds: ProcedureBounds,
    pub created_logical_time: u64,
    pub sensitivity: SensitivityClass,
    pub retention_policy_ref: SemanticId,
    pub lifecycle: ProcedureLifecycle,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledProcedureIdentity {
    pub procedure_id: SemanticId,
    pub procedure_version: String,
    pub predecessor_procedure_refs: BTreeSet<SemanticId>,
    pub candidate_ref: SemanticId,
    pub canonical_source_digest: ContentDigest,
    pub compiler_ref: SemanticId,
    pub language_profile: String,
    pub ir_ref: SemanticId,
    pub ir_digest: ContentDigest,
    pub schema_set_digest: ContentDigest,
    pub effect_class: ProcedureEffectClass,
    pub bound_set_ref: SemanticId,
    pub procedure_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceMapEntry {
    pub source_map_id: SemanticId,
    pub source_span_ref: SemanticId,
    pub ir_subject_ref: SemanticId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CantorProcessIr {
    pub ir_id: SemanticId,
    pub ir_version: String,
    pub ir_digest: ContentDigest,
    pub source_digest: ContentDigest,
    pub compiler_ref: SemanticId,
    pub type_table: BTreeMap<String, ProcedureType>,
    pub schema_set: ProcedureSchemaSet,
    pub constants: BTreeMap<String, ProcedureValue>,
    pub sop_anchors: BTreeMap<SemanticId, SopAnchorBinding>,
    pub process_definitions: BTreeMap<SemanticId, ProcessDefinition>,
    pub effects: ProcedureEffectDeclaration,
    pub bounds: ProcedureBounds,
    pub source_map: BTreeMap<SemanticId, SourceMapEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AwaitedCondition {
    None,
    Message {
        tag: String,
    },
    LogicalTime {
        not_before: u64,
    },
    ProcessTerminal {
        process_instance_ref: SemanticId,
    },
    Join {
        required_process_refs: BTreeSet<SemanticId>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessBudgetState {
    pub transitions_remaining: u64,
    pub messages_remaining: u64,
    pub memory_units_remaining: u64,
    pub trace_events_remaining: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessInstanceState {
    pub state_id: SemanticId,
    pub invocation_ref: SemanticId,
    pub process_instance_id: SemanticId,
    pub generation: u64,
    pub definition_ref: SemanticId,
    pub region_ref: SemanticId,
    pub instruction_index: u64,
    pub local_state: ProcedureValue,
    pub inbox_frontier: BTreeSet<SemanticId>,
    pub outbox_frontier: BTreeSet<SemanticId>,
    pub awaited_condition: AwaitedCondition,
    pub lifecycle: ProcessLifecycle,
    pub logical_time: u64,
    pub remaining_budgets: ProcessBudgetState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SerializedContinuation {
    pub continuation_id: SemanticId,
    pub procedure_ref: SemanticId,
    pub process_state: ProcessInstanceState,
    pub inbox_generation: u64,
    pub continuation_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStep {
    pub step_id: SemanticId,
    pub invocation_ref: SemanticId,
    pub process_instance_ref: SemanticId,
    pub input_generation: u64,
    pub instruction_ref: SemanticId,
    pub input_message_refs: BTreeSet<SemanticId>,
    pub emitted_message_refs: BTreeSet<SemanticId>,
    pub successor_state: Option<ProcessInstanceState>,
    pub returned_value: Option<ProcedureValue>,
    pub fault_ref: Option<SemanticId>,
    pub logical_time_before: u64,
    pub logical_time_after: u64,
    pub consumed_budget: ConsumedBudget,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Participant {
    pub participant_id: SemanticId,
    pub role_ref: SemanticId,
    pub permitted_message_kinds: BTreeSet<ProcedureMessageKind>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureMessage {
    pub message_id: SemanticId,
    pub session_ref: SemanticId,
    pub sender_ref: SemanticId,
    pub receiver_ref: SemanticId,
    pub frame_generation: u64,
    pub sop_anchor_refs: BTreeSet<SemanticId>,
    pub kind: ProcedureMessageKind,
    pub payload: ProcedureValue,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub logical_time: u64,
    pub causal_predecessor_refs: BTreeSet<SemanticId>,
    pub expires_at_logical_time: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegotiatedFrame {
    pub frame_id: SemanticId,
    pub generation: u64,
    pub propositions: BTreeMap<SemanticId, ProcedureValue>,
    pub conditions: BTreeSet<String>,
    pub constraints: BTreeSet<String>,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub objection_refs: BTreeSet<SemanticId>,
    pub participant_refs: BTreeSet<SemanticId>,
    pub policy_ref: SemanticId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegotiationSession {
    pub session_generation_id: SemanticId,
    pub session_id: SemanticId,
    pub frame_generation: u64,
    pub purpose: String,
    pub required_participant_refs: BTreeSet<SemanticId>,
    pub optional_observer_refs: BTreeSet<SemanticId>,
    pub participants: BTreeMap<SemanticId, Participant>,
    pub pinned_sop_anchor_refs: BTreeSet<SemanticId>,
    pub policy_ref: SemanticId,
    pub frame: NegotiatedFrame,
    pub token_holder_ref: SemanticId,
    pub pass_refs: BTreeSet<SemanticId>,
    pub message_frontier: BTreeSet<SemanticId>,
    pub status: NegotiationStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRingPass {
    pub pass_id: SemanticId,
    pub session_ref: SemanticId,
    pub participant_ref: SemanticId,
    pub frame_generation: u64,
    pub participant_set_digest: ContentDigest,
    pub sop_anchor_set_digest: ContentDigest,
    pub policy_ref: SemanticId,
    pub predecessor_pass_ref: Option<SemanticId>,
    pub logical_time: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptEvidence {
    pub evidence_refs: BTreeSet<SemanticId>,
    pub residuals: BTreeSet<String>,
    pub diagnostics: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationReceipt {
    pub receipt_id: SemanticId,
    pub candidate_ref: SemanticId,
    pub candidate_source_digest: ContentDigest,
    pub validator_ref: SemanticId,
    pub profile: String,
    pub disposition: PhaseDisposition,
    pub evidence: ReceiptEvidence,
    pub receipt_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilationReceipt {
    pub receipt_id: SemanticId,
    pub candidate_ref: SemanticId,
    pub candidate_source_digest: ContentDigest,
    pub validation_receipt_ref: SemanticId,
    pub compiler_ref: SemanticId,
    pub ir_ref: Option<SemanticId>,
    pub ir_digest: Option<ContentDigest>,
    pub disposition: PhaseDisposition,
    pub cost_estimate: BTreeMap<String, u64>,
    pub evidence: ReceiptEvidence,
    pub receipt_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationReceipt {
    pub receipt_id: SemanticId,
    pub candidate_ref: SemanticId,
    pub candidate_source_digest: ContentDigest,
    pub compilation_receipt_ref: SemanticId,
    pub verifier_ref: SemanticId,
    pub compiler_ref: SemanticId,
    pub ir_ref: SemanticId,
    pub ir_digest: ContentDigest,
    pub compiled_procedure_ref: SemanticId,
    pub compiled_procedure_digest: ContentDigest,
    pub anchor_set_digest: ContentDigest,
    pub effect_declaration_digest: ContentDigest,
    pub bound_set_ref: SemanticId,
    pub bounds_digest: ContentDigest,
    pub disposition: PhaseDisposition,
    pub evidence: ReceiptEvidence,
    pub receipt_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionDisposition {
    pub disposition_id: SemanticId,
    pub candidate_ref: SemanticId,
    pub candidate_source_digest: ContentDigest,
    pub validation_receipt_ref: SemanticId,
    pub compilation_receipt_ref: SemanticId,
    pub verification_receipt_ref: SemanticId,
    pub observer_ref: SemanticId,
    pub compiler_ref: SemanticId,
    pub ir_ref: SemanticId,
    pub ir_digest: ContentDigest,
    pub procedure_ref: SemanticId,
    pub procedure_digest: ContentDigest,
    pub anchor_set_digest: ContentDigest,
    pub effect_declaration_digest: ContentDigest,
    pub bound_set_ref: SemanticId,
    pub bounds_digest: ContentDigest,
    pub decision: AdmissionDecision,
    pub permitted_invocation_contexts: BTreeSet<String>,
    pub revocation_conditions: BTreeSet<String>,
    pub policy_ref: SemanticId,
    pub policy_digest: ContentDigest,
    pub evidence: ReceiptEvidence,
    pub disposition_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogueReceipt {
    pub receipt_id: SemanticId,
    pub catalogue_generation_before: ContentDigest,
    pub catalogue_generation_after: Option<ContentDigest>,
    pub procedure_ref: SemanticId,
    pub procedure_digest: ContentDigest,
    pub admission_disposition_ref: SemanticId,
    pub admission_disposition_digest: ContentDigest,
    pub principal_ref: SemanticId,
    pub disposition: PhaseDisposition,
    pub evidence: ReceiptEvidence,
    pub receipt_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationRecord {
    pub revocation_id: SemanticId,
    pub procedure_ref: SemanticId,
    pub predecessor_status: CatalogueStatus,
    pub successor_status: CatalogueStatus,
    pub principal_ref: SemanticId,
    pub reason: String,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub logical_time: u64,
    pub record_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedurePhaseReceiptSet {
    pub receipt_set_id: SemanticId,
    pub candidate_ref: SemanticId,
    pub validation_receipt_ref: SemanticId,
    pub compilation_receipt_ref: Option<SemanticId>,
    pub verification_receipt_refs: BTreeSet<SemanticId>,
    pub admission_disposition_ref: Option<SemanticId>,
    pub catalogue_receipt_refs: BTreeSet<SemanticId>,
    pub revocation_refs: BTreeSet<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureCatalogueEntry {
    pub procedure_ref: SemanticId,
    pub procedure_version: String,
    pub procedure_digest: ContentDigest,
    pub admission_disposition_ref: SemanticId,
    pub admission_disposition_digest: ContentDigest,
    pub status: CatalogueStatus,
    pub aliases: BTreeSet<String>,
    pub revocation_ref: Option<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureCatalogueState {
    pub generation: u64,
    pub generation_digest: ContentDigest,
    pub entries: BTreeMap<SemanticId, ProcedureCatalogueEntry>,
    pub aliases: BTreeMap<String, BTreeSet<SemanticId>>,
    pub revocations: BTreeMap<SemanticId, RevocationRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationBudget {
    pub logical_time_limit: u64,
    pub step_limit: u64,
    pub memory_unit_limit: u64,
    pub message_limit: u64,
    pub trace_event_limit: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationRequest {
    pub invocation_id: SemanticId,
    pub caller_ref: SemanticId,
    pub purpose: String,
    pub admitted_procedure_ref: SemanticId,
    pub procedure_digest: ContentDigest,
    pub admission_disposition_ref: SemanticId,
    pub admission_disposition_digest: ContentDigest,
    pub input_schema_ref: SemanticId,
    pub schema_set_digest: ContentDigest,
    pub input: ProcedureValue,
    pub input_sensitivity: SensitivityClass,
    pub sop_generation_ref: SemanticId,
    pub sop_anchor_set_digest: ContentDigest,
    pub policy_ref: SemanticId,
    pub policy_digest: ContentDigest,
    pub participant_refs: BTreeSet<SemanticId>,
    pub initial_logical_time: u64,
    pub budgets: InvocationBudget,
    pub expected_output_schema_ref: SemanticId,
    pub catalogue_generation_digest: ContentDigest,
    pub retention_policy_ref: SemanticId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticTraceEvent {
    pub event_id: SemanticId,
    pub logical_index: u64,
    pub kind: TraceEventKind,
    pub procedure_ref: SemanticId,
    pub process_ref: Option<SemanticId>,
    pub subject_generation: u64,
    pub normalized_payload_digest: ContentDigest,
    pub causal_predecessor_refs: BTreeSet<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticTrace {
    pub trace_id: SemanticId,
    pub events: Vec<SemanticTraceEvent>,
    pub trace_digest: ContentDigest,
    pub sensitivity: SensitivityClass,
    pub retention_policy_ref: SemanticId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumedBudget {
    pub logical_time: u64,
    pub steps: u64,
    pub memory_units: u64,
    pub messages: u64,
    pub trace_events: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureFault {
    pub fault_id: SemanticId,
    pub phase: ProcedurePhase,
    pub category: ProcedureFaultCategory,
    pub subject_refs: BTreeSet<SemanticId>,
    pub expected_versions: BTreeMap<String, String>,
    pub observed_versions: BTreeMap<String, String>,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub consumed_budget: ConsumedBudget,
    pub trace_location: Option<u64>,
    pub safe_residuals: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationResult {
    pub invocation_ref: SemanticId,
    pub procedure_ref: SemanticId,
    pub disposition: InvocationDisposition,
    pub output: Option<ProcedureValue>,
    pub output_sensitivity: SensitivityClass,
    pub fault: Option<ProcedureFault>,
    pub final_process_states: BTreeMap<SemanticId, ProcessInstanceState>,
    pub semantic_trace: SemanticTrace,
    pub consumed_budget: ConsumedBudget,
    pub residuals: BTreeSet<String>,
    pub proof_refs: BTreeSet<SemanticId>,
    pub retention_policy_ref: SemanticId,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureFormSet {
    pub form_version: String,
    pub candidates: BTreeMap<SemanticId, ProcedureCandidate>,
    pub compiled_procedures: BTreeMap<SemanticId, CompiledProcedureIdentity>,
    pub schema_sets: BTreeMap<SemanticId, ProcedureSchemaSet>,
    pub process_definitions: BTreeMap<SemanticId, ProcessDefinition>,
    pub process_irs: BTreeMap<SemanticId, CantorProcessIr>,
    pub process_instances: BTreeMap<SemanticId, ProcessInstanceState>,
    pub continuations: BTreeMap<SemanticId, SerializedContinuation>,
    pub process_steps: BTreeMap<SemanticId, ProcessStep>,
    pub participants: BTreeMap<SemanticId, Participant>,
    pub messages: BTreeMap<SemanticId, ProcedureMessage>,
    pub negotiated_frames: BTreeMap<SemanticId, NegotiatedFrame>,
    pub negotiation_sessions: BTreeMap<SemanticId, NegotiationSession>,
    pub token_ring_passes: BTreeMap<SemanticId, TokenRingPass>,
    pub validation_receipts: BTreeMap<SemanticId, ValidationReceipt>,
    pub compilation_receipts: BTreeMap<SemanticId, CompilationReceipt>,
    pub verification_receipts: BTreeMap<SemanticId, VerificationReceipt>,
    pub admission_dispositions: BTreeMap<SemanticId, AdmissionDisposition>,
    pub catalogue_receipts: BTreeMap<SemanticId, CatalogueReceipt>,
    pub revocations: BTreeMap<SemanticId, RevocationRecord>,
    pub phase_receipt_sets: BTreeMap<SemanticId, ProcedurePhaseReceiptSet>,
    pub catalogues_by_generation_digest: BTreeMap<String, ProcedureCatalogueState>,
    pub invocation_requests: BTreeMap<SemanticId, InvocationRequest>,
    pub invocation_results: BTreeMap<SemanticId, InvocationResult>,
    pub semantic_traces: BTreeMap<SemanticId, SemanticTrace>,
    pub faults: BTreeMap<SemanticId, ProcedureFault>,
}

impl ProcedureFormSet {
    /// Creates an empty data container at the exact CPPE profile version.
    /// Semantic validation and normalization are intentionally deferred.
    pub fn new() -> Self {
        Self {
            form_version: CPPE_FORM_VERSION.to_owned(),
            ..Self::default()
        }
    }
}
