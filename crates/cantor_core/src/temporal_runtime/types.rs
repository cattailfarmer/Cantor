use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    BarrierState, BoundedLagPolicy, CalendarItem, CalendarLifecycleState, CapsuleState,
    ChangeCapsule, CompilerGeneration, CompilerImpact, ContentDigest, ContentObject,
    DeclaredIntent, DiffKind, DiffRecord, EventKind, LaneCursor, LaneMessage, LaneState,
    MaterialEvent, MaterialityDecision, ObserverJoin, PlanRevision, RecurrenceRule,
    ReflectionReturn, ReleaseBarrier, RepositoryGeneration, SemanticId, SemanticSnapshot,
    TemporalFormSet, TimeExpression, WakeCondition, WorkPacket,
};

pub const CDRA_RUNTIME_PROFILE: &str = "cantor-cdra-runtime/0.1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBounds {
    pub max_form_records: usize,
    pub max_payload_bytes: usize,
    pub max_operation_input_bytes: usize,
    pub max_emitted_records: usize,
    pub max_graph_visits: usize,
    pub max_recurrence_occurrences: usize,
    pub max_trace_events: usize,
    pub max_replay_operations: usize,
}

impl Default for RuntimeBounds {
    fn default() -> Self {
        Self {
            max_form_records: 16_384,
            max_payload_bytes: 16 * 1024 * 1024,
            max_operation_input_bytes: 4 * 1024 * 1024,
            max_emitted_records: 4_096,
            max_graph_visits: 16_384,
            max_recurrence_occurrences: 4_096,
            max_trace_events: 16_384,
            max_replay_operations: 4_096,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationLimits {
    pub max_input_bytes: usize,
    pub max_emitted_records: usize,
    pub max_graph_visits: usize,
}

impl Default for OperationLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 1024 * 1024,
            max_emitted_records: 1024,
            max_graph_visits: 4096,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePolicies {
    pub exact_version_only: bool,
    pub stable_identity_tie_break: bool,
    pub objective_priority: BTreeMap<SemanticId, u32>,
    pub recognized_resource_refs: BTreeSet<SemanticId>,
}

impl Default for RuntimePolicies {
    fn default() -> Self {
        Self {
            exact_version_only: true,
            stable_identity_tie_break: true,
            objective_priority: BTreeMap::new(),
            recognized_resource_refs: BTreeSet::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalClock {
    pub clock_id: SemanticId,
    pub tick: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryIndex {
    pub source_generation_ref: Option<SemanticId>,
    pub events_by_subject: BTreeMap<SemanticId, BTreeSet<SemanticId>>,
    pub content_by_digest: BTreeMap<String, SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FakeRepositoryState {
    pub repository_id: SemanticId,
    pub current_generation_ref: Option<SemanticId>,
    pub branch_heads: BTreeMap<SemanticId, SemanticId>,
    pub content_bytes: BTreeMap<SemanticId, Vec<u8>>,
    pub index: RepositoryIndex,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FakeCalendarState {
    pub latest_item_revision: BTreeMap<SemanticId, SemanticId>,
    pub latest_recurrence_revision: BTreeMap<SemanticId, SemanticId>,
    pub recurrence_history: BTreeMap<SemanticId, RecurrenceRule>,
    pub materialized_occurrence_keys: BTreeMap<SemanticId, BTreeSet<String>>,
    pub emitted_wake_candidates: BTreeSet<SemanticId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeterministicPlannerState {
    pub latest_plan_revision_ref: Option<SemanticId>,
    pub last_objective_order: Vec<SemanticId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TandemRuntimeState {
    pub capsule_state_history: BTreeMap<SemanticId, Vec<CapsuleState>>,
    pub lane_state_history: BTreeMap<SemanticId, Vec<LaneState>>,
    pub lane_return_refs: BTreeMap<SemanticId, SemanticId>,
    pub acknowledged_message_refs: BTreeSet<SemanticId>,
    pub reentry_predecessors: BTreeMap<SemanticId, SemanticId>,
    pub transition_counts: BTreeMap<SemanticId, BTreeMap<String, u32>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompilerFixtureStatus {
    Registered,
    ForwardPredicted,
    RearCompared,
    Checked,
    Invalidated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerFixtureManifest {
    pub fixture_id: SemanticId,
    pub before_generation_ref: SemanticId,
    pub candidate_generation_ref: SemanticId,
    pub source_object_refs: BTreeSet<SemanticId>,
    pub semantic_ir_object_refs: BTreeSet<SemanticId>,
    pub build_ir_object_refs: BTreeSet<SemanticId>,
    pub target_metadata_object_refs: BTreeSet<SemanticId>,
    pub correspondence_evidence_refs: BTreeSet<SemanticId>,
    pub independent_correspondence_evidence_refs: BTreeSet<SemanticId>,
    pub proof_record_refs: BTreeSet<SemanticId>,
    pub required_diff_kinds: BTreeSet<DiffKind>,
    pub declared_unrelated_refs: BTreeSet<SemanticId>,
    pub observer_join_ref: SemanticId,
    pub max_fixture_records: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerForwardPrediction {
    pub prediction_id: SemanticId,
    pub fixture_ref: SemanticId,
    pub before_generation_ref: SemanticId,
    pub candidate_generation_ref: SemanticId,
    pub predicted_changed_source_refs: BTreeSet<SemanticId>,
    pub predicted_changed_semantic_refs: BTreeSet<SemanticId>,
    pub predicted_invalidated_refs: BTreeSet<SemanticId>,
    pub predicted_dependency_refs: BTreeSet<SemanticId>,
    pub predicted_target_artifact_refs: BTreeSet<SemanticId>,
    pub predicted_diagnostics: BTreeSet<String>,
    pub predicted_proof_requirement_refs: BTreeSet<SemanticId>,
    pub explicit_unknowns: BTreeSet<String>,
    pub prediction_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerRearCheck {
    pub rear_check_id: SemanticId,
    pub fixture_ref: SemanticId,
    pub before_generation_ref: SemanticId,
    pub candidate_generation_ref: SemanticId,
    pub diff_refs: BTreeMap<DiffKind, SemanticId>,
    pub observed_changed_source_refs: BTreeSet<SemanticId>,
    pub observed_changed_semantic_refs: BTreeSet<SemanticId>,
    pub observed_invalidated_refs: BTreeSet<SemanticId>,
    pub independent_correspondence_evidence_refs: BTreeSet<SemanticId>,
    pub preserved_unrelated_refs: BTreeSet<SemanticId>,
    pub explicit_unknowns: BTreeSet<String>,
    pub matched_forward_prediction: bool,
    pub rear_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerFixtureRecord {
    pub manifest: CompilerFixtureManifest,
    pub status: CompilerFixtureStatus,
    pub forward_prediction_ref: Option<SemanticId>,
    pub rear_check_ref: Option<SemanticId>,
    pub checked_observer_join_ref: Option<SemanticId>,
    pub checked_generation_ref: Option<SemanticId>,
    pub invalidated_refs: BTreeSet<SemanticId>,
    pub preserved_unrelated_refs: BTreeSet<SemanticId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerFixtureRuntimeState {
    pub fixtures: BTreeMap<SemanticId, CompilerFixtureRecord>,
    pub forward_predictions: BTreeMap<SemanticId, CompilerForwardPrediction>,
    pub rear_checks: BTreeMap<SemanticId, CompilerRearCheck>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeOperationKind {
    AdvanceLogicalTime,
    CompareAndAppend,
    ReviseCalendar,
    ExpandRecurrence,
    EvaluateWake,
    ProposePlan,
    ClassifyMateriality,
    EvaluateCalendarState,
    OpenTandem,
    TransitionCapsule,
    TransitionLane,
    AppendLaneMessage,
    AcknowledgeLaneMessage,
    ReconcileObserver,
    EvaluateReleaseBarrier,
    ReenterLane,
    RegisterCompilerFixture,
    RunCompilerForward,
    RunCompilerRear,
    CheckCompilerFixture,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTraceEvent {
    pub trace_index: u64,
    pub operation_id: SemanticId,
    pub operation_kind: RuntimeOperationKind,
    pub logical_tick: u64,
    pub emitted_identities: BTreeSet<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeterministicRuntimeRoot {
    pub runtime_profile: String,
    pub policies: RuntimePolicies,
    pub bounds: RuntimeBounds,
    pub logical_clock: LogicalClock,
    pub forms: TemporalFormSet,
    pub repository: FakeRepositoryState,
    pub calendar: FakeCalendarState,
    pub planner: DeterministicPlannerState,
    pub tandem: TandemRuntimeState,
    pub compiler: CompilerFixtureRuntimeState,
    pub trace: Vec<RuntimeTraceEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSnapshot {
    pub root_digest: ContentDigest,
    pub root: DeterministicRuntimeRoot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeOperationContext {
    pub operation_id: SemanticId,
    pub caller_id: SemanticId,
    pub expected_root_digest: ContentDigest,
    pub limits: OperationLimits,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentInput {
    pub object: ContentObject,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WakeRevalidationContext {
    pub task_ref: SemanticId,
    pub plan_revision_ref: SemanticId,
    pub repository_generation_ref: SemanticId,
    pub capsule_generation_ref: SemanticId,
    pub policy_refs: BTreeSet<SemanticId>,
    pub authority_evidence_refs: BTreeSet<SemanticId>,
    pub satisfied_requirements: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarEvaluationKind {
    Due,
    Missed,
    Cancelled,
    Completed,
    Superseded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarEventCandidate {
    pub candidate_event_id: SemanticId,
    pub calendar_item_ref: SemanticId,
    pub predecessor_revision_ref: SemanticId,
    pub evaluated_at_tick: u64,
    pub evaluation_kind: CalendarEvaluationKind,
    pub lifecycle_state: CalendarLifecycleState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeOperation {
    AdvanceLogicalTime {
        context: RuntimeOperationContext,
        delta: u64,
    },
    CompareAndAppend {
        context: RuntimeOperationContext,
        branch_ref: SemanticId,
        expected_generation_ref: Option<SemanticId>,
        generation: RepositoryGeneration,
        content: Vec<ContentInput>,
        events: Vec<MaterialEvent>,
        snapshot: Option<SemanticSnapshot>,
    },
    ReviseCalendar {
        context: RuntimeOperationContext,
        recurrence: Option<RecurrenceRule>,
        item: CalendarItem,
        wake_conditions: Vec<WakeCondition>,
    },
    ExpandRecurrence {
        context: RuntimeOperationContext,
        recurrence_revision_ref: SemanticId,
        candidate_occurrence_keys: BTreeSet<String>,
    },
    EvaluateWake {
        context: RuntimeOperationContext,
        wake_ref: SemanticId,
        revalidation: WakeRevalidationContext,
    },
    ProposePlan {
        context: RuntimeOperationContext,
        plan: PlanRevision,
        repository_generation_ref: SemanticId,
        calendar_revision_refs: BTreeSet<SemanticId>,
        proof_gate_refs: BTreeSet<SemanticId>,
        available_resource_refs: BTreeSet<SemanticId>,
    },
    ClassifyMateriality {
        context: RuntimeOperationContext,
        policy_revision_ref: SemanticId,
        event_kind: EventKind,
        purpose: String,
        evidence_refs: BTreeSet<SemanticId>,
    },
    EvaluateCalendarState {
        context: RuntimeOperationContext,
        predecessor_revision_ref: SemanticId,
        successor_item: CalendarItem,
        evaluated_at_tick: u64,
        evaluation_kind: CalendarEvaluationKind,
        candidate_event_id: SemanticId,
    },
    OpenTandem {
        context: RuntimeOperationContext,
        declared_intent: DeclaredIntent,
        capsule: ChangeCapsule,
        lane_cursors: Vec<LaneCursor>,
        work_packets: Vec<WorkPacket>,
        release_barriers: Vec<ReleaseBarrier>,
        bounded_lag_policies: Vec<BoundedLagPolicy>,
    },
    TransitionCapsule {
        context: RuntimeOperationContext,
        expected_state: CapsuleState,
        successor: ChangeCapsule,
    },
    TransitionLane {
        context: RuntimeOperationContext,
        expected_state: LaneState,
        successor: LaneCursor,
        return_ref: Option<SemanticId>,
        reflection_return: Option<ReflectionReturn>,
    },
    AppendLaneMessage {
        context: RuntimeOperationContext,
        logical_time: TimeExpression,
        message: LaneMessage,
    },
    AcknowledgeLaneMessage {
        context: RuntimeOperationContext,
        message_ref: SemanticId,
        receiver_cursor_ref: SemanticId,
    },
    ReconcileObserver {
        context: RuntimeOperationContext,
        join: ObserverJoin,
        successor_capsule: ChangeCapsule,
    },
    EvaluateReleaseBarrier {
        context: RuntimeOperationContext,
        expected_state: BarrierState,
        successor: ReleaseBarrier,
    },
    ReenterLane {
        context: RuntimeOperationContext,
        predecessor_cursor_ref: SemanticId,
        successor_cursor: LaneCursor,
    },
    RegisterCompilerFixture {
        context: RuntimeOperationContext,
        manifest: CompilerFixtureManifest,
        before_generation: Box<CompilerGeneration>,
        candidate_generation: Box<CompilerGeneration>,
        impact: Box<CompilerImpact>,
        content: Vec<ContentInput>,
        diffs: Vec<DiffRecord>,
    },
    RunCompilerForward {
        context: RuntimeOperationContext,
        fixture_ref: SemanticId,
        prediction_id: SemanticId,
    },
    RunCompilerRear {
        context: RuntimeOperationContext,
        fixture_ref: SemanticId,
        rear_check_id: SemanticId,
    },
    CheckCompilerFixture {
        context: RuntimeOperationContext,
        fixture_ref: SemanticId,
        checked_generation_id: SemanticId,
    },
}

impl RuntimeOperation {
    pub fn context(&self) -> &RuntimeOperationContext {
        match self {
            Self::AdvanceLogicalTime { context, .. }
            | Self::CompareAndAppend { context, .. }
            | Self::ReviseCalendar { context, .. }
            | Self::ExpandRecurrence { context, .. }
            | Self::EvaluateWake { context, .. }
            | Self::ProposePlan { context, .. }
            | Self::ClassifyMateriality { context, .. }
            | Self::EvaluateCalendarState { context, .. }
            | Self::OpenTandem { context, .. }
            | Self::TransitionCapsule { context, .. }
            | Self::TransitionLane { context, .. }
            | Self::AppendLaneMessage { context, .. }
            | Self::AcknowledgeLaneMessage { context, .. }
            | Self::ReconcileObserver { context, .. }
            | Self::EvaluateReleaseBarrier { context, .. }
            | Self::ReenterLane { context, .. }
            | Self::RegisterCompilerFixture { context, .. }
            | Self::RunCompilerForward { context, .. }
            | Self::RunCompilerRear { context, .. }
            | Self::CheckCompilerFixture { context, .. } => context,
        }
    }

    pub fn operation_kind(&self) -> RuntimeOperationKind {
        match self {
            Self::AdvanceLogicalTime { .. } => RuntimeOperationKind::AdvanceLogicalTime,
            Self::CompareAndAppend { .. } => RuntimeOperationKind::CompareAndAppend,
            Self::ReviseCalendar { .. } => RuntimeOperationKind::ReviseCalendar,
            Self::ExpandRecurrence { .. } => RuntimeOperationKind::ExpandRecurrence,
            Self::EvaluateWake { .. } => RuntimeOperationKind::EvaluateWake,
            Self::ProposePlan { .. } => RuntimeOperationKind::ProposePlan,
            Self::ClassifyMateriality { .. } => RuntimeOperationKind::ClassifyMateriality,
            Self::EvaluateCalendarState { .. } => RuntimeOperationKind::EvaluateCalendarState,
            Self::OpenTandem { .. } => RuntimeOperationKind::OpenTandem,
            Self::TransitionCapsule { .. } => RuntimeOperationKind::TransitionCapsule,
            Self::TransitionLane { .. } => RuntimeOperationKind::TransitionLane,
            Self::AppendLaneMessage { .. } => RuntimeOperationKind::AppendLaneMessage,
            Self::AcknowledgeLaneMessage { .. } => RuntimeOperationKind::AcknowledgeLaneMessage,
            Self::ReconcileObserver { .. } => RuntimeOperationKind::ReconcileObserver,
            Self::EvaluateReleaseBarrier { .. } => RuntimeOperationKind::EvaluateReleaseBarrier,
            Self::ReenterLane { .. } => RuntimeOperationKind::ReenterLane,
            Self::RegisterCompilerFixture { .. } => RuntimeOperationKind::RegisterCompilerFixture,
            Self::RunCompilerForward { .. } => RuntimeOperationKind::RunCompilerForward,
            Self::RunCompilerRear { .. } => RuntimeOperationKind::RunCompilerRear,
            Self::CheckCompilerFixture { .. } => RuntimeOperationKind::CheckCompilerFixture,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeOutput {
    LogicalTime {
        tick: u64,
    },
    RepositoryGeneration {
        generation_ref: SemanticId,
    },
    CalendarRevision {
        revision_ref: SemanticId,
    },
    RecurrenceExpansion {
        recurrence_revision_ref: SemanticId,
        occurrence_keys: BTreeSet<String>,
    },
    WakeCandidate {
        wake_ref: SemanticId,
        calendar_item_ref: SemanticId,
    },
    PlanProposal {
        plan_revision_ref: SemanticId,
        objective_order: Vec<SemanticId>,
        resource_refs_observed: BTreeSet<SemanticId>,
    },
    MaterialityClassification {
        decision: MaterialityDecision,
    },
    CalendarStateEvaluation {
        candidate: CalendarEventCandidate,
        successor_revision_ref: SemanticId,
    },
    TandemOpened {
        capsule_generation_ref: SemanticId,
        lane_cursor_refs: BTreeSet<SemanticId>,
    },
    CapsuleTransition {
        capsule_generation_ref: SemanticId,
        state: CapsuleState,
    },
    LaneTransition {
        cursor_ref: SemanticId,
        state: LaneState,
        return_ref: Option<SemanticId>,
    },
    LaneMessageAppended {
        message_ref: SemanticId,
    },
    LaneMessageAcknowledged {
        message_ref: SemanticId,
        receiver_cursor_ref: SemanticId,
    },
    ObserverReconciliation {
        join_ref: SemanticId,
        capsule_generation_ref: SemanticId,
    },
    ReleaseBarrierEvaluation {
        barrier_ref: SemanticId,
        state: BarrierState,
        released_refs: BTreeSet<SemanticId>,
    },
    LaneReentry {
        predecessor_cursor_ref: SemanticId,
        successor_cursor_ref: SemanticId,
    },
    CompilerFixtureRegistered {
        fixture_ref: SemanticId,
        candidate_generation_ref: SemanticId,
    },
    CompilerForwardPrediction {
        prediction: CompilerForwardPrediction,
    },
    CompilerRearCheck {
        rear_check: CompilerRearCheck,
        invalidated_refs: BTreeSet<SemanticId>,
    },
    CompilerFixtureChecked {
        fixture_ref: SemanticId,
        compiler_generation_ref: SemanticId,
        observer_join_ref: SemanticId,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDisposition {
    Accepted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReceipt {
    pub operation_id: SemanticId,
    pub caller_id: SemanticId,
    pub operation_kind: RuntimeOperationKind,
    pub before_digest: ContentDigest,
    pub after_digest: ContentDigest,
    pub logical_tick: u64,
    pub emitted_identities: BTreeSet<SemanticId>,
    pub trace_event: RuntimeTraceEvent,
    pub applied_limits: OperationLimits,
    pub disposition: RuntimeDisposition,
    pub output: RuntimeOutput,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeFaultKind {
    InvalidForm,
    UnsupportedVersion,
    StalePredecessor,
    MissingReference,
    DuplicateIdentity,
    Cycle,
    BoundExhausted,
    RecurrenceHorizon,
    WakeMismatch,
    IllegalTransition,
    InvalidReentry,
    WrongGeneration,
    IncompleteDiff,
    MissingCorrespondence,
    ForbiddenEffect,
    Nondeterminism,
    InternalInvariant,
    MachineForm,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeFault {
    pub kind: RuntimeFaultKind,
    pub operation_id: SemanticId,
    pub subject_refs: BTreeSet<SemanticId>,
    pub expected: String,
    pub observed: String,
    pub evidence: BTreeSet<String>,
    pub safe_residual: String,
    pub trace_location: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeEvaluation {
    Accepted {
        successor: Box<RuntimeSnapshot>,
        receipt: Box<RuntimeReceipt>,
    },
    Refused {
        fault: RuntimeFault,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReplay {
    pub final_snapshot: RuntimeSnapshot,
    pub receipts: Vec<RuntimeReceipt>,
}
