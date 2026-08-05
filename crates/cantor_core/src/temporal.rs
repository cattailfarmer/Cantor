//! Pure machine forms for the CTPR temporal-planning and change-reflection ABI.
//!
//! This module owns data, normalization, and validation only. It performs no
//! clock reads, persistence, scheduling, concurrency, provider calls, or effects.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{ContentDigest, EvaluationFault, FaultKind, SemanticId};

pub const CTPR_FORM_VERSION: &str = "cantor-ctpr/0.1";
const MAX_FORM_RECORDS: usize = 16_384;
const MAX_TEXT_BYTES: usize = 16_384;

macro_rules! closed_enum {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }
    };
}

closed_enum!(SensitivityClass {
    Public,
    ProjectInternal,
    Personal,
    Confidential,
    Secret,
    Credential,
    Regulated,
    UnknownSensitive,
});

closed_enum!(RepositoryStatus {
    Candidate,
    Admitted,
    Superseded,
    Revoked,
    Quarantined,
    Archived,
});

closed_enum!(ObjectiveStatus {
    Proposed,
    Eligible,
    Selected,
    Active,
    Satisfied,
    Blocked,
    Rejected,
    Superseded,
});

closed_enum!(DependencyKind {
    Objective,
    Artifact,
    Temporal,
    Authority,
    Resource,
    Evidence,
    Review,
});

closed_enum!(ConstraintSeverity {
    Advisory,
    Required,
    Blocking,
});

closed_enum!(PlanState {
    Proposed,
    Eligible,
    Admitted,
    Active,
    Completed,
    Rejected,
    Invalidated,
    Superseded,
});

closed_enum!(TimeDomain {
    Civil,
    Instant,
    Monotonic,
    Logical,
    Valid,
    Transaction,
    Uncertain,
});

closed_enum!(CalendarKind {
    Task,
    Block,
    Appointment,
    Deadline,
    Reminder,
    Wake,
    Recurrence,
    Review,
});

closed_enum!(AuthorityState {
    Proposed,
    Eligible,
    Granted,
    Denied,
    Revoked,
    Expired,
});

closed_enum!(CalendarLifecycleState {
    Proposed,
    Tentative,
    Accepted,
    Declined,
    Committed,
    Triggered,
    Active,
    Completed,
    Missed,
    Cancelled,
    Superseded,
});

closed_enum!(ProviderSyncState {
    LocalOnly,
    Pending,
    Synchronized,
    Divergent,
    Failed,
    Revoked,
});

closed_enum!(EventKind {
    Observation,
    Decision,
    SemanticTransition,
    ToolRequest,
    ToolResult,
    EffectRequest,
    EffectResult,
    Review,
    Calendar,
    Fault,
    Admission,
    Reentry,
    Compaction,
});

closed_enum!(MaterialityDisposition {
    Capture,
    Aggregate,
    Omit,
});

closed_enum!(DiffKind {
    Physical,
    Source,
    Semantic,
    Build,
    Behavioral,
    Effect,
    Proof,
    Calendar,
});

closed_enum!(CapsuleState {
    Opened,
    Prepared,
    ExecutionRequested,
    EffectObserved,
    ReflectionRequested,
    ReflectionReturned,
    Reconciled,
    Admitted,
    Rejected,
    Reverted,
    Compensated,
    Unresolved,
});

closed_enum!(LaneKind {
    Prospective,
    Execution,
    Retrospective,
    ObserverJoin,
});

closed_enum!(LaneState {
    Idle,
    Prepared,
    Running,
    Returned,
    Released,
    BlockedOnAuthority,
    BlockedOnReflection,
    Stale,
    Invalidated,
    TimedOut,
    Cancelled,
    Failed,
});

closed_enum!(WorkPacketKind {
    Prospective,
    Execution,
});

closed_enum!(ReflectionDisposition {
    NoChange,
    Accept,
    Qualify,
    Repair,
    Reject,
    Block,
    Unresolved,
});

closed_enum!(JoinDisposition {
    Admit,
    Qualify,
    Repair,
    Branch,
    Revert,
    Compensate,
    Reject,
    Block,
    Unresolved,
});

closed_enum!(BarrierState {
    Closed,
    Open,
    Invalidated,
    Expired,
});

closed_enum!(CompilerStage {
    SourcePinned,
    Parsed,
    Resolved,
    Lowered,
    Projected,
    SourceDiffed,
    SemanticDiffed,
    ImpactAnalyzed,
    CorrespondenceChecked,
    ProofChecked,
    Admitted,
    Rejected,
    Invalidated,
});

closed_enum!(LessonReviewState {
    Proposed,
    UnderReview,
    Accepted,
    Rejected,
    Invalidated,
    Superseded,
});

closed_enum!(TrainingAdmissionState {
    Candidate,
    Eligible,
    Admitted,
    Rejected,
    Revoked,
});

closed_enum!(GitProjectionKind {
    File,
    Diff,
    Commit,
    Branch,
    Tag,
    Note,
});

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TimeValue {
    Point { value: String },
    Interval { start: String, end: String },
    Duration { magnitude: u64, unit: String },
    Set { members: BTreeSet<String> },
    PartialDate { value: String },
    SymbolicCondition { expression: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeExpression {
    pub time_expression_id: SemanticId,
    pub domain: TimeDomain,
    pub value: TimeValue,
    pub source_ref: SemanticId,
    pub zone: Option<String>,
    pub calendar_system: Option<String>,
    pub precision: String,
    pub uncertainty_interval: Option<String>,
    pub interpretation_policy_ref: Option<SemanticId>,
    pub conversion_evidence_refs: BTreeSet<SemanticId>,
    pub valid_from_ref: Option<SemanticId>,
    pub valid_to_ref: Option<SemanticId>,
    pub recorded_at_ref: Option<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskContract {
    pub task_id: SemanticId,
    pub purpose: String,
    pub source_ref: SemanticId,
    pub principal_refs: BTreeSet<SemanticId>,
    pub input_refs: BTreeSet<SemanticId>,
    pub target_refs: BTreeSet<SemanticId>,
    pub preconditions: BTreeSet<String>,
    pub assumptions: BTreeSet<String>,
    pub invariants: BTreeSet<String>,
    pub authority_request_refs: BTreeSet<SemanticId>,
    pub effect_boundary: BTreeSet<String>,
    pub completion_criteria: BTreeSet<String>,
    pub stop_conditions: BTreeSet<String>,
    pub privacy_profile_ref: SemanticId,
    pub retention_profile_ref: SemanticId,
    pub current_plan_revision_ref: Option<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveNode {
    pub objective_id: SemanticId,
    pub task_ref: SemanticId,
    pub statement: String,
    pub desired_state_criteria: BTreeSet<String>,
    pub priority_source_ref: SemanticId,
    pub uncertainty: BTreeSet<String>,
    pub status: ObjectiveStatus,
    pub proof_route: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyEdge {
    pub edge_id: SemanticId,
    pub predecessor_ref: SemanticId,
    pub successor_objective_ref: SemanticId,
    pub kind: DependencyKind,
    pub condition: String,
    pub strength: String,
    pub source_ref: SemanticId,
    pub invalidation_rule: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstraintNode {
    pub constraint_id: SemanticId,
    pub kind: String,
    pub scope_refs: BTreeSet<SemanticId>,
    pub expression: String,
    pub source_ref: SemanticId,
    pub severity: ConstraintSeverity,
    pub disposition_behavior: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlternativePath {
    pub alternative_id: SemanticId,
    pub objective_path: Vec<SemanticId>,
    pub prerequisite_refs: BTreeSet<SemanticId>,
    pub estimate_range: String,
    pub possible_effects: BTreeSet<String>,
    pub risks: BTreeSet<String>,
    pub review_gate_refs: BTreeSet<SemanticId>,
    pub fallback_ref: Option<SemanticId>,
    pub stop_conditions: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRevision {
    pub plan_id: SemanticId,
    pub revision_id: SemanticId,
    pub predecessor_revision_ref: Option<SemanticId>,
    pub task_ref: SemanticId,
    pub objective_refs: BTreeSet<SemanticId>,
    pub dependency_refs: BTreeSet<SemanticId>,
    pub temporal_refs: BTreeSet<SemanticId>,
    pub effect_refs: BTreeSet<SemanticId>,
    pub review_refs: BTreeSet<SemanticId>,
    pub selected_alternative_ref: Option<SemanticId>,
    pub assumptions: BTreeSet<String>,
    pub uncertainty: BTreeSet<String>,
    pub state: PlanState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleCandidate {
    pub schedule_id: SemanticId,
    pub plan_revision_ref: SemanticId,
    pub calendar_item_refs: BTreeSet<SemanticId>,
    pub source_refs: BTreeSet<SemanticId>,
    pub uncertainty: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commitment {
    pub commitment_id: SemanticId,
    pub schedule_ref: SemanticId,
    pub authority_grant_ref: SemanticId,
    pub committed_item_refs: BTreeSet<SemanticId>,
    pub source_ref: SemanticId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WakeCondition {
    pub wake_id: SemanticId,
    pub calendar_item_ref: SemanticId,
    pub condition: String,
    pub revalidation_requirements: BTreeSet<String>,
    pub source_ref: SemanticId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecurrenceRule {
    pub recurrence_id: SemanticId,
    pub revision_id: SemanticId,
    pub predecessor_revision_ref: Option<SemanticId>,
    pub frequency: String,
    pub interval: u32,
    pub zone: String,
    pub calendar_system: String,
    pub start_boundary_ref: SemanticId,
    pub end_boundary_ref: Option<SemanticId>,
    pub occurrence_limit: Option<u32>,
    pub inclusion_keys: BTreeSet<String>,
    pub exception_keys: BTreeSet<String>,
    pub materialization_horizon_ref: SemanticId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarItem {
    pub calendar_item_id: SemanticId,
    pub revision_id: SemanticId,
    pub predecessor_revision_ref: Option<SemanticId>,
    pub kind: CalendarKind,
    pub task_ref: Option<SemanticId>,
    pub purpose: String,
    pub source_ref: SemanticId,
    pub owner_refs: BTreeSet<SemanticId>,
    pub participant_refs: BTreeSet<SemanticId>,
    pub time_expression_refs: BTreeSet<SemanticId>,
    pub recurrence_rule_ref: Option<SemanticId>,
    pub dependency_refs: BTreeSet<SemanticId>,
    pub review_refs: BTreeSet<SemanticId>,
    pub authority_state: AuthorityState,
    pub lifecycle_state: CalendarLifecycleState,
    pub provider_sync_state: ProviderSyncState,
    pub field_sensitivity: BTreeMap<String, SensitivityClass>,
    pub disclosure_refs: BTreeSet<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterialityDecision {
    pub policy_ref: SemanticId,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub disposition: MaterialityDisposition,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterialityPolicy {
    pub policy_id: SemanticId,
    pub revision_id: SemanticId,
    pub predecessor_revision_ref: Option<SemanticId>,
    pub durable_event_kinds: BTreeSet<EventKind>,
    pub micro_event_purposes: BTreeSet<String>,
    pub aggregation_method: String,
    pub loss_policy: String,
    pub rehydration_policy: String,
    pub retention_profile_ref: SemanticId,
    pub applies_from_generation_ref: SemanticId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentObject {
    pub object_id: SemanticId,
    pub digest: ContentDigest,
    pub byte_length: u64,
    pub media_type: String,
    pub encoding: String,
    pub provenance_refs: BTreeSet<SemanticId>,
    pub sensitivity: SensitivityClass,
    pub retention_profile_ref: SemanticId,
    pub storage_locators: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterialEvent {
    pub event_id: SemanticId,
    pub repository_generation_input_ref: SemanticId,
    pub task_ref: Option<SemanticId>,
    pub attribution_ref: Option<SemanticId>,
    pub kind: EventKind,
    pub subject_refs: BTreeSet<SemanticId>,
    pub content_object_refs: BTreeSet<SemanticId>,
    pub valid_time_ref: Option<SemanticId>,
    pub transaction_time_ref: SemanticId,
    pub materiality: MaterialityDecision,
    pub authority_refs: BTreeSet<SemanticId>,
    pub effect_refs: BTreeSet<SemanticId>,
    pub predecessor_event_refs: BTreeSet<SemanticId>,
    pub retention_profile_ref: SemanticId,
    pub sensitivity: SensitivityClass,
    pub event_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticSnapshot {
    pub snapshot_id: SemanticId,
    pub repository_id: SemanticId,
    pub predecessor_snapshot_refs: BTreeSet<SemanticId>,
    pub event_frontier: BTreeSet<SemanticId>,
    pub canonical_state_root: ContentDigest,
    pub projection_manifest_ref: Option<SemanticId>,
    pub content_object_refs: BTreeSet<SemanticId>,
    pub reconciliation_evidence_refs: BTreeSet<SemanticId>,
    pub loss_records: BTreeSet<String>,
    pub atomic_external_world_claim: bool,
    pub snapshot_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryGeneration {
    pub repository_id: SemanticId,
    pub generation_id: SemanticId,
    pub predecessor_generation_refs: BTreeSet<SemanticId>,
    pub repository_policy_ref: SemanticId,
    pub event_frontier: BTreeSet<SemanticId>,
    pub snapshot_root_ref: Option<SemanticId>,
    pub reference_index_generation_ref: Option<SemanticId>,
    pub created_by_disposition_ref: Option<SemanticId>,
    pub root_digest: ContentDigest,
    pub status: RepositoryStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitProjection {
    pub projection_id: SemanticId,
    pub repository_generation_ref: SemanticId,
    pub kind: GitProjectionKind,
    pub selected_subject_refs: BTreeSet<SemanticId>,
    pub locator: String,
    pub projection_digest: ContentDigest,
    pub authoritative: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvalidationEdge {
    pub invalidation_id: SemanticId,
    pub cause_ref: SemanticId,
    pub source_generation_ref: SemanticId,
    pub affected_subject_ref: SemanticId,
    pub required_action: String,
    pub severity: ConstraintSeverity,
    pub resolution_ref: Option<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiffRecord {
    pub diff_id: SemanticId,
    pub kind: DiffKind,
    pub before_subject_ref: SemanticId,
    pub candidate_subject_ref: SemanticId,
    pub added_refs: BTreeSet<SemanticId>,
    pub changed_refs: BTreeSet<SemanticId>,
    pub removed_refs: BTreeSet<SemanticId>,
    pub preserved_refs: BTreeSet<SemanticId>,
    pub unrelated_refs: BTreeSet<SemanticId>,
    pub derivation_method: String,
    pub independent_evidence_refs: BTreeSet<SemanticId>,
    pub confidence_or_completeness: String,
    pub invalidations: BTreeMap<SemanticId, InvalidationEdge>,
    pub loss_and_unknown: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredIntent {
    pub intent_id: SemanticId,
    pub target_refs: BTreeSet<SemanticId>,
    pub expected_transformations: BTreeSet<String>,
    pub allowed_effects: BTreeSet<String>,
    pub completion_evidence: BTreeSet<String>,
    pub unrelated_state_exclusions: BTreeSet<SemanticId>,
    pub source_ref: SemanticId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeCapsule {
    pub change_id: SemanticId,
    pub candidate_generation_id: SemanticId,
    pub task_ref: SemanticId,
    pub plan_revision_ref: SemanticId,
    pub repository_generation_ref: SemanticId,
    pub before_snapshot_ref: SemanticId,
    pub declared_intent_ref: SemanticId,
    pub prepared_candidate_ref: Option<SemanticId>,
    pub execution_request_ref: Option<SemanticId>,
    pub execution_outcome_ref: Option<SemanticId>,
    pub candidate_snapshot_ref: Option<SemanticId>,
    pub diff_refs: BTreeMap<DiffKind, SemanticId>,
    pub justification_delta: BTreeSet<String>,
    pub support_delta: BTreeSet<String>,
    pub requirement_delta: BTreeSet<String>,
    pub compiler_impact_ref: Option<SemanticId>,
    pub reflection_return_ref: Option<SemanticId>,
    pub reflection_exception_ref: Option<SemanticId>,
    pub observer_join_ref: Option<SemanticId>,
    pub after_snapshot_ref: Option<SemanticId>,
    pub state: CapsuleState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneCursor {
    pub cursor_id: SemanticId,
    pub kind: LaneKind,
    pub task_ref: SemanticId,
    pub input_repository_generation_ref: SemanticId,
    pub plan_revision_ref: SemanticId,
    pub capsule_generation_ref: SemanticId,
    pub dependency_refs: BTreeSet<SemanticId>,
    pub authority_request_ref: Option<SemanticId>,
    pub state: LaneState,
    pub lease_ref: Option<SemanticId>,
    pub timeout_ref: Option<SemanticId>,
    pub last_message_ref: Option<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneMessage {
    pub message_id: SemanticId,
    pub sender_cursor_ref: SemanticId,
    pub receiver_cursor_ref: SemanticId,
    pub subject_version_ref: SemanticId,
    pub payload_refs: BTreeSet<SemanticId>,
    pub required_acknowledgment: bool,
    pub causal_predecessor_refs: BTreeSet<SemanticId>,
    pub created_logical_time_ref: SemanticId,
    pub expiry_condition: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkPacket {
    pub packet_id: SemanticId,
    pub kind: WorkPacketKind,
    pub task_ref: SemanticId,
    pub input_repository_generation_ref: SemanticId,
    pub capsule_generation_ref: SemanticId,
    pub permitted_output_kinds: BTreeSet<String>,
    pub authority_boundary: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReflectionReturn {
    pub return_id: SemanticId,
    pub retrospective_cursor_ref: SemanticId,
    pub capsule_generation_ref: SemanticId,
    pub disposition: ReflectionDisposition,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub objections: BTreeSet<String>,
    pub uncertainty: BTreeSet<String>,
    pub invalidation_refs: BTreeSet<SemanticId>,
    pub residuals: BTreeSet<String>,
    pub signature_ref: Option<SemanticId>,
    pub provider_qualification: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverJoin {
    pub join_id: SemanticId,
    pub capsule_generation_ref: SemanticId,
    pub expected_lane_return_refs: BTreeSet<SemanticId>,
    pub expected_subject_version_refs: BTreeSet<SemanticId>,
    pub received_return_refs: BTreeSet<SemanticId>,
    pub stale_check_refs: BTreeSet<SemanticId>,
    pub reconciliation_record_ref: SemanticId,
    pub disposition: JoinDisposition,
    pub successor_repository_generation_ref: Option<SemanticId>,
    pub release_refs: BTreeSet<SemanticId>,
    pub residuals: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBarrier {
    pub barrier_id: SemanticId,
    pub capsule_generation_ref: SemanticId,
    pub required_return_refs: BTreeSet<SemanticId>,
    pub dependent_refs: BTreeSet<SemanticId>,
    pub observer_join_ref: Option<SemanticId>,
    pub released_refs: BTreeSet<SemanticId>,
    pub state: BarrierState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedLagPolicy {
    pub policy_id: SemanticId,
    pub eligible_transition_kinds: BTreeSet<String>,
    pub maximum_transition_count: Option<u32>,
    pub maximum_duration_ref: Option<SemanticId>,
    pub consequence_bound: String,
    pub rollback_capacity: String,
    pub overdue_behavior: String,
    pub authority_ref: SemanticId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerGeneration {
    pub compiler_generation_id: SemanticId,
    pub predecessor_generation_refs: BTreeSet<SemanticId>,
    pub source_generation_refs: BTreeSet<SemanticId>,
    pub dependency_lock_ref: SemanticId,
    pub language_profile_ref: SemanticId,
    pub compiler_identity_ref: SemanticId,
    pub semantic_ir_root: ContentDigest,
    pub target_profile_refs: BTreeSet<SemanticId>,
    pub target_artifact_refs: BTreeSet<SemanticId>,
    pub correspondence_evidence_refs: BTreeSet<SemanticId>,
    pub independent_correspondence_evidence_refs: BTreeSet<SemanticId>,
    pub loss_records: BTreeSet<String>,
    pub diagnostics: BTreeSet<String>,
    pub proof_bundle_ref: SemanticId,
    pub stage: CompilerStage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerImpact {
    pub impact_id: SemanticId,
    pub compiler_generation_ref: SemanticId,
    pub changed_source_refs: BTreeSet<SemanticId>,
    pub changed_semantic_refs: BTreeSet<SemanticId>,
    pub invalidated_ir_refs: BTreeSet<SemanticId>,
    pub invalidated_index_refs: BTreeSet<SemanticId>,
    pub invalidated_package_refs: BTreeSet<SemanticId>,
    pub invalidated_schedule_refs: BTreeSet<SemanticId>,
    pub invalidated_workflow_refs: BTreeSet<SemanticId>,
    pub invalidated_model_refs: BTreeSet<SemanticId>,
    pub invalidated_tool_schema_refs: BTreeSet<SemanticId>,
    pub invalidated_hardware_refs: BTreeSet<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForecastError {
    pub forecast_error_id: SemanticId,
    pub preserved_forecast_ref: SemanticId,
    pub actual_observation_refs: BTreeSet<SemanticId>,
    pub comparison_method: String,
    pub uncertainty: BTreeSet<String>,
    pub affected_planning_fields: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanDeviation {
    pub deviation_id: SemanticId,
    pub plan_revision_ref: SemanticId,
    pub actual_sequence_refs: Vec<SemanticId>,
    pub deviation_classes: BTreeSet<String>,
    pub reasons: BTreeSet<String>,
    pub effect_refs: BTreeSet<SemanticId>,
    pub review_ref: SemanticId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticSurprise {
    pub surprise_id: SemanticId,
    pub exposed_subject_ref: SemanticId,
    pub meaning: String,
    pub dependency_refs: BTreeSet<SemanticId>,
    pub boundary_refs: BTreeSet<SemanticId>,
    pub source_refs: BTreeSet<SemanticId>,
    pub contradiction_check_refs: BTreeSet<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LessonCandidate {
    pub lesson_id: SemanticId,
    pub contributing_capsule_refs: BTreeSet<SemanticId>,
    pub proposal: String,
    pub eligible_scope: BTreeSet<String>,
    pub counterexamples: BTreeSet<String>,
    pub confidence: String,
    pub review_state: LessonReviewState,
    pub invalidation_refs: BTreeSet<SemanticId>,
    pub rollback: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingExampleCandidate {
    pub training_example_id: SemanticId,
    pub lesson_candidate_ref: SemanticId,
    pub redacted_source_projection_ref: SemanticId,
    pub consent_policy_ref: SemanticId,
    pub sensitivity_policy_ref: SemanticId,
    pub label_provenance_refs: BTreeSet<SemanticId>,
    pub evaluation_split: String,
    pub admission_state: TrainingAdmissionState,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalFormSet {
    pub form_version: String,
    pub time_expressions: BTreeMap<SemanticId, TimeExpression>,
    pub task_contracts: BTreeMap<SemanticId, TaskContract>,
    pub objectives: BTreeMap<SemanticId, ObjectiveNode>,
    pub dependencies: BTreeMap<SemanticId, DependencyEdge>,
    pub constraints: BTreeMap<SemanticId, ConstraintNode>,
    pub alternatives: BTreeMap<SemanticId, AlternativePath>,
    pub plan_revisions: BTreeMap<SemanticId, PlanRevision>,
    pub schedules: BTreeMap<SemanticId, ScheduleCandidate>,
    pub commitments: BTreeMap<SemanticId, Commitment>,
    pub wake_conditions: BTreeMap<SemanticId, WakeCondition>,
    pub recurrence_rules: BTreeMap<SemanticId, RecurrenceRule>,
    pub calendar_items: BTreeMap<SemanticId, CalendarItem>,
    pub materiality_policies: BTreeMap<SemanticId, MaterialityPolicy>,
    pub content_objects: BTreeMap<SemanticId, ContentObject>,
    pub material_events: BTreeMap<SemanticId, MaterialEvent>,
    pub snapshots: BTreeMap<SemanticId, SemanticSnapshot>,
    pub repository_generations: BTreeMap<SemanticId, RepositoryGeneration>,
    pub git_projections: BTreeMap<SemanticId, GitProjection>,
    pub declared_intents: BTreeMap<SemanticId, DeclaredIntent>,
    pub diffs: BTreeMap<SemanticId, DiffRecord>,
    pub capsules: BTreeMap<SemanticId, ChangeCapsule>,
    pub lane_cursors: BTreeMap<SemanticId, LaneCursor>,
    pub lane_messages: BTreeMap<SemanticId, LaneMessage>,
    pub work_packets: BTreeMap<SemanticId, WorkPacket>,
    pub reflection_returns: BTreeMap<SemanticId, ReflectionReturn>,
    pub observer_joins: BTreeMap<SemanticId, ObserverJoin>,
    pub release_barriers: BTreeMap<SemanticId, ReleaseBarrier>,
    pub bounded_lag_policies: BTreeMap<SemanticId, BoundedLagPolicy>,
    pub compiler_generations: BTreeMap<SemanticId, CompilerGeneration>,
    pub compiler_impacts: BTreeMap<SemanticId, CompilerImpact>,
    pub forecast_errors: BTreeMap<SemanticId, ForecastError>,
    pub plan_deviations: BTreeMap<SemanticId, PlanDeviation>,
    pub semantic_surprises: BTreeMap<SemanticId, SemanticSurprise>,
    pub lesson_candidates: BTreeMap<SemanticId, LessonCandidate>,
    pub training_example_candidates: BTreeMap<SemanticId, TrainingExampleCandidate>,
}

impl TemporalFormSet {
    pub fn new() -> Self {
        Self {
            form_version: CTPR_FORM_VERSION.to_owned(),
            ..Self::default()
        }
    }

    pub fn validate(&self) -> Result<(), EvaluationFault> {
        if self.form_version != CTPR_FORM_VERSION {
            return Err(form_fault(format!(
                "unsupported CTPR form version: {:?}",
                self.form_version
            )));
        }
        if self.record_count() > MAX_FORM_RECORDS {
            return Err(form_fault(format!(
                "CTPR form set exceeds {MAX_FORM_RECORDS} records"
            )));
        }

        validate_map(
            "time_expression",
            &self.time_expressions,
            |v| &v.time_expression_id,
            validate_time,
        )?;
        validate_map(
            "task_contract",
            &self.task_contracts,
            |v| &v.task_id,
            validate_task,
        )?;
        validate_map(
            "objective",
            &self.objectives,
            |v| &v.objective_id,
            validate_objective,
        )?;
        validate_map(
            "dependency",
            &self.dependencies,
            |v| &v.edge_id,
            validate_dependency,
        )?;
        validate_map(
            "constraint",
            &self.constraints,
            |v| &v.constraint_id,
            validate_constraint,
        )?;
        validate_map(
            "alternative",
            &self.alternatives,
            |v| &v.alternative_id,
            validate_alternative,
        )?;
        validate_map(
            "plan_revision",
            &self.plan_revisions,
            |v| &v.revision_id,
            validate_plan,
        )?;
        validate_map(
            "schedule",
            &self.schedules,
            |v| &v.schedule_id,
            validate_schedule,
        )?;
        validate_map(
            "commitment",
            &self.commitments,
            |v| &v.commitment_id,
            validate_commitment,
        )?;
        validate_map(
            "wake_condition",
            &self.wake_conditions,
            |v| &v.wake_id,
            validate_wake,
        )?;
        validate_map(
            "recurrence_rule",
            &self.recurrence_rules,
            |v| &v.recurrence_id,
            validate_recurrence,
        )?;
        validate_map(
            "calendar_item",
            &self.calendar_items,
            |v| &v.revision_id,
            validate_calendar,
        )?;
        validate_map(
            "materiality_policy",
            &self.materiality_policies,
            |v| &v.revision_id,
            validate_materiality_policy,
        )?;
        validate_map(
            "content_object",
            &self.content_objects,
            |v| &v.object_id,
            validate_content,
        )?;
        validate_map(
            "material_event",
            &self.material_events,
            |v| &v.event_id,
            validate_event,
        )?;
        validate_map(
            "snapshot",
            &self.snapshots,
            |v| &v.snapshot_id,
            validate_snapshot,
        )?;
        validate_map(
            "repository_generation",
            &self.repository_generations,
            |v| &v.generation_id,
            validate_generation,
        )?;
        validate_map(
            "git_projection",
            &self.git_projections,
            |v| &v.projection_id,
            validate_git_projection,
        )?;
        validate_map(
            "declared_intent",
            &self.declared_intents,
            |v| &v.intent_id,
            validate_intent,
        )?;
        validate_map("diff", &self.diffs, |v| &v.diff_id, validate_diff)?;
        validate_map(
            "capsule",
            &self.capsules,
            |v| &v.candidate_generation_id,
            validate_capsule,
        )?;
        validate_map(
            "lane_cursor",
            &self.lane_cursors,
            |v| &v.cursor_id,
            validate_lane_cursor,
        )?;
        validate_map(
            "lane_message",
            &self.lane_messages,
            |v| &v.message_id,
            validate_lane_message,
        )?;
        validate_map(
            "work_packet",
            &self.work_packets,
            |v| &v.packet_id,
            validate_work_packet,
        )?;
        validate_map(
            "reflection_return",
            &self.reflection_returns,
            |v| &v.return_id,
            validate_reflection,
        )?;
        validate_map(
            "observer_join",
            &self.observer_joins,
            |v| &v.join_id,
            validate_join,
        )?;
        validate_map(
            "release_barrier",
            &self.release_barriers,
            |v| &v.barrier_id,
            validate_barrier,
        )?;
        validate_map(
            "bounded_lag_policy",
            &self.bounded_lag_policies,
            |v| &v.policy_id,
            validate_lag,
        )?;
        validate_map(
            "compiler_generation",
            &self.compiler_generations,
            |v| &v.compiler_generation_id,
            validate_compiler,
        )?;
        validate_map(
            "compiler_impact",
            &self.compiler_impacts,
            |v| &v.impact_id,
            validate_compiler_impact,
        )?;
        validate_map(
            "forecast_error",
            &self.forecast_errors,
            |v| &v.forecast_error_id,
            validate_forecast,
        )?;
        validate_map(
            "plan_deviation",
            &self.plan_deviations,
            |v| &v.deviation_id,
            validate_deviation,
        )?;
        validate_map(
            "semantic_surprise",
            &self.semantic_surprises,
            |v| &v.surprise_id,
            validate_surprise,
        )?;
        validate_map(
            "lesson_candidate",
            &self.lesson_candidates,
            |v| &v.lesson_id,
            validate_lesson,
        )?;
        validate_map(
            "training_example",
            &self.training_example_candidates,
            |v| &v.training_example_id,
            validate_training_example,
        )?;

        self.validate_relations()
    }

    fn record_count(&self) -> usize {
        [
            self.time_expressions.len(),
            self.task_contracts.len(),
            self.objectives.len(),
            self.dependencies.len(),
            self.constraints.len(),
            self.alternatives.len(),
            self.plan_revisions.len(),
            self.schedules.len(),
            self.commitments.len(),
            self.wake_conditions.len(),
            self.recurrence_rules.len(),
            self.calendar_items.len(),
            self.materiality_policies.len(),
            self.content_objects.len(),
            self.material_events.len(),
            self.snapshots.len(),
            self.repository_generations.len(),
            self.git_projections.len(),
            self.declared_intents.len(),
            self.diffs.len(),
            self.capsules.len(),
            self.lane_cursors.len(),
            self.lane_messages.len(),
            self.work_packets.len(),
            self.reflection_returns.len(),
            self.observer_joins.len(),
            self.release_barriers.len(),
            self.bounded_lag_policies.len(),
            self.compiler_generations.len(),
            self.compiler_impacts.len(),
            self.forecast_errors.len(),
            self.plan_deviations.len(),
            self.semantic_surprises.len(),
            self.lesson_candidates.len(),
            self.training_example_candidates.len(),
        ]
        .into_iter()
        .sum()
    }

    fn validate_relations(&self) -> Result<(), EvaluationFault> {
        for task in self.task_contracts.values() {
            if let Some(plan_ref) = &task.current_plan_revision_ref {
                require_present("task current plan", plan_ref, &self.plan_revisions)?;
            }
        }
        for plan in self.plan_revisions.values() {
            require_present("plan task", &plan.task_ref, &self.task_contracts)?;
            require_all_present("plan objective", &plan.objective_refs, &self.objectives)?;
            require_all_present("plan dependency", &plan.dependency_refs, &self.dependencies)?;
            if let Some(alternative_ref) = &plan.selected_alternative_ref {
                require_present("selected alternative", alternative_ref, &self.alternatives)?;
            }
        }
        for item in self.calendar_items.values() {
            if let Some(task_ref) = &item.task_ref {
                require_present("calendar task", task_ref, &self.task_contracts)?;
            }
            require_all_present(
                "calendar time",
                &item.time_expression_refs,
                &self.time_expressions,
            )?;
            if let Some(recurrence_ref) = &item.recurrence_rule_ref {
                require_present(
                    "calendar recurrence",
                    recurrence_ref,
                    &self.recurrence_rules,
                )?;
            }
        }
        for event in self.material_events.values() {
            require_present(
                "event generation",
                &event.repository_generation_input_ref,
                &self.repository_generations,
            )?;
            require_present(
                "event transaction time",
                &event.transaction_time_ref,
                &self.time_expressions,
            )?;
            if let Some(valid_time_ref) = &event.valid_time_ref {
                require_present("event valid time", valid_time_ref, &self.time_expressions)?;
            }
            require_all_present(
                "event content",
                &event.content_object_refs,
                &self.content_objects,
            )?;
        }
        for capsule in self.capsules.values() {
            require_present("capsule task", &capsule.task_ref, &self.task_contracts)?;
            require_present(
                "capsule plan",
                &capsule.plan_revision_ref,
                &self.plan_revisions,
            )?;
            require_present(
                "capsule generation",
                &capsule.repository_generation_ref,
                &self.repository_generations,
            )?;
            require_present(
                "capsule before snapshot",
                &capsule.before_snapshot_ref,
                &self.snapshots,
            )?;
            require_present(
                "capsule declared intent",
                &capsule.declared_intent_ref,
                &self.declared_intents,
            )?;
            for (kind, diff_ref) in &capsule.diff_refs {
                let diff = require_present("capsule diff", diff_ref, &self.diffs)?;
                if diff.kind != *kind {
                    return Err(form_fault(
                        "capsule diff kind does not match its typed slot",
                    ));
                }
            }
            if let Some(reflection_ref) = &capsule.reflection_return_ref {
                let reflection = require_present(
                    "capsule reflection",
                    reflection_ref,
                    &self.reflection_returns,
                )?;
                if reflection.capsule_generation_ref != capsule.candidate_generation_id {
                    return Err(form_fault(
                        "reflection return reviews a different capsule generation",
                    ));
                }
            }
            if let Some(join_ref) = &capsule.observer_join_ref {
                let join = require_present("capsule join", join_ref, &self.observer_joins)?;
                if join.capsule_generation_ref != capsule.candidate_generation_id {
                    return Err(form_fault(
                        "ObserverJoin reconciles a different capsule generation",
                    ));
                }
            }
        }
        for reflection in self.reflection_returns.values() {
            let cursor = require_present(
                "reflection cursor",
                &reflection.retrospective_cursor_ref,
                &self.lane_cursors,
            )?;
            if cursor.kind != LaneKind::Retrospective {
                return Err(form_fault("ReflectionReturn cursor is not retrospective"));
            }
            if cursor.capsule_generation_ref != reflection.capsule_generation_ref {
                return Err(form_fault(
                    "ReflectionReturn cursor has a different capsule generation",
                ));
            }
        }
        for message in self.lane_messages.values() {
            require_present(
                "message sender",
                &message.sender_cursor_ref,
                &self.lane_cursors,
            )?;
            require_present(
                "message receiver",
                &message.receiver_cursor_ref,
                &self.lane_cursors,
            )?;
            let time = require_present(
                "message logical time",
                &message.created_logical_time_ref,
                &self.time_expressions,
            )?;
            if time.domain != TimeDomain::Logical {
                return Err(form_fault(
                    "LaneMessage created time is not in the logical domain",
                ));
            }
        }
        Ok(())
    }
}

pub fn to_normalized_temporal_form(value: &TemporalFormSet) -> Result<String, EvaluationFault> {
    value.validate()?;
    serde_json::to_string(value).map_err(|error| {
        EvaluationFault::new(
            FaultKind::MachineForm,
            format!("CTPR machine-form serialization failed: {error}"),
        )
    })
}

pub fn from_normalized_temporal_form(value: &str) -> Result<TemporalFormSet, EvaluationFault> {
    let form: TemporalFormSet = serde_json::from_str(value).map_err(|error| {
        EvaluationFault::new(
            FaultKind::MachineForm,
            format!("CTPR machine-form restoration failed: {error}"),
        )
    })?;
    form.validate()?;
    let normalized = to_normalized_temporal_form(&form)?;
    if normalized != value {
        return Err(EvaluationFault::new(
            FaultKind::MachineForm,
            "CTPR machine form is valid JSON but not normalized",
        ));
    }
    Ok(form)
}

pub fn validate_capsule_transition(
    from: CapsuleState,
    to: CapsuleState,
) -> Result<(), EvaluationFault> {
    let valid = matches!(
        (from, to),
        (CapsuleState::Opened, CapsuleState::Prepared)
            | (CapsuleState::Opened, CapsuleState::Rejected)
            | (CapsuleState::Prepared, CapsuleState::ExecutionRequested)
            | (CapsuleState::Prepared, CapsuleState::ReflectionRequested)
            | (CapsuleState::Prepared, CapsuleState::Rejected)
            | (
                CapsuleState::ExecutionRequested,
                CapsuleState::EffectObserved
            )
            | (
                CapsuleState::ExecutionRequested,
                CapsuleState::ReflectionRequested
            )
            | (
                CapsuleState::EffectObserved,
                CapsuleState::ReflectionRequested
            )
            | (
                CapsuleState::ReflectionRequested,
                CapsuleState::ReflectionReturned
            )
            | (CapsuleState::ReflectionRequested, CapsuleState::Unresolved)
            | (CapsuleState::ReflectionReturned, CapsuleState::Reconciled)
            | (CapsuleState::ReflectionReturned, CapsuleState::Unresolved)
            | (CapsuleState::Reconciled, CapsuleState::Admitted)
            | (CapsuleState::Reconciled, CapsuleState::Rejected)
            | (CapsuleState::Reconciled, CapsuleState::Reverted)
            | (CapsuleState::Reconciled, CapsuleState::Compensated)
            | (CapsuleState::Unresolved, CapsuleState::ReflectionRequested)
            | (CapsuleState::Unresolved, CapsuleState::Rejected)
    );
    if valid {
        Ok(())
    } else {
        Err(form_fault(format!(
            "illegal capsule transition: {from:?} -> {to:?}"
        )))
    }
}

pub fn validate_lane_transition(from: LaneState, to: LaneState) -> Result<(), EvaluationFault> {
    let terminal = matches!(
        to,
        LaneState::Stale
            | LaneState::Invalidated
            | LaneState::TimedOut
            | LaneState::Cancelled
            | LaneState::Failed
    );
    let valid = terminal
        && matches!(
            from,
            LaneState::Prepared
                | LaneState::Running
                | LaneState::BlockedOnAuthority
                | LaneState::BlockedOnReflection
        )
        || matches!(
            (from, to),
            (LaneState::Idle, LaneState::Prepared)
                | (LaneState::Prepared, LaneState::Running)
                | (LaneState::Prepared, LaneState::BlockedOnAuthority)
                | (LaneState::Prepared, LaneState::BlockedOnReflection)
                | (LaneState::BlockedOnAuthority, LaneState::Prepared)
                | (LaneState::BlockedOnReflection, LaneState::Prepared)
                | (LaneState::Running, LaneState::Returned)
                | (LaneState::Returned, LaneState::Released)
        );
    if valid {
        Ok(())
    } else {
        Err(form_fault(format!(
            "illegal lane transition: {from:?} -> {to:?}"
        )))
    }
}

fn validate_time(value: &TimeExpression) -> Result<(), EvaluationFault> {
    require_text("time precision", &value.precision)?;
    match &value.value {
        TimeValue::Point { value } | TimeValue::PartialDate { value } => {
            require_text("time value", value)?
        }
        TimeValue::Interval { start, end } => {
            require_text("interval start", start)?;
            require_text("interval end", end)?;
            if start == end {
                return Err(form_fault("time interval start and end are equal"));
            }
        }
        TimeValue::Duration { magnitude, unit } => {
            if *magnitude == 0 {
                return Err(form_fault("time duration magnitude is zero"));
            }
            require_text("time duration unit", unit)?;
        }
        TimeValue::Set { members } => require_nonempty("time set", members)?,
        TimeValue::SymbolicCondition { expression } => require_text("time condition", expression)?,
    }
    if value.domain == TimeDomain::Civil {
        require_optional_text("civil time zone", &value.zone)?;
        require_optional_text("civil calendar system", &value.calendar_system)?;
    } else if value.zone.is_some() || value.calendar_system.is_some() {
        return Err(form_fault(
            "zone and calendar system are valid only for civil time",
        ));
    }
    if value.domain == TimeDomain::Uncertain && value.uncertainty_interval.is_none() {
        return Err(form_fault("uncertain time lacks an uncertainty interval"));
    }
    if value.valid_from_ref == value.valid_to_ref && value.valid_from_ref.is_some() {
        return Err(form_fault(
            "valid-from and valid-to time references are equal",
        ));
    }
    Ok(())
}

fn validate_task(value: &TaskContract) -> Result<(), EvaluationFault> {
    require_text("task purpose", &value.purpose)?;
    require_nonempty("task principals", &value.principal_refs)?;
    require_nonempty("task targets", &value.target_refs)?;
    require_nonempty("task invariants", &value.invariants)?;
    require_nonempty("task completion criteria", &value.completion_criteria)
}

fn validate_objective(value: &ObjectiveNode) -> Result<(), EvaluationFault> {
    require_text("objective statement", &value.statement)?;
    require_nonempty(
        "objective desired-state criteria",
        &value.desired_state_criteria,
    )?;
    require_nonempty("objective proof route", &value.proof_route)
}

fn validate_dependency(value: &DependencyEdge) -> Result<(), EvaluationFault> {
    if value.predecessor_ref == value.successor_objective_ref {
        return Err(form_fault("dependency edge is self-referential"));
    }
    require_text("dependency condition", &value.condition)?;
    require_text("dependency strength", &value.strength)?;
    require_text("dependency invalidation rule", &value.invalidation_rule)
}

fn validate_constraint(value: &ConstraintNode) -> Result<(), EvaluationFault> {
    require_text("constraint kind", &value.kind)?;
    require_nonempty("constraint scope", &value.scope_refs)?;
    require_text("constraint expression", &value.expression)?;
    require_text(
        "constraint disposition behavior",
        &value.disposition_behavior,
    )
}

fn validate_alternative(value: &AlternativePath) -> Result<(), EvaluationFault> {
    require_nonempty_vec("alternative objective path", &value.objective_path)?;
    require_text("alternative estimate range", &value.estimate_range)?;
    require_nonempty("alternative stop conditions", &value.stop_conditions)
}

fn validate_plan(value: &PlanRevision) -> Result<(), EvaluationFault> {
    require_nonempty("plan objectives", &value.objective_refs)?;
    if value.predecessor_revision_ref.as_ref() == Some(&value.revision_id) {
        return Err(form_fault("plan revision names itself as predecessor"));
    }
    Ok(())
}

fn validate_schedule(value: &ScheduleCandidate) -> Result<(), EvaluationFault> {
    require_nonempty("schedule calendar items", &value.calendar_item_refs)?;
    require_nonempty("schedule sources", &value.source_refs)
}

fn validate_commitment(value: &Commitment) -> Result<(), EvaluationFault> {
    require_nonempty("committed items", &value.committed_item_refs)
}

fn validate_wake(value: &WakeCondition) -> Result<(), EvaluationFault> {
    require_text("wake condition", &value.condition)?;
    require_nonempty(
        "wake revalidation requirements",
        &value.revalidation_requirements,
    )
}

fn validate_recurrence(value: &RecurrenceRule) -> Result<(), EvaluationFault> {
    require_text("recurrence frequency", &value.frequency)?;
    require_text("recurrence zone", &value.zone)?;
    require_text("recurrence calendar system", &value.calendar_system)?;
    if value.interval == 0 {
        return Err(form_fault("recurrence interval is zero"));
    }
    if value.end_boundary_ref.is_none() && value.occurrence_limit.is_none() {
        return Err(form_fault(
            "recurrence lacks an end boundary or occurrence limit",
        ));
    }
    if value.occurrence_limit == Some(0) {
        return Err(form_fault("recurrence occurrence limit is zero"));
    }
    if value.predecessor_revision_ref.as_ref() == Some(&value.revision_id) {
        return Err(form_fault(
            "recurrence revision names itself as predecessor",
        ));
    }
    Ok(())
}

fn validate_calendar(value: &CalendarItem) -> Result<(), EvaluationFault> {
    require_text("calendar purpose", &value.purpose)?;
    require_nonempty("calendar owners", &value.owner_refs)?;
    require_nonempty("calendar time expressions", &value.time_expression_refs)?;
    if value.kind == CalendarKind::Task && value.task_ref.is_none() {
        return Err(form_fault("task calendar item lacks a task reference"));
    }
    if value.predecessor_revision_ref.as_ref() == Some(&value.revision_id) {
        return Err(form_fault("calendar revision names itself as predecessor"));
    }
    Ok(())
}

fn validate_materiality_policy(value: &MaterialityPolicy) -> Result<(), EvaluationFault> {
    require_nonempty("durable event kinds", &value.durable_event_kinds)?;
    require_text("aggregation method", &value.aggregation_method)?;
    require_text("loss policy", &value.loss_policy)?;
    require_text("rehydration policy", &value.rehydration_policy)
}

fn validate_content(value: &ContentObject) -> Result<(), EvaluationFault> {
    if value.byte_length == 0 {
        return Err(form_fault("content object has zero byte length"));
    }
    validate_digest("content digest", &value.digest)?;
    require_text("content media type", &value.media_type)?;
    require_text("content encoding", &value.encoding)?;
    require_nonempty("content provenance", &value.provenance_refs)
}

fn validate_event(value: &MaterialEvent) -> Result<(), EvaluationFault> {
    require_nonempty("event subjects", &value.subject_refs)?;
    if value.task_ref.is_some() != value.attribution_ref.is_some() {
        return Err(form_fault(
            "work-attributed event requires both task and attribution references",
        ));
    }
    require_text("materiality reason", &value.materiality.reason)?;
    validate_digest("event digest", &value.event_digest)
}

fn validate_snapshot(value: &SemanticSnapshot) -> Result<(), EvaluationFault> {
    if value.atomic_external_world_claim {
        return Err(form_fault(
            "semantic snapshot claims atomic external-world state",
        ));
    }
    require_nonempty("snapshot event frontier", &value.event_frontier)?;
    validate_digest("snapshot state root", &value.canonical_state_root)?;
    validate_digest("snapshot digest", &value.snapshot_digest)
}

fn validate_generation(value: &RepositoryGeneration) -> Result<(), EvaluationFault> {
    validate_digest("repository generation root", &value.root_digest)?;
    if value.status == RepositoryStatus::Admitted && value.created_by_disposition_ref.is_none() {
        return Err(form_fault(
            "admitted repository generation lacks Observer disposition",
        ));
    }
    Ok(())
}

fn validate_git_projection(value: &GitProjection) -> Result<(), EvaluationFault> {
    require_text("Git projection locator", &value.locator)?;
    validate_digest("Git projection digest", &value.projection_digest)?;
    if value.authoritative {
        return Err(form_fault("Git projection cannot be authoritative"));
    }
    Ok(())
}

fn validate_intent(value: &DeclaredIntent) -> Result<(), EvaluationFault> {
    require_nonempty("intent targets", &value.target_refs)?;
    require_nonempty("expected transformations", &value.expected_transformations)?;
    require_nonempty("completion evidence", &value.completion_evidence)
}

fn validate_diff(value: &DiffRecord) -> Result<(), EvaluationFault> {
    if value.before_subject_ref == value.candidate_subject_ref {
        return Err(form_fault("diff before and candidate subjects are equal"));
    }
    require_text("diff derivation method", &value.derivation_method)?;
    require_text(
        "diff confidence or completeness",
        &value.confidence_or_completeness,
    )?;
    for (key, edge) in &value.invalidations {
        if key != &edge.invalidation_id {
            return Err(form_fault(
                "invalidation map key differs from record identity",
            ));
        }
    }
    Ok(())
}

fn validate_capsule(value: &ChangeCapsule) -> Result<(), EvaluationFault> {
    let post_reflection = matches!(
        value.state,
        CapsuleState::ReflectionReturned
            | CapsuleState::Reconciled
            | CapsuleState::Admitted
            | CapsuleState::Rejected
            | CapsuleState::Reverted
            | CapsuleState::Compensated
    );
    if post_reflection
        && value.reflection_return_ref.is_none()
        && value.reflection_exception_ref.is_none()
    {
        return Err(form_fault(
            "post-reflection capsule lacks a return or signed exception",
        ));
    }
    let post_reconciliation = matches!(
        value.state,
        CapsuleState::Reconciled
            | CapsuleState::Admitted
            | CapsuleState::Rejected
            | CapsuleState::Reverted
            | CapsuleState::Compensated
    );
    if post_reconciliation && value.observer_join_ref.is_none() {
        return Err(form_fault("reconciled capsule lacks an ObserverJoin"));
    }
    if value.state == CapsuleState::Admitted {
        if value.after_snapshot_ref.is_none() {
            return Err(form_fault("admitted capsule lacks an after snapshot"));
        }
        let required = BTreeSet::from([
            DiffKind::Physical,
            DiffKind::Source,
            DiffKind::Semantic,
            DiffKind::Build,
            DiffKind::Behavioral,
            DiffKind::Effect,
            DiffKind::Proof,
            DiffKind::Calendar,
        ]);
        if value.diff_refs.keys().copied().collect::<BTreeSet<_>>() != required {
            return Err(form_fault(
                "admitted capsule does not account for all eight diff kinds",
            ));
        }
    } else if value.after_snapshot_ref.is_some() {
        return Err(form_fault("non-admitted capsule has an after snapshot"));
    }
    Ok(())
}

fn validate_lane_cursor(value: &LaneCursor) -> Result<(), EvaluationFault> {
    if value.kind == LaneKind::Execution && value.authority_request_ref.is_none() {
        return Err(form_fault("execution lane lacks an authority request"));
    }
    Ok(())
}

fn validate_lane_message(value: &LaneMessage) -> Result<(), EvaluationFault> {
    if value.sender_cursor_ref == value.receiver_cursor_ref {
        return Err(form_fault("lane message sender and receiver are equal"));
    }
    require_nonempty("lane message payload", &value.payload_refs)?;
    require_text("lane message expiry condition", &value.expiry_condition)
}

fn validate_work_packet(value: &WorkPacket) -> Result<(), EvaluationFault> {
    require_nonempty("work packet output kinds", &value.permitted_output_kinds)?;
    require_nonempty("work packet authority boundary", &value.authority_boundary)
}

fn validate_reflection(value: &ReflectionReturn) -> Result<(), EvaluationFault> {
    if value.evidence_refs.is_empty()
        && value.objections.is_empty()
        && value.uncertainty.is_empty()
        && value.residuals.is_empty()
    {
        return Err(form_fault(
            "ReflectionReturn contains no evidence, objection, uncertainty, or residual",
        ));
    }
    if value.signature_ref.is_some() && value.provider_qualification.is_some() {
        return Err(form_fault(
            "ReflectionReturn cannot be both signed and provider-qualified",
        ));
    }
    Ok(())
}

fn validate_join(value: &ObserverJoin) -> Result<(), EvaluationFault> {
    if !value
        .received_return_refs
        .is_subset(&value.expected_lane_return_refs)
    {
        return Err(form_fault(
            "ObserverJoin received an unexpected lane return",
        ));
    }
    if value.disposition == JoinDisposition::Admit {
        if value.received_return_refs != value.expected_lane_return_refs {
            return Err(form_fault(
                "admitting ObserverJoin lacks an expected return",
            ));
        }
        if value.successor_repository_generation_ref.is_none() {
            return Err(form_fault(
                "admitting ObserverJoin lacks a successor generation",
            ));
        }
    } else if value.successor_repository_generation_ref.is_some() {
        return Err(form_fault(
            "non-admitting ObserverJoin names a successor generation",
        ));
    }
    Ok(())
}

fn validate_barrier(value: &ReleaseBarrier) -> Result<(), EvaluationFault> {
    require_nonempty("release barrier dependencies", &value.dependent_refs)?;
    if value.state == BarrierState::Open {
        if value.observer_join_ref.is_none() {
            return Err(form_fault("open release barrier lacks an ObserverJoin"));
        }
        if value.released_refs != value.dependent_refs {
            return Err(form_fault(
                "open release barrier does not release its exact dependent set",
            ));
        }
    } else if !value.released_refs.is_empty() {
        return Err(form_fault(
            "closed release barrier contains released subjects",
        ));
    }
    Ok(())
}

fn validate_lag(value: &BoundedLagPolicy) -> Result<(), EvaluationFault> {
    require_nonempty(
        "bounded-lag transition kinds",
        &value.eligible_transition_kinds,
    )?;
    if value.maximum_transition_count.is_none() && value.maximum_duration_ref.is_none() {
        return Err(form_fault(
            "bounded-lag policy has no count or duration bound",
        ));
    }
    if value.maximum_transition_count == Some(0) {
        return Err(form_fault("bounded-lag maximum transition count is zero"));
    }
    require_text("bounded-lag consequence bound", &value.consequence_bound)?;
    require_text("bounded-lag rollback capacity", &value.rollback_capacity)?;
    require_text("bounded-lag overdue behavior", &value.overdue_behavior)
}

fn validate_compiler(value: &CompilerGeneration) -> Result<(), EvaluationFault> {
    require_nonempty("compiler source generations", &value.source_generation_refs)?;
    require_nonempty("compiler target profiles", &value.target_profile_refs)?;
    validate_digest("compiler SemanticIR root", &value.semantic_ir_root)?;
    if matches!(
        value.stage,
        CompilerStage::CorrespondenceChecked
            | CompilerStage::ProofChecked
            | CompilerStage::Admitted
    ) && value.independent_correspondence_evidence_refs.is_empty()
    {
        return Err(form_fault(
            "checked compiler generation lacks independent correspondence evidence",
        ));
    }
    Ok(())
}

fn validate_compiler_impact(value: &CompilerImpact) -> Result<(), EvaluationFault> {
    if value.changed_source_refs.is_empty() && value.changed_semantic_refs.is_empty() {
        return Err(form_fault(
            "compiler impact has no changed source or semantic identity",
        ));
    }
    Ok(())
}

fn validate_forecast(value: &ForecastError) -> Result<(), EvaluationFault> {
    require_nonempty("forecast observations", &value.actual_observation_refs)?;
    require_text("forecast comparison method", &value.comparison_method)?;
    require_nonempty("affected planning fields", &value.affected_planning_fields)
}

fn validate_deviation(value: &PlanDeviation) -> Result<(), EvaluationFault> {
    require_nonempty_vec("actual plan sequence", &value.actual_sequence_refs)?;
    require_nonempty("deviation classes", &value.deviation_classes)?;
    require_nonempty("deviation reasons", &value.reasons)
}

fn validate_surprise(value: &SemanticSurprise) -> Result<(), EvaluationFault> {
    require_text("semantic surprise meaning", &value.meaning)?;
    require_nonempty("semantic surprise sources", &value.source_refs)?;
    require_nonempty(
        "semantic surprise contradiction checks",
        &value.contradiction_check_refs,
    )
}

fn validate_lesson(value: &LessonCandidate) -> Result<(), EvaluationFault> {
    require_nonempty("lesson capsules", &value.contributing_capsule_refs)?;
    require_text("lesson proposal", &value.proposal)?;
    require_nonempty("lesson eligible scope", &value.eligible_scope)?;
    require_text("lesson confidence", &value.confidence)?;
    require_text("lesson rollback", &value.rollback)
}

fn validate_training_example(value: &TrainingExampleCandidate) -> Result<(), EvaluationFault> {
    require_nonempty("training label provenance", &value.label_provenance_refs)?;
    require_text("training evaluation split", &value.evaluation_split)
}

fn validate_digest(field: &str, value: &ContentDigest) -> Result<(), EvaluationFault> {
    require_text(&format!("{field} algorithm"), &value.algorithm)?;
    require_text(&format!("{field} value"), &value.value)
}

fn validate_map<T, I, V>(
    name: &str,
    values: &BTreeMap<SemanticId, T>,
    identity: I,
    validate: V,
) -> Result<(), EvaluationFault>
where
    I: Fn(&T) -> &SemanticId,
    V: Fn(&T) -> Result<(), EvaluationFault>,
{
    for (key, value) in values {
        if key != identity(value) {
            return Err(form_fault(format!(
                "{name} map key differs from record identity"
            )));
        }
        validate(value)?;
    }
    Ok(())
}

fn require_present<'a, T>(
    field: &str,
    id: &SemanticId,
    values: &'a BTreeMap<SemanticId, T>,
) -> Result<&'a T, EvaluationFault> {
    values
        .get(id)
        .ok_or_else(|| form_fault(format!("{field} reference is absent: {id}")))
}

fn require_all_present<T>(
    field: &str,
    ids: &BTreeSet<SemanticId>,
    values: &BTreeMap<SemanticId, T>,
) -> Result<(), EvaluationFault> {
    for id in ids {
        require_present(field, id, values)?;
    }
    Ok(())
}

fn require_text(field: &str, value: &str) -> Result<(), EvaluationFault> {
    if value.trim().is_empty() {
        return Err(form_fault(format!("{field} is blank")));
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(form_fault(format!(
            "{field} exceeds {MAX_TEXT_BYTES} bytes"
        )));
    }
    Ok(())
}

fn require_optional_text(field: &str, value: &Option<String>) -> Result<(), EvaluationFault> {
    match value {
        Some(value) => require_text(field, value),
        None => Err(form_fault(format!("{field} is absent"))),
    }
}

fn require_nonempty<T>(field: &str, values: &BTreeSet<T>) -> Result<(), EvaluationFault> {
    if values.is_empty() {
        Err(form_fault(format!("{field} is empty")))
    } else {
        Ok(())
    }
}

fn require_nonempty_vec<T>(field: &str, values: &[T]) -> Result<(), EvaluationFault> {
    if values.is_empty() {
        Err(form_fault(format!("{field} is empty")))
    } else {
        Ok(())
    }
}

fn form_fault(message: impl Into<String>) -> EvaluationFault {
    EvaluationFault::new(FaultKind::ConstraintViolation, message)
}
