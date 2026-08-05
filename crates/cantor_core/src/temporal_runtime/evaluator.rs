// Runtime faults intentionally carry the complete fail-closed evidence contract.
// Keeping that value explicit is more important here than shrinking internal
// Result stack slots; the public evaluation union boxes its substantially larger
// accepted values.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::{
    CTPR_FORM_VERSION, ContentDigest, EvaluationFault, FaultKind, MaterialEvent,
    RepositoryGeneration, SemanticId, SemanticSnapshot, TemporalFormSet, sha256_bytes,
};

use super::compiler::{
    check_compiler_fixture, register_compiler_fixture, run_compiler_forward, run_compiler_rear,
    validate_compiler_runtime,
};
use super::planner::{
    evaluate_calendar_state, evaluate_wake, expand_recurrence, propose_plan, revise_calendar,
};
use super::repository::{classify_materiality, compare_and_append};
use super::tandem::{
    acknowledge_lane_message, append_lane_message, evaluate_release_barrier, open_tandem,
    reconcile_observer, reenter_lane, transition_capsule, transition_lane,
};
use super::types::*;

#[derive(Debug)]
pub(crate) struct TransitionResult {
    pub(crate) output: RuntimeOutput,
    pub(crate) emitted_identities: BTreeSet<SemanticId>,
}

impl RuntimeSnapshot {
    pub fn new(
        repository_id: SemanticId,
        clock_id: SemanticId,
        forms: TemporalFormSet,
        policies: RuntimePolicies,
        bounds: RuntimeBounds,
    ) -> Result<Self, EvaluationFault> {
        let root = DeterministicRuntimeRoot {
            runtime_profile: CDRA_RUNTIME_PROFILE.to_owned(),
            policies,
            bounds,
            logical_clock: LogicalClock { clock_id, tick: 0 },
            forms,
            repository: FakeRepositoryState {
                repository_id,
                current_generation_ref: None,
                branch_heads: BTreeMap::new(),
                content_bytes: BTreeMap::new(),
                index: RepositoryIndex::default(),
            },
            calendar: FakeCalendarState::default(),
            planner: DeterministicPlannerState::default(),
            tandem: TandemRuntimeState::default(),
            compiler: CompilerFixtureRuntimeState::default(),
            trace: Vec::new(),
        };
        Self::from_root(root)
    }

    pub fn from_root(root: DeterministicRuntimeRoot) -> Result<Self, EvaluationFault> {
        validate_root(&root)?;
        Ok(Self {
            root_digest: digest_serializable(&root)?,
            root,
        })
    }

    pub fn validate(&self) -> Result<(), EvaluationFault> {
        validate_root(&self.root)?;
        let observed = digest_serializable(&self.root)?;
        if observed != self.root_digest {
            return Err(EvaluationFault::new(
                FaultKind::MachineForm,
                "runtime snapshot root digest does not match its normalized root",
            ));
        }
        Ok(())
    }
}

pub fn to_normalized_runtime_snapshot(
    snapshot: &RuntimeSnapshot,
) -> Result<String, EvaluationFault> {
    snapshot.validate()?;
    serde_json::to_string(snapshot).map_err(|error| {
        EvaluationFault::new(
            FaultKind::MachineForm,
            format!("runtime snapshot serialization failed: {error}"),
        )
    })
}

pub fn from_normalized_runtime_snapshot(value: &str) -> Result<RuntimeSnapshot, EvaluationFault> {
    let snapshot: RuntimeSnapshot = serde_json::from_str(value).map_err(|error| {
        EvaluationFault::new(
            FaultKind::MachineForm,
            format!("runtime snapshot restoration failed: {error}"),
        )
    })?;
    snapshot.validate()?;
    if to_normalized_runtime_snapshot(&snapshot)? != value {
        return Err(EvaluationFault::new(
            FaultKind::MachineForm,
            "runtime snapshot is valid JSON but is not normalized",
        ));
    }
    Ok(snapshot)
}

pub fn evaluate_runtime(
    snapshot: &RuntimeSnapshot,
    operation: &RuntimeOperation,
) -> RuntimeEvaluation {
    let context = operation.context();
    let trace_location = snapshot.root.trace.len() as u64;

    if snapshot.root.runtime_profile != CDRA_RUNTIME_PROFILE
        || snapshot.root.forms.form_version != CTPR_FORM_VERSION
    {
        return refused(
            context,
            RuntimeFaultKind::UnsupportedVersion,
            BTreeSet::new(),
            format!("{CDRA_RUNTIME_PROFILE} with {CTPR_FORM_VERSION}"),
            format!(
                "{} with {}",
                snapshot.root.runtime_profile, snapshot.root.forms.form_version
            ),
            BTreeSet::from(["exact-version runtime profile".to_owned()]),
            trace_location,
        );
    }
    if let Err(error) = snapshot.validate() {
        return refused(
            context,
            RuntimeFaultKind::InvalidForm,
            BTreeSet::new(),
            "valid normalized runtime snapshot",
            error.to_string(),
            BTreeSet::new(),
            trace_location,
        );
    }
    if context.expected_root_digest != snapshot.root_digest {
        return refused(
            context,
            RuntimeFaultKind::StalePredecessor,
            BTreeSet::new(),
            digest_label(&snapshot.root_digest),
            digest_label(&context.expected_root_digest),
            BTreeSet::from(["compare-and-transition root check".to_owned()]),
            trace_location,
        );
    }
    if snapshot
        .root
        .trace
        .iter()
        .any(|event| event.operation_id == context.operation_id)
    {
        return refused(
            context,
            RuntimeFaultKind::DuplicateIdentity,
            BTreeSet::from([context.operation_id.clone()]),
            "operation identity not already admitted",
            "duplicate operation identity",
            BTreeSet::from(["runtime trace operation identity".to_owned()]),
            trace_location,
        );
    }
    if let Err(fault) = validate_operation_limits(snapshot, operation) {
        return RuntimeEvaluation::Refused { fault };
    }

    let mut successor_root = snapshot.root.clone();
    let transition = match apply_operation(&mut successor_root, operation) {
        Ok(result) => result,
        Err(fault) => return RuntimeEvaluation::Refused { fault },
    };
    if transition.emitted_identities.len() > context.limits.max_emitted_records {
        return refused(
            context,
            RuntimeFaultKind::BoundExhausted,
            transition.emitted_identities,
            format!(
                "at most {} emitted identities",
                context.limits.max_emitted_records
            ),
            "operation emission exceeded its declared bound",
            BTreeSet::from(["operation emission bound".to_owned()]),
            trace_location,
        );
    }

    if successor_root.trace.len() >= successor_root.bounds.max_trace_events {
        return refused(
            context,
            RuntimeFaultKind::BoundExhausted,
            BTreeSet::new(),
            format!(
                "fewer than {} trace events",
                successor_root.bounds.max_trace_events
            ),
            successor_root.trace.len().to_string(),
            BTreeSet::from(["runtime trace bound".to_owned()]),
            trace_location,
        );
    }

    let trace_event = RuntimeTraceEvent {
        trace_index: trace_location,
        operation_id: context.operation_id.clone(),
        operation_kind: operation.operation_kind(),
        logical_tick: successor_root.logical_clock.tick,
        emitted_identities: transition.emitted_identities.clone(),
    };
    successor_root.trace.push(trace_event.clone());

    let successor = match RuntimeSnapshot::from_root(successor_root) {
        Ok(value) => value,
        Err(error) => {
            return refused(
                context,
                RuntimeFaultKind::InternalInvariant,
                transition.emitted_identities,
                "valid successor root",
                error.to_string(),
                BTreeSet::from(["post-transition root validation".to_owned()]),
                trace_location,
            );
        }
    };
    let receipt = RuntimeReceipt {
        operation_id: context.operation_id.clone(),
        caller_id: context.caller_id.clone(),
        operation_kind: operation.operation_kind(),
        before_digest: snapshot.root_digest.clone(),
        after_digest: successor.root_digest.clone(),
        logical_tick: successor.root.logical_clock.tick,
        emitted_identities: transition.emitted_identities,
        trace_event,
        applied_limits: context.limits.clone(),
        disposition: RuntimeDisposition::Accepted,
        output: transition.output,
    };
    RuntimeEvaluation::Accepted {
        successor: Box::new(successor),
        receipt: Box::new(receipt),
    }
}

pub fn replay_runtime(
    initial: &RuntimeSnapshot,
    operations: &[RuntimeOperation],
) -> Result<RuntimeReplay, RuntimeFault> {
    if operations.len() > initial.root.bounds.max_replay_operations {
        return Err(RuntimeFault {
            kind: RuntimeFaultKind::BoundExhausted,
            operation_id: SemanticId::new("runtime.replay").expect("constant identity is valid"),
            subject_refs: BTreeSet::new(),
            expected: format!(
                "at most {} operations",
                initial.root.bounds.max_replay_operations
            ),
            observed: operations.len().to_string(),
            evidence: BTreeSet::from(["runtime replay bound".to_owned()]),
            safe_residual: "initial snapshot remains unchanged".to_owned(),
            trace_location: initial.root.trace.len() as u64,
        });
    }

    let mut current = initial.clone();
    let mut receipts = Vec::with_capacity(operations.len());
    for operation in operations {
        match evaluate_runtime(&current, operation) {
            RuntimeEvaluation::Accepted { successor, receipt } => {
                current = *successor;
                receipts.push(*receipt);
            }
            RuntimeEvaluation::Refused { fault } => return Err(fault),
        }
    }
    Ok(RuntimeReplay {
        final_snapshot: current,
        receipts,
    })
}

pub fn digest_material_event(event: &MaterialEvent) -> Result<ContentDigest, EvaluationFault> {
    digest_serializable(&(
        &event.event_id,
        &event.repository_generation_input_ref,
        &event.task_ref,
        &event.attribution_ref,
        event.kind,
        &event.subject_refs,
        &event.content_object_refs,
        &event.valid_time_ref,
        &event.transaction_time_ref,
        &event.materiality,
        &event.authority_refs,
        &event.effect_refs,
        &event.predecessor_event_refs,
        &event.retention_profile_ref,
        event.sensitivity,
    ))
}

pub fn digest_semantic_snapshot(
    snapshot: &SemanticSnapshot,
) -> Result<ContentDigest, EvaluationFault> {
    digest_serializable(&(
        &snapshot.snapshot_id,
        &snapshot.repository_id,
        &snapshot.predecessor_snapshot_refs,
        &snapshot.event_frontier,
        &snapshot.canonical_state_root,
        &snapshot.projection_manifest_ref,
        &snapshot.content_object_refs,
        &snapshot.reconciliation_evidence_refs,
        &snapshot.loss_records,
        snapshot.atomic_external_world_claim,
    ))
}

pub fn digest_repository_generation(
    generation: &RepositoryGeneration,
) -> Result<ContentDigest, EvaluationFault> {
    digest_serializable(&(
        &generation.repository_id,
        &generation.generation_id,
        &generation.predecessor_generation_refs,
        &generation.repository_policy_ref,
        &generation.event_frontier,
        &generation.snapshot_root_ref,
        &generation.reference_index_generation_ref,
        &generation.created_by_disposition_ref,
        generation.status,
    ))
}

fn apply_operation(
    root: &mut DeterministicRuntimeRoot,
    operation: &RuntimeOperation,
) -> Result<TransitionResult, RuntimeFault> {
    match operation {
        RuntimeOperation::AdvanceLogicalTime { context, delta } => {
            advance_logical_time(root, context, *delta)
        }
        RuntimeOperation::CompareAndAppend {
            context,
            branch_ref,
            expected_generation_ref,
            generation,
            content,
            events,
            snapshot,
        } => compare_and_append(
            root,
            context,
            branch_ref,
            expected_generation_ref,
            generation,
            content,
            events,
            snapshot,
        ),
        RuntimeOperation::ReviseCalendar {
            context,
            recurrence,
            item,
            wake_conditions,
        } => revise_calendar(root, context, recurrence, item, wake_conditions),
        RuntimeOperation::ExpandRecurrence {
            context,
            recurrence_revision_ref,
            candidate_occurrence_keys,
        } => expand_recurrence(
            root,
            context,
            recurrence_revision_ref,
            candidate_occurrence_keys,
        ),
        RuntimeOperation::EvaluateWake {
            context,
            wake_ref,
            revalidation,
        } => evaluate_wake(root, context, wake_ref, revalidation),
        RuntimeOperation::ProposePlan {
            context,
            plan,
            repository_generation_ref,
            calendar_revision_refs,
            proof_gate_refs,
            available_resource_refs,
        } => propose_plan(
            root,
            context,
            plan,
            repository_generation_ref,
            calendar_revision_refs,
            proof_gate_refs,
            available_resource_refs,
        ),
        RuntimeOperation::ClassifyMateriality {
            context,
            policy_revision_ref,
            event_kind,
            purpose,
            evidence_refs,
        } => classify_materiality(
            root,
            context,
            policy_revision_ref,
            *event_kind,
            purpose,
            evidence_refs,
        ),
        RuntimeOperation::EvaluateCalendarState {
            context,
            predecessor_revision_ref,
            successor_item,
            evaluated_at_tick,
            evaluation_kind,
            candidate_event_id,
        } => evaluate_calendar_state(
            root,
            context,
            predecessor_revision_ref,
            successor_item,
            *evaluated_at_tick,
            *evaluation_kind,
            candidate_event_id,
        ),
        RuntimeOperation::OpenTandem {
            context,
            declared_intent,
            capsule,
            lane_cursors,
            work_packets,
            release_barriers,
            bounded_lag_policies,
        } => open_tandem(
            root,
            context,
            declared_intent,
            capsule,
            lane_cursors,
            work_packets,
            release_barriers,
            bounded_lag_policies,
        ),
        RuntimeOperation::TransitionCapsule {
            context,
            expected_state,
            successor,
        } => transition_capsule(root, context, *expected_state, successor),
        RuntimeOperation::TransitionLane {
            context,
            expected_state,
            successor,
            return_ref,
            reflection_return,
        } => transition_lane(
            root,
            context,
            *expected_state,
            successor,
            return_ref,
            reflection_return,
        ),
        RuntimeOperation::AppendLaneMessage {
            context,
            logical_time,
            message,
        } => append_lane_message(root, context, logical_time, message),
        RuntimeOperation::AcknowledgeLaneMessage {
            context,
            message_ref,
            receiver_cursor_ref,
        } => acknowledge_lane_message(root, context, message_ref, receiver_cursor_ref),
        RuntimeOperation::ReconcileObserver {
            context,
            join,
            successor_capsule,
        } => reconcile_observer(root, context, join, successor_capsule),
        RuntimeOperation::EvaluateReleaseBarrier {
            context,
            expected_state,
            successor,
        } => evaluate_release_barrier(root, context, *expected_state, successor),
        RuntimeOperation::ReenterLane {
            context,
            predecessor_cursor_ref,
            successor_cursor,
        } => reenter_lane(root, context, predecessor_cursor_ref, successor_cursor),
        RuntimeOperation::RegisterCompilerFixture {
            context,
            manifest,
            before_generation,
            candidate_generation,
            impact,
            content,
            diffs,
        } => register_compiler_fixture(
            root,
            context,
            manifest,
            before_generation,
            candidate_generation,
            impact,
            content,
            diffs,
        ),
        RuntimeOperation::RunCompilerForward {
            context,
            fixture_ref,
            prediction_id,
        } => run_compiler_forward(root, context, fixture_ref, prediction_id),
        RuntimeOperation::RunCompilerRear {
            context,
            fixture_ref,
            rear_check_id,
        } => run_compiler_rear(root, context, fixture_ref, rear_check_id),
        RuntimeOperation::CheckCompilerFixture {
            context,
            fixture_ref,
            checked_generation_id,
        } => check_compiler_fixture(root, context, fixture_ref, checked_generation_id),
    }
}

fn advance_logical_time(
    root: &mut DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    delta: u64,
) -> Result<TransitionResult, RuntimeFault> {
    if delta == 0 {
        return Err(make_fault(
            context,
            RuntimeFaultKind::IllegalTransition,
            BTreeSet::from([root.logical_clock.clock_id.clone()]),
            "positive logical-time delta",
            "zero",
            BTreeSet::new(),
            root.trace.len() as u64,
        ));
    }
    root.logical_clock.tick = root.logical_clock.tick.checked_add(delta).ok_or_else(|| {
        make_fault(
            context,
            RuntimeFaultKind::BoundExhausted,
            BTreeSet::from([root.logical_clock.clock_id.clone()]),
            "logical tick within u64",
            "overflow",
            BTreeSet::new(),
            root.trace.len() as u64,
        )
    })?;
    Ok(TransitionResult {
        output: RuntimeOutput::LogicalTime {
            tick: root.logical_clock.tick,
        },
        emitted_identities: BTreeSet::new(),
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_operation_limits(
    snapshot: &RuntimeSnapshot,
    operation: &RuntimeOperation,
) -> Result<(), RuntimeFault> {
    let context = operation.context();
    let root_bounds = &snapshot.root.bounds;
    let trace_location = snapshot.root.trace.len() as u64;
    if context.limits.max_input_bytes > root_bounds.max_operation_input_bytes
        || context.limits.max_emitted_records > root_bounds.max_emitted_records
        || context.limits.max_graph_visits > root_bounds.max_graph_visits
        || context.limits.max_input_bytes == 0
        || context.limits.max_emitted_records == 0
        || context.limits.max_graph_visits == 0
    {
        return Err(make_fault(
            context,
            RuntimeFaultKind::BoundExhausted,
            BTreeSet::new(),
            "positive operation limits no greater than root bounds",
            format!("{:?}", context.limits),
            BTreeSet::from(["operation limit envelope".to_owned()]),
            trace_location,
        ));
    }
    let input_bytes = serde_json::to_vec(operation)
        .map_err(|error| machine_fault(context, error.to_string(), trace_location))?
        .len();
    if input_bytes > context.limits.max_input_bytes {
        return Err(make_fault(
            context,
            RuntimeFaultKind::BoundExhausted,
            BTreeSet::new(),
            format!("at most {} operation bytes", context.limits.max_input_bytes),
            input_bytes.to_string(),
            BTreeSet::from(["normalized operation byte bound".to_owned()]),
            trace_location,
        ));
    }
    Ok(())
}

fn validate_root(root: &DeterministicRuntimeRoot) -> Result<(), EvaluationFault> {
    if root.runtime_profile != CDRA_RUNTIME_PROFILE {
        return Err(EvaluationFault::new(
            FaultKind::UnsupportedSurface,
            format!("unsupported runtime profile: {:?}", root.runtime_profile),
        ));
    }
    if !root.policies.exact_version_only || !root.policies.stable_identity_tie_break {
        return Err(EvaluationFault::new(
            FaultKind::ConstraintViolation,
            "CDRA v0.1 requires exact-version and stable-identity policies",
        ));
    }
    validate_bounds(&root.bounds)?;
    root.forms.validate()?;
    if form_record_count(&root.forms) > root.bounds.max_form_records {
        return Err(EvaluationFault::new(
            FaultKind::BudgetExhausted,
            "runtime form record bound exceeded",
        ));
    }
    if root.trace.len() > root.bounds.max_trace_events {
        return Err(EvaluationFault::new(
            FaultKind::BudgetExhausted,
            "runtime trace bound exceeded",
        ));
    }
    for (index, event) in root.trace.iter().enumerate() {
        if event.trace_index != index as u64 {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "runtime trace indexes are not contiguous",
            ));
        }
    }
    if root
        .trace
        .iter()
        .map(|event| &event.operation_id)
        .collect::<BTreeSet<_>>()
        .len()
        != root.trace.len()
    {
        return Err(EvaluationFault::new(
            FaultKind::ConstraintViolation,
            "runtime trace contains duplicate operation identities",
        ));
    }
    let payload_bytes = root
        .repository
        .content_bytes
        .values()
        .try_fold(0usize, |total, bytes| total.checked_add(bytes.len()))
        .ok_or_else(|| EvaluationFault::new(FaultKind::BudgetExhausted, "payload byte overflow"))?;
    if payload_bytes > root.bounds.max_payload_bytes {
        return Err(EvaluationFault::new(
            FaultKind::BudgetExhausted,
            "runtime payload byte bound exceeded",
        ));
    }
    if root.repository.content_bytes.len() != root.forms.content_objects.len() {
        return Err(EvaluationFault::new(
            FaultKind::ConstraintViolation,
            "runtime content payload and ContentObject identity sets differ",
        ));
    }
    for (object_ref, object) in &root.forms.content_objects {
        let bytes = root
            .repository
            .content_bytes
            .get(object_ref)
            .ok_or_else(|| {
                EvaluationFault::new(FaultKind::ConstraintViolation, "content payload is absent")
            })?;
        if bytes.len() as u64 != object.byte_length || sha256_bytes(bytes) != object.digest {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "content payload does not match its ContentObject",
            ));
        }
    }
    for generation in root.forms.repository_generations.values() {
        if generation.repository_id != root.repository.repository_id {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "repository generation belongs to a different repository",
            ));
        }
        if digest_repository_generation(generation)? != generation.root_digest {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "repository generation digest is invalid",
            ));
        }
        for predecessor in &generation.predecessor_generation_refs {
            if !root.forms.repository_generations.contains_key(predecessor) {
                return Err(EvaluationFault::new(
                    FaultKind::ConstraintViolation,
                    "repository generation predecessor is absent",
                ));
            }
        }
        if let Some(snapshot_ref) = &generation.snapshot_root_ref {
            let snapshot = root.forms.snapshots.get(snapshot_ref).ok_or_else(|| {
                EvaluationFault::new(
                    FaultKind::ConstraintViolation,
                    "repository generation snapshot root is absent",
                )
            })?;
            if snapshot.repository_id != generation.repository_id
                || snapshot.event_frontier != generation.event_frontier
            {
                return Err(EvaluationFault::new(
                    FaultKind::ConstraintViolation,
                    "repository generation and snapshot repository/frontier differ",
                ));
            }
        }
    }
    for event in root.forms.material_events.values() {
        if digest_material_event(event)? != event.event_digest {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "material event digest is invalid",
            ));
        }
    }
    for snapshot in root.forms.snapshots.values() {
        if digest_semantic_snapshot(snapshot)? != snapshot.snapshot_digest {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "semantic snapshot digest is invalid",
            ));
        }
    }
    for generation_ref in root.repository.branch_heads.values() {
        if !root
            .forms
            .repository_generations
            .contains_key(generation_ref)
        {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "branch head references an absent generation",
            ));
        }
    }
    if let Some(generation_ref) = &root.repository.current_generation_ref {
        if !root
            .forms
            .repository_generations
            .contains_key(generation_ref)
        {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "current repository generation is absent",
            ));
        }
        if !root
            .repository
            .branch_heads
            .values()
            .any(|head| head == generation_ref)
        {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "current repository generation is not a branch head",
            ));
        }
    } else if !root.repository.branch_heads.is_empty() {
        return Err(EvaluationFault::new(
            FaultKind::ConstraintViolation,
            "uninitialized repository has branch heads",
        ));
    }
    let expected_index =
        rebuild_repository_index(&root.forms, root.repository.current_generation_ref.as_ref());
    if root.repository.index != expected_index {
        return Err(EvaluationFault::new(
            FaultKind::ConstraintViolation,
            "repository index is not the deterministic projection of current forms",
        ));
    }
    for (item_id, revision_ref) in &root.calendar.latest_item_revision {
        let item = root.forms.calendar_items.get(revision_ref).ok_or_else(|| {
            EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "latest calendar revision is absent",
            )
        })?;
        if &item.calendar_item_id != item_id {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "latest calendar revision has a different stable item identity",
            ));
        }
    }
    for (recurrence_id, revision_ref) in &root.calendar.latest_recurrence_revision {
        let rule = root
            .calendar
            .recurrence_history
            .get(revision_ref)
            .ok_or_else(|| {
                EvaluationFault::new(
                    FaultKind::ConstraintViolation,
                    "latest recurrence revision is absent from history",
                )
            })?;
        if &rule.recurrence_id != recurrence_id {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "latest recurrence revision has a different stable identity",
            ));
        }
        if root.forms.recurrence_rules.get(recurrence_id) != Some(rule) {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "latest recurrence projection differs from current CTPR form",
            ));
        }
    }
    for (revision_ref, occurrence_keys) in &root.calendar.materialized_occurrence_keys {
        let rule = root
            .calendar
            .recurrence_history
            .get(revision_ref)
            .ok_or_else(|| {
                EvaluationFault::new(
                    FaultKind::ConstraintViolation,
                    "materialized occurrence set references an absent recurrence revision",
                )
            })?;
        if occurrence_keys.len() > root.bounds.max_recurrence_occurrences
            || occurrence_keys
                .iter()
                .any(|key| key.is_empty() || rule.exception_keys.contains(key))
        {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "materialized occurrence set violates its bound or exceptions",
            ));
        }
    }
    for wake_ref in &root.calendar.emitted_wake_candidates {
        if !root.forms.wake_conditions.contains_key(wake_ref) {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "emitted wake candidate references an absent wake condition",
            ));
        }
    }
    if let Some(plan_ref) = &root.planner.latest_plan_revision_ref
        && !root.forms.plan_revisions.contains_key(plan_ref)
    {
        return Err(EvaluationFault::new(
            FaultKind::ConstraintViolation,
            "latest planner revision is absent",
        ));
    }
    if let Some(plan_ref) = &root.planner.latest_plan_revision_ref {
        let plan = &root.forms.plan_revisions[plan_ref];
        let order = root
            .planner
            .last_objective_order
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if order != plan.objective_refs || order.len() != root.planner.last_objective_order.len() {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "planner objective order is not an exact permutation of the latest plan",
            ));
        }
    } else if !root.planner.last_objective_order.is_empty() {
        return Err(EvaluationFault::new(
            FaultKind::ConstraintViolation,
            "planner objective order exists without a latest plan",
        ));
    }
    for (capsule_ref, history) in &root.tandem.capsule_state_history {
        let capsule = root.forms.capsules.get(capsule_ref).ok_or_else(|| {
            EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "tandem capsule history references an absent capsule",
            )
        })?;
        if history.first() != Some(&crate::CapsuleState::Opened)
            || history.last() != Some(&capsule.state)
            || history
                .windows(2)
                .any(|pair| crate::validate_capsule_transition(pair[0], pair[1]).is_err())
        {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "tandem capsule history is empty, discontinuous, or differs from current state",
            ));
        }
    }
    for (cursor_ref, history) in &root.tandem.lane_state_history {
        let cursor = root.forms.lane_cursors.get(cursor_ref).ok_or_else(|| {
            EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "tandem lane history references an absent cursor",
            )
        })?;
        let ordinary_history = history.first() == Some(&crate::LaneState::Idle)
            && history
                .windows(2)
                .all(|pair| crate::validate_lane_transition(pair[0], pair[1]).is_ok());
        let reentry_history = history.first() == Some(&crate::LaneState::Prepared)
            && root.tandem.reentry_predecessors.contains_key(cursor_ref)
            && history
                .windows(2)
                .all(|pair| crate::validate_lane_transition(pair[0], pair[1]).is_ok());
        if (!ordinary_history && !reentry_history) || history.last() != Some(&cursor.state) {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "tandem lane history is empty, discontinuous, or differs from current state",
            ));
        }
    }
    for (cursor_ref, return_ref) in &root.tandem.lane_return_refs {
        let cursor = root.forms.lane_cursors.get(cursor_ref).ok_or_else(|| {
            EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "lane return references an absent cursor",
            )
        })?;
        if !matches!(
            cursor.state,
            crate::LaneState::Returned | crate::LaneState::Released
        ) || !super::tandem::lane_output_exists(&root.forms, cursor, return_ref)
        {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "lane return identity is absent or its cursor is not returned",
            ));
        }
    }
    for cursor in root.forms.lane_cursors.values().filter(|cursor| {
        root.tandem
            .lane_state_history
            .contains_key(&cursor.cursor_id)
    }) {
        if matches!(
            cursor.state,
            crate::LaneState::Returned | crate::LaneState::Released
        ) && !root.tandem.lane_return_refs.contains_key(&cursor.cursor_id)
        {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "returned lane lacks a recorded return identity",
            ));
        }
    }
    for message_ref in &root.tandem.acknowledged_message_refs {
        let message = root.forms.lane_messages.get(message_ref).ok_or_else(|| {
            EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "acknowledgment references an absent lane message",
            )
        })?;
        if !message.required_acknowledgment {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "acknowledgment exists for a message that did not require one",
            ));
        }
    }
    for (successor_ref, predecessor_ref) in &root.tandem.reentry_predecessors {
        let successor = root.forms.lane_cursors.get(successor_ref).ok_or_else(|| {
            EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "reentry successor is absent",
            )
        })?;
        let predecessor = root
            .forms
            .lane_cursors
            .get(predecessor_ref)
            .ok_or_else(|| {
                EvaluationFault::new(
                    FaultKind::ConstraintViolation,
                    "reentry predecessor is absent",
                )
            })?;
        if !successor.dependency_refs.contains(predecessor_ref)
            || successor.capsule_generation_ref != predecessor.capsule_generation_ref
        {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "reentry successor does not preserve its predecessor dependency and capsule",
            ));
        }
    }
    for (capsule_ref, counts) in &root.tandem.transition_counts {
        if !root.forms.capsules.contains_key(capsule_ref) {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "tandem transition count references an absent capsule",
            ));
        }
        for (transition_kind, count) in counts {
            for policy in root.forms.bounded_lag_policies.values() {
                if policy.eligible_transition_kinds.contains(transition_kind)
                    && policy
                        .maximum_transition_count
                        .is_some_and(|maximum| *count > maximum)
                {
                    return Err(EvaluationFault::new(
                        FaultKind::BudgetExhausted,
                        "tandem transition count exceeds a declared bounded-lag policy",
                    ));
                }
            }
        }
    }
    validate_compiler_runtime(root)?;
    Ok(())
}

fn validate_bounds(bounds: &RuntimeBounds) -> Result<(), EvaluationFault> {
    let values = [
        bounds.max_form_records,
        bounds.max_payload_bytes,
        bounds.max_operation_input_bytes,
        bounds.max_emitted_records,
        bounds.max_graph_visits,
        bounds.max_recurrence_occurrences,
        bounds.max_trace_events,
        bounds.max_replay_operations,
    ];
    if values.contains(&0) {
        return Err(EvaluationFault::new(
            FaultKind::BudgetExhausted,
            "runtime bounds must all be positive",
        ));
    }
    Ok(())
}

pub(crate) fn rebuild_repository_index(
    forms: &TemporalFormSet,
    source_generation_ref: Option<&SemanticId>,
) -> RepositoryIndex {
    let mut events_by_subject = BTreeMap::<SemanticId, BTreeSet<SemanticId>>::new();
    for event in forms.material_events.values() {
        for subject in &event.subject_refs {
            events_by_subject
                .entry(subject.clone())
                .or_default()
                .insert(event.event_id.clone());
        }
    }
    let mut content_by_digest = BTreeMap::new();
    for object in forms.content_objects.values() {
        content_by_digest
            .entry(digest_label(&object.digest))
            .or_insert_with(|| object.object_id.clone());
    }
    RepositoryIndex {
        source_generation_ref: source_generation_ref.cloned(),
        events_by_subject,
        content_by_digest,
    }
}

fn form_record_count(forms: &TemporalFormSet) -> usize {
    [
        forms.time_expressions.len(),
        forms.task_contracts.len(),
        forms.objectives.len(),
        forms.dependencies.len(),
        forms.constraints.len(),
        forms.alternatives.len(),
        forms.plan_revisions.len(),
        forms.schedules.len(),
        forms.commitments.len(),
        forms.wake_conditions.len(),
        forms.recurrence_rules.len(),
        forms.calendar_items.len(),
        forms.materiality_policies.len(),
        forms.content_objects.len(),
        forms.material_events.len(),
        forms.snapshots.len(),
        forms.repository_generations.len(),
        forms.git_projections.len(),
        forms.declared_intents.len(),
        forms.diffs.len(),
        forms.capsules.len(),
        forms.lane_cursors.len(),
        forms.lane_messages.len(),
        forms.work_packets.len(),
        forms.reflection_returns.len(),
        forms.observer_joins.len(),
        forms.release_barriers.len(),
        forms.bounded_lag_policies.len(),
        forms.compiler_generations.len(),
        forms.compiler_impacts.len(),
        forms.forecast_errors.len(),
        forms.plan_deviations.len(),
        forms.semantic_surprises.len(),
        forms.lesson_candidates.len(),
        forms.training_example_candidates.len(),
    ]
    .into_iter()
    .sum()
}

fn digest_serializable<T: Serialize + ?Sized>(value: &T) -> Result<ContentDigest, EvaluationFault> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        EvaluationFault::new(
            FaultKind::MachineForm,
            format!("runtime canonical serialization failed: {error}"),
        )
    })?;
    Ok(sha256_bytes(&bytes))
}

pub(crate) fn digest_label(digest: &ContentDigest) -> String {
    format!("{}:{}", digest.algorithm, digest.value)
}

fn refused(
    context: &RuntimeOperationContext,
    kind: RuntimeFaultKind,
    subject_refs: BTreeSet<SemanticId>,
    expected: impl Into<String>,
    observed: impl Into<String>,
    evidence: BTreeSet<String>,
    trace_location: u64,
) -> RuntimeEvaluation {
    RuntimeEvaluation::Refused {
        fault: make_fault(
            context,
            kind,
            subject_refs,
            expected,
            observed,
            evidence,
            trace_location,
        ),
    }
}

pub(crate) fn make_fault(
    context: &RuntimeOperationContext,
    kind: RuntimeFaultKind,
    subject_refs: BTreeSet<SemanticId>,
    expected: impl Into<String>,
    observed: impl Into<String>,
    evidence: BTreeSet<String>,
    trace_location: u64,
) -> RuntimeFault {
    RuntimeFault {
        kind,
        operation_id: context.operation_id.clone(),
        subject_refs,
        expected: expected.into(),
        observed: observed.into(),
        evidence,
        safe_residual: "prior runtime snapshot remains unchanged".to_owned(),
        trace_location,
    }
}

pub(crate) fn missing_fault(
    context: &RuntimeOperationContext,
    identity: &SemanticId,
    trace_location: u64,
) -> RuntimeFault {
    make_fault(
        context,
        RuntimeFaultKind::MissingReference,
        BTreeSet::from([identity.clone()]),
        "present exact identity",
        "absent identity",
        BTreeSet::new(),
        trace_location,
    )
}

pub(crate) fn duplicate_fault(
    context: &RuntimeOperationContext,
    identity: &SemanticId,
    trace_location: u64,
) -> RuntimeFault {
    make_fault(
        context,
        RuntimeFaultKind::DuplicateIdentity,
        BTreeSet::from([identity.clone()]),
        "new identity",
        "identity already exists",
        BTreeSet::new(),
        trace_location,
    )
}

pub(crate) fn machine_fault(
    context: &RuntimeOperationContext,
    observed: impl Into<String>,
    trace_location: u64,
) -> RuntimeFault {
    make_fault(
        context,
        RuntimeFaultKind::MachineForm,
        BTreeSet::new(),
        "canonical machine form",
        observed,
        BTreeSet::new(),
        trace_location,
    )
}

pub(crate) fn graph_bound_fault(
    context: &RuntimeOperationContext,
    trace_location: u64,
    visits: usize,
) -> RuntimeFault {
    make_fault(
        context,
        RuntimeFaultKind::BoundExhausted,
        BTreeSet::new(),
        format!("at most {} graph visits", context.limits.max_graph_visits),
        visits.to_string(),
        BTreeSet::from(["planner graph traversal".to_owned()]),
        trace_location,
    )
}
