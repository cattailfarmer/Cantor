use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{
    AuthorityState, BarrierState, BoundedLagPolicy, CalendarItem, CalendarKind,
    CalendarLifecycleState, CapsuleState, ChangeCapsule, CompilerFixtureManifest,
    CompilerFixtureStatus, CompilerGeneration, CompilerImpact, CompilerStage, ConstraintSeverity,
    ContentInput, ContentObject, DeclaredIntent, DependencyEdge, DependencyKind, DiffKind,
    DiffRecord, EventKind, InvalidationEdge, JoinDisposition, LaneCursor, LaneKind, LaneState,
    MaterialEvent, MaterialityDecision, MaterialityDisposition, ObjectiveNode, ObjectiveStatus,
    ObserverJoin, PlanRevision, PlanState, ProviderSyncState, RecurrenceRule,
    ReflectionDisposition, ReflectionReturn, ReleaseBarrier, RuntimeEvaluation, RuntimeFaultKind,
    RuntimeOperation, RuntimeOutput, RuntimeReceipt, RuntimeSnapshot, SemanticId, SemanticSnapshot,
    SensitivityClass, WakeCondition, WorkPacket, WorkPacketKind, digest_material_event,
    digest_semantic_snapshot, evaluate_runtime, from_normalized_runtime_snapshot, replay_runtime,
    sha256_bytes, to_normalized_runtime_snapshot, validate_capsule_transition,
    validate_lane_transition,
};

#[allow(dead_code)]
mod temporal_runtime_support;

use temporal_runtime_support::{candidate_generation, context, id, ids, initial_runtime, texts};

fn apply(
    runtime: &mut RuntimeSnapshot,
    operations: &mut Vec<RuntimeOperation>,
    operation: RuntimeOperation,
) -> RuntimeReceipt {
    let (successor, receipt) = match evaluate_runtime(runtime, &operation) {
        RuntimeEvaluation::Accepted { successor, receipt } => (*successor, *receipt),
        RuntimeEvaluation::Refused { fault } => panic!("integrated operation refused: {fault:?}"),
    };
    *runtime = successor;
    operations.push(operation);
    receipt
}

fn integration_initial() -> RuntimeSnapshot {
    let mut root = initial_runtime().root;
    root.forms.dependencies.clear();
    root.forms.objectives.insert(
        id("objective.repair"),
        ObjectiveNode {
            objective_id: id("objective.repair"),
            task_ref: id("task.one"),
            statement: "satisfy the requirement exposed by rear review".to_owned(),
            desired_state_criteria: texts(&["repair complete"]),
            priority_source_ref: id("source.priority"),
            uncertainty: texts(&["bounded fixture only"]),
            status: ObjectiveStatus::Eligible,
            proof_route: texts(&["rear review"]),
        },
    );
    for (edge_id, predecessor, successor, condition) in [
        (
            "dependency.a.b",
            "objective.a",
            "objective.b",
            "a completes before b",
        ),
        (
            "dependency.b.c",
            "objective.b",
            "objective.c",
            "b completes before c",
        ),
        (
            "dependency.repair.b",
            "objective.repair",
            "objective.b",
            "rear-exposed repair completes before b",
        ),
    ] {
        root.forms.dependencies.insert(
            id(edge_id),
            DependencyEdge {
                edge_id: id(edge_id),
                predecessor_ref: id(predecessor),
                successor_objective_ref: id(successor),
                kind: DependencyKind::Objective,
                condition: condition.to_owned(),
                strength: "required".to_owned(),
                source_ref: id("source.fixture"),
                invalidation_rule: "invalidate dependent when predecessor meaning changes"
                    .to_owned(),
            },
        );
    }
    root.policies.objective_priority.clear();
    root.policies
        .objective_priority
        .insert(id("objective.a"), 0);
    root.policies
        .objective_priority
        .insert(id("objective.repair"), 0);
    root.policies
        .objective_priority
        .insert(id("objective.b"), 1);
    root.policies
        .objective_priority
        .insert(id("objective.c"), 2);
    RuntimeSnapshot::from_root(root).expect("integration root is valid")
}

fn initialize_repository(runtime: &mut RuntimeSnapshot, operations: &mut Vec<RuntimeOperation>) {
    let operation = RuntimeOperation::CompareAndAppend {
        context: context(runtime, "integration.repository.initialize"),
        branch_ref: id("branch.main"),
        expected_generation_ref: None,
        generation: candidate_generation("generation.one", &[], &[], None),
        content: Vec::new(),
        events: Vec::new(),
        snapshot: None,
    };
    apply(runtime, operations, operation);
}

fn content(identity: &str, value: &[u8], media_type: &str) -> ContentInput {
    ContentInput {
        object: ContentObject {
            object_id: id(identity),
            digest: sha256_bytes(value),
            byte_length: value.len() as u64,
            media_type: media_type.to_owned(),
            encoding: "utf-8".to_owned(),
            provenance_refs: ids(&["source.fixture"]),
            sensitivity: SensitivityClass::ProjectInternal,
            retention_profile_ref: id("retention.fixture"),
            storage_locators: BTreeSet::new(),
        },
        bytes: value.to_vec(),
    }
}

fn material_event(
    event_id: &str,
    input_generation: &str,
    content_ref: &str,
    subject_refs: &[&str],
    predecessor_refs: &[&str],
) -> MaterialEvent {
    let mut event = MaterialEvent {
        event_id: id(event_id),
        repository_generation_input_ref: id(input_generation),
        task_ref: Some(id("task.one")),
        attribution_ref: Some(id("attribution.fixture")),
        kind: EventKind::Observation,
        subject_refs: ids(subject_refs),
        content_object_refs: ids(&[content_ref]),
        valid_time_ref: None,
        transaction_time_ref: id("time.logical.0"),
        materiality: MaterialityDecision {
            policy_ref: id("materiality.rev1"),
            evidence_refs: ids(&["evidence.fixture"]),
            disposition: MaterialityDisposition::Capture,
            reason: "changes faithful replay and subsequent planning".to_owned(),
        },
        authority_refs: BTreeSet::new(),
        effect_refs: BTreeSet::new(),
        predecessor_event_refs: ids(predecessor_refs),
        retention_profile_ref: id("retention.fixture"),
        sensitivity: SensitivityClass::ProjectInternal,
        event_digest: sha256_bytes(b"placeholder"),
    };
    event.event_digest = digest_material_event(&event).expect("event digest serializes");
    event
}

fn semantic_snapshot(
    snapshot_id: &str,
    predecessors: &[&str],
    frontier: &[&str],
    content_refs: &[&str],
    state: &[u8],
) -> SemanticSnapshot {
    let mut snapshot = SemanticSnapshot {
        snapshot_id: id(snapshot_id),
        repository_id: id("repository.one"),
        predecessor_snapshot_refs: ids(predecessors),
        event_frontier: ids(frontier),
        canonical_state_root: sha256_bytes(state),
        projection_manifest_ref: None,
        content_object_refs: ids(content_refs),
        reconciliation_evidence_refs: ids(&["evidence.fixture"]),
        loss_records: BTreeSet::new(),
        atomic_external_world_claim: false,
        snapshot_digest: sha256_bytes(b"placeholder"),
    };
    snapshot.snapshot_digest =
        digest_semantic_snapshot(&snapshot).expect("snapshot digest serializes");
    snapshot
}

fn append_initial_observation(
    runtime: &mut RuntimeSnapshot,
    operations: &mut Vec<RuntimeOperation>,
) {
    let payload = b"three-step objective admitted for deterministic planning";
    let input = content("content.observation", payload, "text/plain");
    let event = material_event(
        "event.observation",
        "generation.one",
        "content.observation",
        &["task.one", "objective.a", "objective.b", "objective.c"],
        &[],
    );
    let snapshot = semantic_snapshot(
        "snapshot.one",
        &[],
        &["event.observation"],
        &["content.observation"],
        b"objective a then b then c",
    );
    let operation = RuntimeOperation::CompareAndAppend {
        context: context(runtime, "integration.repository.observation"),
        branch_ref: id("branch.main"),
        expected_generation_ref: Some(id("generation.one")),
        generation: candidate_generation(
            "generation.two",
            &["generation.one"],
            &["event.observation"],
            Some("snapshot.one"),
        ),
        content: vec![input],
        events: vec![event],
        snapshot: Some(snapshot),
    };
    apply(runtime, operations, operation);
}

fn install_calendar(runtime: &mut RuntimeSnapshot, operations: &mut Vec<RuntimeOperation>) {
    let recurrence = RecurrenceRule {
        recurrence_id: id("recurrence.integration"),
        revision_id: id("recurrence.integration.rev1"),
        predecessor_revision_ref: None,
        frequency: "daily".to_owned(),
        interval: 1,
        zone: "UTC".to_owned(),
        calendar_system: "gregorian".to_owned(),
        start_boundary_ref: id("time.logical.0"),
        end_boundary_ref: None,
        occurrence_limit: Some(3),
        inclusion_keys: texts(&["review.1", "review.3"]),
        exception_keys: texts(&["review.2"]),
        materialization_horizon_ref: id("time.logical.0"),
    };
    let item = CalendarItem {
        calendar_item_id: id("calendar.integration"),
        revision_id: id("calendar.integration.rev1"),
        predecessor_revision_ref: None,
        kind: CalendarKind::Task,
        task_ref: Some(id("task.one")),
        purpose: "bound the three-step proof and its rear review".to_owned(),
        source_ref: id("source.fixture"),
        owner_refs: ids(&["principal.one"]),
        participant_refs: BTreeSet::new(),
        time_expression_refs: ids(&["time.logical.0"]),
        recurrence_rule_ref: Some(id("recurrence.integration")),
        dependency_refs: BTreeSet::new(),
        review_refs: ids(&["review.integration"]),
        authority_state: AuthorityState::Granted,
        lifecycle_state: CalendarLifecycleState::Committed,
        provider_sync_state: ProviderSyncState::LocalOnly,
        field_sensitivity: BTreeMap::new(),
        disclosure_refs: BTreeSet::new(),
    };
    let wake = WakeCondition {
        wake_id: id("wake.integration"),
        calendar_item_ref: id("calendar.integration.rev1"),
        condition: "logical review checkpoint supplied".to_owned(),
        revalidation_requirements: texts(&[
            "task",
            "plan",
            "repository",
            "capsule",
            "policy",
            "authority",
        ]),
        source_ref: id("source.fixture"),
    };
    let operation = RuntimeOperation::ReviseCalendar {
        context: context(runtime, "integration.calendar.revise"),
        recurrence: Some(recurrence),
        item,
        wake_conditions: vec![wake],
    };
    apply(runtime, operations, operation);
}

fn propose_initial_plan(runtime: &mut RuntimeSnapshot, operations: &mut Vec<RuntimeOperation>) {
    let plan = PlanRevision {
        plan_id: id("plan.integration"),
        revision_id: id("plan.integration.rev1"),
        predecessor_revision_ref: None,
        task_ref: id("task.one"),
        objective_refs: ids(&["objective.a", "objective.b", "objective.c"]),
        dependency_refs: ids(&["dependency.a.b", "dependency.b.c"]),
        temporal_refs: ids(&["calendar.integration.rev1"]),
        effect_refs: BTreeSet::new(),
        review_refs: ids(&["review.integration"]),
        selected_alternative_ref: None,
        assumptions: texts(&["the original three-step path remains sufficient"]),
        uncertainty: BTreeSet::new(),
        state: PlanState::Proposed,
    };
    let operation = RuntimeOperation::ProposePlan {
        context: context(runtime, "integration.plan.initial"),
        plan,
        repository_generation_ref: id("generation.two"),
        calendar_revision_refs: ids(&["calendar.integration.rev1"]),
        proof_gate_refs: ids(&["review.integration"]),
        available_resource_refs: ids(&["resource.fixture"]),
    };
    let receipt = apply(runtime, operations, operation);
    match receipt.output {
        RuntimeOutput::PlanProposal {
            objective_order, ..
        } => assert_eq!(
            objective_order,
            vec![id("objective.a"), id("objective.b"), id("objective.c")]
        ),
        other => panic!("plan proposal expected, observed {other:?}"),
    }
}

#[derive(Clone, Debug)]
struct TandemResult {
    capsule_ref: SemanticId,
    barrier_ref: SemanticId,
    join_ref: SemanticId,
}

#[allow(clippy::too_many_arguments)]
fn open_tandem(
    runtime: &mut RuntimeSnapshot,
    operations: &mut Vec<RuntimeOperation>,
    prefix: &str,
    plan_ref: &str,
    repository_generation_ref: &str,
    before_snapshot_ref: &str,
    _prospective_return_ref: &str,
    execution_outcome_ref: Option<&str>,
    dependent_refs: &[&str],
) {
    let capsule_ref = id(&format!("{prefix}.capsule"));
    let intent_ref = id(&format!("{prefix}.intent"));
    let prospective_cursor_ref = id(&format!("{prefix}.lane.prospective"));
    let retrospective_cursor_ref = id(&format!("{prefix}.lane.retrospective"));
    let barrier_ref = id(&format!("{prefix}.barrier"));
    let lag_ref = id(&format!("{prefix}.lag"));
    let intent = DeclaredIntent {
        intent_id: intent_ref.clone(),
        target_refs: ids(dependent_refs),
        expected_transformations: texts(&[
            "prepare, inspect, reconcile, and conditionally release",
        ]),
        allowed_effects: BTreeSet::new(),
        completion_evidence: texts(&["exact Observer reconciliation"]),
        unrelated_state_exclusions: ids(&["unrelated.stable"]),
        source_ref: id("source.fixture"),
    };
    let capsule = ChangeCapsule {
        change_id: id(&format!("{prefix}.change")),
        candidate_generation_id: capsule_ref.clone(),
        task_ref: id("task.one"),
        plan_revision_ref: id(plan_ref),
        repository_generation_ref: id(repository_generation_ref),
        before_snapshot_ref: id(before_snapshot_ref),
        declared_intent_ref: intent_ref,
        prepared_candidate_ref: None,
        execution_request_ref: None,
        execution_outcome_ref: None,
        candidate_snapshot_ref: None,
        diff_refs: BTreeMap::new(),
        justification_delta: BTreeSet::new(),
        support_delta: BTreeSet::new(),
        requirement_delta: BTreeSet::new(),
        compiler_impact_ref: None,
        reflection_return_ref: None,
        reflection_exception_ref: None,
        observer_join_ref: None,
        after_snapshot_ref: None,
        state: CapsuleState::Opened,
    };
    let cursor = |suffix: &str, kind: LaneKind, authority: Option<&str>| LaneCursor {
        cursor_id: id(&format!("{prefix}.lane.{suffix}")),
        kind,
        task_ref: id("task.one"),
        input_repository_generation_ref: id(repository_generation_ref),
        plan_revision_ref: id(plan_ref),
        capsule_generation_ref: capsule_ref.clone(),
        dependency_refs: BTreeSet::new(),
        authority_request_ref: authority.map(id),
        state: LaneState::Idle,
        lease_ref: None,
        timeout_ref: None,
        last_message_ref: None,
    };
    let mut lane_cursors = vec![
        cursor("prospective", LaneKind::Prospective, None),
        cursor("retrospective", LaneKind::Retrospective, None),
    ];
    let mut work_packets = vec![WorkPacket {
        packet_id: id(&format!("{prefix}.packet.prospective")),
        kind: WorkPacketKind::Prospective,
        task_ref: id("task.one"),
        input_repository_generation_ref: id(repository_generation_ref),
        capsule_generation_ref: capsule_ref.clone(),
        permitted_output_kinds: texts(&["prepared_candidate"]),
        authority_boundary: texts(&["returned immutable values only"]),
    }];
    if execution_outcome_ref.is_some() {
        lane_cursors.push(cursor(
            "execution",
            LaneKind::Execution,
            Some("authority.simulated.effect"),
        ));
        work_packets.push(WorkPacket {
            packet_id: id(&format!("{prefix}.packet.execution")),
            kind: WorkPacketKind::Execution,
            task_ref: id("task.one"),
            input_repository_generation_ref: id(repository_generation_ref),
            capsule_generation_ref: capsule_ref.clone(),
            permitted_output_kinds: texts(&["simulated_effect_observation"]),
            authority_boundary: texts(&["caller-supplied fixture observation only"]),
        });
    }
    let barrier = ReleaseBarrier {
        barrier_id: barrier_ref,
        capsule_generation_ref: capsule_ref,
        required_return_refs: ids(&[&format!("{prefix}.reflection")]),
        dependent_refs: ids(dependent_refs),
        observer_join_ref: None,
        released_refs: BTreeSet::new(),
        state: BarrierState::Closed,
    };
    let lag = BoundedLagPolicy {
        policy_id: lag_ref,
        eligible_transition_kinds: texts(&[
            "capsule_transition",
            "lane_transition",
            "lane_message",
            "lane_acknowledgment",
            "observer_join",
            "release_barrier",
            "lane_reentry",
        ]),
        maximum_transition_count: Some(64),
        maximum_duration_ref: None,
        consequence_bound: "returned value only".to_owned(),
        rollback_capacity: "retain prior snapshot".to_owned(),
        overdue_behavior: "typed refusal".to_owned(),
        authority_ref: id("authority.fixture"),
    };
    let operation = RuntimeOperation::OpenTandem {
        context: context(runtime, &format!("{prefix}.operation.open")),
        declared_intent: intent,
        capsule,
        lane_cursors,
        work_packets,
        release_barriers: vec![barrier],
        bounded_lag_policies: vec![lag],
    };
    let receipt = apply(runtime, operations, operation);
    assert!(matches!(receipt.output, RuntimeOutput::TandemOpened { .. }));
    assert!(
        runtime
            .root
            .forms
            .lane_cursors
            .contains_key(&prospective_cursor_ref)
    );
    assert!(
        runtime
            .root
            .forms
            .lane_cursors
            .contains_key(&retrospective_cursor_ref)
    );
}

#[allow(clippy::too_many_arguments)]
fn transition_capsule(
    runtime: &mut RuntimeSnapshot,
    operations: &mut Vec<RuntimeOperation>,
    prefix: &str,
    expected: CapsuleState,
    target: CapsuleState,
    prospective_return_ref: &str,
    execution_outcome_ref: Option<&str>,
    reflection_ref: Option<&str>,
) {
    let capsule_ref = id(&format!("{prefix}.capsule"));
    let mut successor = runtime.root.forms.capsules[&capsule_ref].clone();
    successor.state = target;
    if matches!(
        target,
        CapsuleState::Prepared
            | CapsuleState::ExecutionRequested
            | CapsuleState::EffectObserved
            | CapsuleState::ReflectionRequested
            | CapsuleState::ReflectionReturned
    ) {
        successor.prepared_candidate_ref = Some(id(prospective_return_ref));
    }
    if matches!(
        target,
        CapsuleState::ExecutionRequested
            | CapsuleState::EffectObserved
            | CapsuleState::ReflectionRequested
            | CapsuleState::ReflectionReturned
    ) && execution_outcome_ref.is_some()
    {
        successor.execution_request_ref = Some(id(&format!("{prefix}.execution.request")));
    }
    if matches!(
        target,
        CapsuleState::EffectObserved
            | CapsuleState::ReflectionRequested
            | CapsuleState::ReflectionReturned
    ) {
        successor.execution_outcome_ref = execution_outcome_ref.map(id);
    }
    if target == CapsuleState::ReflectionReturned {
        successor.reflection_return_ref = reflection_ref.map(id);
    }
    let operation = RuntimeOperation::TransitionCapsule {
        context: context(runtime, &format!("{prefix}.operation.capsule.{target:?}")),
        expected_state: expected,
        successor,
    };
    apply(runtime, operations, operation);
}

#[allow(clippy::too_many_arguments)]
fn transition_lane(
    runtime: &mut RuntimeSnapshot,
    operations: &mut Vec<RuntimeOperation>,
    prefix: &str,
    lane: &str,
    expected: LaneState,
    target: LaneState,
    return_ref: Option<&str>,
    reflection_return: Option<ReflectionReturn>,
) {
    let cursor_ref = id(&format!("{prefix}.lane.{lane}"));
    let mut successor = runtime.root.forms.lane_cursors[&cursor_ref].clone();
    successor.state = target;
    let operation = RuntimeOperation::TransitionLane {
        context: context(
            runtime,
            &format!("{prefix}.operation.lane.{lane}.{target:?}"),
        ),
        expected_state: expected,
        successor,
        return_ref: return_ref.map(id),
        reflection_return,
    };
    apply(runtime, operations, operation);
}

fn exact_observer_subjects(
    runtime: &RuntimeSnapshot,
    prefix: &str,
    plan_ref: &str,
    repository_generation_ref: &str,
    extras: &BTreeSet<SemanticId>,
) -> BTreeSet<SemanticId> {
    let mut subjects = BTreeSet::from([
        id(&format!("{prefix}.capsule")),
        id("task.one"),
        id(plan_ref),
        id(repository_generation_ref),
    ]);
    for policy in runtime.root.forms.materiality_policies.values() {
        subjects.insert(policy.policy_id.clone());
        subjects.insert(policy.revision_id.clone());
    }
    for policy in runtime.root.forms.bounded_lag_policies.values() {
        subjects.insert(policy.policy_id.clone());
        subjects.insert(policy.authority_ref.clone());
    }
    subjects.extend(extras.iter().cloned());
    subjects
}

#[allow(clippy::too_many_arguments)]
fn complete_tandem(
    runtime: &mut RuntimeSnapshot,
    operations: &mut Vec<RuntimeOperation>,
    prefix: &str,
    plan_ref: &str,
    repository_generation_ref: &str,
    prospective_return_ref: &str,
    execution_outcome_ref: Option<&str>,
    reflection_disposition: ReflectionDisposition,
    join_disposition: JoinDisposition,
    invalidation_refs: BTreeSet<SemanticId>,
    extra_observer_subjects: BTreeSet<SemanticId>,
) -> TandemResult {
    let reflection_name = format!("{prefix}.reflection");
    transition_capsule(
        runtime,
        operations,
        prefix,
        CapsuleState::Opened,
        CapsuleState::Prepared,
        prospective_return_ref,
        execution_outcome_ref,
        None,
    );
    if execution_outcome_ref.is_some() {
        transition_capsule(
            runtime,
            operations,
            prefix,
            CapsuleState::Prepared,
            CapsuleState::ExecutionRequested,
            prospective_return_ref,
            execution_outcome_ref,
            None,
        );
        transition_capsule(
            runtime,
            operations,
            prefix,
            CapsuleState::ExecutionRequested,
            CapsuleState::EffectObserved,
            prospective_return_ref,
            execution_outcome_ref,
            None,
        );
    }
    for lane in ["prospective", "retrospective"] {
        transition_lane(
            runtime,
            operations,
            prefix,
            lane,
            LaneState::Idle,
            LaneState::Prepared,
            None,
            None,
        );
        transition_lane(
            runtime,
            operations,
            prefix,
            lane,
            LaneState::Prepared,
            LaneState::Running,
            None,
            None,
        );
    }
    if execution_outcome_ref.is_some() {
        transition_lane(
            runtime,
            operations,
            prefix,
            "execution",
            LaneState::Idle,
            LaneState::Prepared,
            None,
            None,
        );
        transition_lane(
            runtime,
            operations,
            prefix,
            "execution",
            LaneState::Prepared,
            LaneState::Running,
            None,
            None,
        );
    }
    transition_lane(
        runtime,
        operations,
        prefix,
        "prospective",
        LaneState::Running,
        LaneState::Returned,
        Some(prospective_return_ref),
        None,
    );
    if let Some(outcome_ref) = execution_outcome_ref {
        transition_lane(
            runtime,
            operations,
            prefix,
            "execution",
            LaneState::Running,
            LaneState::Returned,
            Some(outcome_ref),
            None,
        );
    }
    let reflection = ReflectionReturn {
        return_id: id(&reflection_name),
        retrospective_cursor_ref: id(&format!("{prefix}.lane.retrospective")),
        capsule_generation_ref: id(&format!("{prefix}.capsule")),
        disposition: reflection_disposition,
        evidence_refs: ids(&[&format!("{prefix}.rear.evidence")]),
        objections: if reflection_disposition == ReflectionDisposition::Block {
            texts(&["execution deviated and exposed a missing prerequisite"])
        } else {
            BTreeSet::new()
        },
        uncertainty: texts(&["fixture evidence only"]),
        invalidation_refs,
        residuals: texts(&["no external effect claim"]),
        signature_ref: None,
        provider_qualification: None,
    };
    transition_lane(
        runtime,
        operations,
        prefix,
        "retrospective",
        LaneState::Running,
        LaneState::Returned,
        Some(&reflection_name),
        Some(reflection),
    );
    let pre_reflection = if execution_outcome_ref.is_some() {
        CapsuleState::EffectObserved
    } else {
        CapsuleState::Prepared
    };
    transition_capsule(
        runtime,
        operations,
        prefix,
        pre_reflection,
        CapsuleState::ReflectionRequested,
        prospective_return_ref,
        execution_outcome_ref,
        None,
    );
    transition_capsule(
        runtime,
        operations,
        prefix,
        CapsuleState::ReflectionRequested,
        CapsuleState::ReflectionReturned,
        prospective_return_ref,
        execution_outcome_ref,
        Some(&reflection_name),
    );

    let capsule_ref = id(&format!("{prefix}.capsule"));
    let barrier_ref = id(&format!("{prefix}.barrier"));
    let join_ref = id(&format!("{prefix}.join"));
    let mut returns = ids(&[prospective_return_ref, &reflection_name]);
    if let Some(outcome_ref) = execution_outcome_ref {
        returns.insert(id(outcome_ref));
    }
    let join = ObserverJoin {
        join_id: join_ref.clone(),
        capsule_generation_ref: capsule_ref.clone(),
        expected_lane_return_refs: returns.clone(),
        expected_subject_version_refs: exact_observer_subjects(
            runtime,
            prefix,
            plan_ref,
            repository_generation_ref,
            &extra_observer_subjects,
        ),
        received_return_refs: returns,
        stale_check_refs: ids(&[plan_ref, repository_generation_ref]),
        reconciliation_record_ref: id(&format!("{prefix}.reconciliation")),
        disposition: join_disposition,
        successor_repository_generation_ref: None,
        release_refs: ids(&[&format!("{prefix}.barrier")]),
        residuals: texts(&["all runtime products remain effectless"]),
    };
    let mut reconciled = runtime.root.forms.capsules[&capsule_ref].clone();
    reconciled.state = CapsuleState::Reconciled;
    reconciled.observer_join_ref = Some(join_ref.clone());
    let operation = RuntimeOperation::ReconcileObserver {
        context: context(runtime, &format!("{prefix}.operation.observer")),
        join,
        successor_capsule: reconciled,
    };
    apply(runtime, operations, operation);

    if matches!(
        join_disposition,
        JoinDisposition::Admit | JoinDisposition::Qualify
    ) {
        let mut barrier = runtime.root.forms.release_barriers[&barrier_ref].clone();
        barrier.state = BarrierState::Open;
        barrier.observer_join_ref = Some(join_ref.clone());
        barrier.released_refs = barrier.dependent_refs.clone();
        let operation = RuntimeOperation::EvaluateReleaseBarrier {
            context: context(runtime, &format!("{prefix}.operation.barrier.open")),
            expected_state: BarrierState::Closed,
            successor: barrier,
        };
        apply(runtime, operations, operation);
    } else {
        let before_refusal = runtime.clone();
        let mut forbidden_open = runtime.root.forms.release_barriers[&barrier_ref].clone();
        forbidden_open.state = BarrierState::Open;
        forbidden_open.observer_join_ref = Some(join_ref.clone());
        forbidden_open.released_refs = forbidden_open.dependent_refs.clone();
        let refused = RuntimeOperation::EvaluateReleaseBarrier {
            context: context(runtime, &format!("{prefix}.operation.barrier.forbidden")),
            expected_state: BarrierState::Closed,
            successor: forbidden_open,
        };
        match evaluate_runtime(runtime, &refused) {
            RuntimeEvaluation::Refused { fault } => {
                assert_eq!(fault.kind, RuntimeFaultKind::MissingReference)
            }
            _ => panic!("blocked rear disposition must not release dependents"),
        }
        assert_eq!(runtime, &before_refusal);

        let mut invalidated = runtime.root.forms.release_barriers[&barrier_ref].clone();
        invalidated.state = BarrierState::Invalidated;
        invalidated.observer_join_ref = Some(join_ref.clone());
        let operation = RuntimeOperation::EvaluateReleaseBarrier {
            context: context(runtime, &format!("{prefix}.operation.barrier.invalidate")),
            expected_state: BarrierState::Closed,
            successor: invalidated,
        };
        apply(runtime, operations, operation);

        let mut rejected = runtime.root.forms.capsules[&capsule_ref].clone();
        rejected.state = CapsuleState::Rejected;
        let operation = RuntimeOperation::TransitionCapsule {
            context: context(runtime, &format!("{prefix}.operation.capsule.reject")),
            expected_state: CapsuleState::Reconciled,
            successor: rejected,
        };
        apply(runtime, operations, operation);
    }
    TandemResult {
        capsule_ref,
        barrier_ref,
        join_ref,
    }
}

fn preserve_deviation(runtime: &mut RuntimeSnapshot, operations: &mut Vec<RuntimeOperation>) {
    let payload = b"rear review blocked objective.b and exposed objective.repair";
    let input = content("content.deviation", payload, "text/plain");
    let event = material_event(
        "event.deviation",
        "generation.two",
        "content.deviation",
        &["walk.deviation", "objective.b", "objective.repair"],
        &["event.observation"],
    );
    let snapshot = semantic_snapshot(
        "snapshot.two",
        &["snapshot.one"],
        &["event.observation", "event.deviation"],
        &["content.observation", "content.deviation"],
        b"objective a observed; objective b blocked pending repair",
    );
    let operation = RuntimeOperation::CompareAndAppend {
        context: context(runtime, "integration.repository.deviation"),
        branch_ref: id("branch.main"),
        expected_generation_ref: Some(id("generation.two")),
        generation: candidate_generation(
            "generation.three",
            &["generation.two"],
            &["event.observation", "event.deviation"],
            Some("snapshot.two"),
        ),
        content: vec![input],
        events: vec![event],
        snapshot: Some(snapshot),
    };
    apply(runtime, operations, operation);
}

fn propose_repaired_plan(runtime: &mut RuntimeSnapshot, operations: &mut Vec<RuntimeOperation>) {
    let plan = PlanRevision {
        plan_id: id("plan.integration"),
        revision_id: id("plan.integration.rev2"),
        predecessor_revision_ref: Some(id("plan.integration.rev1")),
        task_ref: id("task.one"),
        objective_refs: ids(&["objective.repair", "objective.b", "objective.c"]),
        dependency_refs: ids(&["dependency.repair.b", "dependency.b.c"]),
        temporal_refs: ids(&["calendar.integration.rev1"]),
        effect_refs: BTreeSet::new(),
        review_refs: ids(&["review.integration"]),
        selected_alternative_ref: None,
        assumptions: texts(&["rear-exposed repair is required before objective b"]),
        uncertainty: texts(&["simulated observation only"]),
        state: PlanState::Proposed,
    };
    let operation = RuntimeOperation::ProposePlan {
        context: context(runtime, "integration.plan.repaired"),
        plan,
        repository_generation_ref: id("generation.three"),
        calendar_revision_refs: ids(&["calendar.integration.rev1"]),
        proof_gate_refs: ids(&["review.integration"]),
        available_resource_refs: ids(&["resource.fixture"]),
    };
    let receipt = apply(runtime, operations, operation);
    match receipt.output {
        RuntimeOutput::PlanProposal {
            objective_order, ..
        } => assert_eq!(
            objective_order,
            vec![id("objective.repair"), id("objective.b"), id("objective.c")]
        ),
        other => panic!("repaired plan proposal expected, observed {other:?}"),
    }
}

fn compiler_content(identity: &str, value: &[u8]) -> ContentInput {
    let media_type = if identity.starts_with("source.") {
        "application/vnd.cantor.sop"
    } else if identity.starts_with("semantic.") {
        "application/vnd.cantor.semantic-ir+json"
    } else if identity.starts_with("build.") {
        "application/vnd.cantor.build-ir+json"
    } else if identity.starts_with("target.") {
        "application/vnd.cantor.target-metadata+json"
    } else if identity.starts_with("corr.") {
        "application/vnd.cantor.correspondence+json"
    } else {
        "application/vnd.cantor.proof+json"
    };
    content(identity, value, media_type)
}

fn compiler_inputs() -> Vec<ContentInput> {
    vec![
        compiler_content("source.compiler.before", b"Subject: Original path"),
        compiler_content(
            "source.compiler.candidate",
            b"Subject: Repaired path with explicit prerequisite",
        ),
        compiler_content("semantic.compiler.before", b"semantic path a-b-c"),
        compiler_content("semantic.compiler.candidate", b"semantic path repair-b-c"),
        compiler_content("build.compiler.candidate", b"build repaired plan"),
        compiler_content("target.compiler.metadata", b"effectless target metadata"),
        compiler_content("corr.compiler.forward", b"forward correspondence"),
        compiler_content("corr.compiler.rear", b"independent rear correspondence"),
        compiler_content("proof.compiler.bundle", b"bounded integration proof"),
    ]
}

fn input_digest(inputs: &[ContentInput], identity: &str) -> cantor_core::ContentDigest {
    inputs
        .iter()
        .find(|input| input.object.object_id == id(identity))
        .expect("compiler content exists")
        .object
        .digest
        .clone()
}

fn diff_kinds() -> BTreeSet<DiffKind> {
    [
        DiffKind::Physical,
        DiffKind::Source,
        DiffKind::Semantic,
        DiffKind::Build,
        DiffKind::Behavioral,
        DiffKind::Effect,
        DiffKind::Proof,
        DiffKind::Calendar,
    ]
    .into_iter()
    .collect()
}

fn diff_label(kind: DiffKind) -> &'static str {
    match kind {
        DiffKind::Physical => "physical",
        DiffKind::Source => "source",
        DiffKind::Semantic => "semantic",
        DiffKind::Build => "build",
        DiffKind::Behavioral => "behavioral",
        DiffKind::Effect => "effect",
        DiffKind::Proof => "proof",
        DiffKind::Calendar => "calendar",
    }
}

fn diff_ref(kind: DiffKind) -> SemanticId {
    id(&format!("diff.integration.compiler.{}", diff_label(kind)))
}

fn compiler_subjects() -> BTreeSet<SemanticId> {
    let mut subjects = ids(&[
        "compiler.integration.candidate",
        "compiler.integration.checked",
        "impact.integration.compiler",
        "prediction.integration.compiler",
        "rear.integration.compiler",
        "corr.compiler.rear",
        "proof.compiler.bundle",
    ]);
    subjects.extend(diff_kinds().into_iter().map(diff_ref));
    subjects
}

fn compiler_generations(inputs: &[ContentInput]) -> (CompilerGeneration, CompilerGeneration) {
    let before = CompilerGeneration {
        compiler_generation_id: id("compiler.integration.before"),
        predecessor_generation_refs: BTreeSet::new(),
        source_generation_refs: ids(&["source.compiler.before"]),
        dependency_lock_ref: id("lock.integration.before"),
        language_profile_ref: id("language.fixture"),
        compiler_identity_ref: id("compiler.fixture.identity"),
        semantic_ir_root: input_digest(inputs, "semantic.compiler.before"),
        target_profile_refs: ids(&["target.fixture"]),
        target_artifact_refs: BTreeSet::new(),
        correspondence_evidence_refs: BTreeSet::new(),
        independent_correspondence_evidence_refs: BTreeSet::new(),
        loss_records: BTreeSet::new(),
        diagnostics: BTreeSet::new(),
        proof_bundle_ref: id("proof.before"),
        stage: CompilerStage::Projected,
    };
    let candidate = CompilerGeneration {
        compiler_generation_id: id("compiler.integration.candidate"),
        predecessor_generation_refs: ids(&["compiler.integration.before"]),
        source_generation_refs: ids(&["source.compiler.candidate"]),
        dependency_lock_ref: id("lock.integration.candidate"),
        language_profile_ref: id("language.fixture"),
        compiler_identity_ref: id("compiler.fixture.identity"),
        semantic_ir_root: input_digest(inputs, "semantic.compiler.candidate"),
        target_profile_refs: ids(&["target.fixture"]),
        target_artifact_refs: ids(&["target.compiler.metadata"]),
        correspondence_evidence_refs: ids(&["corr.compiler.forward"]),
        independent_correspondence_evidence_refs: ids(&["corr.compiler.rear"]),
        loss_records: texts(&["unknown: no target execution performed"]),
        diagnostics: texts(&["repaired prerequisite changes downstream plan IR"]),
        proof_bundle_ref: id("proof.compiler.bundle"),
        stage: CompilerStage::Projected,
    };
    (before, candidate)
}

fn compiler_impact() -> CompilerImpact {
    CompilerImpact {
        impact_id: id("impact.integration.compiler"),
        compiler_generation_ref: id("compiler.integration.candidate"),
        changed_source_refs: ids(&["source.compiler.candidate"]),
        changed_semantic_refs: ids(&["semantic.compiler.candidate"]),
        invalidated_ir_refs: ids(&["plan.integration.rev1"]),
        invalidated_index_refs: BTreeSet::new(),
        invalidated_package_refs: BTreeSet::new(),
        invalidated_schedule_refs: ids(&["calendar.integration.rev1"]),
        invalidated_workflow_refs: ids(&["objective.b"]),
        invalidated_model_refs: BTreeSet::new(),
        invalidated_tool_schema_refs: BTreeSet::new(),
        invalidated_hardware_refs: BTreeSet::new(),
    }
}

fn compiler_diffs() -> Vec<DiffRecord> {
    diff_kinds()
        .into_iter()
        .map(|kind| {
            let changed_refs = match kind {
                DiffKind::Source => ids(&["source.compiler.candidate"]),
                DiffKind::Semantic => ids(&["semantic.compiler.candidate"]),
                _ => BTreeSet::new(),
            };
            let invalidations = if kind == DiffKind::Semantic {
                [
                    (
                        "invalidation.integration.plan",
                        "semantic.compiler.candidate",
                        "plan.integration.rev1",
                        "replace stale plan with repaired revision",
                    ),
                    (
                        "invalidation.integration.calendar",
                        "semantic.compiler.candidate",
                        "calendar.integration.rev1",
                        "recheck schedule against repaired path",
                    ),
                    (
                        "invalidation.integration.objective",
                        "semantic.compiler.candidate",
                        "objective.b",
                        "hold dependent until repair release",
                    ),
                ]
                .into_iter()
                .map(|(edge_id, cause, subject, action)| {
                    let edge = InvalidationEdge {
                        invalidation_id: id(edge_id),
                        cause_ref: id(cause),
                        source_generation_ref: id("compiler.integration.candidate"),
                        affected_subject_ref: id(subject),
                        required_action: action.to_owned(),
                        severity: ConstraintSeverity::Blocking,
                        resolution_ref: Some(id("plan.integration.rev2")),
                    };
                    (edge.invalidation_id.clone(), edge)
                })
                .collect()
            } else {
                BTreeMap::new()
            };
            DiffRecord {
                diff_id: diff_ref(kind),
                kind,
                before_subject_ref: id("compiler.integration.before"),
                candidate_subject_ref: id("compiler.integration.candidate"),
                added_refs: BTreeSet::new(),
                changed_refs,
                removed_refs: BTreeSet::new(),
                preserved_refs: ids(&["unrelated.stable"]),
                unrelated_refs: ids(&["unrelated.stable"]),
                derivation_method: "independent fixed integration rear comparator".to_owned(),
                independent_evidence_refs: ids(&["corr.compiler.rear"]),
                confidence_or_completeness: "complete for bounded integration fixture".to_owned(),
                invalidations,
                loss_and_unknown: texts(&["unknown: external execution not performed"]),
            }
        })
        .collect()
}

fn run_compiler_fixture(runtime: &mut RuntimeSnapshot, operations: &mut Vec<RuntimeOperation>) {
    let inputs = compiler_inputs();
    let (before_generation, candidate_generation) = compiler_generations(&inputs);
    let manifest = CompilerFixtureManifest {
        fixture_id: id("fixture.integration.compiler"),
        before_generation_ref: id("compiler.integration.before"),
        candidate_generation_ref: id("compiler.integration.candidate"),
        source_object_refs: ids(&["source.compiler.before", "source.compiler.candidate"]),
        semantic_ir_object_refs: ids(&["semantic.compiler.before", "semantic.compiler.candidate"]),
        build_ir_object_refs: ids(&["build.compiler.candidate"]),
        target_metadata_object_refs: ids(&["target.compiler.metadata"]),
        correspondence_evidence_refs: ids(&["corr.compiler.forward"]),
        independent_correspondence_evidence_refs: ids(&["corr.compiler.rear"]),
        proof_record_refs: ids(&["proof.compiler.bundle"]),
        required_diff_kinds: diff_kinds(),
        declared_unrelated_refs: ids(&["unrelated.stable"]),
        observer_join_ref: id("integration.compiler.join"),
        max_fixture_records: 32,
    };
    let operation = RuntimeOperation::RegisterCompilerFixture {
        context: context(runtime, "integration.compiler.register"),
        manifest,
        before_generation: Box::new(before_generation),
        candidate_generation: Box::new(candidate_generation),
        impact: Box::new(compiler_impact()),
        content: inputs,
        diffs: compiler_diffs(),
    };
    apply(runtime, operations, operation);
    let operation = RuntimeOperation::RunCompilerForward {
        context: context(runtime, "integration.compiler.forward"),
        fixture_ref: id("fixture.integration.compiler"),
        prediction_id: id("prediction.integration.compiler"),
    };
    apply(runtime, operations, operation);
    let operation = RuntimeOperation::RunCompilerRear {
        context: context(runtime, "integration.compiler.rear"),
        fixture_ref: id("fixture.integration.compiler"),
        rear_check_id: id("rear.integration.compiler"),
    };
    let receipt = apply(runtime, operations, operation);
    match receipt.output {
        RuntimeOutput::CompilerRearCheck {
            rear_check,
            invalidated_refs,
        } => {
            assert!(rear_check.matched_forward_prediction);
            assert!(invalidated_refs.is_empty());
        }
        other => panic!("compiler rear check expected, observed {other:?}"),
    }
    let operation = RuntimeOperation::CheckCompilerFixture {
        context: context(runtime, "integration.compiler.check"),
        fixture_ref: id("fixture.integration.compiler"),
        checked_generation_id: id("compiler.integration.checked"),
    };
    apply(runtime, operations, operation);
}

fn advance_time(
    runtime: &mut RuntimeSnapshot,
    operations: &mut Vec<RuntimeOperation>,
    operation_id: &str,
) {
    let operation = RuntimeOperation::AdvanceLogicalTime {
        context: context(runtime, operation_id),
        delta: 1,
    };
    apply(runtime, operations, operation);
}

struct IntegratedWalk {
    initial: RuntimeSnapshot,
    operations: Vec<RuntimeOperation>,
    final_snapshot: RuntimeSnapshot,
    deviated: TandemResult,
    repaired: TandemResult,
    compiler: TandemResult,
}

fn integrated_walk() -> IntegratedWalk {
    let initial = integration_initial();
    let mut runtime = initial.clone();
    let mut operations = Vec::new();

    initialize_repository(&mut runtime, &mut operations);
    append_initial_observation(&mut runtime, &mut operations);
    install_calendar(&mut runtime, &mut operations);
    propose_initial_plan(&mut runtime, &mut operations);
    advance_time(
        &mut runtime,
        &mut operations,
        "integration.time.begin-first-step",
    );

    open_tandem(
        &mut runtime,
        &mut operations,
        "integration.deviation",
        "plan.integration.rev1",
        "generation.two",
        "snapshot.one",
        "candidate.objective.a",
        Some("execution.outcome.deviation"),
        &["objective.b"],
    );
    let deviated = complete_tandem(
        &mut runtime,
        &mut operations,
        "integration.deviation",
        "plan.integration.rev1",
        "generation.two",
        "candidate.objective.a",
        Some("execution.outcome.deviation"),
        ReflectionDisposition::Block,
        JoinDisposition::Block,
        ids(&["objective.b"]),
        BTreeSet::new(),
    );

    advance_time(
        &mut runtime,
        &mut operations,
        "integration.time.after-deviation",
    );
    preserve_deviation(&mut runtime, &mut operations);
    propose_repaired_plan(&mut runtime, &mut operations);

    open_tandem(
        &mut runtime,
        &mut operations,
        "integration.repair",
        "plan.integration.rev2",
        "generation.three",
        "snapshot.two",
        "candidate.objective.repair",
        None,
        &["objective.b"],
    );
    let repaired = complete_tandem(
        &mut runtime,
        &mut operations,
        "integration.repair",
        "plan.integration.rev2",
        "generation.three",
        "candidate.objective.repair",
        None,
        ReflectionDisposition::Qualify,
        JoinDisposition::Qualify,
        BTreeSet::new(),
        BTreeSet::new(),
    );

    advance_time(
        &mut runtime,
        &mut operations,
        "integration.time.compiler-review",
    );
    open_tandem(
        &mut runtime,
        &mut operations,
        "integration.compiler",
        "plan.integration.rev2",
        "generation.three",
        "snapshot.two",
        "compiler.integration.candidate",
        None,
        &["compiler.integration.check"],
    );
    let compiler = complete_tandem(
        &mut runtime,
        &mut operations,
        "integration.compiler",
        "plan.integration.rev2",
        "generation.three",
        "compiler.integration.candidate",
        None,
        ReflectionDisposition::Qualify,
        JoinDisposition::Qualify,
        BTreeSet::new(),
        compiler_subjects(),
    );
    run_compiler_fixture(&mut runtime, &mut operations);

    IntegratedWalk {
        initial,
        operations,
        final_snapshot: runtime,
        deviated,
        repaired,
        compiler,
    }
}

#[test]
fn logical_time_three_step_walk_blocks_deviation_replans_releases_and_checks_compiler() {
    let walk = integrated_walk();
    assert_eq!(walk.final_snapshot.root.logical_clock.tick, 3);
    assert_eq!(
        walk.final_snapshot.root.planner.latest_plan_revision_ref,
        Some(id("plan.integration.rev2"))
    );
    assert_eq!(
        walk.final_snapshot.root.planner.last_objective_order,
        vec![id("objective.repair"), id("objective.b"), id("objective.c")]
    );
    assert_eq!(
        walk.final_snapshot.root.forms.capsules[&walk.deviated.capsule_ref].state,
        CapsuleState::Rejected
    );
    assert_eq!(
        walk.final_snapshot.root.forms.release_barriers[&walk.deviated.barrier_ref].state,
        BarrierState::Invalidated
    );
    assert_eq!(
        walk.final_snapshot.root.forms.observer_joins[&walk.deviated.join_ref].disposition,
        JoinDisposition::Block
    );
    assert_eq!(
        walk.final_snapshot.root.forms.release_barriers[&walk.repaired.barrier_ref].state,
        BarrierState::Open
    );
    assert_eq!(
        walk.final_snapshot.root.forms.release_barriers[&walk.repaired.barrier_ref].released_refs,
        ids(&["objective.b"])
    );
    assert_eq!(
        walk.final_snapshot.root.forms.release_barriers[&walk.compiler.barrier_ref].state,
        BarrierState::Open
    );
    assert_eq!(
        walk.final_snapshot.root.compiler.fixtures[&id("fixture.integration.compiler")].status,
        CompilerFixtureStatus::Checked
    );
    assert_eq!(
        walk.final_snapshot.root.forms.compiler_generations[&id("compiler.integration.candidate")]
            .stage,
        CompilerStage::Projected
    );
    assert_eq!(
        walk.final_snapshot.root.forms.compiler_generations[&id("compiler.integration.checked")]
            .stage,
        CompilerStage::ProofChecked
    );
    assert_eq!(
        walk.final_snapshot.root.repository.content_bytes[&id("content.deviation")],
        b"rear review blocked objective.b and exposed objective.repair"
    );

    let replay = replay_runtime(&walk.initial, &walk.operations).expect("full walk replays");
    assert_eq!(replay.receipts.len(), walk.operations.len());
    assert_eq!(replay.final_snapshot, walk.final_snapshot);
    let expected = to_normalized_runtime_snapshot(&walk.final_snapshot).expect("final normalizes");
    let replayed =
        to_normalized_runtime_snapshot(&replay.final_snapshot).expect("replay normalizes");
    assert_eq!(replayed, expected);
    assert_eq!(
        from_normalized_runtime_snapshot(&expected).expect("normalized final restores"),
        walk.final_snapshot
    );
}

#[test]
fn replay_refuses_permutation_stale_binding_and_missing_final_proof() {
    let walk = integrated_walk();
    let mut permuted = walk.operations.clone();
    permuted.swap(0, 1);
    let fault = replay_runtime(&walk.initial, &permuted).expect_err("permutation must refuse");
    assert_eq!(fault.kind, RuntimeFaultKind::StalePredecessor);

    let mut stale = walk.operations.clone();
    match &mut stale[0] {
        RuntimeOperation::CompareAndAppend { context, .. } => {
            context.expected_root_digest = sha256_bytes(b"stale root");
        }
        other => panic!("first integrated operation changed unexpectedly: {other:?}"),
    }
    let fault = replay_runtime(&walk.initial, &stale).expect_err("stale root must refuse");
    assert_eq!(fault.kind, RuntimeFaultKind::StalePredecessor);

    let incomplete = replay_runtime(&walk.initial, &walk.operations[..walk.operations.len() - 1])
        .expect("prefix before the proof-check operation remains replayable");
    assert_eq!(
        incomplete.final_snapshot.root.compiler.fixtures[&id("fixture.integration.compiler")]
            .status,
        CompilerFixtureStatus::RearCompared
    );
    assert!(
        !incomplete
            .final_snapshot
            .root
            .forms
            .compiler_generations
            .contains_key(&id("compiler.integration.checked"))
    );
}

#[test]
fn adversarial_false_shortcuts_never_replay_as_success() {
    let walk = integrated_walk();

    let mut false_commitment = walk.operations.clone();
    let plan = false_commitment
        .iter_mut()
        .find_map(|operation| match operation {
            RuntimeOperation::ProposePlan { plan, .. }
                if plan.revision_id == id("plan.integration.rev1") =>
            {
                Some(plan)
            }
            _ => None,
        })
        .expect("initial plan operation exists");
    plan.state = PlanState::Active;
    let fault = replay_runtime(&walk.initial, &false_commitment)
        .expect_err("a proposal operation must not smuggle an active plan");
    assert_eq!(fault.kind, RuntimeFaultKind::InvalidForm);

    let mut fabricated_atomic_snapshot = walk.operations.clone();
    let snapshot = fabricated_atomic_snapshot
        .iter_mut()
        .find_map(|operation| match operation {
            RuntimeOperation::CompareAndAppend {
                snapshot: Some(snapshot),
                ..
            } if snapshot.snapshot_id == id("snapshot.one") => Some(snapshot),
            _ => None,
        })
        .expect("initial semantic snapshot operation exists");
    snapshot.atomic_external_world_claim = true;
    let fault = replay_runtime(&walk.initial, &fabricated_atomic_snapshot)
        .expect_err("a fabricated atomic external-world claim must refuse");
    assert_eq!(fault.kind, RuntimeFaultKind::InvalidForm);

    let mut mixed_unrelated_diff = walk.operations.clone();
    let diffs = mixed_unrelated_diff
        .iter_mut()
        .find_map(|operation| match operation {
            RuntimeOperation::RegisterCompilerFixture { diffs, .. } => Some(diffs),
            _ => None,
        })
        .expect("compiler registration operation exists");
    diffs
        .iter_mut()
        .find(|diff| diff.kind == DiffKind::Semantic)
        .expect("semantic diff exists")
        .invalidations
        .values_mut()
        .next()
        .expect("semantic invalidation exists")
        .affected_subject_ref = id("unrelated.stable");
    let fault = replay_runtime(&walk.initial, &mixed_unrelated_diff)
        .expect_err("declared unrelated state must not enter the invalidation set");
    assert_eq!(fault.kind, RuntimeFaultKind::IncompleteDiff);
}

#[test]
fn generated_capsule_and_lane_transition_tables_are_exact() {
    let capsule_states = [
        CapsuleState::Opened,
        CapsuleState::Prepared,
        CapsuleState::ExecutionRequested,
        CapsuleState::EffectObserved,
        CapsuleState::ReflectionRequested,
        CapsuleState::ReflectionReturned,
        CapsuleState::Reconciled,
        CapsuleState::Admitted,
        CapsuleState::Rejected,
        CapsuleState::Unresolved,
        CapsuleState::Reverted,
        CapsuleState::Compensated,
    ];
    for from in capsule_states {
        for to in capsule_states {
            let expected = matches!(
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
            assert_eq!(
                validate_capsule_transition(from, to).is_ok(),
                expected,
                "capsule transition {from:?} -> {to:?}"
            );
        }
    }

    let lane_states = [
        LaneState::Idle,
        LaneState::Prepared,
        LaneState::Running,
        LaneState::BlockedOnAuthority,
        LaneState::BlockedOnReflection,
        LaneState::Returned,
        LaneState::Released,
        LaneState::Stale,
        LaneState::Invalidated,
        LaneState::TimedOut,
        LaneState::Cancelled,
        LaneState::Failed,
    ];
    for from in lane_states {
        for to in lane_states {
            let terminal = matches!(
                to,
                LaneState::Stale
                    | LaneState::Invalidated
                    | LaneState::TimedOut
                    | LaneState::Cancelled
                    | LaneState::Failed
            );
            let expected = terminal
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
            assert_eq!(
                validate_lane_transition(from, to).is_ok(),
                expected,
                "lane transition {from:?} -> {to:?}"
            );
        }
    }
}

#[test]
fn reconstructed_root_refuses_history_rewrite_after_integrated_walk() {
    let walk = integrated_walk();
    let mut root = walk.final_snapshot.root;
    root.tandem
        .capsule_state_history
        .get_mut(&walk.repaired.capsule_ref)
        .expect("repaired capsule history exists")
        .remove(0);
    assert!(RuntimeSnapshot::from_root(root).is_err());
}
