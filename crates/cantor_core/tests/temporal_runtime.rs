use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{
    AuthorityState, CalendarItem, CalendarKind, CalendarLifecycleState, CapsuleState,
    ChangeCapsule, ContentDigest, ContentInput, ContentObject, DeclaredIntent, DependencyEdge,
    DependencyKind, DeterministicRuntimeRoot, EventKind, MaterialEvent, MaterialityDecision,
    MaterialityDisposition, MaterialityPolicy, ObjectiveNode, ObjectiveStatus, OperationLimits,
    PlanRevision, PlanState, ProviderSyncState, RecurrenceRule, RepositoryGeneration,
    RepositoryStatus, RuntimeBounds, RuntimeEvaluation, RuntimeFaultKind, RuntimeOperation,
    RuntimeOperationContext, RuntimeOutput, RuntimePolicies, RuntimeSnapshot, SemanticId,
    SemanticSnapshot, SensitivityClass, TaskContract, TemporalFormSet, TimeDomain, TimeExpression,
    TimeValue, WakeCondition, WakeRevalidationContext, digest_material_event,
    digest_repository_generation, digest_semantic_snapshot, evaluate_runtime,
    from_normalized_runtime_snapshot, replay_runtime, sha256_bytes, to_normalized_runtime_snapshot,
};

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity is valid")
}

fn ids(values: &[&str]) -> BTreeSet<SemanticId> {
    values.iter().map(|value| id(value)).collect()
}

fn texts(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn digest(value: &str) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: value.to_owned(),
    }
}

fn base_forms() -> TemporalFormSet {
    let mut forms = TemporalFormSet::new();
    forms.time_expressions.insert(
        id("time.logical.0"),
        TimeExpression {
            time_expression_id: id("time.logical.0"),
            domain: TimeDomain::Logical,
            value: TimeValue::Point {
                value: "0".to_owned(),
            },
            source_ref: id("source.fixture"),
            zone: None,
            calendar_system: None,
            precision: "exact".to_owned(),
            uncertainty_interval: None,
            interpretation_policy_ref: None,
            conversion_evidence_refs: BTreeSet::new(),
            valid_from_ref: None,
            valid_to_ref: None,
            recorded_at_ref: None,
        },
    );
    forms.task_contracts.insert(
        id("task.one"),
        TaskContract {
            task_id: id("task.one"),
            purpose: "prove deterministic runtime behavior".to_owned(),
            source_ref: id("source.fixture"),
            principal_refs: ids(&["principal.one"]),
            input_refs: BTreeSet::new(),
            target_refs: ids(&["target.one"]),
            preconditions: BTreeSet::new(),
            assumptions: BTreeSet::new(),
            invariants: texts(&["no external effects"]),
            authority_request_refs: BTreeSet::new(),
            effect_boundary: texts(&["returned immutable values only"]),
            completion_criteria: texts(&["proof fixtures pass"]),
            stop_conditions: texts(&["effect required"]),
            privacy_profile_ref: id("privacy.fixture"),
            retention_profile_ref: id("retention.fixture"),
            current_plan_revision_ref: None,
        },
    );
    for name in ["a", "b", "c"] {
        let objective_id = id(&format!("objective.{name}"));
        forms.objectives.insert(
            objective_id.clone(),
            ObjectiveNode {
                objective_id,
                task_ref: id("task.one"),
                statement: format!("complete objective {name}"),
                desired_state_criteria: texts(&["complete"]),
                priority_source_ref: id("source.priority"),
                uncertainty: BTreeSet::new(),
                status: ObjectiveStatus::Eligible,
                proof_route: texts(&["fixture"]),
            },
        );
    }
    forms.dependencies.insert(
        id("dependency.a.c"),
        DependencyEdge {
            edge_id: id("dependency.a.c"),
            predecessor_ref: id("objective.a"),
            successor_objective_ref: id("objective.c"),
            kind: DependencyKind::Objective,
            condition: "a completes before c".to_owned(),
            strength: "required".to_owned(),
            source_ref: id("source.fixture"),
            invalidation_rule: "invalidate c when a changes".to_owned(),
        },
    );
    forms.materiality_policies.insert(
        id("materiality.rev1"),
        MaterialityPolicy {
            policy_id: id("materiality.one"),
            revision_id: id("materiality.rev1"),
            predecessor_revision_ref: None,
            durable_event_kinds: BTreeSet::from([EventKind::Observation]),
            micro_event_purposes: texts(&["heartbeat"]),
            aggregation_method: "none".to_owned(),
            loss_policy: "no loss".to_owned(),
            rehydration_policy: "exact payload".to_owned(),
            retention_profile_ref: id("retention.fixture"),
            applies_from_generation_ref: id("generation.one"),
        },
    );
    forms
}

fn initial_runtime() -> RuntimeSnapshot {
    let mut policies = RuntimePolicies::default();
    policies.objective_priority.insert(id("objective.b"), 0);
    policies.objective_priority.insert(id("objective.a"), 1);
    policies
        .recognized_resource_refs
        .insert(id("resource.fixture"));
    RuntimeSnapshot::new(
        id("repository.one"),
        id("clock.logical"),
        base_forms(),
        policies,
        RuntimeBounds::default(),
    )
    .expect("initial runtime is valid")
}

fn context(snapshot: &RuntimeSnapshot, operation_id: &str) -> RuntimeOperationContext {
    RuntimeOperationContext {
        operation_id: id(operation_id),
        caller_id: id("caller.fixture"),
        expected_root_digest: snapshot.root_digest.clone(),
        limits: OperationLimits::default(),
    }
}

fn accepted(evaluation: RuntimeEvaluation) -> (RuntimeSnapshot, cantor_core::RuntimeReceipt) {
    match evaluation {
        RuntimeEvaluation::Accepted { successor, receipt } => (*successor, *receipt),
        RuntimeEvaluation::Refused { fault } => panic!("operation refused: {fault:?}"),
    }
}

fn candidate_generation(
    generation_id: &str,
    predecessors: &[&str],
    frontier: &[&str],
    snapshot_ref: Option<&str>,
) -> RepositoryGeneration {
    let mut generation = RepositoryGeneration {
        repository_id: id("repository.one"),
        generation_id: id(generation_id),
        predecessor_generation_refs: ids(predecessors),
        repository_policy_ref: id("repository.policy"),
        event_frontier: ids(frontier),
        snapshot_root_ref: snapshot_ref.map(id),
        reference_index_generation_ref: None,
        created_by_disposition_ref: None,
        root_digest: digest("placeholder"),
        status: RepositoryStatus::Candidate,
    };
    generation.root_digest =
        digest_repository_generation(&generation).expect("generation digest serializes");
    generation
}

fn initialize_repository(snapshot: &RuntimeSnapshot) -> RuntimeSnapshot {
    let operation = RuntimeOperation::CompareAndAppend {
        context: context(snapshot, "operation.repository.initialize"),
        branch_ref: id("branch.main"),
        expected_generation_ref: None,
        generation: candidate_generation("generation.one", &[], &[], None),
        content: Vec::new(),
        events: Vec::new(),
        snapshot: None,
    };
    accepted(evaluate_runtime(snapshot, &operation)).0
}

fn append_observation(snapshot: &RuntimeSnapshot) -> RuntimeSnapshot {
    let payload = b"faithful observation".to_vec();
    let object = ContentObject {
        object_id: id("content.observation"),
        digest: sha256_bytes(&payload),
        byte_length: payload.len() as u64,
        media_type: "text/plain".to_owned(),
        encoding: "utf-8".to_owned(),
        provenance_refs: ids(&["source.fixture"]),
        sensitivity: SensitivityClass::ProjectInternal,
        retention_profile_ref: id("retention.fixture"),
        storage_locators: BTreeSet::new(),
    };
    let mut event = MaterialEvent {
        event_id: id("event.observation"),
        repository_generation_input_ref: id("generation.one"),
        task_ref: Some(id("task.one")),
        attribution_ref: Some(id("attribution.fixture")),
        kind: EventKind::Observation,
        subject_refs: ids(&["target.one"]),
        content_object_refs: ids(&["content.observation"]),
        valid_time_ref: None,
        transaction_time_ref: id("time.logical.0"),
        materiality: MaterialityDecision {
            policy_ref: id("materiality.rev1"),
            evidence_refs: ids(&["evidence.fixture"]),
            disposition: MaterialityDisposition::Capture,
            reason: "changes faithful replay".to_owned(),
        },
        authority_refs: BTreeSet::new(),
        effect_refs: BTreeSet::new(),
        predecessor_event_refs: BTreeSet::new(),
        retention_profile_ref: id("retention.fixture"),
        sensitivity: SensitivityClass::ProjectInternal,
        event_digest: digest("placeholder"),
    };
    event.event_digest = digest_material_event(&event).expect("event digest serializes");
    let mut semantic_snapshot = SemanticSnapshot {
        snapshot_id: id("snapshot.one"),
        repository_id: id("repository.one"),
        predecessor_snapshot_refs: BTreeSet::new(),
        event_frontier: ids(&["event.observation"]),
        canonical_state_root: sha256_bytes(b"semantic state one"),
        projection_manifest_ref: None,
        content_object_refs: ids(&["content.observation"]),
        reconciliation_evidence_refs: ids(&["evidence.fixture"]),
        loss_records: BTreeSet::new(),
        atomic_external_world_claim: false,
        snapshot_digest: digest("placeholder"),
    };
    semantic_snapshot.snapshot_digest =
        digest_semantic_snapshot(&semantic_snapshot).expect("snapshot digest serializes");
    let operation = RuntimeOperation::CompareAndAppend {
        context: context(snapshot, "operation.repository.append"),
        branch_ref: id("branch.main"),
        expected_generation_ref: Some(id("generation.one")),
        generation: candidate_generation(
            "generation.two",
            &["generation.one"],
            &["event.observation"],
            Some("snapshot.one"),
        ),
        content: vec![ContentInput {
            object,
            bytes: payload,
        }],
        events: vec![event],
        snapshot: Some(semantic_snapshot),
    };
    accepted(evaluate_runtime(snapshot, &operation)).0
}

fn calendar_revision(snapshot: &RuntimeSnapshot) -> RuntimeSnapshot {
    let recurrence = RecurrenceRule {
        recurrence_id: id("recurrence.one"),
        revision_id: id("recurrence.one.rev1"),
        predecessor_revision_ref: None,
        frequency: "daily".to_owned(),
        interval: 1,
        zone: "UTC".to_owned(),
        calendar_system: "gregorian".to_owned(),
        start_boundary_ref: id("time.logical.0"),
        end_boundary_ref: None,
        occurrence_limit: Some(3),
        inclusion_keys: texts(&["day.3"]),
        exception_keys: texts(&["day.2"]),
        materialization_horizon_ref: id("time.logical.0"),
    };
    let item = CalendarItem {
        calendar_item_id: id("calendar.one"),
        revision_id: id("calendar.one.rev1"),
        predecessor_revision_ref: None,
        kind: CalendarKind::Task,
        task_ref: Some(id("task.one")),
        purpose: "review the observation".to_owned(),
        source_ref: id("source.fixture"),
        owner_refs: ids(&["principal.one"]),
        participant_refs: BTreeSet::new(),
        time_expression_refs: ids(&["time.logical.0"]),
        recurrence_rule_ref: Some(id("recurrence.one")),
        dependency_refs: BTreeSet::new(),
        review_refs: ids(&["review.one"]),
        authority_state: AuthorityState::Granted,
        lifecycle_state: CalendarLifecycleState::Committed,
        provider_sync_state: ProviderSyncState::LocalOnly,
        field_sensitivity: BTreeMap::new(),
        disclosure_refs: BTreeSet::new(),
    };
    let wake = WakeCondition {
        wake_id: id("wake.one"),
        calendar_item_ref: id("calendar.one.rev1"),
        condition: "logical due condition supplied".to_owned(),
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
        context: context(snapshot, "operation.calendar.revise"),
        recurrence: Some(recurrence),
        item,
        wake_conditions: vec![wake],
    };
    accepted(evaluate_runtime(snapshot, &operation)).0
}

fn propose_plan(snapshot: &RuntimeSnapshot) -> RuntimeSnapshot {
    let plan = PlanRevision {
        plan_id: id("plan.one"),
        revision_id: id("plan.one.rev1"),
        predecessor_revision_ref: None,
        task_ref: id("task.one"),
        objective_refs: ids(&["objective.a", "objective.b", "objective.c"]),
        dependency_refs: ids(&["dependency.a.c"]),
        temporal_refs: ids(&["calendar.one.rev1"]),
        effect_refs: BTreeSet::new(),
        review_refs: ids(&["review.one"]),
        selected_alternative_ref: None,
        assumptions: texts(&["fixture resources remain supplied"]),
        uncertainty: BTreeSet::new(),
        state: PlanState::Proposed,
    };
    let operation = RuntimeOperation::ProposePlan {
        context: context(snapshot, "operation.plan.propose"),
        plan,
        repository_generation_ref: id("generation.two"),
        calendar_revision_refs: ids(&["calendar.one.rev1"]),
        proof_gate_refs: ids(&["review.one"]),
        available_resource_refs: ids(&["resource.fixture"]),
    };
    let (successor, receipt) = accepted(evaluate_runtime(snapshot, &operation));
    match receipt.output {
        RuntimeOutput::PlanProposal {
            objective_order, ..
        } => assert_eq!(
            objective_order,
            vec![id("objective.b"), id("objective.a"), id("objective.c")]
        ),
        other => panic!("unexpected output: {other:?}"),
    }
    successor
}

#[test]
fn runtime_snapshot_has_strict_normalized_machine_form() {
    let snapshot = initial_runtime();
    let normalized = to_normalized_runtime_snapshot(&snapshot).unwrap();
    assert_eq!(
        from_normalized_runtime_snapshot(&normalized).unwrap(),
        snapshot
    );
    let spaced = normalized.replacen('{', "{ ", 1);
    assert!(
        from_normalized_runtime_snapshot(&spaced)
            .unwrap_err()
            .message
            .contains("not normalized")
    );
    let unknown = normalized.replacen('{', "{\"unknown\":true,", 1);
    assert!(
        from_normalized_runtime_snapshot(&unknown)
            .unwrap_err()
            .message
            .contains("unknown field")
    );
}

#[test]
fn stale_root_and_zero_time_delta_refuse_without_mutation() {
    let snapshot = initial_runtime();
    let mut stale_context = context(&snapshot, "operation.stale");
    stale_context.expected_root_digest = digest("stale");
    let stale = RuntimeOperation::AdvanceLogicalTime {
        context: stale_context,
        delta: 1,
    };
    match evaluate_runtime(&snapshot, &stale) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::StalePredecessor)
        }
        _ => panic!("stale operation must refuse"),
    }
    let zero = RuntimeOperation::AdvanceLogicalTime {
        context: context(&snapshot, "operation.zero"),
        delta: 0,
    };
    match evaluate_runtime(&snapshot, &zero) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::IllegalTransition)
        }
        _ => panic!("zero delta must refuse"),
    }
    assert_eq!(snapshot.root.logical_clock.tick, 0);
    assert!(snapshot.root.trace.is_empty());
}

#[test]
fn unsupported_profile_duplicate_operation_and_input_bound_fail_closed() {
    let initial = initial_runtime();
    let mut unsupported = initial.clone();
    unsupported.root.runtime_profile = "cantor-cdra-runtime/9.9".to_owned();
    let probe = RuntimeOperation::AdvanceLogicalTime {
        context: context(&unsupported, "operation.unsupported"),
        delta: 1,
    };
    match evaluate_runtime(&unsupported, &probe) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::UnsupportedVersion)
        }
        _ => panic!("unsupported profile must refuse"),
    }

    let first = RuntimeOperation::AdvanceLogicalTime {
        context: context(&initial, "operation.unique"),
        delta: 1,
    };
    let advanced = accepted(evaluate_runtime(&initial, &first)).0;
    let duplicate = RuntimeOperation::AdvanceLogicalTime {
        context: RuntimeOperationContext {
            operation_id: id("operation.unique"),
            caller_id: id("caller.fixture"),
            expected_root_digest: advanced.root_digest.clone(),
            limits: OperationLimits::default(),
        },
        delta: 1,
    };
    match evaluate_runtime(&advanced, &duplicate) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::DuplicateIdentity)
        }
        _ => panic!("duplicate operation must refuse"),
    }

    let mut tiny_context = context(&initial, "operation.too.large");
    tiny_context.limits.max_input_bytes = 1;
    let too_large = RuntimeOperation::AdvanceLogicalTime {
        context: tiny_context,
        delta: 1,
    };
    match evaluate_runtime(&initial, &too_large) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::BoundExhausted)
        }
        _ => panic!("input bound exhaustion must refuse"),
    }
}

#[test]
fn repository_append_verifies_content_frontier_digests_and_index() {
    let initial = initial_runtime();
    let generation_one = initialize_repository(&initial);
    let generation_two = append_observation(&generation_one);
    assert_eq!(
        generation_two.root.repository.current_generation_ref,
        Some(id("generation.two"))
    );
    assert_eq!(
        generation_two.root.repository.index.events_by_subject[&id("target.one")],
        ids(&["event.observation"])
    );
    assert_eq!(
        generation_two.root.repository.content_bytes[&id("content.observation")],
        b"faithful observation"
    );

    let stale_append = RuntimeOperation::CompareAndAppend {
        context: context(&generation_two, "operation.repository.stale"),
        branch_ref: id("branch.main"),
        expected_generation_ref: Some(id("generation.one")),
        generation: candidate_generation("generation.three", &["generation.one"], &[], None),
        content: Vec::new(),
        events: Vec::new(),
        snapshot: None,
    };
    match evaluate_runtime(&generation_two, &stale_append) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::StalePredecessor)
        }
        _ => panic!("stale append must refuse"),
    }
    assert_eq!(
        generation_two.root.repository.current_generation_ref,
        Some(id("generation.two"))
    );
}

#[test]
fn reconstructed_root_rejects_tampered_semantic_record_digests() {
    let runtime = append_observation(&initialize_repository(&initial_runtime()));
    let mut root = runtime.root.clone();
    root.forms
        .material_events
        .get_mut(&id("event.observation"))
        .unwrap()
        .event_digest = digest("tampered");
    let fault = RuntimeSnapshot::from_root(root).expect_err("tampered event must fail");
    assert!(fault.message.contains("material event digest"));
}

#[test]
fn recurrence_is_exception_aware_and_horizon_bounded() {
    let runtime = calendar_revision(&append_observation(&initialize_repository(
        &initial_runtime(),
    )));
    let expand = RuntimeOperation::ExpandRecurrence {
        context: context(&runtime, "operation.recurrence.expand"),
        recurrence_revision_ref: id("recurrence.one.rev1"),
        candidate_occurrence_keys: texts(&["day.1", "day.2"]),
    };
    let (expanded, receipt) = accepted(evaluate_runtime(&runtime, &expand));
    match receipt.output {
        RuntimeOutput::RecurrenceExpansion {
            occurrence_keys, ..
        } => assert_eq!(occurrence_keys, texts(&["day.1", "day.3"])),
        other => panic!("unexpected output: {other:?}"),
    }

    let overflow = RuntimeOperation::ExpandRecurrence {
        context: context(&expanded, "operation.recurrence.overflow"),
        recurrence_revision_ref: id("recurrence.one.rev1"),
        candidate_occurrence_keys: texts(&["day.1", "day.4", "day.5", "day.6"]),
    };
    match evaluate_runtime(&expanded, &overflow) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::RecurrenceHorizon)
        }
        _ => panic!("horizon overflow must refuse"),
    }
}

#[test]
fn materiality_policy_and_calendar_lifecycle_emit_candidates_not_effects() {
    let runtime = calendar_revision(&append_observation(&initialize_repository(
        &initial_runtime(),
    )));
    let classify = RuntimeOperation::ClassifyMateriality {
        context: context(&runtime, "operation.materiality.capture"),
        policy_revision_ref: id("materiality.rev1"),
        event_kind: EventKind::Observation,
        purpose: "durable fixture observation".to_owned(),
        evidence_refs: ids(&["evidence.fixture"]),
    };
    let (classified, receipt) = accepted(evaluate_runtime(&runtime, &classify));
    match receipt.output {
        RuntimeOutput::MaterialityClassification { decision } => {
            assert_eq!(decision.disposition, MaterialityDisposition::Capture);
            assert!(decision.reason.contains("event kind is declared durable"));
        }
        other => panic!("unexpected output: {other:?}"),
    }
    assert_eq!(classified.root.forms.material_events.len(), 1);

    let aggregate = RuntimeOperation::ClassifyMateriality {
        context: context(&classified, "operation.materiality.aggregate"),
        policy_revision_ref: id("materiality.rev1"),
        event_kind: EventKind::ToolResult,
        purpose: "heartbeat".to_owned(),
        evidence_refs: ids(&["evidence.fixture"]),
    };
    let (aggregated, receipt) = accepted(evaluate_runtime(&classified, &aggregate));
    match receipt.output {
        RuntimeOutput::MaterialityClassification { decision } => {
            assert_eq!(decision.disposition, MaterialityDisposition::Aggregate)
        }
        other => panic!("unexpected output: {other:?}"),
    }
    let omit = RuntimeOperation::ClassifyMateriality {
        context: context(&aggregated, "operation.materiality.omit"),
        policy_revision_ref: id("materiality.rev1"),
        event_kind: EventKind::ToolResult,
        purpose: "ephemeral probe".to_owned(),
        evidence_refs: ids(&["evidence.fixture"]),
    };
    let (classified, receipt) = accepted(evaluate_runtime(&aggregated, &omit));
    match receipt.output {
        RuntimeOutput::MaterialityClassification { decision } => {
            assert_eq!(decision.disposition, MaterialityDisposition::Omit)
        }
        other => panic!("unexpected output: {other:?}"),
    }

    let advance = RuntimeOperation::AdvanceLogicalTime {
        context: context(&classified, "operation.calendar.time"),
        delta: 7,
    };
    let advanced = accepted(evaluate_runtime(&classified, &advance)).0;
    let mut successor_item = advanced.root.forms.calendar_items[&id("calendar.one.rev1")].clone();
    successor_item.revision_id = id("calendar.one.rev2");
    successor_item.predecessor_revision_ref = Some(id("calendar.one.rev1"));
    successor_item.lifecycle_state = CalendarLifecycleState::Triggered;
    let due = RuntimeOperation::EvaluateCalendarState {
        context: context(&advanced, "operation.calendar.due"),
        predecessor_revision_ref: id("calendar.one.rev1"),
        successor_item,
        evaluated_at_tick: 7,
        evaluation_kind: cantor_core::CalendarEvaluationKind::Due,
        candidate_event_id: id("event.candidate.calendar.due"),
    };
    let (due_runtime, receipt) = accepted(evaluate_runtime(&advanced, &due));
    match receipt.output {
        RuntimeOutput::CalendarStateEvaluation { candidate, .. } => {
            assert_eq!(candidate.evaluated_at_tick, 7);
            assert_eq!(candidate.lifecycle_state, CalendarLifecycleState::Triggered);
        }
        other => panic!("unexpected output: {other:?}"),
    }
    assert_eq!(
        due_runtime.root.calendar.latest_item_revision[&id("calendar.one")],
        id("calendar.one.rev2")
    );
    assert!(
        !due_runtime
            .root
            .forms
            .material_events
            .contains_key(&id("event.candidate.calendar.due"))
    );
}

#[test]
fn calendar_lifecycle_rejects_wrong_time_and_illegal_state() {
    let runtime = calendar_revision(&append_observation(&initialize_repository(
        &initial_runtime(),
    )));
    let mut successor_item = runtime.root.forms.calendar_items[&id("calendar.one.rev1")].clone();
    successor_item.revision_id = id("calendar.one.rev2");
    successor_item.predecessor_revision_ref = Some(id("calendar.one.rev1"));
    successor_item.lifecycle_state = CalendarLifecycleState::Declined;
    let illegal = RuntimeOperation::EvaluateCalendarState {
        context: context(&runtime, "operation.calendar.illegal"),
        predecessor_revision_ref: id("calendar.one.rev1"),
        successor_item,
        evaluated_at_tick: 1,
        evaluation_kind: cantor_core::CalendarEvaluationKind::Completed,
        candidate_event_id: id("event.candidate.calendar.illegal"),
    };
    match evaluate_runtime(&runtime, &illegal) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::StalePredecessor)
        }
        _ => panic!("wrong logical time must refuse before lifecycle evaluation"),
    }
    let mut illegal_state_item =
        runtime.root.forms.calendar_items[&id("calendar.one.rev1")].clone();
    illegal_state_item.revision_id = id("calendar.one.rev2");
    illegal_state_item.predecessor_revision_ref = Some(id("calendar.one.rev1"));
    illegal_state_item.lifecycle_state = CalendarLifecycleState::Declined;
    let illegal_state = RuntimeOperation::EvaluateCalendarState {
        context: context(&runtime, "operation.calendar.illegal.state"),
        predecessor_revision_ref: id("calendar.one.rev1"),
        successor_item: illegal_state_item,
        evaluated_at_tick: 0,
        evaluation_kind: cantor_core::CalendarEvaluationKind::Completed,
        candidate_event_id: id("event.candidate.calendar.illegal.state"),
    };
    match evaluate_runtime(&runtime, &illegal_state) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::IllegalTransition)
        }
        _ => panic!("illegal lifecycle state must refuse"),
    }
}

#[test]
fn planner_uses_declared_priority_then_stable_identity_under_dependencies() {
    let runtime = calendar_revision(&append_observation(&initialize_repository(
        &initial_runtime(),
    )));
    let planned = propose_plan(&runtime);
    assert_eq!(
        planned.root.planner.last_objective_order,
        vec![id("objective.b"), id("objective.a"), id("objective.c")]
    );
}

#[test]
fn planner_cycle_returns_stable_witness_and_preserves_root() {
    let runtime = calendar_revision(&append_observation(&initialize_repository(
        &initial_runtime(),
    )));
    let mut root: DeterministicRuntimeRoot = runtime.root.clone();
    root.forms.dependencies.insert(
        id("dependency.c.a"),
        DependencyEdge {
            edge_id: id("dependency.c.a"),
            predecessor_ref: id("objective.c"),
            successor_objective_ref: id("objective.a"),
            kind: DependencyKind::Objective,
            condition: "c before a".to_owned(),
            strength: "required".to_owned(),
            source_ref: id("source.fixture"),
            invalidation_rule: "invalidate a".to_owned(),
        },
    );
    let runtime = RuntimeSnapshot::from_root(root).unwrap();
    let plan = PlanRevision {
        plan_id: id("plan.cycle"),
        revision_id: id("plan.cycle.rev1"),
        predecessor_revision_ref: None,
        task_ref: id("task.one"),
        objective_refs: ids(&["objective.a", "objective.c"]),
        dependency_refs: ids(&["dependency.a.c", "dependency.c.a"]),
        temporal_refs: BTreeSet::new(),
        effect_refs: BTreeSet::new(),
        review_refs: BTreeSet::new(),
        selected_alternative_ref: None,
        assumptions: BTreeSet::new(),
        uncertainty: BTreeSet::new(),
        state: PlanState::Proposed,
    };
    let operation = RuntimeOperation::ProposePlan {
        context: context(&runtime, "operation.plan.cycle"),
        plan,
        repository_generation_ref: id("generation.two"),
        calendar_revision_refs: BTreeSet::new(),
        proof_gate_refs: BTreeSet::new(),
        available_resource_refs: BTreeSet::new(),
    };
    match evaluate_runtime(&runtime, &operation) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::Cycle);
            assert_eq!(fault.subject_refs, ids(&["objective.a", "objective.c"]));
        }
        _ => panic!("cyclic plan must refuse"),
    }
    assert!(runtime.root.forms.plan_revisions.is_empty());
}

#[test]
fn wake_emits_only_after_exact_revalidation() {
    let planned = propose_plan(&calendar_revision(&append_observation(
        &initialize_repository(&initial_runtime()),
    )));
    let mut root = planned.root.clone();
    root.forms.declared_intents.insert(
        id("intent.one"),
        DeclaredIntent {
            intent_id: id("intent.one"),
            target_refs: ids(&["target.one"]),
            expected_transformations: texts(&["observe"]),
            allowed_effects: BTreeSet::new(),
            completion_evidence: texts(&["fixture"]),
            unrelated_state_exclusions: BTreeSet::new(),
            source_ref: id("source.fixture"),
        },
    );
    root.forms.capsules.insert(
        id("capsule.one.g1"),
        ChangeCapsule {
            change_id: id("change.one"),
            candidate_generation_id: id("capsule.one.g1"),
            task_ref: id("task.one"),
            plan_revision_ref: id("plan.one.rev1"),
            repository_generation_ref: id("generation.two"),
            before_snapshot_ref: id("snapshot.one"),
            declared_intent_ref: id("intent.one"),
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
        },
    );
    let runtime = RuntimeSnapshot::from_root(root).unwrap();
    let exact_revalidation = WakeRevalidationContext {
        task_ref: id("task.one"),
        plan_revision_ref: id("plan.one.rev1"),
        repository_generation_ref: id("generation.two"),
        capsule_generation_ref: id("capsule.one.g1"),
        policy_refs: ids(&["materiality.rev1"]),
        authority_evidence_refs: ids(&["authority.fixture"]),
        satisfied_requirements: texts(&[
            "task",
            "plan",
            "repository",
            "capsule",
            "policy",
            "authority",
        ]),
    };
    let operation = RuntimeOperation::EvaluateWake {
        context: context(&runtime, "operation.wake.exact"),
        wake_ref: id("wake.one"),
        revalidation: exact_revalidation.clone(),
    };
    let (woken, receipt) = accepted(evaluate_runtime(&runtime, &operation));
    assert!(
        woken
            .root
            .calendar
            .emitted_wake_candidates
            .contains(&id("wake.one"))
    );
    assert!(matches!(
        receipt.output,
        RuntimeOutput::WakeCandidate { .. }
    ));

    let mut mismatched = exact_revalidation;
    mismatched.repository_generation_ref = id("generation.one");
    let mismatch = RuntimeOperation::EvaluateWake {
        context: context(&runtime, "operation.wake.mismatch"),
        wake_ref: id("wake.one"),
        revalidation: mismatched,
    };
    match evaluate_runtime(&runtime, &mismatch) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::WakeMismatch)
        }
        _ => panic!("mismatched wake must refuse"),
    }
    assert!(
        !runtime
            .root
            .calendar
            .emitted_wake_candidates
            .contains(&id("wake.one"))
    );
}

#[test]
fn replay_is_byte_stable_for_the_same_root_and_operations() {
    let initial = initial_runtime();
    let first = RuntimeOperation::AdvanceLogicalTime {
        context: context(&initial, "operation.time.one"),
        delta: 2,
    };
    let first_snapshot = accepted(evaluate_runtime(&initial, &first)).0;
    let second = RuntimeOperation::AdvanceLogicalTime {
        context: context(&first_snapshot, "operation.time.two"),
        delta: 3,
    };
    let expected = accepted(evaluate_runtime(&first_snapshot, &second)).0;
    let replay_one = replay_runtime(&initial, &[first.clone(), second.clone()]).unwrap();
    let replay_two = replay_runtime(&initial, &[first, second]).unwrap();
    assert_eq!(replay_one, replay_two);
    assert_eq!(replay_one.final_snapshot, expected);
    assert_eq!(
        to_normalized_runtime_snapshot(&replay_one.final_snapshot).unwrap(),
        to_normalized_runtime_snapshot(&expected).unwrap()
    );
}
