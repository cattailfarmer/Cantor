use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{
    AuthorityState, CalendarItem, CalendarKind, CalendarLifecycleState, ContentDigest,
    ContentInput, ContentObject, DependencyEdge, DependencyKind, EventKind, MaterialEvent,
    MaterialityDecision, MaterialityDisposition, MaterialityPolicy, ObjectiveNode, ObjectiveStatus,
    OperationLimits, PlanRevision, PlanState, ProviderSyncState, RecurrenceRule,
    RepositoryGeneration, RepositoryStatus, RuntimeBounds, RuntimeEvaluation, RuntimeOperation,
    RuntimeOperationContext, RuntimeOutput, RuntimePolicies, RuntimeSnapshot, SemanticId,
    SemanticSnapshot, SensitivityClass, TaskContract, TemporalFormSet, TimeDomain, TimeExpression,
    TimeValue, WakeCondition, digest_material_event, digest_repository_generation,
    digest_semantic_snapshot, evaluate_runtime, sha256_bytes,
};

pub fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity is valid")
}

pub fn ids(values: &[&str]) -> BTreeSet<SemanticId> {
    values.iter().map(|value| id(value)).collect()
}

pub fn texts(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

pub fn digest(value: &str) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: value.to_owned(),
    }
}

pub fn base_forms() -> TemporalFormSet {
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

pub fn initial_runtime() -> RuntimeSnapshot {
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

pub fn context(snapshot: &RuntimeSnapshot, operation_id: &str) -> RuntimeOperationContext {
    RuntimeOperationContext {
        operation_id: id(operation_id),
        caller_id: id("caller.fixture"),
        expected_root_digest: snapshot.root_digest.clone(),
        limits: OperationLimits::default(),
    }
}

pub fn accepted(evaluation: RuntimeEvaluation) -> (RuntimeSnapshot, cantor_core::RuntimeReceipt) {
    match evaluation {
        RuntimeEvaluation::Accepted { successor, receipt } => (*successor, *receipt),
        RuntimeEvaluation::Refused { fault } => panic!("operation refused: {fault:?}"),
    }
}

pub fn candidate_generation(
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

pub fn initialize_repository(snapshot: &RuntimeSnapshot) -> RuntimeSnapshot {
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

pub fn append_observation(snapshot: &RuntimeSnapshot) -> RuntimeSnapshot {
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

pub fn calendar_revision(snapshot: &RuntimeSnapshot) -> RuntimeSnapshot {
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

pub fn propose_plan(snapshot: &RuntimeSnapshot) -> RuntimeSnapshot {
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
