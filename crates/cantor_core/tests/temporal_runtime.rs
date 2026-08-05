use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{
    CalendarLifecycleState, CapsuleState, ChangeCapsule, DeclaredIntent, DependencyEdge,
    DependencyKind, DeterministicRuntimeRoot, EventKind, MaterialityDisposition, OperationLimits,
    PlanRevision, PlanState, RuntimeEvaluation, RuntimeFaultKind, RuntimeOperation,
    RuntimeOperationContext, RuntimeOutput, RuntimeSnapshot, WakeRevalidationContext,
    evaluate_runtime, from_normalized_runtime_snapshot, replay_runtime,
    to_normalized_runtime_snapshot,
};

mod temporal_runtime_support;

use temporal_runtime_support::*;

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
