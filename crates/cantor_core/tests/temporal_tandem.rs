use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{
    BarrierState, BoundedLagPolicy, CapsuleState, ChangeCapsule, DeclaredIntent, JoinDisposition,
    LaneCursor, LaneKind, LaneMessage, LaneState, ObserverJoin, ReflectionDisposition,
    ReflectionReturn, ReleaseBarrier, RuntimeEvaluation, RuntimeFaultKind, RuntimeOperation,
    RuntimeOutput, TimeDomain, TimeExpression, TimeValue, WorkPacket, WorkPacketKind,
    evaluate_runtime,
};

mod temporal_runtime_support;

use temporal_runtime_support::{
    accepted, append_observation, calendar_revision, context, id, ids, initial_runtime,
    initialize_repository, propose_plan, texts,
};

fn prepared_runtime() -> cantor_core::RuntimeSnapshot {
    propose_plan(&calendar_revision(&append_observation(
        &initialize_repository(&initial_runtime()),
    )))
}

fn cursor(identity: &str, kind: LaneKind) -> LaneCursor {
    LaneCursor {
        cursor_id: id(identity),
        kind,
        task_ref: id("task.one"),
        input_repository_generation_ref: id("generation.two"),
        plan_revision_ref: id("plan.one.rev1"),
        capsule_generation_ref: id("capsule.tandem.g1"),
        dependency_refs: BTreeSet::new(),
        authority_request_ref: None,
        state: LaneState::Idle,
        lease_ref: None,
        timeout_ref: None,
        last_message_ref: None,
    }
}

fn open_tandem_with_limit(maximum_transition_count: u32) -> cantor_core::RuntimeSnapshot {
    open_tandem_with_options(maximum_transition_count, false)
}

fn open_tandem_with_options(
    maximum_transition_count: u32,
    include_execution_lane: bool,
) -> cantor_core::RuntimeSnapshot {
    let runtime = prepared_runtime();
    let intent = DeclaredIntent {
        intent_id: id("intent.tandem"),
        target_refs: ids(&["target.one"]),
        expected_transformations: texts(&["prepare and reflect"]),
        allowed_effects: BTreeSet::new(),
        completion_evidence: texts(&["Observer reconciliation"]),
        unrelated_state_exclusions: ids(&["target.unrelated"]),
        source_ref: id("source.fixture"),
    };
    let capsule = ChangeCapsule {
        change_id: id("change.tandem"),
        candidate_generation_id: id("capsule.tandem.g1"),
        task_ref: id("task.one"),
        plan_revision_ref: id("plan.one.rev1"),
        repository_generation_ref: id("generation.two"),
        before_snapshot_ref: id("snapshot.one"),
        declared_intent_ref: id("intent.tandem"),
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
    let packet = WorkPacket {
        packet_id: id("packet.prospective"),
        kind: WorkPacketKind::Prospective,
        task_ref: id("task.one"),
        input_repository_generation_ref: id("generation.two"),
        capsule_generation_ref: id("capsule.tandem.g1"),
        permitted_output_kinds: texts(&["prepared_candidate"]),
        authority_boundary: texts(&["returned values only"]),
    };
    let mut lane_cursors = vec![
        cursor("lane.prospective", LaneKind::Prospective),
        cursor("lane.retrospective", LaneKind::Retrospective),
    ];
    let mut work_packets = vec![packet];
    if include_execution_lane {
        let mut execution = cursor("lane.execution", LaneKind::Execution);
        execution.authority_request_ref = Some(id("authority.execution.fixture"));
        lane_cursors.push(execution);
        work_packets.push(WorkPacket {
            packet_id: id("packet.execution"),
            kind: WorkPacketKind::Execution,
            task_ref: id("task.one"),
            input_repository_generation_ref: id("generation.two"),
            capsule_generation_ref: id("capsule.tandem.g1"),
            permitted_output_kinds: texts(&["simulated_effect_observation"]),
            authority_boundary: texts(&["fixture data only", "no effect"]),
        });
    }
    let barrier = ReleaseBarrier {
        barrier_id: id("barrier.tandem"),
        capsule_generation_ref: id("capsule.tandem.g1"),
        required_return_refs: ids(&["reflection.tandem"]),
        dependent_refs: ids(&["dependent.followup"]),
        observer_join_ref: None,
        released_refs: BTreeSet::new(),
        state: BarrierState::Closed,
    };
    let lag = BoundedLagPolicy {
        policy_id: id("lag.tandem"),
        eligible_transition_kinds: texts(&[
            "capsule_transition",
            "lane_transition",
            "lane_message",
            "lane_acknowledgment",
            "observer_join",
            "release_barrier",
            "lane_reentry",
        ]),
        maximum_transition_count: Some(maximum_transition_count),
        maximum_duration_ref: None,
        consequence_bound: "returned value only".to_owned(),
        rollback_capacity: "retain prior snapshot".to_owned(),
        overdue_behavior: "typed refusal".to_owned(),
        authority_ref: id("authority.fixture"),
    };
    let operation = RuntimeOperation::OpenTandem {
        context: context(&runtime, "operation.tandem.open"),
        declared_intent: intent,
        capsule,
        lane_cursors,
        work_packets,
        release_barriers: vec![barrier],
        bounded_lag_policies: vec![lag],
    };
    let (runtime, receipt) = accepted(evaluate_runtime(&runtime, &operation));
    assert!(matches!(receipt.output, RuntimeOutput::TandemOpened { .. }));
    runtime
}

fn transition_capsule(
    runtime: &cantor_core::RuntimeSnapshot,
    operation_id: &str,
    expected: CapsuleState,
    target: CapsuleState,
    reflection_ref: Option<&str>,
) -> cantor_core::RuntimeSnapshot {
    let mut successor = runtime.root.forms.capsules[&id("capsule.tandem.g1")].clone();
    successor.state = target;
    successor.reflection_return_ref = reflection_ref.map(id);
    if target == CapsuleState::Prepared {
        successor.prepared_candidate_ref = Some(id("candidate.prepared"));
    }
    if target == CapsuleState::ExecutionRequested {
        successor.execution_request_ref = Some(id("execution.request.fixture"));
    }
    if target == CapsuleState::EffectObserved {
        successor.execution_outcome_ref = Some(id("execution.outcome.fixture"));
    }
    let operation = RuntimeOperation::TransitionCapsule {
        context: context(runtime, operation_id),
        expected_state: expected,
        successor,
    };
    accepted(evaluate_runtime(runtime, &operation)).0
}

fn transition_lane(
    runtime: &cantor_core::RuntimeSnapshot,
    cursor_ref: &str,
    operation_id: &str,
    expected: LaneState,
    target: LaneState,
) -> cantor_core::RuntimeSnapshot {
    let mut successor = runtime.root.forms.lane_cursors[&id(cursor_ref)].clone();
    successor.state = target;
    if target == LaneState::TimedOut {
        successor.timeout_ref = Some(id("timeout.logical.fixture"));
    }
    let operation = RuntimeOperation::TransitionLane {
        context: context(runtime, operation_id),
        expected_state: expected,
        successor,
        return_ref: None,
        reflection_return: None,
    };
    accepted(evaluate_runtime(runtime, &operation)).0
}

fn runtime_ready_for_observer(
    required_acknowledgment: bool,
    acknowledge: bool,
) -> cantor_core::RuntimeSnapshot {
    let runtime = open_tandem_with_limit(30);
    let runtime = transition_capsule(
        &runtime,
        "operation.fixture.capsule.prepared",
        CapsuleState::Opened,
        CapsuleState::Prepared,
        None,
    );
    let runtime = transition_lane(
        &runtime,
        "lane.prospective",
        "operation.fixture.prospective.prepared",
        LaneState::Idle,
        LaneState::Prepared,
    );
    let runtime = transition_lane(
        &runtime,
        "lane.prospective",
        "operation.fixture.prospective.running",
        LaneState::Prepared,
        LaneState::Running,
    );
    let runtime = transition_lane(
        &runtime,
        "lane.retrospective",
        "operation.fixture.retrospective.prepared",
        LaneState::Idle,
        LaneState::Prepared,
    );
    let runtime = transition_lane(
        &runtime,
        "lane.retrospective",
        "operation.fixture.retrospective.running",
        LaneState::Prepared,
        LaneState::Running,
    );
    let logical_time = TimeExpression {
        time_expression_id: id("time.fixture.message.0"),
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
    };
    let message = LaneMessage {
        message_id: id("message.fixture.prospective.to.rear"),
        sender_cursor_ref: id("lane.prospective"),
        receiver_cursor_ref: id("lane.retrospective"),
        subject_version_ref: id("capsule.tandem.g1"),
        payload_refs: ids(&["packet.prospective"]),
        required_acknowledgment,
        causal_predecessor_refs: BTreeSet::new(),
        created_logical_time_ref: id("time.fixture.message.0"),
        expiry_condition: "before Observer reconciliation".to_owned(),
    };
    let append = RuntimeOperation::AppendLaneMessage {
        context: context(&runtime, "operation.fixture.message.append"),
        logical_time,
        message,
    };
    let runtime = accepted(evaluate_runtime(&runtime, &append)).0;
    let runtime = if acknowledge {
        let operation = RuntimeOperation::AcknowledgeLaneMessage {
            context: context(&runtime, "operation.fixture.message.ack"),
            message_ref: id("message.fixture.prospective.to.rear"),
            receiver_cursor_ref: id("lane.retrospective"),
        };
        accepted(evaluate_runtime(&runtime, &operation)).0
    } else {
        runtime
    };
    let mut prospective = runtime.root.forms.lane_cursors[&id("lane.prospective")].clone();
    prospective.state = LaneState::Returned;
    let operation = RuntimeOperation::TransitionLane {
        context: context(&runtime, "operation.fixture.prospective.return"),
        expected_state: LaneState::Running,
        successor: prospective,
        return_ref: Some(id("candidate.prepared")),
        reflection_return: None,
    };
    let runtime = accepted(evaluate_runtime(&runtime, &operation)).0;
    let mut returned_cursor = runtime.root.forms.lane_cursors[&id("lane.retrospective")].clone();
    returned_cursor.state = LaneState::Returned;
    let reflection = ReflectionReturn {
        return_id: id("reflection.fixture"),
        retrospective_cursor_ref: id("lane.retrospective"),
        capsule_generation_ref: id("capsule.tandem.g1"),
        disposition: ReflectionDisposition::Qualify,
        evidence_refs: ids(&["message.fixture.prospective.to.rear"]),
        objections: BTreeSet::new(),
        uncertainty: texts(&["fixture uncertainty"]),
        invalidation_refs: BTreeSet::new(),
        residuals: texts(&["fixture residual"]),
        signature_ref: None,
        provider_qualification: None,
    };
    let operation = RuntimeOperation::TransitionLane {
        context: context(&runtime, "operation.fixture.retrospective.return"),
        expected_state: LaneState::Running,
        successor: returned_cursor,
        return_ref: Some(id("reflection.fixture")),
        reflection_return: Some(reflection),
    };
    let runtime = accepted(evaluate_runtime(&runtime, &operation)).0;
    let runtime = transition_capsule(
        &runtime,
        "operation.fixture.capsule.reflection.requested",
        CapsuleState::Prepared,
        CapsuleState::ReflectionRequested,
        None,
    );
    transition_capsule(
        &runtime,
        "operation.fixture.capsule.reflection.returned",
        CapsuleState::ReflectionRequested,
        CapsuleState::ReflectionReturned,
        Some("reflection.fixture"),
    )
}

fn observer_join(disposition: JoinDisposition) -> ObserverJoin {
    ObserverJoin {
        join_id: id("join.fixture"),
        capsule_generation_ref: id("capsule.tandem.g1"),
        expected_lane_return_refs: ids(&["candidate.prepared", "reflection.fixture"]),
        expected_subject_version_refs: ids(&[
            "capsule.tandem.g1",
            "task.one",
            "plan.one.rev1",
            "generation.two",
            "materiality.one",
            "materiality.rev1",
            "lag.tandem",
            "authority.fixture",
        ]),
        received_return_refs: ids(&["candidate.prepared", "reflection.fixture"]),
        stale_check_refs: ids(&["plan.one.rev1", "generation.two"]),
        reconciliation_record_ref: id("reconciliation.fixture"),
        disposition,
        successor_repository_generation_ref: None,
        release_refs: ids(&["barrier.tandem"]),
        residuals: texts(&["fixture remains effectless"]),
    }
}

#[test]
fn tandem_walk_preserves_causality_reconciles_and_opens_exact_barrier() {
    let runtime = open_tandem_with_limit(20);
    let runtime = transition_capsule(
        &runtime,
        "operation.capsule.prepared",
        CapsuleState::Opened,
        CapsuleState::Prepared,
        None,
    );
    let runtime = transition_lane(
        &runtime,
        "lane.prospective",
        "operation.prospective.prepared",
        LaneState::Idle,
        LaneState::Prepared,
    );
    let runtime = transition_lane(
        &runtime,
        "lane.prospective",
        "operation.prospective.running",
        LaneState::Prepared,
        LaneState::Running,
    );
    let runtime = transition_lane(
        &runtime,
        "lane.retrospective",
        "operation.retrospective.prepared",
        LaneState::Idle,
        LaneState::Prepared,
    );
    let runtime = transition_lane(
        &runtime,
        "lane.retrospective",
        "operation.retrospective.running",
        LaneState::Prepared,
        LaneState::Running,
    );
    let logical_time = TimeExpression {
        time_expression_id: id("time.message.0"),
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
    };
    let message = LaneMessage {
        message_id: id("message.prospective.to.rear"),
        sender_cursor_ref: id("lane.prospective"),
        receiver_cursor_ref: id("lane.retrospective"),
        subject_version_ref: id("capsule.tandem.g1"),
        payload_refs: ids(&["packet.prospective"]),
        required_acknowledgment: true,
        causal_predecessor_refs: BTreeSet::new(),
        created_logical_time_ref: id("time.message.0"),
        expiry_condition: "before Observer reconciliation".to_owned(),
    };
    let append = RuntimeOperation::AppendLaneMessage {
        context: context(&runtime, "operation.message.append"),
        logical_time,
        message,
    };
    let runtime = accepted(evaluate_runtime(&runtime, &append)).0;
    let acknowledge = RuntimeOperation::AcknowledgeLaneMessage {
        context: context(&runtime, "operation.message.ack"),
        message_ref: id("message.prospective.to.rear"),
        receiver_cursor_ref: id("lane.retrospective"),
    };
    let runtime = accepted(evaluate_runtime(&runtime, &acknowledge)).0;
    assert!(
        runtime
            .root
            .tandem
            .acknowledged_message_refs
            .contains(&id("message.prospective.to.rear"))
    );

    let mut prospective = runtime.root.forms.lane_cursors[&id("lane.prospective")].clone();
    prospective.state = LaneState::Returned;
    let prospective_return = RuntimeOperation::TransitionLane {
        context: context(&runtime, "operation.prospective.return"),
        expected_state: LaneState::Running,
        successor: prospective,
        return_ref: Some(id("candidate.prepared")),
        reflection_return: None,
    };
    let runtime = accepted(evaluate_runtime(&runtime, &prospective_return)).0;

    let mut returned_cursor = runtime.root.forms.lane_cursors[&id("lane.retrospective")].clone();
    returned_cursor.state = LaneState::Returned;
    let reflection = ReflectionReturn {
        return_id: id("reflection.tandem"),
        retrospective_cursor_ref: id("lane.retrospective"),
        capsule_generation_ref: id("capsule.tandem.g1"),
        disposition: ReflectionDisposition::Qualify,
        evidence_refs: ids(&["message.prospective.to.rear"]),
        objections: BTreeSet::new(),
        uncertainty: texts(&["candidate not externally executed"]),
        invalidation_refs: BTreeSet::new(),
        residuals: texts(&["effect remains absent"]),
        signature_ref: None,
        provider_qualification: None,
    };
    let return_operation = RuntimeOperation::TransitionLane {
        context: context(&runtime, "operation.retrospective.return"),
        expected_state: LaneState::Running,
        successor: returned_cursor,
        return_ref: Some(id("reflection.tandem")),
        reflection_return: Some(reflection),
    };
    let runtime = accepted(evaluate_runtime(&runtime, &return_operation)).0;
    let runtime = transition_capsule(
        &runtime,
        "operation.capsule.reflection.requested",
        CapsuleState::Prepared,
        CapsuleState::ReflectionRequested,
        None,
    );
    let runtime = transition_capsule(
        &runtime,
        "operation.capsule.reflection.returned",
        CapsuleState::ReflectionRequested,
        CapsuleState::ReflectionReturned,
        Some("reflection.tandem"),
    );

    let join = ObserverJoin {
        join_id: id("join.tandem"),
        capsule_generation_ref: id("capsule.tandem.g1"),
        expected_lane_return_refs: ids(&["candidate.prepared", "reflection.tandem"]),
        expected_subject_version_refs: ids(&[
            "capsule.tandem.g1",
            "task.one",
            "plan.one.rev1",
            "generation.two",
            "materiality.one",
            "materiality.rev1",
            "lag.tandem",
            "authority.fixture",
        ]),
        received_return_refs: ids(&["candidate.prepared", "reflection.tandem"]),
        stale_check_refs: ids(&["plan.one.rev1", "generation.two"]),
        reconciliation_record_ref: id("reconciliation.tandem"),
        disposition: JoinDisposition::Qualify,
        successor_repository_generation_ref: None,
        release_refs: ids(&["barrier.tandem"]),
        residuals: texts(&["candidate remains effectless"]),
    };
    let mut reconciled = runtime.root.forms.capsules[&id("capsule.tandem.g1")].clone();
    reconciled.state = CapsuleState::Reconciled;
    reconciled.observer_join_ref = Some(id("join.tandem"));
    let reconcile = RuntimeOperation::ReconcileObserver {
        context: context(&runtime, "operation.observer.reconcile"),
        join,
        successor_capsule: reconciled,
    };
    let runtime = accepted(evaluate_runtime(&runtime, &reconcile)).0;
    let mut open_barrier = runtime.root.forms.release_barriers[&id("barrier.tandem")].clone();
    open_barrier.state = BarrierState::Open;
    open_barrier.observer_join_ref = Some(id("join.tandem"));
    open_barrier.released_refs = ids(&["dependent.followup"]);
    let release = RuntimeOperation::EvaluateReleaseBarrier {
        context: context(&runtime, "operation.barrier.open"),
        expected_state: BarrierState::Closed,
        successor: open_barrier,
    };
    let (runtime, receipt) = accepted(evaluate_runtime(&runtime, &release));
    assert!(matches!(
        receipt.output,
        RuntimeOutput::ReleaseBarrierEvaluation {
            state: BarrierState::Open,
            ..
        }
    ));
    assert_eq!(
        runtime.root.tandem.capsule_state_history[&id("capsule.tandem.g1")],
        vec![
            CapsuleState::Opened,
            CapsuleState::Prepared,
            CapsuleState::ReflectionRequested,
            CapsuleState::ReflectionReturned,
            CapsuleState::Reconciled,
        ]
    );
}

#[test]
fn timeout_and_crash_reentry_create_a_new_exact_cursor() {
    let runtime = open_tandem_with_limit(20);
    let runtime = transition_lane(
        &runtime,
        "lane.prospective",
        "operation.lane.prepared",
        LaneState::Idle,
        LaneState::Prepared,
    );
    let runtime = transition_lane(
        &runtime,
        "lane.prospective",
        "operation.lane.running",
        LaneState::Prepared,
        LaneState::Running,
    );
    let runtime = transition_lane(
        &runtime,
        "lane.prospective",
        "operation.lane.timeout",
        LaneState::Running,
        LaneState::TimedOut,
    );
    let mut successor = runtime.root.forms.lane_cursors[&id("lane.prospective")].clone();
    successor.cursor_id = id("lane.prospective.reentry.1");
    successor.state = LaneState::Prepared;
    successor.dependency_refs.insert(id("lane.prospective"));
    let reentry = RuntimeOperation::ReenterLane {
        context: context(&runtime, "operation.lane.reentry"),
        predecessor_cursor_ref: id("lane.prospective"),
        successor_cursor: successor,
    };
    let (runtime, receipt) = accepted(evaluate_runtime(&runtime, &reentry));
    assert!(matches!(receipt.output, RuntimeOutput::LaneReentry { .. }));
    assert_eq!(
        runtime.root.tandem.reentry_predecessors[&id("lane.prospective.reentry.1")],
        id("lane.prospective")
    );
    let mut cancelled = runtime.root.forms.lane_cursors[&id("lane.prospective.reentry.1")].clone();
    cancelled.state = LaneState::Cancelled;
    let cancel = RuntimeOperation::TransitionLane {
        context: context(&runtime, "operation.lane.reentry.cancel"),
        expected_state: LaneState::Prepared,
        successor: cancelled,
        return_ref: None,
        reflection_return: None,
    };
    let runtime = accepted(evaluate_runtime(&runtime, &cancel)).0;
    assert_eq!(
        runtime.root.tandem.lane_state_history[&id("lane.prospective.reentry.1")],
        vec![LaneState::Prepared, LaneState::Cancelled]
    );
}

#[test]
fn stale_join_wrong_reentry_and_lag_exhaustion_fail_without_successor() {
    let runtime = open_tandem_with_limit(1);
    let runtime = transition_lane(
        &runtime,
        "lane.prospective",
        "operation.lag.first",
        LaneState::Idle,
        LaneState::Prepared,
    );
    let mut running = runtime.root.forms.lane_cursors[&id("lane.prospective")].clone();
    running.state = LaneState::Running;
    let overflow = RuntimeOperation::TransitionLane {
        context: context(&runtime, "operation.lag.overflow"),
        expected_state: LaneState::Prepared,
        successor: running,
        return_ref: None,
        reflection_return: None,
    };
    match evaluate_runtime(&runtime, &overflow) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::BoundExhausted)
        }
        _ => panic!("bounded-lag exhaustion must refuse"),
    }

    let join = ObserverJoin {
        join_id: id("join.stale"),
        capsule_generation_ref: id("capsule.tandem.g1"),
        expected_lane_return_refs: ids(&["reflection.missing"]),
        expected_subject_version_refs: ids(&["capsule.tandem.g1"]),
        received_return_refs: BTreeSet::new(),
        stale_check_refs: BTreeSet::new(),
        reconciliation_record_ref: id("reconciliation.stale"),
        disposition: JoinDisposition::Block,
        successor_repository_generation_ref: None,
        release_refs: BTreeSet::new(),
        residuals: texts(&["missing return"]),
    };
    let mut successor_capsule = runtime.root.forms.capsules[&id("capsule.tandem.g1")].clone();
    successor_capsule.state = CapsuleState::Reconciled;
    successor_capsule.observer_join_ref = Some(id("join.stale"));
    let stale_join = RuntimeOperation::ReconcileObserver {
        context: context(&runtime, "operation.join.stale"),
        join,
        successor_capsule,
    };
    match evaluate_runtime(&runtime, &stale_join) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::IllegalTransition)
        }
        _ => panic!("incomplete stale join must refuse"),
    }

    let mut invalid_reentry = runtime.root.forms.lane_cursors[&id("lane.prospective")].clone();
    invalid_reentry.cursor_id = id("lane.invalid.reentry");
    invalid_reentry.state = LaneState::Prepared;
    invalid_reentry
        .dependency_refs
        .insert(id("lane.prospective"));
    let reentry = RuntimeOperation::ReenterLane {
        context: context(&runtime, "operation.reentry.invalid"),
        predecessor_cursor_ref: id("lane.prospective"),
        successor_cursor: invalid_reentry,
    };
    match evaluate_runtime(&runtime, &reentry) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::InvalidReentry)
        }
        _ => panic!("nonterminal predecessor must refuse reentry"),
    }
}

#[test]
fn lifecycle_evidence_and_reflection_identity_fail_closed() {
    let runtime = open_tandem_with_limit(20);
    let mut unevidenced = runtime.root.forms.capsules[&id("capsule.tandem.g1")].clone();
    unevidenced.state = CapsuleState::Prepared;
    let operation = RuntimeOperation::TransitionCapsule {
        context: context(&runtime, "operation.capsule.unevidenced"),
        expected_state: CapsuleState::Opened,
        successor: unevidenced,
    };
    match evaluate_runtime(&runtime, &operation) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::MissingReference)
        }
        _ => panic!("capsule lifecycle evidence must be explicit"),
    }

    let runtime = transition_lane(
        &runtime,
        "lane.retrospective",
        "operation.reflection.lane.prepared",
        LaneState::Idle,
        LaneState::Prepared,
    );
    let runtime = transition_lane(
        &runtime,
        "lane.retrospective",
        "operation.reflection.lane.running",
        LaneState::Prepared,
        LaneState::Running,
    );
    let mut returned = runtime.root.forms.lane_cursors[&id("lane.retrospective")].clone();
    returned.state = LaneState::Returned;
    let wrong_reflection = ReflectionReturn {
        return_id: id("reflection.wrong-capsule"),
        retrospective_cursor_ref: id("lane.retrospective"),
        capsule_generation_ref: id("capsule.other"),
        disposition: ReflectionDisposition::Block,
        evidence_refs: ids(&["evidence.fixture"]),
        objections: texts(&["wrong capsule"]),
        uncertainty: BTreeSet::new(),
        invalidation_refs: BTreeSet::new(),
        residuals: BTreeSet::new(),
        signature_ref: None,
        provider_qualification: None,
    };
    let operation = RuntimeOperation::TransitionLane {
        context: context(&runtime, "operation.reflection.wrong-capsule"),
        expected_state: LaneState::Running,
        successor: returned,
        return_ref: Some(id("reflection.wrong-capsule")),
        reflection_return: Some(wrong_reflection),
    };
    match evaluate_runtime(&runtime, &operation) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::InvalidForm)
        }
        _ => panic!("reflection for another capsule must be refused"),
    }
}

#[test]
fn observer_requires_acknowledgments_and_current_plan() {
    let runtime = runtime_ready_for_observer(true, false);
    let join = observer_join(JoinDisposition::Qualify);
    let mut reconciled = runtime.root.forms.capsules[&id("capsule.tandem.g1")].clone();
    reconciled.state = CapsuleState::Reconciled;
    reconciled.observer_join_ref = Some(id("join.fixture"));
    let operation = RuntimeOperation::ReconcileObserver {
        context: context(&runtime, "operation.observer.unacknowledged"),
        join: join.clone(),
        successor_capsule: reconciled.clone(),
    };
    match evaluate_runtime(&runtime, &operation) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::IllegalTransition)
        }
        _ => panic!("Observer must refuse an unacknowledged required message"),
    }

    let acknowledge = RuntimeOperation::AcknowledgeLaneMessage {
        context: context(&runtime, "operation.fixture.late-ack"),
        message_ref: id("message.fixture.prospective.to.rear"),
        receiver_cursor_ref: id("lane.retrospective"),
    };
    let runtime = accepted(evaluate_runtime(&runtime, &acknowledge)).0;
    let mut plan = runtime.root.forms.plan_revisions[&id("plan.one.rev1")].clone();
    plan.revision_id = id("plan.one.rev2");
    plan.predecessor_revision_ref = Some(id("plan.one.rev1"));
    let propose = RuntimeOperation::ProposePlan {
        context: context(&runtime, "operation.plan.supersede-for-stale-join"),
        plan,
        repository_generation_ref: id("generation.two"),
        calendar_revision_refs: ids(&["calendar.one.rev1"]),
        proof_gate_refs: ids(&["review.one"]),
        available_resource_refs: ids(&["resource.fixture"]),
    };
    let runtime = accepted(evaluate_runtime(&runtime, &propose)).0;
    let operation = RuntimeOperation::ReconcileObserver {
        context: context(&runtime, "operation.observer.stale-plan"),
        join,
        successor_capsule: reconciled,
    };
    match evaluate_runtime(&runtime, &operation) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::IllegalTransition)
        }
        _ => panic!("Observer must compare the capsule against the current plan"),
    }
}

#[test]
fn blocking_observer_disposition_cannot_open_a_release_barrier() {
    let runtime = runtime_ready_for_observer(false, false);
    let join = observer_join(JoinDisposition::Block);
    let mut reconciled = runtime.root.forms.capsules[&id("capsule.tandem.g1")].clone();
    reconciled.state = CapsuleState::Reconciled;
    reconciled.observer_join_ref = Some(id("join.fixture"));
    let operation = RuntimeOperation::ReconcileObserver {
        context: context(&runtime, "operation.observer.block"),
        join,
        successor_capsule: reconciled,
    };
    let runtime = accepted(evaluate_runtime(&runtime, &operation)).0;
    let mut barrier = runtime.root.forms.release_barriers[&id("barrier.tandem")].clone();
    barrier.state = BarrierState::Open;
    barrier.observer_join_ref = Some(id("join.fixture"));
    barrier.released_refs = ids(&["dependent.followup"]);
    let operation = RuntimeOperation::EvaluateReleaseBarrier {
        context: context(&runtime, "operation.barrier.blocked"),
        expected_state: BarrierState::Closed,
        successor: barrier,
    };
    match evaluate_runtime(&runtime, &operation) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::MissingReference)
        }
        _ => panic!("blocking Observer disposition must keep the barrier closed"),
    }
}

#[test]
fn observer_derives_complete_return_set_from_runtime_state() {
    let runtime = runtime_ready_for_observer(false, false);
    let mut join = observer_join(JoinDisposition::Qualify);
    join.expected_lane_return_refs
        .remove(&id("candidate.prepared"));
    join.received_return_refs.remove(&id("candidate.prepared"));
    let mut reconciled = runtime.root.forms.capsules[&id("capsule.tandem.g1")].clone();
    reconciled.state = CapsuleState::Reconciled;
    reconciled.observer_join_ref = Some(id("join.fixture"));
    let operation = RuntimeOperation::ReconcileObserver {
        context: context(&runtime, "operation.observer.omitted-return"),
        join,
        successor_capsule: reconciled,
    };
    match evaluate_runtime(&runtime, &operation) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::IllegalTransition)
        }
        _ => panic!("Observer must not accept a caller-truncated lane return set"),
    }
}

#[test]
fn execution_lane_returns_only_a_supplied_simulated_outcome() {
    let runtime = open_tandem_with_options(20, true);
    let runtime = transition_capsule(
        &runtime,
        "operation.execution.capsule.prepared",
        CapsuleState::Opened,
        CapsuleState::Prepared,
        None,
    );
    let runtime = transition_capsule(
        &runtime,
        "operation.execution.capsule.requested",
        CapsuleState::Prepared,
        CapsuleState::ExecutionRequested,
        None,
    );
    let runtime = transition_capsule(
        &runtime,
        "operation.execution.capsule.observed",
        CapsuleState::ExecutionRequested,
        CapsuleState::EffectObserved,
        None,
    );
    let runtime = transition_lane(
        &runtime,
        "lane.execution",
        "operation.execution.lane.prepared",
        LaneState::Idle,
        LaneState::Prepared,
    );
    let runtime = transition_lane(
        &runtime,
        "lane.execution",
        "operation.execution.lane.running",
        LaneState::Prepared,
        LaneState::Running,
    );
    let mut returned = runtime.root.forms.lane_cursors[&id("lane.execution")].clone();
    returned.state = LaneState::Returned;
    let wrong = RuntimeOperation::TransitionLane {
        context: context(&runtime, "operation.execution.wrong-return"),
        expected_state: LaneState::Running,
        successor: returned.clone(),
        return_ref: Some(id("candidate.prepared")),
        reflection_return: None,
    };
    match evaluate_runtime(&runtime, &wrong) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::MissingReference)
        }
        _ => panic!("execution lane must not return a prospective artifact"),
    }
    let operation = RuntimeOperation::TransitionLane {
        context: context(&runtime, "operation.execution.fixture-return"),
        expected_state: LaneState::Running,
        successor: returned,
        return_ref: Some(id("execution.outcome.fixture")),
        reflection_return: None,
    };
    let runtime = accepted(evaluate_runtime(&runtime, &operation)).0;
    assert_eq!(
        runtime.root.tandem.lane_return_refs[&id("lane.execution")],
        id("execution.outcome.fixture")
    );
}
