use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{
    CTPR_FORM_VERSION, CapsuleState, ChangeCapsule, CompilerStage, ContentDigest, DeclaredIntent,
    DiffKind, DiffRecord, JoinDisposition, LaneCursor, LaneKind, LaneState, ObjectiveNode,
    ObjectiveStatus, ObserverJoin, PlanRevision, PlanState, ReflectionDisposition,
    ReflectionReturn, RepositoryGeneration, RepositoryStatus, SemanticId, SemanticSnapshot,
    TaskContract, TemporalFormSet, TimeDomain, TimeExpression, TimeValue,
    from_normalized_temporal_form, to_normalized_temporal_form, validate_capsule_transition,
    validate_lane_transition,
};

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity must be valid")
}

fn refs(values: &[&str]) -> BTreeSet<SemanticId> {
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

fn time(expression_id: &str, domain: TimeDomain) -> TimeExpression {
    TimeExpression {
        time_expression_id: id(expression_id),
        domain,
        value: TimeValue::Point {
            value: "1".to_owned(),
        },
        source_ref: id("source.time"),
        zone: None,
        calendar_system: None,
        precision: "exact".to_owned(),
        uncertainty_interval: None,
        interpretation_policy_ref: None,
        conversion_evidence_refs: BTreeSet::new(),
        valid_from_ref: None,
        valid_to_ref: None,
        recorded_at_ref: None,
    }
}

#[test]
fn normalized_form_round_trips_and_map_order_is_deterministic() {
    let mut first = TemporalFormSet::new();
    first
        .time_expressions
        .insert(id("time.b"), time("time.b", TimeDomain::Logical));
    first
        .time_expressions
        .insert(id("time.a"), time("time.a", TimeDomain::Logical));

    let mut second = TemporalFormSet::new();
    second
        .time_expressions
        .insert(id("time.a"), time("time.a", TimeDomain::Logical));
    second
        .time_expressions
        .insert(id("time.b"), time("time.b", TimeDomain::Logical));

    let first_json = to_normalized_temporal_form(&first).expect("first form must normalize");
    let second_json = to_normalized_temporal_form(&second).expect("second form must normalize");
    assert_eq!(first_json, second_json);
    assert_eq!(
        from_normalized_temporal_form(&first_json).expect("normalized form must restore"),
        first
    );
}

#[test]
fn noncanonical_json_and_unknown_fields_fail_closed() {
    let normalized = to_normalized_temporal_form(&TemporalFormSet::new()).unwrap();
    let spaced = normalized.replacen('{', "{ ", 1);
    let fault =
        from_normalized_temporal_form(&spaced).expect_err("whitespace must be noncanonical");
    assert!(fault.message.contains("not normalized"));

    let unknown = normalized.replacen('{', "{\"unexpected\":true,", 1);
    let fault = from_normalized_temporal_form(&unknown).expect_err("unknown fields must fail");
    assert!(fault.message.contains("unknown field"));
}

#[test]
fn invalid_identity_and_unsupported_version_fail_closed() {
    let normalized = to_normalized_temporal_form(&TemporalFormSet::new()).unwrap();
    let invalid_identity = normalized.replacen(
        "\"time_expressions\":{}",
        "\"time_expressions\":{\"bad identity\":{}}",
        1,
    );
    let fault = from_normalized_temporal_form(&invalid_identity)
        .expect_err("invalid map identity must fail during restoration");
    assert!(fault.message.contains("invalid semantic identity"));

    let mut form = TemporalFormSet::new();
    form.form_version = "cantor-ctpr/9.9".to_owned();
    let fault = form
        .validate()
        .expect_err("unsupported form version must fail");
    assert!(fault.message.contains("unsupported CTPR form version"));
    assert_eq!(CTPR_FORM_VERSION, "cantor-ctpr/0.1");
}

#[test]
fn civil_uncertain_and_interval_time_invariants_are_enforced() {
    let mut form = TemporalFormSet::new();
    form.time_expressions
        .insert(id("time.civil"), time("time.civil", TimeDomain::Civil));
    let fault = form
        .validate()
        .expect_err("civil time needs zone and calendar");
    assert!(fault.message.contains("civil time zone"));

    let mut uncertain = time("time.uncertain", TimeDomain::Uncertain);
    uncertain.uncertainty_interval = None;
    let mut form = TemporalFormSet::new();
    form.time_expressions
        .insert(uncertain.time_expression_id.clone(), uncertain);
    let fault = form
        .validate()
        .expect_err("uncertain time needs uncertainty");
    assert!(fault.message.contains("uncertainty interval"));

    let mut interval = time("time.interval", TimeDomain::Logical);
    interval.value = TimeValue::Interval {
        start: "5".to_owned(),
        end: "5".to_owned(),
    };
    let mut form = TemporalFormSet::new();
    form.time_expressions
        .insert(interval.time_expression_id.clone(), interval);
    let fault = form.validate().expect_err("zero-width interval must fail");
    assert!(fault.message.contains("start and end are equal"));
}

#[test]
fn snapshot_cannot_claim_atomic_external_world_state() {
    let snapshot = SemanticSnapshot {
        snapshot_id: id("snapshot.one"),
        repository_id: id("repository.one"),
        predecessor_snapshot_refs: BTreeSet::new(),
        event_frontier: refs(&["event.one"]),
        canonical_state_root: digest("state"),
        projection_manifest_ref: None,
        content_object_refs: BTreeSet::new(),
        reconciliation_evidence_refs: BTreeSet::new(),
        loss_records: BTreeSet::new(),
        atomic_external_world_claim: true,
        snapshot_digest: digest("snapshot"),
    };
    let mut form = TemporalFormSet::new();
    form.snapshots
        .insert(snapshot.snapshot_id.clone(), snapshot);
    let fault = form.validate().expect_err("snapshot overclaim must fail");
    assert!(fault.message.contains("atomic external-world state"));
}

#[test]
fn capsule_and_lane_transition_vocabularies_are_closed() {
    validate_capsule_transition(CapsuleState::Opened, CapsuleState::Prepared).unwrap();
    validate_lane_transition(LaneState::Running, LaneState::Returned).unwrap();

    let fault = validate_capsule_transition(CapsuleState::Opened, CapsuleState::Admitted)
        .expect_err("capsule cannot skip review and reconciliation");
    assert!(fault.message.contains("illegal capsule transition"));

    let fault = validate_lane_transition(LaneState::Idle, LaneState::Released)
        .expect_err("lane cannot skip its lifecycle");
    assert!(fault.message.contains("illegal lane transition"));
}

#[test]
fn missing_cross_record_reference_fails_closed() {
    let plan = PlanRevision {
        plan_id: id("plan.one"),
        revision_id: id("plan.one.rev1"),
        predecessor_revision_ref: None,
        task_ref: id("task.absent"),
        objective_refs: refs(&["objective.one"]),
        dependency_refs: BTreeSet::new(),
        temporal_refs: BTreeSet::new(),
        effect_refs: BTreeSet::new(),
        review_refs: BTreeSet::new(),
        selected_alternative_ref: None,
        assumptions: BTreeSet::new(),
        uncertainty: BTreeSet::new(),
        state: PlanState::Proposed,
    };
    let objective = ObjectiveNode {
        objective_id: id("objective.one"),
        task_ref: id("task.absent"),
        statement: "prove the pure forms".to_owned(),
        desired_state_criteria: texts(&["validated"]),
        priority_source_ref: id("source.priority"),
        uncertainty: BTreeSet::new(),
        status: ObjectiveStatus::Proposed,
        proof_route: texts(&["unit tests"]),
    };
    let mut form = TemporalFormSet::new();
    form.plan_revisions.insert(plan.revision_id.clone(), plan);
    form.objectives
        .insert(objective.objective_id.clone(), objective);
    let fault = form.validate().expect_err("missing task must fail");
    assert!(fault.message.contains("plan task reference is absent"));
}

#[test]
fn admitted_capsule_requires_complete_diffs_reflection_join_and_after_state() {
    let mut form = admitted_capsule_form();
    form.validate()
        .expect("complete admitted capsule must validate");

    form.capsules
        .get_mut(&id("change.one.g1"))
        .unwrap()
        .diff_refs
        .remove(&DiffKind::Proof);
    let fault = form.validate().expect_err("missing proof diff must fail");
    assert!(fault.message.contains("all eight diff kinds"));

    let mut form = admitted_capsule_form();
    form.capsules
        .get_mut(&id("change.one.g1"))
        .unwrap()
        .after_snapshot_ref = None;
    let fault = form
        .validate()
        .expect_err("missing after snapshot must fail");
    assert!(fault.message.contains("lacks an after snapshot"));
}

#[test]
fn reflection_must_use_a_retrospective_cursor_for_the_exact_capsule() {
    let mut form = admitted_capsule_form();
    form.lane_cursors.get_mut(&id("lane.rear")).unwrap().kind = LaneKind::Prospective;
    let fault = form.validate().expect_err("wrong lane kind must fail");
    assert!(fault.message.contains("not retrospective"));

    let mut form = admitted_capsule_form();
    form.lane_cursors
        .get_mut(&id("lane.rear"))
        .unwrap()
        .capsule_generation_ref = id("change.other.g1");
    let fault = form
        .validate()
        .expect_err("wrong capsule generation must fail");
    assert!(fault.message.contains("different capsule generation"));
}

#[test]
fn checked_compiler_generation_needs_independent_correspondence_evidence() {
    let mut form = TemporalFormSet::new();
    let generation = cantor_core::CompilerGeneration {
        compiler_generation_id: id("compiler.g1"),
        predecessor_generation_refs: BTreeSet::new(),
        source_generation_refs: refs(&["source.g1"]),
        dependency_lock_ref: id("dependency.lock"),
        language_profile_ref: id("language.profile"),
        compiler_identity_ref: id("compiler.identity"),
        semantic_ir_root: digest("semantic-ir"),
        target_profile_refs: refs(&["target.exact"]),
        target_artifact_refs: refs(&["artifact.exact"]),
        correspondence_evidence_refs: refs(&["generator.claim"]),
        independent_correspondence_evidence_refs: BTreeSet::new(),
        loss_records: BTreeSet::new(),
        diagnostics: BTreeSet::new(),
        proof_bundle_ref: id("proof.bundle"),
        stage: CompilerStage::CorrespondenceChecked,
    };
    form.compiler_generations
        .insert(generation.compiler_generation_id.clone(), generation);
    let fault = form
        .validate()
        .expect_err("self-certified target must fail");
    assert!(
        fault
            .message
            .contains("independent correspondence evidence")
    );
}

fn admitted_capsule_form() -> TemporalFormSet {
    let task = TaskContract {
        task_id: id("task.one"),
        purpose: "prove a pure transition form".to_owned(),
        source_ref: id("source.task"),
        principal_refs: refs(&["principal.user"]),
        input_refs: refs(&["snapshot.before"]),
        target_refs: refs(&["subject.one"]),
        preconditions: BTreeSet::new(),
        assumptions: BTreeSet::new(),
        invariants: texts(&["no external effect"]),
        authority_request_refs: BTreeSet::new(),
        effect_boundary: texts(&["none"]),
        completion_criteria: texts(&["all diff kinds reviewed"]),
        stop_conditions: texts(&["validation failure"]),
        privacy_profile_ref: id("privacy.local"),
        retention_profile_ref: id("retention.proof"),
        current_plan_revision_ref: Some(id("plan.one.rev1")),
    };
    let objective = ObjectiveNode {
        objective_id: id("objective.one"),
        task_ref: task.task_id.clone(),
        statement: "admit a reviewed candidate".to_owned(),
        desired_state_criteria: texts(&["reviewed", "reconciled"]),
        priority_source_ref: id("source.priority"),
        uncertainty: BTreeSet::new(),
        status: ObjectiveStatus::Satisfied,
        proof_route: texts(&["fixture"]),
    };
    let plan = PlanRevision {
        plan_id: id("plan.one"),
        revision_id: id("plan.one.rev1"),
        predecessor_revision_ref: None,
        task_ref: task.task_id.clone(),
        objective_refs: BTreeSet::from([objective.objective_id.clone()]),
        dependency_refs: BTreeSet::new(),
        temporal_refs: BTreeSet::new(),
        effect_refs: BTreeSet::new(),
        review_refs: refs(&["review.expected"]),
        selected_alternative_ref: None,
        assumptions: BTreeSet::new(),
        uncertainty: BTreeSet::new(),
        state: PlanState::Completed,
    };
    let generation = RepositoryGeneration {
        repository_id: id("repository.one"),
        generation_id: id("repository.g1"),
        predecessor_generation_refs: BTreeSet::new(),
        repository_policy_ref: id("repository.policy"),
        event_frontier: BTreeSet::new(),
        snapshot_root_ref: Some(id("snapshot.before")),
        reference_index_generation_ref: None,
        created_by_disposition_ref: Some(id("join.previous")),
        root_digest: digest("repository-g1"),
        status: RepositoryStatus::Admitted,
    };
    let before = snapshot("snapshot.before");
    let after = snapshot("snapshot.after");
    let intent = DeclaredIntent {
        intent_id: id("intent.one"),
        target_refs: refs(&["subject.one"]),
        expected_transformations: texts(&["validated semantic change"]),
        allowed_effects: BTreeSet::new(),
        completion_evidence: texts(&["reflection and join"]),
        unrelated_state_exclusions: refs(&["subject.unrelated"]),
        source_ref: id("source.intent"),
    };
    let cursor = LaneCursor {
        cursor_id: id("lane.rear"),
        kind: LaneKind::Retrospective,
        task_ref: task.task_id.clone(),
        input_repository_generation_ref: generation.generation_id.clone(),
        plan_revision_ref: plan.revision_id.clone(),
        capsule_generation_ref: id("change.one.g1"),
        dependency_refs: BTreeSet::new(),
        authority_request_ref: None,
        state: LaneState::Returned,
        lease_ref: None,
        timeout_ref: None,
        last_message_ref: None,
    };
    let reflection = ReflectionReturn {
        return_id: id("reflection.one"),
        retrospective_cursor_ref: cursor.cursor_id.clone(),
        capsule_generation_ref: cursor.capsule_generation_ref.clone(),
        disposition: ReflectionDisposition::Accept,
        evidence_refs: refs(&["proof.fixture"]),
        objections: BTreeSet::new(),
        uncertainty: BTreeSet::new(),
        invalidation_refs: BTreeSet::new(),
        residuals: BTreeSet::new(),
        signature_ref: Some(id("signature.rear")),
        provider_qualification: None,
    };
    let join = ObserverJoin {
        join_id: id("join.one"),
        capsule_generation_ref: cursor.capsule_generation_ref.clone(),
        expected_lane_return_refs: BTreeSet::from([reflection.return_id.clone()]),
        expected_subject_version_refs: refs(&["snapshot.before"]),
        received_return_refs: BTreeSet::from([reflection.return_id.clone()]),
        stale_check_refs: refs(&["stale.check"]),
        reconciliation_record_ref: id("reconciliation.one"),
        disposition: JoinDisposition::Admit,
        successor_repository_generation_ref: Some(id("repository.g2")),
        release_refs: refs(&["objective.one"]),
        residuals: BTreeSet::new(),
    };
    let mut diffs = BTreeMap::new();
    let mut diff_refs = BTreeMap::new();
    for kind in [
        DiffKind::Physical,
        DiffKind::Source,
        DiffKind::Semantic,
        DiffKind::Build,
        DiffKind::Behavioral,
        DiffKind::Effect,
        DiffKind::Proof,
        DiffKind::Calendar,
    ] {
        let suffix = format!("{kind:?}").to_ascii_lowercase();
        let diff_id = id(&format!("diff.{suffix}"));
        diffs.insert(
            diff_id.clone(),
            DiffRecord {
                diff_id: diff_id.clone(),
                kind,
                before_subject_ref: id("snapshot.before"),
                candidate_subject_ref: id("snapshot.candidate"),
                added_refs: BTreeSet::new(),
                changed_refs: BTreeSet::new(),
                removed_refs: BTreeSet::new(),
                preserved_refs: refs(&["subject.one"]),
                unrelated_refs: refs(&["subject.unrelated"]),
                derivation_method: "deterministic fixture".to_owned(),
                independent_evidence_refs: refs(&["proof.fixture"]),
                confidence_or_completeness: "complete".to_owned(),
                invalidations: BTreeMap::new(),
                loss_and_unknown: BTreeSet::new(),
            },
        );
        diff_refs.insert(kind, diff_id);
    }
    let capsule = ChangeCapsule {
        change_id: id("change.one"),
        candidate_generation_id: id("change.one.g1"),
        task_ref: task.task_id.clone(),
        plan_revision_ref: plan.revision_id.clone(),
        repository_generation_ref: generation.generation_id.clone(),
        before_snapshot_ref: before.snapshot_id.clone(),
        declared_intent_ref: intent.intent_id.clone(),
        prepared_candidate_ref: Some(id("candidate.one")),
        execution_request_ref: None,
        execution_outcome_ref: None,
        candidate_snapshot_ref: Some(id("snapshot.candidate")),
        diff_refs,
        justification_delta: texts(&["fixture justification"]),
        support_delta: texts(&["fixture support"]),
        requirement_delta: texts(&["none"]),
        compiler_impact_ref: None,
        reflection_return_ref: Some(reflection.return_id.clone()),
        reflection_exception_ref: None,
        observer_join_ref: Some(join.join_id.clone()),
        after_snapshot_ref: Some(after.snapshot_id.clone()),
        state: CapsuleState::Admitted,
    };

    let mut form = TemporalFormSet::new();
    form.task_contracts.insert(task.task_id.clone(), task);
    form.objectives
        .insert(objective.objective_id.clone(), objective);
    form.plan_revisions.insert(plan.revision_id.clone(), plan);
    form.repository_generations
        .insert(generation.generation_id.clone(), generation);
    form.snapshots.insert(before.snapshot_id.clone(), before);
    form.snapshots.insert(after.snapshot_id.clone(), after);
    form.declared_intents
        .insert(intent.intent_id.clone(), intent);
    form.lane_cursors.insert(cursor.cursor_id.clone(), cursor);
    form.reflection_returns
        .insert(reflection.return_id.clone(), reflection);
    form.observer_joins.insert(join.join_id.clone(), join);
    form.diffs = diffs;
    form.capsules
        .insert(capsule.candidate_generation_id.clone(), capsule);
    form
}

fn snapshot(snapshot_id: &str) -> SemanticSnapshot {
    SemanticSnapshot {
        snapshot_id: id(snapshot_id),
        repository_id: id("repository.one"),
        predecessor_snapshot_refs: BTreeSet::new(),
        event_frontier: refs(&["event.frontier"]),
        canonical_state_root: digest(&format!("state-{snapshot_id}")),
        projection_manifest_ref: None,
        content_object_refs: BTreeSet::new(),
        reconciliation_evidence_refs: BTreeSet::new(),
        loss_records: BTreeSet::new(),
        atomic_external_world_claim: false,
        snapshot_digest: digest(&format!("digest-{snapshot_id}")),
    }
}
