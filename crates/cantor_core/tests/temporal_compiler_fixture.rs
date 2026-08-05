use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{
    CapsuleState, ChangeCapsule, CompilerFixtureManifest, CompilerFixtureStatus,
    CompilerGeneration, CompilerImpact, CompilerStage, ConstraintSeverity, ContentInput,
    ContentObject, DeclaredIntent, DiffKind, DiffRecord, InvalidationEdge, JoinDisposition,
    LaneCursor, LaneKind, LaneState, ObserverJoin, ReflectionDisposition, ReflectionReturn,
    RuntimeEvaluation, RuntimeFaultKind, RuntimeOperation, RuntimeOutput, RuntimeSnapshot,
    SemanticId, SensitivityClass, evaluate_runtime, from_normalized_runtime_snapshot, sha256_bytes,
    to_normalized_runtime_snapshot,
};

mod temporal_runtime_support;

use temporal_runtime_support::{
    accepted, append_observation, calendar_revision, context, id, ids, initial_runtime,
    initialize_repository, propose_plan, texts,
};

fn prepared_runtime() -> RuntimeSnapshot {
    propose_plan(&calendar_revision(&append_observation(
        &initialize_repository(&initial_runtime()),
    )))
}

fn compiler_runtime(omit_proof_from_observer: bool) -> RuntimeSnapshot {
    let runtime = prepared_runtime();
    let mut root = runtime.root;
    let intent = DeclaredIntent {
        intent_id: id("intent.compiler.fixture"),
        target_refs: ids(&["compiler.candidate"]),
        expected_transformations: texts(&["compare fixed compiler generations"]),
        allowed_effects: BTreeSet::new(),
        completion_evidence: texts(&["Observer compiler fixture disposition"]),
        unrelated_state_exclusions: ids(&["unrelated.stable"]),
        source_ref: id("source.fixture"),
    };
    let lane = LaneCursor {
        cursor_id: id("lane.compiler.rear"),
        kind: LaneKind::Retrospective,
        task_ref: id("task.one"),
        input_repository_generation_ref: id("generation.two"),
        plan_revision_ref: id("plan.one.rev1"),
        capsule_generation_ref: id("capsule.compiler.fixture"),
        dependency_refs: BTreeSet::new(),
        authority_request_ref: None,
        state: LaneState::Returned,
        lease_ref: None,
        timeout_ref: None,
        last_message_ref: None,
    };
    let reflection = ReflectionReturn {
        return_id: id("reflection.compiler.fixture"),
        retrospective_cursor_ref: lane.cursor_id.clone(),
        capsule_generation_ref: id("capsule.compiler.fixture"),
        disposition: ReflectionDisposition::Qualify,
        evidence_refs: ids(&["corr.rear"]),
        objections: BTreeSet::new(),
        uncertainty: texts(&["bounded fixture only"]),
        invalidation_refs: BTreeSet::new(),
        residuals: texts(&["no general compiler claim"]),
        signature_ref: None,
        provider_qualification: None,
    };
    let mut subjects = ids(&[
        "compiler.candidate",
        "compiler.checked",
        "impact.compiler",
        "prediction.compiler",
        "rear.compiler",
        "corr.rear",
        "proof.bundle",
    ]);
    for kind in complete_diff_kinds() {
        subjects.insert(diff_id(kind));
    }
    if omit_proof_from_observer {
        subjects.remove(&id("proof.bundle"));
    }
    let join = ObserverJoin {
        join_id: id("join.compiler.fixture"),
        capsule_generation_ref: id("capsule.compiler.fixture"),
        expected_lane_return_refs: ids(&["reflection.compiler.fixture"]),
        expected_subject_version_refs: subjects,
        received_return_refs: ids(&["reflection.compiler.fixture"]),
        stale_check_refs: ids(&["plan.one.rev1", "generation.two"]),
        reconciliation_record_ref: id("reconciliation.compiler.fixture"),
        disposition: JoinDisposition::Qualify,
        successor_repository_generation_ref: None,
        release_refs: BTreeSet::new(),
        residuals: texts(&["fixture-only disposition"]),
    };
    let capsule = ChangeCapsule {
        change_id: id("change.compiler.fixture"),
        candidate_generation_id: id("capsule.compiler.fixture"),
        task_ref: id("task.one"),
        plan_revision_ref: id("plan.one.rev1"),
        repository_generation_ref: id("generation.two"),
        before_snapshot_ref: id("snapshot.one"),
        declared_intent_ref: intent.intent_id.clone(),
        prepared_candidate_ref: Some(id("compiler.candidate")),
        execution_request_ref: None,
        execution_outcome_ref: None,
        candidate_snapshot_ref: None,
        diff_refs: BTreeMap::new(),
        justification_delta: BTreeSet::new(),
        support_delta: BTreeSet::new(),
        requirement_delta: BTreeSet::new(),
        compiler_impact_ref: Some(id("impact.compiler")),
        reflection_return_ref: Some(reflection.return_id.clone()),
        reflection_exception_ref: None,
        observer_join_ref: Some(join.join_id.clone()),
        after_snapshot_ref: None,
        state: CapsuleState::Reconciled,
    };
    root.forms
        .declared_intents
        .insert(intent.intent_id.clone(), intent);
    root.forms.lane_cursors.insert(lane.cursor_id.clone(), lane);
    root.forms
        .reflection_returns
        .insert(reflection.return_id.clone(), reflection);
    root.forms.observer_joins.insert(join.join_id.clone(), join);
    root.forms
        .capsules
        .insert(capsule.candidate_generation_id.clone(), capsule);
    RuntimeSnapshot::from_root(root).expect("imported Observer fixture is valid")
}

fn content(identity: &str, value: &[u8]) -> ContentInput {
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

fn fixture_content() -> Vec<ContentInput> {
    vec![
        content("source.before", b"Subject: Before"),
        content("source.candidate", b"Subject: Candidate"),
        content("semantic.before", b"semantic-ir-before"),
        content("semantic.candidate", b"semantic-ir-candidate"),
        content("build.candidate", b"build-ir-candidate"),
        content("target.meta", b"target-metadata"),
        content("corr.forward", b"forward-correspondence"),
        content("corr.rear", b"independent-rear-correspondence"),
        content("proof.bundle", b"fixture-proof"),
    ]
}

fn content_digest(content: &[ContentInput], identity: &str) -> cantor_core::ContentDigest {
    content
        .iter()
        .find(|input| input.object.object_id == id(identity))
        .expect("fixture content exists")
        .object
        .digest
        .clone()
}

fn manifest() -> CompilerFixtureManifest {
    CompilerFixtureManifest {
        fixture_id: id("fixture.compiler"),
        before_generation_ref: id("compiler.before"),
        candidate_generation_ref: id("compiler.candidate"),
        source_object_refs: ids(&["source.before", "source.candidate"]),
        semantic_ir_object_refs: ids(&["semantic.before", "semantic.candidate"]),
        build_ir_object_refs: ids(&["build.candidate"]),
        target_metadata_object_refs: ids(&["target.meta"]),
        correspondence_evidence_refs: ids(&["corr.forward"]),
        independent_correspondence_evidence_refs: ids(&["corr.rear"]),
        proof_record_refs: ids(&["proof.bundle"]),
        required_diff_kinds: complete_diff_kinds(),
        declared_unrelated_refs: ids(&["unrelated.stable"]),
        observer_join_ref: id("join.compiler.fixture"),
        max_fixture_records: 32,
    }
}

fn generations(content: &[ContentInput]) -> (CompilerGeneration, CompilerGeneration) {
    let before = CompilerGeneration {
        compiler_generation_id: id("compiler.before"),
        predecessor_generation_refs: BTreeSet::new(),
        source_generation_refs: ids(&["source.before"]),
        dependency_lock_ref: id("lock.before"),
        language_profile_ref: id("language.fixture"),
        compiler_identity_ref: id("compiler.fixture.identity"),
        semantic_ir_root: content_digest(content, "semantic.before"),
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
        compiler_generation_id: id("compiler.candidate"),
        predecessor_generation_refs: ids(&["compiler.before"]),
        source_generation_refs: ids(&["source.candidate"]),
        dependency_lock_ref: id("lock.candidate"),
        language_profile_ref: id("language.fixture"),
        compiler_identity_ref: id("compiler.fixture.identity"),
        semantic_ir_root: content_digest(content, "semantic.candidate"),
        target_profile_refs: ids(&["target.fixture"]),
        target_artifact_refs: ids(&["target.meta"]),
        correspondence_evidence_refs: ids(&["corr.forward"]),
        independent_correspondence_evidence_refs: ids(&["corr.rear"]),
        loss_records: texts(&["unknown: target execution behavior"]),
        diagnostics: texts(&["fixture diagnostic"]),
        proof_bundle_ref: id("proof.bundle"),
        stage: CompilerStage::Projected,
    };
    (before, candidate)
}

fn impact() -> CompilerImpact {
    CompilerImpact {
        impact_id: id("impact.compiler"),
        compiler_generation_ref: id("compiler.candidate"),
        changed_source_refs: ids(&["source.candidate"]),
        changed_semantic_refs: ids(&["semantic.candidate"]),
        invalidated_ir_refs: ids(&["ir.downstream"]),
        invalidated_index_refs: BTreeSet::new(),
        invalidated_package_refs: BTreeSet::new(),
        invalidated_schedule_refs: BTreeSet::new(),
        invalidated_workflow_refs: BTreeSet::new(),
        invalidated_model_refs: BTreeSet::new(),
        invalidated_tool_schema_refs: BTreeSet::new(),
        invalidated_hardware_refs: BTreeSet::new(),
    }
}

fn complete_diff_kinds() -> BTreeSet<DiffKind> {
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

fn diff_name(kind: DiffKind) -> &'static str {
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

fn diff_id(kind: DiffKind) -> SemanticId {
    id(&format!("diff.compiler.{}", diff_name(kind)))
}

fn diffs(mismatched_semantic: bool) -> Vec<DiffRecord> {
    complete_diff_kinds()
        .into_iter()
        .map(|kind| {
            let changed_refs = match kind {
                DiffKind::Source => ids(&["source.candidate"]),
                DiffKind::Semantic if mismatched_semantic => ids(&["semantic.unexpected"]),
                DiffKind::Semantic => ids(&["semantic.candidate"]),
                _ => BTreeSet::new(),
            };
            let invalidations = if kind == DiffKind::Semantic {
                let edge = InvalidationEdge {
                    invalidation_id: id("invalidation.ir.downstream"),
                    cause_ref: if mismatched_semantic {
                        id("semantic.unexpected")
                    } else {
                        id("semantic.candidate")
                    },
                    source_generation_ref: id("compiler.candidate"),
                    affected_subject_ref: id("ir.downstream"),
                    required_action: "rebuild exact downstream IR".to_owned(),
                    severity: ConstraintSeverity::Blocking,
                    resolution_ref: None,
                };
                BTreeMap::from([(edge.invalidation_id.clone(), edge)])
            } else {
                BTreeMap::new()
            };
            DiffRecord {
                diff_id: diff_id(kind),
                kind,
                before_subject_ref: id("compiler.before"),
                candidate_subject_ref: id("compiler.candidate"),
                added_refs: BTreeSet::new(),
                changed_refs,
                removed_refs: BTreeSet::new(),
                preserved_refs: ids(&["unrelated.stable"]),
                unrelated_refs: ids(&["unrelated.stable"]),
                derivation_method: "independent fixed rear comparator".to_owned(),
                independent_evidence_refs: ids(&["corr.rear"]),
                confidence_or_completeness: "complete for fixed fixture".to_owned(),
                invalidations,
                loss_and_unknown: texts(&["unknown: external execution not performed"]),
            }
        })
        .collect()
}

fn register(
    runtime: &RuntimeSnapshot,
    operation_id: &str,
    mismatched_semantic: bool,
) -> RuntimeEvaluation {
    let content = fixture_content();
    let (before_generation, candidate_generation) = generations(&content);
    evaluate_runtime(
        runtime,
        &RuntimeOperation::RegisterCompilerFixture {
            context: context(runtime, operation_id),
            manifest: manifest(),
            before_generation: Box::new(before_generation),
            candidate_generation: Box::new(candidate_generation),
            impact: Box::new(impact()),
            content,
            diffs: diffs(mismatched_semantic),
        },
    )
}

fn forward(runtime: &RuntimeSnapshot) -> RuntimeSnapshot {
    accepted(evaluate_runtime(
        runtime,
        &RuntimeOperation::RunCompilerForward {
            context: context(runtime, "operation.compiler.forward"),
            fixture_ref: id("fixture.compiler"),
            prediction_id: id("prediction.compiler"),
        },
    ))
    .0
}

fn rear(runtime: &RuntimeSnapshot) -> (RuntimeSnapshot, cantor_core::RuntimeReceipt) {
    accepted(evaluate_runtime(
        runtime,
        &RuntimeOperation::RunCompilerRear {
            context: context(runtime, "operation.compiler.rear"),
            fixture_ref: id("fixture.compiler"),
            rear_check_id: id("rear.compiler"),
        },
    ))
}

#[test]
fn fixed_dual_pass_fixture_reaches_observer_checked_state() {
    let runtime = compiler_runtime(false);
    let (runtime, receipt) = accepted(register(&runtime, "operation.compiler.register", false));
    assert!(matches!(
        receipt.output,
        RuntimeOutput::CompilerFixtureRegistered { .. }
    ));
    let runtime = forward(&runtime);
    let prediction = &runtime.root.compiler.forward_predictions[&id("prediction.compiler")];
    assert_eq!(
        prediction.predicted_changed_source_refs,
        ids(&["source.candidate"])
    );
    assert_eq!(
        prediction.predicted_changed_semantic_refs,
        ids(&["semantic.candidate"])
    );
    assert_eq!(
        prediction.predicted_invalidated_refs,
        ids(&["ir.downstream"])
    );
    assert_eq!(
        prediction.predicted_target_artifact_refs,
        ids(&["target.meta"])
    );
    assert_eq!(
        prediction.predicted_proof_requirement_refs,
        ids(&["proof.bundle"])
    );
    let (runtime, receipt) = rear(&runtime);
    match receipt.output {
        RuntimeOutput::CompilerRearCheck {
            rear_check,
            invalidated_refs,
        } => {
            assert!(rear_check.matched_forward_prediction);
            assert!(invalidated_refs.is_empty());
            assert_eq!(rear_check.diff_refs.len(), 8);
            assert_eq!(
                rear_check.independent_correspondence_evidence_refs,
                ids(&["corr.rear"])
            );
            assert_eq!(
                rear_check.preserved_unrelated_refs,
                ids(&["unrelated.stable"])
            );
        }
        _ => panic!("rear fixture output expected"),
    }
    let (runtime, receipt) = accepted(evaluate_runtime(
        &runtime,
        &RuntimeOperation::CheckCompilerFixture {
            context: context(&runtime, "operation.compiler.check"),
            fixture_ref: id("fixture.compiler"),
            checked_generation_id: id("compiler.checked"),
        },
    ));
    assert!(matches!(
        receipt.output,
        RuntimeOutput::CompilerFixtureChecked { .. }
    ));
    assert_eq!(
        runtime.root.compiler.fixtures[&id("fixture.compiler")].status,
        CompilerFixtureStatus::Checked
    );
    assert_eq!(
        runtime.root.forms.compiler_generations[&id("compiler.candidate")].stage,
        CompilerStage::Projected
    );
    assert_eq!(
        runtime.root.forms.compiler_generations[&id("compiler.checked")].stage,
        CompilerStage::ProofChecked
    );
    let normalized = to_normalized_runtime_snapshot(&runtime).expect("runtime normalizes");
    assert_eq!(
        from_normalized_runtime_snapshot(&normalized).expect("runtime restores"),
        runtime
    );
}

#[test]
fn rear_mismatch_invalidates_exact_derived_set_and_preserves_unrelated() {
    let runtime = compiler_runtime(false);
    let runtime = accepted(register(
        &runtime,
        "operation.compiler.register.mismatch",
        true,
    ))
    .0;
    let runtime = forward(&runtime);
    let (runtime, receipt) = rear(&runtime);
    let expected = ids(&[
        "compiler.candidate",
        "prediction.compiler",
        "ir.downstream",
        "target.meta",
    ]);
    match receipt.output {
        RuntimeOutput::CompilerRearCheck {
            rear_check,
            invalidated_refs,
        } => {
            assert!(!rear_check.matched_forward_prediction);
            assert_eq!(invalidated_refs, expected);
        }
        _ => panic!("rear fixture output expected"),
    }
    let record = &runtime.root.compiler.fixtures[&id("fixture.compiler")];
    assert_eq!(record.status, CompilerFixtureStatus::Invalidated);
    assert_eq!(record.invalidated_refs, expected);
    assert_eq!(record.preserved_unrelated_refs, ids(&["unrelated.stable"]));
    assert!(
        record
            .invalidated_refs
            .is_disjoint(&record.preserved_unrelated_refs)
    );
    match evaluate_runtime(
        &runtime,
        &RuntimeOperation::CheckCompilerFixture {
            context: context(&runtime, "operation.compiler.check.invalidated"),
            fixture_ref: id("fixture.compiler"),
            checked_generation_id: id("compiler.checked"),
        },
    ) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::IllegalTransition)
        }
        _ => panic!("invalidated fixture cannot become checked"),
    }
}

#[test]
fn incomplete_diff_and_tampered_content_refuse_without_successor() {
    let runtime = compiler_runtime(false);
    let content = fixture_content();
    let (before_generation, candidate_generation) = generations(&content);
    let mut incomplete = diffs(false);
    incomplete.pop();
    let operation = RuntimeOperation::RegisterCompilerFixture {
        context: context(&runtime, "operation.compiler.incomplete-diff"),
        manifest: manifest(),
        before_generation: Box::new(before_generation.clone()),
        candidate_generation: Box::new(candidate_generation.clone()),
        impact: Box::new(impact()),
        content: content.clone(),
        diffs: incomplete,
    };
    match evaluate_runtime(&runtime, &operation) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::IncompleteDiff)
        }
        _ => panic!("incomplete diff set must refuse"),
    }
    let mut tampered = content;
    tampered[0].bytes.push(b'!');
    let operation = RuntimeOperation::RegisterCompilerFixture {
        context: context(&runtime, "operation.compiler.tampered-content"),
        manifest: manifest(),
        before_generation: Box::new(before_generation),
        candidate_generation: Box::new(candidate_generation),
        impact: Box::new(impact()),
        content: tampered,
        diffs: diffs(false),
    };
    match evaluate_runtime(&runtime, &operation) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::InvalidForm)
        }
        _ => panic!("tampered fixture content must refuse"),
    }
}

#[test]
fn observer_must_cover_the_complete_compiler_proof_subject_set() {
    let runtime = compiler_runtime(true);
    let runtime = accepted(register(
        &runtime,
        "operation.compiler.register.observer-gap",
        false,
    ))
    .0;
    let runtime = forward(&runtime);
    let runtime = rear(&runtime).0;
    match evaluate_runtime(
        &runtime,
        &RuntimeOperation::CheckCompilerFixture {
            context: context(&runtime, "operation.compiler.check.observer-gap"),
            fixture_ref: id("fixture.compiler"),
            checked_generation_id: id("compiler.checked"),
        },
    ) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::MissingCorrespondence)
        }
        _ => panic!("Observer must cover the proof bundle and every compiler subject"),
    }
}

#[test]
fn fixture_bounds_generation_coordinates_and_category_independence_fail_closed() {
    let runtime = compiler_runtime(false);
    let content = fixture_content();
    let (before_generation, mut candidate_generation) = generations(&content);
    candidate_generation.predecessor_generation_refs.clear();
    let operation = RuntimeOperation::RegisterCompilerFixture {
        context: context(&runtime, "operation.compiler.wrong-generation"),
        manifest: manifest(),
        before_generation: Box::new(before_generation.clone()),
        candidate_generation: Box::new(candidate_generation),
        impact: Box::new(impact()),
        content: content.clone(),
        diffs: diffs(false),
    };
    match evaluate_runtime(&runtime, &operation) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::WrongGeneration)
        }
        _ => panic!("wrong compiler predecessor must refuse"),
    }

    let (_, candidate_generation) = generations(&content);
    let mut bounded_manifest = manifest();
    bounded_manifest.max_fixture_records = 1;
    let operation = RuntimeOperation::RegisterCompilerFixture {
        context: context(&runtime, "operation.compiler.fixture-bound"),
        manifest: bounded_manifest,
        before_generation: Box::new(before_generation.clone()),
        candidate_generation: Box::new(candidate_generation.clone()),
        impact: Box::new(impact()),
        content: content.clone(),
        diffs: diffs(false),
    };
    match evaluate_runtime(&runtime, &operation) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::BoundExhausted)
        }
        _ => panic!("fixture record bound must refuse"),
    }

    let mut conflated_manifest = manifest();
    conflated_manifest.independent_correspondence_evidence_refs = ids(&["corr.forward"]);
    let operation = RuntimeOperation::RegisterCompilerFixture {
        context: context(&runtime, "operation.compiler.conflated-evidence"),
        manifest: conflated_manifest,
        before_generation: Box::new(before_generation),
        candidate_generation: Box::new(candidate_generation),
        impact: Box::new(impact()),
        content,
        diffs: diffs(false),
    };
    match evaluate_runtime(&runtime, &operation) {
        RuntimeEvaluation::Refused { fault } => {
            assert_eq!(fault.kind, RuntimeFaultKind::InvalidForm)
        }
        _ => panic!("forward and independent rear evidence must not collapse"),
    }
}

#[test]
fn derived_record_digest_tampering_is_detected_on_root_reconstruction() {
    let runtime = compiler_runtime(false);
    let runtime = accepted(register(
        &runtime,
        "operation.compiler.register.tamper-check",
        false,
    ))
    .0;
    let runtime = forward(&runtime);
    let mut root = runtime.root;
    root.compiler
        .forward_predictions
        .get_mut(&id("prediction.compiler"))
        .expect("prediction exists")
        .predicted_diagnostics
        .insert("tampered diagnostic".to_owned());
    assert!(RuntimeSnapshot::from_root(root).is_err());
}
