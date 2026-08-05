//! Fixed, effectless compiler-diff fixtures for CDRA-I05.

#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::{
    CompilerGeneration, CompilerImpact, CompilerStage, ContentDigest, ContentObject, DiffKind,
    DiffRecord, EvaluationFault, FaultKind, JoinDisposition, SemanticId, TemporalFormSet,
    sha256_bytes,
};

use super::evaluator::{TransitionResult, duplicate_fault, make_fault, missing_fault};
use super::{
    CompilerFixtureManifest, CompilerFixtureRecord, CompilerFixtureStatus,
    CompilerForwardPrediction, CompilerRearCheck, ContentInput, DeterministicRuntimeRoot,
    RuntimeFault, RuntimeFaultKind, RuntimeOperationContext, RuntimeOutput,
};

const COMPLETE_DIFF_KINDS: [DiffKind; 8] = [
    DiffKind::Physical,
    DiffKind::Source,
    DiffKind::Semantic,
    DiffKind::Build,
    DiffKind::Behavioral,
    DiffKind::Effect,
    DiffKind::Proof,
    DiffKind::Calendar,
];

#[allow(clippy::too_many_arguments)]
pub(crate) fn register_compiler_fixture(
    root: &mut DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    manifest: &CompilerFixtureManifest,
    before_generation: &CompilerGeneration,
    candidate_generation: &CompilerGeneration,
    impact: &CompilerImpact,
    content: &[ContentInput],
    diffs: &[DiffRecord],
) -> Result<TransitionResult, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    if root.compiler.fixtures.contains_key(&manifest.fixture_id) {
        return Err(duplicate_fault(
            context,
            &manifest.fixture_id,
            trace_location,
        ));
    }
    let required = COMPLETE_DIFF_KINDS.into_iter().collect::<BTreeSet<_>>();
    let fixture_record_count = content
        .len()
        .checked_add(diffs.len())
        .and_then(|count| count.checked_add(4))
        .ok_or_else(|| bound_fault(context, &manifest.fixture_id, trace_location))?;
    if manifest.max_fixture_records == 0
        || fixture_record_count > manifest.max_fixture_records
        || fixture_record_count > context.limits.max_graph_visits
        || manifest.required_diff_kinds != required
    {
        return Err(make_fault(
            context,
            RuntimeFaultKind::BoundExhausted,
            BTreeSet::from([manifest.fixture_id.clone()]),
            "positive fixture bound, complete eight-kind diff set, and bounded supplied records",
            format!(
                "records={fixture_record_count}, fixture_bound={}, graph_bound={}, diff_kinds={:?}",
                manifest.max_fixture_records,
                context.limits.max_graph_visits,
                manifest.required_diff_kinds
            ),
            BTreeSet::from(["bounded compiler fixture".to_owned()]),
            trace_location,
        ));
    }
    validate_manifest_categories(context, manifest, content, trace_location)?;
    validate_generation_coordinates(
        context,
        manifest,
        before_generation,
        candidate_generation,
        impact,
        content,
        trace_location,
    )?;
    validate_diffs(context, manifest, diffs, impact, trace_location)?;

    let mut forms = root.forms.clone();
    let mut emitted = BTreeSet::from([
        manifest.fixture_id.clone(),
        before_generation.compiler_generation_id.clone(),
        candidate_generation.compiler_generation_id.clone(),
        impact.impact_id.clone(),
    ]);
    for input in content {
        if input.bytes.len() as u64 != input.object.byte_length
            || sha256_bytes(&input.bytes) != input.object.digest
        {
            return Err(make_fault(
                context,
                RuntimeFaultKind::InvalidForm,
                BTreeSet::from([input.object.object_id.clone()]),
                "content length and SHA-256 equal the supplied immutable object",
                "compiler fixture content digest or length mismatch",
                BTreeSet::from(["fixed fixture content".to_owned()]),
                trace_location,
            ));
        }
        if forms
            .content_objects
            .insert(input.object.object_id.clone(), input.object.clone())
            .is_some()
            || root
                .repository
                .content_bytes
                .contains_key(&input.object.object_id)
        {
            return Err(duplicate_fault(
                context,
                &input.object.object_id,
                trace_location,
            ));
        }
        emitted.insert(input.object.object_id.clone());
    }
    for generation in [before_generation, candidate_generation] {
        if forms
            .compiler_generations
            .insert(
                generation.compiler_generation_id.clone(),
                generation.clone(),
            )
            .is_some()
        {
            return Err(duplicate_fault(
                context,
                &generation.compiler_generation_id,
                trace_location,
            ));
        }
    }
    if forms
        .compiler_impacts
        .insert(impact.impact_id.clone(), impact.clone())
        .is_some()
    {
        return Err(duplicate_fault(context, &impact.impact_id, trace_location));
    }
    for diff in diffs {
        if forms
            .diffs
            .insert(diff.diff_id.clone(), diff.clone())
            .is_some()
        {
            return Err(duplicate_fault(context, &diff.diff_id, trace_location));
        }
        emitted.insert(diff.diff_id.clone());
    }
    forms.validate().map_err(|error| {
        make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            emitted.clone(),
            "valid fixed compiler fixture form graph",
            error.to_string(),
            BTreeSet::from(["compiler fixture form validation".to_owned()]),
            trace_location,
        )
    })?;
    root.forms = forms;
    for input in content {
        root.repository
            .content_bytes
            .insert(input.object.object_id.clone(), input.bytes.clone());
        emitted.insert(input.object.object_id.clone());
    }
    root.repository.index = super::evaluator::rebuild_repository_index(
        &root.forms,
        root.repository.current_generation_ref.as_ref(),
    );
    root.compiler.fixtures.insert(
        manifest.fixture_id.clone(),
        CompilerFixtureRecord {
            manifest: manifest.clone(),
            status: CompilerFixtureStatus::Registered,
            forward_prediction_ref: None,
            rear_check_ref: None,
            checked_observer_join_ref: None,
            checked_generation_ref: None,
            invalidated_refs: BTreeSet::new(),
            preserved_unrelated_refs: manifest.declared_unrelated_refs.clone(),
        },
    );
    Ok(TransitionResult {
        output: RuntimeOutput::CompilerFixtureRegistered {
            fixture_ref: manifest.fixture_id.clone(),
            candidate_generation_ref: manifest.candidate_generation_ref.clone(),
        },
        emitted_identities: emitted,
    })
}

pub(crate) fn run_compiler_forward(
    root: &mut DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    fixture_ref: &SemanticId,
    prediction_id: &SemanticId,
) -> Result<TransitionResult, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    let record = root
        .compiler
        .fixtures
        .get(fixture_ref)
        .ok_or_else(|| missing_fault(context, fixture_ref, trace_location))?;
    if record.status != CompilerFixtureStatus::Registered {
        return Err(state_fault(
            context,
            fixture_ref,
            CompilerFixtureStatus::Registered,
            record.status,
            trace_location,
        ));
    }
    if root
        .compiler
        .forward_predictions
        .contains_key(prediction_id)
    {
        return Err(duplicate_fault(context, prediction_id, trace_location));
    }
    let candidate = &root.forms.compiler_generations[&record.manifest.candidate_generation_ref];
    let impact = root
        .forms
        .compiler_impacts
        .values()
        .find(|impact| impact.compiler_generation_ref == candidate.compiler_generation_id)
        .ok_or_else(|| missing_fault(context, fixture_ref, trace_location))?;
    let mut prediction = CompilerForwardPrediction {
        prediction_id: prediction_id.clone(),
        fixture_ref: fixture_ref.clone(),
        before_generation_ref: record.manifest.before_generation_ref.clone(),
        candidate_generation_ref: record.manifest.candidate_generation_ref.clone(),
        predicted_changed_source_refs: impact.changed_source_refs.clone(),
        predicted_changed_semantic_refs: impact.changed_semantic_refs.clone(),
        predicted_invalidated_refs: impact_invalidations(impact),
        predicted_dependency_refs: BTreeSet::from([candidate.dependency_lock_ref.clone()]),
        predicted_target_artifact_refs: candidate.target_artifact_refs.clone(),
        predicted_diagnostics: candidate.diagnostics.clone(),
        predicted_proof_requirement_refs: BTreeSet::from([candidate.proof_bundle_ref.clone()]),
        explicit_unknowns: candidate.loss_records.clone(),
        prediction_digest: empty_digest(),
    };
    prediction.prediction_digest = digest_forward_prediction(&prediction).map_err(|error| {
        invariant_fault(context, fixture_ref, error.to_string(), trace_location)
    })?;
    root.compiler
        .forward_predictions
        .insert(prediction_id.clone(), prediction.clone());
    let record = root.compiler.fixtures.get_mut(fixture_ref).ok_or_else(|| {
        invariant_fault(context, fixture_ref, "fixture disappeared", trace_location)
    })?;
    record.status = CompilerFixtureStatus::ForwardPredicted;
    record.forward_prediction_ref = Some(prediction_id.clone());
    Ok(TransitionResult {
        output: RuntimeOutput::CompilerForwardPrediction {
            prediction: prediction.clone(),
        },
        emitted_identities: BTreeSet::from([prediction_id.clone()]),
    })
}

pub(crate) fn run_compiler_rear(
    root: &mut DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    fixture_ref: &SemanticId,
    rear_check_id: &SemanticId,
) -> Result<TransitionResult, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    let record = root
        .compiler
        .fixtures
        .get(fixture_ref)
        .ok_or_else(|| missing_fault(context, fixture_ref, trace_location))?;
    if record.status != CompilerFixtureStatus::ForwardPredicted {
        return Err(state_fault(
            context,
            fixture_ref,
            CompilerFixtureStatus::ForwardPredicted,
            record.status,
            trace_location,
        ));
    }
    if root.compiler.rear_checks.contains_key(rear_check_id) {
        return Err(duplicate_fault(context, rear_check_id, trace_location));
    }
    let prediction_ref = record.forward_prediction_ref.as_ref().ok_or_else(|| {
        invariant_fault(
            context,
            fixture_ref,
            "missing forward reference",
            trace_location,
        )
    })?;
    let prediction = root
        .compiler
        .forward_predictions
        .get(prediction_ref)
        .ok_or_else(|| missing_fault(context, prediction_ref, trace_location))?;
    let candidate = &root.forms.compiler_generations[&record.manifest.candidate_generation_ref];
    let diffs = fixture_diffs(&root.forms, &record.manifest, context, trace_location)?;
    let diff_refs = diffs
        .iter()
        .map(|diff| (diff.kind, diff.diff_id.clone()))
        .collect::<BTreeMap<_, _>>();
    let observed_changed_source_refs = changed_for_kind(&diffs, DiffKind::Source);
    let observed_changed_semantic_refs = changed_for_kind(&diffs, DiffKind::Semantic);
    let observed_invalidated_refs = diffs
        .iter()
        .flat_map(|diff| {
            diff.invalidations
                .values()
                .map(|edge| edge.affected_subject_ref.clone())
        })
        .collect::<BTreeSet<_>>();
    let explicit_unknowns = candidate
        .loss_records
        .iter()
        .cloned()
        .chain(
            diffs
                .iter()
                .flat_map(|diff| diff.loss_and_unknown.iter().cloned()),
        )
        .collect::<BTreeSet<_>>();
    let preserved_unrelated_refs = record
        .manifest
        .declared_unrelated_refs
        .iter()
        .filter(|identity| {
            diffs
                .iter()
                .all(|diff| diff.unrelated_refs.contains(*identity))
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    let matched_forward_prediction = observed_changed_source_refs
        == prediction.predicted_changed_source_refs
        && observed_changed_semantic_refs == prediction.predicted_changed_semantic_refs
        && observed_invalidated_refs == prediction.predicted_invalidated_refs
        && preserved_unrelated_refs == record.manifest.declared_unrelated_refs;
    let mut rear = CompilerRearCheck {
        rear_check_id: rear_check_id.clone(),
        fixture_ref: fixture_ref.clone(),
        before_generation_ref: record.manifest.before_generation_ref.clone(),
        candidate_generation_ref: record.manifest.candidate_generation_ref.clone(),
        diff_refs,
        observed_changed_source_refs,
        observed_changed_semantic_refs,
        observed_invalidated_refs: observed_invalidated_refs.clone(),
        independent_correspondence_evidence_refs: record
            .manifest
            .independent_correspondence_evidence_refs
            .clone(),
        preserved_unrelated_refs: preserved_unrelated_refs.clone(),
        explicit_unknowns,
        matched_forward_prediction,
        rear_digest: empty_digest(),
    };
    rear.rear_digest = digest_rear_check(&rear).map_err(|error| {
        invariant_fault(context, fixture_ref, error.to_string(), trace_location)
    })?;
    root.compiler
        .rear_checks
        .insert(rear_check_id.clone(), rear.clone());
    let invalidated_refs = if matched_forward_prediction {
        BTreeSet::new()
    } else {
        prediction
            .predicted_invalidated_refs
            .union(&observed_invalidated_refs)
            .cloned()
            .chain(candidate.target_artifact_refs.iter().cloned())
            .chain([
                record.manifest.candidate_generation_ref.clone(),
                prediction.prediction_id.clone(),
            ])
            .collect()
    };
    if !invalidated_refs.is_disjoint(&record.manifest.declared_unrelated_refs) {
        return Err(invariant_fault(
            context,
            fixture_ref,
            "mismatch invalidation intersects declared unrelated state",
            trace_location,
        ));
    }
    let record = root.compiler.fixtures.get_mut(fixture_ref).ok_or_else(|| {
        invariant_fault(context, fixture_ref, "fixture disappeared", trace_location)
    })?;
    record.rear_check_ref = Some(rear_check_id.clone());
    record.preserved_unrelated_refs = preserved_unrelated_refs;
    record.invalidated_refs = invalidated_refs.clone();
    record.status = if matched_forward_prediction {
        CompilerFixtureStatus::RearCompared
    } else {
        CompilerFixtureStatus::Invalidated
    };
    Ok(TransitionResult {
        output: RuntimeOutput::CompilerRearCheck {
            rear_check: rear.clone(),
            invalidated_refs,
        },
        emitted_identities: BTreeSet::from([rear_check_id.clone()]),
    })
}

pub(crate) fn check_compiler_fixture(
    root: &mut DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    fixture_ref: &SemanticId,
    checked_generation_id: &SemanticId,
) -> Result<TransitionResult, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    let record = root
        .compiler
        .fixtures
        .get(fixture_ref)
        .ok_or_else(|| missing_fault(context, fixture_ref, trace_location))?;
    if record.status != CompilerFixtureStatus::RearCompared {
        return Err(state_fault(
            context,
            fixture_ref,
            CompilerFixtureStatus::RearCompared,
            record.status,
            trace_location,
        ));
    }
    let prediction_ref = record.forward_prediction_ref.as_ref().ok_or_else(|| {
        invariant_fault(
            context,
            fixture_ref,
            "missing forward reference",
            trace_location,
        )
    })?;
    let rear_ref = record.rear_check_ref.as_ref().ok_or_else(|| {
        invariant_fault(
            context,
            fixture_ref,
            "missing rear reference",
            trace_location,
        )
    })?;
    let rear = root
        .compiler
        .rear_checks
        .get(rear_ref)
        .ok_or_else(|| missing_fault(context, rear_ref, trace_location))?;
    if !rear.matched_forward_prediction
        || rear.diff_refs.keys().copied().collect::<BTreeSet<_>>()
            != record.manifest.required_diff_kinds
        || rear.independent_correspondence_evidence_refs.is_empty()
        || !rear
            .independent_correspondence_evidence_refs
            .is_disjoint(&record.manifest.correspondence_evidence_refs)
    {
        return Err(make_fault(
            context,
            RuntimeFaultKind::MissingCorrespondence,
            BTreeSet::from([fixture_ref.clone(), rear_ref.clone()]),
            "matched independent rear check with all eight diff classes",
            "rear correspondence evidence is incomplete or non-independent",
            BTreeSet::from(["compiler fixture correspondence gate".to_owned()]),
            trace_location,
        ));
    }
    let join = root
        .forms
        .observer_joins
        .get(&record.manifest.observer_join_ref)
        .ok_or_else(|| missing_fault(context, &record.manifest.observer_join_ref, trace_location))?
        .clone();
    let impact = root
        .forms
        .compiler_impacts
        .values()
        .find(|impact| impact.compiler_generation_ref == record.manifest.candidate_generation_ref)
        .ok_or_else(|| missing_fault(context, fixture_ref, trace_location))?;
    let mut required_subjects = BTreeSet::from([
        record.manifest.candidate_generation_ref.clone(),
        checked_generation_id.clone(),
        impact.impact_id.clone(),
        prediction_ref.clone(),
        rear_ref.clone(),
    ]);
    required_subjects.extend(rear.diff_refs.values().cloned());
    required_subjects.extend(
        rear.independent_correspondence_evidence_refs
            .iter()
            .cloned(),
    );
    let candidate = root
        .forms
        .compiler_generations
        .get(&record.manifest.candidate_generation_ref)
        .ok_or_else(|| {
            missing_fault(
                context,
                &record.manifest.candidate_generation_ref,
                trace_location,
            )
        })?;
    required_subjects.insert(candidate.proof_bundle_ref.clone());
    let join_is_bound = root.forms.capsules.values().any(|capsule| {
        capsule.observer_join_ref.as_ref() == Some(&join.join_id)
            && matches!(
                capsule.state,
                crate::CapsuleState::Reconciled
                    | crate::CapsuleState::Admitted
                    | crate::CapsuleState::Rejected
                    | crate::CapsuleState::Reverted
                    | crate::CapsuleState::Compensated
            )
    });
    if !matches!(
        join.disposition,
        JoinDisposition::Admit | JoinDisposition::Qualify
    ) || !join_is_bound
        || !required_subjects.is_subset(&join.expected_subject_version_refs)
    {
        return Err(make_fault(
            context,
            RuntimeFaultKind::MissingCorrespondence,
            BTreeSet::from([fixture_ref.clone(), join.join_id.clone()]),
            "bound admitting or qualifying Observer disposition over every compiler proof subject",
            "Observer compiler-check subject or disposition mismatch",
            BTreeSet::from(["compiler fixture Observer gate".to_owned()]),
            trace_location,
        ));
    }
    if root
        .forms
        .compiler_generations
        .contains_key(checked_generation_id)
    {
        return Err(duplicate_fault(
            context,
            checked_generation_id,
            trace_location,
        ));
    }
    let mut checked = candidate.clone();
    checked.compiler_generation_id = checked_generation_id.clone();
    checked.predecessor_generation_refs =
        BTreeSet::from([candidate.compiler_generation_id.clone()]);
    checked.stage = CompilerStage::ProofChecked;
    let mut forms = root.forms.clone();
    forms
        .compiler_generations
        .insert(checked.compiler_generation_id.clone(), checked.clone());
    forms.validate().map_err(|error| {
        make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            BTreeSet::from([fixture_ref.clone()]),
            "valid proof-checked compiler fixture generation",
            error.to_string(),
            BTreeSet::new(),
            trace_location,
        )
    })?;
    root.forms = forms;
    let record = root.compiler.fixtures.get_mut(fixture_ref).ok_or_else(|| {
        invariant_fault(context, fixture_ref, "fixture disappeared", trace_location)
    })?;
    record.status = CompilerFixtureStatus::Checked;
    record.checked_observer_join_ref = Some(join.join_id.clone());
    record.checked_generation_ref = Some(checked_generation_id.clone());
    Ok(TransitionResult {
        output: RuntimeOutput::CompilerFixtureChecked {
            fixture_ref: fixture_ref.clone(),
            compiler_generation_ref: checked.compiler_generation_id.clone(),
            observer_join_ref: join.join_id.clone(),
        },
        emitted_identities: BTreeSet::from([checked.compiler_generation_id]),
    })
}

pub(crate) fn validate_compiler_runtime(
    root: &DeterministicRuntimeRoot,
) -> Result<(), EvaluationFault> {
    for (fixture_ref, record) in &root.compiler.fixtures {
        let content_refs = manifest_content_refs(&record.manifest);
        let fixture_diffs = root
            .forms
            .diffs
            .values()
            .filter(|diff| {
                diff.before_subject_ref == record.manifest.before_generation_ref
                    && diff.candidate_subject_ref == record.manifest.candidate_generation_ref
            })
            .collect::<Vec<_>>();
        let fixture_diff_kinds = fixture_diffs
            .iter()
            .map(|diff| diff.kind)
            .collect::<BTreeSet<_>>();
        if fixture_ref != &record.manifest.fixture_id
            || !compiler_fixture_record_is_consistent(root, record)
            || record.manifest.max_fixture_records == 0
            || !root
                .forms
                .compiler_generations
                .contains_key(&record.manifest.before_generation_ref)
            || !root
                .forms
                .compiler_generations
                .contains_key(&record.manifest.candidate_generation_ref)
            || !root
                .forms
                .observer_joins
                .contains_key(&record.manifest.observer_join_ref)
            || content_refs.iter().any(|identity| {
                !root.forms.content_objects.contains_key(identity)
                    || !root.repository.content_bytes.contains_key(identity)
            })
            || !root.forms.compiler_impacts.values().any(|impact| {
                impact.compiler_generation_ref == record.manifest.candidate_generation_ref
            })
            || fixture_diffs.len() != record.manifest.required_diff_kinds.len()
            || fixture_diff_kinds != record.manifest.required_diff_kinds
            || !record
                .invalidated_refs
                .is_disjoint(&record.manifest.declared_unrelated_refs)
            || record.manifest.declared_unrelated_refs != record.preserved_unrelated_refs
        {
            return Err(EvaluationFault::new(
                FaultKind::ConstraintViolation,
                "compiler fixture root record is inconsistent",
            ));
        }
        match record.status {
            CompilerFixtureStatus::Registered => {
                if record.forward_prediction_ref.is_some()
                    || record.rear_check_ref.is_some()
                    || record.checked_observer_join_ref.is_some()
                    || record.checked_generation_ref.is_some()
                {
                    return Err(runtime_validation_fault());
                }
            }
            CompilerFixtureStatus::ForwardPredicted => {
                require_runtime_ref(
                    record.forward_prediction_ref.as_ref(),
                    &root.compiler.forward_predictions,
                )?;
                if record.rear_check_ref.is_some()
                    || record.checked_observer_join_ref.is_some()
                    || record.checked_generation_ref.is_some()
                {
                    return Err(runtime_validation_fault());
                }
            }
            CompilerFixtureStatus::RearCompared | CompilerFixtureStatus::Invalidated => {
                require_runtime_ref(
                    record.forward_prediction_ref.as_ref(),
                    &root.compiler.forward_predictions,
                )?;
                require_runtime_ref(record.rear_check_ref.as_ref(), &root.compiler.rear_checks)?;
                if record.checked_observer_join_ref.is_some()
                    || record.checked_generation_ref.is_some()
                {
                    return Err(runtime_validation_fault());
                }
            }
            CompilerFixtureStatus::Checked => {
                require_runtime_ref(
                    record.forward_prediction_ref.as_ref(),
                    &root.compiler.forward_predictions,
                )?;
                require_runtime_ref(record.rear_check_ref.as_ref(), &root.compiler.rear_checks)?;
                let join_ref = record
                    .checked_observer_join_ref
                    .as_ref()
                    .ok_or_else(runtime_validation_fault)?;
                let checked_ref = record
                    .checked_generation_ref
                    .as_ref()
                    .ok_or_else(runtime_validation_fault)?;
                let checked = root
                    .forms
                    .compiler_generations
                    .get(checked_ref)
                    .ok_or_else(runtime_validation_fault)?;
                if !root.forms.observer_joins.contains_key(join_ref)
                    || join_ref != &record.manifest.observer_join_ref
                    || checked.stage != CompilerStage::ProofChecked
                    || checked.predecessor_generation_refs
                        != BTreeSet::from([record.manifest.candidate_generation_ref.clone()])
                {
                    return Err(runtime_validation_fault());
                }
            }
        }
        if let Some(prediction_ref) = &record.forward_prediction_ref {
            let prediction = root
                .compiler
                .forward_predictions
                .get(prediction_ref)
                .ok_or_else(runtime_validation_fault)?;
            if prediction.fixture_ref != *fixture_ref
                || prediction.before_generation_ref != record.manifest.before_generation_ref
                || prediction.candidate_generation_ref != record.manifest.candidate_generation_ref
            {
                return Err(runtime_validation_fault());
            }
        }
        if let Some(rear_ref) = &record.rear_check_ref {
            let rear = root
                .compiler
                .rear_checks
                .get(rear_ref)
                .ok_or_else(runtime_validation_fault)?;
            if rear.fixture_ref != *fixture_ref
                || rear.before_generation_ref != record.manifest.before_generation_ref
                || rear.candidate_generation_ref != record.manifest.candidate_generation_ref
                || (record.status == CompilerFixtureStatus::Invalidated
                    && (rear.matched_forward_prediction || record.invalidated_refs.is_empty()))
                || (matches!(
                    record.status,
                    CompilerFixtureStatus::RearCompared | CompilerFixtureStatus::Checked
                ) && (!rear.matched_forward_prediction || !record.invalidated_refs.is_empty()))
            {
                return Err(runtime_validation_fault());
            }
        }
    }
    for prediction in root.compiler.forward_predictions.values() {
        if digest_forward_prediction(prediction)? != prediction.prediction_digest
            || !root.compiler.fixtures.contains_key(&prediction.fixture_ref)
            || root.compiler.fixtures[&prediction.fixture_ref]
                .forward_prediction_ref
                .as_ref()
                != Some(&prediction.prediction_id)
        {
            return Err(runtime_validation_fault());
        }
    }
    for rear in root.compiler.rear_checks.values() {
        if digest_rear_check(rear)? != rear.rear_digest
            || !root.compiler.fixtures.contains_key(&rear.fixture_ref)
            || root.compiler.fixtures[&rear.fixture_ref]
                .rear_check_ref
                .as_ref()
                != Some(&rear.rear_check_id)
        {
            return Err(runtime_validation_fault());
        }
    }
    Ok(())
}

fn compiler_fixture_record_is_consistent(
    root: &DeterministicRuntimeRoot,
    record: &CompilerFixtureRecord,
) -> bool {
    let manifest = &record.manifest;
    let required = COMPLETE_DIFF_KINDS.into_iter().collect::<BTreeSet<_>>();
    let categories = [
        &manifest.source_object_refs,
        &manifest.semantic_ir_object_refs,
        &manifest.build_ir_object_refs,
        &manifest.target_metadata_object_refs,
        &manifest.correspondence_evidence_refs,
        &manifest.independent_correspondence_evidence_refs,
        &manifest.proof_record_refs,
    ];
    let mut categorized = BTreeSet::new();
    if categories.iter().any(|category| category.is_empty())
        || !categories.iter().all(|category| {
            category
                .iter()
                .all(|identity| categorized.insert(identity.clone()))
        })
        || manifest.required_diff_kinds != required
    {
        return false;
    }
    let Some(before) = root
        .forms
        .compiler_generations
        .get(&manifest.before_generation_ref)
    else {
        return false;
    };
    let Some(candidate) = root
        .forms
        .compiler_generations
        .get(&manifest.candidate_generation_ref)
    else {
        return false;
    };
    let impacts = root
        .forms
        .compiler_impacts
        .values()
        .filter(|impact| impact.compiler_generation_ref == manifest.candidate_generation_ref)
        .collect::<Vec<_>>();
    if impacts.len() != 1 {
        return false;
    }
    let impact = impacts[0];
    let diffs = root
        .forms
        .diffs
        .values()
        .filter(|diff| {
            diff.before_subject_ref == manifest.before_generation_ref
                && diff.candidate_subject_ref == manifest.candidate_generation_ref
        })
        .collect::<Vec<_>>();
    let record_count = categorized
        .len()
        .checked_add(diffs.len())
        .and_then(|count| count.checked_add(4));
    let semantic_digests = manifest
        .semantic_ir_object_refs
        .iter()
        .filter_map(|identity| root.forms.content_objects.get(identity))
        .map(|object| object.digest.clone())
        .collect::<Vec<_>>();
    if manifest.max_fixture_records == 0
        || record_count.is_none_or(|count| count > manifest.max_fixture_records)
        || categorized.iter().any(|identity| {
            let Some(object) = root.forms.content_objects.get(identity) else {
                return true;
            };
            !root.repository.content_bytes.contains_key(identity)
                || !content_role_is_valid(manifest, object)
        })
        || before.compiler_generation_id != manifest.before_generation_ref
        || candidate.compiler_generation_id != manifest.candidate_generation_ref
        || candidate.predecessor_generation_refs
            != BTreeSet::from([before.compiler_generation_id.clone()])
        || !before
            .source_generation_refs
            .is_subset(&manifest.source_object_refs)
        || !candidate
            .source_generation_refs
            .is_subset(&manifest.source_object_refs)
        || candidate.target_artifact_refs != manifest.target_metadata_object_refs
        || candidate.correspondence_evidence_refs != manifest.correspondence_evidence_refs
        || candidate.independent_correspondence_evidence_refs
            != manifest.independent_correspondence_evidence_refs
        || !manifest
            .proof_record_refs
            .contains(&candidate.proof_bundle_ref)
        || !semantic_digests.contains(&before.semantic_ir_root)
        || !semantic_digests.contains(&candidate.semantic_ir_root)
        || !impact
            .changed_source_refs
            .is_subset(&manifest.source_object_refs)
        || !impact
            .changed_semantic_refs
            .is_subset(&manifest.semantic_ir_object_refs)
        || !impact_invalidations(impact).is_disjoint(&manifest.declared_unrelated_refs)
        || diffs.len() != manifest.required_diff_kinds.len()
        || diffs.iter().map(|diff| diff.kind).collect::<BTreeSet<_>>()
            != manifest.required_diff_kinds
        || diffs.iter().any(|diff| {
            !manifest
                .declared_unrelated_refs
                .is_subset(&diff.unrelated_refs)
                || !manifest
                    .independent_correspondence_evidence_refs
                    .is_subset(&diff.independent_evidence_refs)
                || diff.invalidations.values().any(|edge| {
                    edge.source_generation_ref != manifest.candidate_generation_ref
                        || manifest
                            .declared_unrelated_refs
                            .contains(&edge.affected_subject_ref)
                        || (!diff.added_refs.contains(&edge.cause_ref)
                            && !diff.changed_refs.contains(&edge.cause_ref)
                            && !diff.removed_refs.contains(&edge.cause_ref))
                })
        })
    {
        return false;
    }
    matches!(
        candidate.stage,
        CompilerStage::Projected | CompilerStage::ImpactAnalyzed
    )
}

fn validate_manifest_categories(
    context: &RuntimeOperationContext,
    manifest: &CompilerFixtureManifest,
    content: &[ContentInput],
    trace_location: u64,
) -> Result<(), RuntimeFault> {
    let categories = [
        &manifest.source_object_refs,
        &manifest.semantic_ir_object_refs,
        &manifest.build_ir_object_refs,
        &manifest.target_metadata_object_refs,
        &manifest.correspondence_evidence_refs,
        &manifest.independent_correspondence_evidence_refs,
        &manifest.proof_record_refs,
    ];
    let nonempty = categories.iter().all(|category| !category.is_empty());
    let mut union = BTreeSet::new();
    let disjoint = categories.iter().all(|category| {
        category
            .iter()
            .all(|identity| union.insert(identity.clone()))
    });
    let supplied = content
        .iter()
        .map(|input| input.object.object_id.clone())
        .collect::<BTreeSet<_>>();
    if !nonempty || !disjoint || supplied.len() != content.len() || union != supplied {
        return Err(make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            BTreeSet::from([manifest.fixture_id.clone()]),
            "nonempty disjoint content categories exactly equal unique supplied objects",
            "compiler fixture content categories overlap, omit, or duplicate objects",
            BTreeSet::from(["fixed compiler fixture category boundary".to_owned()]),
            trace_location,
        ));
    }
    let typed_content = content
        .iter()
        .all(|input| content_role_is_valid(manifest, &input.object));
    if !typed_content {
        return Err(make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            BTreeSet::from([manifest.fixture_id.clone()]),
            "exact fixed-fixture media types and UTF-8 SOP sources",
            "compiler fixture content role and media type differ",
            BTreeSet::from(["compiler fixture artifact role".to_owned()]),
            trace_location,
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_generation_coordinates(
    context: &RuntimeOperationContext,
    manifest: &CompilerFixtureManifest,
    before: &CompilerGeneration,
    candidate: &CompilerGeneration,
    impact: &CompilerImpact,
    content: &[ContentInput],
    trace_location: u64,
) -> Result<(), RuntimeFault> {
    let semantic_digests = content
        .iter()
        .filter(|input| {
            manifest
                .semantic_ir_object_refs
                .contains(&input.object.object_id)
        })
        .map(|input| input.object.digest.clone())
        .collect::<Vec<_>>();
    let invalidated = impact_invalidations(impact);
    if before.compiler_generation_id != manifest.before_generation_ref
        || candidate.compiler_generation_id != manifest.candidate_generation_ref
        || before.compiler_generation_id == candidate.compiler_generation_id
        || candidate.predecessor_generation_refs
            != BTreeSet::from([before.compiler_generation_id.clone()])
        || impact.compiler_generation_ref != candidate.compiler_generation_id
        || !before
            .source_generation_refs
            .is_subset(&manifest.source_object_refs)
        || !candidate
            .source_generation_refs
            .is_subset(&manifest.source_object_refs)
        || candidate.target_artifact_refs != manifest.target_metadata_object_refs
        || candidate.correspondence_evidence_refs != manifest.correspondence_evidence_refs
        || candidate.independent_correspondence_evidence_refs
            != manifest.independent_correspondence_evidence_refs
        || !manifest
            .proof_record_refs
            .contains(&candidate.proof_bundle_ref)
        || !semantic_digests
            .iter()
            .any(|digest| digest == &before.semantic_ir_root)
        || !semantic_digests
            .iter()
            .any(|digest| digest == &candidate.semantic_ir_root)
        || !impact
            .changed_source_refs
            .is_subset(&manifest.source_object_refs)
        || !impact
            .changed_semantic_refs
            .is_subset(&manifest.semantic_ir_object_refs)
        || !invalidated.is_disjoint(&manifest.declared_unrelated_refs)
        || !matches!(
            candidate.stage,
            CompilerStage::Projected | CompilerStage::ImpactAnalyzed
        )
    {
        return Err(make_fault(
            context,
            RuntimeFaultKind::WrongGeneration,
            BTreeSet::from([
                manifest.fixture_id.clone(),
                before.compiler_generation_id.clone(),
                candidate.compiler_generation_id.clone(),
            ]),
            "exact predecessor, categorized objects, impact, target, evidence, proof, and fixture stage",
            "compiler generation coordinate mismatch",
            BTreeSet::from(["fixed compiler generation boundary".to_owned()]),
            trace_location,
        ));
    }
    Ok(())
}

fn validate_diffs(
    context: &RuntimeOperationContext,
    manifest: &CompilerFixtureManifest,
    diffs: &[DiffRecord],
    impact: &CompilerImpact,
    trace_location: u64,
) -> Result<(), RuntimeFault> {
    let kinds = diffs.iter().map(|diff| diff.kind).collect::<BTreeSet<_>>();
    let ids = diffs
        .iter()
        .map(|diff| diff.diff_id.clone())
        .collect::<BTreeSet<_>>();
    let invalidations = diffs
        .iter()
        .flat_map(|diff| diff.invalidations.values())
        .collect::<Vec<_>>();
    if kinds != manifest.required_diff_kinds
        || ids.len() != diffs.len()
        || diffs.iter().any(|diff| {
            diff.before_subject_ref != manifest.before_generation_ref
                || diff.candidate_subject_ref != manifest.candidate_generation_ref
                || !manifest
                    .declared_unrelated_refs
                    .is_subset(&diff.unrelated_refs)
                || !manifest
                    .independent_correspondence_evidence_refs
                    .is_subset(&diff.independent_evidence_refs)
                || diff.invalidations.values().any(|edge| {
                    !diff.added_refs.contains(&edge.cause_ref)
                        && !diff.changed_refs.contains(&edge.cause_ref)
                        && !diff.removed_refs.contains(&edge.cause_ref)
                })
        })
        || invalidations.iter().any(|edge| {
            edge.source_generation_ref != manifest.candidate_generation_ref
                || manifest
                    .declared_unrelated_refs
                    .contains(&edge.affected_subject_ref)
        })
        || !impact_invalidations(impact).is_disjoint(&manifest.declared_unrelated_refs)
    {
        return Err(make_fault(
            context,
            RuntimeFaultKind::IncompleteDiff,
            ids,
            "one exact before/candidate diff for every declared class with unrelated state preserved",
            "diff class, subject, invalidation, or preservation mismatch",
            BTreeSet::from(["compiler rear comparison inputs".to_owned()]),
            trace_location,
        ));
    }
    Ok(())
}

fn fixture_diffs<'a>(
    forms: &'a TemporalFormSet,
    manifest: &CompilerFixtureManifest,
    context: &RuntimeOperationContext,
    trace_location: u64,
) -> Result<Vec<&'a DiffRecord>, RuntimeFault> {
    let diffs = forms
        .diffs
        .values()
        .filter(|diff| {
            diff.before_subject_ref == manifest.before_generation_ref
                && diff.candidate_subject_ref == manifest.candidate_generation_ref
                && manifest.required_diff_kinds.contains(&diff.kind)
        })
        .collect::<Vec<_>>();
    if diffs.len() != manifest.required_diff_kinds.len() {
        return Err(make_fault(
            context,
            RuntimeFaultKind::IncompleteDiff,
            BTreeSet::from([manifest.fixture_id.clone()]),
            "complete fixed fixture diff set",
            diffs.len().to_string(),
            BTreeSet::new(),
            trace_location,
        ));
    }
    Ok(diffs)
}

fn manifest_content_refs(manifest: &CompilerFixtureManifest) -> BTreeSet<SemanticId> {
    [
        &manifest.source_object_refs,
        &manifest.semantic_ir_object_refs,
        &manifest.build_ir_object_refs,
        &manifest.target_metadata_object_refs,
        &manifest.correspondence_evidence_refs,
        &manifest.independent_correspondence_evidence_refs,
        &manifest.proof_record_refs,
    ]
    .into_iter()
    .flat_map(|values| values.iter().cloned())
    .collect()
}

fn content_role_is_valid(manifest: &CompilerFixtureManifest, object: &ContentObject) -> bool {
    let identity = &object.object_id;
    if manifest.source_object_refs.contains(identity) {
        object.media_type == "application/vnd.cantor.sop"
            && object.encoding.eq_ignore_ascii_case("utf-8")
    } else if manifest.semantic_ir_object_refs.contains(identity) {
        object.media_type == "application/vnd.cantor.semantic-ir+json"
    } else if manifest.build_ir_object_refs.contains(identity) {
        object.media_type == "application/vnd.cantor.build-ir+json"
    } else if manifest.target_metadata_object_refs.contains(identity) {
        object.media_type == "application/vnd.cantor.target-metadata+json"
    } else if manifest.correspondence_evidence_refs.contains(identity)
        || manifest
            .independent_correspondence_evidence_refs
            .contains(identity)
    {
        object.media_type == "application/vnd.cantor.correspondence+json"
    } else {
        manifest.proof_record_refs.contains(identity)
            && object.media_type == "application/vnd.cantor.proof+json"
    }
}

fn changed_for_kind(diffs: &[&DiffRecord], kind: DiffKind) -> BTreeSet<SemanticId> {
    diffs
        .iter()
        .filter(|diff| diff.kind == kind)
        .flat_map(|diff| {
            diff.added_refs
                .iter()
                .chain(&diff.changed_refs)
                .chain(&diff.removed_refs)
                .cloned()
        })
        .collect()
}

fn impact_invalidations(impact: &CompilerImpact) -> BTreeSet<SemanticId> {
    [
        &impact.invalidated_ir_refs,
        &impact.invalidated_index_refs,
        &impact.invalidated_package_refs,
        &impact.invalidated_schedule_refs,
        &impact.invalidated_workflow_refs,
        &impact.invalidated_model_refs,
        &impact.invalidated_tool_schema_refs,
        &impact.invalidated_hardware_refs,
    ]
    .into_iter()
    .flat_map(|values| values.iter().cloned())
    .collect()
}

fn digest_forward_prediction(
    prediction: &CompilerForwardPrediction,
) -> Result<ContentDigest, EvaluationFault> {
    digest_value(&(
        &prediction.prediction_id,
        &prediction.fixture_ref,
        &prediction.before_generation_ref,
        &prediction.candidate_generation_ref,
        &prediction.predicted_changed_source_refs,
        &prediction.predicted_changed_semantic_refs,
        &prediction.predicted_invalidated_refs,
        &prediction.predicted_dependency_refs,
        &prediction.predicted_target_artifact_refs,
        &prediction.predicted_diagnostics,
        &prediction.predicted_proof_requirement_refs,
        &prediction.explicit_unknowns,
    ))
}

fn digest_rear_check(rear: &CompilerRearCheck) -> Result<ContentDigest, EvaluationFault> {
    digest_value(&(
        &rear.rear_check_id,
        &rear.fixture_ref,
        &rear.before_generation_ref,
        &rear.candidate_generation_ref,
        &rear.diff_refs,
        &rear.observed_changed_source_refs,
        &rear.observed_changed_semantic_refs,
        &rear.observed_invalidated_refs,
        &rear.independent_correspondence_evidence_refs,
        &rear.preserved_unrelated_refs,
        &rear.explicit_unknowns,
        rear.matched_forward_prediction,
    ))
}

fn digest_value<T: Serialize>(value: &T) -> Result<ContentDigest, EvaluationFault> {
    serde_json::to_vec(value)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| EvaluationFault::new(FaultKind::MachineForm, error.to_string()))
}

fn empty_digest() -> ContentDigest {
    sha256_bytes(&[])
}

fn require_runtime_ref<T>(
    identity: Option<&SemanticId>,
    values: &BTreeMap<SemanticId, T>,
) -> Result<(), EvaluationFault> {
    if identity.is_some_and(|identity| values.contains_key(identity)) {
        Ok(())
    } else {
        Err(runtime_validation_fault())
    }
}

fn runtime_validation_fault() -> EvaluationFault {
    EvaluationFault::new(
        FaultKind::ConstraintViolation,
        "compiler fixture runtime projection is inconsistent",
    )
}

fn state_fault(
    context: &RuntimeOperationContext,
    fixture_ref: &SemanticId,
    expected: CompilerFixtureStatus,
    observed: CompilerFixtureStatus,
    trace_location: u64,
) -> RuntimeFault {
    make_fault(
        context,
        RuntimeFaultKind::IllegalTransition,
        BTreeSet::from([fixture_ref.clone()]),
        format!("compiler fixture state {expected:?}"),
        format!("{observed:?}"),
        BTreeSet::from(["compiler fixture state machine".to_owned()]),
        trace_location,
    )
}

fn bound_fault(
    context: &RuntimeOperationContext,
    fixture_ref: &SemanticId,
    trace_location: u64,
) -> RuntimeFault {
    make_fault(
        context,
        RuntimeFaultKind::BoundExhausted,
        BTreeSet::from([fixture_ref.clone()]),
        "fixture record count within usize",
        "record count overflow",
        BTreeSet::new(),
        trace_location,
    )
}

fn invariant_fault(
    context: &RuntimeOperationContext,
    fixture_ref: &SemanticId,
    observed: impl Into<String>,
    trace_location: u64,
) -> RuntimeFault {
    make_fault(
        context,
        RuntimeFaultKind::InternalInvariant,
        BTreeSet::from([fixture_ref.clone()]),
        "valid compiler fixture runtime invariant",
        observed,
        BTreeSet::new(),
        trace_location,
    )
}
