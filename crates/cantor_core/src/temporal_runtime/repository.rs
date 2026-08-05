// Runtime faults retain the complete evidence contract across internal passes.
#![allow(clippy::result_large_err)]

use std::collections::BTreeSet;

use crate::{
    EventKind, MaterialEvent, MaterialityDecision, MaterialityDisposition, RepositoryGeneration,
    SemanticId, SemanticSnapshot, sha256_bytes,
};

use super::evaluator::{
    TransitionResult, digest_label, duplicate_fault, machine_fault, make_fault, missing_fault,
    rebuild_repository_index,
};
use super::{
    ContentInput, DeterministicRuntimeRoot, RuntimeFault, RuntimeFaultKind,
    RuntimeOperationContext, RuntimeOutput, digest_material_event, digest_repository_generation,
    digest_semantic_snapshot,
};

pub(crate) fn classify_materiality(
    root: &DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    policy_revision_ref: &SemanticId,
    event_kind: EventKind,
    purpose: &str,
    evidence_refs: &BTreeSet<SemanticId>,
) -> Result<TransitionResult, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    let policy = root
        .forms
        .materiality_policies
        .get(policy_revision_ref)
        .ok_or_else(|| missing_fault(context, policy_revision_ref, trace_location))?;
    if purpose.trim().is_empty() || evidence_refs.is_empty() {
        return Err(make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            BTreeSet::from([policy_revision_ref.clone()]),
            "nonblank purpose and explicit classification evidence",
            "blank purpose or absent evidence",
            BTreeSet::new(),
            trace_location,
        ));
    }
    let (disposition, rule) = if policy.durable_event_kinds.contains(&event_kind) {
        (
            MaterialityDisposition::Capture,
            "event kind is declared durable",
        )
    } else if policy.micro_event_purposes.contains(purpose) {
        (
            MaterialityDisposition::Aggregate,
            "purpose is declared aggregatable",
        )
    } else {
        (
            MaterialityDisposition::Omit,
            "no durable or aggregation rule matched",
        )
    };
    Ok(TransitionResult {
        output: RuntimeOutput::MaterialityClassification {
            decision: MaterialityDecision {
                policy_ref: policy_revision_ref.clone(),
                evidence_refs: evidence_refs.clone(),
                disposition,
                reason: format!(
                    "policy_revision={}; rule={rule}; purpose={purpose}",
                    policy.revision_id
                ),
            },
        },
        emitted_identities: BTreeSet::new(),
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compare_and_append(
    root: &mut DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    branch_ref: &SemanticId,
    expected_generation_ref: &Option<SemanticId>,
    generation: &RepositoryGeneration,
    content: &[ContentInput],
    events: &[MaterialEvent],
    snapshot: &Option<SemanticSnapshot>,
) -> Result<TransitionResult, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    let observed_head = root.repository.branch_heads.get(branch_ref);
    match (observed_head, expected_generation_ref) {
        (None, None) if root.repository.current_generation_ref.is_none() => {}
        (Some(observed), Some(expected)) if observed == expected => {}
        (None, Some(expected)) if root.forms.repository_generations.contains_key(expected) => {}
        _ => {
            return Err(make_fault(
                context,
                RuntimeFaultKind::StalePredecessor,
                BTreeSet::from([branch_ref.clone()]),
                expected_generation_ref
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "uninitialized repository".to_owned()),
                observed_head
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "absent branch head".to_owned()),
                BTreeSet::from(["branch compare-and-append".to_owned()]),
                trace_location,
            ));
        }
    }
    if generation.repository_id != root.repository.repository_id {
        return Err(make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            BTreeSet::from([generation.generation_id.clone()]),
            root.repository.repository_id.to_string(),
            generation.repository_id.to_string(),
            BTreeSet::new(),
            trace_location,
        ));
    }
    if root
        .forms
        .repository_generations
        .contains_key(&generation.generation_id)
    {
        return Err(duplicate_fault(
            context,
            &generation.generation_id,
            trace_location,
        ));
    }
    let required_predecessors = expected_generation_ref
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if !required_predecessors.is_subset(&generation.predecessor_generation_refs)
        || (expected_generation_ref.is_none() && !generation.predecessor_generation_refs.is_empty())
    {
        return Err(make_fault(
            context,
            RuntimeFaultKind::StalePredecessor,
            BTreeSet::from([generation.generation_id.clone()]),
            format!("predecessors include {required_predecessors:?}"),
            format!("{:?}", generation.predecessor_generation_refs),
            BTreeSet::new(),
            trace_location,
        ));
    }
    for predecessor in &generation.predecessor_generation_refs {
        if !root.forms.repository_generations.contains_key(predecessor) {
            return Err(missing_fault(context, predecessor, trace_location));
        }
    }
    let expected_generation_digest = digest_repository_generation(generation)
        .map_err(|error| machine_fault(context, error.to_string(), trace_location))?;
    if generation.root_digest != expected_generation_digest {
        return Err(make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            BTreeSet::from([generation.generation_id.clone()]),
            digest_label(&expected_generation_digest),
            digest_label(&generation.root_digest),
            BTreeSet::from(["repository generation digest".to_owned()]),
            trace_location,
        ));
    }

    let mut candidate_forms = root.forms.clone();
    let mut candidate_bytes = root.repository.content_bytes.clone();
    let mut emitted = BTreeSet::from([generation.generation_id.clone()]);
    for input in content {
        if candidate_forms
            .content_objects
            .contains_key(&input.object.object_id)
        {
            return Err(duplicate_fault(
                context,
                &input.object.object_id,
                trace_location,
            ));
        }
        if input.bytes.is_empty()
            || input.bytes.len() as u64 != input.object.byte_length
            || sha256_bytes(&input.bytes) != input.object.digest
        {
            return Err(make_fault(
                context,
                RuntimeFaultKind::InvalidForm,
                BTreeSet::from([input.object.object_id.clone()]),
                "nonempty bytes matching byte_length and digest",
                format!("{} supplied bytes", input.bytes.len()),
                BTreeSet::from(["content digest verification".to_owned()]),
                trace_location,
            ));
        }
        candidate_bytes.insert(input.object.object_id.clone(), input.bytes.clone());
        candidate_forms
            .content_objects
            .insert(input.object.object_id.clone(), input.object.clone());
        emitted.insert(input.object.object_id.clone());
    }

    let new_event_ids = events
        .iter()
        .map(|event| event.event_id.clone())
        .collect::<BTreeSet<_>>();
    if new_event_ids.len() != events.len() {
        return Err(make_fault(
            context,
            RuntimeFaultKind::DuplicateIdentity,
            new_event_ids,
            "unique event identities",
            "duplicate event identity in operation",
            BTreeSet::new(),
            trace_location,
        ));
    }
    for event in events {
        if candidate_forms
            .material_events
            .contains_key(&event.event_id)
        {
            return Err(duplicate_fault(context, &event.event_id, trace_location));
        }
        let Some(expected_input) = expected_generation_ref else {
            return Err(make_fault(
                context,
                RuntimeFaultKind::MissingReference,
                BTreeSet::from([event.event_id.clone()]),
                "an admitted predecessor generation for each event",
                "initial repository generation",
                BTreeSet::new(),
                trace_location,
            ));
        };
        if &event.repository_generation_input_ref != expected_input {
            return Err(make_fault(
                context,
                RuntimeFaultKind::StalePredecessor,
                BTreeSet::from([event.event_id.clone()]),
                expected_input.to_string(),
                event.repository_generation_input_ref.to_string(),
                BTreeSet::from(["event input generation".to_owned()]),
                trace_location,
            ));
        }
        let digest = digest_material_event(event)
            .map_err(|error| machine_fault(context, error.to_string(), trace_location))?;
        if event.event_digest != digest {
            return Err(make_fault(
                context,
                RuntimeFaultKind::InvalidForm,
                BTreeSet::from([event.event_id.clone()]),
                digest_label(&digest),
                digest_label(&event.event_digest),
                BTreeSet::from(["material event digest".to_owned()]),
                trace_location,
            ));
        }
        candidate_forms
            .material_events
            .insert(event.event_id.clone(), event.clone());
        emitted.insert(event.event_id.clone());
    }

    let mut expected_frontier = BTreeSet::new();
    for predecessor in &generation.predecessor_generation_refs {
        expected_frontier.extend(
            root.forms.repository_generations[predecessor]
                .event_frontier
                .iter()
                .cloned(),
        );
    }
    expected_frontier.extend(new_event_ids);
    if generation.event_frontier != expected_frontier {
        return Err(make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            BTreeSet::from([generation.generation_id.clone()]),
            format!("event frontier {expected_frontier:?}"),
            format!("{:?}", generation.event_frontier),
            BTreeSet::from(["append-only event frontier".to_owned()]),
            trace_location,
        ));
    }

    if let Some(candidate_snapshot) = snapshot {
        if candidate_forms
            .snapshots
            .contains_key(&candidate_snapshot.snapshot_id)
        {
            return Err(duplicate_fault(
                context,
                &candidate_snapshot.snapshot_id,
                trace_location,
            ));
        }
        if candidate_snapshot.repository_id != root.repository.repository_id
            || candidate_snapshot.event_frontier != generation.event_frontier
            || generation.snapshot_root_ref.as_ref() != Some(&candidate_snapshot.snapshot_id)
        {
            return Err(make_fault(
                context,
                RuntimeFaultKind::InvalidForm,
                BTreeSet::from([candidate_snapshot.snapshot_id.clone()]),
                "snapshot repository, frontier, and generation root reference agree",
                "snapshot/generation mismatch",
                BTreeSet::new(),
                trace_location,
            ));
        }
        let digest = digest_semantic_snapshot(candidate_snapshot)
            .map_err(|error| machine_fault(context, error.to_string(), trace_location))?;
        if candidate_snapshot.snapshot_digest != digest {
            return Err(make_fault(
                context,
                RuntimeFaultKind::InvalidForm,
                BTreeSet::from([candidate_snapshot.snapshot_id.clone()]),
                digest_label(&digest),
                digest_label(&candidate_snapshot.snapshot_digest),
                BTreeSet::from(["semantic snapshot digest".to_owned()]),
                trace_location,
            ));
        }
        candidate_forms.snapshots.insert(
            candidate_snapshot.snapshot_id.clone(),
            candidate_snapshot.clone(),
        );
        emitted.insert(candidate_snapshot.snapshot_id.clone());
    } else if generation.snapshot_root_ref.is_some() {
        return Err(make_fault(
            context,
            RuntimeFaultKind::MissingReference,
            BTreeSet::from([generation.generation_id.clone()]),
            "supplied snapshot matching generation snapshot root",
            "no snapshot",
            BTreeSet::new(),
            trace_location,
        ));
    }

    candidate_forms
        .repository_generations
        .insert(generation.generation_id.clone(), generation.clone());
    candidate_forms.validate().map_err(|error| {
        make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            emitted.clone(),
            "valid CTPR form graph",
            error.to_string(),
            BTreeSet::from(["candidate form validation".to_owned()]),
            trace_location,
        )
    })?;

    root.forms = candidate_forms;
    root.repository.content_bytes = candidate_bytes;
    root.repository.current_generation_ref = Some(generation.generation_id.clone());
    root.repository
        .branch_heads
        .insert(branch_ref.clone(), generation.generation_id.clone());
    root.repository.index = rebuild_repository_index(&root.forms, Some(&generation.generation_id));

    Ok(TransitionResult {
        output: RuntimeOutput::RepositoryGeneration {
            generation_ref: generation.generation_id.clone(),
        },
        emitted_identities: emitted,
    })
}
