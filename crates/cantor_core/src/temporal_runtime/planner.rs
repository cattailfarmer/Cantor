// Runtime faults retain the complete evidence contract across internal passes.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    AuthorityState, CalendarLifecycleState, DependencyKind, PlanRevision, RecurrenceRule,
    SemanticId, TemporalFormSet,
};

use super::evaluator::{
    TransitionResult, duplicate_fault, graph_bound_fault, make_fault, missing_fault,
};
use super::{
    CalendarEvaluationKind, CalendarEventCandidate, DeterministicRuntimeRoot, RuntimeFault,
    RuntimeFaultKind, RuntimeOperationContext, RuntimeOutput, WakeRevalidationContext,
};

pub(crate) fn revise_calendar(
    root: &mut DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    recurrence: &Option<RecurrenceRule>,
    item: &crate::CalendarItem,
    wake_conditions: &[crate::WakeCondition],
) -> Result<TransitionResult, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    if root.forms.calendar_items.contains_key(&item.revision_id) {
        return Err(duplicate_fault(context, &item.revision_id, trace_location));
    }
    let current_item_revision = root
        .calendar
        .latest_item_revision
        .get(&item.calendar_item_id);
    if item.predecessor_revision_ref.as_ref() != current_item_revision {
        return Err(make_fault(
            context,
            RuntimeFaultKind::StalePredecessor,
            BTreeSet::from([item.calendar_item_id.clone()]),
            current_item_revision
                .map(ToString::to_string)
                .unwrap_or_else(|| "no predecessor".to_owned()),
            item.predecessor_revision_ref
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "no predecessor".to_owned()),
            BTreeSet::from(["calendar revision chain".to_owned()]),
            trace_location,
        ));
    }
    if let Some(revision_ref) = current_item_revision {
        let predecessor = &root.forms.calendar_items[revision_ref];
        if predecessor.lifecycle_state != item.lifecycle_state {
            return Err(make_fault(
                context,
                RuntimeFaultKind::IllegalTransition,
                BTreeSet::from([item.calendar_item_id.clone()]),
                "ordinary calendar revision preserves lifecycle; use evaluate_calendar_state for a lifecycle transition",
                format!(
                    "{:?} to {:?}",
                    predecessor.lifecycle_state, item.lifecycle_state
                ),
                BTreeSet::new(),
                trace_location,
            ));
        }
    }

    let mut forms = root.forms.clone();
    let mut emitted = BTreeSet::from([item.revision_id.clone()]);
    if let Some(rule) = recurrence {
        if root
            .calendar
            .recurrence_history
            .contains_key(&rule.revision_id)
        {
            return Err(duplicate_fault(context, &rule.revision_id, trace_location));
        }
        let current_rule_revision = root
            .calendar
            .latest_recurrence_revision
            .get(&rule.recurrence_id);
        if rule.predecessor_revision_ref.as_ref() != current_rule_revision {
            return Err(make_fault(
                context,
                RuntimeFaultKind::StalePredecessor,
                BTreeSet::from([rule.recurrence_id.clone()]),
                current_rule_revision
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "no predecessor".to_owned()),
                rule.predecessor_revision_ref
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "no predecessor".to_owned()),
                BTreeSet::from(["recurrence revision chain".to_owned()]),
                trace_location,
            ));
        }
        if item.recurrence_rule_ref.as_ref() != Some(&rule.recurrence_id) {
            return Err(make_fault(
                context,
                RuntimeFaultKind::InvalidForm,
                BTreeSet::from([item.revision_id.clone(), rule.revision_id.clone()]),
                "calendar item references supplied recurrence identity",
                "recurrence reference mismatch",
                BTreeSet::new(),
                trace_location,
            ));
        }
        forms
            .recurrence_rules
            .insert(rule.recurrence_id.clone(), rule.clone());
        emitted.insert(rule.revision_id.clone());
    }
    for wake in wake_conditions {
        if forms.wake_conditions.contains_key(&wake.wake_id) {
            return Err(duplicate_fault(context, &wake.wake_id, trace_location));
        }
        if wake.calendar_item_ref != item.revision_id {
            return Err(make_fault(
                context,
                RuntimeFaultKind::InvalidForm,
                BTreeSet::from([wake.wake_id.clone()]),
                item.revision_id.to_string(),
                wake.calendar_item_ref.to_string(),
                BTreeSet::from(["wake calendar revision".to_owned()]),
                trace_location,
            ));
        }
        forms
            .wake_conditions
            .insert(wake.wake_id.clone(), wake.clone());
        emitted.insert(wake.wake_id.clone());
    }
    forms
        .calendar_items
        .insert(item.revision_id.clone(), item.clone());
    forms.validate().map_err(|error| {
        make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            emitted.clone(),
            "valid CTPR calendar graph",
            error.to_string(),
            BTreeSet::from(["calendar candidate validation".to_owned()]),
            trace_location,
        )
    })?;

    root.forms = forms;
    root.calendar
        .latest_item_revision
        .insert(item.calendar_item_id.clone(), item.revision_id.clone());
    if let Some(rule) = recurrence {
        root.calendar
            .latest_recurrence_revision
            .insert(rule.recurrence_id.clone(), rule.revision_id.clone());
        root.calendar
            .recurrence_history
            .insert(rule.revision_id.clone(), rule.clone());
    }
    Ok(TransitionResult {
        output: RuntimeOutput::CalendarRevision {
            revision_ref: item.revision_id.clone(),
        },
        emitted_identities: emitted,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_calendar_state(
    root: &mut DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    predecessor_revision_ref: &SemanticId,
    successor_item: &crate::CalendarItem,
    evaluated_at_tick: u64,
    evaluation_kind: CalendarEvaluationKind,
    candidate_event_id: &SemanticId,
) -> Result<TransitionResult, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    let predecessor = root
        .forms
        .calendar_items
        .get(predecessor_revision_ref)
        .ok_or_else(|| missing_fault(context, predecessor_revision_ref, trace_location))?;
    let current = root
        .calendar
        .latest_item_revision
        .get(&predecessor.calendar_item_id);
    if current != Some(predecessor_revision_ref)
        || successor_item.predecessor_revision_ref.as_ref() != Some(predecessor_revision_ref)
        || successor_item.calendar_item_id != predecessor.calendar_item_id
    {
        return Err(make_fault(
            context,
            RuntimeFaultKind::StalePredecessor,
            BTreeSet::from([predecessor.calendar_item_id.clone()]),
            format!("latest exact predecessor {predecessor_revision_ref}"),
            format!(
                "successor predecessor {:?}",
                successor_item.predecessor_revision_ref
            ),
            BTreeSet::from(["calendar lifecycle compare-and-transition".to_owned()]),
            trace_location,
        ));
    }
    if evaluated_at_tick != root.logical_clock.tick {
        return Err(make_fault(
            context,
            RuntimeFaultKind::StalePredecessor,
            BTreeSet::from([root.logical_clock.clock_id.clone()]),
            root.logical_clock.tick.to_string(),
            evaluated_at_tick.to_string(),
            BTreeSet::from(["supplied logical evaluation time".to_owned()]),
            trace_location,
        ));
    }
    if root
        .forms
        .calendar_items
        .contains_key(&successor_item.revision_id)
        || root.forms.material_events.contains_key(candidate_event_id)
        || root
            .trace
            .iter()
            .any(|event| event.emitted_identities.contains(candidate_event_id))
    {
        return Err(duplicate_fault(context, candidate_event_id, trace_location));
    }
    let expected_state = match evaluation_kind {
        CalendarEvaluationKind::Due => CalendarLifecycleState::Triggered,
        CalendarEvaluationKind::Missed => CalendarLifecycleState::Missed,
        CalendarEvaluationKind::Cancelled => CalendarLifecycleState::Cancelled,
        CalendarEvaluationKind::Completed => CalendarLifecycleState::Completed,
        CalendarEvaluationKind::Superseded => CalendarLifecycleState::Superseded,
    };
    if successor_item.lifecycle_state != expected_state
        || !legal_calendar_transition(predecessor.lifecycle_state, expected_state)
    {
        return Err(make_fault(
            context,
            RuntimeFaultKind::IllegalTransition,
            BTreeSet::from([
                predecessor_revision_ref.clone(),
                successor_item.revision_id.clone(),
            ]),
            format!(
                "legal {:?} transition to {expected_state:?}",
                evaluation_kind
            ),
            format!(
                "{:?} to {:?}",
                predecessor.lifecycle_state, successor_item.lifecycle_state
            ),
            BTreeSet::from(["calendar lifecycle transition table".to_owned()]),
            trace_location,
        ));
    }
    let mut forms = root.forms.clone();
    forms
        .calendar_items
        .insert(successor_item.revision_id.clone(), successor_item.clone());
    forms.validate().map_err(|error| {
        make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            BTreeSet::from([successor_item.revision_id.clone()]),
            "valid successor CalendarItem form",
            error.to_string(),
            BTreeSet::new(),
            trace_location,
        )
    })?;
    root.forms = forms;
    root.calendar.latest_item_revision.insert(
        successor_item.calendar_item_id.clone(),
        successor_item.revision_id.clone(),
    );
    let candidate = CalendarEventCandidate {
        candidate_event_id: candidate_event_id.clone(),
        calendar_item_ref: successor_item.revision_id.clone(),
        predecessor_revision_ref: predecessor_revision_ref.clone(),
        evaluated_at_tick,
        evaluation_kind,
        lifecycle_state: expected_state,
    };
    Ok(TransitionResult {
        output: RuntimeOutput::CalendarStateEvaluation {
            candidate,
            successor_revision_ref: successor_item.revision_id.clone(),
        },
        emitted_identities: BTreeSet::from([
            successor_item.revision_id.clone(),
            candidate_event_id.clone(),
        ]),
    })
}

fn legal_calendar_transition(from: CalendarLifecycleState, to: CalendarLifecycleState) -> bool {
    matches!(
        (from, to),
        (
            CalendarLifecycleState::Proposed,
            CalendarLifecycleState::Tentative
                | CalendarLifecycleState::Accepted
                | CalendarLifecycleState::Declined
                | CalendarLifecycleState::Cancelled
        ) | (
            CalendarLifecycleState::Tentative,
            CalendarLifecycleState::Accepted
                | CalendarLifecycleState::Declined
                | CalendarLifecycleState::Cancelled
                | CalendarLifecycleState::Superseded
        ) | (
            CalendarLifecycleState::Accepted,
            CalendarLifecycleState::Committed
                | CalendarLifecycleState::Active
                | CalendarLifecycleState::Cancelled
                | CalendarLifecycleState::Superseded
        ) | (
            CalendarLifecycleState::Committed,
            CalendarLifecycleState::Triggered
                | CalendarLifecycleState::Active
                | CalendarLifecycleState::Completed
                | CalendarLifecycleState::Missed
                | CalendarLifecycleState::Cancelled
                | CalendarLifecycleState::Superseded
        ) | (
            CalendarLifecycleState::Triggered,
            CalendarLifecycleState::Active
                | CalendarLifecycleState::Completed
                | CalendarLifecycleState::Missed
                | CalendarLifecycleState::Cancelled
                | CalendarLifecycleState::Superseded
        ) | (
            CalendarLifecycleState::Active,
            CalendarLifecycleState::Completed
                | CalendarLifecycleState::Missed
                | CalendarLifecycleState::Cancelled
                | CalendarLifecycleState::Superseded
        )
    )
}

pub(crate) fn expand_recurrence(
    root: &mut DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    recurrence_revision_ref: &SemanticId,
    candidate_keys: &BTreeSet<String>,
) -> Result<TransitionResult, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    let rule = root
        .calendar
        .recurrence_history
        .get(recurrence_revision_ref)
        .ok_or_else(|| missing_fault(context, recurrence_revision_ref, trace_location))?;
    if candidate_keys.iter().any(|key| key.is_empty()) {
        return Err(make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            BTreeSet::from([recurrence_revision_ref.clone()]),
            "nonempty occurrence keys",
            "empty occurrence key",
            BTreeSet::new(),
            trace_location,
        ));
    }
    let mut expanded = candidate_keys.clone();
    expanded.extend(rule.inclusion_keys.iter().cloned());
    expanded.retain(|key| !rule.exception_keys.contains(key));
    let rule_limit = rule.occurrence_limit.map(|value| value as usize);
    let effective_limit = rule_limit
        .unwrap_or(root.bounds.max_recurrence_occurrences)
        .min(root.bounds.max_recurrence_occurrences)
        .min(context.limits.max_emitted_records);
    if expanded.len() > effective_limit {
        return Err(make_fault(
            context,
            RuntimeFaultKind::RecurrenceHorizon,
            BTreeSet::from([recurrence_revision_ref.clone()]),
            format!("at most {effective_limit} occurrences"),
            expanded.len().to_string(),
            BTreeSet::from([
                format!("frequency={}", rule.frequency),
                format!("interval={}", rule.interval),
                format!("horizon={}", rule.materialization_horizon_ref),
            ]),
            trace_location,
        ));
    }
    root.calendar
        .materialized_occurrence_keys
        .insert(recurrence_revision_ref.clone(), expanded.clone());
    Ok(TransitionResult {
        output: RuntimeOutput::RecurrenceExpansion {
            recurrence_revision_ref: recurrence_revision_ref.clone(),
            occurrence_keys: expanded,
        },
        emitted_identities: BTreeSet::new(),
    })
}

pub(crate) fn evaluate_wake(
    root: &mut DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    wake_ref: &SemanticId,
    revalidation: &WakeRevalidationContext,
) -> Result<TransitionResult, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    let wake = root
        .forms
        .wake_conditions
        .get(wake_ref)
        .ok_or_else(|| missing_fault(context, wake_ref, trace_location))?;
    let item = root
        .forms
        .calendar_items
        .get(&wake.calendar_item_ref)
        .ok_or_else(|| missing_fault(context, &wake.calendar_item_ref, trace_location))?;
    let plan = root
        .forms
        .plan_revisions
        .get(&revalidation.plan_revision_ref)
        .ok_or_else(|| missing_fault(context, &revalidation.plan_revision_ref, trace_location))?;
    let capsule = root
        .forms
        .capsules
        .get(&revalidation.capsule_generation_ref)
        .ok_or_else(|| {
            missing_fault(
                context,
                &revalidation.capsule_generation_ref,
                trace_location,
            )
        })?;
    let requirements_satisfied = wake
        .revalidation_requirements
        .is_subset(&revalidation.satisfied_requirements);
    let policies_exist = revalidation
        .policy_refs
        .iter()
        .all(|policy| root.forms.materiality_policies.contains_key(policy));
    let lifecycle_is_open = matches!(
        item.lifecycle_state,
        CalendarLifecycleState::Accepted
            | CalendarLifecycleState::Committed
            | CalendarLifecycleState::Active
            | CalendarLifecycleState::Triggered
    );
    let exact = item.task_ref.as_ref() == Some(&revalidation.task_ref)
        && plan.task_ref == revalidation.task_ref
        && root.repository.current_generation_ref.as_ref()
            == Some(&revalidation.repository_generation_ref)
        && capsule.task_ref == revalidation.task_ref
        && capsule.plan_revision_ref == revalidation.plan_revision_ref
        && capsule.repository_generation_ref == revalidation.repository_generation_ref
        && policies_exist
        && !revalidation.policy_refs.is_empty()
        && !revalidation.authority_evidence_refs.is_empty()
        && item.authority_state == AuthorityState::Granted
        && lifecycle_is_open
        && requirements_satisfied;
    if !exact {
        return Err(make_fault(
            context,
            RuntimeFaultKind::WakeMismatch,
            BTreeSet::from([wake_ref.clone(), wake.calendar_item_ref.clone()]),
            "exact task, plan, generation, capsule, policy, authority, lifecycle, and requirement revalidation",
            "one or more wake revalidation coordinates did not match",
            BTreeSet::from([
                format!("requirements_satisfied={requirements_satisfied}"),
                format!("policies_exist={policies_exist}"),
                format!("lifecycle_is_open={lifecycle_is_open}"),
            ]),
            trace_location,
        ));
    }
    root.calendar
        .emitted_wake_candidates
        .insert(wake_ref.clone());
    Ok(TransitionResult {
        output: RuntimeOutput::WakeCandidate {
            wake_ref: wake_ref.clone(),
            calendar_item_ref: wake.calendar_item_ref.clone(),
        },
        emitted_identities: BTreeSet::from([wake_ref.clone()]),
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn propose_plan(
    root: &mut DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    plan: &PlanRevision,
    repository_generation_ref: &SemanticId,
    calendar_revision_refs: &BTreeSet<SemanticId>,
    proof_gate_refs: &BTreeSet<SemanticId>,
    available_resource_refs: &BTreeSet<SemanticId>,
) -> Result<TransitionResult, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    if plan.state != crate::PlanState::Proposed {
        return Err(make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            BTreeSet::from([plan.revision_id.clone()]),
            "plan state Proposed",
            format!("plan state {:?}", plan.state),
            BTreeSet::from(["Planner proposal-only boundary".to_owned()]),
            trace_location,
        ));
    }
    if root.forms.plan_revisions.contains_key(&plan.revision_id) {
        return Err(duplicate_fault(context, &plan.revision_id, trace_location));
    }
    if plan.predecessor_revision_ref != root.planner.latest_plan_revision_ref {
        return Err(make_fault(
            context,
            RuntimeFaultKind::StalePredecessor,
            BTreeSet::from([plan.revision_id.clone()]),
            root.planner
                .latest_plan_revision_ref
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "no predecessor".to_owned()),
            plan.predecessor_revision_ref
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "no predecessor".to_owned()),
            BTreeSet::from(["plan revision chain".to_owned()]),
            trace_location,
        ));
    }
    if root.repository.current_generation_ref.as_ref() != Some(repository_generation_ref) {
        return Err(make_fault(
            context,
            RuntimeFaultKind::StalePredecessor,
            BTreeSet::from([repository_generation_ref.clone()]),
            root.repository
                .current_generation_ref
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "initialized repository generation".to_owned()),
            repository_generation_ref.to_string(),
            BTreeSet::from(["planner repository generation".to_owned()]),
            trace_location,
        ));
    }
    for revision_ref in calendar_revision_refs {
        if !root.forms.calendar_items.contains_key(revision_ref) {
            return Err(missing_fault(context, revision_ref, trace_location));
        }
    }
    if !plan.temporal_refs.is_subset(calendar_revision_refs) {
        return Err(make_fault(
            context,
            RuntimeFaultKind::MissingReference,
            plan.temporal_refs.clone(),
            "all plan temporal references supplied in the Calendar view",
            format!("supplied {calendar_revision_refs:?}"),
            BTreeSet::from(["planner Calendar view".to_owned()]),
            trace_location,
        ));
    }
    if !plan.review_refs.is_subset(proof_gate_refs) {
        return Err(make_fault(
            context,
            RuntimeFaultKind::MissingReference,
            plan.review_refs.clone(),
            "all declared plan review gates supplied",
            format!("supplied {proof_gate_refs:?}"),
            BTreeSet::from(["planner proof gates".to_owned()]),
            trace_location,
        ));
    }
    if !available_resource_refs.is_subset(&root.policies.recognized_resource_refs) {
        return Err(make_fault(
            context,
            RuntimeFaultKind::MissingReference,
            available_resource_refs.clone(),
            "resource identities recognized by the pinned runtime policy",
            format!("recognized {:?}", root.policies.recognized_resource_refs),
            BTreeSet::from(["planner resource view".to_owned()]),
            trace_location,
        ));
    }

    let mut forms = root.forms.clone();
    forms
        .plan_revisions
        .insert(plan.revision_id.clone(), plan.clone());
    forms.validate().map_err(|error| {
        make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            BTreeSet::from([plan.revision_id.clone()]),
            "valid CTPR plan graph",
            error.to_string(),
            BTreeSet::from(["planner candidate validation".to_owned()]),
            trace_location,
        )
    })?;
    let order = objective_order(root, context, &forms, plan)?;
    root.forms = forms;
    root.planner.latest_plan_revision_ref = Some(plan.revision_id.clone());
    root.planner.last_objective_order = order.clone();
    Ok(TransitionResult {
        output: RuntimeOutput::PlanProposal {
            plan_revision_ref: plan.revision_id.clone(),
            objective_order: order,
            resource_refs_observed: available_resource_refs.clone(),
        },
        emitted_identities: BTreeSet::from([plan.revision_id.clone()]),
    })
}

fn objective_order(
    root: &DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    forms: &TemporalFormSet,
    plan: &PlanRevision,
) -> Result<Vec<SemanticId>, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    let mut indegree = plan
        .objective_refs
        .iter()
        .cloned()
        .map(|identity| (identity, 0usize))
        .collect::<BTreeMap<_, _>>();
    let mut successors = plan
        .objective_refs
        .iter()
        .cloned()
        .map(|identity| (identity, BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    let mut visits = 0usize;
    for dependency_ref in &plan.dependency_refs {
        visits += 1;
        if visits > context.limits.max_graph_visits {
            return Err(graph_bound_fault(context, trace_location, visits));
        }
        let dependency = forms
            .dependencies
            .get(dependency_ref)
            .ok_or_else(|| missing_fault(context, dependency_ref, trace_location))?;
        if dependency.kind != DependencyKind::Objective {
            continue;
        }
        if !plan.objective_refs.contains(&dependency.predecessor_ref)
            || !plan
                .objective_refs
                .contains(&dependency.successor_objective_ref)
        {
            return Err(make_fault(
                context,
                RuntimeFaultKind::MissingReference,
                BTreeSet::from([
                    dependency.predecessor_ref.clone(),
                    dependency.successor_objective_ref.clone(),
                ]),
                "objective dependency endpoints in plan",
                dependency.edge_id.to_string(),
                BTreeSet::new(),
                trace_location,
            ));
        }
        if successors
            .get_mut(&dependency.predecessor_ref)
            .expect("plan objective map is complete")
            .insert(dependency.successor_objective_ref.clone())
        {
            *indegree
                .get_mut(&dependency.successor_objective_ref)
                .expect("plan objective map is complete") += 1;
        }
    }

    let mut ready = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(identity, _)| priority_key(root, identity))
        .collect::<BTreeSet<_>>();
    let mut result = Vec::with_capacity(plan.objective_refs.len());
    while let Some(key) = ready.pop_first() {
        let identity = key.1;
        result.push(identity.clone());
        visits += 1;
        if visits > context.limits.max_graph_visits {
            return Err(graph_bound_fault(context, trace_location, visits));
        }
        for successor in &successors[&identity] {
            let degree = indegree
                .get_mut(successor)
                .expect("successor is a plan objective");
            *degree -= 1;
            if *degree == 0 {
                ready.insert(priority_key(root, successor));
            }
        }
    }
    if result.len() != plan.objective_refs.len() {
        let witness = indegree
            .into_iter()
            .filter(|(_, degree)| *degree > 0)
            .map(|(identity, _)| identity)
            .collect::<BTreeSet<_>>();
        return Err(make_fault(
            context,
            RuntimeFaultKind::Cycle,
            witness,
            "acyclic objective dependency graph",
            "cycle witness contains every residual positive-indegree objective",
            BTreeSet::from(["deterministic Kahn traversal".to_owned()]),
            trace_location,
        ));
    }
    Ok(result)
}

fn priority_key(root: &DeterministicRuntimeRoot, identity: &SemanticId) -> (u32, SemanticId) {
    (
        root.policies
            .objective_priority
            .get(identity)
            .copied()
            .unwrap_or(u32::MAX),
        identity.clone(),
    )
}
