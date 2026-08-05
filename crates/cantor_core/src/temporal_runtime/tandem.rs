// Runtime faults retain the complete evidence contract across internal passes.
#![allow(clippy::result_large_err)]

use std::collections::BTreeSet;

use crate::{
    BarrierState, BoundedLagPolicy, CapsuleState, ChangeCapsule, DeclaredIntent, JoinDisposition,
    LaneCursor, LaneKind, LaneMessage, LaneState, ObserverJoin, ReflectionReturn, ReleaseBarrier,
    SemanticId, TimeDomain, TimeExpression, TimeValue, WorkPacket, validate_capsule_transition,
    validate_lane_transition,
};

use super::evaluator::{TransitionResult, duplicate_fault, make_fault, missing_fault};
use super::{
    DeterministicRuntimeRoot, RuntimeFault, RuntimeFaultKind, RuntimeOperationContext,
    RuntimeOutput,
};

const BOUNDED_TRANSITION_KINDS: [&str; 7] = [
    "capsule_transition",
    "lane_transition",
    "lane_message",
    "lane_acknowledgment",
    "observer_join",
    "release_barrier",
    "lane_reentry",
];

#[allow(clippy::too_many_arguments)]
pub(crate) fn open_tandem(
    root: &mut DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    declared_intent: &DeclaredIntent,
    capsule: &ChangeCapsule,
    lane_cursors: &[LaneCursor],
    work_packets: &[WorkPacket],
    release_barriers: &[ReleaseBarrier],
    bounded_lag_policies: &[BoundedLagPolicy],
) -> Result<TransitionResult, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    if root
        .forms
        .declared_intents
        .contains_key(&declared_intent.intent_id)
    {
        return Err(duplicate_fault(
            context,
            &declared_intent.intent_id,
            trace_location,
        ));
    }
    if root
        .forms
        .capsules
        .contains_key(&capsule.candidate_generation_id)
    {
        return Err(duplicate_fault(
            context,
            &capsule.candidate_generation_id,
            trace_location,
        ));
    }
    if capsule.state != CapsuleState::Opened
        || !capsule_is_clean_open(capsule)
        || capsule.declared_intent_ref != declared_intent.intent_id
        || root.repository.current_generation_ref.as_ref()
            != Some(&capsule.repository_generation_ref)
        || root.planner.latest_plan_revision_ref.as_ref() != Some(&capsule.plan_revision_ref)
    {
        return Err(make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            BTreeSet::from([capsule.candidate_generation_id.clone()]),
            "opened capsule bound to the supplied intent and current repository generation",
            format!(
                "state={:?}, repository={}",
                capsule.state, capsule.repository_generation_ref
            ),
            BTreeSet::from(["tandem opening identity boundary".to_owned()]),
            trace_location,
        ));
    }
    let cursor_ids = lane_cursors
        .iter()
        .map(|cursor| cursor.cursor_id.clone())
        .collect::<BTreeSet<_>>();
    let lane_kinds = lane_cursors
        .iter()
        .map(|cursor| cursor.kind)
        .collect::<BTreeSet<_>>();
    if cursor_ids.len() != lane_cursors.len()
        || !lane_kinds.contains(&LaneKind::Prospective)
        || !lane_kinds.contains(&LaneKind::Retrospective)
    {
        return Err(make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            cursor_ids,
            "unique cursors including prospective and retrospective lanes",
            format!("lane kinds {lane_kinds:?}"),
            BTreeSet::new(),
            trace_location,
        ));
    }
    for cursor in lane_cursors {
        if root.forms.lane_cursors.contains_key(&cursor.cursor_id) {
            return Err(duplicate_fault(context, &cursor.cursor_id, trace_location));
        }
        if cursor.state != LaneState::Idle
            || cursor.task_ref != capsule.task_ref
            || cursor.input_repository_generation_ref != capsule.repository_generation_ref
            || cursor.plan_revision_ref != capsule.plan_revision_ref
            || cursor.capsule_generation_ref != capsule.candidate_generation_id
        {
            return Err(make_fault(
                context,
                RuntimeFaultKind::InvalidForm,
                BTreeSet::from([cursor.cursor_id.clone()]),
                "idle lane cursor with exact capsule coordinates",
                "lane coordinate mismatch",
                BTreeSet::new(),
                trace_location,
            ));
        }
    }
    for packet in work_packets {
        if packet.task_ref != capsule.task_ref
            || packet.input_repository_generation_ref != capsule.repository_generation_ref
            || packet.capsule_generation_ref != capsule.candidate_generation_id
        {
            return Err(make_fault(
                context,
                RuntimeFaultKind::InvalidForm,
                BTreeSet::from([packet.packet_id.clone()]),
                "work packet with exact capsule coordinates",
                "work packet coordinate mismatch",
                BTreeSet::new(),
                trace_location,
            ));
        }
    }
    let work_packet_kinds = work_packets
        .iter()
        .map(|packet| packet.kind)
        .collect::<BTreeSet<_>>();
    if !work_packet_kinds.contains(&crate::WorkPacketKind::Prospective)
        || (lane_kinds.contains(&LaneKind::Execution)
            && !work_packet_kinds.contains(&crate::WorkPacketKind::Execution))
        || release_barriers.is_empty()
    {
        return Err(make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            BTreeSet::from([capsule.candidate_generation_id.clone()]),
            "prospective work packet, execution packet when applicable, and a release barrier",
            format!(
                "packet kinds {work_packet_kinds:?}, barriers {}",
                release_barriers.len()
            ),
            BTreeSet::from(["tandem work and release topology".to_owned()]),
            trace_location,
        ));
    }
    for barrier in release_barriers {
        if barrier.capsule_generation_ref != capsule.candidate_generation_id
            || barrier.state != BarrierState::Closed
            || barrier.observer_join_ref.is_some()
            || !barrier.released_refs.is_empty()
        {
            return Err(make_fault(
                context,
                RuntimeFaultKind::InvalidForm,
                BTreeSet::from([barrier.barrier_id.clone()]),
                "closed unreleased barrier for the exact capsule",
                "barrier opening mismatch",
                BTreeSet::new(),
                trace_location,
            ));
        }
    }
    let uncovered_transition_kinds = BOUNDED_TRANSITION_KINDS
        .iter()
        .filter(|transition_kind| {
            !bounded_lag_policies.iter().any(|policy| {
                policy.eligible_transition_kinds.contains(**transition_kind)
                    && policy.maximum_transition_count.is_some()
            })
        })
        .copied()
        .collect::<BTreeSet<_>>();
    if !uncovered_transition_kinds.is_empty() {
        return Err(make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            BTreeSet::from([capsule.candidate_generation_id.clone()]),
            "count-bounded lag policy coverage for every tandem transition kind",
            format!("uncovered transition kinds {uncovered_transition_kinds:?}"),
            BTreeSet::from(["bounded tandem progress".to_owned()]),
            trace_location,
        ));
    }

    let mut forms = root.forms.clone();
    forms
        .declared_intents
        .insert(declared_intent.intent_id.clone(), declared_intent.clone());
    forms
        .capsules
        .insert(capsule.candidate_generation_id.clone(), capsule.clone());
    let mut emitted = BTreeSet::from([
        declared_intent.intent_id.clone(),
        capsule.candidate_generation_id.clone(),
    ]);
    for cursor in lane_cursors {
        forms
            .lane_cursors
            .insert(cursor.cursor_id.clone(), cursor.clone());
        emitted.insert(cursor.cursor_id.clone());
    }
    for packet in work_packets {
        if forms
            .work_packets
            .insert(packet.packet_id.clone(), packet.clone())
            .is_some()
        {
            return Err(duplicate_fault(context, &packet.packet_id, trace_location));
        }
        emitted.insert(packet.packet_id.clone());
    }
    for barrier in release_barriers {
        if forms
            .release_barriers
            .insert(barrier.barrier_id.clone(), barrier.clone())
            .is_some()
        {
            return Err(duplicate_fault(
                context,
                &barrier.barrier_id,
                trace_location,
            ));
        }
        emitted.insert(barrier.barrier_id.clone());
    }
    for policy in bounded_lag_policies {
        if forms
            .bounded_lag_policies
            .insert(policy.policy_id.clone(), policy.clone())
            .is_some()
        {
            return Err(duplicate_fault(context, &policy.policy_id, trace_location));
        }
        emitted.insert(policy.policy_id.clone());
    }
    forms.validate().map_err(|error| {
        make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            emitted.clone(),
            "valid exact tandem form graph",
            error.to_string(),
            BTreeSet::from(["tandem opening form validation".to_owned()]),
            trace_location,
        )
    })?;
    root.forms = forms;
    root.tandem.capsule_state_history.insert(
        capsule.candidate_generation_id.clone(),
        vec![CapsuleState::Opened],
    );
    root.tandem
        .transition_counts
        .insert(capsule.candidate_generation_id.clone(), Default::default());
    for cursor in lane_cursors {
        root.tandem
            .lane_state_history
            .insert(cursor.cursor_id.clone(), vec![LaneState::Idle]);
    }
    Ok(TransitionResult {
        output: RuntimeOutput::TandemOpened {
            capsule_generation_ref: capsule.candidate_generation_id.clone(),
            lane_cursor_refs: lane_cursors
                .iter()
                .map(|cursor| cursor.cursor_id.clone())
                .collect(),
        },
        emitted_identities: emitted,
    })
}

pub(crate) fn transition_capsule(
    root: &mut DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    expected_state: CapsuleState,
    successor: &ChangeCapsule,
) -> Result<TransitionResult, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    let current = root
        .forms
        .capsules
        .get(&successor.candidate_generation_id)
        .ok_or_else(|| {
            missing_fault(context, &successor.candidate_generation_id, trace_location)
        })?;
    if current.state != expected_state
        || !same_capsule_identity(current, successor)
        || !preserves_capsule_evidence(current, successor)
    {
        return Err(stale_tandem_fault(
            context,
            &successor.candidate_generation_id,
            format!("exact capsule in state {expected_state:?}"),
            format!("state {:?} or identity mismatch", current.state),
            trace_location,
        ));
    }
    validate_capsule_transition(current.state, successor.state).map_err(|error| {
        make_fault(
            context,
            RuntimeFaultKind::IllegalTransition,
            BTreeSet::from([successor.candidate_generation_id.clone()]),
            "legal capsule transition",
            error.to_string(),
            BTreeSet::from(["CTPR capsule transition table".to_owned()]),
            trace_location,
        )
    })?;
    if !capsule_transition_evidence_is_valid(successor) {
        return Err(make_fault(
            context,
            RuntimeFaultKind::MissingReference,
            BTreeSet::from([successor.candidate_generation_id.clone()]),
            "state-specific capsule evidence",
            format!("incomplete evidence for {:?}", successor.state),
            BTreeSet::from(["capsule lifecycle evidence gate".to_owned()]),
            trace_location,
        ));
    }
    let next_count = check_lag(
        root,
        context,
        &successor.candidate_generation_id,
        "capsule_transition",
    )?;
    let mut forms = root.forms.clone();
    forms
        .capsules
        .insert(successor.candidate_generation_id.clone(), successor.clone());
    validate_candidate_forms(context, &forms, trace_location)?;
    root.forms = forms;
    root.tandem
        .capsule_state_history
        .get_mut(&successor.candidate_generation_id)
        .ok_or_else(|| missing_fault(context, &successor.candidate_generation_id, trace_location))?
        .push(successor.state);
    store_transition_count(
        root,
        &successor.candidate_generation_id,
        "capsule_transition",
        next_count,
    );
    Ok(TransitionResult {
        output: RuntimeOutput::CapsuleTransition {
            capsule_generation_ref: successor.candidate_generation_id.clone(),
            state: successor.state,
        },
        emitted_identities: BTreeSet::new(),
    })
}

pub(crate) fn transition_lane(
    root: &mut DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    expected_state: LaneState,
    successor: &LaneCursor,
    return_ref: &Option<SemanticId>,
    reflection_return: &Option<ReflectionReturn>,
) -> Result<TransitionResult, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    let current = root
        .forms
        .lane_cursors
        .get(&successor.cursor_id)
        .ok_or_else(|| missing_fault(context, &successor.cursor_id, trace_location))?;
    if current.state != expected_state
        || !same_lane_identity(current, successor)
        || !preserves_lane_evidence(current, successor)
    {
        return Err(stale_tandem_fault(
            context,
            &successor.cursor_id,
            format!("exact lane in state {expected_state:?}"),
            format!("state {:?} or identity mismatch", current.state),
            trace_location,
        ));
    }
    validate_lane_transition(current.state, successor.state).map_err(|error| {
        make_fault(
            context,
            RuntimeFaultKind::IllegalTransition,
            BTreeSet::from([successor.cursor_id.clone()]),
            "legal lane transition",
            error.to_string(),
            BTreeSet::from(["CTPR lane transition table".to_owned()]),
            trace_location,
        )
    })?;
    if successor.state == LaneState::TimedOut && successor.timeout_ref.is_none() {
        return Err(make_fault(
            context,
            RuntimeFaultKind::MissingReference,
            BTreeSet::from([successor.cursor_id.clone()]),
            "logical timeout identity on a timed-out lane",
            "timeout reference absent",
            BTreeSet::from(["logical timeout transition".to_owned()]),
            trace_location,
        ));
    }
    if successor.state == LaneState::Returned && return_ref.is_none() {
        return Err(make_fault(
            context,
            RuntimeFaultKind::MissingReference,
            BTreeSet::from([successor.cursor_id.clone()]),
            "explicit return identity for a returned lane",
            "no return identity",
            BTreeSet::new(),
            trace_location,
        ));
    }
    if successor.state != LaneState::Returned
        && (return_ref.is_some() || reflection_return.is_some())
    {
        return Err(make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            BTreeSet::from([successor.cursor_id.clone()]),
            "return data only on Running to Returned",
            format!("successor state {:?}", successor.state),
            BTreeSet::new(),
            trace_location,
        ));
    }
    let mut forms = root.forms.clone();
    forms
        .lane_cursors
        .insert(successor.cursor_id.clone(), successor.clone());
    let mut emitted = BTreeSet::new();
    if let Some(reflection) = reflection_return {
        if successor.kind != LaneKind::Retrospective
            || reflection.retrospective_cursor_ref != successor.cursor_id
            || reflection.capsule_generation_ref != successor.capsule_generation_ref
            || return_ref.as_ref() != Some(&reflection.return_id)
            || forms.reflection_returns.contains_key(&reflection.return_id)
        {
            return Err(make_fault(
                context,
                RuntimeFaultKind::InvalidForm,
                BTreeSet::from([reflection.return_id.clone()]),
                "new exact ReflectionReturn for the retrospective lane",
                "reflection return coordinate mismatch or duplicate",
                BTreeSet::new(),
                trace_location,
            ));
        }
        forms
            .reflection_returns
            .insert(reflection.return_id.clone(), reflection.clone());
        emitted.insert(reflection.return_id.clone());
    }
    if let Some(identity) = return_ref
        && !lane_output_exists(&forms, successor, identity)
    {
        return Err(missing_fault(context, identity, trace_location));
    }
    let next_count = check_lag(
        root,
        context,
        &successor.capsule_generation_ref,
        "lane_transition",
    )?;
    validate_candidate_forms(context, &forms, trace_location)?;
    root.forms = forms;
    if let Some(identity) = return_ref {
        root.tandem
            .lane_return_refs
            .insert(successor.cursor_id.clone(), identity.clone());
    }
    root.tandem
        .lane_state_history
        .get_mut(&successor.cursor_id)
        .ok_or_else(|| missing_fault(context, &successor.cursor_id, trace_location))?
        .push(successor.state);
    store_transition_count(
        root,
        &successor.capsule_generation_ref,
        "lane_transition",
        next_count,
    );
    Ok(TransitionResult {
        output: RuntimeOutput::LaneTransition {
            cursor_ref: successor.cursor_id.clone(),
            state: successor.state,
            return_ref: return_ref.clone(),
        },
        emitted_identities: emitted,
    })
}

pub(crate) fn append_lane_message(
    root: &mut DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    logical_time: &TimeExpression,
    message: &LaneMessage,
) -> Result<TransitionResult, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    if root.forms.lane_messages.contains_key(&message.message_id)
        || root
            .forms
            .time_expressions
            .contains_key(&logical_time.time_expression_id)
    {
        return Err(duplicate_fault(
            context,
            &message.message_id,
            trace_location,
        ));
    }
    if message.created_logical_time_ref != logical_time.time_expression_id
        || logical_time.domain != TimeDomain::Logical
        || logical_time.value
            != (TimeValue::Point {
                value: root.logical_clock.tick.to_string(),
            })
    {
        return Err(make_fault(
            context,
            RuntimeFaultKind::StalePredecessor,
            BTreeSet::from([message.message_id.clone()]),
            format!("logical time point {}", root.logical_clock.tick),
            format!("{:?}", logical_time.value),
            BTreeSet::from(["lane message logical time".to_owned()]),
            trace_location,
        ));
    }
    let sender = root
        .forms
        .lane_cursors
        .get(&message.sender_cursor_ref)
        .ok_or_else(|| missing_fault(context, &message.sender_cursor_ref, trace_location))?;
    let receiver = root
        .forms
        .lane_cursors
        .get(&message.receiver_cursor_ref)
        .ok_or_else(|| missing_fault(context, &message.receiver_cursor_ref, trace_location))?;
    if sender.capsule_generation_ref != receiver.capsule_generation_ref
        || !message_subject_is_exact(root, sender, &message.subject_version_ref)
        || sender
            .last_message_ref
            .as_ref()
            .is_some_and(|prior| !message.causal_predecessor_refs.contains(prior))
        || message
            .causal_predecessor_refs
            .iter()
            .any(|prior| !root.forms.lane_messages.contains_key(prior))
    {
        return Err(make_fault(
            context,
            RuntimeFaultKind::StalePredecessor,
            BTreeSet::from([message.message_id.clone()]),
            "same-capsule cursors, exact subject version, and complete causal predecessors",
            "message coordinate or causal mismatch",
            BTreeSet::from(["lane message causal boundary".to_owned()]),
            trace_location,
        ));
    }
    let next_count = check_lag(
        root,
        context,
        &sender.capsule_generation_ref,
        "lane_message",
    )?;
    let capsule_generation_ref = sender.capsule_generation_ref.clone();
    let mut forms = root.forms.clone();
    forms.time_expressions.insert(
        logical_time.time_expression_id.clone(),
        logical_time.clone(),
    );
    forms
        .lane_messages
        .insert(message.message_id.clone(), message.clone());
    forms
        .lane_cursors
        .get_mut(&message.sender_cursor_ref)
        .expect("sender was checked")
        .last_message_ref = Some(message.message_id.clone());
    validate_candidate_forms(context, &forms, trace_location)?;
    root.forms = forms;
    store_transition_count(root, &capsule_generation_ref, "lane_message", next_count);
    Ok(TransitionResult {
        output: RuntimeOutput::LaneMessageAppended {
            message_ref: message.message_id.clone(),
        },
        emitted_identities: BTreeSet::from([
            logical_time.time_expression_id.clone(),
            message.message_id.clone(),
        ]),
    })
}

pub(crate) fn acknowledge_lane_message(
    root: &mut DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    message_ref: &SemanticId,
    receiver_cursor_ref: &SemanticId,
) -> Result<TransitionResult, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    let message = root
        .forms
        .lane_messages
        .get(message_ref)
        .ok_or_else(|| missing_fault(context, message_ref, trace_location))?;
    if !message.required_acknowledgment || &message.receiver_cursor_ref != receiver_cursor_ref {
        return Err(make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            BTreeSet::from([message_ref.clone(), receiver_cursor_ref.clone()]),
            "required acknowledgment by the exact receiver",
            "acknowledgment not required or receiver mismatch",
            BTreeSet::new(),
            trace_location,
        ));
    }
    if root.tandem.acknowledged_message_refs.contains(message_ref) {
        return Err(duplicate_fault(context, message_ref, trace_location));
    }
    let receiver = &root.forms.lane_cursors[receiver_cursor_ref];
    let next_count = check_lag(
        root,
        context,
        &receiver.capsule_generation_ref,
        "lane_acknowledgment",
    )?;
    root.tandem
        .acknowledged_message_refs
        .insert(message_ref.clone());
    let capsule_generation_ref = receiver.capsule_generation_ref.clone();
    store_transition_count(
        root,
        &capsule_generation_ref,
        "lane_acknowledgment",
        next_count,
    );
    Ok(TransitionResult {
        output: RuntimeOutput::LaneMessageAcknowledged {
            message_ref: message_ref.clone(),
            receiver_cursor_ref: receiver_cursor_ref.clone(),
        },
        emitted_identities: BTreeSet::new(),
    })
}

pub(crate) fn reconcile_observer(
    root: &mut DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    join: &ObserverJoin,
    successor_capsule: &ChangeCapsule,
) -> Result<TransitionResult, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    let current = root
        .forms
        .capsules
        .get(&join.capsule_generation_ref)
        .ok_or_else(|| missing_fault(context, &join.capsule_generation_ref, trace_location))?;
    if root.forms.observer_joins.contains_key(&join.join_id) {
        return Err(duplicate_fault(context, &join.join_id, trace_location));
    }
    let mut exact_subjects = BTreeSet::from([
        current.candidate_generation_id.clone(),
        current.task_ref.clone(),
        current.plan_revision_ref.clone(),
        current.repository_generation_ref.clone(),
    ]);
    for policy in root.forms.materiality_policies.values() {
        exact_subjects.insert(policy.policy_id.clone());
        exact_subjects.insert(policy.revision_id.clone());
    }
    for policy in root.forms.bounded_lag_policies.values() {
        exact_subjects.insert(policy.policy_id.clone());
        exact_subjects.insert(policy.authority_ref.clone());
    }
    let returns_exist = join
        .expected_lane_return_refs
        .iter()
        .all(|identity| lane_return_exists(&root.forms, &join.capsule_generation_ref, identity));
    let expected_runtime_returns = root
        .tandem
        .lane_return_refs
        .iter()
        .filter_map(|(cursor_ref, return_ref)| {
            root.forms
                .lane_cursors
                .get(cursor_ref)
                .filter(|cursor| cursor.capsule_generation_ref == join.capsule_generation_ref)
                .map(|_| return_ref.clone())
        })
        .collect::<BTreeSet<_>>();
    let lanes_settled = root
        .forms
        .lane_cursors
        .values()
        .filter(|cursor| cursor.capsule_generation_ref == join.capsule_generation_ref)
        .all(|cursor| {
            matches!(
                cursor.state,
                LaneState::Returned
                    | LaneState::Released
                    | LaneState::Stale
                    | LaneState::Invalidated
                    | LaneState::TimedOut
                    | LaneState::Cancelled
                    | LaneState::Failed
            )
        });
    let terminal_without_return = root
        .forms
        .lane_cursors
        .values()
        .filter(|cursor| cursor.capsule_generation_ref == join.capsule_generation_ref)
        .any(|cursor| {
            matches!(
                cursor.state,
                LaneState::Stale
                    | LaneState::Invalidated
                    | LaneState::TimedOut
                    | LaneState::Cancelled
                    | LaneState::Failed
            ) && !root.tandem.lane_return_refs.contains_key(&cursor.cursor_id)
        });
    let required_messages_acknowledged =
        root.forms.lane_messages.iter().all(|(identity, message)| {
            !message.required_acknowledgment
                || !message_belongs_to_capsule(root, message, &join.capsule_generation_ref)
                || root.tandem.acknowledged_message_refs.contains(identity)
        });
    if current.state != CapsuleState::ReflectionReturned
        || root.repository.current_generation_ref.as_ref()
            != Some(&current.repository_generation_ref)
        || root.planner.latest_plan_revision_ref.as_ref() != Some(&current.plan_revision_ref)
        || join.received_return_refs != join.expected_lane_return_refs
        || join.expected_lane_return_refs != expected_runtime_returns
        || !returns_exist
        || !lanes_settled
        || (terminal_without_return && join.residuals.is_empty())
        || !required_messages_acknowledged
        || !exact_subjects.is_subset(&join.expected_subject_version_refs)
        || !BTreeSet::from([
            current.plan_revision_ref.clone(),
            current.repository_generation_ref.clone(),
        ])
        .is_subset(&join.stale_check_refs)
        || successor_capsule.state != CapsuleState::Reconciled
        || successor_capsule.observer_join_ref.as_ref() != Some(&join.join_id)
        || !same_capsule_identity(current, successor_capsule)
        || !preserves_capsule_evidence(current, successor_capsule)
    {
        return Err(make_fault(
            context,
            RuntimeFaultKind::IllegalTransition,
            BTreeSet::from([join.join_id.clone(), join.capsule_generation_ref.clone()]),
            "complete exact returns, subject versions, stale checks, and reconciled successor capsule",
            "Observer join coordinate, completeness, or successor mismatch",
            BTreeSet::from(["Observer exact-generation join".to_owned()]),
            trace_location,
        ));
    }
    validate_capsule_transition(current.state, successor_capsule.state).map_err(|error| {
        make_fault(
            context,
            RuntimeFaultKind::IllegalTransition,
            BTreeSet::from([join.capsule_generation_ref.clone()]),
            "ReflectionReturned to Reconciled",
            error.to_string(),
            BTreeSet::new(),
            trace_location,
        )
    })?;
    let next_count = check_lag(root, context, &join.capsule_generation_ref, "observer_join")?;
    let mut forms = root.forms.clone();
    forms
        .observer_joins
        .insert(join.join_id.clone(), join.clone());
    forms.capsules.insert(
        successor_capsule.candidate_generation_id.clone(),
        successor_capsule.clone(),
    );
    validate_candidate_forms(context, &forms, trace_location)?;
    root.forms = forms;
    root.tandem
        .capsule_state_history
        .get_mut(&join.capsule_generation_ref)
        .ok_or_else(|| missing_fault(context, &join.capsule_generation_ref, trace_location))?
        .push(CapsuleState::Reconciled);
    store_transition_count(
        root,
        &join.capsule_generation_ref,
        "observer_join",
        next_count,
    );
    Ok(TransitionResult {
        output: RuntimeOutput::ObserverReconciliation {
            join_ref: join.join_id.clone(),
            capsule_generation_ref: join.capsule_generation_ref.clone(),
        },
        emitted_identities: BTreeSet::from([join.join_id.clone()]),
    })
}

pub(crate) fn evaluate_release_barrier(
    root: &mut DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    expected_state: BarrierState,
    successor: &ReleaseBarrier,
) -> Result<TransitionResult, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    let current = root
        .forms
        .release_barriers
        .get(&successor.barrier_id)
        .ok_or_else(|| missing_fault(context, &successor.barrier_id, trace_location))?;
    let legal = matches!(
        (current.state, successor.state),
        (BarrierState::Closed, BarrierState::Open)
            | (BarrierState::Closed, BarrierState::Invalidated)
            | (BarrierState::Closed, BarrierState::Expired)
            | (BarrierState::Open, BarrierState::Invalidated)
            | (BarrierState::Open, BarrierState::Expired)
    );
    if current.state != expected_state
        || current.capsule_generation_ref != successor.capsule_generation_ref
        || current.required_return_refs != successor.required_return_refs
        || current.dependent_refs != successor.dependent_refs
        || !legal
    {
        return Err(stale_tandem_fault(
            context,
            &successor.barrier_id,
            format!("exact barrier in state {expected_state:?} with a legal successor"),
            format!("{:?} to {:?}", current.state, successor.state),
            trace_location,
        ));
    }
    if successor.state == BarrierState::Open {
        let join_ref = successor
            .observer_join_ref
            .as_ref()
            .ok_or_else(|| missing_fault(context, &successor.barrier_id, trace_location))?;
        let join = root
            .forms
            .observer_joins
            .get(join_ref)
            .ok_or_else(|| missing_fault(context, join_ref, trace_location))?;
        if join.capsule_generation_ref != successor.capsule_generation_ref
            || !matches!(
                join.disposition,
                JoinDisposition::Admit | JoinDisposition::Qualify
            )
            || !join.release_refs.contains(&successor.barrier_id)
            || !successor
                .required_return_refs
                .is_subset(&join.received_return_refs)
            || successor.released_refs != successor.dependent_refs
        {
            return Err(make_fault(
                context,
                RuntimeFaultKind::MissingReference,
                BTreeSet::from([successor.barrier_id.clone(), join_ref.clone()]),
                "exact join, complete required returns, and exact dependent release set",
                "barrier release precondition mismatch",
                BTreeSet::from(["release barrier exact dependency set".to_owned()]),
                trace_location,
            ));
        }
    }
    let next_count = check_lag(
        root,
        context,
        &successor.capsule_generation_ref,
        "release_barrier",
    )?;
    let mut forms = root.forms.clone();
    forms
        .release_barriers
        .insert(successor.barrier_id.clone(), successor.clone());
    validate_candidate_forms(context, &forms, trace_location)?;
    root.forms = forms;
    store_transition_count(
        root,
        &successor.capsule_generation_ref,
        "release_barrier",
        next_count,
    );
    Ok(TransitionResult {
        output: RuntimeOutput::ReleaseBarrierEvaluation {
            barrier_ref: successor.barrier_id.clone(),
            state: successor.state,
            released_refs: successor.released_refs.clone(),
        },
        emitted_identities: BTreeSet::new(),
    })
}

pub(crate) fn reenter_lane(
    root: &mut DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    predecessor_cursor_ref: &SemanticId,
    successor: &LaneCursor,
) -> Result<TransitionResult, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    let predecessor = root
        .forms
        .lane_cursors
        .get(predecessor_cursor_ref)
        .ok_or_else(|| missing_fault(context, predecessor_cursor_ref, trace_location))?;
    let terminal = matches!(
        predecessor.state,
        LaneState::Stale | LaneState::TimedOut | LaneState::Cancelled | LaneState::Failed
    );
    if !terminal
        || root.forms.lane_cursors.contains_key(&successor.cursor_id)
        || successor.state != LaneState::Prepared
        || successor.kind != predecessor.kind
        || successor.task_ref != predecessor.task_ref
        || successor.plan_revision_ref != predecessor.plan_revision_ref
        || successor.capsule_generation_ref != predecessor.capsule_generation_ref
        || successor.input_repository_generation_ref != predecessor.input_repository_generation_ref
        || successor.authority_request_ref != predecessor.authority_request_ref
        || successor.last_message_ref != predecessor.last_message_ref
        || root.repository.current_generation_ref.as_ref()
            != Some(&successor.input_repository_generation_ref)
        || !successor.dependency_refs.contains(predecessor_cursor_ref)
    {
        return Err(make_fault(
            context,
            RuntimeFaultKind::InvalidReentry,
            BTreeSet::from([predecessor_cursor_ref.clone(), successor.cursor_id.clone()]),
            "new prepared cursor bound to an exact terminal predecessor and current generation",
            "reentry coordinate, state, dependency, or generation mismatch",
            BTreeSet::from(["logical crash reentry".to_owned()]),
            trace_location,
        ));
    }
    let next_count = check_lag(
        root,
        context,
        &successor.capsule_generation_ref,
        "lane_reentry",
    )?;
    let mut forms = root.forms.clone();
    forms
        .lane_cursors
        .insert(successor.cursor_id.clone(), successor.clone());
    validate_candidate_forms(context, &forms, trace_location)?;
    root.forms = forms;
    root.tandem
        .lane_state_history
        .insert(successor.cursor_id.clone(), vec![LaneState::Prepared]);
    root.tandem
        .reentry_predecessors
        .insert(successor.cursor_id.clone(), predecessor_cursor_ref.clone());
    store_transition_count(
        root,
        &successor.capsule_generation_ref,
        "lane_reentry",
        next_count,
    );
    Ok(TransitionResult {
        output: RuntimeOutput::LaneReentry {
            predecessor_cursor_ref: predecessor_cursor_ref.clone(),
            successor_cursor_ref: successor.cursor_id.clone(),
        },
        emitted_identities: BTreeSet::from([successor.cursor_id.clone()]),
    })
}

fn same_capsule_identity(current: &ChangeCapsule, successor: &ChangeCapsule) -> bool {
    current.change_id == successor.change_id
        && current.candidate_generation_id == successor.candidate_generation_id
        && current.task_ref == successor.task_ref
        && current.plan_revision_ref == successor.plan_revision_ref
        && current.repository_generation_ref == successor.repository_generation_ref
        && current.before_snapshot_ref == successor.before_snapshot_ref
        && current.declared_intent_ref == successor.declared_intent_ref
}

fn capsule_is_clean_open(capsule: &ChangeCapsule) -> bool {
    capsule.prepared_candidate_ref.is_none()
        && capsule.execution_request_ref.is_none()
        && capsule.execution_outcome_ref.is_none()
        && capsule.candidate_snapshot_ref.is_none()
        && capsule.diff_refs.is_empty()
        && capsule.justification_delta.is_empty()
        && capsule.support_delta.is_empty()
        && capsule.requirement_delta.is_empty()
        && capsule.compiler_impact_ref.is_none()
        && capsule.reflection_return_ref.is_none()
        && capsule.reflection_exception_ref.is_none()
        && capsule.observer_join_ref.is_none()
        && capsule.after_snapshot_ref.is_none()
}

fn capsule_transition_evidence_is_valid(capsule: &ChangeCapsule) -> bool {
    match capsule.state {
        CapsuleState::Prepared => capsule.prepared_candidate_ref.is_some(),
        CapsuleState::ExecutionRequested => {
            capsule.prepared_candidate_ref.is_some() && capsule.execution_request_ref.is_some()
        }
        CapsuleState::EffectObserved => {
            capsule.execution_request_ref.is_some() && capsule.execution_outcome_ref.is_some()
        }
        CapsuleState::ReflectionReturned => {
            capsule.reflection_return_ref.is_some() || capsule.reflection_exception_ref.is_some()
        }
        CapsuleState::Reconciled
        | CapsuleState::Admitted
        | CapsuleState::Rejected
        | CapsuleState::Reverted
        | CapsuleState::Compensated => capsule.observer_join_ref.is_some(),
        CapsuleState::Opened | CapsuleState::ReflectionRequested | CapsuleState::Unresolved => true,
    }
}

fn preserves_capsule_evidence(current: &ChangeCapsule, successor: &ChangeCapsule) -> bool {
    option_is_preserved(
        &current.prepared_candidate_ref,
        &successor.prepared_candidate_ref,
    ) && option_is_preserved(
        &current.execution_request_ref,
        &successor.execution_request_ref,
    ) && option_is_preserved(
        &current.execution_outcome_ref,
        &successor.execution_outcome_ref,
    ) && option_is_preserved(
        &current.candidate_snapshot_ref,
        &successor.candidate_snapshot_ref,
    ) && current
        .diff_refs
        .iter()
        .all(|(kind, identity)| successor.diff_refs.get(kind) == Some(identity))
        && current
            .justification_delta
            .is_subset(&successor.justification_delta)
        && current.support_delta.is_subset(&successor.support_delta)
        && current
            .requirement_delta
            .is_subset(&successor.requirement_delta)
        && option_is_preserved(&current.compiler_impact_ref, &successor.compiler_impact_ref)
        && option_is_preserved(
            &current.reflection_return_ref,
            &successor.reflection_return_ref,
        )
        && option_is_preserved(
            &current.reflection_exception_ref,
            &successor.reflection_exception_ref,
        )
        && option_is_preserved(&current.observer_join_ref, &successor.observer_join_ref)
        && option_is_preserved(&current.after_snapshot_ref, &successor.after_snapshot_ref)
}

fn same_lane_identity(current: &LaneCursor, successor: &LaneCursor) -> bool {
    current.cursor_id == successor.cursor_id
        && current.kind == successor.kind
        && current.task_ref == successor.task_ref
        && current.input_repository_generation_ref == successor.input_repository_generation_ref
        && current.plan_revision_ref == successor.plan_revision_ref
        && current.capsule_generation_ref == successor.capsule_generation_ref
        && current.authority_request_ref == successor.authority_request_ref
}

fn preserves_lane_evidence(current: &LaneCursor, successor: &LaneCursor) -> bool {
    current
        .dependency_refs
        .is_subset(&successor.dependency_refs)
        && option_is_preserved(&current.lease_ref, &successor.lease_ref)
        && option_is_preserved(&current.timeout_ref, &successor.timeout_ref)
        && option_is_preserved(&current.last_message_ref, &successor.last_message_ref)
}

fn message_subject_is_exact(
    root: &DeterministicRuntimeRoot,
    sender: &LaneCursor,
    subject_ref: &SemanticId,
) -> bool {
    subject_ref == &sender.capsule_generation_ref
        || subject_ref == &sender.plan_revision_ref
        || root.repository.current_generation_ref.as_ref() == Some(subject_ref)
}

fn message_belongs_to_capsule(
    root: &DeterministicRuntimeRoot,
    message: &LaneMessage,
    capsule_ref: &SemanticId,
) -> bool {
    [&message.sender_cursor_ref, &message.receiver_cursor_ref]
        .into_iter()
        .filter_map(|cursor_ref| root.forms.lane_cursors.get(cursor_ref))
        .any(|cursor| &cursor.capsule_generation_ref == capsule_ref)
}

fn lane_return_exists(
    forms: &crate::TemporalFormSet,
    capsule_ref: &SemanticId,
    identity: &SemanticId,
) -> bool {
    forms
        .reflection_returns
        .get(identity)
        .is_some_and(|reflection| &reflection.capsule_generation_ref == capsule_ref)
        || forms.capsules.get(capsule_ref).is_some_and(|capsule| {
            capsule.prepared_candidate_ref.as_ref() == Some(identity)
                || capsule.execution_outcome_ref.as_ref() == Some(identity)
                || capsule.candidate_snapshot_ref.as_ref() == Some(identity)
        })
}

pub(crate) fn lane_output_exists(
    forms: &crate::TemporalFormSet,
    cursor: &LaneCursor,
    identity: &SemanticId,
) -> bool {
    let Some(capsule) = forms.capsules.get(&cursor.capsule_generation_ref) else {
        return false;
    };
    match cursor.kind {
        LaneKind::Prospective => capsule.prepared_candidate_ref.as_ref() == Some(identity),
        LaneKind::Execution => capsule.execution_outcome_ref.as_ref() == Some(identity),
        LaneKind::Retrospective => {
            forms
                .reflection_returns
                .get(identity)
                .is_some_and(|reflection| {
                    reflection.capsule_generation_ref == cursor.capsule_generation_ref
                        && reflection.retrospective_cursor_ref == cursor.cursor_id
                })
        }
        LaneKind::ObserverJoin => false,
    }
}

fn option_is_preserved<T: PartialEq>(current: &Option<T>, successor: &Option<T>) -> bool {
    current
        .as_ref()
        .is_none_or(|value| successor.as_ref() == Some(value))
}

fn check_lag(
    root: &DeterministicRuntimeRoot,
    context: &RuntimeOperationContext,
    capsule_ref: &SemanticId,
    transition_kind: &str,
) -> Result<u32, RuntimeFault> {
    let trace_location = root.trace.len() as u64;
    let next = root
        .tandem
        .transition_counts
        .get(capsule_ref)
        .and_then(|counts| counts.get(transition_kind))
        .copied()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| {
            make_fault(
                context,
                RuntimeFaultKind::BoundExhausted,
                BTreeSet::from([capsule_ref.clone()]),
                "bounded tandem transition count",
                "u32 overflow",
                BTreeSet::new(),
                trace_location,
            )
        })?;
    for policy in root.forms.bounded_lag_policies.values() {
        if policy.eligible_transition_kinds.contains(transition_kind)
            && policy
                .maximum_transition_count
                .is_some_and(|maximum| next > maximum)
        {
            return Err(make_fault(
                context,
                RuntimeFaultKind::BoundExhausted,
                BTreeSet::from([capsule_ref.clone(), policy.policy_id.clone()]),
                format!(
                    "at most {:?} tandem transitions",
                    policy.maximum_transition_count
                ),
                next.to_string(),
                BTreeSet::from([format!("lag transition kind={transition_kind}")]),
                trace_location,
            ));
        }
    }
    Ok(next)
}

fn store_transition_count(
    root: &mut DeterministicRuntimeRoot,
    capsule_ref: &SemanticId,
    transition_kind: &str,
    count: u32,
) {
    root.tandem
        .transition_counts
        .entry(capsule_ref.clone())
        .or_default()
        .insert(transition_kind.to_owned(), count);
}

fn validate_candidate_forms(
    context: &RuntimeOperationContext,
    forms: &crate::TemporalFormSet,
    trace_location: u64,
) -> Result<(), RuntimeFault> {
    forms.validate().map_err(|error| {
        make_fault(
            context,
            RuntimeFaultKind::InvalidForm,
            BTreeSet::new(),
            "valid CTPR tandem form graph",
            error.to_string(),
            BTreeSet::from(["tandem candidate validation".to_owned()]),
            trace_location,
        )
    })
}

fn stale_tandem_fault(
    context: &RuntimeOperationContext,
    identity: &SemanticId,
    expected: impl Into<String>,
    observed: impl Into<String>,
    trace_location: u64,
) -> RuntimeFault {
    make_fault(
        context,
        RuntimeFaultKind::StalePredecessor,
        BTreeSet::from([identity.clone()]),
        expected,
        observed,
        BTreeSet::from(["tandem compare-and-transition".to_owned()]),
        trace_location,
    )
}
