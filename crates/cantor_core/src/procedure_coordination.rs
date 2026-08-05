//! Deterministic effectless two-process coordination for CPPE-I06.
//!
//! This module makes multi-pass coordination inspectable as immutable values.
//! It does not create threads, open channels, read a clock, invoke a model, or
//! mutate shared hidden state. A scheduler step operates one process state;
//! messages, continuations, token passes, traces, and replay receipts are the
//! only coordination products.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::procedure_runtime::{
    build_trace, derived_id, digest_serialized, empty_sha256, machine_fault, resolve_value,
    set_binding, validate_invocation_inputs, value_matches_schema,
};
use crate::{
    AdmissionDisposition, AwaitedCondition, CantorProcessIr, CompiledProcedureIdentity,
    ConsumedBudget, ContentDigest, EvaluationFault, InvocationDisposition, InvocationRequest,
    InvocationResult, NegotiatedFrame, NegotiationSession, NegotiationStatus,
    ProcedureCatalogueState, ProcedureFault, ProcedureFaultCategory, ProcedureMessage,
    ProcedureMessageKind, ProcedurePhase, ProcedureValue, ProcessBudgetState, ProcessDefinition,
    ProcessInstanceState, ProcessLifecycle, ProcessOperation, ProcessStep, SemanticId,
    SemanticTraceEvent, SerializedContinuation, TokenRingPass, TraceEventKind,
    compute_continuation_digest,
};

pub const CPPE_COORDINATOR_ID: &str = "cantor-effectless-coordinator/0.1";
pub const CPPE_TOKEN_RING_ID: &str = "cantor-token-ring/0.1";

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationOutcome {
    pub result: InvocationResult,
    pub steps: Vec<ProcessStep>,
    pub continuations: BTreeMap<SemanticId, SerializedContinuation>,
    pub active_continuation_refs: BTreeMap<SemanticId, SemanticId>,
    pub messages: BTreeMap<SemanticId, ProcedureMessage>,
    pub delivered_message_refs: BTreeSet<SemanticId>,
    pub terminal_returns: BTreeMap<SemanticId, ProcedureValue>,
    pub session_successor: Option<NegotiationSession>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRingTransition {
    pub pass: TokenRingPass,
    pub successor: NegotiationSession,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrameRevisionTransition {
    pub predecessor_session_ref: SemanticId,
    pub successor: NegotiationSession,
    pub cleared_pass_refs: BTreeSet<SemanticId>,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationReplayReceipt {
    pub receipt_id: SemanticId,
    pub invocation_ref: SemanticId,
    pub procedure_ref: SemanticId,
    pub coordinator_ref: SemanticId,
    pub catalogue_generation_digest: ContentDigest,
    pub first_outcome_digest: ContentDigest,
    pub replay_outcome_digest: ContentDigest,
    pub matched: bool,
    pub receipt_digest: ContentDigest,
}

#[derive(Default)]
struct RuntimeProducts {
    states: BTreeMap<SemanticId, ProcessInstanceState>,
    steps: Vec<ProcessStep>,
    continuations: BTreeMap<SemanticId, SerializedContinuation>,
    active_continuations: BTreeMap<SemanticId, SemanticId>,
    messages: BTreeMap<SemanticId, ProcedureMessage>,
    delivered: BTreeSet<SemanticId>,
    pending_reactivations: BTreeSet<SemanticId>,
    returns: BTreeMap<SemanticId, ProcedureValue>,
    trace: Vec<SemanticTraceEvent>,
    clock: u64,
    session: Option<NegotiationSession>,
}

#[allow(clippy::too_many_arguments)]
pub fn coordinate_catalogued_procedure(
    catalogue: &ProcedureCatalogueState,
    procedure: &CompiledProcedureIdentity,
    ir: &CantorProcessIr,
    admission: &AdmissionDisposition,
    request: &InvocationRequest,
    session: &NegotiationSession,
) -> Result<CoordinationOutcome, EvaluationFault> {
    if let Err(fault) = validate_invocation_inputs(catalogue, procedure, ir, admission, request)
        .and_then(|_| validate_coordination_inputs(ir, request, admission, session))
    {
        return coordination_fault_outcome(
            procedure,
            request,
            ProcedureFaultCategory::StaleGeneration,
            InvocationDisposition::Faulted,
            fault.message,
            RuntimeProducts {
                clock: request.initial_logical_time,
                ..RuntimeProducts::default()
            },
        );
    }

    let mut runtime = RuntimeProducts {
        clock: request.initial_logical_time,
        session: Some(session.clone()),
        ..RuntimeProducts::default()
    };
    for definition in ir.process_definitions.values() {
        let state = initial_process_state(definition, request)?;
        runtime
            .states
            .insert(definition.process_definition_id.clone(), state);
    }
    push_runtime_trace(
        &mut runtime,
        request,
        procedure,
        None,
        TraceEventKind::InvocationStarted,
        &request.input,
    )?;

    loop {
        if runtime
            .states
            .values()
            .all(|state| state.lifecycle == ProcessLifecycle::TerminalReturn)
        {
            return successful_coordination_outcome(procedure, ir, admission, request, runtime);
        }
        if runtime.steps.len() as u64 >= request.budgets.step_limit
            || runtime.trace.len() as u64 + 3 > request.budgets.trace_event_limit
            || runtime.clock.saturating_sub(request.initial_logical_time)
                >= request.budgets.logical_time_limit
        {
            return coordination_fault_outcome(
                procedure,
                request,
                ProcedureFaultCategory::ResourceExhausted,
                InvocationDisposition::BudgetRefused,
                "coordination step, trace, or logical-time budget exhausted".to_owned(),
                runtime,
            );
        }
        if let Some(definition_ref) = next_scheduler_wakeup(&runtime) {
            if let Err(fault) =
                apply_scheduler_wakeup(&mut runtime, ir, procedure, request, &definition_ref)
            {
                return runtime_error_outcome(procedure, request, fault, runtime);
            }
            continue;
        }
        let ready = runtime
            .states
            .iter()
            .filter(|(_, state)| state.lifecycle == ProcessLifecycle::Ready)
            .map(|(definition_ref, _)| definition_ref.clone())
            .next();
        if let Some(definition_ref) = ready {
            if let Err(fault) = execute_process_step(
                &mut runtime,
                ir,
                procedure,
                request,
                session,
                &definition_ref,
            ) {
                return runtime_error_outcome(procedure, request, fault, runtime);
            }
            if runtime.states.values().any(|state| {
                state.lifecycle == ProcessLifecycle::TerminalFault
                    || state.lifecycle == ProcessLifecycle::Cancelled
            }) {
                return coordination_fault_outcome(
                    procedure,
                    request,
                    ProcedureFaultCategory::InternalInvariant,
                    InvocationDisposition::Faulted,
                    "one coordinated process reached a terminal fault".to_owned(),
                    runtime,
                );
            }
            continue;
        }

        let next_logical_wake = runtime
            .states
            .values()
            .filter_map(|state| match state.awaited_condition {
                AwaitedCondition::LogicalTime { not_before } if not_before > runtime.clock => {
                    Some(not_before)
                }
                _ => None,
            })
            .min();
        if let Some(next_clock) = next_logical_wake {
            if next_clock.saturating_sub(request.initial_logical_time)
                > request.budgets.logical_time_limit
            {
                return coordination_fault_outcome(
                    procedure,
                    request,
                    ProcedureFaultCategory::ResourceExhausted,
                    InvocationDisposition::BudgetRefused,
                    "logical wait exceeds invocation time bound".to_owned(),
                    runtime,
                );
            }
            runtime.clock = next_clock;
            continue;
        }
        return coordination_fault_outcome(
            procedure,
            request,
            ProcedureFaultCategory::UnstableNegotiation,
            InvocationDisposition::Faulted,
            "coordination reached a wait cycle with no eligible deterministic wakeup".to_owned(),
            runtime,
        );
    }
}

pub fn record_token_ring_pass(
    session: &NegotiationSession,
    known_passes: &BTreeMap<SemanticId, TokenRingPass>,
    participant_ref: &SemanticId,
    logical_time: u64,
) -> Result<TokenRingTransition, EvaluationFault> {
    validate_negotiation_session(session)?;
    if !matches!(
        session.status,
        NegotiationStatus::Opened | NegotiationStatus::Deliberating
    ) {
        return Err(machine_fault(
            "token pass requires an open or deliberating session",
        ));
    }
    if &session.token_holder_ref != participant_ref
        || !session.required_participant_refs.contains(participant_ref)
    {
        return Err(machine_fault(
            "only the exact required token holder may pass",
        ));
    }
    let active = active_pass_chain(session, known_passes)?;
    if active
        .iter()
        .any(|pass| &pass.participant_ref == participant_ref)
    {
        return Err(machine_fault(
            "participant already passed on the current frame generation",
        ));
    }
    if active
        .last()
        .is_some_and(|pass| logical_time <= pass.logical_time)
    {
        return Err(machine_fault(
            "token pass logical time must advance monotonically",
        ));
    }

    let predecessor_pass_ref = active.last().map(|pass| pass.pass_id.clone());
    let participant_set_digest = digest_serialized(
        &session.required_participant_refs,
        "token ring participant set",
    )?;
    let sop_anchor_set_digest =
        digest_serialized(&session.pinned_sop_anchor_refs, "token ring SOP anchor set")?;
    let pass_seed = digest_serialized(
        &(
            &session.session_id,
            session.frame_generation,
            participant_ref,
            &participant_set_digest,
            &sop_anchor_set_digest,
            &session.policy_ref,
            &predecessor_pass_ref,
            logical_time,
        ),
        "token ring pass",
    )?;
    let pass = TokenRingPass {
        pass_id: derived_id("cppe:token-pass", &pass_seed)?,
        session_ref: session.session_id.clone(),
        participant_ref: participant_ref.clone(),
        frame_generation: session.frame_generation,
        participant_set_digest,
        sop_anchor_set_digest,
        policy_ref: session.policy_ref.clone(),
        predecessor_pass_ref,
        logical_time,
    };
    let mut successor = session.clone();
    successor.pass_refs.insert(pass.pass_id.clone());
    let passed = active
        .iter()
        .map(|item| item.participant_ref.clone())
        .chain(std::iter::once(participant_ref.clone()))
        .collect::<BTreeSet<_>>();
    if passed == successor.required_participant_refs {
        successor.status = NegotiationStatus::StableCandidate;
    } else {
        successor.status = NegotiationStatus::Deliberating;
        successor.token_holder_ref =
            next_required_participant(&successor.required_participant_refs, participant_ref)?;
    }
    successor.session_generation_id = successor_session_identity(&successor)?;
    Ok(TokenRingTransition { pass, successor })
}

pub fn revise_negotiated_frame(
    session: &NegotiationSession,
    successor_frame: NegotiatedFrame,
) -> Result<FrameRevisionTransition, EvaluationFault> {
    validate_negotiation_session(session)?;
    if successor_frame.generation
        != session
            .frame_generation
            .checked_add(1)
            .ok_or_else(|| machine_fault("negotiated frame generation overflow"))?
        || successor_frame.frame_id == session.frame.frame_id
        || successor_frame.policy_ref != session.policy_ref
        || successor_frame.participant_refs != session.frame.participant_refs
    {
        return Err(machine_fault(
            "frame revision must be one exact successor under the same policy and participants",
        ));
    }
    if successor_frame.propositions == session.frame.propositions
        && successor_frame.conditions == session.frame.conditions
        && successor_frame.constraints == session.frame.constraints
        && successor_frame.evidence_refs == session.frame.evidence_refs
        && successor_frame.objection_refs == session.frame.objection_refs
    {
        return Err(machine_fault(
            "frame revision must identify an actual semantic frame change",
        ));
    }
    let first = session
        .required_participant_refs
        .iter()
        .next()
        .cloned()
        .ok_or_else(|| machine_fault("token ring has no required participant"))?;
    let mut successor = session.clone();
    let cleared_pass_refs = std::mem::take(&mut successor.pass_refs);
    successor.frame_generation = successor_frame.generation;
    successor.frame = successor_frame;
    successor.token_holder_ref = first;
    successor.status = NegotiationStatus::Deliberating;
    successor.session_generation_id = successor_session_identity(&successor)?;
    Ok(FrameRevisionTransition {
        predecessor_session_ref: session.session_generation_id.clone(),
        successor,
        cleared_pass_refs,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_coordination_replay(
    catalogue: &ProcedureCatalogueState,
    procedure: &CompiledProcedureIdentity,
    ir: &CantorProcessIr,
    admission: &AdmissionDisposition,
    request: &InvocationRequest,
    session: &NegotiationSession,
) -> Result<CoordinationReplayReceipt, EvaluationFault> {
    let first =
        coordinate_catalogued_procedure(catalogue, procedure, ir, admission, request, session)?;
    let replay =
        coordinate_catalogued_procedure(catalogue, procedure, ir, admission, request, session)?;
    let first_outcome_digest = digest_serialized(&first, "first coordination outcome")?;
    let replay_outcome_digest = digest_serialized(&replay, "replayed coordination outcome")?;
    let matched = first == replay && first_outcome_digest == replay_outcome_digest;
    let coordinator_ref = SemanticId::new(CPPE_COORDINATOR_ID)?;
    let seed = digest_serialized(
        &(
            &request.invocation_id,
            &procedure.procedure_id,
            &coordinator_ref,
            &catalogue.generation_digest,
            &first_outcome_digest,
            &replay_outcome_digest,
            matched,
        ),
        "coordination replay receipt",
    )?;
    let mut receipt = CoordinationReplayReceipt {
        receipt_id: derived_id("cppe:coordination-replay", &seed)?,
        invocation_ref: request.invocation_id.clone(),
        procedure_ref: procedure.procedure_id.clone(),
        coordinator_ref,
        catalogue_generation_digest: catalogue.generation_digest.clone(),
        first_outcome_digest,
        replay_outcome_digest,
        matched,
        receipt_digest: empty_sha256(),
    };
    receipt.receipt_digest = compute_coordination_replay_receipt_digest(&receipt)?;
    Ok(receipt)
}

pub fn compute_coordination_replay_receipt_digest(
    receipt: &CoordinationReplayReceipt,
) -> Result<ContentDigest, EvaluationFault> {
    let mut body = receipt.clone();
    body.receipt_digest = empty_sha256();
    digest_serialized(&body, "coordination replay receipt")
}

fn validate_coordination_inputs(
    ir: &CantorProcessIr,
    request: &InvocationRequest,
    admission: &AdmissionDisposition,
    session: &NegotiationSession,
) -> Result<(), EvaluationFault> {
    if ir.process_definitions.len() != 2 || ir.bounds.maximum_processes < 2 {
        return Err(machine_fault(
            "CPPE-I06 requires exactly two declared bounded processes",
        ));
    }
    validate_negotiation_session(session)?;
    let process_refs = ir
        .process_definitions
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if request.participant_refs != process_refs
        || session.required_participant_refs != process_refs
        || session.frame.participant_refs != process_refs
        || session.pinned_sop_anchor_refs != ir.sop_anchors.keys().cloned().collect::<BTreeSet<_>>()
        || session.policy_ref != admission.policy_ref
        || session.policy_ref != request.policy_ref
        || session.frame.policy_ref != session.policy_ref
    {
        return Err(machine_fault(
            "coordination request, process, participant, anchor, or policy lineage differs",
        ));
    }
    for (definition_ref, definition) in &ir.process_definitions {
        let participant = session
            .participants
            .get(definition_ref)
            .ok_or_else(|| machine_fault("process lacks an exact session participant"))?;
        if participant.participant_id != *definition_ref
            || participant.role_ref != definition.role_ref
        {
            return Err(machine_fault(
                "process role differs from its declared session participant",
            ));
        }
    }
    Ok(())
}

fn validate_negotiation_session(session: &NegotiationSession) -> Result<(), EvaluationFault> {
    if session.required_participant_refs.is_empty()
        || session.frame_generation != session.frame.generation
        || session.frame.policy_ref != session.policy_ref
        || session.frame.participant_refs != session.required_participant_refs
        || !session.optional_observer_refs.is_empty()
        || !session
            .required_participant_refs
            .contains(&session.token_holder_ref)
        || session
            .participants
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            != session.required_participant_refs
    {
        return Err(machine_fault(
            "negotiation session has inconsistent participants, frame, policy, or token holder",
        ));
    }
    for (participant_ref, participant) in &session.participants {
        if participant_ref != &participant.participant_id {
            return Err(machine_fault(
                "participant map key differs from participant identity",
            ));
        }
    }
    Ok(())
}

fn initial_process_state(
    definition: &ProcessDefinition,
    request: &InvocationRequest,
) -> Result<ProcessInstanceState, EvaluationFault> {
    let seed = digest_serialized(
        &(&request.invocation_id, &definition.process_definition_id),
        "coordinated process instance",
    )?;
    let process_instance_id = derived_id("cppe:process-instance", &seed)?;
    let mut local_state = definition.initial_state.clone();
    set_binding(&mut local_state, "input", request.input.clone())?;
    let mut state = ProcessInstanceState {
        state_id: SemanticId::new("cppe:pending-state")?,
        invocation_ref: request.invocation_id.clone(),
        process_instance_id,
        generation: 1,
        definition_ref: definition.process_definition_id.clone(),
        region_ref: definition.entry_region_ref.clone(),
        instruction_index: 0,
        local_state,
        inbox_frontier: BTreeSet::new(),
        outbox_frontier: BTreeSet::new(),
        awaited_condition: AwaitedCondition::None,
        lifecycle: ProcessLifecycle::Ready,
        logical_time: request.initial_logical_time,
        remaining_budgets: ProcessBudgetState {
            transitions_remaining: request.budgets.step_limit,
            messages_remaining: request.budgets.message_limit,
            memory_units_remaining: request.budgets.memory_unit_limit,
            trace_events_remaining: request.budgets.trace_event_limit,
        },
    };
    refresh_state_identity(&mut state)?;
    Ok(state)
}

fn next_scheduler_wakeup(runtime: &RuntimeProducts) -> Option<SemanticId> {
    runtime.states.iter().find_map(|(definition_ref, state)| {
        let eligible = match &state.awaited_condition {
            AwaitedCondition::None => {
                state.lifecycle == ProcessLifecycle::Passivated
                    && runtime.pending_reactivations.contains(definition_ref)
            }
            AwaitedCondition::Message { tag } => runtime.messages.values().any(|message| {
                !runtime.delivered.contains(&message.message_id)
                    && message.receiver_ref == *definition_ref
                    && message.logical_time <= runtime.clock
                    && message.expires_at_logical_time >= runtime.clock
                    && message_tag(message).is_some_and(|observed| observed == tag)
            }),
            AwaitedCondition::LogicalTime { not_before } => *not_before <= runtime.clock,
            AwaitedCondition::ProcessTerminal {
                process_instance_ref,
            } => runtime.states.values().any(|candidate| {
                candidate.process_instance_id == *process_instance_ref
                    && is_terminal(candidate.lifecycle)
            }),
            AwaitedCondition::Join {
                required_process_refs,
            } => required_process_refs.iter().all(|required| {
                runtime.states.values().any(|candidate| {
                    candidate.process_instance_id == *required && is_terminal(candidate.lifecycle)
                })
            }),
        };
        eligible.then(|| definition_ref.clone())
    })
}

fn apply_scheduler_wakeup(
    runtime: &mut RuntimeProducts,
    ir: &CantorProcessIr,
    procedure: &CompiledProcedureIdentity,
    request: &InvocationRequest,
    definition_ref: &SemanticId,
) -> Result<(), EvaluationFault> {
    ensure_step_capacity(runtime, request)?;
    let before = runtime
        .states
        .get(definition_ref)
        .cloned()
        .ok_or_else(|| machine_fault("scheduler wake target disappeared"))?;
    let awaited = before.awaited_condition.clone();
    let trace_kind = match awaited {
        AwaitedCondition::Join { .. } | AwaitedCondition::ProcessTerminal { .. } => {
            TraceEventKind::Joined
        }
        _ => TraceEventKind::Reactivated,
    };
    runtime.pending_reactivations.remove(definition_ref);
    runtime.active_continuations.remove(definition_ref);
    let state = runtime
        .states
        .get_mut(definition_ref)
        .ok_or_else(|| machine_fault("scheduler wake target disappeared"))?;
    consume_transition(state)?;
    state.lifecycle = ProcessLifecycle::Ready;
    state.awaited_condition = AwaitedCondition::None;
    state.logical_time = runtime.clock;
    state.generation = state
        .generation
        .checked_add(1)
        .ok_or_else(|| machine_fault("process generation overflow"))?;
    refresh_state_identity(state)?;
    let after = state.clone();
    let synthetic = SemanticId::new(match trace_kind {
        TraceEventKind::Joined => "cppe:scheduler-join-wake",
        _ => "cppe:scheduler-reactivate",
    })?;
    let step = make_step(
        request,
        &before,
        &after,
        &synthetic,
        BTreeSet::new(),
        BTreeSet::new(),
        None,
        None,
        1,
        1,
    )?;
    runtime.steps.push(step);
    push_runtime_trace(
        runtime,
        request,
        procedure,
        Some(&after),
        trace_kind,
        &after.local_state,
    )?;
    if runtime.states.len() as u64 > ir.bounds.maximum_processes {
        return Err(machine_fault(
            "scheduler process count exceeds static bound",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn execute_process_step(
    runtime: &mut RuntimeProducts,
    ir: &CantorProcessIr,
    procedure: &CompiledProcedureIdentity,
    request: &InvocationRequest,
    session: &NegotiationSession,
    definition_ref: &SemanticId,
) -> Result<(), EvaluationFault> {
    ensure_step_capacity(runtime, request)?;
    runtime.clock = runtime
        .clock
        .checked_add(1)
        .ok_or_else(|| machine_fault("coordination logical time overflow"))?;
    if runtime.clock.saturating_sub(request.initial_logical_time)
        > request.budgets.logical_time_limit
    {
        return Err(machine_fault("coordination logical-time budget exhausted"));
    }
    let definition = ir
        .process_definitions
        .get(definition_ref)
        .ok_or_else(|| machine_fault("selected process definition disappeared"))?;
    let before = runtime
        .states
        .get(definition_ref)
        .cloned()
        .ok_or_else(|| machine_fault("selected process state disappeared"))?;
    let region = definition
        .control_regions
        .get(&before.region_ref)
        .ok_or_else(|| machine_fault("process state references a missing region"))?;
    let instruction = region
        .instructions
        .get(before.instruction_index as usize)
        .ok_or_else(|| machine_fault("process instruction index is out of range"))?;
    push_runtime_trace(
        runtime,
        request,
        procedure,
        Some(&before),
        TraceEventKind::ProcessSelected,
        &before.local_state,
    )?;

    let mut state = before.clone();
    consume_transition(&mut state)?;
    state.lifecycle = ProcessLifecycle::Operating;
    state.logical_time = runtime.clock;
    let mut input_message_refs = BTreeSet::new();
    let mut emitted_message_refs = BTreeSet::new();
    let mut returned = None;
    let mut selected_successor = None;
    let mut event_kind = TraceEventKind::StateReplaced;

    let operation = (|| -> Result<(), EvaluationFault> {
        match instruction.operation {
            ProcessOperation::Bind | ProcessOperation::Inspect => {
                let value = required_operand(instruction, "value")
                    .or_else(|_| first_operand(instruction))?;
                let value = resolve_value(value, &request.input, &state.local_state)?;
                let binding = instruction
                    .result_binding
                    .as_deref()
                    .ok_or_else(|| machine_fault("bind or inspect requires a result binding"))?;
                set_binding(&mut state.local_state, binding, value)?;
            }
            ProcessOperation::Compare => {
                let left = resolve_value(
                    required_operand(instruction, "left")?,
                    &request.input,
                    &state.local_state,
                )?;
                let right = resolve_value(
                    required_operand(instruction, "right")?,
                    &request.input,
                    &state.local_state,
                )?;
                let binding = instruction
                    .result_binding
                    .as_deref()
                    .ok_or_else(|| machine_fault("compare requires a result binding"))?;
                set_binding(
                    &mut state.local_state,
                    binding,
                    ProcedureValue::Boolean {
                        value: left == right,
                    },
                )?;
            }
            ProcessOperation::Branch => {
                let value = resolve_value(
                    required_operand(instruction, "condition")?,
                    &request.input,
                    &state.local_state,
                )?;
                let ProcedureValue::Boolean { value } = value else {
                    return Err(machine_fault("branch condition is not boolean"));
                };
                if instruction.successor_region_refs.len() != 2 {
                    return Err(machine_fault("branch requires two successors"));
                }
                selected_successor =
                    Some(instruction.successor_region_refs[usize::from(!value)].clone());
            }
            ProcessOperation::Select => {
                let value = resolve_value(
                    required_operand(instruction, "index")?,
                    &request.input,
                    &state.local_state,
                )?;
                let ProcedureValue::Integer { value } = value else {
                    return Err(machine_fault("select index is not an integer"));
                };
                let index = usize::try_from(value)
                    .map_err(|_| machine_fault("select index is negative or too large"))?;
                selected_successor = instruction.successor_region_refs.get(index).cloned();
                if selected_successor.is_none() {
                    return Err(machine_fault("select index exceeds successor set"));
                }
            }
            ProcessOperation::MapBounded => {
                let value = resolve_value(
                    required_operand(instruction, "value")?,
                    &request.input,
                    &state.local_state,
                )?;
                let ProcedureValue::List { members } = &value else {
                    return Err(machine_fault("bounded map operand is not a list"));
                };
                if members.len() as u64 > ir.bounds.maximum_collection_items {
                    return Err(machine_fault("bounded map exceeds collection bound"));
                }
                let binding = instruction
                    .result_binding
                    .as_deref()
                    .ok_or_else(|| machine_fault("bounded map requires a result binding"))?;
                set_binding(&mut state.local_state, binding, value)?;
            }
            ProcessOperation::Emit => {
                let receiver = identity_operand(instruction, "receiver")?;
                let tag = text_operand(instruction, "tag")?;
                let kind = message_kind(&text_operand(instruction, "kind")?)?;
                let payload = resolve_value(
                    required_operand(instruction, "payload")?,
                    &request.input,
                    &state.local_state,
                )?;
                let message = emit_message(
                    runtime, ir, request, session, definition, &state, receiver, tag, kind, payload,
                )?;
                state.outbox_frontier.insert(message.message_id.clone());
                state.remaining_budgets.messages_remaining = state
                    .remaining_budgets
                    .messages_remaining
                    .checked_sub(1)
                    .ok_or_else(|| machine_fault("process message budget exhausted"))?;
                emitted_message_refs.insert(message.message_id.clone());
                runtime.messages.insert(message.message_id.clone(), message);
                event_kind = TraceEventKind::MessageEmitted;
            }
            ProcessOperation::Receive => {
                let tag = text_operand(instruction, "tag")?;
                if !definition.accepted_message_tags.contains(&tag) {
                    return Err(machine_fault("receive tag is not declared by process"));
                }
                if let Some(message) = next_message(runtime, definition_ref, &tag) {
                    let message_id = message.message_id.clone();
                    let payload = message_payload(&message)?.clone();
                    runtime.delivered.insert(message_id.clone());
                    state.inbox_frontier.insert(message_id.clone());
                    input_message_refs.insert(message_id);
                    if let Some(binding) = instruction.result_binding.as_deref() {
                        set_binding(&mut state.local_state, binding, payload)?;
                    }
                    event_kind = TraceEventKind::MessageReceived;
                } else {
                    state.lifecycle = ProcessLifecycle::Waiting;
                    state.awaited_condition = AwaitedCondition::Message { tag };
                    event_kind = TraceEventKind::Waiting;
                }
            }
            ProcessOperation::Yield => {
                advance_program_counter(definition, instruction, &mut state, None)?;
                state.lifecycle = ProcessLifecycle::Passivated;
                state.awaited_condition = AwaitedCondition::None;
                event_kind = TraceEventKind::Yielded;
            }
            ProcessOperation::WaitLogical => {
                let not_before = integer_operand(instruction, "not_before")?;
                let not_before = u64::try_from(not_before)
                    .map_err(|_| machine_fault("logical wait cannot be negative"))?;
                advance_program_counter(definition, instruction, &mut state, None)?;
                if not_before > runtime.clock {
                    state.lifecycle = ProcessLifecycle::Waiting;
                    state.awaited_condition = AwaitedCondition::LogicalTime { not_before };
                    event_kind = TraceEventKind::Waiting;
                } else {
                    state.lifecycle = ProcessLifecycle::Ready;
                }
            }
            ProcessOperation::Reactivate => {
                let target = identity_operand(instruction, "target")?;
                let target_state = runtime
                    .states
                    .get(target)
                    .ok_or_else(|| machine_fault("reactivate target is not a process"))?;
                let active_continuation = runtime
                    .active_continuations
                    .get(target)
                    .and_then(|continuation_ref| runtime.continuations.get(continuation_ref));
                if target_state.lifecycle != ProcessLifecycle::Passivated
                    || !active_continuation
                        .is_some_and(|continuation| continuation.process_state == *target_state)
                {
                    return Err(machine_fault(
                        "reactivate requires one exact passivated continuation",
                    ));
                }
                runtime.pending_reactivations.insert(target.clone());
            }
            ProcessOperation::Join => {
                let targets = identity_list_operand(instruction, "targets")?;
                let required_instances = targets
                    .iter()
                    .map(|target| {
                        runtime
                            .states
                            .get(target)
                            .map(|state| state.process_instance_id.clone())
                            .ok_or_else(|| machine_fault("join target is not a process"))
                    })
                    .collect::<Result<BTreeSet<_>, _>>()?;
                if required_instances
                    .iter()
                    .all(|instance| process_instance_terminal(runtime, instance))
                {
                    event_kind = TraceEventKind::Joined;
                } else {
                    advance_program_counter(definition, instruction, &mut state, None)?;
                    state.lifecycle = ProcessLifecycle::Waiting;
                    state.awaited_condition = AwaitedCondition::Join {
                        required_process_refs: required_instances,
                    };
                    event_kind = TraceEventKind::Waiting;
                }
            }
            ProcessOperation::Return => {
                let value = instruction
                    .operands
                    .first()
                    .map(|operand| {
                        resolve_value(&operand.value, &request.input, &state.local_state)
                    })
                    .transpose()?
                    .unwrap_or_else(|| request.input.clone());
                returned = Some(value.clone());
                runtime.returns.insert(definition_ref.clone(), value);
                state.lifecycle = ProcessLifecycle::TerminalReturn;
                state.awaited_condition = AwaitedCondition::None;
                event_kind = TraceEventKind::Returned;
            }
            ProcessOperation::Fault => {
                state.lifecycle = ProcessLifecycle::TerminalFault;
                state.awaited_condition = AwaitedCondition::None;
                event_kind = TraceEventKind::Faulted;
            }
        }
        Ok(())
    })();
    if let Err(fault) = operation {
        state.lifecycle = ProcessLifecycle::TerminalFault;
        state.awaited_condition = AwaitedCondition::None;
        event_kind = TraceEventKind::Faulted;
        set_binding(
            &mut state.local_state,
            "coordination_fault",
            ProcedureValue::Text {
                value: fault.message,
            },
        )?;
    }

    if state.lifecycle == ProcessLifecycle::Operating {
        advance_program_counter(definition, instruction, &mut state, selected_successor)?;
        state.lifecycle = ProcessLifecycle::Ready;
    }
    state.generation = state
        .generation
        .checked_add(1)
        .ok_or_else(|| machine_fault("process generation overflow"))?;
    let memory_units = serde_json::to_vec(&state.local_state)
        .map_err(|error| machine_fault(format!("local state serialization failed: {error}")))?
        .len() as u64;
    if memory_units > request.budgets.memory_unit_limit
        || memory_units > ir.bounds.maximum_memory_units
    {
        return Err(machine_fault("coordinated process memory bound exhausted"));
    }
    state.remaining_budgets.memory_units_remaining = request
        .budgets
        .memory_unit_limit
        .saturating_sub(memory_units);
    refresh_state_identity(&mut state)?;
    if matches!(
        state.lifecycle,
        ProcessLifecycle::Waiting | ProcessLifecycle::Passivated
    ) {
        let continuation = serialize_continuation(procedure, &state)?;
        runtime
            .active_continuations
            .insert(definition_ref.clone(), continuation.continuation_id.clone());
        runtime
            .continuations
            .insert(continuation.continuation_id.clone(), continuation);
    }
    let fault_ref = (state.lifecycle == ProcessLifecycle::TerminalFault).then(|| {
        let seed = digest_serialized(
            &(
                &request.invocation_id,
                &state.process_instance_id,
                state.generation,
                &instruction.instruction_id,
            ),
            "coordination fault",
        )
        .expect("serializable coordination fault seed");
        derived_id("cppe:procedure-fault", &seed).expect("digest-derived fault identity")
    });
    let step = make_step(
        request,
        &before,
        &state,
        &instruction.instruction_id,
        input_message_refs,
        emitted_message_refs,
        returned,
        fault_ref,
        1,
        2,
    )?;
    runtime.states.insert(definition_ref.clone(), state.clone());
    runtime.steps.push(step);
    push_runtime_trace(
        runtime,
        request,
        procedure,
        Some(&state),
        event_kind,
        &state.local_state,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn emit_message(
    runtime: &RuntimeProducts,
    ir: &CantorProcessIr,
    request: &InvocationRequest,
    session: &NegotiationSession,
    sender: &ProcessDefinition,
    sender_state: &ProcessInstanceState,
    receiver_ref: &SemanticId,
    tag: String,
    kind: ProcedureMessageKind,
    payload: ProcedureValue,
) -> Result<ProcedureMessage, EvaluationFault> {
    let receiver = ir
        .process_definitions
        .get(receiver_ref)
        .ok_or_else(|| machine_fault("message receiver is not a declared process"))?;
    if !sender.emitted_message_tags.contains(&tag)
        || !receiver.accepted_message_tags.contains(&tag)
        || !session
            .participants
            .get(&sender.process_definition_id)
            .is_some_and(|participant| participant.permitted_message_kinds.contains(&kind))
    {
        return Err(machine_fault(
            "message tag or kind is outside declared participant contracts",
        ));
    }
    if runtime.messages.len() as u64 >= request.budgets.message_limit
        || runtime.messages.len() as u64 >= ir.bounds.maximum_messages
        || runtime
            .messages
            .values()
            .filter(|message| {
                message.receiver_ref == *receiver_ref
                    && !runtime.delivered.contains(&message.message_id)
            })
            .count() as u64
            >= ir.bounds.maximum_queue_depth
    {
        return Err(machine_fault("message or queue bound exhausted"));
    }
    let tagged_payload = ProcedureValue::TaggedUnion {
        tag,
        value: Box::new(payload),
    };
    let causal_predecessor_refs = sender_state
        .inbox_frontier
        .union(&sender_state.outbox_frontier)
        .cloned()
        .collect::<BTreeSet<_>>();
    let message_seed = digest_serialized(
        &(
            &session.session_id,
            &sender.process_definition_id,
            receiver_ref,
            session.frame_generation,
            runtime.messages.len(),
            &tagged_payload,
            kind,
            runtime.clock,
            &causal_predecessor_refs,
        ),
        "procedure message",
    )?;
    Ok(ProcedureMessage {
        message_id: derived_id("cppe:message", &message_seed)?,
        session_ref: session.session_id.clone(),
        sender_ref: sender.process_definition_id.clone(),
        receiver_ref: receiver_ref.clone(),
        frame_generation: session.frame_generation,
        sop_anchor_refs: session.pinned_sop_anchor_refs.clone(),
        kind,
        payload: tagged_payload,
        evidence_refs: BTreeSet::from([request.admission_disposition_ref.clone()]),
        logical_time: runtime.clock,
        causal_predecessor_refs,
        expires_at_logical_time: request
            .initial_logical_time
            .saturating_add(request.budgets.logical_time_limit),
    })
}

fn next_message(
    runtime: &RuntimeProducts,
    receiver_ref: &SemanticId,
    tag: &str,
) -> Option<ProcedureMessage> {
    runtime
        .messages
        .values()
        .find(|message| {
            message.receiver_ref == *receiver_ref
                && !runtime.delivered.contains(&message.message_id)
                && message.logical_time <= runtime.clock
                && message.expires_at_logical_time >= runtime.clock
                && message_tag(message).is_some_and(|observed| observed == tag)
        })
        .cloned()
}

fn message_tag(message: &ProcedureMessage) -> Option<&str> {
    match &message.payload {
        ProcedureValue::TaggedUnion { tag, .. } => Some(tag.as_str()),
        _ => None,
    }
}

fn message_payload(message: &ProcedureMessage) -> Result<&ProcedureValue, EvaluationFault> {
    match &message.payload {
        ProcedureValue::TaggedUnion { value, .. } => Ok(value),
        _ => Err(machine_fault("procedure message payload is not tagged")),
    }
}

fn serialize_continuation(
    procedure: &CompiledProcedureIdentity,
    state: &ProcessInstanceState,
) -> Result<SerializedContinuation, EvaluationFault> {
    let seed = digest_serialized(
        &(
            &procedure.procedure_id,
            &state.process_instance_id,
            state.generation,
            state,
        ),
        "serialized continuation identity",
    )?;
    let mut continuation = SerializedContinuation {
        continuation_id: derived_id("cppe:continuation", &seed)?,
        procedure_ref: procedure.procedure_id.clone(),
        process_state: state.clone(),
        inbox_generation: state.inbox_frontier.len() as u64,
        continuation_digest: empty_sha256(),
    };
    continuation.continuation_digest = compute_continuation_digest(&continuation)?;
    Ok(continuation)
}

fn advance_program_counter(
    definition: &ProcessDefinition,
    instruction: &crate::ProcessInstruction,
    state: &mut ProcessInstanceState,
    selected_successor: Option<SemanticId>,
) -> Result<(), EvaluationFault> {
    let region = definition
        .control_regions
        .get(&state.region_ref)
        .ok_or_else(|| machine_fault("process region disappeared"))?;
    if let Some(successor) = selected_successor.or_else(|| {
        (instruction.successor_region_refs.len() == 1)
            .then(|| instruction.successor_region_refs[0].clone())
    }) {
        state.region_ref = successor;
        state.instruction_index = 0;
    } else if (state.instruction_index as usize) + 1 < region.instructions.len() {
        state.instruction_index += 1;
    } else {
        return Err(machine_fault(
            "nonterminal coordination instruction has no deterministic successor",
        ));
    }
    Ok(())
}

fn consume_transition(state: &mut ProcessInstanceState) -> Result<(), EvaluationFault> {
    state.remaining_budgets.transitions_remaining = state
        .remaining_budgets
        .transitions_remaining
        .checked_sub(1)
        .ok_or_else(|| machine_fault("process transition budget exhausted"))?;
    Ok(())
}

fn ensure_step_capacity(
    runtime: &RuntimeProducts,
    request: &InvocationRequest,
) -> Result<(), EvaluationFault> {
    if runtime.steps.len() as u64 >= request.budgets.step_limit
        || runtime.trace.len() as u64 + 3 > request.budgets.trace_event_limit
    {
        return Err(machine_fault("coordination step or trace budget exhausted"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn make_step(
    request: &InvocationRequest,
    before: &ProcessInstanceState,
    after: &ProcessInstanceState,
    instruction_ref: &SemanticId,
    input_message_refs: BTreeSet<SemanticId>,
    emitted_message_refs: BTreeSet<SemanticId>,
    returned_value: Option<ProcedureValue>,
    fault_ref: Option<SemanticId>,
    steps: u64,
    trace_events: u64,
) -> Result<ProcessStep, EvaluationFault> {
    let seed = digest_serialized(
        &(
            &request.invocation_id,
            &before.process_instance_id,
            before.generation,
            instruction_ref,
            &after.state_id,
        ),
        "coordination process step",
    )?;
    let memory_units = serde_json::to_vec(&after.local_state)
        .map_err(|error| machine_fault(format!("state serialization failed: {error}")))?
        .len() as u64;
    Ok(ProcessStep {
        step_id: derived_id("cppe:process-step", &seed)?,
        invocation_ref: request.invocation_id.clone(),
        process_instance_ref: before.process_instance_id.clone(),
        input_generation: before.generation,
        instruction_ref: instruction_ref.clone(),
        input_message_refs,
        emitted_message_refs: emitted_message_refs.clone(),
        successor_state: (!is_terminal(after.lifecycle)).then(|| after.clone()),
        returned_value,
        fault_ref,
        logical_time_before: before.logical_time,
        logical_time_after: after.logical_time,
        consumed_budget: ConsumedBudget {
            logical_time: after.logical_time.saturating_sub(before.logical_time),
            steps,
            memory_units,
            messages: emitted_message_refs.len() as u64,
            trace_events,
        },
    })
}

fn refresh_state_identity(state: &mut ProcessInstanceState) -> Result<(), EvaluationFault> {
    let seed = digest_serialized(
        &(
            &state.invocation_ref,
            &state.process_instance_id,
            state.generation,
            &state.definition_ref,
            &state.region_ref,
            state.instruction_index,
            &state.local_state,
            &state.inbox_frontier,
            &state.outbox_frontier,
            &state.awaited_condition,
            state.lifecycle,
            state.logical_time,
            &state.remaining_budgets,
        ),
        "coordinated process state",
    )?;
    state.state_id = derived_id("cppe:process-state", &seed)?;
    Ok(())
}

fn process_instance_terminal(runtime: &RuntimeProducts, instance_ref: &SemanticId) -> bool {
    runtime
        .states
        .values()
        .any(|state| &state.process_instance_id == instance_ref && is_terminal(state.lifecycle))
}

fn is_terminal(lifecycle: ProcessLifecycle) -> bool {
    matches!(
        lifecycle,
        ProcessLifecycle::TerminalReturn
            | ProcessLifecycle::TerminalFault
            | ProcessLifecycle::Cancelled
    )
}

fn required_operand<'a>(
    instruction: &'a crate::ProcessInstruction,
    name: &str,
) -> Result<&'a ProcedureValue, EvaluationFault> {
    instruction
        .operands
        .iter()
        .find(|operand| operand.name == name)
        .map(|operand| &operand.value)
        .ok_or_else(|| machine_fault(format!("instruction operand {name:?} is missing")))
}

fn first_operand(
    instruction: &crate::ProcessInstruction,
) -> Result<&ProcedureValue, EvaluationFault> {
    instruction
        .operands
        .first()
        .map(|operand| &operand.value)
        .ok_or_else(|| machine_fault("instruction requires one operand"))
}

fn text_operand(
    instruction: &crate::ProcessInstruction,
    name: &str,
) -> Result<String, EvaluationFault> {
    let ProcedureValue::Text { value } = required_operand(instruction, name)? else {
        return Err(machine_fault(format!("operand {name:?} is not text")));
    };
    Ok(value.clone())
}

fn integer_operand(
    instruction: &crate::ProcessInstruction,
    name: &str,
) -> Result<i64, EvaluationFault> {
    let ProcedureValue::Integer { value } = required_operand(instruction, name)? else {
        return Err(machine_fault(format!("operand {name:?} is not an integer")));
    };
    Ok(*value)
}

fn identity_operand<'a>(
    instruction: &'a crate::ProcessInstruction,
    name: &str,
) -> Result<&'a SemanticId, EvaluationFault> {
    let ProcedureValue::IdentityReference { value } = required_operand(instruction, name)? else {
        return Err(machine_fault(format!(
            "operand {name:?} is not an identity"
        )));
    };
    Ok(value)
}

fn identity_list_operand(
    instruction: &crate::ProcessInstruction,
    name: &str,
) -> Result<BTreeSet<SemanticId>, EvaluationFault> {
    let ProcedureValue::List { members } = required_operand(instruction, name)? else {
        return Err(machine_fault(format!("operand {name:?} is not a list")));
    };
    members
        .iter()
        .map(|member| match member {
            ProcedureValue::IdentityReference { value } => Ok(value.clone()),
            _ => Err(machine_fault("join target list contains a nonidentity")),
        })
        .collect()
}

fn message_kind(value: &str) -> Result<ProcedureMessageKind, EvaluationFault> {
    match value {
        "propose" => Ok(ProcedureMessageKind::Propose),
        "question" => Ok(ProcedureMessageKind::Question),
        "support" => Ok(ProcedureMessageKind::Support),
        "object" => Ok(ProcedureMessageKind::Object),
        "counter" => Ok(ProcedureMessageKind::Counter),
        "qualify" => Ok(ProcedureMessageKind::Qualify),
        "withdraw" => Ok(ProcedureMessageKind::Withdraw),
        "admit_candidate" => Ok(ProcedureMessageKind::AdmitCandidate),
        "refuse" => Ok(ProcedureMessageKind::Refuse),
        "yield" => Ok(ProcedureMessageKind::Yield),
        "pass" => Ok(ProcedureMessageKind::Pass),
        "fault" => Ok(ProcedureMessageKind::Fault),
        _ => Err(machine_fault("message kind is not in the closed CPPE set")),
    }
}

fn push_runtime_trace(
    runtime: &mut RuntimeProducts,
    request: &InvocationRequest,
    procedure: &CompiledProcedureIdentity,
    state: Option<&ProcessInstanceState>,
    kind: TraceEventKind,
    payload: &ProcedureValue,
) -> Result<(), EvaluationFault> {
    if runtime.trace.len() as u64 >= request.budgets.trace_event_limit {
        return Err(machine_fault("coordination trace budget exhausted"));
    }
    let index = runtime.trace.len() as u64;
    let payload_digest = digest_serialized(payload, "coordination trace payload")?;
    let seed = digest_serialized(
        &(&request.invocation_id, index, kind, &payload_digest),
        "coordination trace event",
    )?;
    let causal_predecessor_refs = runtime
        .trace
        .last()
        .map(|event| BTreeSet::from([event.event_id.clone()]))
        .unwrap_or_default();
    runtime.trace.push(SemanticTraceEvent {
        event_id: derived_id("cppe:trace-event", &seed)?,
        logical_index: index,
        kind,
        procedure_ref: procedure.procedure_id.clone(),
        process_ref: state.map(|value| value.process_instance_id.clone()),
        subject_generation: state.map_or(0, |value| value.generation),
        normalized_payload_digest: payload_digest,
        causal_predecessor_refs,
    });
    Ok(())
}

fn successful_coordination_outcome(
    procedure: &CompiledProcedureIdentity,
    ir: &CantorProcessIr,
    admission: &AdmissionDisposition,
    request: &InvocationRequest,
    mut runtime: RuntimeProducts,
) -> Result<CoordinationOutcome, EvaluationFault> {
    let mut values = runtime.returns.values();
    let output = values
        .next()
        .cloned()
        .ok_or_else(|| machine_fault("terminal coordination has no returned value"))?;
    if values.any(|candidate| candidate != &output) {
        return coordination_fault_outcome(
            procedure,
            request,
            ProcedureFaultCategory::UnstableNegotiation,
            InvocationDisposition::Faulted,
            "coordinated processes returned different values".to_owned(),
            runtime,
        );
    }
    let output_schema = ir
        .schema_set
        .schemas
        .get(&request.expected_output_schema_ref)
        .ok_or_else(|| machine_fault("coordination output schema disappeared"))?;
    if !value_matches_schema(&output, output_schema, &ir.schema_set.schemas, 64)? {
        return coordination_fault_outcome(
            procedure,
            request,
            ProcedureFaultCategory::SchemaMismatch,
            InvocationDisposition::Faulted,
            "coordinated return does not satisfy output schema".to_owned(),
            runtime,
        );
    }
    push_runtime_trace(
        &mut runtime,
        request,
        procedure,
        None,
        TraceEventKind::InvocationCompleted,
        &output,
    )?;
    let consumed = consumed_budget(&runtime, request);
    let trace = build_trace(request, procedure, runtime.trace.clone())?;
    let session_successor = materialize_session_successor(&runtime)?;
    Ok(CoordinationOutcome {
        result: InvocationResult {
            invocation_ref: request.invocation_id.clone(),
            procedure_ref: procedure.procedure_id.clone(),
            disposition: InvocationDisposition::Returned,
            output: Some(output),
            output_sensitivity: request.input_sensitivity,
            fault: None,
            final_process_states: runtime
                .states
                .values()
                .map(|state| (state.state_id.clone(), state.clone()))
                .collect(),
            semantic_trace: trace,
            consumed_budget: consumed,
            residuals: BTreeSet::from([
                "coordination is an effectless two-process value walk".to_owned(),
                "model and provider calls remain outside this runtime".to_owned(),
            ]),
            proof_refs: BTreeSet::from([admission.disposition_id.clone()]),
            retention_policy_ref: request.retention_policy_ref.clone(),
        },
        steps: runtime.steps,
        continuations: runtime.continuations,
        active_continuation_refs: runtime.active_continuations,
        messages: runtime.messages,
        delivered_message_refs: runtime.delivered,
        terminal_returns: runtime.returns,
        session_successor,
    })
}

fn coordination_fault_outcome(
    procedure: &CompiledProcedureIdentity,
    request: &InvocationRequest,
    category: ProcedureFaultCategory,
    disposition: InvocationDisposition,
    message: String,
    mut runtime: RuntimeProducts,
) -> Result<CoordinationOutcome, EvaluationFault> {
    let consumed = consumed_budget(&runtime, request);
    let seed = digest_serialized(
        &(
            &request.invocation_id,
            &procedure.procedure_id,
            category,
            &message,
            &consumed,
        ),
        "coordination invocation fault",
    )?;
    let fault_id = runtime
        .steps
        .last()
        .and_then(|step| step.fault_ref.clone())
        .unwrap_or(derived_id("cppe:procedure-fault", &seed)?);
    if (runtime.trace.len() as u64) < request.budgets.trace_event_limit {
        let payload = ProcedureValue::Text {
            value: message.clone(),
        };
        push_runtime_trace(
            &mut runtime,
            request,
            procedure,
            None,
            if disposition == InvocationDisposition::BudgetRefused {
                TraceEventKind::BudgetRefused
            } else {
                TraceEventKind::Faulted
            },
            &payload,
        )?;
    }
    let consumed = consumed_budget(&runtime, request);
    let fault = ProcedureFault {
        fault_id,
        phase: ProcedurePhase::Invocation,
        category,
        subject_refs: BTreeSet::from([
            request.invocation_id.clone(),
            procedure.procedure_id.clone(),
        ]),
        expected_versions: BTreeMap::from([(
            "coordinator".to_owned(),
            CPPE_COORDINATOR_ID.to_owned(),
        )]),
        observed_versions: BTreeMap::new(),
        evidence_refs: BTreeSet::from([request.admission_disposition_ref.clone()]),
        consumed_budget: consumed.clone(),
        trace_location: runtime.trace.last().map(|event| event.logical_index),
        safe_residuals: BTreeSet::from([
            message,
            "all input, catalogue, message, and continuation values remain inspectable".to_owned(),
        ]),
    };
    let trace = build_trace(request, procedure, runtime.trace.clone())?;
    let session_successor = materialize_session_successor(&runtime)?;
    Ok(CoordinationOutcome {
        result: InvocationResult {
            invocation_ref: request.invocation_id.clone(),
            procedure_ref: procedure.procedure_id.clone(),
            disposition,
            output: None,
            output_sensitivity: request.input_sensitivity,
            fault: Some(fault),
            final_process_states: runtime
                .states
                .values()
                .map(|state| (state.state_id.clone(), state.clone()))
                .collect(),
            semantic_trace: trace,
            consumed_budget: consumed,
            residuals: BTreeSet::from([
                "no external effect and no successor catalogue state".to_owned()
            ]),
            proof_refs: BTreeSet::from([request.admission_disposition_ref.clone()]),
            retention_policy_ref: request.retention_policy_ref.clone(),
        },
        steps: runtime.steps,
        continuations: runtime.continuations,
        active_continuation_refs: runtime.active_continuations,
        messages: runtime.messages,
        delivered_message_refs: runtime.delivered,
        terminal_returns: runtime.returns,
        session_successor,
    })
}

fn runtime_error_outcome(
    procedure: &CompiledProcedureIdentity,
    request: &InvocationRequest,
    fault: EvaluationFault,
    runtime: RuntimeProducts,
) -> Result<CoordinationOutcome, EvaluationFault> {
    let resource = ["budget", "bound", "exhausted", "queue"]
        .iter()
        .any(|marker| fault.message.contains(marker));
    coordination_fault_outcome(
        procedure,
        request,
        if resource {
            ProcedureFaultCategory::ResourceExhausted
        } else {
            ProcedureFaultCategory::InternalInvariant
        },
        if resource {
            InvocationDisposition::BudgetRefused
        } else {
            InvocationDisposition::Faulted
        },
        fault.message,
        runtime,
    )
}

fn consumed_budget(runtime: &RuntimeProducts, request: &InvocationRequest) -> ConsumedBudget {
    ConsumedBudget {
        logical_time: runtime.clock.saturating_sub(request.initial_logical_time),
        steps: runtime.steps.len() as u64,
        memory_units: runtime
            .states
            .values()
            .map(|state| {
                serde_json::to_vec(&state.local_state)
                    .map(|bytes| bytes.len() as u64)
                    .unwrap_or(u64::MAX)
            })
            .sum(),
        messages: runtime.messages.len() as u64,
        trace_events: runtime.trace.len() as u64,
    }
}

fn materialize_session_successor(
    runtime: &RuntimeProducts,
) -> Result<Option<NegotiationSession>, EvaluationFault> {
    let Some(mut session) = runtime.session.clone() else {
        return Ok(None);
    };
    session
        .message_frontier
        .extend(runtime.messages.keys().cloned());
    if session.status == NegotiationStatus::Opened && !session.message_frontier.is_empty() {
        session.status = NegotiationStatus::Deliberating;
    }
    session.session_generation_id = successor_session_identity(&session)?;
    Ok(Some(session))
}

fn active_pass_chain<'a>(
    session: &NegotiationSession,
    known_passes: &'a BTreeMap<SemanticId, TokenRingPass>,
) -> Result<Vec<&'a TokenRingPass>, EvaluationFault> {
    let expected_participant_digest = digest_serialized(
        &session.required_participant_refs,
        "token ring participant set",
    )?;
    let expected_anchor_digest =
        digest_serialized(&session.pinned_sop_anchor_refs, "token ring SOP anchor set")?;
    let mut remaining = session.pass_refs.clone();
    let mut chain = Vec::new();
    let mut predecessor: Option<SemanticId> = None;
    let mut participants = BTreeSet::new();
    let mut logical_time = None;
    while !remaining.is_empty() {
        let next = remaining.iter().find_map(|pass_ref| {
            known_passes.get(pass_ref).filter(|pass| {
                pass.predecessor_pass_ref == predecessor
                    && pass.session_ref == session.session_id
                    && pass.frame_generation == session.frame_generation
                    && pass.policy_ref == session.policy_ref
                    && pass.participant_set_digest == expected_participant_digest
                    && pass.sop_anchor_set_digest == expected_anchor_digest
                    && session
                        .required_participant_refs
                        .contains(&pass.participant_ref)
                    && logical_time.is_none_or(|before| pass.logical_time > before)
                    && !participants.contains(&pass.participant_ref)
            })
        });
        let pass = next.ok_or_else(|| {
            machine_fault("session pass refs do not form one exact current-generation chain")
        })?;
        remaining.remove(&pass.pass_id);
        predecessor = Some(pass.pass_id.clone());
        participants.insert(pass.participant_ref.clone());
        logical_time = Some(pass.logical_time);
        chain.push(pass);
    }
    Ok(chain)
}

fn next_required_participant(
    participants: &BTreeSet<SemanticId>,
    current: &SemanticId,
) -> Result<SemanticId, EvaluationFault> {
    participants
        .range((
            std::ops::Bound::Excluded(current),
            std::ops::Bound::Unbounded,
        ))
        .next()
        .or_else(|| participants.iter().next())
        .cloned()
        .ok_or_else(|| machine_fault("token ring has no participant"))
}

fn successor_session_identity(session: &NegotiationSession) -> Result<SemanticId, EvaluationFault> {
    let mut body = session.clone();
    body.session_generation_id = SemanticId::new("cppe:pending-session-generation")?;
    let digest = digest_serialized(&body, "negotiation session generation")?;
    derived_id("cppe:session-generation", &digest)
}
