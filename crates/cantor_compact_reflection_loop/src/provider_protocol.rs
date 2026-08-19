//! Pure provider-transcript construction and admission for the iterative loop.

use std::collections::BTreeSet;

use cantor_compact_coordination_mcp::{
    CompactCoordinationHandle, CompactResponseStatus, CompactSessionOperation,
    CompactSessionResponse, CompactSessionResult, CompactSessionStatus, HANDLE_PROFILE,
    RESPONSE_PROFILE,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    DeterministicAdvanceSuccessor, DeterministicDriveResult, IterationRecord, IterationSuccessor,
    IterativeRunState, ParsedAdvanceCall, RunPolicy, StopReason, TOOL_NAME, TerminalProjection,
    extract_advance_call, final_schema, project_terminal_observation, sanitize,
    validate_deterministic_drive_result, validate_ready_projection, validate_run_policy,
};

pub const ITERATIVE_PROVIDER_PREFIX_PROFILE: &str = "cantor-iterative-provider-prefix/0.1";
pub const ITERATIVE_PROVIDER_NONCLAIMS: [&str; 5] = [
    "protocol conformance is not correct reasoning",
    "recorded provider bytes are not authenticated producer identity",
    "no private reasoning is retained",
    "no provider network or process call was performed",
    "no external effect or semantic-truth claim",
];

const MAX_MODEL_BYTES: usize = 1_024;
const MAX_PROMPT_BYTES: usize = 32 * 1_024;
const ADVANCE_SYSTEM_DIRECTIVE: &str = "Call advance_attention_procedure exactly once with the required host-selected quota. If a prior tool result is READY, continue from that host-bound state. Do not answer the subject yet. The host retains exact state and will return either another READY projection or the terminal projection in a later separate pass.";
const REFLECTION_SYSTEM_DIRECTIVE: &str = "Import the ordered Cantor tool projections. The last projection is terminal. Return only the required JSON, preserve its session and outcome digests exactly, and do not treat any digest as external truth or effect authority.";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IterativeProviderPhase {
    Advance,
    ReflectTerminal,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IterativeProviderPrefixProjection {
    pub profile: String,
    pub model: String,
    pub session_id: cantor_core::SemanticId,
    pub opening_sequence: u64,
    pub iteration_count: usize,
    pub call_ids: Vec<String>,
    pub head_handle: CompactCoordinationHandle,
    pub phase: IterativeProviderPhase,
    pub private_reasoning_recorded: bool,
    pub nonclaims: Vec<String>,
}

pub fn iterative_advance_request(
    model: &str,
    prompt: &str,
    policy: &RunPolicy,
    opening_handle: &CompactCoordinationHandle,
    iterations: &[IterationRecord],
) -> Result<Value, String> {
    let projection =
        validate_iterative_provider_prefix(model, prompt, policy, opening_handle, iterations)?;
    if projection.phase != IterativeProviderPhase::Advance {
        return Err("terminal provider prefix cannot request another advance".to_owned());
    }
    if iterations.len()
        >= usize::try_from(policy.maximum_tool_calls)
            .map_err(|_| "provider tool-call cap cannot be represented".to_owned())?
    {
        return Err("provider tool-call cap is exhausted".to_owned());
    }
    let messages = transcript_messages(ADVANCE_SYSTEM_DIRECTIVE, prompt, iterations)?;
    Ok(advance_request_value(
        model,
        messages,
        policy.maximum_steps_per_call,
    ))
}

pub fn admit_iterative_provider_iteration(
    model: &str,
    prompt: &str,
    policy: &RunPolicy,
    opening_handle: &CompactCoordinationHandle,
    prior_iterations: &[IterationRecord],
    raw_provider_response: &Value,
    one_advance: &DeterministicDriveResult,
) -> Result<IterationRecord, String> {
    let prefix = validate_iterative_provider_prefix(
        model,
        prompt,
        policy,
        opening_handle,
        prior_iterations,
    )?;
    if prefix.phase != IterativeProviderPhase::Advance {
        return Err("terminal provider prefix cannot admit another iteration".to_owned());
    }
    if prior_iterations.len()
        >= usize::try_from(policy.maximum_tool_calls)
            .map_err(|_| "provider tool-call cap cannot be represented".to_owned())?
    {
        return Err("provider tool-call cap is exhausted".to_owned());
    }
    validate_single_advance_result(one_advance, policy, &prefix.head_handle)?;
    let request =
        iterative_advance_request(model, prompt, policy, opening_handle, prior_iterations)?;
    let sanitized_response = sanitize(raw_provider_response);
    let call = extract_advance_call(&sanitized_response, policy.maximum_steps_per_call)?;
    validate_new_call_identity(&call, prior_iterations)?;

    let deterministic = one_advance
        .advances
        .first()
        .ok_or_else(|| "single-advance result omitted its advance".to_owned())?;
    let successor = match &deterministic.successor {
        DeterministicAdvanceSuccessor::Ready { projection } => IterationSuccessor::Ready {
            projection: projection.clone(),
        },
        DeterministicAdvanceSuccessor::Terminal { handle } => {
            let observation = one_advance
                .terminal_observation
                .as_ref()
                .ok_or_else(|| "terminal single-advance result omitted observation".to_owned())?;
            if &observation.handle != handle {
                return Err("terminal deterministic handle and observation differ".to_owned());
            }
            IterationSuccessor::Terminal {
                projection: project_terminal_observation(observation)?,
            }
        }
    };
    let iteration_index = u32::try_from(prior_iterations.len())
        .map_err(|_| "provider iteration index cannot be represented".to_owned())?;
    let record = IterationRecord {
        iteration_index,
        predecessor_handle: prefix.head_handle,
        request,
        sanitized_response,
        call_id: call.call_id,
        maximum_steps: policy.maximum_steps_per_call,
        compact_response: deterministic.compact_response.clone(),
        successor,
    };
    let mut candidate = prior_iterations.to_vec();
    candidate.push(record.clone());
    validate_iterative_provider_prefix(model, prompt, policy, opening_handle, &candidate)?;
    Ok(record)
}

pub fn iterative_terminal_reflection_request(
    model: &str,
    prompt: &str,
    policy: &RunPolicy,
    opening_handle: &CompactCoordinationHandle,
    iterations: &[IterationRecord],
) -> Result<Value, String> {
    let prefix =
        validate_iterative_provider_prefix(model, prompt, policy, opening_handle, iterations)?;
    if prefix.phase != IterativeProviderPhase::ReflectTerminal {
        return Err("terminal reflection requires a terminal provider prefix".to_owned());
    }
    if iterations
        .len()
        .checked_add(1)
        .ok_or_else(|| "provider-call count overflow".to_owned())?
        > usize::try_from(policy.maximum_provider_calls)
            .map_err(|_| "provider-call cap cannot be represented".to_owned())?
    {
        return Err("terminal reflection exceeds the provider-call cap".to_owned());
    }
    let projection = match &iterations
        .last()
        .ok_or_else(|| "terminal provider prefix is empty".to_owned())?
        .successor
    {
        IterationSuccessor::Terminal { projection } => projection,
        IterationSuccessor::Ready { .. } => {
            return Err("terminal provider prefix ends with READY".to_owned());
        }
    };
    let mut messages = transcript_messages(REFLECTION_SYSTEM_DIRECTIVE, prompt, iterations)?;
    messages.push(json!({
        "role": "user",
        "content": "Reflection checkpoint: acknowledge the imported terminal result now."
    }));
    Ok(json!({
        "model": model,
        "messages": messages,
        "tools": [],
        "tool_choice": "none",
        "parallel_tool_calls": false,
        "response_format": {
            "type": "json_object",
            "schema": final_schema(projection)
        },
        "chat_template_kwargs": {"enable_thinking": false},
        "temperature": 0,
        "max_tokens": 512
    }))
}

pub fn validate_iterative_provider_prefix(
    model: &str,
    prompt: &str,
    policy: &RunPolicy,
    opening_handle: &CompactCoordinationHandle,
    iterations: &[IterationRecord],
) -> Result<IterativeProviderPrefixProjection, String> {
    validate_provider_inputs(model, prompt, policy, opening_handle)?;
    if iterations.len()
        > usize::try_from(policy.maximum_tool_calls)
            .map_err(|_| "provider tool-call cap cannot be represented".to_owned())?
    {
        return Err("provider prefix exceeds its tool-call cap".to_owned());
    }

    let mut expected = opening_handle;
    let mut call_ids_seen = BTreeSet::new();
    let mut call_ids = Vec::new();
    let mut prior = Vec::new();
    for (index, iteration) in iterations.iter().enumerate() {
        let expected_request = advance_request_value(
            model,
            transcript_messages(ADVANCE_SYSTEM_DIRECTIVE, prompt, &prior)?,
            policy.maximum_steps_per_call,
        );
        if iteration.request != expected_request
            || iteration.sanitized_response != sanitize(&iteration.sanitized_response)
            || usize::try_from(iteration.iteration_index).ok() != Some(index)
            || &iteration.predecessor_handle != expected
            || iteration.maximum_steps != policy.maximum_steps_per_call
        {
            return Err("provider iteration request predecessor or quota is invalid".to_owned());
        }
        let call =
            extract_advance_call(&iteration.sanitized_response, policy.maximum_steps_per_call)?;
        if call.call_id.trim().is_empty()
            || call.call_id.len() > 1_024
            || call
                .assistant_message
                .pointer("/tool_calls/0/type")
                .and_then(Value::as_str)
                != Some("function")
            || call.call_id != iteration.call_id
            || !call_ids_seen.insert(iteration.call_id.clone())
        {
            return Err(
                "provider iteration call identity is empty changed or duplicate".to_owned(),
            );
        }
        call_ids.push(iteration.call_id.clone());
        let successor = validate_compact_iteration(iteration, opening_handle)?;
        match &iteration.successor {
            IterationSuccessor::Ready { .. } => {
                if successor.status != CompactSessionStatus::Ready {
                    return Err("READY provider successor has a non-READY handle".to_owned());
                }
            }
            IterationSuccessor::Terminal { .. } => {
                if index + 1 != iterations.len() {
                    return Err("terminal provider successor is not last".to_owned());
                }
            }
        }
        expected = successor;
        prior.push(iteration.clone());
    }

    let phase = if expected.status == CompactSessionStatus::Terminal {
        IterativeProviderPhase::ReflectTerminal
    } else {
        IterativeProviderPhase::Advance
    };
    let projection = IterativeProviderPrefixProjection {
        profile: ITERATIVE_PROVIDER_PREFIX_PROFILE.to_owned(),
        model: model.to_owned(),
        session_id: opening_handle.session_id.clone(),
        opening_sequence: opening_handle.sequence,
        iteration_count: iterations.len(),
        call_ids,
        head_handle: expected.clone(),
        phase,
        private_reasoning_recorded: false,
        nonclaims: provider_nonclaims(),
    };
    validate_provider_prefix_projection(&projection, model, opening_handle, iterations)?;
    Ok(projection)
}

pub fn validate_provider_prefix_projection(
    projection: &IterativeProviderPrefixProjection,
    expected_model: &str,
    opening_handle: &CompactCoordinationHandle,
    iterations: &[IterationRecord],
) -> Result<(), String> {
    if projection.profile != ITERATIVE_PROVIDER_PREFIX_PROFILE
        || projection.model != expected_model
        || projection.session_id != opening_handle.session_id
        || projection.opening_sequence != opening_handle.sequence
        || projection.iteration_count != iterations.len()
        || projection.call_ids
            != iterations
                .iter()
                .map(|iteration| iteration.call_id.clone())
                .collect::<Vec<_>>()
        || projection.private_reasoning_recorded
        || projection.nonclaims != provider_nonclaims()
        || projection.call_ids.iter().collect::<BTreeSet<_>>().len() != projection.call_ids.len()
    {
        return Err("provider prefix projection identity or authority is invalid".to_owned());
    }
    let expected_head = iterations
        .last()
        .map(|iteration| response_handle(&iteration.compact_response))
        .transpose()?
        .unwrap_or(opening_handle);
    if &projection.head_handle != expected_head
        || (projection.phase == IterativeProviderPhase::ReflectTerminal)
            != (expected_head.status == CompactSessionStatus::Terminal)
    {
        return Err("provider prefix projection misstates its head or phase".to_owned());
    }
    Ok(())
}

fn validate_single_advance_result(
    result: &DeterministicDriveResult,
    policy: &RunPolicy,
    expected_opening: &CompactCoordinationHandle,
) -> Result<(), String> {
    validate_deterministic_drive_result(result)?;
    if &result.opening_handle != expected_opening
        || result.policy.maximum_steps_per_call != policy.maximum_steps_per_call
        || result.advances.len() != 1
    {
        return Err("provider iteration requires one exact deterministic advance".to_owned());
    }
    match &result.advances[0].successor {
        DeterministicAdvanceSuccessor::Ready { .. } => {
            if result.status != IterativeRunState::Stopped
                || result.stop_reason != Some(StopReason::ToolCallCap)
                || result.policy.maximum_tool_calls != 1
                || result.reentry_available != Some(true)
            {
                return Err("single READY advance did not stop at its exact live head".to_owned());
            }
        }
        DeterministicAdvanceSuccessor::Terminal { .. } => {
            if result.status != IterativeRunState::Complete {
                return Err("single terminal advance did not complete exactly".to_owned());
            }
        }
    }
    Ok(())
}

fn validate_provider_inputs(
    model: &str,
    prompt: &str,
    policy: &RunPolicy,
    opening_handle: &CompactCoordinationHandle,
) -> Result<(), String> {
    validate_run_policy(policy)?;
    if model.trim().is_empty() || model.len() > MAX_MODEL_BYTES {
        return Err("provider model must contain 1..=1024 bytes".to_owned());
    }
    if prompt.trim().is_empty() || prompt.len() > MAX_PROMPT_BYTES {
        return Err("provider prompt must contain 1..=32768 bytes".to_owned());
    }
    if opening_handle.profile != HANDLE_PROFILE
        || opening_handle.status != CompactSessionStatus::Ready
        || opening_handle.sequence == 0
        || opening_handle.checkpoint_digest.is_none()
        || opening_handle.outcome_digest.is_some()
    {
        return Err("provider opening handle is not a READY compact identity".to_owned());
    }
    Ok(())
}

fn validate_new_call_identity(
    call: &ParsedAdvanceCall,
    prior_iterations: &[IterationRecord],
) -> Result<(), String> {
    if call.call_id.trim().is_empty()
        || call.call_id.len() > 1_024
        || call
            .assistant_message
            .pointer("/tool_calls/0/type")
            .and_then(Value::as_str)
            != Some("function")
        || prior_iterations
            .iter()
            .any(|iteration| iteration.call_id == call.call_id)
    {
        return Err("new provider call identity is empty or already used".to_owned());
    }
    Ok(())
}

fn validate_compact_iteration<'a>(
    iteration: &'a IterationRecord,
    opening_handle: &CompactCoordinationHandle,
) -> Result<&'a CompactCoordinationHandle, String> {
    if iteration.compact_response.profile != RESPONSE_PROFILE
        || iteration.compact_response.operation != CompactSessionOperation::Advance
        || iteration.compact_response.status != CompactResponseStatus::Succeeded
        || iteration.compact_response.fault.is_some()
    {
        return Err("provider iteration compact response is not a successful ADVANCE".to_owned());
    }
    let handle = response_handle(&iteration.compact_response)?;
    if handle.profile != HANDLE_PROFILE
        || handle.registry_id != opening_handle.registry_id
        || handle.session_id != opening_handle.session_id
        || handle.sequence
            != iteration
                .predecessor_handle
                .sequence
                .checked_add(1)
                .ok_or_else(|| "provider iteration sequence overflow".to_owned())?
    {
        return Err("provider iteration compact successor leaves causal identity".to_owned());
    }
    match &iteration.successor {
        IterationSuccessor::Ready { projection } => validate_ready_projection(projection, handle)?,
        IterationSuccessor::Terminal { projection } => {
            validate_terminal_projection(projection, handle)?;
        }
    }
    Ok(handle)
}

fn validate_terminal_projection(
    projection: &TerminalProjection,
    handle: &CompactCoordinationHandle,
) -> Result<(), String> {
    if projection.profile != "cantor-verified-terminal-projection/0.1"
        || projection.observed_status != "terminal_outcome"
        || !projection.exact_record_available_via_read
        || handle.status != CompactSessionStatus::Terminal
        || projection.session_id != handle.session_id
        || projection.sequence != handle.sequence
        || projection.record_digest != handle.record_digest
        || Some(&projection.outcome_digest) != handle.outcome_digest.as_ref()
    {
        return Err("terminal provider projection differs from its exact handle".to_owned());
    }
    Ok(())
}

fn transcript_messages(
    system_directive: &str,
    prompt: &str,
    iterations: &[IterationRecord],
) -> Result<Vec<Value>, String> {
    let mut messages = vec![
        json!({"role": "system", "content": system_directive}),
        json!({"role": "user", "content": prompt}),
    ];
    for iteration in iterations {
        let call = extract_advance_call(&iteration.sanitized_response, iteration.maximum_steps)?;
        if call.call_id != iteration.call_id {
            return Err("provider transcript call identity changed".to_owned());
        }
        messages.push(call.assistant_message);
        messages.push(json!({
            "role": "tool",
            "tool_call_id": iteration.call_id,
            "content": successor_json(&iteration.successor)?
        }));
    }
    Ok(messages)
}

fn successor_json(successor: &IterationSuccessor) -> Result<String, String> {
    match successor {
        IterationSuccessor::Ready { projection } => serde_json::to_string(projection),
        IterationSuccessor::Terminal { projection } => serde_json::to_string(projection),
    }
    .map_err(|error| format!("provider tool projection serialization failed: {error}"))
}

fn advance_request_value(model: &str, messages: Vec<Value>, maximum_steps: u64) -> Value {
    json!({
        "model": model,
        "messages": messages,
        "tools": [{
            "type": "function",
            "function": {
                "name": TOOL_NAME,
                "description": "Advance one bounded slice of the host-bound Cantor attention procedure.",
                "parameters": {
                    "type": "object",
                    "properties": {"maximum_steps": {"type": "integer", "const": maximum_steps}},
                    "required": ["maximum_steps"],
                    "additionalProperties": false
                }
            }
        }],
        "tool_choice": "required",
        "parallel_tool_calls": false,
        "chat_template_kwargs": {"enable_thinking": false},
        "temperature": 0,
        "max_tokens": 256
    })
}

fn response_handle(
    response: &CompactSessionResponse,
) -> Result<&CompactCoordinationHandle, String> {
    match response.result.as_ref() {
        Some(CompactSessionResult::State { handle }) => Ok(handle),
        Some(CompactSessionResult::Record { .. }) => {
            Err("provider iteration ADVANCE response cannot be a READ record".to_owned())
        }
        None => Err("provider iteration ADVANCE response omitted its handle".to_owned()),
    }
}

fn provider_nonclaims() -> Vec<String> {
    ITERATIVE_PROVIDER_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}
