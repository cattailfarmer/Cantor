//! Experimental compact attention reentry frames derived from retained replay authority.

use cantor_core::{ContentDigest, SemanticId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::{
    BoundSession, IterationRecord, IterationSuccessor, IterativeProviderPhase, RunPolicy,
    TOOL_NAME, admit_iterative_provider_iteration, drive_bound_session,
    experimental_fixture_context_json, extract_advance_call, iterative_advance_request,
    iterative_terminal_reflection_request, open_bound_session,
    scripted_orchestrator::scripted_advance_response, validate_iterative_provider_prefix,
    validate_run_policy,
};

pub const ATTENTION_REENTRY_FRAME_PROFILE: &str = "cantor-attention-reentry-frame/0.1";
pub const ATTENTION_REENTRY_MEASUREMENT_PROFILE: &str =
    "cantor-attention-reentry-frame-measurement/0.1";
pub const ATTENTION_REENTRY_FRAME_NONCLAIMS: [&str; 6] = [
    "frame is a derived transport view not replay authority",
    "digest commitment does not reproduce omitted semantic content",
    "structural request equivalence is not semantic output equivalence",
    "full retained prefix remains under host custody",
    "no provider compatibility or model quality claim",
    "no hidden-state live-token external-effect or remote operation",
];
pub const ATTENTION_REENTRY_MEASUREMENT_NONCLAIMS: [&str; 5] = [
    "compact UTF-8 JSON bytes are not model tokens",
    "request size is not latency memory quality or accuracy evidence",
    "full transcript requests remain the authoritative default",
    "fixture responses are synthesized and not provider output",
    "no provider model process network hidden state or external effect was used",
];

const COMPACT_ADVANCE_DIRECTIVE: &str = "Continue from the host-validated Cantor attention reentry frame and latest matching tool projection. Call advance_attention_procedure exactly once with the required host-selected quota. The host retains and replay-validates the omitted prefix; the digest is a commitment, not semantic reconstruction. Do not answer the subject yet.";
const COMPACT_REFLECTION_DIRECTIVE: &str = "Import the host-validated Cantor terminal reentry frame and latest matching terminal tool projection. Return only the required JSON and preserve its session and outcome digests exactly. The host retains and replay-validates the omitted prefix; do not treat any digest as external truth or effect authority.";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttentionHeadKind {
    Ready,
    Terminal,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AttentionReentryFrame {
    pub profile: String,
    pub phase: IterativeProviderPhase,
    pub model: String,
    pub session_id: SemanticId,
    pub opening_sequence: u64,
    pub iteration_count: usize,
    pub retained_prefix_digest: ContentDigest,
    pub head_sequence: u64,
    pub head_handle_digest: ContentDigest,
    pub latest_call_id: String,
    pub head_kind: AttentionHeadKind,
    pub exact_prefix_under_host_custody: bool,
    pub private_reasoning_recorded: bool,
    pub nonclaims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReentryRequestByteMeasurement {
    pub iteration_count: usize,
    pub phase: IterativeProviderPhase,
    pub full_request_bytes: usize,
    pub compact_request_bytes: usize,
    pub full_minus_compact_bytes: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AttentionReentryMeasurement {
    pub profile: String,
    pub fixture: String,
    pub maximum_steps_per_call: u64,
    pub frames: Vec<ReentryRequestByteMeasurement>,
    pub ready_frame_count: usize,
    pub terminal_frame_count: usize,
    pub total_full_request_bytes: usize,
    pub total_compact_request_bytes: usize,
    pub total_full_minus_compact_bytes: i64,
    pub first_full_request_bytes: usize,
    pub last_full_request_bytes: usize,
    pub first_compact_request_bytes: usize,
    pub last_compact_request_bytes: usize,
    pub maximum_compact_request_bytes: usize,
    pub full_request_growth_bytes: i64,
    pub compact_request_growth_bytes: i64,
    pub compact_to_full_basis_points: u64,
    pub byte_basis: String,
    pub semantic_equivalence_claimed: bool,
    pub provider_compatibility_claimed: bool,
    pub nonclaims: Vec<String>,
}

pub fn compile_attention_reentry_frame(
    model: &str,
    prompt: &str,
    policy: &RunPolicy,
    opening_handle: &cantor_compact_coordination_mcp::CompactCoordinationHandle,
    iterations: &[IterationRecord],
) -> Result<AttentionReentryFrame, String> {
    if iterations.is_empty() {
        return Err("attention reentry frame requires a nonempty retained prefix".to_owned());
    }
    let prefix =
        validate_iterative_provider_prefix(model, prompt, policy, opening_handle, iterations)?;
    let latest = iterations
        .last()
        .ok_or_else(|| "attention reentry frame omitted latest iteration".to_owned())?;
    let head_kind = match &latest.successor {
        IterationSuccessor::Ready { .. } => AttentionHeadKind::Ready,
        IterationSuccessor::Terminal { .. } => AttentionHeadKind::Terminal,
    };
    Ok(AttentionReentryFrame {
        profile: ATTENTION_REENTRY_FRAME_PROFILE.to_owned(),
        phase: prefix.phase,
        model: model.to_owned(),
        session_id: prefix.session_id,
        opening_sequence: opening_handle.sequence,
        iteration_count: iterations.len(),
        retained_prefix_digest: retained_prefix_digest(
            model,
            prompt,
            policy,
            opening_handle,
            iterations,
        )?,
        head_sequence: prefix.head_handle.sequence,
        head_handle_digest: prefix.head_handle.handle_digest,
        latest_call_id: latest.call_id.clone(),
        head_kind,
        exact_prefix_under_host_custody: true,
        private_reasoning_recorded: false,
        nonclaims: frame_nonclaims(),
    })
}

pub fn validate_attention_reentry_frame(
    frame: &AttentionReentryFrame,
    model: &str,
    prompt: &str,
    policy: &RunPolicy,
    opening_handle: &cantor_compact_coordination_mcp::CompactCoordinationHandle,
    iterations: &[IterationRecord],
) -> Result<(), String> {
    let expected =
        compile_attention_reentry_frame(model, prompt, policy, opening_handle, iterations)?;
    if frame != &expected {
        return Err("attention reentry frame differs from retained prefix replay".to_owned());
    }
    Ok(())
}

pub fn compact_iterative_advance_request(
    model: &str,
    prompt: &str,
    policy: &RunPolicy,
    opening_handle: &cantor_compact_coordination_mcp::CompactCoordinationHandle,
    iterations: &[IterationRecord],
) -> Result<Value, String> {
    let frame = compile_attention_reentry_frame(model, prompt, policy, opening_handle, iterations)?;
    if frame.phase != IterativeProviderPhase::Advance || frame.head_kind != AttentionHeadKind::Ready
    {
        return Err("compact advance request requires a READY reentry frame".to_owned());
    }
    if iterations.len()
        >= usize::try_from(policy.maximum_tool_calls)
            .map_err(|_| "attention reentry tool-call cap cannot be represented".to_owned())?
    {
        return Err("attention reentry tool-call cap is exhausted".to_owned());
    }
    let messages = compact_messages(COMPACT_ADVANCE_DIRECTIVE, prompt, &frame, iterations, false)?;
    Ok(advance_request_value(
        model,
        messages,
        policy.maximum_steps_per_call,
    ))
}

pub fn compact_terminal_reflection_request(
    model: &str,
    prompt: &str,
    policy: &RunPolicy,
    opening_handle: &cantor_compact_coordination_mcp::CompactCoordinationHandle,
    iterations: &[IterationRecord],
) -> Result<Value, String> {
    let frame = compile_attention_reentry_frame(model, prompt, policy, opening_handle, iterations)?;
    if frame.phase != IterativeProviderPhase::ReflectTerminal
        || frame.head_kind != AttentionHeadKind::Terminal
    {
        return Err("compact terminal reflection requires a terminal reentry frame".to_owned());
    }
    if iterations
        .len()
        .checked_add(1)
        .ok_or_else(|| "attention reentry provider-call count overflow".to_owned())?
        > usize::try_from(policy.maximum_provider_calls)
            .map_err(|_| "attention reentry provider-call cap cannot be represented".to_owned())?
    {
        return Err("compact terminal reflection exceeds the provider-call cap".to_owned());
    }
    let projection = match &iterations
        .last()
        .ok_or_else(|| "terminal reentry prefix is empty".to_owned())?
        .successor
    {
        IterationSuccessor::Terminal { projection } => projection,
        IterationSuccessor::Ready { .. } => {
            return Err("terminal reentry prefix ends with READY".to_owned());
        }
    };
    let mut messages = compact_messages(
        COMPACT_REFLECTION_DIRECTIVE,
        prompt,
        &frame,
        iterations,
        true,
    )?;
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
            "schema": crate::final_schema(projection)
        },
        "chat_template_kwargs": {"enable_thinking": false},
        "temperature": 0,
        "max_tokens": 512
    }))
}

pub fn validate_compact_attention_request(
    candidate: &Value,
    model: &str,
    prompt: &str,
    policy: &RunPolicy,
    opening_handle: &cantor_compact_coordination_mcp::CompactCoordinationHandle,
    iterations: &[IterationRecord],
) -> Result<(), String> {
    let frame = compile_attention_reentry_frame(model, prompt, policy, opening_handle, iterations)?;
    let (expected, full, preserved_fields, full_tail_start, compact_tail_start) = match frame.phase
    {
        IterativeProviderPhase::Advance => (
            compact_iterative_advance_request(model, prompt, policy, opening_handle, iterations)?,
            iterative_advance_request(model, prompt, policy, opening_handle, iterations)?,
            [
                "/model",
                "/tools",
                "/tool_choice",
                "/parallel_tool_calls",
                "/chat_template_kwargs",
                "/temperature",
                "/max_tokens",
            ]
            .as_slice(),
            full_message_count(iterations)? - 2,
            3,
        ),
        IterativeProviderPhase::ReflectTerminal => (
            compact_terminal_reflection_request(model, prompt, policy, opening_handle, iterations)?,
            iterative_terminal_reflection_request(
                model,
                prompt,
                policy,
                opening_handle,
                iterations,
            )?,
            [
                "/model",
                "/tools",
                "/tool_choice",
                "/parallel_tool_calls",
                "/response_format",
                "/chat_template_kwargs",
                "/temperature",
                "/max_tokens",
            ]
            .as_slice(),
            full_message_count(iterations)? - 2,
            3,
        ),
    };
    if candidate != &expected {
        return Err(
            "compact attention request differs from deterministic reconstruction".to_owned(),
        );
    }
    for pointer in preserved_fields {
        if candidate.pointer(pointer) != full.pointer(pointer) {
            return Err(
                "compact attention request changed a preserved protocol surface".to_owned(),
            );
        }
    }
    let full_messages = full["messages"]
        .as_array()
        .ok_or_else(|| "full attention request omitted messages".to_owned())?;
    let compact_messages = candidate["messages"]
        .as_array()
        .ok_or_else(|| "compact attention request omitted messages".to_owned())?;
    if compact_messages.get(1) != Some(&json!({"role": "user", "content": prompt}))
        || compact_messages.get(compact_tail_start) != full_messages.get(full_tail_start)
        || compact_messages.get(compact_tail_start + 1) != full_messages.get(full_tail_start + 1)
    {
        return Err("compact attention request changed objective or latest call pair".to_owned());
    }
    Ok(())
}

pub fn generate_attention_reentry_measurement() -> Result<AttentionReentryMeasurement, String> {
    let model = "scripted-reentry-model";
    let prompt = "Run the quota-one attention reentry measurement fixture.";
    let policy = RunPolicy {
        maximum_steps_per_call: 1,
        maximum_tool_calls: 64,
        maximum_provider_calls: 65,
        timeout_seconds: 120,
    };
    validate_run_policy(&policy)?;
    let opening = open_bound_session(
        experimental_fixture_context_json()?,
        SemanticId::new("registry:attention-reentry-measurement")
            .map_err(|fault| fault.to_string())?,
        SemanticId::new("session:attention-reentry-measurement")
            .map_err(|fault| fault.to_string())?,
    )?;
    let mut current = opening.clone();
    let mut iterations = Vec::<IterationRecord>::new();
    let mut frames = Vec::<ReentryRequestByteMeasurement>::new();
    for index in 0..policy.maximum_tool_calls {
        let response = scripted_advance_response(
            &format!("call-attention-reentry-{index}"),
            policy.maximum_steps_per_call,
        );
        let one_advance = drive_bound_session(
            &current,
            RunPolicy {
                maximum_steps_per_call: policy.maximum_steps_per_call,
                maximum_tool_calls: 1,
                maximum_provider_calls: 2,
                timeout_seconds: policy.timeout_seconds,
            },
        )?;
        let iteration = admit_iterative_provider_iteration(
            model,
            prompt,
            &policy,
            &opening.handle,
            &iterations,
            &response,
            &one_advance,
        )?;
        let terminal = matches!(iteration.successor, IterationSuccessor::Terminal { .. });
        iterations.push(iteration);
        let (phase, full, compact) = if terminal {
            (
                IterativeProviderPhase::ReflectTerminal,
                iterative_terminal_reflection_request(
                    model,
                    prompt,
                    &policy,
                    &opening.handle,
                    &iterations,
                )?,
                compact_terminal_reflection_request(
                    model,
                    prompt,
                    &policy,
                    &opening.handle,
                    &iterations,
                )?,
            )
        } else {
            let head = one_advance
                .stopped_head
                .clone()
                .ok_or_else(|| "quota-one READY advance omitted live head".to_owned())?;
            current = BoundSession {
                registry: one_advance.successor_registry,
                handle: head,
            };
            (
                IterativeProviderPhase::Advance,
                iterative_advance_request(model, prompt, &policy, &opening.handle, &iterations)?,
                compact_iterative_advance_request(
                    model,
                    prompt,
                    &policy,
                    &opening.handle,
                    &iterations,
                )?,
            )
        };
        validate_compact_attention_request(
            &compact,
            model,
            prompt,
            &policy,
            &opening.handle,
            &iterations,
        )?;
        let full_bytes = compact_json_bytes(&full)?;
        let compact_bytes = compact_json_bytes(&compact)?;
        frames.push(ReentryRequestByteMeasurement {
            iteration_count: iterations.len(),
            phase,
            full_request_bytes: full_bytes,
            compact_request_bytes: compact_bytes,
            full_minus_compact_bytes: signed_difference(full_bytes, compact_bytes)?,
        });
        if terminal {
            break;
        }
    }
    let measurement = assemble_measurement(frames, policy.maximum_steps_per_call)?;
    validate_attention_reentry_measurement(&measurement)?;
    Ok(measurement)
}

pub fn validate_attention_reentry_measurement(
    measurement: &AttentionReentryMeasurement,
) -> Result<(), String> {
    if measurement.profile != ATTENTION_REENTRY_MEASUREMENT_PROFILE
        || measurement.fixture != "quota_one_multi_frame_v1"
        || measurement.maximum_steps_per_call != 1
        || measurement.frames.len() < 3
        || measurement.semantic_equivalence_claimed
        || measurement.provider_compatibility_claimed
        || measurement.nonclaims != measurement_nonclaims()
        || measurement.byte_basis
            != "compact UTF-8 JSON requests; full_minus_compact is signed full bytes minus experimental compact bytes"
    {
        return Err("attention reentry measurement identity is invalid".to_owned());
    }
    let mut ready = 0_usize;
    let mut terminal = 0_usize;
    for (index, frame) in measurement.frames.iter().enumerate() {
        let expected_phase = if index + 1 == measurement.frames.len() {
            IterativeProviderPhase::ReflectTerminal
        } else {
            IterativeProviderPhase::Advance
        };
        if frame.iteration_count != index + 1
            || frame.phase != expected_phase
            || frame.full_request_bytes == 0
            || frame.compact_request_bytes == 0
            || frame.full_minus_compact_bytes
                != signed_difference(frame.full_request_bytes, frame.compact_request_bytes)?
        {
            return Err("attention reentry measurement frame is inconsistent".to_owned());
        }
        match frame.phase {
            IterativeProviderPhase::Advance => ready += 1,
            IterativeProviderPhase::ReflectTerminal => terminal += 1,
        }
    }
    let total_full = checked_sum(
        measurement
            .frames
            .iter()
            .map(|frame| frame.full_request_bytes),
    )?;
    let total_compact = checked_sum(
        measurement
            .frames
            .iter()
            .map(|frame| frame.compact_request_bytes),
    )?;
    let first = measurement
        .frames
        .first()
        .ok_or_else(|| "attention reentry measurement omitted first frame".to_owned())?;
    let last = measurement
        .frames
        .last()
        .ok_or_else(|| "attention reentry measurement omitted last frame".to_owned())?;
    let maximum_compact = measurement
        .frames
        .iter()
        .map(|frame| frame.compact_request_bytes)
        .max()
        .ok_or_else(|| "attention reentry measurement omitted compact maximum".to_owned())?;
    if measurement.ready_frame_count != ready
        || measurement.terminal_frame_count != terminal
        || terminal != 1
        || measurement.total_full_request_bytes != total_full
        || measurement.total_compact_request_bytes != total_compact
        || measurement.total_full_minus_compact_bytes
            != signed_difference(total_full, total_compact)?
        || measurement.first_full_request_bytes != first.full_request_bytes
        || measurement.last_full_request_bytes != last.full_request_bytes
        || measurement.first_compact_request_bytes != first.compact_request_bytes
        || measurement.last_compact_request_bytes != last.compact_request_bytes
        || measurement.maximum_compact_request_bytes != maximum_compact
        || measurement.full_request_growth_bytes
            != signed_difference(last.full_request_bytes, first.full_request_bytes)?
        || measurement.compact_request_growth_bytes
            != signed_difference(last.compact_request_bytes, first.compact_request_bytes)?
        || measurement.compact_to_full_basis_points
            != ratio_basis_points(total_compact, total_full)?
    {
        return Err("attention reentry measurement aggregate is inconsistent".to_owned());
    }
    Ok(())
}

pub fn pretty_attention_reentry_measurement_bytes(
    measurement: &AttentionReentryMeasurement,
) -> Result<Vec<u8>, String> {
    validate_attention_reentry_measurement(measurement)?;
    let mut bytes = serde_json::to_vec_pretty(measurement)
        .map_err(|error| format!("attention reentry measurement serialization failed: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn compact_messages(
    directive: &str,
    prompt: &str,
    frame: &AttentionReentryFrame,
    iterations: &[IterationRecord],
    terminal: bool,
) -> Result<Vec<Value>, String> {
    let latest = iterations
        .last()
        .ok_or_else(|| "compact attention request omitted latest iteration".to_owned())?;
    let call = extract_advance_call(&latest.sanitized_response, latest.maximum_steps)?;
    if call.call_id != latest.call_id {
        return Err("compact attention latest call identity changed".to_owned());
    }
    if terminal != matches!(latest.successor, IterationSuccessor::Terminal { .. }) {
        return Err("compact attention request phase differs from latest successor".to_owned());
    }
    let frame_json = serde_json::to_string(frame)
        .map_err(|error| format!("attention reentry frame serialization failed: {error}"))?;
    let projection_json = successor_json(&latest.successor)?;
    Ok(vec![
        json!({"role": "system", "content": directive}),
        json!({"role": "user", "content": prompt}),
        json!({
            "role": "system",
            "content": format!("Cantor attention reentry frame (derived; exact prefix remains under host custody): {frame_json}")
        }),
        call.assistant_message,
        json!({
            "role": "tool",
            "tool_call_id": latest.call_id,
            "content": projection_json
        }),
    ])
}

fn retained_prefix_digest(
    model: &str,
    prompt: &str,
    policy: &RunPolicy,
    opening_handle: &cantor_compact_coordination_mcp::CompactCoordinationHandle,
    iterations: &[IterationRecord],
) -> Result<ContentDigest, String> {
    let bytes = serde_json::to_vec(&json!({
        "model": model,
        "prompt": prompt,
        "policy": policy,
        "opening_handle": opening_handle,
        "iterations": iterations
    }))
    .map_err(|error| format!("retained prefix commitment serialization failed: {error}"))?;
    Ok(ContentDigest {
        algorithm: "sha256".to_owned(),
        value: Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    })
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

fn successor_json(successor: &IterationSuccessor) -> Result<String, String> {
    match successor {
        IterationSuccessor::Ready { projection } => serde_json::to_string(projection),
        IterationSuccessor::Terminal { projection } => serde_json::to_string(projection),
    }
    .map_err(|error| format!("attention reentry projection serialization failed: {error}"))
}

fn full_message_count(iterations: &[IterationRecord]) -> Result<usize, String> {
    2_usize
        .checked_add(
            iterations
                .len()
                .checked_mul(2)
                .ok_or_else(|| "full message count overflow".to_owned())?,
        )
        .ok_or_else(|| "full message count overflow".to_owned())
}

fn assemble_measurement(
    frames: Vec<ReentryRequestByteMeasurement>,
    maximum_steps_per_call: u64,
) -> Result<AttentionReentryMeasurement, String> {
    let first = frames
        .first()
        .ok_or_else(|| "attention reentry measurement omitted first frame".to_owned())?;
    let last = frames
        .last()
        .ok_or_else(|| "attention reentry measurement omitted last frame".to_owned())?;
    let total_full_request_bytes =
        checked_sum(frames.iter().map(|frame| frame.full_request_bytes))?;
    let total_compact_request_bytes =
        checked_sum(frames.iter().map(|frame| frame.compact_request_bytes))?;
    Ok(AttentionReentryMeasurement {
        profile: ATTENTION_REENTRY_MEASUREMENT_PROFILE.to_owned(),
        fixture: "quota_one_multi_frame_v1".to_owned(),
        maximum_steps_per_call,
        ready_frame_count: frames
            .iter()
            .filter(|frame| frame.phase == IterativeProviderPhase::Advance)
            .count(),
        terminal_frame_count: frames
            .iter()
            .filter(|frame| frame.phase == IterativeProviderPhase::ReflectTerminal)
            .count(),
        total_full_request_bytes,
        total_compact_request_bytes,
        total_full_minus_compact_bytes: signed_difference(
            total_full_request_bytes,
            total_compact_request_bytes,
        )?,
        first_full_request_bytes: first.full_request_bytes,
        last_full_request_bytes: last.full_request_bytes,
        first_compact_request_bytes: first.compact_request_bytes,
        last_compact_request_bytes: last.compact_request_bytes,
        maximum_compact_request_bytes: frames
            .iter()
            .map(|frame| frame.compact_request_bytes)
            .max()
            .ok_or_else(|| "attention reentry measurement omitted compact maximum".to_owned())?,
        full_request_growth_bytes: signed_difference(
            last.full_request_bytes,
            first.full_request_bytes,
        )?,
        compact_request_growth_bytes: signed_difference(
            last.compact_request_bytes,
            first.compact_request_bytes,
        )?,
        compact_to_full_basis_points: ratio_basis_points(
            total_compact_request_bytes,
            total_full_request_bytes,
        )?,
        frames,
        byte_basis: "compact UTF-8 JSON requests; full_minus_compact is signed full bytes minus experimental compact bytes".to_owned(),
        semantic_equivalence_claimed: false,
        provider_compatibility_claimed: false,
        nonclaims: measurement_nonclaims(),
    })
}

fn compact_json_bytes(value: &Value) -> Result<usize, String> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|error| format!("attention reentry request serialization failed: {error}"))
}

fn checked_sum(values: impl IntoIterator<Item = usize>) -> Result<usize, String> {
    values.into_iter().try_fold(0_usize, |sum, value| {
        sum.checked_add(value)
            .ok_or_else(|| "attention reentry measurement sum overflow".to_owned())
    })
}

fn signed_difference(left: usize, right: usize) -> Result<i64, String> {
    let left = i64::try_from(left)
        .map_err(|_| "attention reentry byte count cannot fit i64".to_owned())?;
    let right = i64::try_from(right)
        .map_err(|_| "attention reentry byte count cannot fit i64".to_owned())?;
    left.checked_sub(right)
        .ok_or_else(|| "attention reentry byte difference overflow".to_owned())
}

fn ratio_basis_points(numerator: usize, denominator: usize) -> Result<u64, String> {
    if denominator == 0 {
        return Err("attention reentry ratio denominator is zero".to_owned());
    }
    let scaled = (numerator as u128)
        .checked_mul(10_000)
        .ok_or_else(|| "attention reentry ratio overflow".to_owned())?
        / denominator as u128;
    u64::try_from(scaled).map_err(|_| "attention reentry ratio overflow".to_owned())
}

fn frame_nonclaims() -> Vec<String> {
    ATTENTION_REENTRY_FRAME_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn measurement_nonclaims() -> Vec<String> {
    ATTENTION_REENTRY_MEASUREMENT_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}
