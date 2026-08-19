//! Pure contracts for one compact procedure call followed by model reflection.

#![forbid(unsafe_code)]

use cantor_compact_coordination_mcp::{
    CompactCoordinationHandle, CompactCoordinationRecord, CompactCoordinationRegistry,
    CompactResponseStatus, CompactSessionCommand, CompactSessionResult, CompactSessionStatus,
    apply_compact_coordination_command, new_compact_coordination_registry,
};
use cantor_core::{ContentDigest, SemanticId};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

pub const REPORT_PROFILE: &str = "cantor-compact-procedure-reflection-report/0.1";
pub const TOOL_NAME: &str = "advance_attention_procedure";
pub const FINAL_STATEMENT: &str = "Cantor reached the referenced terminal procedure outcome; its digest is evidence, not external truth or effect authority.";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdvanceAttentionArguments {
    pub maximum_steps: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedAdvanceCall {
    pub assistant_message: Value,
    pub call_id: String,
    pub arguments: AdvanceAttentionArguments,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TerminalObservation {
    pub observed_status: String,
    pub handle: CompactCoordinationHandle,
    pub record_json: String,
    pub outcome_digest: ContentDigest,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinalOutput {
    pub observed_status: String,
    pub session_id: SemanticId,
    pub outcome_digest: ContentDigest,
    pub statement: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundSession {
    pub registry: CompactCoordinationRegistry,
    pub handle: CompactCoordinationHandle,
}

pub fn normalize_loopback_base_url(candidate: &str) -> Result<String, String> {
    let parsed = Url::parse(candidate).map_err(|error| format!("invalid base URL: {error}"))?;
    let loopback = matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if parsed.scheme() != "http"
        || !loopback
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path().trim_end_matches('/') != "/v1"
    {
        return Err("base URL must be an unauthenticated loopback HTTP /v1 root".to_owned());
    }
    Ok(candidate.trim_end_matches('/').to_owned())
}

pub fn open_bound_session(
    context_json: String,
    registry_id: SemanticId,
    session_id: SemanticId,
) -> Result<BoundSession, String> {
    let registry = new_compact_coordination_registry(registry_id)?;
    let transition = apply_compact_coordination_command(
        &registry,
        CompactSessionCommand::Open {
            expected_registry_digest: registry.registry_digest.clone(),
            session_id,
            context_json,
        },
    );
    let handle = successful_state_handle(&transition.response)?;
    if handle.status != CompactSessionStatus::Ready {
        return Err("new compact session did not return a ready handle".to_owned());
    }
    Ok(BoundSession {
        registry: transition.successor,
        handle,
    })
}

pub fn advance_bound_session_terminal(
    session: &BoundSession,
    maximum_steps: u64,
) -> Result<(BoundSession, TerminalObservation), String> {
    if maximum_steps == 0 {
        return Err("maximum_steps must be positive".to_owned());
    }
    let transition = apply_compact_coordination_command(
        &session.registry,
        CompactSessionCommand::Advance {
            expected_registry_digest: session.handle.registry_digest.clone(),
            session_id: session.handle.session_id.clone(),
            expected_sequence: session.handle.sequence,
            expected_record_digest: session.handle.record_digest.clone(),
            maximum_steps,
        },
    );
    let handle = successful_state_handle(&transition.response)?;
    if handle.status != CompactSessionStatus::Terminal {
        return Err("P0 advancement did not reach terminal state".to_owned());
    }
    let read = apply_compact_coordination_command(
        &transition.successor,
        CompactSessionCommand::Read {
            expected_registry_digest: handle.registry_digest.clone(),
            session_id: handle.session_id.clone(),
        },
    );
    if read.successor != transition.successor {
        return Err("terminal READ unexpectedly changed the registry".to_owned());
    }
    let (read_handle, record_json, record_digest) = match read.response.result {
        Some(CompactSessionResult::Record {
            handle,
            record_json,
            record_digest,
        }) if read.response.status == CompactResponseStatus::Succeeded => {
            (handle, record_json, record_digest)
        }
        _ => return Err(compact_fault("terminal READ", &read.response)),
    };
    if read_handle != handle || record_digest != handle.record_digest {
        return Err("terminal READ identity differs from advancement handle".to_owned());
    }
    let record: CompactCoordinationRecord = serde_json::from_str(&record_json)
        .map_err(|error| format!("terminal record JSON is invalid: {error}"))?;
    if record.record_digest != record_digest
        || record.outcome.is_none()
        || record.checkpoint.is_some()
    {
        return Err("terminal record has an invalid digest or state shape".to_owned());
    }
    let outcome_digest = handle
        .outcome_digest
        .clone()
        .ok_or("terminal handle omitted outcome digest")?;
    Ok((
        BoundSession {
            registry: transition.successor,
            handle: handle.clone(),
        },
        TerminalObservation {
            observed_status: "terminal_outcome".to_owned(),
            handle,
            record_json,
            outcome_digest,
        },
    ))
}

pub fn first_request(model: &str, prompt: &str, maximum_steps: u64) -> Value {
    json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "Call advance_attention_procedure exactly once with the required quota. Do not answer the subject yet. The host retains the signed context and will return the exact terminal result for a separate reflection pass."
            },
            {"role": "user", "content": prompt}
        ],
        "tools": [{
            "type": "function",
            "function": {
                "name": TOOL_NAME,
                "description": "Advance the host-bound Cantor attention procedure to its terminal result.",
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

pub fn extract_advance_call(
    response: &Value,
    expected_maximum_steps: u64,
) -> Result<ParsedAdvanceCall, String> {
    let choice = single_choice(response)?;
    if choice.get("finish_reason").and_then(Value::as_str) != Some("tool_calls") {
        return Err("first pass did not finish with tool_calls".to_owned());
    }
    let message = choice.get("message").ok_or("first pass omitted message")?;
    if message.get("role").and_then(Value::as_str) != Some("assistant") {
        return Err("first pass message is not assistant-authored".to_owned());
    }
    if message
        .get("content")
        .is_some_and(|value| !value.is_null() && value.as_str() != Some(""))
    {
        return Err("first pass mixed public content with its tool call".to_owned());
    }
    let calls = message
        .get("tool_calls")
        .and_then(Value::as_array)
        .ok_or("first pass omitted tool_calls")?;
    if calls.len() != 1 {
        return Err(format!("expected one tool call, observed {}", calls.len()));
    }
    let call = &calls[0];
    if call.pointer("/function/name").and_then(Value::as_str) != Some(TOOL_NAME) {
        return Err("first pass called the wrong tool".to_owned());
    }
    let call_id = call
        .get("id")
        .and_then(Value::as_str)
        .ok_or("tool call omitted id")?
        .to_owned();
    let encoded = call
        .pointer("/function/arguments")
        .ok_or("tool call omitted arguments")?;
    let value = if let Some(text) = encoded.as_str() {
        serde_json::from_str(text)
            .map_err(|error| format!("tool arguments are invalid JSON: {error}"))?
    } else if encoded.is_object() {
        encoded.clone()
    } else {
        return Err("tool arguments are not an encoded object".to_owned());
    };
    let arguments: AdvanceAttentionArguments = serde_json::from_value(value)
        .map_err(|error| format!("tool arguments violate the closed contract: {error}"))?;
    if arguments.maximum_steps != expected_maximum_steps {
        return Err("tool call changed the host-selected quota".to_owned());
    }
    Ok(ParsedAdvanceCall {
        assistant_message: json!({
            "role": "assistant",
            "content": message.get("content").cloned().unwrap_or(Value::Null),
            "tool_calls": [call.clone()]
        }),
        call_id,
        arguments,
    })
}

pub fn reflection_request(
    model: &str,
    prompt: &str,
    call: &ParsedAdvanceCall,
    observation: &TerminalObservation,
) -> Value {
    json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "Import the exact terminal Cantor result from the tool message. Return only the required JSON. Preserve its session and outcome digests exactly, and do not treat the digest as external truth or effect authority."
            },
            {"role": "user", "content": prompt},
            call.assistant_message,
            {
                "role": "tool",
                "tool_call_id": call.call_id,
                "content": serde_json::to_string(observation).expect("observation serializes")
            },
            {"role": "user", "content": "Reflection checkpoint: acknowledge the imported terminal result now."}
        ],
        "tools": [],
        "tool_choice": "none",
        "parallel_tool_calls": false,
        "response_format": {
            "type": "json_object",
            "schema": final_schema(observation)
        },
        "chat_template_kwargs": {"enable_thinking": false},
        "temperature": 0,
        "max_tokens": 512
    })
}

pub fn extract_final_output(
    response: &Value,
    observation: &TerminalObservation,
) -> Result<FinalOutput, String> {
    let choice = single_choice(response)?;
    if choice.get("finish_reason").and_then(Value::as_str) != Some("stop") {
        return Err("reflection pass did not finish with stop".to_owned());
    }
    let message = choice
        .get("message")
        .ok_or("reflection pass omitted message")?;
    if message.get("role").and_then(Value::as_str) != Some("assistant") {
        return Err("reflection message is not assistant-authored".to_owned());
    }
    if message
        .get("tool_calls")
        .and_then(Value::as_array)
        .is_some_and(|calls| !calls.is_empty())
    {
        return Err("reflection pass attempted another tool call".to_owned());
    }
    let content = message
        .get("content")
        .and_then(Value::as_str)
        .ok_or("reflection pass omitted string content")?;
    let output: FinalOutput = serde_json::from_str(content)
        .map_err(|error| format!("reflection output violates JSON contract: {error}"))?;
    let expected = FinalOutput {
        observed_status: observation.observed_status.clone(),
        session_id: observation.handle.session_id.clone(),
        outcome_digest: observation.outcome_digest.clone(),
        statement: FINAL_STATEMENT.to_owned(),
    };
    if output != expected {
        return Err("reflection output changed the admitted terminal identity".to_owned());
    }
    Ok(output)
}

pub fn sanitize(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut result = Map::new();
            for (key, item) in object {
                if !matches!(
                    key.as_str(),
                    "reasoning" | "reasoning_content" | "thinking" | "thinking_content"
                ) {
                    result.insert(key.clone(), sanitize(item));
                }
            }
            Value::Object(result)
        }
        Value::Array(items) => Value::Array(items.iter().map(sanitize).collect()),
        _ => value.clone(),
    }
}

fn successful_state_handle(
    response: &cantor_compact_coordination_mcp::CompactSessionResponse,
) -> Result<CompactCoordinationHandle, String> {
    match (&response.status, &response.result) {
        (CompactResponseStatus::Succeeded, Some(CompactSessionResult::State { handle })) => {
            Ok(handle.clone())
        }
        _ => Err(compact_fault("compact command", response)),
    }
}

fn compact_fault(
    stage: &str,
    response: &cantor_compact_coordination_mcp::CompactSessionResponse,
) -> String {
    let detail = response
        .fault
        .as_ref()
        .map(|fault| format!("{}: {}", fault.code, fault.message))
        .unwrap_or_else(|| "response omitted expected result".to_owned());
    format!("{stage} failed: {detail}")
}

fn single_choice(response: &Value) -> Result<&Map<String, Value>, String> {
    let choices = response
        .get("choices")
        .and_then(Value::as_array)
        .ok_or("provider response omitted choices")?;
    if choices.len() != 1 {
        return Err(format!(
            "expected one provider choice, observed {}",
            choices.len()
        ));
    }
    choices[0]
        .as_object()
        .ok_or_else(|| "provider choice is not an object".to_owned())
}

fn final_schema(observation: &TerminalObservation) -> Value {
    json!({
        "type": "object",
        "properties": {
            "observed_status": {"type": "string", "const": observation.observed_status},
            "session_id": {"type": "string", "const": observation.handle.session_id.as_str()},
            "outcome_digest": {
                "type": "object",
                "properties": {
                    "algorithm": {"type": "string", "const": observation.outcome_digest.algorithm},
                    "value": {"type": "string", "const": observation.outcome_digest.value}
                },
                "required": ["algorithm", "value"],
                "additionalProperties": false
            },
            "statement": {"type": "string", "const": FINAL_STATEMENT}
        },
        "required": ["observed_status", "session_id", "outcome_digest", "statement"],
        "additionalProperties": false
    })
}
