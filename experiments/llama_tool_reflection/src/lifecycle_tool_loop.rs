//! Closed model-facing contract for the Slice 11 lifecycle tool-loop probe.

use cantor_core::NativeLifecycleValidationResponse;
use cantor_lifecycle_tool_loop::GovernedLifecycleFixture;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

pub const MODEL_TOOL_NAME: &str = "cantor_validate_lifecycle";
pub const MODEL_OPERATION: &str = "validate";
pub const MAX_MODEL_ARGUMENT_BYTES: usize = 4_096;
pub const MAX_TOOL_CALL_ID_CHARACTERS: usize = 256;
pub const MAX_PROVIDER_FAULT_CHARACTERS: usize = 2_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelToolArguments {
    pub fixture_id: String,
    pub operation: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleProjection {
    pub source_identity: String,
    pub operation: Option<String>,
    pub lifecycle_outcome: String,
    pub deepest_valid_stage: Option<String>,
    pub verification_disposition: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolInvocation {
    pub assistant_message: Value,
    pub tool_call: Value,
    pub call_id: String,
    pub arguments: ModelToolArguments,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptFault {
    pub kind: &'static str,
    pub detail: String,
}

impl TranscriptFault {
    #[must_use]
    pub fn new(kind: &'static str, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: truncate(&detail.into(), MAX_PROVIDER_FAULT_CHARACTERS),
        }
    }
}

impl std::fmt::Display for TranscriptFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for TranscriptFault {}

#[must_use]
pub fn first_request(model: &str, fixture_id: &str) -> Value {
    json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You are executing a controlled lifecycle-validation tool test. Call cantor_validate_lifecycle exactly once. Copy the declared fixture_id and operation exactly. Do not invent a request body, signature, trust record, receipt, handle, lifecycle result, or authority claim. Wait for the tool result."
            },
            {
                "role": "user",
                "content": format!(
                    "Validate governed lifecycle source identity \"{fixture_id}\" with operation \"{MODEL_OPERATION}\"."
                )
            }
        ],
        "tools": [model_tool_schema(fixture_id)],
        "tool_choice": "required",
        "parallel_tool_calls": false,
        "temperature": 0,
        "max_tokens": 128
    })
}

#[must_use]
pub fn model_tool_schema(fixture_id: &str) -> Value {
    json!({
        "type": "function",
        "function": {
            "name": MODEL_TOOL_NAME,
            "description": "Request host-owned validation of one named governed native lifecycle fixture. The host, not the model, supplies proof-bearing request bytes.",
            "parameters": {
                "type": "object",
                "additionalProperties": false,
                "required": ["fixture_id", "operation"],
                "properties": {
                    "fixture_id": {"type": "string", "const": fixture_id},
                    "operation": {"type": "string", "const": MODEL_OPERATION}
                }
            }
        }
    })
}

pub fn extract_tool_invocation(
    response: &Value,
    expected_fixture_id: &str,
) -> Result<ToolInvocation, TranscriptFault> {
    let message = response
        .pointer("/choices/0/message")
        .ok_or_else(|| TranscriptFault::new("provider_fault", "missing choices[0].message"))?;
    let calls = message
        .get("tool_calls")
        .and_then(Value::as_array)
        .ok_or_else(|| TranscriptFault::new("tool_not_called", "missing tool_calls array"))?;
    if calls.len() != 1 {
        return Err(TranscriptFault::new(
            "tool_cardinality_fault",
            format!("expected exactly one call, received {}", calls.len()),
        ));
    }
    let call = &calls[0];
    let name = call
        .pointer("/function/name")
        .and_then(Value::as_str)
        .ok_or_else(|| TranscriptFault::new("wrong_tool", "missing function name"))?;
    if name != MODEL_TOOL_NAME {
        return Err(TranscriptFault::new(
            "wrong_tool",
            format!("expected {MODEL_TOOL_NAME}, received {name}"),
        ));
    }
    let call_id = call
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| TranscriptFault::new("call_id_fault", "missing tool call id"))?;
    if call_id.is_empty() || call_id.chars().count() > MAX_TOOL_CALL_ID_CHARACTERS {
        return Err(TranscriptFault::new(
            "call_id_fault",
            format!(
                "invalid tool call id character count: {}",
                call_id.chars().count()
            ),
        ));
    }
    let raw_arguments = call
        .pointer("/function/arguments")
        .ok_or_else(|| TranscriptFault::new("argument_fault", "missing function arguments"))?;
    let argument_value = match raw_arguments {
        Value::String(encoded) => {
            if encoded.len() > MAX_MODEL_ARGUMENT_BYTES {
                return Err(TranscriptFault::new(
                    "argument_bound_fault",
                    format!("encoded arguments contain {} bytes", encoded.len()),
                ));
            }
            serde_json::from_str(encoded).map_err(|error| {
                TranscriptFault::new("argument_fault", format!("invalid argument JSON: {error}"))
            })?
        }
        Value::Object(_) => {
            let bytes = serde_json::to_vec(raw_arguments).map_err(|error| {
                TranscriptFault::new(
                    "argument_fault",
                    format!("cannot encode arguments: {error}"),
                )
            })?;
            if bytes.len() > MAX_MODEL_ARGUMENT_BYTES {
                return Err(TranscriptFault::new(
                    "argument_bound_fault",
                    format!("arguments contain {} bytes", bytes.len()),
                ));
            }
            raw_arguments.clone()
        }
        _ => {
            return Err(TranscriptFault::new(
                "argument_fault",
                "arguments must be an object or an encoded object",
            ));
        }
    };
    let arguments: ModelToolArguments =
        serde_json::from_value(argument_value).map_err(|error| {
            TranscriptFault::new(
                "argument_fault",
                format!("arguments violate the closed contract: {error}"),
            )
        })?;
    let expected = ModelToolArguments {
        fixture_id: expected_fixture_id.to_owned(),
        operation: MODEL_OPERATION.to_owned(),
    };
    if arguments != expected {
        return Err(TranscriptFault::new(
            "argument_fault",
            format!("expected {expected:?}, received {arguments:?}"),
        ));
    }
    let assistant_message = json!({
        "role": "assistant",
        "content": message.get("content").cloned().unwrap_or(Value::Null),
        "tool_calls": [call.clone()]
    });
    Ok(ToolInvocation {
        assistant_message,
        tool_call: call.clone(),
        call_id: call_id.to_owned(),
        arguments,
    })
}

pub fn lifecycle_projection(
    fixture: &GovernedLifecycleFixture,
    response: &NativeLifecycleValidationResponse,
) -> Result<LifecycleProjection, TranscriptFault> {
    if response != &fixture.direct_response {
        return Err(TranscriptFault::new(
            "semantic_mismatch",
            "bridge response differs from governed direct response",
        ));
    }
    let value = serde_json::to_value(response).map_err(|error| {
        TranscriptFault::new(
            "projection_fault",
            format!("cannot project lifecycle response: {error}"),
        )
    })?;
    Ok(LifecycleProjection {
        source_identity: fixture.fixture_id.to_owned(),
        operation: optional_string(&value, "operation")?,
        lifecycle_outcome: required_string(&value, "outcome")?,
        deepest_valid_stage: optional_string(&value, "deepest_valid_stage")?,
        verification_disposition: optional_string(&value, "verification_disposition")?,
    })
}

pub fn second_request(
    model: &str,
    fixture_id: &str,
    invocation: &ToolInvocation,
    supplied_call_id: &str,
    projection: &LifecycleProjection,
) -> Result<Value, TranscriptFault> {
    if supplied_call_id != invocation.call_id {
        return Err(TranscriptFault::new(
            "tool_call_id_mismatch",
            format!(
                "originating call id {:?} differs from supplied id {:?}",
                invocation.call_id, supplied_call_id
            ),
        ));
    }
    Ok(json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You are completing checkpoint two of a controlled lifecycle-validation tool test. Import the tool result without reinterpretation. Return exactly the five declared fields. Do not call a tool, add a field, infer authority, or change a null value."
            },
            {
                "role": "user",
                "content": format!(
                    "Validate governed lifecycle source identity \"{fixture_id}\" with operation \"{MODEL_OPERATION}\"."
                )
            },
            invocation.assistant_message.clone(),
            {
                "role": "tool",
                "tool_call_id": supplied_call_id,
                "content": serde_json::to_string(projection).expect("projection serialization")
            },
            {
                "role": "user",
                "content": "Checkpoint 2: import the preceding lifecycle result exactly as source_identity, operation, lifecycle_outcome, deepest_valid_stage, and verification_disposition."
            }
        ],
        "tools": [model_tool_schema(fixture_id)],
        "tool_choice": "none",
        "parallel_tool_calls": false,
        "response_format": {
            "type": "json_schema",
            "schema": projection_schema(projection)
        },
        "temperature": 0,
        "max_tokens": 256
    }))
}

#[must_use]
pub fn projection_schema(expected: &LifecycleProjection) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "source_identity",
            "operation",
            "lifecycle_outcome",
            "deepest_valid_stage",
            "verification_disposition"
        ],
        "properties": {
            "source_identity": const_schema(&expected.source_identity),
            "operation": optional_const_schema(expected.operation.as_deref()),
            "lifecycle_outcome": const_schema(&expected.lifecycle_outcome),
            "deepest_valid_stage": optional_const_schema(expected.deepest_valid_stage.as_deref()),
            "verification_disposition": optional_const_schema(expected.verification_disposition.as_deref())
        }
    })
}

pub fn extract_imported_projection(
    response: &Value,
    expected: &LifecycleProjection,
) -> Result<LifecycleProjection, TranscriptFault> {
    let message = response
        .pointer("/choices/0/message")
        .ok_or_else(|| TranscriptFault::new("provider_fault", "missing choices[0].message"))?;
    if message
        .get("tool_calls")
        .and_then(Value::as_array)
        .is_some_and(|calls| !calls.is_empty())
    {
        return Err(TranscriptFault::new(
            "tool_loop_fault",
            "checkpoint two emitted a tool call",
        ));
    }
    let content = message
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| TranscriptFault::new("projection_fault", "missing text content"))?;
    let imported: LifecycleProjection = serde_json::from_str(content).map_err(|error| {
        TranscriptFault::new(
            "projection_fault",
            format!("invalid closed projection JSON: {error}"),
        )
    })?;
    if &imported != expected {
        return Err(TranscriptFault::new(
            "projection_mismatch",
            format!("expected {expected:?}, received {imported:?}"),
        ));
    }
    Ok(imported)
}

#[must_use]
pub fn sanitize_response(response: &Value) -> Value {
    match response {
        Value::Object(object) => {
            let mut sanitized = Map::new();
            for (key, value) in object {
                if matches!(
                    key.as_str(),
                    "reasoning" | "reasoning_content" | "thinking" | "thinking_content"
                ) {
                    continue;
                }
                sanitized.insert(key.clone(), sanitize_response(value));
            }
            Value::Object(sanitized)
        }
        Value::Array(items) => Value::Array(items.iter().map(sanitize_response).collect()),
        other => other.clone(),
    }
}

fn required_string(value: &Value, field: &str) -> Result<String, TranscriptFault> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| TranscriptFault::new("projection_fault", format!("{field} is not a string")))
}

fn optional_string(value: &Value, field: &str) -> Result<Option<String>, TranscriptFault> {
    match value.get(field) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        _ => Err(TranscriptFault::new(
            "projection_fault",
            format!("{field} is neither string nor null"),
        )),
    }
}

fn const_schema(value: &str) -> Value {
    json!({"type": "string", "const": value})
}

fn optional_const_schema(value: Option<&str>) -> Value {
    match value {
        Some(value) => const_schema(value),
        None => json!({"type": "null", "const": null}),
    }
}

fn truncate(value: &str, maximum_characters: usize) -> String {
    value.chars().take(maximum_characters).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cantor_lifecycle_tool_loop::LifecycleFixtureCase;

    fn invocation_response(_fixture_id: &str, arguments: Value) -> Value {
        json!({
            "choices": [{
                "message": {
                    "content": "",
                    "tool_calls": [{
                        "id": "call-governed-1",
                        "type": "function",
                        "function": {
                            "name": MODEL_TOOL_NAME,
                            "arguments": arguments.to_string()
                        }
                    }]
                }
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        })
    }

    #[test]
    fn first_checkpoint_contract_is_closed_and_parallel_calls_are_disabled() {
        let fixture = GovernedLifecycleFixture::load(LifecycleFixtureCase::Valid).unwrap();
        let request = first_request("model", fixture.fixture_id);
        assert_eq!(request["tool_choice"], "required");
        assert_eq!(request["parallel_tool_calls"], false);
        assert_eq!(
            request["tools"][0]["function"]["parameters"]["additionalProperties"],
            false
        );
        assert_eq!(
            request["tools"][0]["function"]["parameters"]["properties"]["fixture_id"]["const"],
            fixture.fixture_id
        );
    }

    #[test]
    fn exact_call_projects_and_imports_both_governed_outcomes() {
        for case in [
            LifecycleFixtureCase::Valid,
            LifecycleFixtureCase::LifecycleRefused,
        ] {
            let fixture = GovernedLifecycleFixture::load(case).unwrap();
            let response = invocation_response(
                fixture.fixture_id,
                json!({"fixture_id": fixture.fixture_id, "operation": MODEL_OPERATION}),
            );
            let invocation = extract_tool_invocation(&response, fixture.fixture_id).unwrap();
            let projection = lifecycle_projection(&fixture, &fixture.direct_response).unwrap();
            let second = second_request(
                "model",
                fixture.fixture_id,
                &invocation,
                &invocation.call_id,
                &projection,
            )
            .unwrap();
            assert_eq!(second["tool_choice"], "none");
            assert_eq!(second["messages"][3]["tool_call_id"], invocation.call_id);
            let imported_response = json!({
                "choices": [{"message": {
                    "content": serde_json::to_string(&projection).unwrap()
                }}]
            });
            assert_eq!(
                extract_imported_projection(&imported_response, &projection).unwrap(),
                projection
            );
        }
    }

    #[test]
    fn malformed_unknown_duplicate_and_substituted_calls_refuse() {
        let fixture = GovernedLifecycleFixture::load(LifecycleFixtureCase::Valid).unwrap();
        for arguments in [
            json!({"fixture_id": fixture.fixture_id}),
            json!({"fixture_id": fixture.fixture_id, "operation": MODEL_OPERATION, "extra": true}),
            json!({"fixture_id": "substituted", "operation": MODEL_OPERATION}),
            json!({"fixture_id": fixture.fixture_id, "operation": "install"}),
        ] {
            assert!(
                extract_tool_invocation(
                    &invocation_response(fixture.fixture_id, arguments),
                    fixture.fixture_id
                )
                .is_err()
            );
        }
        let mut duplicate = invocation_response(
            fixture.fixture_id,
            json!({"fixture_id": fixture.fixture_id, "operation": MODEL_OPERATION}),
        );
        let call = duplicate["choices"][0]["message"]["tool_calls"][0].clone();
        duplicate["choices"][0]["message"]["tool_calls"] = json!([call.clone(), call]);
        assert!(extract_tool_invocation(&duplicate, fixture.fixture_id).is_err());
    }

    #[test]
    fn mismatched_call_id_and_projection_changes_refuse() {
        let fixture = GovernedLifecycleFixture::load(LifecycleFixtureCase::Valid).unwrap();
        let response = invocation_response(
            fixture.fixture_id,
            json!({"fixture_id": fixture.fixture_id, "operation": MODEL_OPERATION}),
        );
        let invocation = extract_tool_invocation(&response, fixture.fixture_id).unwrap();
        let projection = lifecycle_projection(&fixture, &fixture.direct_response).unwrap();
        assert!(
            second_request(
                "model",
                fixture.fixture_id,
                &invocation,
                "substituted-call-id",
                &projection
            )
            .is_err()
        );
        let changed = json!({
            "choices": [{"message": {
                "content": serde_json::to_string(&json!({
                    "source_identity": projection.source_identity,
                    "operation": projection.operation,
                    "lifecycle_outcome": "artifact_valid",
                    "deepest_valid_stage": projection.deepest_valid_stage,
                    "verification_disposition": projection.verification_disposition,
                    "authority": "invented"
                })).unwrap()
            }}]
        });
        assert!(extract_imported_projection(&changed, &projection).is_err());
    }

    #[test]
    fn private_reasoning_fields_are_recursively_removed() {
        let sanitized = sanitize_response(&json!({
            "reasoning": "secret",
            "choices": [{"message": {"thinking_content": "private", "content": "public"}}]
        }));
        assert!(sanitized.get("reasoning").is_none());
        assert!(
            sanitized["choices"][0]["message"]
                .get("thinking_content")
                .is_none()
        );
        assert_eq!(sanitized["choices"][0]["message"]["content"], "public");
    }
}
