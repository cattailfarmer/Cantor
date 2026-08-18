//! Pure contracts for the experimental Cantor two-pass reflection loop.

#![forbid(unsafe_code)]

use std::collections::HashSet;

use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

pub const TRACE_PROFILE: &str = "cantor-reflection-loop-trace/0.1";
pub const REPORT_PROFILE: &str = "cantor-reflection-loop-report/0.2";
pub const POSITIVE_SUMMARY: &str =
    "Cantor returned an evidence-backed learned route, and its attention frame was applied.";
pub const REFUSAL_SUMMARY: &str =
    "Cantor returned a verified refusal, and no attention frame was applied.";
pub const CONTROL_SUMMARY: &str = "No Cantor tool was available or applied in this control.";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaseKind {
    Positive,
    Refusal,
    Control,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FlowState {
    Created,
    FirstInferenceRequested,
    ToolCallReceived,
    ToolCallValidated,
    ToolResultReceived,
    ReflectionRequested,
    FinalReceived,
    Completed,
    Failed,
    ControlCompleted,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct CaseDefinition {
    pub case_id: &'static str,
    pub kind: CaseKind,
    pub stimulus: &'static str,
}

pub const POSITIVE_CASE: CaseDefinition = CaseDefinition {
    case_id: "positive_cantor_route",
    kind: CaseKind::Positive,
    stimulus: "What is Cantor?",
};

pub const REFUSAL_CASE: CaseDefinition = CaseDefinition {
    case_id: "refusal_unsupported_weaver_route",
    kind: CaseKind::Refusal,
    stimulus: "Weaver",
};

pub const CONTROL_CASE: CaseDefinition = CaseDefinition {
    case_id: "control_without_cantor",
    kind: CaseKind::Control,
    stimulus: "Return a short statement that this is the no-tool control case.",
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RouteArguments {
    pub stimulus: String,
    pub response_mode: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedToolCall {
    pub assistant_message: Value,
    pub call: Value,
    pub call_id: String,
    pub arguments: RouteArguments,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinalOutput {
    pub case_id: String,
    pub observed_tool_status: String,
    pub applied_attention: bool,
    pub summary: String,
    pub evidence_reference: String,
    pub procedure_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ToolObservation {
    pub observed_tool_status: String,
    pub applied_attention: bool,
    pub evidence_reference: String,
    pub procedure_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FlowEvent {
    pub sequence: usize,
    pub state: FlowState,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReportVerification {
    pub profile: &'static str,
    pub status: &'static str,
    pub case_count: usize,
    pub routed_case_count: usize,
    pub control_case_count: usize,
    pub private_reasoning_absent: bool,
    pub evidence_links_verified: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReportInspection {
    pub profile: &'static str,
    pub status: &'static str,
    pub model: String,
    pub runner_sha256: Option<String>,
    pub authority: &'static str,
    pub cases: Vec<CaseInspection>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CaseInspection {
    pub case_id: String,
    pub final_state: String,
    pub states: Vec<String>,
    pub observed_tool_status: String,
    pub applied_attention: bool,
    pub procedure_id: Option<String>,
    pub evidence_reference: String,
    pub summary: String,
    pub elapsed_ms: u64,
    pub first_completion_tokens: Option<u64>,
    pub reflection_completion_tokens: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReflectionLoopContract {
    pub profile: &'static str,
    pub report_profile: &'static str,
    pub trace_profile: &'static str,
    pub authority: &'static str,
    pub tool_name: &'static str,
    pub model_selection: &'static str,
    pub campaign: &'static str,
    pub max_tool_calls_per_routed_case: usize,
    pub provider_passes_per_routed_case: usize,
    pub provider_passes_per_control_case: usize,
    pub cases: Vec<ContractCase>,
    pub routed_state_path: Vec<FlowState>,
    pub control_state_path: Vec<FlowState>,
    pub excluded_private_fields: Vec<&'static str>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ContractCase {
    pub case_id: &'static str,
    pub kind: CaseKind,
    pub stimulus: &'static str,
    pub final_summary: &'static str,
}

pub fn contract() -> ReflectionLoopContract {
    ReflectionLoopContract {
        profile: "cantor-reflection-loop-contract/0.1",
        report_profile: REPORT_PROFILE,
        trace_profile: TRACE_PROFILE,
        authority: "experimental_evidence_not_signed_SOP_authority",
        tool_name: cantor_attention_mcp::TOOL_NAME,
        model_selection: "sole_advertised_model",
        campaign: "mandatory_positive_refusal_control",
        max_tool_calls_per_routed_case: 1,
        provider_passes_per_routed_case: 2,
        provider_passes_per_control_case: 1,
        cases: vec![
            contract_case(&POSITIVE_CASE),
            contract_case(&REFUSAL_CASE),
            contract_case(&CONTROL_CASE),
        ],
        routed_state_path: vec![
            FlowState::Created,
            FlowState::FirstInferenceRequested,
            FlowState::ToolCallReceived,
            FlowState::ToolCallValidated,
            FlowState::ToolResultReceived,
            FlowState::ReflectionRequested,
            FlowState::FinalReceived,
            FlowState::Completed,
        ],
        control_state_path: vec![
            FlowState::Created,
            FlowState::FirstInferenceRequested,
            FlowState::FinalReceived,
            FlowState::ControlCompleted,
        ],
        excluded_private_fields: vec![
            "reasoning",
            "reasoning_content",
            "thinking",
            "thinking_content",
        ],
    }
}

fn contract_case(case: &CaseDefinition) -> ContractCase {
    ContractCase {
        case_id: case.case_id,
        kind: case.kind,
        stimulus: case.stimulus,
        final_summary: expected_summary(case),
    }
}

pub fn routed_cases() -> [CaseDefinition; 2] {
    [POSITIVE_CASE, REFUSAL_CASE]
}

pub fn first_request(model: &str, case: &CaseDefinition) -> Value {
    assert!(case.kind != CaseKind::Control);
    json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "This is a controlled externalized attention checkpoint. Call route_attention exactly once with the exact arguments constrained by its schema. Do not answer the subject directly. The host will validate the call, execute Cantor, and return evidence for a separate reflection pass."
            },
            {
                "role": "user",
                "content": format!(
                    "Call route_attention for the exact stimulus {:?} using response_mode \"frame\".",
                    case.stimulus
                )
            }
        ],
        "tools": [route_attention_schema(case.stimulus)],
        "tool_choice": "required",
        "parallel_tool_calls": false,
        "chat_template_kwargs": {"enable_thinking": false},
        "temperature": 0,
        "max_tokens": 384
    })
}

pub fn control_request(model: &str) -> Value {
    json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "This is a controlled no-tool baseline. No Cantor tool is available. Return only the required JSON object and do not imply that attention routing occurred."
            },
            {
                "role": "user",
                "content": CONTROL_CASE.stimulus
            }
        ],
        "response_format": {
            "type": "json_object",
            "schema": final_schema(
                CONTROL_CASE.case_id,
                "no_tool_control",
                false,
                "none",
                None,
                CONTROL_SUMMARY
            )
        },
        "chat_template_kwargs": {"enable_thinking": false},
        "temperature": 0,
        "max_tokens": 384
    })
}

pub fn extract_tool_call(
    response: &Value,
    case: &CaseDefinition,
) -> Result<ParsedToolCall, String> {
    if case.kind == CaseKind::Control {
        return Err("control case cannot admit a tool call".to_owned());
    }
    let choice = single_choice(response)?;
    if choice.get("finish_reason").and_then(Value::as_str) != Some("tool_calls") {
        return Err("required first pass did not finish with tool_calls".to_owned());
    }
    let message = choice
        .get("message")
        .ok_or("provider response omitted choices[0].message")?;
    require_assistant_message(message)?;
    if message
        .get("content")
        .is_some_and(|content| !content.is_null() && content.as_str() != Some(""))
    {
        return Err("tool-call pass mixed public answer content with the call".to_owned());
    }
    let calls = message
        .get("tool_calls")
        .and_then(Value::as_array)
        .ok_or("required first pass emitted no tool_calls array")?;
    if calls.len() != 1 {
        return Err(format!(
            "expected exactly one tool call, observed {}",
            calls.len()
        ));
    }
    let call = &calls[0];
    let name = call
        .pointer("/function/name")
        .and_then(Value::as_str)
        .ok_or("tool call omitted function name")?;
    if name != cantor_attention_mcp::TOOL_NAME {
        return Err(format!("wrong tool: {name}"));
    }
    let call_id = call
        .get("id")
        .and_then(Value::as_str)
        .ok_or("tool call omitted id")?
        .to_owned();
    let encoded = call
        .pointer("/function/arguments")
        .ok_or("tool call omitted arguments")?;
    let argument_value = match encoded {
        Value::String(value) => serde_json::from_str(value)
            .map_err(|error| format!("tool arguments are not JSON: {error}"))?,
        Value::Object(_) => encoded.clone(),
        _ => return Err("tool arguments are neither an object nor encoded object".to_owned()),
    };
    let arguments: RouteArguments = serde_json::from_value(argument_value)
        .map_err(|error| format!("tool arguments violate the closed schema: {error}"))?;
    let expected = RouteArguments {
        stimulus: case.stimulus.to_owned(),
        response_mode: "frame".to_owned(),
    };
    if arguments != expected {
        return Err(format!(
            "tool arguments changed the case: expected {expected:?}, observed {arguments:?}"
        ));
    }
    Ok(ParsedToolCall {
        assistant_message: json!({
            "role": "assistant",
            "content": message.get("content").cloned().unwrap_or(Value::Null),
            "tool_calls": [call.clone()]
        }),
        call: call.clone(),
        call_id,
        arguments,
    })
}

pub fn admit_tool_result(
    structured: &Value,
    case: &CaseDefinition,
) -> Result<ToolObservation, String> {
    match case.kind {
        CaseKind::Positive => admit_positive(structured),
        CaseKind::Refusal => admit_refusal(structured),
        CaseKind::Control => Err("control case cannot admit a tool result".to_owned()),
    }
}

pub fn reflection_request(
    model: &str,
    case: &CaseDefinition,
    call: &ParsedToolCall,
    structured: &Value,
    observation: &ToolObservation,
) -> Value {
    let instruction = if case.kind == CaseKind::Positive {
        "Read the supplied route_attention result as a learned, evidence-backed attention proposal, not signed SOP authority. State what route was observed and whether its attention frame was applied in this response."
    } else {
        "Read the supplied route_attention refusal. Preserve the refusal explicitly, do not invent a route, and state that no attention frame was applied."
    };
    json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": format!("This is checkpoint two of a controlled reflection loop. {instruction} Return only the required JSON object. Do not call a tool again.")
            },
            {
                "role": "user",
                "content": case.stimulus
            },
            call.assistant_message,
            {
                "role": "tool",
                "tool_call_id": call.call_id,
                "content": serde_json::to_string(structured)
                    .expect("a serde_json::Value always serializes")
            },
            {
                "role": "user",
                "content": "Reflection checkpoint: import the preceding structured Cantor result now. Keep its authority boundary and fault status exact."
            }
        ],
        "tools": [route_attention_schema(case.stimulus)],
        "tool_choice": "none",
        "parallel_tool_calls": false,
        "response_format": {
            "type": "json_object",
            "schema": final_schema(
                case.case_id,
                &observation.observed_tool_status,
                observation.applied_attention,
                &observation.evidence_reference,
                observation.procedure_id.as_deref(),
                expected_summary(case)
            )
        },
        "chat_template_kwargs": {"enable_thinking": false},
        "temperature": 0,
        "max_tokens": 512
    })
}

pub fn extract_final_output(
    response: &Value,
    case: &CaseDefinition,
    observation: &ToolObservation,
) -> Result<FinalOutput, String> {
    let choice = single_choice(response)?;
    if choice.get("finish_reason").and_then(Value::as_str) != Some("stop") {
        return Err("final response did not finish cleanly".to_owned());
    }
    let message = choice
        .get("message")
        .ok_or("final response omitted choices[0].message")?;
    require_assistant_message(message)?;
    if message
        .get("tool_calls")
        .and_then(Value::as_array)
        .is_some_and(|calls| !calls.is_empty())
    {
        return Err("final pass attempted another tool call".to_owned());
    }
    let content = message
        .get("content")
        .and_then(Value::as_str)
        .ok_or("final response omitted text content")?;
    let output: FinalOutput = serde_json::from_str(content)
        .map_err(|error| format!("final content violates JSON syntax or schema: {error}"))?;
    let expected_case = case.case_id;
    if output.case_id != expected_case
        || output.observed_tool_status != observation.observed_tool_status
        || output.applied_attention != observation.applied_attention
        || output.evidence_reference != observation.evidence_reference
        || output.procedure_id != observation.procedure_id
        || output.summary != expected_summary(case)
    {
        return Err(format!(
            "final output changed admitted evidence: expected case={} observation={observation:?}, observed={output:?}",
            expected_case
        ));
    }
    Ok(output)
}

pub fn extract_control_output(response: &Value) -> Result<FinalOutput, String> {
    let observation = ToolObservation {
        observed_tool_status: "no_tool_control".to_owned(),
        applied_attention: false,
        evidence_reference: "none".to_owned(),
        procedure_id: None,
    };
    extract_final_output(response, &CONTROL_CASE, &observation)
}

pub fn sanitize(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut result = Map::new();
            for (key, item) in object {
                if matches!(
                    key.as_str(),
                    "reasoning" | "reasoning_content" | "thinking" | "thinking_content"
                ) {
                    continue;
                }
                result.insert(key.clone(), sanitize(item));
            }
            Value::Object(result)
        }
        Value::Array(items) => Value::Array(items.iter().map(sanitize).collect()),
        scalar => scalar.clone(),
    }
}

pub fn verify_report(report: &Value) -> Result<ReportVerification, String> {
    require_string(report, "/profile", REPORT_PROFILE)?;
    require_string(
        report,
        "/contract",
        "Cantor_Prototype_Graduation_And_Reflection_Loop_P0.sop",
    )?;
    require_string(report, "/status", "passed")?;
    verify_loopback_url(report)?;
    let started = report
        .get("started_unix_ms")
        .and_then(Value::as_u64)
        .ok_or("report omitted integer started_unix_ms")?;
    let finished = report
        .get("finished_unix_ms")
        .and_then(Value::as_u64)
        .ok_or("report omitted integer finished_unix_ms")?;
    if finished < started || finished - started > 600_000 {
        return Err("report timestamps are reversed or outside the P0 time bound".to_owned());
    }
    if report
        .get("private_reasoning_recorded")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err("report does not explicitly exclude private reasoning".to_owned());
    }
    reject_private_reasoning_keys(report, "$")?;
    for pointer in ["/model", "/mcp_program", "/mcp_config"] {
        let value = report
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("report omitted string {pointer}"))?;
        if value.trim().is_empty() {
            return Err(format!("report field {pointer} is empty"));
        }
    }
    for pointer in ["/mcp_program_sha256", "/mcp_config_sha256"] {
        let value = report
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("report omitted digest {pointer}"))?;
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("report field {pointer} is not SHA-256"));
        }
    }
    if report
        .get("dependency_identity_stable")
        .and_then(Value::as_bool)
        != Some(true)
        || report.get("mcp_program_sha256") != report.get("mcp_program_sha256_after")
        || report.get("mcp_config_sha256") != report.get("mcp_config_sha256_after")
    {
        return Err("dependency identity is absent or changed during the run".to_owned());
    }
    let runner = report
        .pointer("/runner")
        .and_then(Value::as_str)
        .ok_or("hardened report omitted /runner")?;
    if runner.trim().is_empty() {
        return Err("hardened report field /runner is empty".to_owned());
    }
    for pointer in [
        "/mcp_program_sha256_after",
        "/mcp_config_sha256_after",
        "/runner_sha256",
    ] {
        let value = report
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("hardened report omitted digest {pointer}"))?;
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("hardened report field {pointer} is not SHA-256"));
        }
    }
    let cases = report
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("report omitted cases array")?;
    if cases.len() != 3 {
        return Err(format!(
            "expected exactly three cases, observed {}",
            cases.len()
        ));
    }
    let observed_order = cases
        .iter()
        .filter_map(|case| case.get("case_id").and_then(Value::as_str))
        .collect::<Vec<_>>();
    if observed_order
        != [
            POSITIVE_CASE.case_id,
            REFUSAL_CASE.case_id,
            CONTROL_CASE.case_id,
        ]
    {
        return Err("case order or identity changed".to_owned());
    }
    let positive = unique_case(cases, POSITIVE_CASE.case_id)?;
    let refusal = unique_case(cases, REFUSAL_CASE.case_id)?;
    let control = unique_case(cases, CONTROL_CASE.case_id)?;
    let mut trace_ids = HashSet::new();
    for (case, definition) in [
        (positive, &POSITIVE_CASE),
        (refusal, &REFUSAL_CASE),
        (control, &CONTROL_CASE),
    ] {
        verify_case_envelope(case, definition, finished - started)?;
        let trace_id = case
            .get("trace_id")
            .and_then(Value::as_str)
            .ok_or("case omitted trace_id")?;
        if !trace_ids.insert(trace_id) {
            return Err("case trace identities are not unique".to_owned());
        }
    }
    verify_event_order(
        positive,
        &[
            "created",
            "first_inference_requested",
            "tool_call_received",
            "tool_call_validated",
            "tool_result_received",
            "reflection_requested",
            "final_received",
            "completed",
        ],
    )?;
    verify_event_order(
        refusal,
        &[
            "created",
            "first_inference_requested",
            "tool_call_received",
            "tool_call_validated",
            "tool_result_received",
            "reflection_requested",
            "final_received",
            "completed",
        ],
    )?;
    verify_event_order(
        control,
        &[
            "created",
            "first_inference_requested",
            "final_received",
            "control_completed",
        ],
    )?;
    let model = report
        .get("model")
        .and_then(Value::as_str)
        .ok_or("report omitted model")?;
    verify_routed_common(positive, &POSITIVE_CASE, model)?;
    verify_routed_common(refusal, &REFUSAL_CASE, model)?;
    verify_control(control, model)?;
    verify_positive_link(positive)?;
    verify_refusal_link(refusal)?;
    Ok(ReportVerification {
        profile: "cantor-reflection-loop-verification/0.2",
        status: "verified",
        case_count: 3,
        routed_case_count: 2,
        control_case_count: 1,
        private_reasoning_absent: true,
        evidence_links_verified: 2,
    })
}

fn verify_loopback_url(report: &Value) -> Result<(), String> {
    let candidate = report
        .get("base_url")
        .and_then(Value::as_str)
        .ok_or("report omitted base_url")?;
    let parsed = Url::parse(candidate).map_err(|error| format!("invalid base_url: {error}"))?;
    let loopback = matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if parsed.scheme() != "http"
        || !loopback
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path().trim_end_matches('/') != "/v1"
    {
        return Err("report base_url is outside the loopback HTTP /v1 boundary".to_owned());
    }
    Ok(())
}

fn verify_case_envelope(
    case: &Value,
    definition: &CaseDefinition,
    report_elapsed_ms: u64,
) -> Result<(), String> {
    require_string(case, "/profile", TRACE_PROFILE)?;
    require_string(case, "/case_id", definition.case_id)?;
    if case.get("fault").is_none_or(|fault| !fault.is_null()) {
        return Err(format!(
            "passed case {} contains a fault",
            definition.case_id
        ));
    }
    let elapsed = case
        .get("elapsed_ms")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("case {} omitted elapsed_ms", definition.case_id))?;
    if elapsed == 0 || elapsed > report_elapsed_ms.saturating_add(1_000) {
        return Err(format!(
            "case {} elapsed time is outside the report envelope",
            definition.case_id
        ));
    }
    let trace_id = case
        .get("trace_id")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("case {} omitted trace_id", definition.case_id))?;
    if !trace_id.strip_prefix("trace-").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    }) {
        return Err(format!(
            "case {} has malformed trace_id",
            definition.case_id
        ));
    }
    Ok(())
}

pub fn inspect_report(report: &Value) -> Result<ReportInspection, String> {
    verify_report(report)?;
    let model = report
        .get("model")
        .and_then(Value::as_str)
        .ok_or("verified report omitted model")?
        .to_owned();
    let runner_sha256 = report
        .get("runner_sha256")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let cases = report
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("verified report omitted cases")?
        .iter()
        .map(inspect_case)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ReportInspection {
        profile: "cantor-reflection-loop-inspection/0.2",
        status: "verified_trace_projection",
        model,
        runner_sha256,
        authority: "experimental_evidence_not_signed_SOP_authority",
        cases,
    })
}

fn admit_positive(structured: &Value) -> Result<ToolObservation, String> {
    if structured.get("status").and_then(Value::as_str) != Some("route_selected") {
        return Err("positive case did not return route_selected".to_owned());
    }
    if structured.get("profile").and_then(Value::as_str)
        != Some(cantor_attention_mcp::FRAME_RESULT_PROFILE)
        || structured.get("response_mode").and_then(Value::as_str) != Some("frame")
        || structured.get("authority").and_then(Value::as_str)
            != Some("learned_evidence_backed_proposal")
    {
        return Err("positive result crossed its profile or authority boundary".to_owned());
    }
    let frame = structured
        .get("attention_frame")
        .ok_or("positive result omitted attention_frame")?;
    let procedure_id = frame
        .pointer("/sequence/0/procedure_id")
        .and_then(Value::as_str)
        .ok_or("attention frame omitted procedure_id")?
        .to_owned();
    let evidence_reference = frame
        .pointer("/sequence/3/evidence_id")
        .and_then(Value::as_str)
        .ok_or("attention frame omitted evidence_id")?
        .to_owned();
    let sequence = frame
        .get("sequence")
        .and_then(Value::as_array)
        .ok_or("attention frame omitted sequence")?;
    if sequence.len() != 4 {
        return Err(format!(
            "attention frame requires four operators, observed {}",
            sequence.len()
        ));
    }
    let operators = sequence
        .iter()
        .map(|entry| {
            entry
                .get("operator")
                .and_then(Value::as_str)
                .ok_or("attention frame contains an operator-less entry")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if operators != ["FOCUS", "BOUND", "ADMIT", "RETURN"] {
        return Err(format!(
            "unexpected attention operator sequence: {operators:?}"
        ));
    }
    Ok(ToolObservation {
        observed_tool_status: "route_selected".to_owned(),
        applied_attention: true,
        evidence_reference,
        procedure_id: Some(procedure_id),
    })
}

fn admit_refusal(structured: &Value) -> Result<ToolObservation, String> {
    if structured.get("profile").and_then(Value::as_str)
        != Some(cantor_attention_mcp::ADAPTER_PROFILE)
        || structured.get("status").and_then(Value::as_str) != Some("fault")
        || structured.pointer("/fault/code").and_then(Value::as_str) != Some("runtime_refused")
        || structured
            .pointer("/verification/status")
            .and_then(Value::as_str)
            != Some("verified")
    {
        return Err("refusal case did not return runtime_refused".to_owned());
    }
    if structured.get("attention_frame").is_some() {
        return Err("refusal carried a positive attention_frame".to_owned());
    }
    let evidence_reference = structured
        .pointer("/verification/evidence_id")
        .and_then(Value::as_str)
        .ok_or("refusal omitted verified evidence_id")?
        .to_owned();
    Ok(ToolObservation {
        observed_tool_status: "runtime_refused".to_owned(),
        applied_attention: false,
        evidence_reference,
        procedure_id: None,
    })
}

fn route_attention_schema(stimulus: &str) -> Value {
    json!({
        "type": "function",
        "function": {
            "name": cantor_attention_mcp::TOOL_NAME,
            "description": "Propose one evidence-verified hardened attention route. The result is a learned proposal, not signed SOP authority.",
            "parameters": {
                "type": "object",
                "additionalProperties": false,
                "required": ["stimulus", "response_mode"],
                "properties": {
                    "stimulus": { "type": "string", "const": stimulus },
                    "response_mode": { "type": "string", "const": "frame" }
                }
            }
        }
    })
}

fn final_schema(
    case_id: &str,
    status: &str,
    applied: bool,
    evidence: &str,
    procedure_id: Option<&str>,
    summary: &str,
) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "case_id",
            "observed_tool_status",
            "applied_attention",
            "summary",
            "evidence_reference",
            "procedure_id"
        ],
        "properties": {
            "case_id": { "type": "string", "const": case_id },
            "observed_tool_status": { "type": "string", "const": status },
            "applied_attention": { "type": "boolean", "const": applied },
            "summary": { "type": "string", "const": summary },
            "evidence_reference": { "type": "string", "const": evidence },
            "procedure_id": match procedure_id {
                Some(value) => json!({ "type": "string", "const": value }),
                None => json!({ "type": "null" })
            }
        }
    })
}

fn expected_summary(case: &CaseDefinition) -> &'static str {
    match case.kind {
        CaseKind::Positive => POSITIVE_SUMMARY,
        CaseKind::Refusal => REFUSAL_SUMMARY,
        CaseKind::Control => CONTROL_SUMMARY,
    }
}

fn require_string(value: &Value, pointer: &str, expected: &str) -> Result<(), String> {
    match value.pointer(pointer).and_then(Value::as_str) {
        Some(observed) if observed == expected => Ok(()),
        observed => Err(format!(
            "expected {pointer}={expected:?}, observed {observed:?}"
        )),
    }
}

fn single_choice(response: &Value) -> Result<&Value, String> {
    let choices = response
        .get("choices")
        .and_then(Value::as_array)
        .ok_or("provider response omitted choices array")?;
    if choices.len() != 1 {
        return Err(format!(
            "expected exactly one provider choice, observed {}",
            choices.len()
        ));
    }
    Ok(&choices[0])
}

fn require_assistant_message(message: &Value) -> Result<(), String> {
    if message.get("role").and_then(Value::as_str) != Some("assistant") {
        return Err("provider choice did not contain an assistant message".to_owned());
    }
    Ok(())
}

fn reject_private_reasoning_keys(value: &Value, path: &str) -> Result<(), String> {
    match value {
        Value::Object(object) => {
            for (key, item) in object {
                if matches!(
                    key.as_str(),
                    "reasoning" | "reasoning_content" | "thinking" | "thinking_content"
                ) {
                    return Err(format!("private reasoning key present at {path}.{key}"));
                }
                reject_private_reasoning_keys(item, &format!("{path}.{key}"))?;
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                reject_private_reasoning_keys(item, &format!("{path}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn unique_case<'a>(cases: &'a [Value], case_id: &str) -> Result<&'a Value, String> {
    let matches: Vec<&Value> = cases
        .iter()
        .filter(|case| case.get("case_id").and_then(Value::as_str) == Some(case_id))
        .collect();
    if matches.len() != 1 {
        return Err(format!(
            "expected one {case_id} case, observed {}",
            matches.len()
        ));
    }
    Ok(matches[0])
}

fn verify_event_order(case: &Value, expected_states: &[&str]) -> Result<(), String> {
    let expected_final = expected_states
        .last()
        .copied()
        .ok_or("verification expected an empty state path")?;
    require_string(case, "/status", "passed")?;
    require_string(case, "/final_state", expected_final)?;
    let events = case
        .get("events")
        .and_then(Value::as_array)
        .ok_or("case omitted events array")?;
    if events.len() != expected_states.len() {
        return Err(format!(
            "expected {} flow events, observed {}",
            expected_states.len(),
            events.len()
        ));
    }
    for (index, event) in events.iter().enumerate() {
        if event.get("sequence").and_then(Value::as_u64) != Some(index as u64) {
            return Err(format!("event sequence is discontinuous at {index}"));
        }
        if event.get("state").and_then(Value::as_str) != Some(expected_states[index]) {
            return Err(format!(
                "event {index} changed state: expected {:?}, observed {:?}",
                expected_states[index],
                event.get("state")
            ));
        }
    }
    if events
        .last()
        .and_then(|event| event.get("state"))
        .and_then(Value::as_str)
        != Some(expected_final)
    {
        return Err("last event does not match final state".to_owned());
    }
    Ok(())
}

fn verify_routed_common(
    case: &Value,
    definition: &CaseDefinition,
    model: &str,
) -> Result<(), String> {
    let expected_kind = match definition.kind {
        CaseKind::Positive => "positive",
        CaseKind::Refusal => "refusal",
        CaseKind::Control => return Err("control is not a routed case".to_owned()),
    };
    require_string(case, "/expected_case_kind", expected_kind)?;
    for pointer in [
        "/first_request",
        "/first_response",
        "/tool_call",
        "/tool_result",
        "/reflection_request",
        "/reflection_response",
        "/final_output",
    ] {
        if case.pointer(pointer).is_none_or(Value::is_null) {
            return Err(format!("routed case omitted {pointer}"));
        }
    }
    if case.get("first_request") != Some(&first_request(model, definition)) {
        return Err("routed first request changed the governed request contract".to_owned());
    }
    let parsed_call = extract_tool_call(
        case.get("first_response")
            .ok_or("routed case omitted first_response")?,
        definition,
    )?;
    if case.get("tool_call") != Some(&parsed_call.call) {
        return Err("recorded tool call differs from the admitted provider call".to_owned());
    }
    let tool_result = case
        .get("tool_result")
        .ok_or("routed case omitted tool_result")?;
    let observation = admit_tool_result(tool_result, definition)?;
    let expected_reflection =
        reflection_request(model, definition, &parsed_call, tool_result, &observation);
    if case.get("reflection_request") != Some(&expected_reflection) {
        return Err("reflection request changed the admitted call or tool result".to_owned());
    }
    let extracted = extract_final_output(
        case.get("reflection_response")
            .ok_or("routed case omitted reflection_response")?,
        definition,
        &observation,
    )?;
    if case.get("final_output") != Some(&serde_json::to_value(extracted).unwrap()) {
        return Err("recorded final output differs from the verified model output".to_owned());
    }
    Ok(())
}

fn verify_control(case: &Value, model: &str) -> Result<(), String> {
    require_string(case, "/expected_case_kind", "control")?;
    require_string(
        case,
        "/final_output/observed_tool_status",
        "no_tool_control",
    )?;
    if case
        .pointer("/final_output/applied_attention")
        .and_then(Value::as_bool)
        != Some(false)
        || case
            .pointer("/final_output/evidence_reference")
            .and_then(Value::as_str)
            != Some("none")
        || case.pointer("/first_request/tools").is_some()
    {
        return Err("control case crossed the no-tool boundary".to_owned());
    }
    if case.get("first_request") != Some(&control_request(model)) {
        return Err("control request changed the governed no-tool contract".to_owned());
    }
    let extracted = extract_control_output(
        case.get("first_response")
            .ok_or("control case omitted first_response")?,
    )?;
    if case.get("final_output") != Some(&serde_json::to_value(extracted).unwrap()) {
        return Err("control final output differs from the verified model output".to_owned());
    }
    for pointer in [
        "/tool_call",
        "/tool_result",
        "/reflection_request",
        "/reflection_response",
    ] {
        if case.pointer(pointer).is_some_and(|value| !value.is_null()) {
            return Err(format!("control case unexpectedly populated {pointer}"));
        }
    }
    Ok(())
}

fn verify_positive_link(case: &Value) -> Result<(), String> {
    require_string(case, "/tool_result/status", "route_selected")?;
    require_string(case, "/final_output/observed_tool_status", "route_selected")?;
    if case
        .pointer("/final_output/applied_attention")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("positive final output did not apply the admitted frame".to_owned());
    }
    let evidence = case
        .pointer("/tool_result/attention_frame/sequence/3/evidence_id")
        .and_then(Value::as_str)
        .ok_or("positive tool result omitted evidence link")?;
    let procedure = case
        .pointer("/tool_result/attention_frame/sequence/0/procedure_id")
        .and_then(Value::as_str)
        .ok_or("positive tool result omitted procedure link")?;
    if case
        .pointer("/final_output/evidence_reference")
        .and_then(Value::as_str)
        != Some(evidence)
        || case
            .pointer("/final_output/procedure_id")
            .and_then(Value::as_str)
            != Some(procedure)
    {
        return Err("positive final output is not linked to the MCP frame".to_owned());
    }
    Ok(())
}

fn verify_refusal_link(case: &Value) -> Result<(), String> {
    require_string(case, "/tool_result/status", "fault")?;
    require_string(case, "/tool_result/fault/code", "runtime_refused")?;
    require_string(
        case,
        "/final_output/observed_tool_status",
        "runtime_refused",
    )?;
    if case.pointer("/tool_result/attention_frame").is_some()
        || case
            .pointer("/final_output/applied_attention")
            .and_then(Value::as_bool)
            != Some(false)
        || !case
            .pointer("/final_output/procedure_id")
            .is_some_and(Value::is_null)
    {
        return Err("refusal acquired positive attention state".to_owned());
    }
    let evidence = case
        .pointer("/tool_result/verification/evidence_id")
        .and_then(Value::as_str)
        .ok_or("refusal tool result omitted evidence link")?;
    if case
        .pointer("/final_output/evidence_reference")
        .and_then(Value::as_str)
        != Some(evidence)
    {
        return Err("refusal final output is not linked to refusal evidence".to_owned());
    }
    Ok(())
}

fn inspect_case(case: &Value) -> Result<CaseInspection, String> {
    let output = case
        .get("final_output")
        .ok_or("verified case omitted final_output")?;
    let strings = |pointer: &str| -> Result<String, String> {
        case.pointer(pointer)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("verified case omitted {pointer}"))
    };
    let states = case
        .get("events")
        .and_then(Value::as_array)
        .ok_or("verified case omitted events")?
        .iter()
        .map(|event| {
            event
                .get("state")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or("verified event omitted state".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CaseInspection {
        case_id: strings("/case_id")?,
        final_state: strings("/final_state")?,
        states,
        observed_tool_status: output
            .get("observed_tool_status")
            .and_then(Value::as_str)
            .ok_or("verified output omitted observed_tool_status")?
            .to_owned(),
        applied_attention: output
            .get("applied_attention")
            .and_then(Value::as_bool)
            .ok_or("verified output omitted applied_attention")?,
        procedure_id: output
            .get("procedure_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        evidence_reference: output
            .get("evidence_reference")
            .and_then(Value::as_str)
            .ok_or("verified output omitted evidence_reference")?
            .to_owned(),
        summary: output
            .get("summary")
            .and_then(Value::as_str)
            .ok_or("verified output omitted summary")?
            .to_owned(),
        elapsed_ms: case
            .get("elapsed_ms")
            .and_then(Value::as_u64)
            .ok_or("verified case omitted elapsed_ms")?,
        first_completion_tokens: case
            .pointer("/first_response/usage/completion_tokens")
            .and_then(Value::as_u64),
        reflection_completion_tokens: case
            .pointer("/reflection_response/usage/completion_tokens")
            .and_then(Value::as_u64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn positive_result() -> Value {
        json!({
            "profile": cantor_attention_mcp::FRAME_RESULT_PROFILE,
            "status": "route_selected",
            "response_mode": "frame",
            "authority": "learned_evidence_backed_proposal",
            "attention_frame": {
                "profile": cantor_attention_mcp::ATTENTION_FRAME_PROFILE,
                "sequence": [
                    {"operator": "FOCUS", "procedure_id": "attention.resolve_sop_subject"},
                    {"operator": "BOUND"},
                    {"operator": "ADMIT"},
                    {"operator": "RETURN", "evidence_id": "run-positive"}
                ]
            }
        })
    }

    fn refusal_result() -> Value {
        json!({
            "profile": cantor_attention_mcp::ADAPTER_PROFILE,
            "status": "fault",
            "fault": {"code": "runtime_refused", "message": "low_selection_confidence"},
            "verification": {"evidence_id": "run-refusal", "status": "verified"}
        })
    }

    fn tool_response(arguments: Value) -> Value {
        json!({
            "choices": [{
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": cantor_attention_mcp::TOOL_NAME,
                            "arguments": arguments.to_string()
                        }
                    }]
                }
            }]
        })
    }

    #[test]
    fn exact_call_is_admitted() {
        let parsed = extract_tool_call(
            &tool_response(json!({
                "stimulus": POSITIVE_CASE.stimulus,
                "response_mode": "frame"
            })),
            &POSITIVE_CASE,
        )
        .expect("exact call should pass");
        assert_eq!(parsed.arguments.stimulus, POSITIVE_CASE.stimulus);
    }

    #[test]
    fn changed_extra_and_multiple_calls_are_rejected() {
        assert!(
            extract_tool_call(
                &tool_response(json!({"stimulus": "changed", "response_mode": "frame"})),
                &POSITIVE_CASE
            )
            .is_err()
        );
        assert!(
            extract_tool_call(
                &tool_response(json!({
                    "stimulus": POSITIVE_CASE.stimulus,
                    "response_mode": "frame",
                    "extra": true
                })),
                &POSITIVE_CASE
            )
            .is_err()
        );
        let mut multiple = tool_response(json!({
            "stimulus": POSITIVE_CASE.stimulus,
            "response_mode": "frame"
        }));
        let call = multiple
            .pointer("/choices/0/message/tool_calls/0")
            .unwrap()
            .clone();
        multiple
            .pointer_mut("/choices/0/message/tool_calls")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(call);
        assert!(extract_tool_call(&multiple, &POSITIVE_CASE).is_err());
    }

    #[test]
    fn positive_and_refusal_admission_keep_distinct_boundaries() {
        let positive = admit_tool_result(&positive_result(), &POSITIVE_CASE).unwrap();
        assert!(positive.applied_attention);
        assert_eq!(positive.evidence_reference, "run-positive");
        let refusal = admit_tool_result(&refusal_result(), &REFUSAL_CASE).unwrap();
        assert!(!refusal.applied_attention);
        assert_eq!(refusal.observed_tool_status, "runtime_refused");
        let mut contaminated = refusal_result();
        contaminated["attention_frame"] = json!({});
        assert!(admit_tool_result(&contaminated, &REFUSAL_CASE).is_err());
    }

    #[test]
    fn final_output_must_preserve_observation() {
        let observation = admit_positive(&positive_result()).unwrap();
        let valid = FinalOutput {
            case_id: POSITIVE_CASE.case_id.to_owned(),
            observed_tool_status: observation.observed_tool_status.clone(),
            applied_attention: true,
            summary: POSITIVE_SUMMARY.to_owned(),
            evidence_reference: observation.evidence_reference.clone(),
            procedure_id: observation.procedure_id.clone(),
        };
        let response = json!({"choices": [{
            "finish_reason": "stop",
            "message": {"role": "assistant", "content": serde_json::to_string(&valid).unwrap()}
        }]});
        assert_eq!(
            extract_final_output(&response, &POSITIVE_CASE, &observation).unwrap(),
            valid
        );
        let mut changed = valid;
        changed.evidence_reference = "invented".to_owned();
        let response = json!({"choices": [{
            "finish_reason": "stop",
            "message": {"role": "assistant", "content": serde_json::to_string(&changed).unwrap()}
        }]});
        assert!(extract_final_output(&response, &POSITIVE_CASE, &observation).is_err());
    }

    #[test]
    fn provider_cardinality_and_mixed_tool_content_are_rejected() {
        let arguments = json!({
            "stimulus": POSITIVE_CASE.stimulus,
            "response_mode": "frame"
        });
        let mut multiple = tool_response(arguments.clone());
        let second = multiple["choices"][0].clone();
        multiple["choices"].as_array_mut().unwrap().push(second);
        assert!(extract_tool_call(&multiple, &POSITIVE_CASE).is_err());

        let mut mixed = tool_response(arguments);
        mixed["choices"][0]["message"]["content"] = json!("direct answer");
        assert!(extract_tool_call(&mixed, &POSITIVE_CASE).is_err());
    }

    #[test]
    fn malformed_frame_and_unverified_refusal_are_rejected() {
        let mut frame = positive_result();
        frame["attention_frame"]["sequence"]
            .as_array_mut()
            .unwrap()
            .insert(1, json!({"note": "operator omitted"}));
        assert!(admit_tool_result(&frame, &POSITIVE_CASE).is_err());

        let mut refusal = refusal_result();
        refusal["verification"]["status"] = json!("unverified");
        assert!(admit_tool_result(&refusal, &REFUSAL_CASE).is_err());
    }

    #[test]
    fn sanitizer_removes_private_reasoning_recursively() {
        let value = json!({
            "reasoning": "private",
            "choices": [{"message": {"reasoning_content": "private", "content": "kept"}}],
            "thinking": {"nested": true},
            "ordinary": {"thinking_content": "private", "kept": 1}
        });
        assert_eq!(
            sanitize(&value),
            json!({"choices": [{"message": {"content": "kept"}}], "ordinary": {"kept": 1}})
        );
    }

    #[test]
    fn contract_exposes_the_closed_p0_surface() {
        let contract = contract();
        assert_eq!(contract.report_profile, REPORT_PROFILE);
        assert_eq!(contract.cases.len(), 3);
        assert_eq!(contract.tool_name, cantor_attention_mcp::TOOL_NAME);
        assert_eq!(contract.max_tool_calls_per_routed_case, 1);
        assert_eq!(contract.provider_passes_per_routed_case, 2);
        assert_eq!(
            contract.routed_state_path,
            [
                FlowState::Created,
                FlowState::FirstInferenceRequested,
                FlowState::ToolCallReceived,
                FlowState::ToolCallValidated,
                FlowState::ToolResultReceived,
                FlowState::ReflectionRequested,
                FlowState::FinalReceived,
                FlowState::Completed,
            ]
        );
        assert_eq!(contract.cases[1].final_summary, REFUSAL_SUMMARY);
    }
}
